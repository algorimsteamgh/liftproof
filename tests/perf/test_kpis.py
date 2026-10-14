"""One test per KPI threshold in PRD N8 (docs/kpis.md). A release that misses one does
not ship until it is explained or fixed (N9)."""

from __future__ import annotations

import resource
import statistics
import time

import pytest

from liftproof.config import LOCK_TIMEOUT_MS, SOURCE_PAUSE_MS, SOURCE_ROWS_PER_SECOND
from liftproof.findings import Comparator, Finding, FindingWriter, Kind, Severity, read_findings
from liftproof.reconcile.engine import ReconcileOptions, Reconciler
from liftproof.report.builder import build_report, write_reports
from liftproof.web.browser import BodyPolicy
from liftproof.web.compare import WebOptions
from liftproof.web.recorder import Recorder
from liftproof.web.run import JourneyResult, WebResult, run_journeys
from tests.test_web import drive
from tests.webapp import PASSWORD, ShopApp

pytestmark = pytest.mark.perf

# PRD N8 thresholds
REPLAY_RATIO_MAX = 2.0
ROWS_PER_MINUTE_MIN = 1_000_000
REPORT_SECONDS_MAX = 60.0
TOOL_FAILURE_RATE_MAX = 0.02

# The sample application answers like a real one across a network.
LATENCY_MS = 150
REPLAYS = 60  # one tool failure in 60 is 1.7 %, under the 2 % threshold
ROWS = 1_000_000


# ------------------------------------------------------------------ replay KPIs
@pytest.fixture(scope="module")
def replays(browser_available, tmp_path_factory):
    assets_dir = tmp_path_factory.mktemp("assets")
    with ShopApp(latency_ms=LATENCY_MS) as app:
        journey, assets = Recorder(
            app.url, policy=BodyPolicy(["/api/*"]), headless=True
        ).record("checkout", start="/login", story="ORD-14", drive=drive)
    for sha, body in assets.items():
        (assets_dir / sha).write_bytes(body)
    results = []
    with ShopApp(latency_ms=LATENCY_MS) as target:  # unchanged: any failure is the tool's
        for _ in range(REPLAYS):
            r = run_journeys(
                [journey],
                target_url=target.url,
                options=WebOptions(),
                emit=lambda _f: None,
                assets_dir=lambda _j: assets_dir,
                secret_values=lambda j: {t: PASSWORD for t in j.secrets},
            )
            results.append(r.journeys[0])
    return journey, results


def test_kpi_replay_time_within_twice_the_recorded_time(replays, kpi):
    """Replay not more than twice the recorded duration, first attempt, retries excluded."""
    journey, results = replays
    ratios = [
        j.replayed_wall_ms / j.recorded_wall_ms
        for j in results
        if j.status == "passed" and j.attempts == 1 and j.replayed_wall_ms
    ]
    assert ratios, "no first attempt replay to measure"
    worst = max(ratios)
    kpi(
        "replay_time_ratio",
        value=round(worst, 2),
        median=round(statistics.median(ratios), 2),
        threshold=REPLAY_RATIO_MAX,
        unit="replayed / recorded journey wall clock (worst of the runs)",
        recorded_ms=journey.wall_ms,
        runs=len(ratios),
        steps=len(journey.steps),
        latency_ms=LATENCY_MS,
        passed=worst <= REPLAY_RATIO_MAX,
    )
    assert worst <= REPLAY_RATIO_MAX


def test_kpi_tool_failures_under_two_percent(replays, kpi):
    """Runs failing for tool reasons, not real differences: under 2 %. Against an
    unchanged target every run that does not pass cleanly is the tool's failure, and a
    flake (a retried step) counts too, as the report counts it."""
    _, results = replays
    failed = [j for j in results if j.status != "passed" or j.flakes or j.attempts > 1]
    rate = len(failed) / len(results)
    kpi(
        "tool_failure_rate",
        value=round(rate, 4),
        threshold=TOOL_FAILURE_RATE_MAX,
        unit="share of runs",
        runs=len(results),
        failures=[{"status": j.status, "reason": j.reason, "flakes": j.flakes} for j in failed],
        passed=rate < TOOL_FAILURE_RATE_MAX,
    )
    assert rate < TOOL_FAILURE_RATE_MAX


# ---------------------------------------------------------------- database KPIs
TABLE = """
CREATE TABLE orders (
  id bigint PRIMARY KEY, customer_id int, status text, total numeric(12,2),
  placed_at timestamp, shipped_at timestamp, sku text, quantity int, note text,
  updated_at timestamptz);
INSERT INTO orders
SELECT g, g % 50000, (ARRAY['OPEN','PAID','SHIPPED','CLOSED'])[1 + g % 4],
       (g % 100000) / 100.0, timestamp '2020-01-01' + g * interval '1 minute',
       timestamp '2020-01-02' + g * interval '1 minute', 'SKU-' || (g % 9973),
       1 + g % 7, md5(g::text), timestamptz '2024-01-01 00:00+00' + g * interval '1 second'
FROM generate_series(1, {rows}) g;
ANALYZE orders;
"""
# A second table like the first. Each table after the first in a run starts by paying for
# the last read of the one before it (spec 9.15), so the throughput KPI is timed on it.
SECOND = """
CREATE TABLE orders_copy (LIKE orders INCLUDING ALL);
INSERT INTO orders_copy SELECT * FROM orders;
ANALYZE orders_copy;
"""


@pytest.fixture(scope="module")
def big_pair(pg_available):
    import uuid

    import psycopg

    from tests.conftest import PG, _admin

    names = [f"liftproof_perf_{uuid.uuid4().hex[:8]}" for _ in range(2)]
    conns = []
    with _admin() as c:
        for n in names:
            c.execute(f'CREATE DATABASE "{n}" ENCODING UTF8 TEMPLATE template0')
    for n in names:
        conn = psycopg.connect(host=PG["host"], port=PG["port"], user=PG["user"],
                               password=PG["password"], dbname=n, autocommit=True)  # fmt: skip
        conn.execute(TABLE.format(rows=ROWS))
        conn.execute(SECOND)
        conns.append(conn)
    width = conns[0].execute("SELECT avg(pg_column_size(o.*))::int FROM orders o").fetchone()[0]
    yield names, conns, width
    for c in conns:
        c.close()
    with _admin() as c:
        for n in names:
            c.execute(f'DROP DATABASE IF EXISTS "{n}" WITH (FORCE)')


# The product as shipped (spec 9.15): the source read under the default cap and pause, one
# core per connection; the target without either. Every connection's lock timeout.
SHIPPED = (
    {"rows_per_second": SOURCE_ROWS_PER_SECOND, "pause_ms": SOURCE_PAUSE_MS,
     "lock_timeout_ms": LOCK_TIMEOUT_MS},
    {"lock_timeout_ms": LOCK_TIMEOUT_MS},
)  # fmt: skip


def _reconcile(tmp_path, adapter_for, names, settings=({}, {}), tables=("orders",)):
    """The run's result, its seconds, and each table's seconds as the run log times them:
    from the table's start to the next one's, the last one's to the end of the run."""
    source, target = (adapter_for(n, **kw) for n, kw in zip(names, settings, strict=True))
    writer = FindingWriter(tmp_path / "findings", "r-perf")
    starts: list[float] = []

    def progress(message: str) -> None:
        if message.startswith("reconciling"):
            starts.append(time.perf_counter())

    t0 = time.perf_counter()
    result = Reconciler(
        target, writer, ReconcileOptions(tables=list(tables)), source=source, progress=progress
    ).run()
    end = time.perf_counter()
    writer.close()
    return result, end - t0, [b - a for a, b in zip(starts, [*starts[1:], end], strict=True)]


def test_kpi_database_throughput(tmp_path, adapter_for, big_pair, kpi):
    """At least 1 million rows per minute per table, stated with its variables
    (Technical Spec 17): column count, average row width, rows, cores, both sides read.
    The slowest of two tables counts: the second also pays for the first one's last read,
    as every table after the first does."""
    names, _, width = big_pair
    tables = ("orders", "orders_copy")
    result, _, seconds = _reconcile(tmp_path, adapter_for, names, SHIPPED, tables)
    assert [t.status for t in result.tables] == ["matched", "matched"]
    per_minute = ROWS / max(seconds) * 60
    kpi(
        "database_throughput",
        value=round(per_minute),
        threshold=ROWS_PER_MINUTE_MIN,
        unit="rows per minute per table (source and target both hashed)",
        rows=ROWS,
        columns=10,
        avg_row_bytes=width,
        seconds=[round(x, 2) for x in seconds],
        engine="postgresql, hash pushdown",
        source_rows_per_second=SOURCE_ROWS_PER_SECOND,
        source_pause_ms=SOURCE_PAUSE_MS,
        passed=per_minute >= ROWS_PER_MINUTE_MIN,
    )
    assert per_minute >= ROWS_PER_MINUTE_MIN


def test_large_table_drill_down_streams(tmp_path, adapter_for, big_pair, kpi):
    """Nothing loads a table into memory (spec 17): drilling into differences spread over
    many buckets of a large table keeps the process's memory nearly flat."""
    names, conns, _ = big_pair
    conns[1].execute("UPDATE orders SET status = 'LOST' WHERE id % 50000 = 0")  # 20 rows
    try:
        before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        result, elapsed, _ = _reconcile(tmp_path, adapter_for, names)
        grown_mb = (resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - before) / 1024
    finally:
        conns[1].execute("UPDATE orders SET status = 'CLOSED' WHERE id % 50000 = 0")
    [t] = result.tables
    assert t.status == "different" and t.changed_rows == 20
    kpi("large_table_memory", value=round(grown_mb, 1), threshold=200, unit="MB peak growth",
        rows=ROWS, mismatched_buckets=t.mismatched_buckets, seconds=round(elapsed, 2),
        passed=grown_mb < 200)  # fmt: skip
    assert grown_mb < 200


# ------------------------------------------------------------------ report KPI
def test_kpi_report_for_500_journeys_under_a_minute(tmp_path, kpi):
    """Report generation after the checks finish: under 60 s for 500 journeys."""
    run_dir = tmp_path / "run"
    writer = FindingWriter(run_dir, "r-perf")
    web = WebResult(target_url="https://target.example")
    for n in range(500):
        jid = f"journey-{n:03d}"
        web.journeys.append(JourneyResult(jid, f"STORY-{n}", "different" if n % 5 == 0 else
                                          "passed", 12, 12, 1, 0, 2 if n % 5 == 0 else 0,
                                          4800.0, 5200.0))  # fmt: skip
        for s in range(8):  # findings of every kind a replay writes, 4000 in all
            writer.write(Finding(
                Comparator.API if s % 2 else Comparator.UI,
                Kind.DIFFERENCE if n % 5 == 0 and s < 2 else Kind.NOTICE,
                Severity.MEDIUM if s < 2 else Severity.INFO,
                f"{jid} step {s + 1}", f"value of $.items[{s}].price differs",
                locator=f"$.items[{s}].price", journey=jid, story=f"STORY-{n}",
            ))  # fmt: skip
    web.endpoints = [{"endpoint": f"GET /api/r{i}", "source_ms": 120.0, "target_ms": 110.0,
                      "change_pct": -8.3} for i in range(200)]  # fmt: skip
    writer.close()
    t0 = time.perf_counter()
    report = build_report(
        run_id="r-perf", project="perf", mode="replay", findings=list(read_findings(run_dir)),
        db=None, started_at="2026-10-07T00:00:00Z", web=web, finished_at="2026-10-07T01:00:00Z",
        metadata={}, range_block={},
    )  # fmt: skip
    write_reports(report, run_dir)
    elapsed = time.perf_counter() - t0
    kpi("report_generation", value=round(elapsed, 2), threshold=REPORT_SECONDS_MAX,
        unit="seconds", journeys=500, findings=4000,
        passed=elapsed < REPORT_SECONDS_MAX)  # fmt: skip
    assert elapsed < REPORT_SECONDS_MAX
