"""End to end reconciliation between two PostgreSQL databases.

The acceptance test for PRD F6: a known injected difference of ten rows in one table is
reported with the table named, the count difference shown and the differing rows listed.
"""

import json

import pytest

from liftproof.canonical import CANONICAL_REVISION
from liftproof.findings import FindingWriter, Kind, read_findings
from liftproof.reconcile.baseline import Baseline, take_baseline
from liftproof.reconcile.engine import REASON_INFINITY, ReconcileOptions, Reconciler
from liftproof.reconcile.plan import IgnoreRule

pytestmark = pytest.mark.postgres

SCHEMA = """
CREATE TABLE customers (id int PRIMARY KEY, name text NOT NULL, email text);
CREATE TABLE orders (
  id bigint PRIMARY KEY, customer_id int, status text, total numeric(10,2),
  unit_price double precision, created_at timestamptz, last_synced_at timestamp
);
CREATE TABLE audit_log (at timestamp, message text);
CREATE TABLE sessions (token text PRIMARY KEY);
INSERT INTO customers SELECT g, 'Customer ' || g, 'c' || g || '@example.com'
  FROM generate_series(1, 500) g;
INSERT INTO orders SELECT g, 1 + g % 500, 'DISPATCHED', (g % 1000) + 0.5, g * 0.1,
  timestamptz '2026-01-01 00:00+00' + g * interval '1 minute', now()
  FROM generate_series(1, 20000) g;
INSERT INTO audit_log SELECT timestamp '2026-01-01' + g * interval '1 hour', 'event ' || g
  FROM generate_series(1, 300) g;
INSERT INTO sessions SELECT md5(g::text) FROM generate_series(1, 50) g;
"""


ETL = IgnoreRule("orders", "rewritten by ETL", "last_synced_at")


def _run(tmp_path, source, target, **opts):
    opts.setdefault("ignore", [ETL])
    writer = FindingWriter(tmp_path / "findings", "r-test", segment_size=7)
    options = ReconcileOptions(rows_per_bucket=1000, **opts)
    result = Reconciler(target, writer, options, source=source).run()
    writer.close()
    return result, list(read_findings(tmp_path / "findings"))


@pytest.fixture
def pair(make_db, adapter_for):
    s, sc = make_db("src")
    t, tc = make_db("tgt")
    sc.execute(SCHEMA)
    tc.execute(SCHEMA.replace("last_synced_at timestamp", "last_synced_at timestamp, "
                              "tenant_id int DEFAULT 1"))
    return adapter_for(s), adapter_for(t), sc, tc


def test_identical_databases_match(tmp_path, pair):
    src, tgt, _, tc = pair
    tc.execute("ALTER TABLE orders DROP COLUMN tenant_id")
    result, findings = _run(tmp_path, src, tgt, ignore=[
        IgnoreRule("orders", "rewritten by ETL", "last_synced_at")])
    assert {t.status for t in result.tables} == {"matched"}
    assert not [f for f in findings if f.kind == Kind.DIFFERENCE]
    assert any(f.column == "unit_price" and f.kind == Kind.NOTICE for f in findings)
    assert any(f.column == "last_synced_at" and "rewritten by ETL" in f.summary
               for f in findings)


def test_ten_row_injected_difference(tmp_path, pair):
    src, tgt, _, tc = pair
    tc.execute("DELETE FROM orders WHERE id IN (88, 213, 214, 219, 3000, 3001, 7777, 12000, "
               "15000, 19999)")
    tc.execute("UPDATE orders SET status = 'dispatched' WHERE id = 4002")
    tc.execute("INSERT INTO audit_log VALUES ('2030-01-01', 'extra')")
    result, findings = _run(tmp_path, src, tgt, ignore=[
        IgnoreRule("orders", "rewritten by ETL", "last_synced_at"),
        IgnoreRule("sessions", "session tokens are not migrated")])

    by_table = {t.table: t for t in result.tables}
    orders = by_table["public.orders"]
    assert orders.status == "different"
    assert (orders.source_rows, orders.target_rows) == (20000, 19990)
    assert orders.missing_rows == 10 and orders.changed_rows == 1 and orders.extra_rows == 0

    missing = sorted(int(f.detail["key"][0]) for f in findings
                     if f.object == "public.orders" and f.summary == "row missing in target")
    assert missing == [88, 213, 214, 219, 3000, 3001, 7777, 12000, 15000, 19999]
    [changed] = [f for f in findings if f.summary == "value differs in column status"]
    assert changed.locator == "id = 4002"
    assert changed.expected.startswith("md5:")  # values hidden by default

    count = [f for f in findings
             if f.object == "public.orders" and f.summary.startswith("row count differs")]
    assert count and count[0].detail["difference"] == -10

    audit = by_table["public.audit_log"]
    assert audit.status == "different" and audit.extra_rows == 1 and audit.key.startswith("none")
    assert by_table["public.sessions"].status == "excluded"
    assert by_table["public.customers"].status == "matched"
    added = [f for f in findings if f.column == "tenant_id"]
    assert added and added[0].detail["issue"] == "added_in_target"
    # ten deleted rows also move the approximate aggregates of the float column
    assert any(f.column == "unit_price" and f.kind == Kind.DIFFERENCE for f in findings)


def test_show_values_flag(tmp_path, pair):
    src, tgt, _, tc = pair
    tc.execute("UPDATE orders SET status = 'dispatched' WHERE id = 4002")
    _, findings = _run(tmp_path, src, tgt, show_values=True, tables=["orders"])
    [changed] = [f for f in findings if f.column == "status" and f.kind == Kind.DIFFERENCE]
    assert (changed.expected, changed.actual) == ("DISPATCHED", "dispatched")


def test_float_difference_detected(tmp_path, pair):
    src, tgt, _, tc = pair
    tc.execute("UPDATE orders SET unit_price = unit_price + 1 WHERE id = 5")
    result, findings = _run(tmp_path, src, tgt, tables=["orders"])
    assert result.tables[0].status == "different"
    assert any(f.column == "unit_price" and f.kind == Kind.DIFFERENCE for f in findings)


def test_circuit_breaker_on_systemic_change(tmp_path, pair):
    src, tgt, _, tc = pair
    tc.execute("UPDATE orders SET status = lower(status)")
    result, findings = _run(tmp_path, src, tgt, tables=["orders"])
    systemic = [f for f in findings if f.severity == 5]
    assert systemic and "status" in systemic[0].detail["columns"]
    assert "collation or case" in systemic[0].summary
    # the drill-down stopped: no per row findings for 20,000 changed rows
    assert len([f for f in findings if f.summary.startswith("value differs")]) <= 5


def test_diff_row_limit_states_true_total(tmp_path, pair):
    src, tgt, _, tc = pair
    tc.execute("DELETE FROM orders WHERE id % 1000 = 0")  # 20 rows across buckets
    _, findings = _run(tmp_path, src, tgt, tables=["orders"], diff_row_limit=5,
                       breaker_bucket_ratio=1.0)
    listed = [f for f in findings if f.summary == "row missing in target"]
    assert len(listed) == 5
    [summary] = [f for f in findings if f.detail.get("limit") == 5]
    assert summary.detail["missing"] == 20 and summary.detail["shown"] == 5


def test_baseline_then_reconcile(tmp_path, make_db, adapter_for, pair):
    src, tgt, sc, tc = pair
    tc.execute("ALTER TABLE orders DROP COLUMN tenant_id")
    manifest = tmp_path / "baseline" / "manifest.json"
    take_baseline(src, manifest, baseline_id="b1", schemas=["public"], tables=None,
                  ignore=[IgnoreRule("orders", "rewritten by ETL", "last_synced_at")],
                  business_keys={}, rows_per_bucket=1000, precision=6)
    b = Baseline.load(manifest)
    assert b.complete and b.tables["public.orders"].row_count == 20000
    assert b.position["type"] == "lsn" and b.position["position"]

    tc.execute("DELETE FROM customers WHERE id = 7")
    writer = FindingWriter(tmp_path / "f2", "r2")
    opts = ReconcileOptions(rows_per_bucket=1000, ignore=[
        IgnoreRule("orders", "rewritten by ETL", "last_synced_at")])
    # without a live source: bucket level only, and it says so
    result = Reconciler(tgt, writer, opts, baseline=b).run()
    writer.close()
    cust = {t.table: t for t in result.tables}["public.customers"]
    assert cust.status == "different" and cust.mismatched_buckets == 1
    findings = list(read_findings(tmp_path / "f2"))
    assert any("needs the live source" in f.summary for f in findings)
    # with the source still readable: row level
    writer = FindingWriter(tmp_path / "f3", "r3")
    Reconciler(tgt, writer, opts, baseline=b, source=src).run()
    writer.close()
    findings = list(read_findings(tmp_path / "f3"))
    assert [f.locator for f in findings if f.summary == "row missing in target"] == ["id = 7"]


CONTRACTS = """
CREATE TABLE contracts (id int PRIMARY KEY, valid_from date, valid_to timestamptz);
INSERT INTO contracts SELECT g, date '2026-01-01' + g,
  CASE WHEN g % 2 = 0 THEN 'infinity' ELSE timestamptz '2027-01-01 00:00+00' + g * interval '1 hour'
  END FROM generate_series(1, 2000) g;
"""


@pytest.fixture
def contracts(make_db, adapter_for):
    s, sc = make_db("src")
    t, tc = make_db("tgt")
    for c in (sc, tc):
        c.execute(CONTRACTS)
    return adapter_for(s), adapter_for(t), sc, tc


def test_infinity_differences(tmp_path, contracts):
    """An open ended date that became NULL, or minus infinity, is a changed value: before
    canonical revision 1 infinity hashed as NULL, and reading its range failed the run."""
    src, tgt, _, tc = contracts
    tc.execute("UPDATE contracts SET valid_to = NULL WHERE id = 10")
    tc.execute("UPDATE contracts SET valid_to = '-infinity' WHERE id = 20")
    result, findings = _run(tmp_path / "a", src, tgt, show_values=True)
    [table] = result.tables
    assert table.status == "different" and table.changed_rows == 2
    changed = {f.locator: (f.expected, f.actual) for f in findings
               if f.summary == "value differs in column valid_to"}  # fmt: skip
    assert changed == {"id = 10": ("infinity", "NULL"), "id = 20": ("infinity", "-infinity")}

    tc.execute("UPDATE contracts SET valid_to = 'infinity' WHERE id IN (10, 20)")
    result, findings = _run(tmp_path / "b", src, tgt)
    [table] = result.tables
    assert table.status == "matched", [f.summary for f in findings]
    assert table.ranges["valid_to"]["source"] == ["2027-01-01T01:00:00+00:00", "infinity"]
    assert table.ranges["valid_to"]["target"][1] == "infinity"


def test_infinity_mapped_to_null_is_named_as_the_likely_cause(tmp_path, contracts):
    src, tgt, _, tc = contracts
    tc.execute("UPDATE contracts SET valid_to = NULL WHERE valid_to = 'infinity'")
    _, findings = _run(tmp_path, src, tgt, breaker_min_buckets=2)
    [systemic] = [f for f in findings if f.severity == 5]
    assert "PostgreSQL infinity dates mapped to NULL" in systemic.summary
    assert "time zone" not in systemic.summary


def _strip(manifest, tables, *, keep_ranges=()):
    """The manifest as a build from before canonical revisions wrote it for these tables:
    no revision, and no data ranges unless kept (the oldest builds wrote none)."""
    doc = json.loads(manifest.read_text())
    for q in tables:
        entry = doc["tables"][q]
        del entry["canonical_revision"]
        if q not in keep_ranges:
            entry.pop("ranges")
    manifest.write_text(json.dumps(doc))
    return Baseline.load(manifest)


def test_a_baseline_from_before_revisions(tmp_path, contracts, monkeypatch):
    src, tgt, sc, tc = contracts
    for c in (sc, tc):
        c.execute("CREATE TABLE events (id int PRIMARY KEY, at date);"
                  "CREATE TABLE plain (id int PRIMARY KEY, v text);"
                  "CREATE TABLE docs (id int PRIMARY KEY, body jsonb, at date);"
                  "INSERT INTO events SELECT g, date '2026-01-01' + g FROM generate_series(1, 9) g;"
                  "INSERT INTO plain SELECT g, 'v' || g FROM generate_series(1, 9) g;"
                  "INSERT INTO docs SELECT g, '{\"a\": 1}', date '2026-01-01' + g "
                  "FROM generate_series(1, 9) g")  # fmt: skip
    manifest = tmp_path / "b1" / "manifest.json"
    take_baseline(src, manifest, baseline_id="b1", schemas=["public"], tables=None, ignore=[],
                  business_keys={}, rows_per_bucket=1000, precision=6)  # fmt: skip
    b = Baseline.load(manifest)
    assert {t.canonical_revision for t in b.tables.values()} == {CANONICAL_REVISION}

    def compare(name, baseline, source=None):
        writer = FindingWriter(tmp_path / name, name)
        opts = ReconcileOptions(rows_per_bucket=1000)
        result = Reconciler(tgt, writer, opts, baseline=baseline, source=source).run()
        writer.close()
        return {t.table: t for t in result.tables}, list(read_findings(tmp_path / name))

    tables, _ = compare("f1", b)
    assert {t.status for t in tables.values()} == {"matched"}  # infinity in the baseline too

    # Old entries are reused when nothing could have hashed as NULL: their data ranges
    # cover every date column, they have none, or they were hashed here (JSON)
    old = _strip(manifest, list(b.tables), keep_ranges=["public.events"])
    tables, findings = compare("f2", old)
    assert tables["public.contracts"].status == "not_checked"
    assert tables["public.contracts"].reason.endswith(
        "take a new baseline, or compare with the live source without --baseline"
    )
    [f] = [f for f in findings if f.detail.get("reason") == REASON_INFINITY]
    assert f.kind == Kind.NOT_CHECKED and f.detail["baseline_canonical_revision"] == 0
    for q in ("public.events", "public.plain", "public.docs"):
        assert tables[q].status == "matched", q  # no live source: the baseline was reused

    # the live source does not stand in for it: replication was checked at the baseline
    hashed = []
    monkeypatch.setattr(src, "bucket_aggregates", lambda plan: hashed.append(plan))
    tables, _ = compare("f3", old, source=src)
    assert tables["public.contracts"].status == "not_checked" and hashed == []

    target = tmp_path / "t1" / "manifest.json"
    take_baseline(tgt, target, baseline_id="t1", schemas=["public"], tables=["contracts"],
                  ignore=[], business_keys={}, rows_per_bucket=1000, precision=6,
                  side="target")  # fmt: skip
    tables, _ = compare("f4", _strip(target, ["public.contracts"]))
    assert tables["public.contracts"].reason == (
        f"{REASON_INFINITY}; take a new target baseline (liftproof rebaseline)"
    )


@pytest.mark.postgres
def test_bucket_rows_one_pass_matches_one_query_per_bucket(make_db, adapter_for):
    """PostgreSQL's single ordered pass yields exactly what the default yields: every
    wanted bucket in order, empty ones included."""
    from liftproof.adapters.base import Adapter
    from liftproof.reconcile.plan import plan_table

    name, conn = make_db("b")
    conn.execute("CREATE TABLE t (id int PRIMARY KEY, v text);"
                 "INSERT INTO t SELECT g, 'v' || g FROM generate_series(1, 300) g")  # fmt: skip
    a = adapter_for(name)
    [ref] = a.list_tables(["public"])
    plan = plan_table(a.describe(ref), None, rows=300, rows_per_bucket=10, precision=6,
                      ignore=[], business_key=None).plan  # fmt: skip
    wanted = set(range(plan.buckets)) | {plan.buckets + 5}  # one bucket that cannot exist
    one_pass = list(a.bucket_rows(plan, wanted))
    per_bucket = list(Adapter.bucket_rows(a, plan, wanted))
    assert one_pass == per_bucket
    assert [b for b, _ in one_pass] == sorted(wanted)
    assert sum(len(r) for _, r in one_pass) == 300 and one_pass[-1][1] == {}
