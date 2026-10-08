"""Sampled reconciliation (Technical Spec 9.18): above a configured size a random share of
the buckets is compared, the report says so plainly with the share of rows compared, and
the rest is marked not checked. A sampled result is never presented as a full one."""

import pytest

from liftproof.config import load_project
from liftproof.errors import ConfigError
from liftproof.findings import FindingWriter, Kind, read_findings
from liftproof.reconcile.baseline import Baseline, take_baseline
from liftproof.reconcile.engine import ReconcileOptions, Reconciler
from liftproof.report.builder import build_report

SCHEMA = """
CREATE TABLE orders (id int PRIMARY KEY, status text, total numeric(10,2));
INSERT INTO orders SELECT g, 'OPEN', g + 0.5 FROM generate_series(1, 20000) g;
CREATE TABLE regions (id int PRIMARY KEY, name text);
INSERT INTO regions SELECT g, 'r' || g FROM generate_series(1, 50) g;
"""


def _run(tmp_path, target, *, source=None, baseline=None, name="f", **opts):
    opts.setdefault("sample_above_rows", 1000)
    opts.setdefault("sample_percent", 25)
    opts.setdefault("breaker_bucket_ratio", 1.0)  # the tests spread changes over every bucket
    writer = FindingWriter(tmp_path / name, "r")
    options = ReconcileOptions(rows_per_bucket=500, **opts)  # orders: 40 buckets
    result = Reconciler(target, writer, options, source=source, baseline=baseline).run()
    writer.close()
    return result, {t.table: t for t in result.tables}, list(read_findings(tmp_path / name))


@pytest.fixture
def pair(make_db, adapter_for):
    s, sc = make_db("src")
    t, tc = make_db("tgt")
    sc.execute(SCHEMA)
    tc.execute(SCHEMA)
    return adapter_for(s), adapter_for(t), sc, tc


pytestmark = pytest.mark.postgres


def test_large_table_is_sampled_and_says_so(tmp_path, pair):
    src, tgt, _, _ = pair
    result, tables, findings = _run(tmp_path, tgt, source=src, sample_seed=7)
    orders, regions = tables["public.orders"], tables["public.regions"]
    assert orders.status == "matched"
    assert 15 < orders.sampled_percent < 35  # 10 of 40 buckets, by row share
    assert orders.source_rows == orders.target_rows < 20000
    assert regions.sampled_percent is None and regions.source_rows == 50  # small: in full
    [note] = [f for f in findings if f.kind == Kind.NOT_CHECKED]
    assert note.object == "public.orders" and note.summary.startswith("sampled: 10 of 40")
    assert note.detail["seed"] == 7 == result.sample_seed

    report = build_report(run_id="r", project="p", mode="reconcile", started_at="t",
                          finished_at="t", db=result, findings=findings, metadata={},
                          range_block={})  # fmt: skip
    assert report["coverage"]["sampled"] == [
        {"object": "public.orders", "percent": orders.sampled_percent}
    ]
    # never shown as a full comparison
    assert report["counts"]["not_checked"] >= 1 and report["verdict"] != "passed"


def test_same_seed_same_sample_and_differences_inside_it_are_found(tmp_path, pair):
    src, tgt, _, tc = pair
    tc.execute("DELETE FROM orders WHERE id % 100 = 0")  # 200 rows, spread over every bucket
    _, a, fa = _run(tmp_path, tgt, source=src, sample_seed=11, name="a")
    _, b, _ = _run(tmp_path, tgt, source=src, sample_seed=11, name="b")
    orders = a["public.orders"]
    assert orders.status == "different"
    assert 20 < orders.missing_rows < 90  # only the sampled quarter was looked at
    assert (orders.missing_rows, orders.source_rows) == (
        b["public.orders"].missing_rows,
        b["public.orders"].source_rows,
    )
    assert any("of 10 sampled buckets mismatched" in f.summary for f in fa)


def test_without_sampling_every_row_is_compared(tmp_path, pair):
    src, tgt, _, tc = pair
    tc.execute("DELETE FROM orders WHERE id % 100 = 0")
    _, tables, findings = _run(tmp_path, tgt, source=src, sample_above_rows=None)
    assert tables["public.orders"].missing_rows == 200
    assert tables["public.orders"].sampled_percent is None
    assert not [f for f in findings if f.kind == Kind.NOT_CHECKED]


def test_engine_without_sampling_compares_in_full(tmp_path, pair, monkeypatch):
    src, tgt, _, _ = pair
    monkeypatch.setattr(type(tgt), "supports_sampling", False)
    _, tables, findings = _run(tmp_path, tgt, source=src)
    assert tables["public.orders"].sampled_percent is None
    assert tables["public.orders"].source_rows == 20000
    assert any("compared in full" in f.summary for f in findings)


def test_baseline_is_sampled_on_the_same_buckets(tmp_path, pair):
    src, tgt, _, tc = pair
    manifest = tmp_path / "b" / "manifest.json"
    take_baseline(src, manifest, baseline_id="b1", schemas=["public"], tables=None, ignore=[],
                  business_keys={}, rows_per_bucket=500, precision=6)  # fmt: skip
    b = Baseline.load(manifest)
    _, tables, _ = _run(tmp_path, tgt, baseline=b, sample_seed=3)
    assert tables["public.orders"].status == "matched"
    tc.execute("UPDATE orders SET status = 'X'")  # every bucket changes
    _, tables, _ = _run(tmp_path, tgt, baseline=b, sample_seed=3, name="g",
                        breaker_bucket_ratio=0.9)  # fmt: skip
    orders = tables["public.orders"]
    assert orders.status == "different" and orders.mismatched_buckets == 10


def _project(tmp_path, sampling):
    p = tmp_path / "project.yaml"
    p.write_text(
        "project: t\nsource: {engine: postgresql, host: a, database: a, "
        "secret_arn: arn:aws:secretsmanager:ap-south-1:111111111111:secret:a}\n"
        "target: {engine: postgresql, host: b, database: b, "
        "secret_arn: arn:aws:secretsmanager:ap-south-1:111111111111:secret:b}\n"
        f"database: {{sampling: {sampling}}}\n"
    )
    return p


@pytest.mark.parametrize(
    "sampling, error",
    [("{percent: 10}", "above_rows"), ("{above_rows: 10, percent: 100}", "between 0 and 100")],
)
def test_sampling_config_is_checked(tmp_path, sampling, error):
    with pytest.raises(ConfigError, match=error):
        load_project(_project(tmp_path, sampling))


def test_sampling_config_round_trips(tmp_path):
    o = load_project(_project(tmp_path, "{above_rows: 1000000, percent: 5, seed: 9}")).database
    assert (o.sample_above_rows, o.sample_percent, o.sample_seed) == (1000000, 5.0, 9)
