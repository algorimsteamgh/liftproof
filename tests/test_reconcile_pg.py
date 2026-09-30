"""End to end reconciliation between two PostgreSQL databases.

The acceptance test for PRD F6: a known injected difference of ten rows in one table is
reported with the table named, the count difference shown and the differing rows listed.
"""

import pytest

from certus.findings import FindingWriter, Kind, read_findings
from certus.reconcile.baseline import Baseline, take_baseline
from certus.reconcile.engine import ReconcileOptions, Reconciler
from certus.reconcile.plan import IgnoreRule

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
