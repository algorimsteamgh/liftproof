"""End to end reconciliation between two PostgreSQL databases.

The acceptance test for PRD F6: a known injected difference of ten rows in one table is
reported with the table named, the count difference shown and the differing rows listed.
"""

import json

import pytest

from liftproof.canonical import CANONICAL_REVISION
from liftproof.findings import FindingWriter, Kind, Severity, read_findings
from liftproof.reconcile.baseline import Baseline, take_baseline
from liftproof.reconcile.engine import REASON_INFINITY, ReconcileOptions, Reconciler
from liftproof.reconcile.plan import IgnoreRule
from liftproof.reconcile.structure import StructureChecks
from liftproof.report.builder import verdict

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


def _structure(findings):
    return sorted((f.object, f.detail["issue"], f.severity) for f in findings
                  if f.detail.get("issue") and f.kind in (Kind.DIFFERENCE, Kind.NOTICE)
                  and f.column != "tenant_id")  # fmt: skip


def _restructure(sc, tc):
    """Spec 9.13: what a DMS full load leaves behind, a NOT NULL, a unique key, a foreign
    key, an index and a primary key short."""
    tc.execute("ALTER TABLE customers ALTER name DROP NOT NULL;"
               "ALTER TABLE sessions DROP CONSTRAINT sessions_pkey")  # fmt: skip
    sc.execute("CREATE UNIQUE INDEX ON customers (email); CREATE INDEX ON orders (customer_id);"
               "ALTER TABLE orders ADD FOREIGN KEY (customer_id) REFERENCES customers")  # fmt: skip


def test_structure_differences_reported(tmp_path, pair):
    src, tgt, sc, tc = pair
    _restructure(sc, tc)
    result, findings = _run(tmp_path / "a", src, tgt)
    assert _structure(findings) == [
        ("public.customers", "key_missing_in_target", Severity.MEDIUM),
        ("public.customers", "nullability_changed", Severity.MEDIUM),
        ("public.orders", "foreign_key_missing_in_target", Severity.MEDIUM),
        ("public.orders", "index_missing_in_target", Severity.LOW),
        ("public.sessions", "key_missing_in_target", Severity.MEDIUM),
    ]
    [pk] = [f for f in findings if f.object == "public.sessions" and f.detail.get("issue")]
    assert (pk.expected, pk.actual) == ("primary key (token)", "none")
    [fk] = [f for f in findings if f.detail.get("issue") == "foreign_key_missing_in_target"]
    assert fk.detail["references"] == "public.customers" and fk.detail["columns"] == ["customer_id"]
    tables = {t.table: t for t in result.tables}
    assert {t.status for t in tables.values()} == {"matched"}  # the data still matches
    assert {q: t.structure_differences for q, t in tables.items()} == {
        "public.customers": 2, "public.orders": 2, "public.audit_log": 0, "public.sessions": 1}
    assert verdict(findings) == "failed"
    assert result.structure == {"nullability": True, "keys": True, "foreign_keys": True,
                                "indexes": True}  # fmt: skip

    # accepted with a reason: named in the exclusions, compared no more
    rules = [ETL, IgnoreRule("sessions", "rebuilt after the load", structure="keys"),
             IgnoreRule("customers", "relaxed on purpose", "name", structure="nullability")]
    result, findings = _run(tmp_path / "b", src, tgt, ignore=rules)
    assert [t for t in _structure(findings) if t[0] != "public.orders"] == [
        ("public.customers", "key_missing_in_target", Severity.MEDIUM)]
    accepted = sorted((f.object, f.column, f.detail["structure"]) for f in findings
                      if f.detail.get("reason") and f.detail.get("structure"))  # fmt: skip
    assert accepted == [("public.customers", "name", "nullability"),
                        ("public.sessions", None, "keys")]  # fmt: skip


def test_structure_can_be_switched_off(tmp_path, pair):
    src, tgt, sc, tc = pair
    _restructure(sc, tc)
    off = StructureChecks(False, False, False, False)
    result, findings = _run(tmp_path, src, tgt, structure=off)
    assert _structure(findings) == []
    assert not any(t.structure_differences for t in result.tables)
    assert set(result.structure.values()) == {False}
    _, findings = _run(tmp_path / "b", src, tgt, structure=StructureChecks(indexes=False,
                                                                           foreign_keys=False))
    assert [i for _, i, _ in _structure(findings)] == ["key_missing_in_target",
                                                       "nullability_changed",
                                                       "key_missing_in_target"]  # fmt: skip


def test_structure_against_a_baseline(tmp_path, pair):
    src, tgt, sc, tc = pair
    tc.execute("ALTER TABLE orders DROP COLUMN tenant_id")
    manifest = tmp_path / "baseline" / "manifest.json"
    take_baseline(src, manifest, baseline_id="b1", schemas=["public"], tables=None,
                  ignore=[ETL], business_keys={}, rows_per_bucket=1000, precision=6)  # fmt: skip
    entry = json.loads(manifest.read_text())["tables"]["public.customers"]
    assert entry["not_null"] == ["id", "name"] and entry["indexes"] == []
    assert entry["foreign_keys"] == []
    tc.execute("ALTER TABLE customers ALTER name DROP NOT NULL")

    def compare(name, baseline):
        writer = FindingWriter(tmp_path / name, name)
        opts = ReconcileOptions(rows_per_bucket=1000, ignore=[ETL])
        result = Reconciler(tgt, writer, opts, baseline=baseline).run()
        writer.close()
        return result, list(read_findings(tmp_path / name))

    result, findings = compare("f1", Baseline.load(manifest))
    assert _structure(findings) == [("public.customers", "nullability_changed", Severity.MEDIUM)]
    assert "unrecorded" not in result.structure

    # a manifest from before structure was recorded: the primary key alone is compared
    doc = json.loads(manifest.read_text())
    for entry in doc["tables"].values():
        for key in ("not_null", "indexes", "foreign_keys"):
            del entry[key]
    manifest.write_text(json.dumps(doc))
    tc.execute("ALTER TABLE sessions DROP CONSTRAINT sessions_pkey")
    result, findings = compare("f2", Baseline.load(manifest))
    assert _structure(findings) == [("public.sessions", "key_missing_in_target", Severity.MEDIUM)]
    assert result.structure["unrecorded"].startswith(
        "baseline b1 was taken before nullability, keys and indexes were recorded; only "
        "primary keys are compared for public.audit_log, public.customers"
    )


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


# ------------------------------------------------------------------------------ XML
DOCS = """
CREATE TABLE docs (id int PRIMARY KEY, doc xml, note text);
CREATE TABLE notes (id int PRIMARY KEY, v text);
INSERT INTO notes SELECT g, 'v' || g FROM generate_series(1, 50) g;
"""
# the same documents, written as two engines or tools might write them
COMPACT = """INSERT INTO docs SELECT g, xmlelement(name "order", xmlattributes(g AS id, 'EUR' AS
  currency), xmlelement(name line, xmlattributes('A-' || g AS sku), g % 7)), 'n' || g
  FROM generate_series(1, 200) g"""
PRETTY = """INSERT INTO docs SELECT g, format(E'<?xml version="1.0"?>\\n<order currency=''EUR''
  id="%s">\\n  <!-- exported -->\\n  <line sku="A-%s">%s</line>\\n</order>\\n', g, g, g % 7)::xml,
  'n' || g FROM generate_series(1, 200) g"""
XHTML = (
    '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" '
    '"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"><html>&nbsp;</html>'
)


@pytest.fixture
def documents(make_db, adapter_for):
    s, sc = make_db("src")
    t, tc = make_db("tgt")
    sc.execute(DOCS + COMPACT)
    tc.execute(DOCS + PRETTY)
    return adapter_for(s), adapter_for(t), sc, tc


def _by_table(result):
    return {t.table: t for t in result.tables}


def test_xml_documents_compare_semantically(tmp_path, documents):
    src, tgt, _, tc = documents
    result, findings = _run(tmp_path / "a", src, tgt, ignore=[])
    docs = _by_table(result)["public.docs"]
    assert docs.status == "matched" and not docs.partial, [f.summary for f in findings]
    assert docs.excluded_columns == [] and docs.key == "id"
    [notice] = [f for f in findings if f.detail.get("xml_columns")]
    assert notice.kind == Kind.NOTICE and notice.detail["xml_columns"] == ["doc"]
    assert verdict(findings) == "passed"

    tc.execute("UPDATE docs SET doc = replace(doc::text, 'EUR', 'USD')::xml WHERE id = 42")
    result, findings = _run(tmp_path / "b", src, tgt, ignore=[], show_values=True)
    docs = _by_table(result)["public.docs"]
    assert docs.status == "different" and docs.changed_rows == 1
    [changed] = [f for f in findings if f.summary == "value differs in column doc"]
    assert changed.locator == "id = 42"
    assert changed.expected == '<order currency="EUR" id="42"><line sku="A-42">0</line></order>'
    assert changed.actual == '<order currency="USD" id="42"><line sku="A-42">0</line></order>'
    assert verdict(findings) == "failed"


def test_a_value_that_cannot_be_canonicalised_leaves_its_column_out(tmp_path, documents):
    """PostgreSQL accepts an XHTML document whose entities its external DTD declares;
    expat cannot read that DTD. The column is not checked, with the reason, and the rest of
    the table and the run are compared (spec 9.6)."""
    src, tgt, _, tc = documents
    tc.execute("UPDATE docs SET doc = %s WHERE id = 7", (XHTML,))
    tc.execute("UPDATE docs SET note = 'changed' WHERE id = 8")
    result, findings = _run(tmp_path, src, tgt, ignore=[])
    tables = _by_table(result)
    docs = tables["public.docs"]
    assert docs.partial and docs.excluded_columns == ["doc"]
    assert docs.status == "different" and docs.changed_rows == 1  # the note, found by key
    [f] = [f for f in findings if f.column == "doc" and f.kind == Kind.NOT_CHECKED]
    assert f.detail["issue"] == "not_canonicalisable" and f.severity == 3
    assert f.summary.startswith("column not canonicalisable: not well-formed XML")
    assert "nbsp" in f.summary and "html" not in f.summary  # the reason, not the value
    assert [x.summary for x in findings if x.column == "note"] == ["value differs in column note"]
    assert tables["public.notes"].status == "matched"


def test_baselines_and_xml(tmp_path, documents):
    src, tgt, sc, tc = documents

    def baseline(name, adapter, **kw):
        manifest = tmp_path / name / "manifest.json"
        take_baseline(adapter, manifest, baseline_id=name, schemas=["public"], tables=None,
                      business_keys={}, rows_per_bucket=1000, precision=6,
                      **{"ignore": [], **kw})  # fmt: skip
        return manifest

    def compare(name, manifest, source=None):
        writer = FindingWriter(tmp_path / name, name)
        b = Baseline.load(manifest)
        result = Reconciler(tgt, writer, ReconcileOptions(), baseline=b, source=source).run()
        writer.close()
        return _by_table(result), list(read_findings(tmp_path / name))

    # a baseline from before XML was compared: the column stays not checked, as it was,
    # until the baseline is taken again; it is no type change, and the baseline still holds
    old = baseline("old", src, ignore=[IgnoreRule("docs", "before canonical revision 2", "doc")])
    manifest = json.loads(old.read_text())
    for entry in manifest["tables"].values():
        entry["canonical_revision"] = 1
        entry.pop("unhashed")
    [doc] = [c for c in manifest["tables"]["public.docs"]["columns"] if c[0] == "doc"]
    doc[2] = "unsupported"
    old.write_text(json.dumps(manifest))
    tables, findings = compare("f1", old)
    assert tables["public.docs"].status == "matched", [f.summary for f in findings]
    assert tables["public.docs"].excluded_columns == ["doc"]
    [f] = [f for f in findings if f.column == "doc"]
    assert (f.kind, f.severity, f.detail["issue"]) == (Kind.NOT_CHECKED, 2, "not_in_baseline")
    assert "canonical revision 2" in f.summary and (f.expected, f.actual) == ("xml", "xml")
    assert verdict(findings) == "passed_with_differences"

    # a value that cannot be canonicalised: the baseline is taken without its column
    sc.execute("UPDATE docs SET doc = %s WHERE id = 7", (XHTML,))
    seen = baseline("b1", src)
    entry = Baseline.load(seen).tables["public.docs"]
    assert entry.canonical_revision == CANONICAL_REVISION
    assert [n for n, _ in entry.plan.columns] == ["id", "note"]
    assert entry.unhashed["doc"][0] == "not_canonicalisable"
    tables, findings = compare("f2", seen)
    assert tables["public.docs"].status == "matched" and tables["public.docs"].partial
    [f] = [f for f in findings if f.column == "doc"]
    assert f.detail["issue"] == "not_canonicalisable"
    assert "when the baseline was taken, not well-formed XML" in f.summary

    # baselines in which every document canonicalised (the target's equal the source's)
    as_source = baseline("b2", tgt)
    as_target = baseline("t1", tgt, side="target")

    # the live source's documents are first rendered in the drill-down: the differences
    # found stand, the rows cannot be named
    tc.execute("UPDATE docs SET note = 'changed' WHERE id = 9")
    tables, findings = compare("f3", as_source, source=src)
    assert tables["public.docs"].status == "different"
    assert any(f.summary.startswith("table aggregate differs") for f in findings)
    [stopped] = [f for f in findings if f.summary.startswith("row level drill-down stopped")]
    assert stopped.column == "doc" and stopped.detail["issue"] == "not_canonicalisable"

    # the target now holds one: the rest of the table needs a new target baseline
    tc.execute("UPDATE docs SET note = 'n9', doc = %s WHERE id = 9", (XHTML,))
    tables, findings = compare("f4", as_target)
    assert tables["public.docs"].status == "not_checked"
    assert tables["public.docs"].reason == (
        "the baseline hashed doc, which cannot be canonicalised now; rebaseline to compare "
        "the rest of the table"
    )
    assert tables["public.notes"].status == "matched"
