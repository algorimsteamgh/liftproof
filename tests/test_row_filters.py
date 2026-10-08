"""Row ignore rules (Technical Spec 9.11): rows a migration deliberately leaves behind, or
that differ by design, are left out on each side by a predicate, and the report says so."""

from dataclasses import replace

import pytest

from liftproof.config import load_project
from liftproof.errors import ConfigError
from liftproof.findings import FindingWriter, Kind, read_findings
from liftproof.reconcile.baseline import Baseline, take_baseline
from liftproof.reconcile.engine import ReconcileOptions, Reconciler
from liftproof.reconcile.plan import IgnoreRule, row_filter

SCHEMA = """
CREATE TABLE orders (id int PRIMARY KEY, status text, tenant text, total numeric(10,2),
                     weight double precision);
INSERT INTO orders SELECT g, CASE WHEN g % 10 = 0 THEN 'ARCHIVED' ELSE 'OPEN' END,
  CASE WHEN g <= 100 THEN 'test' ELSE 'acme' END, g + 0.5, g * 0.25
  FROM generate_series(1, 3000) g;
"""
ARCHIVED = IgnoreRule("orders", "archived orders are not migrated", where="status = 'ARCHIVED'")


def _run(tmp_path, target, *, source=None, baseline=None, ignore=(), name="f"):
    writer = FindingWriter(tmp_path / name, "r")
    opts = ReconcileOptions(rows_per_bucket=500, ignore=list(ignore))
    result = Reconciler(target, writer, opts, source=source, baseline=baseline).run()
    writer.close()
    return result.tables[0], list(read_findings(tmp_path / name))


@pytest.fixture
def pair(make_db, adapter_for):
    s, sc = make_db("src")
    t, tc = make_db("tgt")
    sc.execute(SCHEMA)
    tc.execute(SCHEMA)
    # the migration left archived orders behind
    tc.execute("DELETE FROM orders WHERE status = 'ARCHIVED'")
    return adapter_for(s), adapter_for(t), sc, tc


def test_predicates_combine_per_side():
    rules = [
        ARCHIVED,
        IgnoreRule("public.orders", "test tenant", source_where="tenant = 'test'"),
        IgnoreRule("orders", "status", "status"),  # a column rule adds nothing here
        IgnoreRule("other", "elsewhere", where="true"),
    ]
    assert row_filter(rules, "public.orders", "source") == (
        "(status = 'ARCHIVED') OR (tenant = 'test')"
    )
    assert row_filter(rules, "public.orders", "target") == "(status = 'ARCHIVED')"
    assert row_filter(rules, "public.customers", "source") is None
    assert not ARCHIVED.whole_table and IgnoreRule("x", "r").whole_table


@pytest.mark.postgres
def test_rows_left_behind_are_not_differences(tmp_path, pair):
    src, tgt, _, _ = pair
    table, findings = _run(tmp_path, tgt, source=src)
    assert table.status == "different" and table.target_rows == 2700  # without the rule

    table, findings = _run(tmp_path, tgt, source=src, ignore=[ARCHIVED], name="g")
    assert table.status == "matched", findings
    assert (table.source_rows, table.target_rows) == (2700, 2700)
    [notice] = [f for f in findings if "excluded by ignore rule" in f.summary]
    assert notice.kind == Kind.NOTICE
    assert notice.detail["source_where"] == "status = 'ARCHIVED'"


@pytest.mark.postgres
def test_a_real_difference_outside_the_rule_is_still_found(tmp_path, pair):
    src, tgt, _, tc = pair
    tc.execute("UPDATE orders SET total = total + 1 WHERE id = 1234")
    tc.execute("UPDATE orders SET weight = weight + 1 WHERE id = 1235")
    table, findings = _run(tmp_path, tgt, source=src, ignore=[ARCHIVED])
    assert table.status == "different"
    diffs = [f for f in findings if f.kind == Kind.DIFFERENCE]
    assert any(f.locator == "id = 1234" and f.column == "total" for f in diffs)
    assert any(f.column == "weight" for f in diffs)  # float statistics are filtered too


@pytest.mark.postgres
def test_null_predicate_keeps_the_row(tmp_path, pair):
    # "status = 'ARCHIVED'" is NULL for a NULL status: such a row is compared, not dropped
    src, tgt, sc, tc = pair
    sc.execute("UPDATE orders SET status = NULL WHERE id = 7")
    table, findings = _run(tmp_path, tgt, source=src, ignore=[ARCHIVED])
    assert table.status == "different"
    assert any(f.locator == "id = 7" for f in findings if f.kind == Kind.DIFFERENCE)


@pytest.mark.postgres
def test_side_specific_predicates(tmp_path, pair):
    # the target renamed the test tenant; each side states its own rows
    src, tgt, _, tc = pair
    tc.execute("UPDATE orders SET tenant = 'qa' WHERE tenant = 'test'")
    rule = IgnoreRule("orders", "test tenant data", source_where="tenant = 'test'",
                      target_where="tenant = 'qa'")  # fmt: skip
    table, _ = _run(tmp_path, tgt, source=src, ignore=[ARCHIVED, rule])
    assert table.status == "matched"
    assert (table.source_rows, table.target_rows) == (2610, 2610)


@pytest.mark.postgres
def test_baseline_holds_the_filtered_rows(tmp_path, pair):
    src, tgt, _, _ = pair
    manifest = tmp_path / "b" / "manifest.json"
    take_baseline(src, manifest, baseline_id="b1", schemas=["public"], tables=None,
                  ignore=[ARCHIVED], business_keys={}, rows_per_bucket=500,
                  precision=6)  # fmt: skip
    b = Baseline.load(manifest)
    t = b.tables["public.orders"]
    assert t.row_count == 2700 and t.plan.filter == "(status = 'ARCHIVED')"
    table, _ = _run(tmp_path, tgt, baseline=b, ignore=[ARCHIVED])
    assert table.status == "matched"


@pytest.mark.postgres
def test_adapter_without_row_filters_reports_not_checked(tmp_path, pair, monkeypatch):
    src, tgt, _, _ = pair
    monkeypatch.setattr(type(tgt), "supports_row_filters", False)
    table, findings = _run(tmp_path, tgt, source=src, ignore=[ARCHIVED])
    assert table.status == "not_checked"
    assert any(f.kind == Kind.NOT_CHECKED and "row ignore rules" in f.summary for f in findings)
    with pytest.raises(ConfigError, match="row ignore rules"):
        take_baseline(tgt, tmp_path / "b2" / "manifest.json", baseline_id="b2",
                      schemas=["public"], tables=None, ignore=[ARCHIVED], business_keys={},
                      rows_per_bucket=500, precision=6)  # fmt: skip


def _project(tmp_path, rule):
    p = tmp_path / "project.yaml"
    p.write_text(
        "project: t\nsource: {engine: postgresql, host: a, database: a, "
        "secret_arn: arn:aws:secretsmanager:ap-south-1:111111111111:secret:a}\n"
        "target: {engine: postgresql, host: b, database: b, "
        "secret_arn: arn:aws:secretsmanager:ap-south-1:111111111111:secret:b}\n"
        f"database: {{ignore: [{rule}]}}\n"
    )
    return p


@pytest.mark.parametrize(
    "rule, error",
    [
        ("{table: orders, reason: r, where: \"status = 'A'; DROP TABLE orders\"}", "without ';'"),
        ("{table: orders, reason: r, where: 'id > 1 -- x'}", "without ';'"),
        ("{table: orders, reason: r, source_where: 'id > 1 /* x */'}", "without ';'"),
        ("{table: orders, reason: r, where: '  '}", "without ';'"),
        ("{table: orders, reason: r, column: status, where: 'id > 1'}", "not both"),
    ],
)
def test_unsafe_or_ambiguous_rules_are_refused(tmp_path, rule, error):
    with pytest.raises(ConfigError, match=error):
        load_project(_project(tmp_path, rule))


def test_rule_round_trips_from_the_project_file(tmp_path):
    p = _project(tmp_path, "{table: orders, reason: r, source_where: \"status = 'A'\"}")
    [rule] = load_project(p).database.ignore
    assert replace(rule) == IgnoreRule("orders", "r", source_where="status = 'A'")
