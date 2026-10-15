"""Structure compared before data (Technical Spec 9.13): nullability, keys, foreign keys
and indexes, no database needed."""

import json

import pytest
import yaml

from liftproof.adapters.base import Column, ForeignKey, Index, TableRef, TableSchema
from liftproof.canonical import CanonicalType as T
from liftproof.findings import Comparator, Finding, Kind, Severity
from liftproof.reconcile.baseline import BaselineTable
from liftproof.reconcile.engine import ReconcileResult, TableResult
from liftproof.reconcile.plan import IgnoreRule, plan_table
from liftproof.reconcile.structure import StructureChecks, compare_structure
from liftproof.report.builder import build_report, render_html


def _t(*columns, pk=("id",), indexes=(), fks=(), schema="public", known=True):
    """A table; a column is a name (NOT NULL) or a (name, nullable) pair."""
    cols = [Column(*((c, False) if isinstance(c, str) else c)[:1], "integer", T.INTEGER,
                   nullable=c[1] if isinstance(c, tuple) else False) for c in columns]  # fmt: skip
    return TableSchema(TableRef(schema, "t"), cols, list(pk), list(indexes) if known else None,
                       list(fks) if known else None)  # fmt: skip


def _issues(reference, target, **kw):
    return [(i.issue, i.severity, i.kind) for i in compare_structure(reference, target, **kw)]


DIFF, NOTE = Kind.DIFFERENCE, Kind.NOTICE
LOW, MEDIUM, INFO = Severity.LOW, Severity.MEDIUM, Severity.INFO


def test_lost_not_null_is_medium_gained_is_low():
    found = compare_structure(_t("id", "a", ("b", True)), _t("id", ("a", True), "b"))
    assert [(i.issue, i.column, i.severity, i.expected, i.actual) for i in found] == [
        ("nullability_changed", "a", MEDIUM, "NOT NULL", "NULL"),
        ("nullability_changed", "b", LOW, "NULL", "NOT NULL"),
    ]
    assert found[0].summary == "column a is NOT NULL on the source and nullable on the target"
    found = compare_structure(_t("id", "a"), _t("id", ("A", True)), reference_name="baseline")
    assert found[0].summary.endswith("NOT NULL on the baseline and nullable on the target")


def test_nullability_skips_ignored_missing_unknown_and_lost_key_columns():
    source = _t("id", "a", "b", "c", "d")
    target = _t(("id", True), ("a", True), ("c", True), ("D", None), pk=())
    rules = [IgnoreRule("t", "rewritten by ETL", "a")]
    # a: ignored; b: not on the target; D: not known; id: reported once, as the lost key
    assert _issues(source, target, rules=rules) == [
        ("nullability_changed", MEDIUM, DIFF),
        ("key_missing_in_target", MEDIUM, DIFF),
    ]
    assert compare_structure(source, target, rules=rules)[0].column == "c"


def test_primary_key_lost_or_changed_is_medium_and_names_both():
    [lost] = compare_structure(_t("id", "a"), _t("id", "a", pk=()))
    assert (lost.issue, lost.severity, lost.expected, lost.actual) == (
        "key_missing_in_target", MEDIUM, "primary key (id)", "none")
    assert lost.summary == "primary key (id) is not enforced on the target"
    # a partitioned target: the key must include the partition column
    [changed] = compare_structure(_t("id", "at"), _t("id", "at", pk=("id", "at")))
    assert (changed.issue, changed.actual) == ("key_missing_in_target", "primary key (id, at)")
    # names compare without case: Oracle's ID is PostgreSQL's id
    assert compare_structure(_t("id", "a"), _t("ID", "A", pk=("ID",))) == []


def test_a_surrogate_primary_key_with_the_old_key_still_unique_is_a_notice():
    source = _t("order_no", "a", pk=("order_no",))
    target = _t("id", "order_no", "a", indexes=[Index("uq_order", ("order_no",), True)])
    [moved] = compare_structure(source, target)
    assert (moved.issue, moved.kind) == ("primary_key_moved", NOTE)
    assert moved.summary == ("the primary key is (id) on the target; the source's, "
                             "(order_no), is still unique on the target")  # fmt: skip
    # the new key on the column only the target has is that column's own finding (plan.py)


def test_a_stricter_target_key_is_low():
    # (a) unique on the target keeps (a, b) unique, and is a key the source never had
    assert _issues(_t("a", "b", pk=("a", "b")), _t("a", "b", pk=("a",))) == [
        ("primary_key_moved", INFO, NOTE),
        ("key_added_in_target", LOW, DIFF),
    ]


def test_unique_keys_match_as_column_sets():
    ab = Index("uq_ab", ("a", "b"), True)
    ba = Index("t_b_a_key", ("B", "A"), True)
    assert _issues(_t("id", "a", "b", indexes=[ab]), _t("id", "a", "b", indexes=[ba])) == []
    # a unique key the target holds as its primary key
    assert _issues(_t("id", "a", indexes=[Index("uq_a", ("a",), True)]),
                   _t("id", "a", pk=("a",), indexes=[Index("uq_id", ("id",), True)])) == [
        ("primary_key_moved", INFO, NOTE)]  # fmt: skip
    # Oracle lists the primary key's own index, a unique index on the same columns
    pk_index = Index("SYS_C0012", ("ID",), True)
    assert _issues(_t("id"), _t("ID", pk=("ID",), indexes=[pk_index])) == []


def test_a_unique_key_turned_plain_index_is_medium_and_not_an_index_finding():
    source = _t("id", "email", indexes=[Index("uq_email", ("email",), True)])
    target = _t("id", "email", indexes=[Index("ix_email", ("email",), False)])
    [lost] = compare_structure(source, target)
    assert (lost.issue, lost.severity) == ("key_missing_in_target", MEDIUM)
    assert lost.actual == "not unique"
    assert lost.detail == {"constraint": "unique key uq_email", "columns": ["email"]}


def test_a_filtered_unique_index_keeps_a_nullable_unique_key_at_low():
    """SQL Server allows one NULL in a unique constraint, so a nullable unique key arrives
    as a unique index WHERE email IS NOT NULL."""
    pg = _t("id", ("email", True), indexes=[Index("t_email_key", ("email",), True)])
    ms = _t("id", ("email", True), indexes=[Index("ux_email", ("email",), True, "partial")])
    [kept] = compare_structure(pg, ms)
    assert (kept.issue, kept.severity, kept.detail["index"]) == ("key_partial_in_target", LOW,
                                                                "ux_email")  # fmt: skip
    # the other way round, the filtered index is named, not compared, and implies the key
    [named] = compare_structure(ms, pg)
    assert (named.issue, named.kind, named.detail["structure"]) == ("index_not_compared", NOTE,
                                                                   "keys")  # fmt: skip


def test_an_index_is_there_when_a_target_btree_starts_with_its_columns():
    a, ab = Index("ix_a", ("a",), False), Index("ix_ab", ("a", "b"), False)
    source = _t("id", "a", "b", indexes=[a, ab])
    assert _issues(source, _t("id", "a", "b", indexes=[Index("x", ("A", "B"), False)])) == []
    wider = _t("id", "a", "b", indexes=[Index("x", ("a", "b", "id"), False)])
    assert _issues(source, wider) == [("index_added_in_target", INFO, NOTE)]
    # (b, a) serves neither (a) nor (a, b)
    found = compare_structure(source, _t("id", "a", "b", indexes=[Index("x", ("b", "a"), False)]))
    assert [(i.issue, i.severity, i.detail["index"]) for i in found] == [
        ("index_missing_in_target", LOW, "ix_a"),
        ("index_missing_in_target", LOW, "ix_ab"),
        ("index_added_in_target", INFO, "x"),
    ]
    # the primary key is an order too, and a duplicate column list is reported once
    dup = Index("ix_a2", ("A",), False)
    keyed = {"pk": ("a", "id")}
    assert _issues(_t("id", "a", indexes=[a, dup], **keyed), _t("id", "a", **keyed)) == []
    found = compare_structure(_t("id", "a", indexes=[a, dup]), _t("id", "a", indexes=[]))
    assert [i.issue for i in found] == ["index_missing_in_target"]


def test_an_index_only_on_the_target_is_a_notice():
    """MySQL indexes every foreign key: a PostgreSQL source without those indexes must not
    make every run pass with differences."""
    [extra] = compare_structure(_t("id", "a"), _t("id", "a", indexes=[Index("fk1", ("a",), False)]))
    assert (extra.issue, extra.kind, extra.summary) == (
        "index_added_in_target", NOTE, "index fk1 (a) is on the target only")


def test_other_kinds_of_index_are_named_not_compared():
    gin = Index("t_tags_idx", ("tags",), False, "other")
    expr = Index("t_lower_idx", (), False, "expression")
    part = Index("t_a_idx", ("a",), False, "partial")
    source = _t("id", "a", "tags", indexes=[gin, expr, part])
    found = compare_structure(source, _t("id", "a", "tags", indexes=[]))
    assert [(i.issue, i.kind, i.detail["index"]) for i in found] == [
        ("index_not_compared", NOTE, "t_tags_idx"),
        ("index_not_compared", NOTE, "t_lower_idx"),
        ("index_not_compared", NOTE, "t_a_idx"),
    ]
    assert found[0].detail["reason"].startswith("not a B-tree index; its kind is not compared")
    # a target index of another kind on the same leading column may stand in for a B-tree
    found = compare_structure(_t("id", "a", indexes=[Index("ix_a", ("a",), False)]),
                              _t("id", "a", indexes=[part]))  # fmt: skip
    assert [(i.issue, i.kind) for i in found] == [("index_not_compared", NOTE)]
    assert found[0].detail["reason"].startswith("target index t_a_idx may serve it: a partial")
    # and is never a B-tree that covers one
    assert _issues(_t("id", "a", indexes=[part]), _t("id", "a", indexes=[part])) == [
        ("index_not_compared", INFO, NOTE)]  # fmt: skip


def test_foreign_keys_match_on_column_pairs_and_the_mapped_table():
    parent = TableRef("shop", "parent")
    fk = ForeignKey("fk2", ("pcode", "pid"), parent, ("code", "id"))
    same = ForeignKey("t_pid_pcode_fkey", ("PID", "PCODE"), TableRef("public", "PARENT"),
                      ("ID", "CODE"))  # fmt: skip
    source = _t("id", "pid", "pcode", fks=[fk], schema="shop")
    target = _t("id", "pid", "pcode", fks=[same])
    assert _issues(source, target, schema_map={"shop": "public"}) == []
    # unmapped, the referenced table is another one: lost on one side, added on the other
    found = compare_structure(source, target)
    assert [(i.issue, i.severity) for i in found] == [
        ("foreign_key_missing_in_target", MEDIUM), ("foreign_key_added_in_target", LOW)]
    assert found[0].summary == ("foreign key fk2 (pcode, pid) to shop.parent (code, id) is not "
                                "on the target")  # fmt: skip
    assert found[0].detail["references"] == "shop.parent"
    # pairs, not columns: the same columns pointing at other columns are another key
    swapped = ForeignKey("x", ("pcode", "pid"), TableRef("public", "parent"), ("id", "code"))
    assert len(compare_structure(source, _t("id", "pid", "pcode", fks=[swapped]),
                                 schema_map={"shop": "public"})) == 2  # fmt: skip


def test_switches_and_structure_rules():
    source = _t("id", "a", "b", indexes=[Index("ix_b", ("b",), False), Index("uq_a", ("a",), True)],
                fks=[ForeignKey("fk", ("b",), TableRef("public", "p"), ("id",))])  # fmt: skip
    target = _t(("id", True), ("a", True), "b", pk=(), indexes=[])
    every = [i.issue for i in compare_structure(source, target)]
    assert every == ["nullability_changed", "key_missing_in_target", "key_missing_in_target",
                     "foreign_key_missing_in_target", "index_missing_in_target"]  # fmt: skip
    assert compare_structure(source, target, StructureChecks(False, False, False, False)) == []
    only = compare_structure(source, target, StructureChecks(indexes=False, foreign_keys=False))
    assert [i.issue for i in only] == every[:3]
    # the id column's nullability is reported once the key is accepted
    rule = IgnoreRule("t", "partitioned target", structure="keys")
    found = compare_structure(source, target, rules=[rule])
    assert [(i.issue, i.column) for i in found][:2] == [("nullability_changed", "id"),
                                                       ("nullability_changed", "a")]  # fmt: skip
    assert "key_missing_in_target" not in [i.issue for i in found]
    # with a column, only what holds that column
    rule = IgnoreRule("t", "relaxed on purpose", "a", structure="keys")
    assert [i.detail.get("constraint") for i in compare_structure(source, target, rules=[rule])
            if i.issue == "key_missing_in_target"] == ["primary key"]  # fmt: skip
    rule = IgnoreRule("t", "relaxed on purpose", "a", structure="nullability")
    assert ("nullability_changed", "a") not in [
        (i.issue, i.column) for i in compare_structure(source, target, rules=[rule])]
    # a column ignore rule leaves out every object holding the column
    found = compare_structure(source, target, rules=[IgnoreRule("t", "ETL", "b")])
    assert [i.issue for i in found] == every[:3]


def test_a_structure_rule_is_no_data_exclusion():
    rule = IgnoreRule("t", "partitioned target", "a", structure="keys")
    assert not rule.whole_table and not rule.excludes_column
    assert not IgnoreRule("t", "partitioned target", structure="keys").whole_table
    tp = plan_table(_t("id", "a"), _t("id", "a"), rows=10, rows_per_bucket=5, precision=6,
                    ignore=[rule])  # fmt: skip
    assert not tp.ignored and not tp.partial and len(tp.plan.columns) == 2


def test_unknown_structure_compares_the_primary_key_only():
    old = _t(("id", None), ("a", None), known=False)  # a baseline from before it was recorded
    target = _t(("id", True), ("a", True), pk=(), indexes=[Index("ix", ("a",), True)])
    assert _issues(old, target) == [("key_missing_in_target", MEDIUM, DIFF)]
    assert _issues(old, _t("id", "a", indexes=[Index("ix", ("a",), True)])) == []
    # nor are the reference's unique keys held against a target whose keys are unknown
    source = _t("id", "a", indexes=[Index("uq", ("a",), True)])
    assert _issues(source, _t("id", "a", known=False)) == []


def _entry(schema):
    plan = {"columns": [["id", "integer"]], "key_columns": ["id"], "buckets": 1, "precision": 6}
    d = {"columns": [[c.name, c.native_type, str(c.canonical), False] for c in schema.columns],
         "primary_key": schema.primary_key, "plan": plan, "row_count": 1,
         "bucket_aggregates": {"0": [1, "5"]}, "completed_at": "t"}  # fmt: skip
    return d


def test_baseline_table_round_trip_keeps_structure():
    fk = ForeignKey("fk", ("a",), TableRef("public", "p"), ("id",))
    schema = _t("id", ("a", True), indexes=[Index("ix", ("a",), False, "partial")], fks=[fk])
    entry = BaselineTable.from_dict("public.t", _entry(schema))
    assert entry.schema.indexes is None and entry.schema.foreign_keys is None  # an old one
    assert [c.nullable for c in entry.schema.columns] == [None, None]
    # saved again by a resume, it still claims nothing
    d = entry.to_dict()
    assert "not_null" not in d and "indexes" not in d and "foreign_keys" not in d
    entry.schema = schema
    d = json.loads(json.dumps(entry.to_dict()))
    assert d["not_null"] == ["id"]
    back = BaselineTable.from_dict("public.t", d).schema
    assert [c.nullable for c in back.columns] == [False, True]
    assert back.indexes == schema.indexes and back.foreign_keys == [fk]


def _project(tmp_path, database):
    from liftproof.config import load_project

    doc = {"project": "p", "source": {"host": "s", "database": "a"},
           "target": {"host": "t", "database": "a"}, "database": database}  # fmt: skip
    f = tmp_path / "p.yaml"
    f.write_text(yaml.safe_dump(doc))
    return load_project(f).database


def test_structure_switches_in_the_project_file(tmp_path):
    from liftproof.errors import ConfigError

    assert _project(tmp_path, {}).structure == StructureChecks()
    assert _project(tmp_path, {"structure": False}).structure == StructureChecks(
        False, False, False, False)
    assert _project(tmp_path, {"structure": {"indexes": False}}).structure == StructureChecks(
        indexes=False)
    for bad in ({"index": False}, 3, {"keys": "no"}):
        with pytest.raises(ConfigError, match="database.structure is true, false or a map"):
            _project(tmp_path, {"structure": bad})
    rule = {"table": "events", "structure": "keys", "reason": "partitioned target"}
    [r] = _project(tmp_path, {"ignore": [rule]}).ignore
    assert (r.structure, r.whole_table) == ("keys", False)
    for bad in ({**rule, "structure": "key"}, {**rule, "where": "id > 1"}):
        with pytest.raises(ConfigError, match="structure is one of nullability, keys"):
            _project(tmp_path, {"ignore": [bad]})


def test_the_report_shows_structure_and_what_was_not_compared():
    def notice(summary, **detail):
        return Finding(Comparator.DATABASE, Kind.NOTICE, Severity.INFO, "public.t", summary,
                       detail=detail)  # fmt: skip

    findings = [
        Finding(Comparator.DATABASE, Kind.DIFFERENCE, Severity.MEDIUM, "public.t",
                "column a is NOT NULL on the source and nullable on the target", column="a",
                detail={"issue": "nullability_changed"}),
        notice("index t_tags_idx is not compared", reason="not a B-tree index", index="t_tags_idx",
               structure="indexes"),
        notice("keys not compared: partitioned target", reason="partitioned target",
               structure="keys"),
    ]  # fmt: skip
    db = ReconcileResult([TableResult("public.t", "matched", 5, 5, structure_differences=1)],
                         structure={"nullability": True})  # fmt: skip
    report = build_report(run_id="r", project="p", mode="reconcile", started_at="t",
                          finished_at="t", db=db, findings=findings, metadata={},
                          range_block={"structure": db.structure})  # fmt: skip
    assert report["verdict"] == "failed"
    assert report["tables"][0]["structure_differences"] == 1
    assert report["coverage"]["exclusions"] == [
        {"object": "public.t", "column": None, "reason": "not a B-tree index",
         "structure": "indexes", "index": "t_tags_idx"},
        {"object": "public.t", "column": None, "reason": "partitioned target", "structure": "keys"},
    ]  # fmt: skip
    html = render_html(report)
    assert "(structure differs)" in html
    assert "<td>index t_tags_idx</td><td>not a B-tree index</td>" in html
    assert "<td>keys</td><td>partitioned target</td>" in html
