"""Planning tables with XML columns (Technical Spec 9.4, 9.6), no database needed."""

from liftproof.adapters.base import Column, TableRef, TableSchema
from liftproof.canonical import CanonicalType as T
from liftproof.reconcile.baseline import BaselineTable
from liftproof.reconcile.plan import NOT_CANONICALISABLE, NOT_IN_BASELINE, plan_table


def _schema(*columns, pk=("id",), schema="public"):
    return TableSchema(
        TableRef(schema, "docs"), [Column(n, nt, t) for n, nt, t in columns], list(pk)
    )


def _plan(source, target, **kw):
    return plan_table(source, target, rows=10, rows_per_bucket=5, precision=6, ignore=[], **kw)


ID = ("id", "integer", T.INTEGER)


def test_xml_columns_are_hashed():
    tp = _plan(_schema(ID, ("DOC", "XMLTYPE", T.XML)), _schema(ID, ("doc", "xml", T.XML)))
    assert tp.plan.columns == [("DOC", T.XML), ("id", T.INTEGER)]
    assert not tp.issues and not tp.partial
    assert tp.plan.key_columns == ["id"]


def test_xml_against_text_is_a_type_change():
    tp = _plan(_schema(ID, ("doc", "XMLTYPE", T.XML)), _schema(ID, ("doc", "longtext", T.TEXT)))
    [issue] = tp.issues
    assert issue.issue == "type_changed" and tp.plan.columns == [("id", T.INTEGER)]


def test_unhashed_columns_are_left_out_with_their_reason():
    source = _schema(ID, ("doc", "xml", T.XML), ("note", "text", T.TEXT))
    target = _schema(ID, ("doc", "xml", T.XML), ("note", "text", T.TEXT))
    unhashed = {"doc": (NOT_CANONICALISABLE, "not well-formed XML: ...")}
    tp = _plan(source, target, unhashed=unhashed)
    [issue] = tp.issues
    assert (issue.column, issue.issue, issue.detail) == ("doc", *unhashed["doc"])
    assert (issue.source_type, issue.target_type) == ("xml", "xml")
    assert tp.plan.columns == [("id", T.INTEGER), ("note", T.TEXT)]
    assert tp.excluded_columns == ["doc"] and tp.partial
    # planning a baseline: no target yet
    tp = _plan(source, None, unhashed=unhashed)
    assert [i.issue for i in tp.issues] == [NOT_CANONICALISABLE]
    assert tp.plan.columns == [("id", T.INTEGER), ("note", T.TEXT)]


def _old_entry(native, canonical):
    """A baseline table taken before XML was compared (canonical revision 1)."""
    plan = {"columns": [["ID", "integer"]], "key_columns": ["ID"], "buckets": 2, "precision": 6}
    return BaselineTable.from_dict(
        "APP.DOCS",
        {
            "columns": [["ID", "NUMBER(10)", "integer", False], ["DOC", native, canonical, False]],
            "primary_key": ["ID"],
            "plan": plan,
            "row_count": 10,
            "bucket_aggregates": {"0": [5, "1"], "1": [5, "2"]},
            "completed_at": "2026-10-01T00:00:00+00:00",
            "canonical_revision": 1,
        },
    )


def test_a_baseline_from_before_xml_keeps_its_plan_and_says_why():
    entry = _old_entry("XMLTYPE", "unsupported")
    target = _schema(("id", "bigint", T.INTEGER), ("doc", "xml", T.XML))
    tp = _plan(entry.schema, target, unhashed=entry.unhashed)
    [issue] = tp.issues
    assert issue.issue == NOT_IN_BASELINE and "canonical revision 2" in issue.detail
    # not a type change, and the baseline's aggregates still apply
    assert tp.plan.columns == entry.plan.columns and tp.plan.key_columns == ["ID"]
    # a target that retyped the column is still a type change, as against a live source
    text = _schema(("id", "bigint", T.INTEGER), ("doc", "text", T.TEXT))
    [issue] = _plan(entry.schema, text, unhashed=entry.unhashed).issues
    assert issue.issue == "type_changed"


def test_an_unsupported_reference_column_migrated_to_xml_stays_a_type_change():
    # Oracle LONG (never compared) moved into an xml column: no baseline left it out
    entry = _old_entry("LONG", "unsupported")
    assert entry.unhashed == {}
    target = _schema(("id", "bigint", T.INTEGER), ("doc", "xml", T.XML))
    [issue] = _plan(entry.schema, target, unhashed=entry.unhashed).issues
    assert issue.issue == "type_changed"
    source = _schema(ID, ("doc", "LONG", T.UNSUPPORTED))
    [issue] = _plan(source, target).issues
    assert issue.issue == "type_changed"


def test_an_xml_business_key_buckets_on_the_whole_row():
    source = _schema(ID, ("doc", "xml", T.XML))
    tp = _plan(source, source, business_key=["doc"])
    assert tp.plan.key_columns == []
    assert tp.key_source == "none (an xml column cannot be a key; bucketed on the whole row)"
    assert _plan(source, source, business_key=["id"]).key_source == "declared business key"
