"""Pushdown against fallback parity (Technical Spec 19).

The application side hash must produce byte identical values to the PostgreSQL
pushdown, for every type rule.
"""

from decimal import Decimal

import pytest

from liftproof.adapters.base import ForeignKey, HashPlan, Index, TableRef
from liftproof.adapters.postgres import PostgresAdapter
from liftproof.canonical import CanonicalType as T
from liftproof.canonical import RenderError, Verbatim
from liftproof.reconcile import ranges

pytestmark = pytest.mark.postgres

DDL = """
CREATE TABLE everything (
  id        bigint PRIMARY KEY,
  i2        smallint,
  num       numeric(12,4),
  flag      boolean,
  label     text,
  code      char(6),
  day       date,
  at_time   time(3),
  naive     timestamp(6),
  aware     timestamptz,
  blob      bytea,
  ref       uuid
);
INSERT INTO everything VALUES
 (1, 7, 10.5000, true, 'caf' || 'é', 'AB', '2026-01-31', '13:14:15.123',
  '2026-09-25 11:02:41.123456', '2026-09-25 13:02:41.5+02', '\\x00ff10',
  'A0EEBC99-9C0B-4EF8-BB6D-6BB9BD380A11'),
 (2, -1, -0.0000, false, 'cafe' || U&'\\0301', 'X     ', '1999-12-31', '00:00:00',
  '2000-01-01 00:00:00', '2000-01-01 00:00:00+00', '', '00000000-0000-0000-0000-000000000000'),
 (3, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL),
 (4, 0, 'NaN', true, E'tab\\there\\u001fsep', '', '2026-02-28', '23:59:59.999',
  '2026-02-28 23:59:59.999999', '2026-02-28 23:59:59.999999-05', '\\xdeadbeef', NULL),
 (5, 32767, 12345678.9, false, '\\N', 'Z', '0001-01-01', '12:00', '1970-01-01', '1970-01-01+00',
  '\\x5c4e', NULL),
 (6, 1, 1, true, 'x', 'x', 'infinity', '00:00', '-infinity', 'infinity', NULL, NULL),
 (7, 2, 2, false, 'y', 'y', '-infinity', '00:00', 'infinity', '-infinity', NULL, NULL);
"""

COLUMNS = [
    ("aware", T.TIMESTAMPTZ), ("at_time", T.TIME), ("blob", T.BINARY), ("code", T.CHAR),
    ("day", T.DATE), ("flag", T.BOOLEAN), ("i2", T.INTEGER), ("id", T.INTEGER),
    ("label", T.TEXT), ("naive", T.TIMESTAMP), ("num", T.DECIMAL), ("ref", T.UUID),
]


@pytest.mark.parametrize("precision", [0, 3, 6])
@pytest.mark.parametrize("keyed", [True, False])
def test_pushdown_matches_fallback(make_db, adapter_for, precision, keyed):
    db, conn = make_db()
    conn.execute(DDL)
    a: PostgresAdapter = adapter_for(db)
    plan = HashPlan(TableRef("public", "everything"), COLUMNS, ["id"] if keyed else [], 3,
                    precision)
    pushed = a.bucket_aggregates(plan)
    fallback = a._bucket_aggregates_fallback(plan)
    assert pushed == fallback
    assert sum(b.count for b in pushed.values()) == 7

    rows_push = sorted(a.row_hashes(plan, set(range(3))))
    plan_json = HashPlan(plan.table, plan.columns, plan.key_columns, 3, precision)
    a._pushdown = lambda p: False  # force the fallback path
    rows_fb = sorted(a.row_hashes(plan_json, set(range(3))))
    assert rows_push == rows_fb


def test_describe_maps_types(make_db, adapter_for):
    db, conn = make_db()
    conn.execute(DDL)
    schema = adapter_for(db).describe(TableRef("public", "everything"))
    assert schema.primary_key == ["id"]
    got = {c.name: c.canonical for c in schema.columns}
    assert got == dict(COLUMNS)


def test_describe_reads_nullability_keys_and_indexes(make_db, adapter_for):
    db, conn = make_db()
    conn.execute("""
    CREATE TABLE parent (id int PRIMARY KEY, code text, UNIQUE (code, id));
    CREATE TABLE period (id int, at date, PRIMARY KEY (id, at)) PARTITION BY RANGE (at);
    CREATE TABLE period_2026 PARTITION OF period FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
    CREATE TABLE child (b int, a int, c text NOT NULL, h text, tags int[], at date, pid int,
      pcode text, PRIMARY KEY (a, b), UNIQUE (b, a, c),
      FOREIGN KEY (pcode, pid) REFERENCES parent (code, id),
      FOREIGN KEY (pid, at) REFERENCES period);
    CREATE INDEX ix_c ON child (c DESC) INCLUDE (h);
    CREATE INDEX ix_expr ON child (lower(c), a);
    CREATE INDEX ix_part ON child (a) WHERE a > 0;
    CREATE INDEX ix_gin ON child USING gin (tags);
    CREATE INDEX ix_brin ON child USING brin (at);
    """)
    s = adapter_for(db).describe(TableRef("public", "child"))
    assert s.primary_key == ["a", "b"]  # in key order
    assert [c.name for c in s.columns if not c.nullable] == ["b", "a", "c"]
    assert s.indexes == [
        Index("child_b_a_c_key", ("b", "a", "c"), True),
        Index("ix_brin", ("at",), False, "other"),
        Index("ix_c", ("c",), False),  # INCLUDE columns are not keys
        Index("ix_expr", (), False, "expression"),
        Index("ix_gin", ("tags",), False, "other"),
        Index("ix_part", ("a",), False, "partial"),
    ]
    # one foreign key to the partitioned table, not one more per partition
    assert s.foreign_keys == [
        ForeignKey("child_pcode_pid_fkey", ("pcode", "pid"), TableRef("public", "parent"),
                   ("code", "id")),
        ForeignKey("child_pid_at_fkey", ("pid", "at"), TableRef("public", "period"),
                   ("id", "at")),
    ]  # fmt: skip


def test_infinity_is_not_null(make_db, adapter_for):
    """to_char renders infinity as NULL and psycopg cannot load it: neither may make it
    NULL, nor fail a read."""
    db, conn = make_db()
    conn.execute(
        "CREATE TABLE spans (id int PRIMARY KEY, d date, ts timestamp(3), tz timestamptz);"
        "INSERT INTO spans VALUES (1, 'infinity', 'infinity', 'infinity'),"
        " (2, '-infinity', '-infinity', '-infinity'), (3, NULL, NULL, NULL),"
        " (4, '2026-10-01', '2026-10-01 12:00', '2026-10-01 12:00+00')"
    )
    a = adapter_for(db)
    table = TableRef("public", "spans")
    cols = [("d", T.DATE), ("id", T.INTEGER), ("ts", T.TIMESTAMP), ("tz", T.TIMESTAMPTZ)]
    plan = HashPlan(table, cols, ["id"], 1, 3)
    dates = HashPlan(table, [c for c in cols if c[0] != "id"], [], 1, 3)
    assert len({h for _, h in a.row_hashes(dates, {0})}) == 4
    schema = a.describe(table)
    assert ranges.read(a, table, schema, ["d", "ts", "tz"], None) == {
        "d": ["-infinity", "infinity"],
        "ts": ["-infinity", "infinity"],
        "tz": ["-infinity", "infinity"],
    }
    rows = a.fetch_rows(plan, [("1",), ("2",), ("3",)])
    assert rows[("1",)] == [Verbatim("infinity"), 1, "infinity", "infinity"]
    assert rows[("2",)][0] == "-infinity" and isinstance(rows[("2",)][3], Verbatim)
    assert rows[("3",)] == [None, 3, None, None]

    # infinity as a key: rendered alike in the hash and in the drill-down's IN list
    keyed = HashPlan(table, cols, ["d"], 1, 3)
    keys = sorted(k for k, _ in a.row_hashes(keyed, {0}) if k != (None,))
    assert keys == [("-infinity",), ("2026-10-01",), ("infinity",)]
    assert set(a.fetch_rows(keyed, keys)) == set(keys)

    # PostgreSQL 14 and later: numeric Infinity as a key's range
    conn.execute("CREATE TABLE amounts (n numeric PRIMARY KEY);"
                 "INSERT INTO amounts VALUES (1), ('Infinity')")  # fmt: skip
    amounts = TableRef("public", "amounts")
    assert ranges.read(a, amounts, a.describe(amounts), ["n"], None) == {"n": [1, "Infinity"]}
    assert a.value_ranges(amounts, ["n"])["n"][1] == Decimal("Infinity")


XHTML = (
    '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" '
    '"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"><html>&nbsp;</html>'
)


def test_xml_is_hashed_here_like_its_canonical_text(make_db, adapter_for):
    """xml values reach the reference implementation as PostgreSQL stores them: content
    (fragments) as well as documents, and hash like the canonical text they render to."""
    db, conn = make_db()
    conn.execute("CREATE TABLE docs (id int PRIMARY KEY, doc xml, canon text)")
    with conn.cursor() as cur:
        cur.executemany("INSERT INTO docs VALUES (%s, %s, %s)", [
            (1, "<a b='2' a=\"1\">\n  <x/>\n  <y>t</y></a>", '<a a="1" b="2"><x></x><y>t</y></a>'),
            (2, "<a/><b/>text", "<a></a><b></b>text"),
            (3, None, None),
            (4, '<!DOCTYPE a [<!ENTITY e "hi">]><a>&e;<!-- c --></a>', "<a>hi</a>"),
            (5, "", ""),
            (6, '<p xmlns="urn:p"><![CDATA[<&>]]></p>', '<p xmlns="urn:p">&lt;&amp;&gt;</p>'),
        ])  # fmt: skip
    a = adapter_for(db)
    table = TableRef("public", "docs")
    assert {c.name: c.canonical for c in a.describe(table).columns} == {
        "id": T.INTEGER, "doc": T.XML, "canon": T.TEXT,
    }  # fmt: skip
    as_xml = HashPlan(table, [("doc", T.XML), ("id", T.INTEGER)], ["id"], 4)
    as_text = HashPlan(table, [("canon", T.TEXT), ("id", T.INTEGER)], ["id"], 4)
    aggregates = a.bucket_aggregates(as_xml)
    assert aggregates == a.bucket_aggregates(as_text)  # the text pushed down, xml here
    assert sorted(a.row_hashes(as_xml, {0, 1, 2, 3})) == sorted(a.row_hashes(as_text, {0, 1, 2, 3}))
    sampled = HashPlan(table, as_xml.columns, ["id"], 4, sample=(1, 3))
    assert a.bucket_aggregates(sampled) == {b: aggregates[b] for b in (1, 3) if b in aggregates}
    assert a.fetch_rows(as_xml, [("2",)]) == {("2",): ["<a/><b/>text", 2]}

    # a value expat cannot parse: an external DTD's entity, which PostgreSQL accepts
    conn.execute("INSERT INTO docs VALUES (7, %s, NULL)", (XHTML,))
    with pytest.raises(RenderError, match="^column doc: not well-formed XML") as caught:
        a.bucket_aggregates(as_xml)
    assert caught.value.column == "doc" and "nbsp" in caught.value.reason
    # the stream was closed: the connection reads on
    assert a.bucket_aggregates(as_text) == a.bucket_aggregates(as_text)
