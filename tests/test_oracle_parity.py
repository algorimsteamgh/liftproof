"""Oracle pushdown against the reference implementation (Technical Spec 19).

The in-database hash (with the rows Oracle cannot render exactly routed to the
application side) must be byte identical to hashing every row through the reference
implementation.
"""

import datetime as dt
import uuid
from decimal import Decimal

import pytest

from liftproof.adapters.base import HashPlan, TableRef
from liftproof.adapters.oracle import OracleAdapter, _pushable_sql, canonical_type
from liftproof.canonical import CanonicalType as T
from liftproof.canonical import render

pytestmark = pytest.mark.oracle

DDL = """
CREATE TABLE everything (
  id      NUMBER(19) PRIMARY KEY,
  i2      NUMBER(5),
  num     NUMBER(12,4),
  anynum  NUMBER,
  flag    BOOLEAN,
  label   VARCHAR2(4000),
  nlabel  NVARCHAR2(50),
  code    CHAR(6),
  ncode   NCHAR(4),
  day     DATE,
  naive   TIMESTAMP(6),
  nano    TIMESTAMP(9),
  aware   TIMESTAMP(6) WITH TIME ZONE,
  loc     TIMESTAMP(6) WITH LOCAL TIME ZONE,
  blob_   RAW(2000),
  weight  BINARY_DOUBLE
)"""

INSERT = "INSERT INTO everything VALUES (" + ", ".join(f":{i}" for i in range(1, 17)) + ")"

ROWS = [
    (
        1,
        7,
        Decimal("10.5"),
        Decimal("123.4500"),
        True,
        "cafe",
        "plain",
        "AB",
        "N",
        dt.datetime(2026, 1, 31, 13, 14, 15),
        dt.datetime(2026, 9, 25, 11, 2, 41, 123456),
        dt.datetime(2026, 9, 25, 11, 2, 41, 999999),
        dt.datetime(2026, 9, 25, 16, 32, 41, 500000),
        dt.datetime(2026, 1, 1),
        bytes.fromhex("00ff10"),
        1.5,
    ),
    (
        2,
        -1,
        Decimal("-0.5"),
        Decimal("-0.000001"),
        False,
        "café",
        "café",
        "X     ",
        "    ",
        dt.datetime(1999, 12, 31),
        dt.datetime(2000, 1, 1),
        dt.datetime(2000, 1, 1),
        dt.datetime(2000, 1, 1, 0, 0, 1),
        dt.datetime(1970, 1, 1, 0, 0, 1),
        b"",
        0.0,
    ),
    (3,) + (None,) * 15,
    (
        4,
        0,
        Decimal("12345678.9"),
        Decimal("1E-50"),
        True,
        "tab\there\\Nsep",
        "naïve",
        "      ",
        "ab",
        dt.datetime(2026, 2, 28, 23, 59, 59),
        dt.datetime(2038, 1, 19, 3, 14, 7),
        dt.datetime(2026, 2, 28, 23, 59, 59, 999999),
        dt.datetime(2026, 2, 28, 23, 59, 59),
        dt.datetime(2026, 2, 28),
        bytes.fromhex("deadbeef"),
        float("nan"),
    ),
    (
        5,
        32767,
        Decimal("0.0001"),
        Decimal("98765432109876543210987654321098765432"),
        False,
        "x" * 4000,
        "z",
        "Z",
        "z",
        dt.datetime(1901, 1, 1),
        dt.datetime(1901, 1, 1, 1),
        dt.datetime(1901, 1, 1, 1),
        dt.datetime(1901, 1, 1, 1),
        dt.datetime(1901, 1, 1, 1),
        bytes(range(256)) * 7 + bytes(206),
        float("inf"),
    ),
    (  # plain ASCII at every limit: rendered by Oracle itself
        6,
        -3,
        Decimal("-0.5"),
        Decimal("-0.000001"),
        False,
        "y" * 3990,
        "q",
        "      ",
        "    ",
        dt.datetime(2000, 2, 29, 12),
        dt.datetime(2000, 2, 29, 12, 0, 0, 1),
        dt.datetime(2000, 2, 29, 12, 0, 0, 120000),
        dt.datetime(2000, 2, 29, 23, 59, 59, 999999),
        dt.datetime(2000, 2, 29, 12),
        bytes(range(256)) * 7 + bytes(203),
        -1.0,
    ),
]

COLUMNS = [
    ("anynum", T.DECIMAL),
    ("aware", T.TIMESTAMPTZ),
    ("blob_", T.BINARY),
    ("code", T.CHAR),
    ("day", T.TIMESTAMP),
    ("flag", T.BOOLEAN),
    ("i2", T.INTEGER),
    ("id", T.INTEGER),
    ("label", T.TEXT),
    ("loc", T.TIMESTAMPTZ),
    ("nano", T.TIMESTAMP),
    ("naive", T.TIMESTAMP),
    ("ncode", T.CHAR),
    ("nlabel", T.TEXT),
    ("num", T.DECIMAL),
]


def _upper(columns):
    return [(n.upper(), t) for n, t in columns]


@pytest.fixture
def loaded(make_oracle_db, oracle_adapter_for):
    schema, cur = make_oracle_db()
    import oracledb

    cur.execute(DDL)
    ts = oracledb.DB_TYPE_TIMESTAMP  # a datetime binds as DATE by default: no fraction
    cur.setinputsizes(*[None] * 10, ts, ts, ts, ts, None, oracledb.DB_TYPE_BINARY_DOUBLE)
    cur.executemany(INSERT, ROWS)
    # zone aware values stored with an offset other than UTC
    cur.execute(
        "UPDATE everything SET aware = FROM_TZ(TIMESTAMP '2026-09-25 11:02:41.5', '+05:30') "
        "WHERE id = 1"
    )
    return oracle_adapter_for(), schema


@pytest.mark.parametrize("precision", [0, 3, 6])
@pytest.mark.parametrize("keyed", [True, False])
def test_pushdown_matches_reference(loaded, precision, keyed):
    a, schema = loaded
    table = TableRef(schema, "EVERYTHING")
    plan = HashPlan(table, _upper(COLUMNS), ["ID"] if keyed else [], 3, precision)
    assert a._pushdown(plan)
    pushed = a.bucket_aggregates(plan)
    reference = a._bucket_aggregates_fallback(plan)
    assert pushed == reference
    assert sum(b.count for b in pushed.values()) == 6

    rows_push = sorted(a.row_hashes(plan, set(range(3))))
    a._pushdown = lambda p: False
    rows_ref = sorted(a.row_hashes(plan, set(range(3))))
    assert rows_push == rows_ref
    assert len(rows_push) == 6


def test_rows_oracle_cannot_render_take_the_reference_path(loaded):
    """Rows 1, 3 and 6 are plain ASCII, short enough, and printable without an exponent."""
    a, schema = loaded
    plan = HashPlan(TableRef(schema, "EVERYTHING"), _upper(COLUMNS), ["ID"], 1)
    pushable = _pushable_sql(plan.columns)
    q = f'SELECT "ID" FROM "{schema}"."EVERYTHING" WHERE {pushable} ORDER BY 1'
    assert [int(r[0]) for r in a._query(q)] == [1, 3, 6]


def test_values_render_canonically(loaded):
    a, schema = loaded
    plan = HashPlan(TableRef(schema, "EVERYTHING"), _upper(COLUMNS), ["ID"], 1)
    rows = a.fetch_rows(plan, [("1",), ("2",), ("4",)])
    names = [n for n, _ in COLUMNS]
    one = dict(zip(names, rows[("1",)], strict=True))
    assert render(one["aware"], T.TIMESTAMPTZ) == "2026-09-25T05:32:41.500000"
    assert render(one["day"], T.TIMESTAMP, precision=3) == "2026-01-31T13:14:15.000"
    assert render(one["nano"], T.TIMESTAMP) == "2026-09-25T11:02:41.999999"
    assert render(one["anynum"], T.DECIMAL) == "123.45"
    two = dict(zip(names, rows[("2",)], strict=True))
    assert render(two["num"], T.DECIMAL) == "-0.5"
    assert render(two["code"], T.CHAR) == "X"
    assert render(two["ncode"], T.CHAR) == ""  # all spaces: empty, not NULL
    four = dict(zip(names, rows[("4",)], strict=True))
    assert render(four["anynum"], T.DECIMAL) == "0." + "0" * 49 + "1"


def test_lob_and_json_columns_hash_like_their_short_forms(make_oracle_db, oracle_adapter_for):
    schema, cur = make_oracle_db()
    cur.execute(
        "CREATE TABLE docs (id NUMBER(9) PRIMARY KEY, v VARCHAR2(100), c CLOB, n NCLOB, "
        "r RAW(100), b BLOB, j JSON, jt VARCHAR2(200))"
    )
    cur.executemany(
        "INSERT INTO docs VALUES (:i, :t, :t, :t, :r, :r, :j, :j)",
        [
            {"i": 1, "t": "café latte", "r": b"\x01\x02", "j": '{"b": [1, 2], "a": "é"}'},
            {"i": 2, "t": "plain", "r": b"", "j": '{"a":1}'},
            {"i": 3, "t": None, "r": None, "j": None},
        ],
    )
    a = oracle_adapter_for()
    schema_ = a.describe(TableRef(schema, "DOCS"))
    types = {c.name: c.canonical for c in schema_.columns}
    assert types == {
        "ID": T.INTEGER,
        "V": T.TEXT,
        "C": T.TEXT,
        "N": T.TEXT,
        "R": T.BINARY,
        "B": T.BINARY,
        "J": T.JSON,
        "JT": T.TEXT,
    }

    def agg(col, ctype):
        plan = HashPlan(TableRef(schema, "DOCS"), [("ID", T.INTEGER), (col, ctype)], ["ID"], 2)
        return a.bucket_aggregates(plan)

    assert agg("V", T.TEXT) == agg("C", T.TEXT) == agg("N", T.TEXT)
    assert agg("R", T.BINARY) == agg("B", T.BINARY)
    assert agg("J", T.JSON) == agg("JT", T.JSON)


def test_describe_maps_types(loaded):
    a, schema = loaded
    s = a.describe(TableRef(schema, "EVERYTHING"))
    assert s.primary_key == ["ID"]
    got = {c.name: c.canonical for c in s.columns}
    assert got == dict(_upper(COLUMNS)) | {"WEIGHT": T.FLOAT}
    natives = {c.name: c.native_type for c in s.columns}
    assert natives["NUM"] == "NUMBER(12,4)" and natives["ID"] == "NUMBER(19)"
    assert natives["ANYNUM"] == "NUMBER" and natives["CODE"] == "CHAR(6)"


def test_canonical_type_rules():
    assert canonical_type("NUMBER", None, 0) is T.INTEGER  # INTEGER
    assert canonical_type("NUMBER", 5, -2) is T.INTEGER
    assert canonical_type("NUMBER", None, None) is T.DECIMAL
    assert canonical_type("FLOAT", 126, None) is T.FLOAT
    assert canonical_type("TIMESTAMP(3) WITH LOCAL TIME ZONE", None, 3) is T.TIMESTAMPTZ
    assert canonical_type("INTERVAL DAY(2) TO SECOND(6)", None, None) is T.UNSUPPORTED
    assert canonical_type("LONG", None, None) is T.UNSUPPORTED


def test_float_stats_counts_nan_and_infinity(loaded):
    a, schema = loaded
    s = a.float_stats(TableRef(schema, "EVERYTHING"), "WEIGHT")
    assert (s.count, s.non_null, s.nan_count, s.inf_count) == (6, 5, 1, 1)
    assert (s.minimum, s.maximum, s.total) == (-1.0, 1.5, 0.5)


def test_snapshot_and_session(loaded):
    a, _ = loaded
    snap = a.begin_snapshot()
    assert snap["type"] == "scn" and int(snap["position"]) > 0
    assert snap["exact"] is False
    a.end_snapshot()
    s = a.session_settings()
    assert s["TIME_ZONE"] == "+00:00"
    assert s["snapshot"] == "SET TRANSACTION READ ONLY"


def test_read_only_session_refuses_writes(loaded):
    import oracledb

    a, schema = loaded
    a.begin_snapshot()
    with pytest.raises(oracledb.Error, match="ORA-01456"):
        a._query(f'DELETE FROM "{schema}"."EVERYTHING"')
    a.end_snapshot()


def test_verify_read_only_reads_the_dictionary(make_oracle_db, oracle_adapter_for):
    from tests.conftest import ORA, _ora_connect

    def login(user, pw):
        return OracleAdapter(
            host=ORA["host"],
            port=ORA["port"],
            database=ORA["service"],
            user=user,
            password=pw,
            sslmode="disable",
        )

    schema, cur = make_oracle_db()
    cur.execute("CREATE TABLE t (id NUMBER PRIMARY KEY)")
    assert not oracle_adapter_for().verify_read_only()  # the test login is SYSTEM
    user, pw = f"LP_RO_{uuid.uuid4().hex[:6]}".upper(), "Ro" + uuid.uuid4().hex
    with _ora_connect() as c, c.cursor() as admin:
        admin.execute(f'CREATE USER "{user}" IDENTIFIED BY "{pw}"')
        admin.execute(f'GRANT CREATE SESSION TO "{user}"')
        admin.execute(f'GRANT SELECT ON "{schema}"."T" TO "{user}"')
        try:
            ro = login(user, pw)
            try:
                assert ro.verify_read_only()
                assert ro.list_tables([schema]) == [TableRef(schema, "T")]
            finally:
                ro.close()
            admin.execute(f'GRANT INSERT ON "{schema}"."T" TO "{user}"')
            rw = login(user, pw)
            try:
                assert not rw.verify_read_only()
            finally:
                rw.close()
        finally:
            admin.execute(f'DROP USER "{user}" CASCADE')
