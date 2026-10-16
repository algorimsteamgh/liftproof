"""A single-byte Oracle source against a UTF-8 target (Technical Spec 19 and 9.3).

The same data in a WE8MSWIN1252 Oracle database and a UTF8 PostgreSQL database must give
identical hashes. Only plain ASCII rows are hashed inside Oracle, where their bytes are
UTF-8 too; python-oracledb asks for AL32UTF8, so Oracle transcodes every other row before
the reference implementation hashes it. A gate that counted bytes against characters
would pass every AL32UTF8 test and hash Windows-1252 bytes here.

These tests run in the main suite against its AL32UTF8 server, where the ones that only
mean something when every character is one byte skip. The charset workflow
(.github/workflows/charset.yml) runs them, with tests/test_oracle_parity.py, against
Oracle's own Free image created in WE8MSWIN1252. Locally:

    docker run -d --name lp-oracle-1252 -p 127.0.0.1:1522:1521 \\
      -e ORACLE_PWD=ci-only-local-service -e ORACLE_CHARACTERSET=WE8MSWIN1252 \\
      container-registry.oracle.com/database/free:23.26.0.0
    LIFTPROOF_TEST_ORACLE_PORT=1522 LIFTPROOF_TEST_ORACLE_CHARSET=WE8MSWIN1252 \\
      pytest tests/test_charset_oracle.py tests/test_oracle_parity.py

LIFTPROOF_TEST_ORACLE_CHARSET turns a server that is missing or in another character set
into a failure (tests/conftest.py). VARCHAR2, CHAR and CLOB values use only characters
Windows-1252 defines: Oracle maps its five undefined bytes differently from Python.
"""

import pytest

from liftproof.adapters import oracle
from liftproof.adapters.base import HashPlan, TableRef
from liftproof.canonical import CanonicalType as T
from liftproof.canonical import column_digest, render
from liftproof.findings import FindingWriter, Kind, read_findings
from liftproof.reconcile.engine import ReconcileOptions, Reconciler
from liftproof.reconcile.plan import plan_table

pytestmark = [pytest.mark.postgres, pytest.mark.oracle]

SINGLE = "WE8MSWIN1252"
N = 1200
# the 123 characters Windows-1252 has beyond ASCII, and their canonical digest as one value
CP = bytes(b for b in range(0x80, 0x100) if b not in {0x81, 0x8D, 0x8F, 0x90, 0x9D}).decode(
    "cp1252"
)
GOLDEN = "01453c2597defb988d9ac5722020ed2c"

ORA_DDL = """
CREATE TABLE items (
  code VARCHAR2(20) PRIMARY KEY, name VARCHAR2(4000), fixed CHAR(8), nname NVARCHAR2(40),
  body CLOB, n NUMBER(9)
)"""

PG_DDL = """
CREATE TABLE items (
  code text PRIMARY KEY, name text, fixed char(8), nname text, body text, n integer
)"""

COLUMNS = [("CODE", T.TEXT), ("NAME", T.TEXT), ("FIXED", T.CHAR), ("NNAME", T.TEXT),
           ("N", T.INTEGER)]  # fmt: skip


def _code(i: int) -> str:
    return f"K{i}" if i % 3 == 0 else f"{CP[i % len(CP)]}-{i}"  # most keys are not ASCII


def _rows():
    """Row 12's name is ASCII at the pushdown limit; row 7's is every character; row 8's is
    set afterwards (_long), on both engines alike."""
    for i in range(1, N + 1):
        ch = CP[i % len(CP)]
        name = [f"plain {i}", f"Café crème {i} – “{ch}” €", f"back\\slash {i}", CP][i % 4]
        name = "y" * 3990 if i == 12 else "-" if i == 8 else name
        yield (
            _code(i),
            name,
            None if i % 7 == 0 else ("Été" if i % 2 else "ab"),
            None if i % 5 == 0 else ("Ω ☕ ā" if i % 2 else "plain"),  # outside Windows-1252
            name,
            i,
        )


def _long(charset: str) -> int:
    """Row 8's name and body: '€' this many times. 4000 fills a VARCHAR2(4000) in one byte
    per character and grows to 12,000 bytes when read as UTF-8; three bytes each, 1333."""
    return 4000 if charset == SINGLE else 1333


@pytest.fixture
def loaded(oracle_available, make_oracle_db, oracle_adapter_for, make_db, adapter_for):
    """(Oracle adapter, its schema, its cursor, PostgreSQL adapter, its connection,
    the Oracle character set)"""
    import oracledb

    rows = list(_rows())
    long = _long(oracle_available)
    schema, oc = make_oracle_db("cs")
    oc.execute(ORA_DDL)
    with oc.connection.cursor() as cur:  # NNAME bound as NVARCHAR, so Ω survives
        cur.setinputsizes(None, None, None, oracledb.DB_TYPE_NVARCHAR, None, None)
        cur.executemany("INSERT INTO items VALUES (:1, :2, :3, :4, :5, :6)", rows)
    # a bind of 12,000 UTF-8 bytes is too long for a VARCHAR2, so Oracle builds the value
    oc.execute("UPDATE items SET name = RPAD('€', :n, '€'), body = RPAD('€', :n, '€') "
               "WHERE n = 8", {"n": long})  # fmt: skip
    db, pc = make_db("cs")
    pc.execute(PG_DDL)
    with pc.cursor() as cur:
        cur.executemany("INSERT INTO items VALUES (%s, %s, %s, %s, %s, %s)", rows)
    pc.execute("UPDATE items SET name = repeat('€', %s), body = repeat('€', %s) WHERE n = 8",
               (long, long))  # fmt: skip
    return oracle_adapter_for(), schema, oc, adapter_for(db), pc, oracle_available


def _plan(schema, columns=COLUMNS, keys=("CODE",), buckets=7):
    return HashPlan(TableRef(schema, "ITEMS"), list(columns), list(keys), buckets)


def _pg(plan):
    return HashPlan(TableRef("public", "items"), [(n.lower(), t) for n, t in plan.columns],
                    [k.lower() for k in plan.key_columns], plan.buckets)  # fmt: skip


def test_the_server_stores_one_byte_per_character(loaded):
    a, schema, oc, _, _, charset = loaded
    if charset != SINGLE:
        pytest.skip(f"the Oracle test server is {charset}")
    oc.execute("SELECT MAX(LENGTHB(name) - LENGTH(name)), MAX(LENGTHB(name)) FROM items")
    assert oc.fetchone() == (0, 4000)


def test_the_gate_admits_only_ascii_rows(loaded):
    a, schema, _, _, _, _ = loaded
    text = [i for i, (_, t) in enumerate(COLUMNS) if t in oracle.TEXT_TYPES]
    expected = {
        row[-1]
        for row in _rows()
        if row[-1] != 8
        and all(row[i] is None or (row[i].isascii() and "\\" not in row[i]) for i in text)
    }
    pushable = oracle._pushable_sql(COLUMNS)
    found = a._query(f'SELECT "N" FROM "{schema}"."ITEMS" WHERE {pushable}')
    assert {int(n) for (n,) in found} == expected
    assert 12 in expected  # 3990 ASCII characters are still hashed in Oracle


def test_a_byte_count_gate_is_caught_only_here(loaded, monkeypatch):
    """The rule spec 19 fears: a gate that counts bytes against characters admits é where
    each character is one byte, and STANDARD_HASH then hashes the Windows-1252 byte."""
    a, schema, _, _, _, charset = loaded

    def byte_count_gate(columns):
        parts = [
            f"({oracle.quote(n)} IS NULL OR (LENGTHB({oracle.quote(n)}) = "
            f"LENGTH({oracle.quote(n)}) AND LENGTH({oracle.quote(n)}) <= {oracle.MAX_TEXT}))"
            for n, t in columns
            if t in oracle.TEXT_TYPES
        ]
        return " AND ".join(parts) or None

    plan = _plan(schema, [c for c in COLUMNS if c[0] != "NNAME"])
    reference = a._bucket_aggregates_fallback(plan)
    monkeypatch.setattr(oracle, "_pushable_sql", byte_count_gate)
    if charset == SINGLE:
        assert a.bucket_aggregates(plan) != reference
    else:  # what every AL32UTF8 test sees: nothing wrong
        assert a.bucket_aggregates(plan) == reference


@pytest.mark.parametrize("keys", [("CODE",), ()])
def test_pushdown_matches_reference(loaded, keys):
    a, schema, _, _, _, _ = loaded
    plan = _plan(schema, keys=keys)
    assert a._pushdown(plan)
    pushed = a.bucket_aggregates(plan)
    assert pushed == a._bucket_aggregates_fallback(plan)
    assert sum(b.count for b in pushed.values()) == N
    # a CLOB is read through the LOB fallback, and holds the same text as NAME
    clob = _plan(schema, [("CODE", T.TEXT), ("BODY", T.TEXT)], keys)
    assert a.bucket_aggregates(clob) == a.bucket_aggregates(_plan(schema, COLUMNS[:2], keys))
    rows_push = sorted(a.row_hashes(plan, set(range(7))))
    a._pushdown = lambda p: False
    assert rows_push == sorted(a.row_hashes(plan, set(range(7))))


@pytest.mark.parametrize("keys", [("CODE",), ()])
def test_same_hashes_as_utf8_postgres(loaded, keys):
    a, schema, _, pg, _, _ = loaded
    ours, theirs = a.describe(TableRef(schema, "ITEMS")), pg.describe(TableRef("public", "items"))
    tp = plan_table(ours, theirs, rows=N, rows_per_bucket=200, precision=6, ignore=[])
    assert not tp.issues, tp.issues
    assert {n for n, _ in tp.plan.columns} == {n for n, _ in COLUMNS} | {"BODY"}
    for columns in (COLUMNS, tp.plan.columns):  # pushdown and fallback; all through the LOB
        plan = _plan(schema, columns, keys)
        assert a.bucket_aggregates(plan) == pg.bucket_aggregates(_pg(plan))
        assert sorted(a.row_hashes(plan, set(range(7)))) == sorted(
            pg.row_hashes(_pg(plan), set(range(7)))
        )


def test_a_value_of_every_windows_1252_character_has_the_golden_digest(loaded):
    a, schema, _, pg, _, _ = loaded
    plan = _plan(schema)
    for adapter, p in ((a, plan), (pg, _pg(plan))):
        [row] = adapter.fetch_rows(p, [(_code(7),)]).values()
        assert column_digest(render(row[1], T.TEXT)) == GOLDEN


def _reconcile(tmp_path, ora, schema, pg):
    writer = FindingWriter(tmp_path / "findings", "r-x")
    options = ReconcileOptions(schemas=[schema], schema_map={schema: "public"},
                               rows_per_bucket=200)  # fmt: skip
    result = Reconciler(pg, writer, options, source=ora).run()
    writer.close()
    return result, list(read_findings(tmp_path / "findings"))


def _shown(findings, table):
    """(column, key) of each value difference shown in the table."""
    return {
        (f.column.upper(), f.locator.split(" = ", 1)[1])
        for f in findings
        if f.kind == Kind.DIFFERENCE and f.column and f.object.upper().endswith(f".{table}")
    }


def test_reconcile_reports_exactly_the_injected_differences(tmp_path, loaded):
    """Keys are bound back through the single-byte database to fetch the changed rows."""
    a, schema, _, pg, pc, _ = loaded
    result, findings = _reconcile(tmp_path / "same", a, schema, pg)
    assert [t.status for t in result.tables] == ["matched"]
    assert not [f for f in findings if f.kind == Kind.DIFFERENCE]

    pc.execute("DELETE FROM items WHERE n = 17")
    pc.execute("UPDATE items SET name = replace(name, '€', 'EUR') WHERE n = 25")
    pc.execute("UPDATE items SET nname = 'Ω ☕ a' WHERE n = 31")
    result, findings = _reconcile(tmp_path / "changed", a, schema, pg)
    [items] = result.tables
    assert (items.missing_rows, items.changed_rows, items.extra_rows) == (1, 2, 0)
    assert _shown(findings, "ITEMS") == {("NAME", _code(25)), ("NNAME", _code(31))}


def test_a_national_character_key_outside_the_database_set_is_drilled_into(tmp_path, loaded):
    """An NVARCHAR2 and NCHAR key holding Ω, which WE8MSWIN1252 cannot hold: the changed
    row is fetched by its key and its column difference shown."""
    import oracledb

    a, schema, oc, pg, pc, _ = loaded
    oc.execute("CREATE TABLE nkeys (k NVARCHAR2(20), f NCHAR(4), v VARCHAR2(20), "
               "PRIMARY KEY (k, f))")  # fmt: skip
    pc.execute("CREATE TABLE nkeys (k text, f char(4), v text, PRIMARY KEY (k, f))")
    rows = [(f"Ω{i}" if i % 2 else f"plain{i}", "☕" if i % 3 else "a", f"v{i}")
            for i in range(1, 101)]  # fmt: skip
    with oc.connection.cursor() as cur:
        cur.setinputsizes(oracledb.DB_TYPE_NVARCHAR, oracledb.DB_TYPE_NVARCHAR, None)
        cur.executemany("INSERT INTO nkeys VALUES (:1, :2, :3)", rows)
    with pc.cursor() as cur:
        cur.executemany("INSERT INTO nkeys VALUES (%s, %s, %s)", rows)
    pc.execute("UPDATE nkeys SET v = 'changed' WHERE k IN ('Ω7', 'plain8', 'Ω9')")
    result, findings = _reconcile(tmp_path, a, schema, pg)
    [nkeys] = [t for t in result.tables if t.table.upper().endswith(".NKEYS")]
    assert nkeys.changed_rows == 3
    # keys in canonical order (F, K), as the locator names them
    assert _shown(findings, "NKEYS") == {("V", "☕, Ω7"), ("V", "☕, plain8"), ("V", "a, Ω9")}


class _Cursor:
    """Records what fetch_rows sends and answers with fixed rows."""

    def __init__(self, sent, rows):
        self.sent, self.rows = sent, rows

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def setinputsizes(self, *sizes):
        self.sent.append(("sizes", sizes))

    def execute(self, q, args):
        self.sent.append(("execute", q, list(args)))

    def fetchall(self):
        return self.rows


class _Conn:
    def __init__(self, rows):
        self.sent, self.rows = [], rows

    def cursor(self):
        return _Cursor(self.sent, self.rows)


def test_national_key_binds_line_up_with_their_placeholders():
    """Runs without a server: a key of VARCHAR2, NCHAR and NVARCHAR2 columns binds each
    national value, and only those, as NVARCHAR, in the order of the placeholders."""
    import oracledb

    table = TableRef("S", "T")
    a = object.__new__(oracle.OracleAdapter)
    a._natives = {table: {"CODE": "VARCHAR2", "F": "NCHAR", "K": "NVARCHAR2", "V": "VARCHAR2"}}
    a.conn = _Conn([("a", "☕", "Ω7", "a", "☕   ", "Ω7", "v7")])
    plan = HashPlan(table, [("CODE", T.TEXT), ("F", T.CHAR), ("K", T.TEXT), ("V", T.TEXT)],
                    ["CODE", "F", "K"], 1)  # fmt: skip
    rows = a.fetch_rows(plan, [("a", "☕", "Ω7"), ("b", "x", "y")])
    assert rows == {("a", "☕", "Ω7"): ["a", "☕   ", "Ω7", "v7"]}
    [(_, sizes), (_, q, args)] = a.conn.sent
    nv = oracledb.DB_TYPE_NVARCHAR
    assert sizes == (None, nv, nv, None, nv, nv)
    assert args == ["a", "☕", "Ω7", "b", "x", "y"]
    keys = 'TO_CHAR("CODE"), RTRIM("F", \' \'), "K"'
    assert q.startswith(f"SELECT {keys}, ")
    assert q.endswith(f"WHERE ({keys}) IN ((:1, :2, :3), (:4, :5, :6))")

    a.conn = _Conn([])
    a.fetch_rows(HashPlan(table, plan.columns, ["CODE"], 1), [("a",)])
    assert [s[0] for s in a.conn.sent] == ["execute"]  # no national key: no sizes set
