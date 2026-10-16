"""XML columns across engines (Technical Spec 9.4, 9.6).

PostgreSQL xml, SQL Server xml and Oracle XMLTYPE holding the same documents, each written
the way that engine or a migration tool might write it (a declaration, indentation,
comments, attribute order, CDATA, decomposed characters), give identical bucket
aggregates, and a changed attribute is reported as exactly that row and column. A value
an engine accepts and the canonical rule cannot read leaves its column out, with the
reason, and the run carries on.
"""

import pytest

from liftproof.adapters.base import HashPlan, TableRef
from liftproof.canonical import CanonicalType as T
from liftproof.findings import Kind
from liftproof.reconcile.plan import plan_table
from tests.test_cross_engine_oracle import _run

pytestmark = pytest.mark.postgres

N = 200
UNREADABLE = (  # an xsi:type prefix that is declared nowhere: every engine stores it
    '<a xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="zz:Order"/>'
)


def _doc(i: int, pretty: bool) -> str | None:
    if i % 50 == 0:
        return None
    lines = "".join(f'<o:line sku="A-{i}-{j}" qty="{j}"/>' for j in range(i % 4))
    status = "OPEN" if i % 3 else "PAID"
    if not pretty:
        return (
            f'<o:order xmlns:o="urn:lp:order" id="{i}" status="{status}"><o:customer>café '
            f"{i}</o:customer><o:lines>{lines}</o:lines><o:note xml:space=\"preserve\"> a "
            "&lt; b &amp; c </o:note></o:order>"
        )
    return (
        f"<?xml version=\"1.0\"?>\n<o:order status='{status}' id='{i}' xmlns:o='urn:lp:order'>"
        f"\n  <!-- exported -->\n  <o:customer>café {i}</o:customer>\n  <o:lines>"
        f"{lines}</o:lines>\n  <o:note xml:space='preserve'> <![CDATA[a < b & c]]> </o:note>"
        "\n</o:order>\n"
    )


def _changed(i: int) -> str:
    return _doc(i, False).replace('status="PAID"', 'status="LOST"')


@pytest.fixture
def pg_docs(make_db, adapter_for):
    def load(pretty: bool = True):
        name, conn = make_db("x")
        conn.execute(
            "CREATE TABLE docs (id int PRIMARY KEY, doc xml);"
            "CREATE TABLE notes (id int PRIMARY KEY, v text);"
            "INSERT INTO notes SELECT g, 'v' || g FROM generate_series(1, 20) g"
        )
        with conn.cursor() as cur:
            cur.executemany(
                "INSERT INTO docs VALUES (%s, %s)", [(i, _doc(i, pretty)) for i in range(1, N + 1)]
            )
        return adapter_for(name), conn

    return load


@pytest.fixture
def mssql_docs(make_sqlserver_db, sqlserver_adapter_for):
    def load():
        db, cur = make_sqlserver_db("x")
        cur.execute(
            "CREATE TABLE dbo.docs (id int PRIMARY KEY, doc xml);"
            "CREATE TABLE dbo.notes (id int PRIMARY KEY, v nvarchar(20))"
        )
        for i in range(1, N + 1):
            cur.execute("INSERT INTO dbo.docs VALUES (%s, %s)", (i, _doc(i, i % 2 == 0)))
        for i in range(1, 21):
            cur.execute("INSERT INTO dbo.notes VALUES (%s, %s)", (i, f"v{i}"))
        return sqlserver_adapter_for(db), cur

    return load


@pytest.fixture
def oracle_docs(make_oracle_db, oracle_adapter_for):
    def load():
        schema, cur = make_oracle_db("x")
        cur.execute("CREATE TABLE docs (id NUMBER(9) PRIMARY KEY, doc XMLTYPE)")
        cur.execute("CREATE TABLE notes (id NUMBER(9) PRIMARY KEY, v VARCHAR2(20))")
        cur.executemany(
            "INSERT INTO docs VALUES (:i, CASE WHEN :d IS NULL THEN NULL ELSE XMLTYPE(:d) END)",
            [{"i": i, "d": _doc(i, i % 2 == 1)} for i in range(1, N + 1)],
        )
        cur.executemany("INSERT INTO notes VALUES (:1, :2)", [(i, f"v{i}") for i in range(1, 21)])
        return oracle_adapter_for(), cur, schema

    return load


def _same_aggregates(a, a_table, b, b_table):
    a_schema, b_schema = a.describe(a_table), b.describe(b_table)
    plan = plan_table(a_schema, b_schema, rows=N, rows_per_bucket=50, precision=6,
                      ignore=[]).plan  # fmt: skip
    assert [t for _, t in plan.columns] == [T.XML, T.INTEGER]
    named = {c.name.lower(): c.name for c in b_schema.columns}  # Oracle's are upper case
    for keys in (plan.key_columns, []):
        p = HashPlan(a_table, plan.columns, keys, 5)
        q = HashPlan(b_table, [(named[n.lower()], t) for n, t in plan.columns],
                     [named[k.lower()] for k in keys], 5)  # fmt: skip
        assert a.bucket_aggregates(p) == b.bucket_aggregates(q)


def _one_changed_attribute(tmp_path, source, target, schemas, schema_map):
    result, findings = _run(tmp_path, source, target, schemas, schema_map)
    tables = {t.table.split(".")[1].lower(): t for t in result.tables}
    assert tables["docs"].changed_rows == 1 and not tables["docs"].partial
    assert tables["notes"].status == "matched"
    [diff] = [f for f in findings if f.kind == Kind.DIFFERENCE and f.column]
    assert diff.column.lower() == "doc" and diff.locator.lower() == "id = 42"
    assert diff.summary.lower() == "value differs in column doc"


def _unreadable_left_out(tmp_path, source, target, schemas, schema_map):
    """The value sits mid table: the stream is closed at once and the table read again."""
    result, findings = _run(tmp_path, source, target, schemas, schema_map)
    tables = {t.table.split(".")[1].lower(): t for t in result.tables}
    assert tables["docs"].status == "matched" and tables["docs"].partial
    [f] = [f for f in findings if (f.column or "").lower() == "doc"]
    assert f.kind == Kind.NOT_CHECKED and f.detail["issue"] == "not_canonicalisable"
    assert "xsi:type" in f.summary and "Order" not in f.summary
    assert tables["notes"].status == "matched"


@pytest.mark.sqlserver
def test_postgresql_and_sqlserver(tmp_path, pg_docs, mssql_docs):
    pg, pc = pg_docs()
    ms, mc = mssql_docs()
    _same_aggregates(ms, TableRef("dbo", "docs"), pg, TableRef("public", "docs"))

    mc.execute("UPDATE dbo.docs SET doc = %s WHERE id = 42", (_changed(42),))
    _one_changed_attribute(tmp_path / "a", pg, ms, ["public"], {"public": "dbo"})
    pc.execute("UPDATE docs SET doc = %s WHERE id = 42", (_changed(42),))
    pc.execute("UPDATE docs SET doc = %s WHERE id = 120", (UNREADABLE,))
    mc.execute("UPDATE dbo.docs SET doc = %s WHERE id = 120", (UNREADABLE,))
    _unreadable_left_out(tmp_path / "b", ms, pg, ["dbo"], {"dbo": "public"})


@pytest.mark.oracle
def test_postgresql_and_oracle(tmp_path, pg_docs, oracle_docs):
    pg, pc = pg_docs(pretty=False)
    ora, oc, schema = oracle_docs()
    _same_aggregates(pg, TableRef("public", "docs"), ora, TableRef(schema, "DOCS"))

    pc.execute("UPDATE docs SET doc = %s WHERE id = 42", (_changed(42),))
    _one_changed_attribute(tmp_path / "a", ora, pg, [schema], {schema: "public"})
    oc.execute("UPDATE docs SET doc = XMLTYPE(:1) WHERE id = 42", [_changed(42)])
    oc.execute("UPDATE docs SET doc = XMLTYPE(:1) WHERE id = 120", [UNREADABLE])
    pc.execute("UPDATE docs SET doc = %s WHERE id = 120", (UNREADABLE,))
    _unreadable_left_out(tmp_path / "b", pg, ora, ["public"], {"public": schema})


@pytest.mark.oracle
@pytest.mark.sqlserver
def test_oracle_and_sqlserver(tmp_path, oracle_docs, mssql_docs):
    ora, _, schema = oracle_docs()
    ms, mc = mssql_docs()
    mc.execute("UPDATE dbo.docs SET doc = %s WHERE id = 42", (_changed(42),))
    _one_changed_attribute(tmp_path, ora, ms, [schema], {schema: "dbo"})


@pytest.mark.oracle
@pytest.mark.mysql
def test_xmltype_against_mysql_text_is_a_type_change(
    tmp_path, oracle_docs, make_mysql_db, mysql_adapter_for
):
    ora, _, schema = oracle_docs()
    db, cur = make_mysql_db("x")
    cur.execute("CREATE TABLE docs (id int PRIMARY KEY, doc longtext)")
    cur.execute("CREATE TABLE notes (id int PRIMARY KEY, v varchar(20))")
    cur.executemany("INSERT INTO docs VALUES (%s, %s)", [(i, _doc(i, False)) for i in (1, 2)])
    cur.executemany("INSERT INTO notes VALUES (%s, %s)", [(i, f"v{i}") for i in range(1, 21)])
    result, findings = _run(tmp_path, ora, mysql_adapter_for(db), [schema], {schema: db})
    [f] = [f for f in findings if (f.column or "").lower() == "doc"]
    assert f.detail["issue"] == "type_changed" and (f.expected, f.actual) == ("XMLTYPE", "longtext")
