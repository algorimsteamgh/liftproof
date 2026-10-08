"""SQL Server against PostgreSQL, MySQL and Oracle: the cross engine promise of canonical
v1.0 for SQL Server.

The same logical data loaded into each engine must produce identical bucket aggregates,
and an injected difference must be reported exactly as it is between two PostgreSQL
databases. The SQL Server copy stores 'café' decomposed in an nvarchar column (hashed
application side, NFC), keeps a legacy datetime column and a datetimeoffset.
"""

import pytest

from liftproof.adapters.base import HashPlan, TableRef
from liftproof.findings import Kind
from liftproof.reconcile.plan import plan_table
from tests.test_cross_engine_oracle import MY_DDL, PG_DDL, N, _rows, _run

pytestmark = [pytest.mark.postgres, pytest.mark.sqlserver]

MS_DDL = """
CREATE TABLE dbo.orders (
  id bigint PRIMARY KEY, status varchar(20), code char(4), total decimal(10,2), qty int,
  active bit, placed datetime, created datetime2(6), updated datetimeoffset(6),
  payload varbinary(8), note nvarchar(40), weight float
)"""


def _load_sqlserver(make_sqlserver_db, prefix: str):
    import pytds

    db, cur = make_sqlserver_db(prefix)
    cur.execute(MS_DDL)
    marks = ", ".join(["%s"] * 12)
    rows = [r[:9] + (pytds.Binary(r[9]),) + r[10:] for r in _rows(True)]
    for start in range(0, len(rows), 150):  # 12 x 150 parameters per statement
        chunk = rows[start : start + 150]
        values = ", ".join(f"({marks})" for _ in chunk)
        cur.execute(f"INSERT INTO dbo.orders VALUES {values}", [v for r in chunk for v in r])
    return db, cur


@pytest.fixture
def pg_and_sqlserver(make_db, adapter_for, make_sqlserver_db, sqlserver_adapter_for):
    pdb, pc = make_db("s")
    pc.execute(PG_DDL)
    with pc.cursor() as cur:
        cur.executemany(
            "INSERT INTO orders VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)", list(_rows(False))
        )
    db, mc = _load_sqlserver(make_sqlserver_db, "o")
    return adapter_for(pdb), sqlserver_adapter_for(db), pc, mc


def test_same_data_same_aggregates(pg_and_sqlserver):
    pg, ms, _, _ = pg_and_sqlserver
    ps = pg.describe(TableRef("public", "orders"))
    ss = ms.describe(TableRef("dbo", "orders"))
    tp = plan_table(ss, ps, rows=N, rows_per_bucket=500, precision=6, ignore=[])
    assert not tp.issues, tp.issues
    for keys in (["id"], []):
        for precision in (0, 3, 6):
            s = HashPlan(TableRef("dbo", "orders"), tp.plan.columns, keys, 7, precision)
            p = HashPlan(TableRef("public", "orders"), tp.plan.columns, keys, 7, precision)
            assert pg.bucket_aggregates(p) == ms.bucket_aggregates(s)


@pytest.mark.parametrize("direction", ["sqlserver_to_pg", "pg_to_sqlserver"])
def test_reconcile_across_engines(tmp_path, pg_and_sqlserver, direction):
    pg, ms, pc, mc = pg_and_sqlserver
    if direction == "sqlserver_to_pg":
        source, target, schemas, smap, table = ms, pg, ["dbo"], {"dbo": "public"}, "dbo.orders"
        pc.execute("DELETE FROM orders WHERE id IN (17, 2500)")
        pc.execute("UPDATE orders SET total = total + 0.01 WHERE id = 1234")
    else:
        source, target, schemas, smap = pg, ms, ["public"], {"public": "dbo"}
        table = "public.orders"
        mc.execute("DELETE FROM dbo.orders WHERE id IN (17, 2500)")
        mc.execute("UPDATE dbo.orders SET total = total + 0.01 WHERE id = 1234")

    result, findings = _run(tmp_path, source, target, schemas, smap)
    [orders] = result.tables
    assert orders.table == table
    assert (orders.source_rows, orders.target_rows) == (N, N - 2)
    assert orders.missing_rows == 2 and orders.changed_rows == 1 and orders.extra_rows == 0
    [diff] = [f for f in findings if f.kind == Kind.DIFFERENCE and f.column == "total"]
    assert diff.locator == "id = 1234"
    other = [
        f
        for f in findings
        if f.kind == Kind.DIFFERENCE and (f.column or "") not in ("", "total", "weight")
    ]
    assert not other, other


def test_identical_across_engines_matches(tmp_path, pg_and_sqlserver):
    pg, ms, _, _ = pg_and_sqlserver
    result, findings = _run(tmp_path, ms, pg, ["dbo"], {"dbo": "public"})
    assert [t.status for t in result.tables] == ["matched"]
    assert not [f for f in findings if f.kind == Kind.DIFFERENCE]


@pytest.mark.mysql
def test_sqlserver_and_mysql_agree(
    tmp_path, make_sqlserver_db, sqlserver_adapter_for, make_mysql_db, mysql_adapter_for
):
    db, _ = _load_sqlserver(make_sqlserver_db, "m")
    mdb, mc = make_mysql_db("s")
    mc.execute(MY_DDL)
    mc.executemany(
        "INSERT INTO orders VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
        [r[:8] + (r[8].replace(tzinfo=None),) + r[9:] for r in _rows(False)],
    )
    result, findings = _run(
        tmp_path, sqlserver_adapter_for(db), mysql_adapter_for(mdb), ["dbo"], {"dbo": mdb}
    )
    assert [t.status for t in result.tables] == ["matched"]
    assert not [f for f in findings if f.kind == Kind.DIFFERENCE]


@pytest.mark.oracle
def test_oracle_to_sqlserver(
    tmp_path, make_sqlserver_db, sqlserver_adapter_for, make_oracle_db, oracle_adapter_for
):
    import oracledb

    from tests.test_cross_engine_oracle import ORA_DDL, ORA_INSERT, _ora_rows

    schema, oc = make_oracle_db("s")
    oc.execute(ORA_DDL)
    ts = oracledb.DB_TYPE_TIMESTAMP
    oc.setinputsizes(None, None, None, None, None, None, ts, ts, ts)
    oc.executemany(ORA_INSERT, list(_ora_rows()))
    db, mc = _load_sqlserver(make_sqlserver_db, "r")
    mc.execute("UPDATE dbo.orders SET note = N'cafe 10' WHERE id = 10")
    result, findings = _run(
        tmp_path, oracle_adapter_for(), sqlserver_adapter_for(db), [schema], {schema: "dbo"}
    )
    [orders] = result.tables
    assert orders.changed_rows == 1
    [diff] = [f for f in findings if f.kind == Kind.DIFFERENCE and f.column]
    assert diff.column.lower() == "note" and diff.locator.lower() == "id = 10"
