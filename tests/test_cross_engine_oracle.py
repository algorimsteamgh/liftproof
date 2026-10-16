"""PostgreSQL to Oracle and back, and Oracle against MySQL: the cross engine promise of
canonical v1.0 for Oracle.

The same logical data loaded into each engine must produce identical bucket aggregates,
and an injected difference must be reported exactly as it is between two PostgreSQL
databases. The Oracle copy stores 'café' decomposed (e + combining acute) in an
NVARCHAR2 column, which canonical NFC rendering treats as equal to the precomposed form.
An unconstrained Oracle NUMBER holding whole numbers compares with a PostgreSQL integer.
"""

import datetime as dt
from decimal import Decimal

import pytest

from liftproof.adapters.base import HashPlan, TableRef
from liftproof.canonical.typemap import DEFAULT_TYPE_MAP
from liftproof.findings import FindingWriter, Kind, read_findings
from liftproof.reconcile.engine import ReconcileOptions, Reconciler
from liftproof.reconcile.plan import plan_table

pytestmark = [pytest.mark.postgres, pytest.mark.oracle]

N = 3000

PG_DDL = """
CREATE TABLE orders (
  id bigint PRIMARY KEY, status text, code char(4), total numeric(10,2), qty integer,
  active boolean, placed timestamp(0), created timestamp(6), updated timestamptz,
  payload bytea, note text, weight double precision
)"""

ORA_DDL = """
CREATE TABLE orders (
  id NUMBER(19) PRIMARY KEY, status VARCHAR2(20), code CHAR(4), total NUMBER(10,2),
  qty NUMBER, active BOOLEAN, placed DATE, created TIMESTAMP(6),
  updated TIMESTAMP(6) WITH TIME ZONE, payload RAW(8), note NVARCHAR2(40),
  weight BINARY_DOUBLE
)"""

MY_DDL = """
CREATE TABLE orders (
  id bigint PRIMARY KEY, status varchar(20), code char(4), total decimal(10,2),
  qty int, active tinyint(1), placed datetime, created datetime(6),
  updated timestamp(6) NULL, payload varbinary(8), note varchar(40), weight double
)"""


def _rows(decomposed: bool):
    epoch = dt.datetime(2026, 1, 1)
    for i in range(1, N + 1):
        cafe = "café" if decomposed else "café"
        yield (
            i,
            "DISPATCHED" if i % 3 else "OPEN",
            f"C{i % 97}" if i % 11 else None,
            Decimal(i % 1000) + Decimal("0.50"),
            i % 50,
            i % 2 == 0,
            epoch + dt.timedelta(days=i % 400, seconds=i),
            epoch + dt.timedelta(minutes=i, microseconds=i),
            (epoch + dt.timedelta(hours=i)).replace(tzinfo=dt.UTC),
            i.to_bytes(4, "big"),
            f"{cafe} {i}" if i % 5 == 0 else f"note {i}",
            i * 0.1,
        )


def _ora_rows():
    for r in _rows(True):
        # FROM_TZ input: naive UTC wall time plus a zone
        yield r[:8] + (r[8].replace(tzinfo=None),) + r[9:]


ORA_INSERT = (
    "INSERT INTO orders VALUES (:1, :2, :3, :4, :5, :6, :7, :8, "
    "FROM_TZ(:9, '+00:00'), :10, :11, :12)"
)


@pytest.fixture
def pg_and_oracle(make_db, adapter_for, make_oracle_db, oracle_adapter_for):
    import oracledb

    pdb, pc = make_db("o")
    pc.execute(PG_DDL)
    with pc.cursor() as cur:
        cur.executemany(
            "INSERT INTO orders VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)", list(_rows(False))
        )
    schema, oc = make_oracle_db("o")
    oc.execute(ORA_DDL)
    ts = oracledb.DB_TYPE_TIMESTAMP
    oc.setinputsizes(None, None, None, None, None, None, ts, ts, ts)
    oc.executemany(ORA_INSERT, list(_ora_rows()))
    return adapter_for(pdb), oracle_adapter_for(), pc, oc, schema


def _run(tmp_path, source, target, schemas, schema_map, **opts):
    writer = FindingWriter(tmp_path / "findings", "r-x")
    options = ReconcileOptions(schemas=schemas, schema_map=schema_map, rows_per_bucket=500,
                               **opts)  # fmt: skip
    result = Reconciler(target, writer, options, source=source).run()
    writer.close()
    return result, list(read_findings(tmp_path / "findings"))


def test_same_data_same_aggregates(pg_and_oracle):
    pg, ora, _, _, schema = pg_and_oracle
    ps = pg.describe(TableRef("public", "orders"))
    os_ = ora.describe(TableRef(schema, "ORDERS"))
    tp = plan_table(os_, ps, rows=N, rows_per_bucket=500, precision=6, ignore=[])
    assert not tp.issues, tp.issues  # NUMBER and integer plan together as decimals
    hashed = tp.plan.columns
    for keys in (["ID"], []):
        for precision in (0, 3, 6):
            o = HashPlan(TableRef(schema, "ORDERS"), hashed, keys, 7, precision)
            p = HashPlan(
                TableRef("public", "orders"),
                [(n.lower(), t) for n, t in hashed],
                [k.lower() for k in keys],
                7,
                precision,
            )
            assert pg.bucket_aggregates(p) == ora.bucket_aggregates(o)


@pytest.mark.parametrize("direction", ["pg_to_oracle", "oracle_to_pg"])
def test_reconcile_across_engines(tmp_path, pg_and_oracle, direction):
    pg, ora, pc, oc, schema = pg_and_oracle
    if direction == "pg_to_oracle":
        source, target, schemas, smap = pg, ora, ["public"], {"public": schema}
        table = "public.orders"
        changed = oc
    else:
        source, target, schemas, smap = ora, pg, [schema], {schema: "public"}
        table = f"{schema}.ORDERS"
        changed = pc
    changed.execute("DELETE FROM orders WHERE id IN (17, 2500)")
    changed.execute("UPDATE orders SET total = total + 0.01 WHERE id = 1234")

    result, findings = _run(tmp_path, source, target, schemas, smap)
    [orders] = result.tables
    assert orders.table == table
    assert (orders.source_rows, orders.target_rows) == (N, N - 2)
    assert orders.missing_rows == 2 and orders.changed_rows == 1 and orders.extra_rows == 0
    [diff] = [
        f for f in findings if f.kind == Kind.DIFFERENCE and (f.column or "").lower() == "total"
    ]
    assert diff.locator.lower() == "id = 1234"
    other = [
        f
        for f in findings
        if f.kind == Kind.DIFFERENCE and (f.column or "").lower() not in ("", "total", "weight")
    ]
    assert not other, other


def test_identical_across_engines_matches(tmp_path, pg_and_oracle):
    pg, ora, _, _, schema = pg_and_oracle
    result, findings = _run(tmp_path, ora, pg, [schema], {schema: "public"})
    assert [t.status for t in result.tables] == ["matched"]
    assert not [f for f in findings if f.kind == Kind.DIFFERENCE]


@pytest.mark.mysql
def test_oracle_and_mysql_agree(
    tmp_path, make_oracle_db, oracle_adapter_for, make_mysql_db, mysql_adapter_for
):
    import oracledb

    schema, oc = make_oracle_db("m")
    oc.execute(ORA_DDL)
    ts = oracledb.DB_TYPE_TIMESTAMP
    oc.setinputsizes(None, None, None, None, None, None, ts, ts, ts)
    oc.executemany(ORA_INSERT, list(_ora_rows()))
    mdb, mc = make_mysql_db("o")
    mc.execute(MY_DDL)
    mc.executemany(
        "INSERT INTO orders VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
        [r[:8] + (r[8].replace(tzinfo=None),) + r[9:] for r in _rows(False)],
    )
    result, findings = _run(
        tmp_path, oracle_adapter_for(), mysql_adapter_for(mdb), [schema], {schema: mdb}
    )
    assert [t.status for t in result.tables] == ["matched"]
    assert not [f for f in findings if f.kind == Kind.DIFFERENCE]


def test_the_projects_type_map_compares_dates_and_flags(tmp_path, pg_and_oracle):
    """Oracle DATE moved into a PostgreSQL date and NUMBER(1) into a boolean are type
    changes under the shipped map; the project's map compares them, and a DATE with a time
    of day is a changed value rather than matching its day."""
    pg, ora, pc, oc, schema = pg_and_oracle
    pc.execute("CREATE TABLE events (id int PRIMARY KEY, day date, active boolean)")
    oc.execute("CREATE TABLE events (id NUMBER(9) PRIMARY KEY, day DATE, active NUMBER(1))")
    days = [(i, dt.date(2026, 1, 1) + dt.timedelta(days=i), [None, True, False][i % 3])
            for i in range(1, 201)]  # fmt: skip
    with pc.cursor() as cur:
        cur.executemany("INSERT INTO events VALUES (%s, %s, %s)", days)
    oc.executemany(
        "INSERT INTO events VALUES (:1, :2, :3)",
        [(i, dt.datetime.combine(d, dt.time()), None if a is None else int(a)) for i, d, a in days],
    )
    where = ([schema], {schema: "public"})

    result, findings = _run(tmp_path / "shipped", ora, pg, *where, tables=["EVENTS"])
    assert result.tables[0].excluded_columns == ["ACTIVE", "DAY"]
    assert {f.column for f in findings if f.detail.get("issue") == "type_changed"} == {
        "ACTIVE", "DAY",
    }  # fmt: skip

    mapped = DEFAULT_TYPE_MAP.with_overrides(
        {"oracle": {"DATE": "date", "NUMBER(1)": "boolean"}}, {"oracle", "postgresql"}
    )
    result, findings = _run(tmp_path / "mapped", ora, pg, *where, tables=["EVENTS"],
                            type_map=mapped)  # fmt: skip
    [events] = result.tables
    assert (events.status, events.partial) == ("matched", False)
    assert not [f for f in findings if f.kind == Kind.DIFFERENCE]

    oc.execute("UPDATE events SET day = day + 0.5 WHERE id = 7")  # noon on the same day
    result, findings = _run(tmp_path / "noon", ora, pg, *where, tables=["EVENTS"],
                            type_map=mapped)  # fmt: skip
    [events] = result.tables
    assert (events.status, events.changed_rows) == ("different", 1)
    [changed] = [f for f in findings if f.kind == Kind.DIFFERENCE and f.column == "DAY"]
    assert changed.locator.lower() == "id = 7"
