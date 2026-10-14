"""PostgreSQL to MySQL and back: the cross engine promise of canonical v1.0.

The same logical data loaded into each engine must produce identical bucket aggregates,
and an injected difference must be reported exactly as it is between two PostgreSQL
databases. The MySQL copy stores 'café' decomposed (e + combining acute), which canonical
NFC rendering treats as equal to PostgreSQL's precomposed form.
"""

import datetime as dt
from decimal import Decimal

import pytest

from liftproof.adapters.base import HashPlan, TableRef
from liftproof.findings import FindingWriter, Kind, read_findings
from liftproof.reconcile.engine import ReconcileOptions, Reconciler

pytestmark = [pytest.mark.postgres, pytest.mark.mysql]

N = 3000

PG_DDL = """
CREATE TABLE orders (
  id bigint PRIMARY KEY, status text, code char(4), total numeric(10,2), active boolean,
  placed date, at_time time(3), created timestamp(6), updated timestamptz, payload bytea,
  note text, weight double precision
)"""

MY_DDL = """
CREATE TABLE orders (
  id bigint PRIMARY KEY, status varchar(20), code char(4), total decimal(10,2),
  active tinyint(1), placed date, at_time time(3), created datetime(6), updated timestamp(6) NULL,
  payload varbinary(8), note varchar(40), weight double
)"""


def _rows(decomposed: bool):
    epoch = dt.datetime(2026, 1, 1)
    for i in range(1, N + 1):
        cafe = "café" if decomposed else "café"
        yield (
            i,
            "DISPATCHED" if i % 3 else "OPEN",
            f"C{i % 97}" if i % 11 else None,
            Decimal(i % 1000) + Decimal("0.50"),
            i % 2 == 0,
            (epoch + dt.timedelta(days=i % 400)).date(),
            dt.time(i % 24, i % 60, i % 60, (i % 1000) * 1000),
            epoch + dt.timedelta(minutes=i, microseconds=i),
            (epoch + dt.timedelta(hours=i)).replace(tzinfo=dt.UTC),
            i.to_bytes(4, "big"),
            f"{cafe} {i}" if i % 5 == 0 else f"note {i}",
            i * 0.1,
        )


@pytest.fixture
def pg_and_mysql(make_db, adapter_for, make_mysql_db, mysql_adapter_for):
    pdb, pc = make_db("x")
    pc.execute(PG_DDL)
    with pc.cursor() as cur:
        cur.executemany(
            "INSERT INTO orders VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)", list(_rows(False))
        )
    mdb, mc = make_mysql_db("x")
    mc.execute(MY_DDL)
    mc.executemany(
        "INSERT INTO orders VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
        [r[:8] + (r[8].replace(tzinfo=None),) + r[9:] for r in _rows(True)],
    )
    return adapter_for(pdb), mysql_adapter_for(mdb), pc, mc, mdb


def _run(tmp_path, source, target, schemas, schema_map, **opts):
    writer = FindingWriter(tmp_path / "findings", "r-x")
    options = ReconcileOptions(schemas=schemas, schema_map=schema_map, rows_per_bucket=500,
                               **opts)  # fmt: skip
    result = Reconciler(target, writer, options, source=source).run()
    writer.close()
    return result, list(read_findings(tmp_path / "findings"))


def test_same_data_same_aggregates(pg_and_mysql):
    pg, my, _, _, mdb = pg_and_mysql
    pg_schema = pg.describe(TableRef("public", "orders"))
    my_schema = my.describe(TableRef(mdb, "orders"))
    hashed = sorted((c.name, c.canonical) for c in pg_schema.columns if c.canonical.hashed)
    assert hashed == sorted((c.name, c.canonical) for c in my_schema.columns if c.canonical.hashed)
    for keys in (["id"], []):
        for precision in (0, 3, 6):
            p = HashPlan(TableRef("public", "orders"), hashed, keys, 7, precision)
            m = HashPlan(TableRef(mdb, "orders"), hashed, keys, 7, precision)
            assert pg.bucket_aggregates(p) == my.bucket_aggregates(m)


@pytest.mark.parametrize("direction", ["pg_to_mysql", "mysql_to_pg"])
def test_reconcile_across_engines(tmp_path, pg_and_mysql, direction):
    pg, my, pc, mc, mdb = pg_and_mysql
    if direction == "pg_to_mysql":
        source, target, schemas, smap, table = pg, my, ["public"], {"public": mdb}, "public.orders"
        mc.execute("DELETE FROM orders WHERE id IN (17, 2500)")
        mc.execute("UPDATE orders SET total = total + 0.01 WHERE id = 1234")
    else:
        source, target, schemas, smap, table = my, pg, [mdb], {mdb: "public"}, f"{mdb}.orders"
        pc.execute("DELETE FROM orders WHERE id IN (17, 2500)")
        pc.execute("UPDATE orders SET total = total + 0.01 WHERE id = 1234")

    result, findings = _run(tmp_path, source, target, schemas, smap)
    [orders] = result.tables
    assert orders.table == table
    assert (orders.source_rows, orders.target_rows) == (N, N - 2)
    assert orders.missing_rows == 2 and orders.changed_rows == 1 and orders.extra_rows == 0
    [changed] = [f for f in findings if f.kind == Kind.DIFFERENCE and f.column == "total"]
    assert changed.locator == "id = 1234"
    # nothing else differs: no column of either engine renders differently
    other = [
        f
        for f in findings
        if f.kind == Kind.DIFFERENCE and f.column not in (None, "total", "weight")
    ]
    assert not other, other


def test_identical_across_engines_matches(tmp_path, pg_and_mysql):
    pg, my, _, _, mdb = pg_and_mysql
    result, findings = _run(tmp_path, pg, my, ["public"], {"public": mdb})
    assert [t.status for t in result.tables] == ["matched"]
    assert not [f for f in findings if f.kind == Kind.DIFFERENCE]


@pytest.mark.parametrize("direction", ["pg_to_mysql", "mysql_to_pg"])
def test_postgres_infinity_is_a_changed_value(tmp_path, pg_and_mysql, direction):
    """MySQL cannot store infinity: a migration maps it to NULL or a sentinel date, and
    either is reported, never matched (it used to hash as NULL)."""
    pg, my, pc, mc, mdb = pg_and_mysql
    pc.execute("UPDATE orders SET placed = 'infinity', updated = '-infinity' WHERE id = 5")
    pc.execute("UPDATE orders SET placed = 'infinity' WHERE id = 6")
    mc.execute("UPDATE orders SET placed = NULL, updated = NULL WHERE id = 5")
    mc.execute("UPDATE orders SET placed = '9999-12-31' WHERE id = 6")
    if direction == "pg_to_mysql":
        result, findings = _run(tmp_path, pg, my, ["public"], {"public": mdb}, show_values=True)
        pg_side, my_side = "expected", "actual"
    else:
        result, findings = _run(tmp_path, my, pg, [mdb], {mdb: "public"}, show_values=True)
        pg_side, my_side = "actual", "expected"
    [orders] = result.tables
    assert orders.status == "different" and orders.changed_rows == 2
    changed = {(f.locator, f.column): (getattr(f, pg_side), getattr(f, my_side))
               for f in findings if f.summary.startswith("value differs")}  # fmt: skip
    assert changed == {
        ("id = 5", "placed"): ("infinity", "NULL"),
        ("id = 5", "updated"): ("-infinity", "NULL"),
        ("id = 6", "placed"): ("infinity", "9999-12-31"),
    }
