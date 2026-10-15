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
from liftproof.canonical.typemap import DEFAULT_TYPE_MAP
from liftproof.errors import ConfigError
from liftproof.findings import FindingWriter, Kind, read_findings
from liftproof.reconcile.baseline import Baseline, take_baseline
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



def test_foreign_keys_and_their_indexes_across_engines(
    tmp_path, make_db, adapter_for, make_mysql_db, mysql_adapter_for
):
    """MySQL indexes every foreign key itself: a notice when it is the target, and an
    index missing on a PostgreSQL target, where a foreign key has none of its own."""
    pdb, pc = make_db("fk")
    pc.execute("CREATE TABLE customers (id int PRIMARY KEY, email varchar(40) NOT NULL UNIQUE);"
               "CREATE TABLE orders (id int PRIMARY KEY, "
               "customer_id int NOT NULL REFERENCES customers (id))")  # fmt: skip
    mdb, mc = make_mysql_db("fk")
    mc.execute("CREATE TABLE customers (id int PRIMARY KEY, email varchar(40) NOT NULL UNIQUE)")
    mc.execute("CREATE TABLE orders (id int PRIMARY KEY, customer_id int NOT NULL, "
               "FOREIGN KEY (customer_id) REFERENCES customers (id))")  # fmt: skip
    pg, my = adapter_for(pdb), mysql_adapter_for(mdb)

    def structure(findings):
        return [(f.object.split(".")[1], f.kind, f.detail["issue"]) for f in findings
                if f.detail.get("issue") and f.kind in (Kind.DIFFERENCE, Kind.NOTICE)]  # fmt: skip

    _, findings = _run(tmp_path / "a", pg, my, ["public"], {"public": mdb})
    assert structure(findings) == [("orders", Kind.NOTICE, "index_added_in_target")]
    _, findings = _run(tmp_path / "b", my, pg, [mdb], {mdb: "public"})
    assert structure(findings) == [("orders", Kind.DIFFERENCE, "index_missing_in_target")]
    mc.execute("ALTER TABLE orders DROP FOREIGN KEY orders_ibfk_1")  # its index stays
    _, findings = _run(tmp_path / "c", pg, my, ["public"], {"public": mdb})
    assert structure(findings) == [("orders", Kind.DIFFERENCE, "foreign_key_missing_in_target"),
                                   ("orders", Kind.NOTICE, "index_added_in_target")]  # fmt: skip


MAPPED = DEFAULT_TYPE_MAP.with_overrides(
    {"mysql": {"tinyint(1)": "integer", "datetime": "timestamptz"}}, {"mysql", "postgresql"}
)


@pytest.fixture
def flags(pg_and_mysql):
    """A tinyint(1) moved into a smallint, and a datetime holding UTC times moved into a
    timestamptz."""
    pg, my, pc, mc, mdb = pg_and_mysql
    pc.execute("CREATE TABLE flags (id int PRIMARY KEY, flag smallint, at timestamptz)")
    mc.execute("CREATE TABLE flags (id int PRIMARY KEY, flag tinyint(1), at datetime(6))")
    epoch = dt.datetime(2026, 1, 1, 12)
    rows = [(i, i % 3 - 1 if i % 7 else None, epoch + dt.timedelta(minutes=i, microseconds=i))
            for i in range(1, 301)]  # fmt: skip
    with pc.cursor() as cur:
        cur.executemany("INSERT INTO flags VALUES (%s, %s, %s)",
                        [(i, f, at.replace(tzinfo=dt.UTC)) for i, f, at in rows])  # fmt: skip
    mc.executemany("INSERT INTO flags VALUES (%s, %s, %s)", rows)
    return pg_and_mysql


def test_the_projects_type_map_compares_what_the_shipped_one_cannot(tmp_path, flags):
    """Type changes under the shipped map; the project's map compares them."""
    pg, my, pc, mc, mdb = flags
    where = ([mdb], {mdb: "public"})

    result, findings = _run(tmp_path / "shipped", my, pg, *where, tables=["flags"])
    [flags] = result.tables
    assert flags.partial and flags.excluded_columns == ["at", "flag"]
    assert sorted(f.column for f in findings if f.detail.get("issue") == "type_changed") == [
        "at", "flag",
    ]  # fmt: skip

    result, findings = _run(tmp_path / "mapped", my, pg, *where, tables=["flags"],
                            type_map=MAPPED)  # fmt: skip
    [flags] = result.tables
    assert (flags.status, flags.partial) == ("matched", False)
    [notice] = [f for f in findings if "type_map" in f.detail]
    assert notice.kind == Kind.NOTICE
    assert [(o["column"], o["side"], o["native"], o["canonical"], o["default"])
            for o in notice.detail["type_map"]] == [
        ("flag", "source", "tinyint(1)", "integer", "boolean"),
        ("at", "source", "datetime(6)", "timestamptz", "timestamp"),
    ]  # fmt: skip
    assert not [f for f in findings if f.kind == Kind.DIFFERENCE]

    pc.execute("UPDATE flags SET flag = 2 WHERE id = 10")  # 1 on MySQL: alike as booleans
    result, findings = _run(tmp_path / "changed", my, pg, *where, tables=["flags"],
                            type_map=MAPPED)  # fmt: skip
    [flags] = result.tables
    assert (flags.status, flags.changed_rows) == ("different", 1)
    [changed] = [f for f in findings if f.kind == Kind.DIFFERENCE and f.column == "flag"]
    assert changed.locator == "id = 10"


def test_a_baseline_is_compared_under_the_map_it_was_taken_under(tmp_path, flags):
    """A baseline taken under another map than the project's is not reused for the columns
    the map types otherwise; without the live source the table is not checked, saying why."""
    pg, my, pc, mc, mdb = flags
    manifest = tmp_path / "b1.json"
    take = dict(baseline_id="b1", schemas=[mdb], tables=["flags"], ignore=[],
                business_keys={}, rows_per_bucket=500, precision=6)  # fmt: skip
    take_baseline(my, manifest, **take)
    b = Baseline.load(manifest)
    assert b.type_map == DEFAULT_TYPE_MAP.record("mysql")
    assert dict(b.tables[f"{mdb}.flags"].plan.columns)["flag"] == "boolean"
    opts = dict(schemas=[mdb], schema_map={mdb: "public"}, rows_per_bucket=500, type_map=MAPPED)

    def compare(name, baseline, source=None):
        writer = FindingWriter(tmp_path / name, "r-x")
        result = Reconciler(pg, writer, ReconcileOptions(**opts), baseline=baseline,
                            source=source).run()  # fmt: skip
        writer.close()
        return result.tables[0], list(read_findings(tmp_path / name))

    flags_, findings = compare("alone", b)
    assert flags_.status == "not_checked"
    assert flags_.reason == (
        "the type map compares at, flag otherwise than the baseline did; the live source is "
        "needed to re-hash"
    )
    flags_, _ = compare("live", b, source=my)  # hashed again, under the project's map
    assert flags_.status == "matched" and not flags_.partial

    # resumed under another map, its finished tables would be typed otherwise than the rest
    with pytest.raises(ConfigError, match=r"started under type map 1\.0 without overrides, not "
                       r"type map 1\.0 with mysql datetime as timestamptz, mysql tinyint\(1\) "
                       "as integer"):  # fmt: skip
        take_baseline(my, manifest, resume=True, type_map=MAPPED, **take)
    mapped_manifest = tmp_path / "b2.json"
    take_baseline(my, mapped_manifest, type_map=MAPPED, **dict(take, baseline_id="b2"))
    b2 = Baseline.load(mapped_manifest)
    assert b2.type_map["overrides"] == {
        "mysql": {"datetime": "timestamptz", "tinyint(1)": "integer"}
    }
    flags_, _ = compare("taken-under-it", b2)  # its plan applies: no source needed
    assert flags_.status == "matched" and not flags_.partial

    # a target baseline, the target's own accepted state: rebaseline under the new map
    take_baseline(my, tmp_path / "t1.json", side="target", **dict(take, baseline_id="t1"))
    writer = FindingWriter(tmp_path / "target", "r-x")
    options = ReconcileOptions(schemas=[mdb], rows_per_bucket=500, type_map=MAPPED)
    result = Reconciler(my, writer, options, baseline=Baseline.load(tmp_path / "t1.json")).run()
    writer.close()
    assert result.tables[0].reason == (
        "the type map compares at, flag otherwise than the target baseline did; rebaseline to "
        "apply it"
    )
