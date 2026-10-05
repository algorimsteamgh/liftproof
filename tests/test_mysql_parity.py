"""MySQL pushdown against the reference implementation (Technical Spec 19).

The in-database hash (with non-ASCII rows routed to the application side) must be byte
identical to hashing every row through the reference implementation.
"""

import datetime as dt

import pytest

from liftproof.adapters.base import HashPlan, TableRef
from liftproof.adapters.mysql import MySQLAdapter, prepare
from liftproof.canonical import CanonicalType as T
from liftproof.canonical import Verbatim, render

pytestmark = pytest.mark.mysql

DDL = """
CREATE TABLE everything (
  id      bigint PRIMARY KEY,
  i2      smallint,
  u8      bigint unsigned,
  num     decimal(12,4),
  flag    tinyint(1),
  label   varchar(100),
  code    char(6),
  day     date,
  at_time time(3),
  naive   datetime(6),
  aware   timestamp(6) NULL,
  blob_   varbinary(16),
  yr      year,
  kind    enum('a','b')
)
"""

ROWS = """
INSERT INTO everything VALUES
 (1, 7, 18446744073709551615, 10.5000, 1, 'cafe', 'AB', '2026-01-31', '13:14:15.123',
  '2026-09-25 11:02:41.123456', '2026-09-25 11:02:41.5', X'00ff10', 2026, 'a'),
 (2, -1, 0, -0.0000, 0, 'café', 'X     ', '1999-12-31', '00:00:00',
  '2000-01-01 00:00:00', '2000-01-01 00:00:01', X'', 1999, 'b'),
 (3, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL),
 (4, 0, 1, 12345678.9, 1, 'tab\\there\\Nsep', '', '0000-00-00', '-01:02:03.5',
  '0000-00-00 00:00:00', '2038-01-19 03:14:07.999999', X'deadbeef', 2000, 'a'),
 (5, 32767, 42, 0.0001, 0, 'café', 'Z', '2026-02-28', '125:00:00',
  '2026-02-28 23:59:59.999999', '1970-01-01 00:00:01', X'5c4e', 1901, NULL)
"""

COLUMNS = [
    ("at_time", T.TIME),
    ("aware", T.TIMESTAMPTZ),
    ("blob_", T.BINARY),
    ("code", T.CHAR),
    ("day", T.DATE),
    ("flag", T.BOOLEAN),
    ("i2", T.INTEGER),
    ("id", T.INTEGER),
    ("kind", T.TEXT),
    ("label", T.TEXT),
    ("naive", T.TIMESTAMP),
    ("num", T.DECIMAL),
    ("u8", T.INTEGER),
    ("yr", T.INTEGER),
]


@pytest.fixture
def loaded(make_mysql_db, mysql_adapter_for):
    db, cur = make_mysql_db()
    cur.execute(DDL)
    cur.execute(ROWS)
    return mysql_adapter_for(db), db


@pytest.mark.parametrize("precision", [0, 3, 6])
@pytest.mark.parametrize("keyed", [True, False])
def test_pushdown_matches_reference(loaded, precision, keyed):
    a, db = loaded
    plan = HashPlan(TableRef(db, "everything"), COLUMNS, ["id"] if keyed else [], 3, precision)
    pushed = a.bucket_aggregates(plan)
    reference = a._bucket_aggregates_fallback(plan)
    assert pushed == reference
    assert sum(b.count for b in pushed.values()) == 5

    rows_push = sorted(a.row_hashes(plan, set(range(3))))
    a._pushdown = lambda p: False
    rows_ref = sorted(a.row_hashes(plan, set(range(3))))
    assert rows_push == rows_ref
    assert len(rows_push) == 5


def test_non_ascii_rows_take_the_reference_path(loaded):
    """'cafe' + combining acute and the precomposed form are the same text after NFC."""
    a, db = loaded
    plan = HashPlan(TableRef(db, "everything"), [("id", T.INTEGER), ("label", T.TEXT)], ["id"], 1)
    hashes = dict((k, h) for k, h in a.row_hashes(plan, {0}))
    assert len(hashes) == 5
    rendered = {
        r[0]: r[1] for r in a._query(f"SELECT id, label FROM `{db}`.everything WHERE id IN (2, 5)")
    }
    assert render(rendered[2], T.TEXT) == render(rendered[5], T.TEXT) == "café"


def test_describe_maps_types(loaded):
    a, db = loaded
    schema = a.describe(TableRef(db, "everything"))
    assert schema.primary_key == ["id"]
    assert {c.name: c.canonical for c in schema.columns} == dict(COLUMNS)


def test_mysql_only_values_render_as_mysql_prints_them():
    assert prepare(
        dt.timedelta(hours=-1, minutes=-2, seconds=-3, microseconds=-500000), T.TIME, 6
    ) == Verbatim("-01:02:03.500000")
    assert prepare(dt.timedelta(hours=125), T.TIME, 0) == "125:00:00"
    assert prepare(dt.timedelta(hours=13, minutes=14), T.TIME, 6) == dt.time(13, 14)
    assert prepare("0000-00-00 00:00:00", T.TIMESTAMP, 3) == "0000-00-00T00:00:00.000"
    assert prepare("0000-00-00", T.DATE, 6) == "0000-00-00"


def test_snapshot_and_session(loaded):
    a, _ = loaded
    snap = a.begin_snapshot()
    assert snap["type"] in ("gtid", "binlog", "none")
    assert snap["exact"] is False
    a.end_snapshot()
    s = a.session_settings()
    assert s["time_zone"] == "+00:00"
    assert s["transaction_read_only"] == "ON"


def test_read_only_session_refuses_writes(loaded):
    import pymysql

    a, db = loaded
    with pytest.raises(pymysql.err.MySQLError):
        a._query(f"DELETE FROM `{db}`.everything")


def test_verify_read_only_reads_the_grants(make_mysql_db, mysql_adapter_for):
    import uuid

    from tests.conftest import MY, _my_connect

    db, cur = make_mysql_db()
    cur.execute("CREATE TABLE t (id int PRIMARY KEY)")
    assert not mysql_adapter_for(db).verify_read_only()  # the test login is root
    user, pw = f"lp_ro_{uuid.uuid4().hex[:6]}", uuid.uuid4().hex
    with _my_connect() as c, c.cursor() as admin:
        admin.execute(f"CREATE USER '{user}'@'%' IDENTIFIED BY '{pw}'")
        admin.execute(f"GRANT SELECT ON `{db}`.* TO '{user}'@'%'")
        try:
            ro = MySQLAdapter(
                host=MY["host"],
                port=MY["port"],
                database=db,
                user=user,
                password=pw,
                sslmode="disable",
            )
            try:
                assert ro.verify_read_only()
            finally:
                ro.close()
        finally:
            admin.execute(f"DROP USER '{user}'@'%'")
