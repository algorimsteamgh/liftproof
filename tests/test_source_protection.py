"""Protecting the source (Technical Spec 9.15): the rows per second cap, the pause between
statements, lock timeouts and one core per capped connection, on every engine."""

import time

import psycopg
import pytest
import yaml

from liftproof import cli
from liftproof.adapters.base import Pacer, TableRef
from liftproof.config import LOCK_TIMEOUT_MS, SOURCE_PAUSE_MS, SOURCE_ROWS_PER_SECOND, load_project
from liftproof.errors import ConfigError
from liftproof.findings import FindingWriter
from liftproof.reconcile.baseline import take_baseline
from liftproof.reconcile.engine import ReconcileOptions, Reconciler
from tests.conftest import PG, _ms_connect, _my_connect


class Clock:
    """Time that moves only when the pacer sleeps or a test moves it."""

    def __init__(self):
        self.now = 100.0
        self.slept = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.slept.append(round(seconds, 6))
        self.now += seconds


def _pacer(rate=0, pause_ms=0):
    c = Clock()
    return Pacer(rate, pause_ms, clock=c, sleep=c.sleep), c


# ------------------------------------------------------------------------ the pacer
def test_no_cap_and_no_pause_never_wait():
    p, c = _pacer()
    for _ in range(5):
        with p.statement(1_000_000):
            c.now += 0.1
    assert c.slept == [] and p.charged == 5_000_000


def test_the_next_statement_pays_for_the_rows_before_it():
    p, c = _pacer(1000)
    with p.statement(2000):
        c.now += 0.5
    assert c.slept == []  # nothing waits after a statement
    with p.statement(10):
        pass
    assert c.slept == [1.5]  # 2000 rows at 1000 a second, of which 0.5 s went on reading


def test_a_statement_slower_than_the_cap_waits_nothing():
    p, c = _pacer(1000)
    for _ in range(3):
        with p.statement(1000):
            c.now += 2.0
    assert c.slept == []


def test_idle_time_earns_no_credit():
    p, c = _pacer(1000)
    with p.statement(1000):
        pass
    c.now += 100  # idle
    with p.statement(1000):
        pass
    with p.statement(1):
        pass
    assert c.slept == [1.0]  # the second statement is paid for in full


def test_the_pause_falls_between_statements_never_after_the_last():
    p, c = _pacer(0, pause_ms=50)
    for _ in range(3):
        with p.statement(10):
            c.now += 0.02
    assert c.slept == [0.05, 0.05]


def test_a_stream_is_charged_as_it_arrives():
    p, c = _pacer(1000)
    assert sum(1 for _ in p.each(range(2500))) == 2500
    assert c.slept == [1.0, 1.0] and p.charged == 2500  # the stream itself is slowed
    with p.statement(0):
        pass
    assert c.slept == [1.0, 1.0, 0.5]  # the last 500 rows, before the next statement


def test_a_stream_inside_a_statement_is_charged_once():
    p, c = _pacer(1000)
    with p.statement(2500):
        list(p.each(range(1500)))
    assert p.charged == 2500
    with p.statement(0):
        pass
    assert p.waited == pytest.approx(2.5)


def test_a_statement_learns_how_much_it_read():
    p, _ = _pacer(1000)
    with p.statement(100) as s:
        s.rows = 3000
    assert p.charged == 3000


# ---------------------------------------------------------------------- the settings
def _project_file(tmp_path, source=None, target=None):
    conn = {"engine": "postgresql", "host": "db", "database": "app"}
    doc = {"project": "acme", "source": {**conn, **(source or {})},
           "target": {**conn, **(target or {})}}  # fmt: skip
    path = tmp_path / "acme.yaml"
    path.write_text(yaml.safe_dump(doc))
    return path


def _limits(conn):
    return conn.rows_per_second, conn.pause_ms, conn.lock_timeout_ms


def test_the_source_alone_is_capped_by_default(tmp_path):
    p = load_project(_project_file(tmp_path))
    assert _limits(p.source) == (SOURCE_ROWS_PER_SECOND, SOURCE_PAUSE_MS, LOCK_TIMEOUT_MS)
    assert _limits(p.target) == (0, 0, LOCK_TIMEOUT_MS)
    off = {"rows_per_second": 0, "pause_ms": 0, "lock_timeout_ms": 0}
    p = load_project(_project_file(tmp_path, off, {"rows_per_second": 2000, "pause_ms": 20}))
    assert _limits(p.source) == (0, 0, 0)  # a read replica: as fast as it goes
    assert _limits(p.target) == (2000, 20, LOCK_TIMEOUT_MS)  # a target in production


@pytest.mark.parametrize("value", [-1, "fast", True, 1.5, None])
@pytest.mark.parametrize("key", ["rows_per_second", "pause_ms", "lock_timeout_ms"])
def test_a_limit_is_a_whole_number(tmp_path, key, value):
    with pytest.raises(ConfigError, match=f"source.{key} is a whole number"):
        load_project(_project_file(tmp_path, {key: value}))


def test_init_writes_the_defaults_and_leaves_the_target_uncapped(tmp_path):
    assert cli.main(["init", "demo", "--dir", str(tmp_path)]) == 0
    path = tmp_path / "demo.yaml"
    assert "read replica" in path.read_text()
    p = load_project(path)
    assert _limits(p.source) == (SOURCE_ROWS_PER_SECOND, SOURCE_PAUSE_MS, LOCK_TIMEOUT_MS)
    assert _limits(p.target) == (0, 0, LOCK_TIMEOUT_MS)


# ------------------------------------------------------------- reading PostgreSQL
SCHEMA = """
CREATE TABLE orders (id int PRIMARY KEY, status text, total numeric(10,2));
INSERT INTO orders SELECT g, 'OPEN', g + 0.5 FROM generate_series(1, 2000) g;
CREATE TABLE events (id int PRIMARY KEY, body jsonb);
INSERT INTO events SELECT g, jsonb_build_object('n', g) FROM generate_series(1, 2000) g;
CREATE TABLE lines (sku text, qty int);
INSERT INTO lines SELECT 'S' || g, g FROM generate_series(1, 2000) g;
"""
ROWS = 2000
CHANGES = {
    "orders": "UPDATE orders SET status = 'open' WHERE id IN (7, 777, 1777)",
    "events": "UPDATE events SET body = '{\"n\": 0}' WHERE id IN (7, 777, 1777)",
    "lines": "UPDATE lines SET qty = 0 WHERE qty IN (7, 777, 1777)",
}


@pytest.fixture
def pg_pair(make_db):
    (s, sc), (t, tc) = make_db("src"), make_db("tgt")
    sc.execute(SCHEMA)
    tc.execute(SCHEMA)
    return s, t, sc, tc


def _reconcile(tmp_path, source, target, tables):
    writer = FindingWriter(tmp_path / "findings", "r-test")
    opts = ReconcileOptions(rows_per_bucket=100, tables=tables)
    result = Reconciler(target, writer, opts, source=source).run()
    writer.close()
    return {t.table.split(".")[1]: t for t in result.tables}


def _paced(adapter, rate=0, pause_ms=0):
    c = Clock()
    adapter.pacer = Pacer(rate, pause_ms, clock=c, sleep=c.sleep)
    return c


@pytest.mark.postgres
@pytest.mark.parametrize(
    "table, reads",
    [
        # count, aggregate, ranges, one pass over the table for every differing bucket, and
        # the changed rows' values (matched on their rendering: another read)
        ("orders", lambda bad: 4 + 1),  # hashed in PostgreSQL: one pass for all buckets
        ("events", lambda bad: 4 + bad),  # hashed here (jsonb): one pass per bucket
        ("lines", lambda bad: 2 + bad),  # no key: no ranges or values, one pass per bucket
    ],
)
def test_every_read_of_the_source_is_charged(tmp_path, pg_pair, adapter_for, table, reads):
    s, t, _, tc = pg_pair
    tc.execute(CHANGES[table])
    src, tgt = adapter_for(s, rows_per_second=1000), adapter_for(t)
    _paced(src, 1000)
    res = _reconcile(tmp_path, src, tgt, [table])[table]
    assert res.status == "different" and res.mismatched_buckets >= 1
    assert src.pacer.charged == reads(res.mismatched_buckets) * ROWS
    # paid for before each next statement; nothing waits for the last one's rows
    assert src.pacer.waited == pytest.approx((src.pacer.charged - ROWS) / 1000)
    assert tgt.pacer.waited == 0  # the target is not capped by default


@pytest.mark.postgres
def test_the_pause_falls_between_statements_and_tables(tmp_path, pg_pair, adapter_for):
    s, t, _, tc = pg_pair
    src = adapter_for(s, pause_ms=50)
    c = _paced(src, 0, 50)
    found = _reconcile(tmp_path, src, adapter_for(t), ["orders", "events"])
    assert {r.status for r in found.values()} == {"matched"}
    assert c.slept == [0.05] * 5  # count, aggregate, ranges per table; none after the last

    tc.execute(CHANGES["orders"])
    tc.execute(CHANGES["events"])
    c.slept.clear()
    found = _reconcile(tmp_path / "2", src, adapter_for(t), ["orders", "events"])
    # orders: 5 statements, the drill-down one pass never paused inside; events: one
    # statement per differing bucket, a pause between each
    statements = 5 + 4 + found["events"].mismatched_buckets
    assert len(c.slept) == statements  # the first statement of this run follows the last


@pytest.mark.postgres
def test_a_baseline_is_charged_like_a_comparison(tmp_path, pg_pair, adapter_for):
    s, *_ = pg_pair
    src = adapter_for(s, rows_per_second=1000)
    _paced(src, 1000)
    b = take_baseline(src, tmp_path / "b.json", baseline_id="b1", schemas=["public"],
                      tables=["orders", "lines"], ignore=[], business_keys={},
                      rows_per_bucket=100, precision=6)  # fmt: skip
    assert len(b.tables) == 2
    assert b.session["rows_per_second"] == "1000"  # the manifest records the limits
    assert src.pacer.charged == (3 + 2) * ROWS  # lines: no key or date to take ranges of
    assert src.pacer.waited == pytest.approx((src.pacer.charged - ROWS) / 1000)


@pytest.mark.postgres
def test_each_worker_connection_has_its_own_cap(pg_pair, adapter_for):
    s, *_ = pg_pair
    src = adapter_for(s, rows_per_second=1000, pause_ms=20, lock_timeout_ms=300)
    other = src.fork()
    try:
        assert other.pacer is not src.pacer
        assert (other.pacer.rate, other.pacer.pause) == (1000, 0.02)
        assert other.protection() == src.protection() == {
            "rows_per_second": 1000, "pause_ms": 20, "statement_timeout_ms": 0,
            "lock_timeout_ms": 300,
        }  # fmt: skip
    finally:
        other.close()


@pytest.mark.postgres
def test_postgresql_gives_up_a_lock_wait(pg_pair, adapter_for):
    s, *_ = pg_pair
    a = adapter_for(s, lock_timeout_ms=200)
    assert a.session_settings()["lock_timeout"] == "200"
    assert adapter_for(s).session_settings()["lock_timeout"] == "0"  # 0: wait
    with psycopg.connect(host=PG["host"], port=PG["port"], user=PG["user"],
                         password=PG["password"], dbname=s) as ddl:  # fmt: skip
        ddl.execute("LOCK TABLE orders IN ACCESS EXCLUSIVE MODE")  # as an ALTER TABLE does
        t0 = time.monotonic()
        with pytest.raises(psycopg.errors.LockNotAvailable):
            a.row_count(TableRef("public", "orders"))
        assert time.monotonic() - t0 < 5
        ddl.rollback()


@pytest.mark.postgres
def test_a_capped_postgresql_connection_reads_on_one_core(pg_pair, adapter_for):
    s, *_ = pg_pair

    def plan(a):
        with a.conn.cursor() as cur:
            for knob in ("parallel_setup_cost", "parallel_tuple_cost",
                         "min_parallel_table_scan_size"):  # fmt: skip
                cur.execute(f"SET {knob} = 0")  # a parallel plan for even a small table
            cur.execute("EXPLAIN SELECT count(*) FROM orders")
            return "\n".join(r[0] for r in cur.fetchall())

    capped = adapter_for(s, rows_per_second=1000)
    assert capped.session_settings()["max_parallel_workers_per_gather"] == "0"
    assert "Gather" not in plan(capped)
    assert "Gather" in plan(adapter_for(s))  # uncapped, the planner chooses


# ------------------------------------------------------------------- other engines
@pytest.mark.mysql
def test_mysql_lock_wait_timeout_and_one_thread(make_mysql_db, mysql_adapter_for):
    import pymysql

    db, cur = make_mysql_db("lock")
    cur.execute("CREATE TABLE t (id int PRIMARY KEY)")
    cur.execute("INSERT INTO t VALUES (1), (2)")

    def session(a, name):
        return a._query(f"SELECT @@SESSION.{name}")[0][0]

    a = mysql_adapter_for(db, lock_timeout_ms=200, rows_per_second=1000)
    assert session(a, "lock_wait_timeout") == 1  # whole seconds, rounded up
    assert session(a, "innodb_parallel_read_threads") == 1
    assert a.session_settings()["innodb_parallel_read_threads"] == "1"
    assert session(mysql_adapter_for(db, lock_timeout_ms=LOCK_TIMEOUT_MS),
                   "lock_wait_timeout") == 10  # fmt: skip
    wait = mysql_adapter_for(db)  # 0: the server's own (a year by default)
    assert wait.session_settings()["lock_wait_timeout"] == "server default"
    assert "innodb_parallel_read_threads" not in wait.session_settings()
    with _my_connect(db) as ddl, ddl.cursor() as dc:
        dc.execute("LOCK TABLES t WRITE")
        t0 = time.monotonic()
        with pytest.raises(pymysql.err.MySQLError) as err:
            a.row_count(TableRef(db, "t"))
        assert err.value.args[0] == 1205 and time.monotonic() - t0 < 5
        dc.execute("UNLOCK TABLES")


@pytest.mark.sqlserver
def test_sql_server_lock_timeout_on_every_connection(make_sqlserver_db, sqlserver_adapter_for):
    import pytds

    # READ_COMMITTED_SNAPSHOT is off, and the read is outside a snapshot: under SNAPSHOT
    # isolation a reader takes no shared lock, and TABLOCKX would not block it
    db, cur = make_sqlserver_db("lock")
    cur.execute("CREATE TABLE t (id int PRIMARY KEY)")
    cur.execute("INSERT INTO t VALUES (1), (2)")
    a = sqlserver_adapter_for(db, lock_timeout_ms=200)
    other = a.fork()
    try:
        for x in (a, other):
            assert x._query("SELECT @@LOCK_TIMEOUT")[0][0] == 200
    finally:
        other.close()
    assert a.session_settings()["LOCK_TIMEOUT"] == "200"
    wait = sqlserver_adapter_for(db, lock_timeout_ms=0)
    assert wait._query("SELECT @@LOCK_TIMEOUT")[0][0] == -1  # SQL Server's 0 never waits
    with _ms_connect(db) as holder, holder.cursor() as hc:
        hc.execute("BEGIN TRANSACTION")
        hc.execute("SELECT COUNT(*) FROM t WITH (TABLOCKX, HOLDLOCK)")
        hc.fetchall()
        t0 = time.monotonic()
        with pytest.raises(pytds.Error) as err:
            a.row_count(TableRef("dbo", "t"))
        assert err.value.msg_no == 1222  # lock request time out period exceeded
        assert time.monotonic() - t0 < 5
        hc.execute("ROLLBACK TRANSACTION")


@pytest.mark.sqlserver
def test_a_capped_sql_server_connection_hashes_alike_on_one_core(
    make_sqlserver_db, sqlserver_adapter_for
):
    from liftproof.reconcile.plan import plan_table

    db, cur = make_sqlserver_db("maxdop")
    cur.execute("CREATE TABLE t (id int PRIMARY KEY, name nvarchar(40), price float)")
    cur.execute("INSERT INTO t VALUES (1, N'plain', 1.5), (2, N'café', 2.5), (3, NULL, NULL)")
    capped = sqlserver_adapter_for(db, rows_per_second=1000)
    free = sqlserver_adapter_for(db)
    assert capped.session_settings()["MAXDOP"] == "1" and capped._hint
    t = TableRef("dbo", "t")
    plan = plan_table(capped.describe(t), None, rows=3, rows_per_bucket=1, precision=6,
                      ignore=[], business_key=None, side="source").plan  # fmt: skip

    def read(a):
        return (
            a.row_count(t),
            a.bucket_aggregates(plan),  # the non-ASCII row is streamed and hashed here
            sorted(a.row_hashes(plan, set(range(plan.buckets)))),
            a.fetch_rows(plan, [("1",), ("2",)]),
            a.float_stats(t, "price"),
            a.value_ranges(t, ["id"]),
        )

    assert read(capped) == read(free)


@pytest.mark.oracle
def test_oracle_accepts_the_settings_and_reads_serially(oracle_adapter_for):
    a = oracle_adapter_for(lock_timeout_ms=200, rows_per_second=1000, pause_ms=20)
    settings = a.session_settings()
    assert settings["lock_timeout"].startswith("not applicable")
    assert settings["parallel_query"] == "disabled"
    assert (settings["rows_per_second"], settings["pause_ms"]) == ("1000", "20")
    q = "SELECT pq_status FROM v$session WHERE sid = SYS_CONTEXT('USERENV', 'SID')"
    assert a._query(q)[0][0] == "DISABLED"

