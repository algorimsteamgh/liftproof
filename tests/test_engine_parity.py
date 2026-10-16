"""Engine parity: row ignore rules, sampled reconciliation, parallel workers and the
replication check on MySQL, Oracle and SQL Server, each engine against itself (the
cross engine files cover mixed pairs). The same scenarios as the PostgreSQL tests in
test_row_filters, test_sampling, test_workers and test_replication."""

from __future__ import annotations

import datetime as dt
import time
from dataclasses import dataclass, replace
from typing import Any

import pytest

from liftproof.adapters.base import TableRef
from liftproof.errors import ConfigError
from liftproof.findings import FindingWriter, Kind, read_findings
from liftproof.reconcile.baseline import Baseline, take_baseline
from liftproof.reconcile.engine import ReconcileOptions, Reconciler
from liftproof.reconcile.plan import IgnoreRule, plan_table
from liftproof.reconcile.replication import ReplicationConfig, check

N = 3000
ARCHIVED = IgnoreRule("orders", "archived orders are not migrated", where="status = 'ARCHIVED'")


@dataclass
class Engine:
    name: str
    make: Any  # prefix -> (database or schema, raw cursor)
    adapter: Any  # database or schema -> adapter
    ddl: str  # one table, {t} for its name
    mark: Any  # i -> the i-th parameter marker
    schema_of: Any  # database or schema -> where its tables live
    status_ddl: str  # an AWS DMS awsdms_status table

    def load(self, cur, table: str, rows: list[tuple]) -> None:
        cur.execute(self.ddl.format(t=table))
        marks = ", ".join(self.mark(i) for i in range(len(rows[0])))
        cur.executemany(f"INSERT INTO {table} VALUES ({marks})", rows)
        if self.name == "oracle":
            cur.connection.commit()


def _rows(n: int = N, offset: int = 0) -> list[tuple]:
    out = []
    for g in range(1 + offset, n + 1 + offset):
        status = "ARCHIVED" if g % 10 == 0 else ("café" if g % 7 == 0 else "OPEN")
        out.append((g, status, "test" if g <= 100 else "acme", g + 0.5, g * 0.25))
    return out


ENGINES = {
    "mysql": dict(
        ddl="CREATE TABLE {t} (id int PRIMARY KEY, status varchar(20), tenant varchar(10), "
        "total decimal(10,2), weight double)",
        mark=lambda i: "%s",
        status_ddl="CREATE TABLE awsdms_status (server_name varchar(100), task_name "
        "varchar(100), task_status varchar(30), status_time datetime, pending_changes int, "
        "source_current_timestamp datetime, source_timestamp_applied datetime)",
    ),
    "oracle": dict(
        ddl="CREATE TABLE {t} (id NUMBER(10) PRIMARY KEY, status VARCHAR2(20), "
        "tenant VARCHAR2(10), total NUMBER(10,2), weight BINARY_DOUBLE)",
        mark=lambda i: f":{i + 1}",
        status_ddl="CREATE TABLE awsdms_status (server_name VARCHAR2(100), task_name "
        "VARCHAR2(100), task_status VARCHAR2(30), status_time TIMESTAMP, pending_changes "
        "NUMBER(10), source_current_timestamp TIMESTAMP, source_timestamp_applied TIMESTAMP)",
    ),
    "sqlserver": dict(
        ddl="CREATE TABLE {t} (id int PRIMARY KEY, status nvarchar(20), tenant varchar(10), "
        "total decimal(10,2), weight float)",
        mark=lambda i: "%s",
        status_ddl="CREATE TABLE dbo.awsdms_status (server_name nvarchar(100), task_name "
        "nvarchar(100), task_status varchar(30), status_time datetime2, pending_changes int, "
        "source_current_timestamp datetime2, source_timestamp_applied datetime2)",
    ),
}


@pytest.fixture(params=list(ENGINES), ids=list(ENGINES))
def engine(request) -> Engine:
    name = request.param
    request.applymarker(getattr(pytest.mark, name))
    spec = ENGINES[name]
    if name == "mysql":
        make = request.getfixturevalue("make_mysql_db")
        adapter = request.getfixturevalue("mysql_adapter_for")
        return Engine(name, make, adapter, schema_of=lambda db: db, **spec)
    if name == "oracle":
        make = request.getfixturevalue("make_oracle_db")
        factory = request.getfixturevalue("oracle_adapter_for")

        def make_ora(prefix: str):
            schema, cur = make(prefix)
            cur.connection.autocommit = False
            return schema, cur

        return Engine(name, make_ora, lambda _schema: factory(), schema_of=lambda s: s, **spec)
    make = request.getfixturevalue("make_sqlserver_db")
    adapter = request.getfixturevalue("sqlserver_adapter_for")
    return Engine(name, make, adapter, schema_of=lambda _db: "dbo", **spec)


def _opts(e: Engine, src: str, tgt: str, **kw) -> ReconcileOptions:
    s, t = e.schema_of(src), e.schema_of(tgt)
    return ReconcileOptions(schemas=[s], schema_map={s: t} if s != t else {}, **kw)


def _run(tmp_path, e, src, tgt, *, name="f", **kw):
    writer = FindingWriter(tmp_path / name, "r")
    opts = _opts(e, src, tgt, rows_per_bucket=500, breaker_bucket_ratio=1.0, **kw)
    result = Reconciler(e.adapter(tgt), writer, opts, source=e.adapter(src)).run()
    writer.close()
    tables = {t.table.split(".", 1)[1].lower(): t for t in result.tables}
    return result, tables, list(read_findings(tmp_path / name))


@pytest.fixture
def pair(engine):
    src, sc = engine.make("src")
    tgt, tc = engine.make("tgt")
    engine.load(sc, "orders", _rows())
    engine.load(tc, "orders", _rows())
    return engine, src, tgt, sc, tc


def _exec(e: Engine, cur, q: str) -> None:
    cur.execute(q)
    if e.name == "oracle":
        cur.connection.commit()


# ---------------------------------------------------------------- row ignore rules
def test_rows_left_behind_are_not_differences(tmp_path, pair):
    e, src, tgt, _, tc = pair
    _exec(e, tc, "DELETE FROM orders WHERE status = 'ARCHIVED'")  # left behind
    _, tables, _ = _run(tmp_path, e, src, tgt)
    assert tables["orders"].status == "different"

    _, tables, findings = _run(tmp_path, e, src, tgt, ignore=[ARCHIVED], name="g")
    orders = tables["orders"]
    assert orders.status == "matched", [f.summary for f in findings]
    assert (orders.source_rows, orders.target_rows) == (2700, 2700)
    assert any("excluded by ignore rule" in f.summary for f in findings)
    assert not any(f.kind == Kind.NOT_CHECKED for f in findings)


def test_a_difference_outside_the_rule_is_still_found(tmp_path, pair):
    e, src, tgt, _, tc = pair
    _exec(e, tc, "DELETE FROM orders WHERE status = 'ARCHIVED'")
    _exec(e, tc, "UPDATE orders SET total = total + 1 WHERE id = 1234")
    _exec(e, tc, "UPDATE orders SET status = 'cafe' WHERE id = 1239")  # a non-ASCII row
    _, tables, findings = _run(tmp_path, e, src, tgt, ignore=[ARCHIVED])
    assert tables["orders"].status == "different"
    assert tables["orders"].changed_rows == 2
    located = " ".join(f"{f.locator} {f.summary}" for f in findings if f.kind == Kind.DIFFERENCE)
    assert "1234" in located and "1239" in located


def test_float_statistics_honour_the_rule(pair):
    e, src, _, _, _ = pair
    a = e.adapter(src)
    t = TableRef(e.schema_of(src), "ORDERS" if e.name == "oracle" else "orders")
    col = "WEIGHT" if e.name == "oracle" else "weight"
    assert a.float_stats(t, col).count == N
    assert a.float_stats(t, col, where="status = 'ARCHIVED'").count == N - N // 10


def test_per_side_rules_in_each_dialect(tmp_path, pair):
    e, src, tgt, _, tc = pair
    _exec(e, tc, "DELETE FROM orders WHERE tenant = 'test'")
    rule = IgnoreRule("orders", "test tenant not migrated", source_where="tenant = 'test'")
    _, tables, _ = _run(tmp_path, e, src, tgt, ignore=[rule])
    assert tables["orders"].status == "matched"
    assert tables["orders"].source_rows == N - 100


# ------------------------------------------------------------------- sampling
def test_sampled_aggregates_are_the_full_ones_restricted(pair):
    e, src, _, _, _ = pair
    a = e.adapter(src)
    table = TableRef(e.schema_of(src), "ORDERS" if e.name == "oracle" else "orders")
    tp = plan_table(a.describe(table), None, rows=N, rows_per_bucket=250, precision=6, ignore=[])
    full = a.bucket_aggregates(tp.plan)
    sample = (0, 3, 5, 11)
    got = a.bucket_aggregates(replace(tp.plan, sample=sample))
    assert got == {b: v for b, v in full.items() if b in sample}
    # with a row rule too, and every row read application side (no pushdown)
    filtered = replace(tp.plan, sample=sample, filter="status = 'ARCHIVED'")
    pushed = a.bucket_aggregates(filtered)
    a._pushdown = lambda _plan: False
    assert a.bucket_aggregates(filtered) == pushed
    assert sum(v.count for v in pushed.values()) < sum(got[b].count for b in got)


def test_large_table_is_sampled_and_says_so(tmp_path, pair):
    e, src, tgt, _, _ = pair
    _, tables, findings = _run(
        tmp_path, e, src, tgt, sample_above_rows=1000, sample_percent=25, sample_seed=7
    )
    orders = tables["orders"]
    assert orders.status == "matched" and orders.sampled_percent is not None
    assert orders.source_rows == orders.target_rows < N
    assert any(f.summary.startswith("sampled: 2 of 6") for f in findings)
    assert not any("sampling is not available" in f.summary for f in findings)


# -------------------------------------------------------------------- workers
TABLES = 4


@pytest.fixture
def many(engine):
    src, sc = engine.make("src")
    tgt, tc = engine.make("tgt")
    for i in range(TABLES):
        rows = _rows(500 * (i + 1))
        engine.load(sc, f"t{i}", rows)
        engine.load(tc, f"t{i}", rows)
    if engine.name == "oracle":
        # flashback refuses an SCN older than a table's last DDL (ORA-01466), and Oracle
        # maps time to SCN in steps of a few seconds
        time.sleep(6)
    return engine, src, tgt, sc, tc


def test_workers_reconcile_tables_at_once(tmp_path, many):
    e, src, tgt, _, tc = many
    _exec(e, tc, "UPDATE t2 SET total = 0 WHERE id = 7")
    _, tables, findings = _run(tmp_path, e, src, tgt, workers=3)
    assert {n: t.status for n, t in tables.items()} == {
        "t0": "matched", "t1": "matched", "t2": "different", "t3": "matched",
    }  # fmt: skip
    assert not any("one at a time" in f.summary for f in findings)


def test_baseline_with_workers(tmp_path, many):
    e, src, tgt, _, _ = many
    messages: list[str] = []
    manifest = tmp_path / "b" / "manifest.json"
    a = e.adapter(src)
    take_baseline(a, manifest, baseline_id="b1", schemas=[e.schema_of(src)], tables=None,
                  ignore=[], business_keys={}, rows_per_bucket=250, precision=6, workers=3,
                  progress=messages.append)  # fmt: skip
    b = Baseline.load(manifest)
    assert sorted(t.row_count for t in b.tables.values()) == [500 * (i + 1) for i in range(4)]
    one_at_a_time = any("one at a time" in m for m in messages)
    if e.name == "oracle":  # one SCN shared by every session through DBMS_FLASHBACK
        assert not one_at_a_time and b.position["exact"] is True
    else:  # MySQL and SQL Server cannot hand a snapshot to another connection
        assert one_at_a_time
    writer = FindingWriter(tmp_path / "f", "r")
    opts = _opts(e, src, tgt, rows_per_bucket=250, workers=3)
    result = Reconciler(e.adapter(tgt), writer, opts, baseline=b).run()
    writer.close()
    assert {t.status for t in result.tables} == {"matched"}


# ---------------------------------------------------------------- replication
def test_dms_status_table_on_the_target(engine):
    tgt, tc = engine.make("tgt")
    _exec(engine, tc, engine.status_ddl)
    ref = dt.datetime(2026, 10, 8, 10, 0, 0)
    taken_at = ref.replace(tzinfo=dt.UTC).isoformat()
    position = {"type": "none", "position": None, "taken_at": taken_at}
    a = engine.adapter(tgt)
    schema = engine.schema_of(tgt) if engine.name != "sqlserver" else None
    cfg = ReplicationConfig("dms", "TASK1", control_schema=schema)

    def status(applied, current, pending):
        _exec(engine, tc, "DELETE FROM awsdms_status")
        marks = ", ".join(engine.mark(i) for i in range(7))
        tc.execute(f"INSERT INTO awsdms_status VALUES ({marks})",
                   ("ip-10-0-0-1", "TASK1", "CHANGE PROCESSING", current, pending, current,
                    applied))  # fmt: skip
        if engine.name == "oracle":
            tc.connection.commit()
        return check(cfg, position, source=None, target=a)

    second = dt.timedelta(seconds=1)
    assert status(ref + second, ref + second, 3).status == "caught_up"
    behind = status(ref - second, ref + second, 3)
    assert behind.status == "behind" and "3 changes pending" in behind.applied
    assert status(ref - second, ref + second, 0).status == "caught_up"  # idle source
    assert status(ref - second, ref - second, 0).status == "behind"
    with pytest.raises(Exception, match="not found"):
        check(replace(cfg, name="OTHER"), position, source=None, target=a)


GG_DDL = {
    "mysql": ("CREATE TABLE ggs_checkpoint (group_name varchar(8), group_key bigint, "
              "log_cmplt_csn varchar(129))",
              "CREATE TABLE gg_heartbeat (incoming_replicat varchar(8), "
              "incoming_heartbeat_ts datetime(6))"),
    "oracle": ("CREATE TABLE ggs_checkpoint (group_name VARCHAR2(8), group_key NUMBER(19), "
               "log_cmplt_csn VARCHAR2(129))",
               "CREATE TABLE gg_heartbeat (incoming_replicat VARCHAR2(8), "
               "incoming_heartbeat_ts TIMESTAMP(6))"),
    "sqlserver": ("CREATE TABLE dbo.ggs_checkpoint (group_name varchar(8), group_key bigint, "
                  "log_cmplt_csn varchar(129))",
                  "CREATE TABLE dbo.gg_heartbeat (incoming_replicat varchar(8), "
                  "incoming_heartbeat_ts datetime2(6))"),
}  # fmt: skip


def test_goldengate_tables_on_the_target(engine):
    tgt, tc = engine.make("tgt")
    for ddl in GG_DDL[engine.name]:
        _exec(engine, tc, ddl)
    m = ", ".join(engine.mark(i) for i in range(3))
    tc.executemany(f"INSERT INTO ggs_checkpoint VALUES ({m})",
                   [("REP1    ", 1, "1000"), ("RPAR001", 2, "900"), ("RPAR002", 3, "1100"),
                    ("REP10", 4, "1")])  # fmt: skip
    beat = dt.datetime(2026, 10, 9, 5, 0, 0)
    m2 = ", ".join(engine.mark(i) for i in range(2))
    tc.executemany(f"INSERT INTO gg_heartbeat VALUES ({m2})",
                   [("REP1", beat - dt.timedelta(minutes=1)), ("REP1", beat)])  # fmt: skip
    if engine.name == "oracle":
        tc.connection.commit()
    a = engine.adapter(tgt)
    schema = engine.schema_of(tgt)
    cfg = ReplicationConfig.from_dict({"method": "goldengate", "name": "REP1",
                                       "checkpoint_table": f"{schema}.ggs_checkpoint",
                                       "heartbeat_table": f"{schema}.gg_heartbeat"})  # fmt: skip
    ref = (beat + dt.timedelta(seconds=30)).replace(tzinfo=dt.UTC).isoformat()

    def at(scn, name="REP1", taken_at=ref, kind="scn"):
        pos = {"type": kind, "position": scn, "taken_at": taken_at}
        return check(replace(cfg, name=name), pos, source=None, target=a)

    assert a.goldengate_status(cfg.checkpoint_table, None, "rep1")["csn"] == 1000  # not REP10
    assert at("1000").status == "caught_up"
    behind = at("1001")
    assert behind.status == "behind" and "source CSN 1000" in behind.applied
    assert at("1000", name="RPAR").status == "behind"  # the slowest thread counts
    assert at("950", name="RPAR", taken_at=None).status == "behind"
    # no SCN (a source other than Oracle), or an idle Oracle source: the heartbeat answers
    early = (beat - dt.timedelta(seconds=1)).replace(tzinfo=dt.UTC).isoformat()
    assert at("0/1", kind="lsn", taken_at=early).status == "caught_up"
    assert at("0/1", kind="lsn").status == "behind"
    assert at("1", kind="lsn", taken_at=None).status == "unverified"
    with pytest.raises(ConfigError, match="not found"):
        at("1000", name="OTHER")


def test_live_source_position(engine):
    db, _ = engine.make("src")
    a = engine.adapter(db)
    pos = a.current_position()
    kinds = {"mysql": ("gtid", "binlog", "none"), "oracle": ("scn",), "sqlserver": ("dbts",)}
    assert pos["type"] in kinds[engine.name]
    taken = dt.datetime.fromisoformat(pos["taken_at"])
    assert abs((dt.datetime.now(dt.UTC) - taken).total_seconds()) < 120


@pytest.mark.sqlserver
def test_sqlserver_availability_group(make_sqlserver_db, sqlserver_adapter_for):
    from liftproof.adapters.sqlserver import SQLServerAdapter

    db, _ = make_sqlserver_db("ag")
    a = sqlserver_adapter_for(db)
    # the test server is not in an availability group
    snap = a.begin_snapshot()
    a.end_snapshot()
    assert "commit_lsn" not in snap and a._replicas() == {}
    cfg = ReplicationConfig("availability_group", "EC2AMAZ-TARGET")
    assert check(cfg, snap, source=a, target=a).status == "unverified"
    with pytest.raises(ConfigError, match="not found"):
        check(cfg, {**snap, "commit_lsn": "45000000042000001"}, source=a, target=a)

    class Primary(SQLServerAdapter):
        def __init__(self, replicas):  # noqa: D107 - no connection
            self.replicas = replicas

        def _replicas(self):
            return self.replicas

    ref = {"type": "dbts", "position": "0x07D1", "commit_lsn": "45000000042000001"}
    synced = Primary({"EC2AMAZ-TARGET": ("45000000042000001", "synchronized")})
    r = check(cfg, ref, source=synced, target=a)
    assert r.status == "caught_up" and "synchronized" in r.applied
    lag = Primary({"EC2AMAZ-TARGET": ("45000000041999999", "synchronizing")})
    assert check(cfg, ref, source=lag, target=a).status == "behind"
    assert check(cfg, ref, source=Primary({"EC2AMAZ-TARGET": (None, "not synchronizing")}),
                 target=a).status == "behind"  # fmt: skip


@pytest.mark.mysql
def test_mysql_replica_gtid_and_binlog(make_mysql_db, mysql_adapter_for):
    from liftproof.adapters.mysql import MySQLAdapter

    db, _ = make_mysql_db("t")
    a = mysql_adapter_for(db)
    executed = a.replication_applied("replica", "")
    foreign = "3e11fa47-71ca-11e1-9e33-c80aa9429562:1-5"
    applied, reached = a.replication_reached("replica", "", "gtid", foreign)
    assert not reached and applied == (executed or "(no transactions)")
    if executed:  # GTIDs on: the target's own set is executed
        assert a.replication_reached("replica", "", "gtid", executed)[1]
    k = MySQLAdapter.position_key
    assert k("binlog", "mysql-bin.000009:4") < k("binlog", "mysql-bin.000010:4")
    assert k("binlog", "mysql-bin.000010:4") < k("binlog", "mysql-bin.000010:120")
    # not a replica: nothing to read for a binlog position
    assert a.replication_reached("replica", "", "binlog", "mysql-bin.000001:4") is None


# ---------------------------------------------------------------- report data ranges
def test_data_ranges_follow_the_rule(tmp_path, pair):
    """Spec 12: the range block names the key and date ranges of the rows compared."""
    e, src, tgt, _, _ = pair
    _, tables, _ = _run(tmp_path, e, src, tgt)
    [(column, span)] = tables["orders"].ranges.items()
    assert column.lower() == "id" and span["role"] == "key"
    assert span["source"] == span["target"] == [1, N]
    _, tables, _ = _run(tmp_path, e, src, tgt, ignore=[ARCHIVED], name="g")
    [span] = tables["orders"].ranges.values()
    assert span["source"] == span["target"] == [1, N - 1]  # row N is archived

    _exec(e, pair[4], e.status_ddl)
    marks = ", ".join(e.mark(i) for i in range(7))
    early, late = dt.datetime(2026, 10, 1, 8, 30), dt.datetime(2026, 10, 9, 17, 5, 1)
    for when in (late, early):
        pair[4].execute(f"INSERT INTO awsdms_status VALUES ({marks})",
                        ("h", "T", "RUNNING", when, 0, when, when))  # fmt: skip
    if e.name == "oracle":
        pair[4].connection.commit()
    table = TableRef(e.schema_of(tgt), "AWSDMS_STATUS" if e.name == "oracle" else "awsdms_status")
    column = "STATUS_TIME" if e.name == "oracle" else "status_time"
    assert e.adapter(tgt).value_ranges(table, [column]) == {column: (early, late)}


def test_statements_are_logged_at_debug_without_their_values(pair):
    """Spec 16: --log-level debug shows the SQL each engine is sent, never parameters."""
    import logging

    e, src, tgt, _, tc = pair
    _exec(e, tc, e.status_ddl)
    sql_log = logging.getLogger("liftproof.sql")
    seen: list[str] = []
    handler = logging.Handler()
    handler.emit = lambda record: seen.append(record.getMessage())
    old = sql_log.level
    sql_log.setLevel(logging.DEBUG)
    sql_log.addHandler(handler)
    try:
        a = e.adapter(tgt)
        t = TableRef(e.schema_of(tgt), "ORDERS" if e.name == "oracle" else "orders")
        a.value_ranges(t, ["ID" if e.name == "oracle" else "id"], "status = 'ARCHIVED'")
        schema = e.schema_of(tgt) if e.name != "sqlserver" else None
        assert a.dms_status(schema, "task-named-in-a-parameter") is None
    finally:
        sql_log.removeHandler(handler)
        sql_log.setLevel(old)
    assert any("MIN(" in s and "ARCHIVED" in s for s in seen), seen
    assert any("awsdms_status" in s.lower() for s in seen)
    assert all(s.startswith(f"{a.engine}: ") for s in seen)
    assert not any("task-named-in-a-parameter" in s for s in seen)
