"""Replication position check (Technical Spec 9.2, 18): a row still in flight is not a
lost row. Real PostgreSQL logical replication where the server allows it
(wal_level = logical), and the waiting rules against a stand in."""

from __future__ import annotations

import time
import uuid

import psycopg
import pytest

from liftproof.adapters.postgres import PostgresAdapter
from liftproof.errors import ConfigError
from liftproof.findings import FindingWriter, Kind, read_findings
from liftproof.reconcile.engine import ReconcileOptions, Reconciler
from liftproof.reconcile.replication import REASON_BEHIND, ReplicationConfig, check
from tests.conftest import PG, _admin


# ------------------------------------------------------------------ the rules
class Stand(PostgresAdapter):
    """A target whose subscription reports positions from a list."""

    def __init__(self, applied):  # noqa: D107 - no connection
        self.applied = list(applied)
        self.calls = 0

    def replication_applied(self, method, name):
        self.calls += 1
        return self.applied[min(self.calls - 1, len(self.applied) - 1)]


class Clock:
    def __init__(self):
        self.now = 0.0

    def sleep(self, s):
        self.now += s


def test_lsn_order():
    k = PostgresAdapter.position_key
    assert k("lsn", "0/16B3748") < k("lsn", "0/16B3750") < k("lsn", "1/0")


def test_waits_for_replication_then_reports_caught_up():
    c = Clock()
    stand = Stand(["0/100", "0/180", "0/200"])
    cfg = ReplicationConfig("subscription", "sub", wait_seconds=60, poll_seconds=5)
    r = check(cfg, {"type": "lsn", "position": "0/200"}, source=None, target=stand,
              sleep=c.sleep, clock=lambda: c.now)  # fmt: skip
    assert (r.status, r.applied, stand.calls, r.waited_seconds) == ("caught_up", "0/200", 3, 10)


def test_gives_up_after_the_wait():
    c = Clock()
    cfg = ReplicationConfig("subscription", "sub", wait_seconds=12, poll_seconds=5)
    r = check(cfg, {"type": "lsn", "position": "0/200"}, source=None, target=Stand(["0/100"]),
              sleep=c.sleep, clock=lambda: c.now)  # fmt: skip
    assert r.behind and r.applied == "0/100" and r.waited_seconds == 12


def test_unverified_without_a_method_or_a_position():
    assert check(ReplicationConfig(), {"type": "lsn", "position": "0/1"}, source=None,
                 target=Stand([])).status == "unverified"  # fmt: skip
    cfg = ReplicationConfig("subscription", "sub")
    assert check(cfg, None, source=None, target=Stand([])).status == "unverified"
    with pytest.raises(ConfigError, match="not found"):
        check(cfg, {"type": "lsn", "position": "0/1"}, source=None, target=Stand([None]))


def test_config_rules():
    assert ReplicationConfig.from_dict(None).method == "none"
    with pytest.raises(ConfigError, match="must be one of"):
        ReplicationConfig.from_dict({"method": "logshipping"})
    with pytest.raises(ConfigError, match="checkpoint_table, heartbeat_table or both"):
        ReplicationConfig.from_dict({"method": "goldengate", "name": "REP1"})
    with pytest.raises(ConfigError, match="table or schema.table"):
        ReplicationConfig.from_dict({"method": "goldengate", "name": "REP1",
                                     "checkpoint_table": "gg.ckpt; drop"})  # fmt: skip
    gg = ReplicationConfig.from_dict({"method": "goldengate", "name": "REP1",
                                      "checkpoint_table": "ggadmin.ggs_checkpoint"})  # fmt: skip
    assert (gg.checkpoint_table, gg.heartbeat_table) == ("ggadmin.ggs_checkpoint", None)
    with pytest.raises(ConfigError, match="name is required"):
        ReplicationConfig.from_dict({"method": "slot"})
    with pytest.raises(ConfigError, match="name is required"):
        ReplicationConfig.from_dict({"method": "dms"})
    assert ReplicationConfig.from_dict({"method": "replica"}).name is None  # default channel
    with pytest.raises(ConfigError, match="plain name"):
        ReplicationConfig.from_dict({"method": "dms", "name": "T", "control_schema": "a;b"})


# --------------------------------------------------------- real replication
def _logical():
    try:
        with _admin() as c:
            return c.execute("SHOW wal_level").fetchone()[0] == "logical"
    except psycopg.OperationalError:
        return False


logical = pytest.mark.skipif(not _logical(), reason="PostgreSQL wal_level is not logical")

TABLE = "CREATE TABLE orders (id int PRIMARY KEY, status text)"


@pytest.fixture
def replicated(make_db, adapter_for):
    """A source with a logical slot and publication, and an empty target."""
    s, sc = make_db("rs")
    t, tc = make_db("rt")
    sc.execute(TABLE)
    tc.execute(TABLE)
    slot = f"lp_{uuid.uuid4().hex[:8]}"
    sc.execute("CREATE PUBLICATION lp_pub FOR TABLE orders")
    sc.execute("SELECT pg_create_logical_replication_slot(%s, 'pgoutput')", (slot,))
    # written after the slot: in flight until a consumer applies them
    sc.execute("INSERT INTO orders SELECT g, 'OPEN' FROM generate_series(1, 100) g")
    yield s, sc, t, tc, slot
    for c, q in ((tc, "DROP SUBSCRIPTION IF EXISTS lp_sub"),):
        try:
            c.execute("ALTER SUBSCRIPTION lp_sub DISABLE")
            c.execute("ALTER SUBSCRIPTION lp_sub SET (slot_name = NONE)")
        except psycopg.Error:
            pass
        c.execute(q)
    sc.execute("SELECT pg_drop_replication_slot(slot_name) FROM pg_replication_slots "
               "WHERE slot_name = %s", (slot,))  # fmt: skip


def _reconcile(tmp_path, source, target, cfg):
    writer = FindingWriter(tmp_path / f"f-{uuid.uuid4().hex[:6]}", "r")
    result = Reconciler(target, writer, ReconcileOptions(rows_per_bucket=50, replication=cfg),
                        source=source).run()  # fmt: skip
    writer.close()
    return result, list(read_findings(writer.directory))


@pytest.mark.postgres
@logical
def test_slot_behind_is_not_checked_never_a_difference(tmp_path, replicated, adapter_for):
    s, sc, t, tc, slot = replicated
    # the target has nothing yet: by the data alone, 100 rows are missing
    cfg = ReplicationConfig("slot", slot)
    result, findings = _reconcile(tmp_path, adapter_for(s), adapter_for(t), cfg)
    assert result.replication["status"] == "behind"
    assert [x.status for x in result.tables] == ["not_checked"]
    assert not [f for f in findings if f.kind == Kind.DIFFERENCE]
    assert REASON_BEHIND in findings[0].summary

    # the consumer catches up (here: the slot is advanced) and the real comparison runs
    sc.execute("SELECT pg_replication_slot_advance(%s, pg_current_wal_lsn())", (slot,))
    result, findings = _reconcile(tmp_path, adapter_for(s), adapter_for(t), cfg)
    assert result.replication["status"] == "caught_up"
    assert [x.status for x in result.tables] == ["different"]


@pytest.mark.postgres
@logical
def test_subscription_waits_until_rows_in_flight_have_landed(tmp_path, replicated, adapter_for):
    s, sc, t, tc, slot = replicated
    host = PG["host"]
    conninfo = f"host={host} port={PG['port']} dbname={s} user={PG['user']}"
    if PG["password"]:
        conninfo += f" password={PG['password']}"
    tc.execute(f"CREATE SUBSCRIPTION lp_sub CONNECTION '{conninfo}' PUBLICATION lp_pub "
               f"WITH (create_slot = false, slot_name = '{slot}', copy_data = false)")  # fmt: skip
    sc.execute("UPDATE orders SET status = 'PAID' WHERE id <= 10")
    cfg = ReplicationConfig("subscription", "lp_sub", wait_seconds=60, poll_seconds=1)
    t0 = time.monotonic()
    result, findings = _reconcile(tmp_path, adapter_for(s), adapter_for(t), cfg)
    assert result.replication["status"] == "caught_up", result.replication
    assert time.monotonic() - t0 < 60
    assert [x.status for x in result.tables] == ["matched"], [f.summary for f in findings]


# ------------------------------------------------------------ GoldenGate on PostgreSQL
@pytest.mark.postgres
def test_goldengate_tables_on_a_postgresql_target(make_db, adapter_for):
    import datetime as dt

    db, cur = make_db("gg")
    cur.execute("CREATE TABLE ggs_checkpoint (group_name varchar(8), group_key bigint, "
                "log_cmplt_csn varchar(129));"
                "CREATE TABLE gg_heartbeat (incoming_replicat varchar(8), "
                "incoming_heartbeat_ts timestamp(6));"
                "INSERT INTO ggs_checkpoint VALUES ('REP1    ', 1, '5000');"
                "INSERT INTO gg_heartbeat VALUES ('REP1', '2026-10-09 05:00:00')")  # fmt: skip
    a = adapter_for(db)
    cfg = ReplicationConfig.from_dict({"method": "goldengate", "name": "rep1",
                                       "checkpoint_table": "public.ggs_checkpoint",
                                       "heartbeat_table": "gg_heartbeat"})  # fmt: skip
    at = dt.datetime(2026, 10, 9, 5, 0, 30, tzinfo=dt.UTC).isoformat()
    r = check(cfg, {"type": "scn", "position": "4000", "taken_at": at}, source=None, target=a)
    assert r.status == "caught_up" and "source CSN 5000" in r.applied
    # a PostgreSQL source has no SCN: the heartbeat answers, and is older than the snapshot
    r = check(cfg, {"type": "lsn", "position": "0/1", "taken_at": at}, source=None, target=a)
    assert r.status == "behind" and "heartbeat from 2026-10-09T05:00:00" in r.applied
