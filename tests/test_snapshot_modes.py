"""A snapshot per table (Technical Spec 9.2). Where a database cannot hold one snapshot for
a whole baseline, each table is read in a snapshot of its own, and the baseline and the
report then say in plain words that cross table consistency was not held; so do they for
a baseline that was resumed, or read without a snapshot. Replication must reach the
latest point a table was read at."""

from __future__ import annotations

import datetime as dt
import json

import psycopg
import pytest

from liftproof.adapters.postgres import PostgresAdapter
from liftproof.canonical import CANONICAL_VERSION, HASH_ALGORITHM
from liftproof.config import load_project
from liftproof.errors import ConfigError, RunFailed
from liftproof.findings import FindingWriter
from liftproof.reconcile import baseline as baseline_mod
from liftproof.reconcile import engine as engine_mod
from liftproof.reconcile.baseline import Baseline, take_baseline
from liftproof.reconcile.engine import ReconcileOptions, Reconciler
from liftproof.reconcile.replication import ReplicationResult

TABLES = 6
SCHEMA = "".join(
    f"CREATE TABLE t{i} (id int PRIMARY KEY, v text);"
    f"INSERT INTO t{i} SELECT g, 'v' || g FROM generate_series(1, {1000 * (i + 1)}) g;"
    for i in range(TABLES)
)
NOT_HELD = "Cross table consistency was not held"


# ------------------------------------------------------------------ the project file
def _project(tmp_path, source: str = "", target: str = ""):
    p = tmp_path / "p.yaml"
    p.write_text(
        "project: t\nsource: {engine: postgresql, host: a, database: a, "
        f"secret_arn: arn:aws:secretsmanager:ap-south-1:111111111111:secret:a{source}}}\n"
        "target: {engine: postgresql, host: b, database: b, "
        f"secret_arn: arn:aws:secretsmanager:ap-south-1:111111111111:secret:b{target}}}\n"
    )
    return load_project(p)


def test_one_snapshot_unless_a_side_says_per_table(tmp_path):
    p = _project(tmp_path)
    assert (p.source.snapshot, p.target.snapshot) == ("whole", "whole")
    p = _project(tmp_path, source=", snapshot: per_table")
    assert (p.source.snapshot, p.target.snapshot) == ("per_table", "whole")


@pytest.mark.parametrize("value", ["per-table", "table", "true"])
def test_snapshot_is_whole_or_per_table(tmp_path, value):
    with pytest.raises(ConfigError, match="target.snapshot is whole .* or per_table"):
        _project(tmp_path, target=f", snapshot: {value}")


# ------------------------------------------------------------------ manifests
def _entry(**kw):
    return {
        "columns": [["id", "integer", "integer", False]],
        "primary_key": ["id"],
        "plan": {"columns": [["id", "integer"]], "key_columns": ["id"], "buckets": 1,
                 "precision": 6},  # fmt: skip
        "row_count": 1,
        "bucket_aggregates": {"0": [1, "7"]},
        "completed_at": "2026-10-01T10:00:00+00:00",
        "canonical_revision": 2,
        **kw,
    }


def _manifest(tmp_path, tables: dict, **position) -> Baseline:
    """A manifest as an earlier build wrote it, unless the entries say otherwise."""
    path = tmp_path / "manifest.json"
    position = {"type": "lsn", "position": "0/100", "taken_at": "2026-10-01T10:00:00+00:00",
                **position}  # fmt: skip
    path.write_text(json.dumps({
        "baseline_id": "b1", "canonical_version": CANONICAL_VERSION,
        "hash_algorithm": HASH_ALGORITHM,
        "product_version": "0", "engine": "postgresql", "consistency": position,
        "session": {}, "taken_at": "2026-10-01T10:00:00+00:00", "selection": list(tables),
        "tables": tables,
    }))  # fmt: skip
    return Baseline.load(path)


FIRST, RESUMED = "2026-10-01T10:00:00+00:00", "2026-10-01T12:00:00+00:00"
LATER = {"type": "lsn", "position": "0/300", "taken_at": RESUMED}


def _read(at: str, snapshot: str = "whole") -> dict:
    return _entry(read_at=at, snapshot=snapshot)


def test_a_manifest_from_before_held_its_one_snapshot(tmp_path):
    b = _manifest(tmp_path, {"public.a": _entry(), "public.b": _entry()})
    assert b.snapshot_mode == "whole" and b.end_position is None
    assert b.consistency() == {
        "held": True, "snapshot": "whole",
        "summary": "Every table of the source was read in one snapshot.",
    }  # fmt: skip
    assert b.reference_position is b.position
    # it is written back as it was read, with how it was taken
    entry = b.tables["public.a"].to_dict()
    assert "read_at" not in entry and "snapshot" not in entry
    assert b.to_dict()["snapshot_mode"] == "whole"


def test_a_resumed_manifest_from_before_did_not(tmp_path):
    b = _manifest(tmp_path, {"public.a": _entry()}, resumed_at=[LATER])
    c = b.consistency()
    assert not c["held"] and c["summary"].startswith(NOT_HELD)
    assert f"resumed at {RESUMED}" in c["summary"]
    # its tables after the resume were read as of the resume
    assert b.reference_position == LATER
    # so is one this build resumed: the entries from before do not say where they were read
    b = _manifest(tmp_path, {"public.a": _entry(), "public.b": _read(RESUMED)}, resumed_at=[LATER])
    assert not b.consistency()["held"] and b.reference_position == LATER


def test_read_without_a_snapshot(tmp_path):
    b = _manifest(tmp_path, {"public.a": _read(FIRST, "none")})
    c = b.consistency()
    assert (c["held"], c["snapshot"]) == (False, "none")
    assert "SQL Server snapshot isolation is off" in c["summary"]
    assert "one table's count and hashes" in c["summary"]
    entry = b.tables["public.a"].to_dict()
    assert (entry["read_at"], entry["snapshot"]) == (FIRST, "none")


def test_snapshots_are_counted_not_their_times(tmp_path):
    """SQL Server's clock can give two snapshots of workers the same time."""
    b = _manifest(tmp_path, {"public.a": _read(FIRST, "per_table"),
                             "public.b": _read(FIRST, "per_table")})  # fmt: skip
    c = b.consistency()
    assert not c["held"] and c["read_between"] == [FIRST, FIRST]
    assert "2 points" in c["summary"] and "each in its own snapshot" in c["summary"]


def test_the_reference_is_the_latest_point_a_table_was_read_at(tmp_path, monkeypatch):
    # a resume that read the rest: their snapshot is the reference
    tables = {"public.a": _read(FIRST), "public.b": _read(RESUMED)}
    b = _manifest(tmp_path, tables, resumed_at=[LATER])
    assert b.reference_position == LATER
    c = b.consistency()
    assert not c["held"] and c["read_between"] == [FIRST, RESUMED]
    assert "2 points" in c["summary"] and "in a new snapshot after a resume" in c["summary"]

    # one that read nothing moves neither
    b = _manifest(tmp_path, {"public.a": _read(FIRST)}, resumed_at=[LATER])
    assert b.consistency()["held"] and b.reference_position is b.position

    # what the replication check is given
    given = []

    def check(cfg, position, **kw):
        given.append(position)
        return ReplicationResult("unverified", None, None, "none", "")

    monkeypatch.setattr(engine_mod, "check", check)
    b = _manifest(tmp_path, tables, resumed_at=[LATER])
    writer = FindingWriter(tmp_path / "f", "r")
    Reconciler(object(), writer, ReconcileOptions(), baseline=b)._replication_behind([])
    writer.close()
    assert given == [LATER]


# ------------------------------------------------------------------ PostgreSQL
@pytest.fixture
def pair(make_db, adapter_for):
    s, sc = make_db("src")
    t, tc = make_db("tgt")
    sc.execute(SCHEMA)
    tc.execute(SCHEMA)
    return adapter_for(s), adapter_for(t), sc, tc


def _baseline(tmp_path, adapter, name="b", **kw) -> Baseline:
    manifest = tmp_path / name / "manifest.json"
    take_baseline(adapter, manifest, baseline_id=name, schemas=["public"], tables=None,
                  ignore=[], business_keys={}, rows_per_bucket=500, precision=6,
                  **kw)  # fmt: skip
    return Baseline.load(manifest)


def _write_during_first_table(monkeypatch, sc) -> list[str]:
    """The first table's hashes are read after a row went into every table."""
    real = PostgresAdapter.bucket_aggregates
    lsn: list[str] = []

    def write_first(self, plan):
        if not lsn:
            for i in range(TABLES):
                sc.execute(f"INSERT INTO t{i} VALUES (999999, 'late')")
            lsn.append(sc.execute("SELECT pg_current_wal_lsn()::text").fetchone()[0])
        return real(self, plan)

    monkeypatch.setattr(PostgresAdapter, "bucket_aggregates", write_first)
    return lsn


@pytest.mark.postgres
def test_each_table_is_read_in_a_snapshot_of_its_own(tmp_path, pair, monkeypatch):
    src, _, sc, _ = pair
    lsn = _write_during_first_table(monkeypatch, sc)
    b = _baseline(tmp_path, src, snapshot="per_table")
    for q, t in b.tables.items():  # a table's count and hashes are one state of it
        assert sum(a.count for a in t.buckets.values()) == t.row_count, q
    assert {q: t.row_count for q, t in b.tables.items()} == {
        f"public.t{i}": 1000 * (i + 1) + (i > 0) for i in range(TABLES)
    }
    assert b.snapshot_mode == "per_table"
    assert {t.snapshot for t in b.tables.values()} == {"per_table"}
    assert len({t.read_at for t in b.tables.values()}) == TABLES
    c = b.consistency()
    assert not c["held"] and c["snapshot"] == "per_table"
    assert c["summary"].startswith(NOT_HELD) and "6 points" in c["summary"]
    assert "each in its own snapshot" in c["summary"]
    # replication must reach past the late rows the later tables hold
    key = PostgresAdapter.position_key
    assert b.reference_position is b.end_position and b.end_position["type"] == "lsn"
    assert key("lsn", b.end_position["position"]) >= key("lsn", lsn[0])
    assert key("lsn", b.position["position"]) < key("lsn", lsn[0])  # the start is kept


@pytest.mark.postgres
def test_per_table_workers_open_their_own(tmp_path, pair, monkeypatch):
    src, tgt, _, _ = pair
    forks: list = []
    real = PostgresAdapter.fork

    def fork(self, snapshot=None):
        forks.append(snapshot)
        return real(self, snapshot)

    def never(self, position):
        raise AssertionError("nothing is shared per table")

    monkeypatch.setattr(PostgresAdapter, "fork", fork)
    monkeypatch.setattr(PostgresAdapter, "shares_snapshot", never)
    messages: list[str] = []
    b = _baseline(tmp_path, src, snapshot="per_table", workers=3, progress=messages.append)
    assert forks == [None, None] and not any("one at a time" in m for m in messages)
    writer = FindingWriter(tmp_path / "f", "r")
    result = Reconciler(tgt, writer, ReconcileOptions(rows_per_bucket=500), baseline=b).run()
    writer.close()
    assert {t.status for t in result.tables} == {"matched"}


class Stopped(BaseException):
    """Nothing in the product handles this, as nothing runs when an instance dies."""


def _stop_at(monkeypatch, table: str):
    real = baseline_mod.plan_table

    def plan_or_stop(schema, *a, **kw):
        if schema.table.name == table:
            raise Stopped
        return real(schema, *a, **kw)

    monkeypatch.setattr(baseline_mod, "plan_table", plan_or_stop)
    return real


@pytest.mark.parametrize("then", ["whole", "per_table"])
@pytest.mark.postgres
def test_a_resumed_baseline_says_where_it_was_not_held(tmp_path, pair, monkeypatch, then):
    src, _, _, _ = pair
    real = _stop_at(monkeypatch, "t3")
    with pytest.raises(Stopped):
        _baseline(tmp_path, src)
    first = json.loads((tmp_path / "b" / "manifest.json").read_text())["consistency"]
    monkeypatch.setattr(baseline_mod, "plan_table", real)
    b = _baseline(tmp_path, src, resume=True, snapshot=then)
    read = {q.split(".")[1]: t.read_at for q, t in b.tables.items()}
    assert read["t0"] == read["t1"] == read["t2"] == first["taken_at"]
    [resumed] = b.position["resumed_at"]
    c = b.consistency()
    assert not c["held"] and c["read_between"][0] == first["taken_at"]
    if then == "whole":  # the rest in the resume's snapshot
        assert read["t3"] == read["t4"] == read["t5"] == resumed["taken_at"]
        assert b.snapshot_mode == "whole" and "2 points" in c["summary"]
        assert b.reference_position == resumed
    else:  # the rest each in its own, after the resume
        assert len({read["t3"], read["t4"], read["t5"], first["taken_at"]}) == 4
        assert b.snapshot_mode == "mixed" and "4 points" in c["summary"]
        assert b.reference_position == b.end_position
        when = dt.datetime.fromisoformat
        assert when(b.end_position["taken_at"]) > max(map(when, read.values()))
    assert b.position["position"] == first["position"]  # the start is kept

    # resumed again with nothing left to read: nothing moves
    again = _baseline(tmp_path, src, resume=True, snapshot=then)
    assert again.position["resumed_at"] == [resumed]
    assert again.reference_position == b.reference_position


@pytest.mark.postgres
def test_resuming_a_whole_baseline_that_read_nothing_still_held(tmp_path, pair):
    src, _, _, _ = pair
    b = _baseline(tmp_path, src)
    again = _baseline(tmp_path, src, resume=True)
    assert again.consistency()["held"] and "resumed_at" not in again.position
    assert again.reference_position == b.position


@pytest.mark.postgres
def test_a_snapshot_too_old_names_the_fallback(tmp_path, pair, monkeypatch):
    src, _, _, _ = pair
    real = PostgresAdapter.bucket_aggregates

    def too_old(self, plan):
        if plan.table.name == "t2":
            raise psycopg.errors.SnapshotTooOld("snapshot too old")
        return real(self, plan)

    monkeypatch.setattr(PostgresAdapter, "bucket_aggregates", too_old)
    with pytest.raises(RunFailed, match=r"source.snapshot: per_table .* --resume"):
        _baseline(tmp_path, src)
    with pytest.raises(psycopg.errors.SnapshotTooOld):  # nothing to fall back to
        _baseline(tmp_path, src, "c", snapshot="per_table")
    monkeypatch.setattr(PostgresAdapter, "bucket_aggregates", real)
    b = _baseline(tmp_path, src, resume=True, snapshot="per_table")
    assert b.complete and b.snapshot_mode == "mixed"
