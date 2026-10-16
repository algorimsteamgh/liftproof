"""Parallel database workers (Technical Spec 9.1, 9.15). Tables are reconciled several at a
time on separate connections, and a baseline taken by several workers still reads one
snapshot: every worker imports the snapshot the first connection exported."""

import pytest

from liftproof.config import load_project
from liftproof.errors import ConfigError
from liftproof.findings import FindingWriter, Kind, read_findings
from liftproof.reconcile.baseline import Baseline, take_baseline
from liftproof.reconcile.engine import ReconcileOptions, Reconciler

TABLES = 6
SCHEMA = "".join(
    f"CREATE TABLE t{i} (id int PRIMARY KEY, v text);"
    f"INSERT INTO t{i} SELECT g, 'v' || g FROM generate_series(1, {1000 * (i + 1)}) g;"
    for i in range(TABLES)
)


@pytest.fixture
def pair(make_db, adapter_for):
    s, sc = make_db("src")
    t, tc = make_db("tgt")
    sc.execute(SCHEMA)
    tc.execute(SCHEMA)
    return adapter_for(s), adapter_for(t), sc, tc


def _run(tmp_path, target, name="f", **kw):
    workers = kw.pop("workers")
    writer = FindingWriter(tmp_path / name, "r", segment_size=3)
    opts = ReconcileOptions(rows_per_bucket=500, workers=workers)
    result = Reconciler(target, writer, opts, **kw).run()
    writer.close()
    return result, list(read_findings(tmp_path / name))


@pytest.mark.postgres
def test_workers_give_the_same_result_as_one(tmp_path, pair):
    src, tgt, _, tc = pair
    tc.execute("DELETE FROM t2 WHERE id IN (5, 6)")
    tc.execute("UPDATE t4 SET v = 'x' WHERE id = 9")
    one, f1 = _run(tmp_path, tgt, "a", source=src, workers=1)
    many, f4 = _run(tmp_path, tgt, "b", source=src, workers=4)
    assert [t.table for t in many.tables] == [f"public.t{i}" for i in range(TABLES)]
    assert [(t.table, t.status, t.missing_rows, t.changed_rows) for t in many.tables] == [
        (t.table, t.status, t.missing_rows, t.changed_rows) for t in one.tables
    ]

    def key(f):
        return (f.object, f.summary, f.locator)

    assert sorted(map(key, f4)) == sorted(map(key, f1))
    assert {f.locator for f in f4 if f.kind == Kind.DIFFERENCE and f.locator} == {
        "id = 5", "id = 6", "id = 9"
    }  # fmt: skip


@pytest.mark.postgres
def test_baseline_workers_read_one_snapshot(tmp_path, pair, monkeypatch):
    """A write committed while workers are hashing is in no worker's view."""
    src, tgt, sc, _ = pair
    from liftproof.adapters.postgres import PostgresAdapter

    real = PostgresAdapter.bucket_aggregates
    wrote = []

    def slow(self, plan):
        if not wrote:  # the first table hashed: change every table under the baseline
            wrote.append(1)
            for i in range(TABLES):
                sc.execute(f"INSERT INTO t{i} VALUES (999999, 'late')")
        return real(self, plan)

    monkeypatch.setattr(PostgresAdapter, "bucket_aggregates", slow)
    manifest = tmp_path / "b" / "manifest.json"
    take_baseline(src, manifest, baseline_id="b1", schemas=["public"], tables=None, ignore=[],
                  business_keys={}, rows_per_bucket=500, precision=6, workers=3)  # fmt: skip
    b = Baseline.load(manifest)
    assert {q: t.row_count for q, t in b.tables.items()} == {
        f"public.t{i}": 1000 * (i + 1) for i in range(TABLES)
    }
    assert {t.read_at for t in b.tables.values()} == {b.position["taken_at"]}
    assert b.consistency()["held"] and b.reference_position is b.position
    monkeypatch.setattr(PostgresAdapter, "bucket_aggregates", real)
    result, _ = _run(tmp_path, tgt, baseline=b, workers=3)
    assert {t.status for t in result.tables} == {"matched"}


@pytest.mark.postgres
def test_engine_without_workers_runs_one_at_a_time(tmp_path, pair, monkeypatch):
    src, tgt, _, _ = pair
    monkeypatch.setattr(type(tgt), "supports_workers", False)
    result, findings = _run(tmp_path, tgt, source=src, workers=4)
    assert {t.status for t in result.tables} == {"matched"}
    assert any("one at a time" in f.summary for f in findings)


@pytest.mark.parametrize("value", [0, 9, "4"])
def test_workers_are_bounded(tmp_path, value):
    p = tmp_path / "p.yaml"
    p.write_text(
        "project: t\nsource: {engine: postgresql, host: a, database: a, "
        "secret_arn: arn:aws:secretsmanager:ap-south-1:111111111111:secret:a}\n"
        "target: {engine: postgresql, host: b, database: b, "
        "secret_arn: arn:aws:secretsmanager:ap-south-1:111111111111:secret:b}\n"
        f"database: {{workers: {value!r}}}\n"
    )
    with pytest.raises(ConfigError, match="database.workers"):
        load_project(p)
