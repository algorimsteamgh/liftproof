"""Nothing irreplaceable stays on the instance (spec 3, 9.16 and 18). A reconciliation or
a baseline that loses its instance halfway resumes on a replacement pointed at the same
bucket, and the replacement finds the projects, journeys and run history again.

"Losing the instance" here is an exception that no handler in the product catches,
followed by deleting the whole work directory; the replacement gets a new one.
"""

from __future__ import annotations

import json
import shutil
from collections import Counter

import pytest
import yaml

from liftproof import checkpoint as ckpt
from liftproof import cli
from liftproof.credentials import DbCredentials
from liftproof.errors import EXIT_CONFIG, EXIT_DIFFERENCES, EXIT_RUN_FAILED
from liftproof.findings import Comparator, Finding, FindingWriter, Kind, read_findings
from liftproof.reconcile import baseline as baseline_mod
from liftproof.reconcile.engine import REASON_STOPPED, Reconciler
from liftproof.store import S3Store
from tests.conftest import PG

BUCKET = "acme-mvt"
SECRET = "arn:aws:secretsmanager:ap-south-1:000000000000:secret:liftproof/test"
TABLES = ("t1", "t2", "t3", "t4")


class InstanceLost(BaseException):
    """Nothing in the product handles this, as nothing runs when an instance dies."""


@pytest.fixture(autouse=True)
def secret(monkeypatch):
    monkeypatch.setattr(cli, "from_secrets_manager",
                        lambda arn: DbCredentials(PG["user"], PG["password"]))  # fmt: skip


@pytest.fixture
def s3(tmp_path, monkeypatch):
    moto = pytest.importorskip("moto")
    import boto3

    with moto.mock_aws():
        client = boto3.client("s3", region_name="ap-south-1")
        client.create_bucket(
            Bucket=BUCKET, CreateBucketConfiguration={"LocationConstraint": "ap-south-1"}
        )
        monkeypatch.setattr("liftproof.store.aws.client", lambda service, region=None: client)
        settings = tmp_path / "instance.yaml"
        settings.write_text(yaml.safe_dump({"deployment": "acme", "bucket": BUCKET}))
        monkeypatch.setattr(cli, "INSTANCE_CONFIG", settings)
        yield client


def _keys(s3, prefix: str) -> list[str]:
    return [o["Key"] for o in s3.list_objects_v2(Bucket=BUCKET, Prefix=prefix).get("Contents", [])]


@pytest.fixture
def project(tmp_path, make_db):
    """Four tables, each with one changed row: four findings when all is compared."""
    s, sc = make_db("src")
    t, tc = make_db("tgt")
    for c in (sc, tc):
        for name in TABLES:
            c.execute(f"CREATE TABLE {name} (id int PRIMARY KEY, v text)")
            c.execute(f"INSERT INTO {name} SELECT g, 'v' || g FROM generate_series(1, 50) g")
    for name in TABLES:
        tc.execute(f"UPDATE {name} SET v = 'changed' WHERE id = 7")
    conn = {"engine": "postgresql", "host": PG["host"], "port": PG["port"], "user": PG["user"],
            "sslmode": "disable", "secret_arn": SECRET}  # fmt: skip
    doc = {"project": "acme", "source": dict(conn, database=s),
           "target": dict(conn, database=t), "database": {"rows_per_bucket": 20}}  # fmt: skip
    path = tmp_path / "projects" / "acme.yaml"
    path.parent.mkdir()
    path.write_text(yaml.safe_dump(doc))
    return path


def _main(*argv) -> int:
    return cli.main([*argv, "--format", "json"])


def _lose_instance_at(monkeypatch, table: str, compared: list[str]):
    original = Reconciler._table

    def table_or_crash(self, ref, tref):
        if ref.name == table:
            raise InstanceLost
        compared.append(ref.name)
        return original(self, ref, tref)

    monkeypatch.setattr(Reconciler, "_table", table_or_crash)


def _checkpoint_times(monkeypatch, *answers: bool):
    """Which calls to the checkpoint throttle are due, in order (then never)."""
    queue = list(answers)
    monkeypatch.setattr(ckpt.Throttle, "due", lambda self: queue.pop(0) if queue else False)


def test_reconcile_resumes_on_a_replacement_instance(tmp_path, project, monkeypatch, s3):
    first, second = tmp_path / "first", tmp_path / "second"
    original = Reconciler._table
    compared: list[str] = []
    # checkpoints after the table list and after t1; t2 finishes but is not checkpointed
    _checkpoint_times(monkeypatch, True, True, False)
    _lose_instance_at(monkeypatch, "t3", compared)
    with pytest.raises(InstanceLost):
        _main("reconcile", "--project", str(project), "--workdir", str(first), "--run-id", "r1")
    assert compared == ["t1", "t2"]
    # the last checkpoint names the segments up to t1's; t2's reached the store when the
    # dying process closed its writer, and must not be read as well as t2's second pass
    saved = s3.get_object(Bucket=BUCKET, Key="acme/runs/r1/progress.json")["Body"].read()
    saved = json.loads(saved)
    assert [t["table"] for t in saved["tables"]] == ["public.t1"]
    assert len(_keys(s3, "acme/runs/r1/findings-")) == len(saved["segments"]) + 1
    shutil.rmtree(first)

    compared.clear()

    def counting(self, ref, tref):
        compared.append(ref.name)
        return original(self, ref, tref)

    monkeypatch.setattr(Reconciler, "_table", counting)
    code = _main("reconcile", "--project", str(project), "--workdir", str(second), "--resume")
    assert code == EXIT_DIFFERENCES
    assert compared == ["t2", "t3", "t4"]  # t1 was finished and checkpointed

    report = json.loads((second / "acme/runs/r1/report.json").read_text())
    differences = Counter(f["object"] for f in report["findings"] if f["kind"] == "difference")
    # the tables are alike: t1's findings come from the first instance, t2's from the
    # second alone (the first one's copy was voided), t3 and t4's from the second
    assert set(differences) == {f"public.{t}" for t in TABLES}
    assert set(differences.values()) == {differences["public.t1"]}
    ids = [f["finding_id"] for f in report["findings"]]
    assert len(ids) == len(set(ids))
    assert [t["status"] for t in report["tables"]] == ["different"] * 4
    assert report["run"]["resumed_at"] == report["range"]["resumed_at"]
    assert report["coverage"]["tables_coverage_pct"] == 100
    # the voided segment holds nothing, so a reader of the store sees each finding once
    stored = tmp_path / "from-store"
    stored.mkdir()
    for key in _keys(s3, "acme/runs/r1/findings-"):
        s3.download_file(BUCKET, key, str(stored / key.rsplit("/", 1)[1]))
    assert sorted(f.finding_id for f in read_findings(stored)) == sorted(ids)
    assert "acme/runs/r1/report.json" in _keys(s3, "acme/runs/r1/")
    # finished: nothing left to resume
    assert _main("reconcile", "--project", str(project), "--workdir", str(second),
                 "--resume") == EXIT_CONFIG  # fmt: skip


@pytest.mark.usefixtures("s3")
def test_a_failed_run_names_what_it_never_compared_and_resumes(tmp_path, project, monkeypatch):
    work = tmp_path / "w"
    original = Reconciler._table

    def flaky(self, ref, tref):
        if ref.name == "t3":
            raise ConnectionError("server closed the connection unexpectedly")
        return original(self, ref, tref)

    monkeypatch.setattr(Reconciler, "_table", flaky)
    code = _main("reconcile", "--project", str(project), "--workdir", str(work), "--run-id", "r2")
    assert code == EXIT_RUN_FAILED
    report = json.loads((work / "acme/runs/r2/report.json").read_text())
    status = {t["table"]: t["status"] for t in report["tables"]}
    assert status == {"public.t1": "different", "public.t2": "different",
                      "public.t3": "not_checked", "public.t4": "not_checked"}  # fmt: skip
    assert report["coverage"]["tables_coverage_pct"] == 50
    assert {c["object"] for c in report["coverage"]["not_covered"]} == {"public.t3", "public.t4"}
    assert all(c["reason"] == REASON_STOPPED for c in report["coverage"]["not_covered"])

    monkeypatch.setattr(Reconciler, "_table", original)
    code = _main("reconcile", "--project", str(project), "--workdir", str(work), "--resume")
    assert code == EXIT_DIFFERENCES
    report = json.loads((work / "acme/runs/r2/report.json").read_text())
    assert report["verdict"] != "run failed" and report["failure"] is None
    assert [t["status"] for t in report["tables"]] == ["different"] * 4
    differences = Counter(f["object"] for f in report["findings"] if f["kind"] == "difference")
    assert len(differences) == 4 and len(set(differences.values())) == 1
    assert not [f for f in report["findings"] if f["kind"] in ("error", "not_checked")]


def test_baseline_resumes_on_a_replacement_instance(tmp_path, project, monkeypatch, s3):
    first, second = tmp_path / "first", tmp_path / "second"
    monkeypatch.setattr(ckpt.Throttle, "due", lambda self: True)
    taken: list[str] = []
    original = baseline_mod.plan_table

    def plan_or_crash(schema, *a, **kw):
        if schema.table.name == "t3":
            raise InstanceLost
        taken.append(schema.table.name)
        return original(schema, *a, **kw)

    monkeypatch.setattr(baseline_mod, "plan_table", plan_or_crash)
    with pytest.raises(InstanceLost):
        _main("baseline", "--project", str(project), "--workdir", str(first))
    shutil.rmtree(first)
    [marker] = _keys(s3, "acme/baselines/in-progress-source")
    bid = s3.get_object(Bucket=BUCKET, Key=marker)["Body"].read().decode()
    # an unfinished baseline is never compared against
    assert _main("reconcile", "--project", str(project), "--workdir", str(second),
                 "--baseline", bid) == EXIT_CONFIG  # fmt: skip

    monkeypatch.setattr(baseline_mod, "plan_table", original)
    resumed: list[str] = []

    def counting(schema, *a, **kw):
        resumed.append(schema.table.name)
        return original(schema, *a, **kw)

    monkeypatch.setattr(baseline_mod, "plan_table", counting)
    assert _main("baseline", "--project", str(project), "--workdir", str(second), "--resume") == 0
    assert taken == ["t1", "t2"] and resumed == ["t3", "t4"]
    manifest = json.loads(
        s3.get_object(Bucket=BUCKET, Key=f"acme/baselines/{bid}/manifest.json")["Body"].read()
    )
    assert manifest["complete"] and len(manifest["tables"]) == 4
    assert s3.get_object(Bucket=BUCKET, Key=marker)["Body"].read() == b""
    assert _main("reconcile", "--project", str(project), "--workdir", str(second),
                 "--baseline", "latest") == EXIT_DIFFERENCES  # fmt: skip


def test_a_replacement_finds_projects_journeys_and_history(tmp_path, project, s3):
    first = tmp_path / "first"
    assert _main("reconcile", "--project", str(project), "--workdir", str(first),
                 "--run-id", "r9") == EXIT_DIFFERENCES  # fmt: skip
    assert "acme/project.yaml" in _keys(s3, "acme/")
    assert _keys(s3, ".liftproof/projects/") == [".liftproof/projects/acme.yaml"]

    projects = tmp_path / "replacement" / "projects"
    assert _main("restore", "--projects-dir", str(projects)) == 0
    restored = projects / "acme.yaml"
    assert restored.read_text() == project.read_text()
    restored.write_text(restored.read_text() + "# edited on this instance\n")
    assert _main("restore", "--projects-dir", str(projects)) == 0
    assert restored.read_text().endswith("# edited on this instance\n")  # never overwritten

    work = projects  # as on the AMI: project files and work directories side by side
    store = cli._store(cli.load_project(restored), work)
    history = cli.run_history(work / "acme" / "runs")
    assert history == []
    cli.sync_reports(store, work / "acme" / "runs")
    assert [r["run_id"] for r in cli.run_history(work / "acme" / "runs")] == ["r9"]

    s3.put_object(Bucket=BUCKET, Key="acme/journeys/checkout.json", Body=b"{}")
    s3.put_object(Bucket=BUCKET, Key="acme/journeys/checkout/assets/abc", Body=b"x")
    (work / "acme" / "journeys").mkdir(parents=True)
    (work / "acme" / "journeys" / "login.json").write_text("{}")
    assert cli.journey_index(store, work / "acme") == ["checkout", "login"]


def test_restore_needs_a_bucket(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "INSTANCE_CONFIG", tmp_path / "none.yaml")
    assert _main("restore", "--projects-dir", str(tmp_path / "p")) == EXIT_CONFIG


def test_validate_names_the_stages_a_failure_never_reached(tmp_path, project, monkeypatch):
    doc = yaml.safe_load(project.read_text())
    doc["files"] = [{"name": "docs", "source": str(tmp_path), "target": str(tmp_path)}]
    project.write_text(yaml.safe_dump(doc))

    def broken(*a, **kw):
        raise RuntimeError("lost the target")

    monkeypatch.setattr(cli, "_reconcile_into", broken)
    work = tmp_path / "w"
    code = _main("validate", "--project", str(project), "--workdir", str(work), "--run-id", "v1")
    assert code == EXIT_RUN_FAILED
    report = json.loads((work / "acme/runs/v1/report.json").read_text())
    assert {"object": "file set docs", "reason": cli.STOPPED} in report["coverage"]["not_covered"]
    assert report["counts"]["not_checked"] >= 1


def test_findings_reach_the_store_while_the_run_goes(tmp_path):
    sent: list[str] = []
    w = FindingWriter(tmp_path, "r", on_segment=lambda p: sent.append(p.name), flush_seconds=0)
    w.write(Finding(Comparator.DATABASE, Kind.DIFFERENCE, 50, "a", "x"))
    w.write(Finding(Comparator.DATABASE, Kind.DIFFERENCE, 50, "b", "y"))
    assert sent == ["findings-00001.jsonl", "findings-00002.jsonl"]

    # resuming keeps the named segments, drops later ones, and numbers on from there
    w2 = FindingWriter(tmp_path, "r", keep=["findings-00001.jsonl"])
    assert not (tmp_path / "findings-00002.jsonl").exists()
    assert w2.write(Finding(Comparator.DATABASE, Kind.NOTICE, 10, "c", "z")).finding_id == (
        "f-000002"
    )
    assert [p.name for p in w2.close()] == ["findings-00001.jsonl", "findings-00002.jsonl"]


def test_a_failed_segment_copy_does_not_stop_the_run(tmp_path):
    class Flaky(S3Store):
        def __init__(self):
            self.calls = 0

        def put_file(self, key, path):
            self.calls += 1
            if self.calls == 1:
                from liftproof.errors import RunFailed

                raise RunFailed("S3 write failed")

    store = Flaky()
    uploads = ckpt.SegmentUploads(store, "r")
    seg = tmp_path / "findings-00001.jsonl"
    seg.write_text("")
    uploads(seg)  # fails, logged
    assert uploads.done == set()
    assert uploads.catch_up([seg]) and uploads.done == {seg.name}


def test_list_keys(s3):
    store = S3Store(BUCKET, "acme", client=s3)
    for key in ("acme/runs/r1/report.json", "acme/runs/r2/report.json", "other/runs/x"):
        s3.put_object(Bucket=BUCKET, Key=key, Body=b"{}")
    assert store.list_keys("runs/") == ["runs/r1/report.json", "runs/r2/report.json"]
    assert S3Store(BUCKET, "", client=s3).list_keys("other/") == ["other/runs/x"]
