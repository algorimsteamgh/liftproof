"""Nothing irreplaceable stays on the instance (spec 3, 9.16 and 18). A reconciliation or
a baseline that loses its instance halfway resumes on a replacement pointed at the same
bucket, a replay leaves the journeys it finished for the report, and the replacement
finds the projects, journeys and run history again.

"Losing the instance" here is an exception that no handler in the product catches,
followed by deleting the whole work directory; the replacement gets a new one.
"""

from __future__ import annotations

import datetime as dt
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
from liftproof.web import run as webrun
from liftproof.web.run import JourneyResult, WebResult
from tests import fakereplay
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


@pytest.fixture
def web_project(tmp_path):
    """Web only, four journeys recorded on this instance, each finding one difference."""
    path = tmp_path / "projects" / "acme.yaml"
    path.parent.mkdir()
    path.write_text(yaml.safe_dump({"project": "acme", "web": {
        "source_url": "http://source.invalid", "target_url": "http://target.invalid"}}))
    return path


def _journeys_on(work, *ids: str) -> None:
    for jid in ids:
        fakereplay.journey(jid).save(work / "acme" / "journeys" / f"{jid}.json")


def _stop_replay_at(monkeypatch, journey_id: str, error: BaseException) -> None:
    def replay_one(j):
        if j.journey_id == journey_id:
            raise error
        return fakereplay.replayed(j)

    fakereplay.no_browser(monkeypatch, replay_one)


def test_a_lost_replay_reports_what_it_finished_on_a_replacement(tmp_path, web_project,
                                                                  monkeypatch, s3):  # fmt: skip
    first, second = tmp_path / "first", tmp_path / "second"
    _journeys_on(first, "j1", "j2", "j3", "j4")
    _checkpoint_times(monkeypatch, True, True)  # after j1 and after j2
    _stop_replay_at(monkeypatch, "j3", InstanceLost())
    with pytest.raises(InstanceLost):
        _main("replay", "--project", str(web_project), "--workdir", str(first), "--run-id", "r1")
    shutil.rmtree(first)

    saved = json.loads(s3.get_object(Bucket=BUCKET, Key="acme/runs/r1/web-results.json")["Body"]
                       .read())  # fmt: skip
    assert not saved["complete"]
    assert [(j["journey"], j["status"]) for j in saved["journeys"]] == [
        ("j1", "different"), ("j2", "different"), ("j3", "not_run"), ("j4", "not_run")]
    stored = tmp_path / "from-store"
    stored.mkdir()
    for key in _keys(s3, "acme/runs/r1/findings-"):
        s3.download_file(BUCKET, key, str(stored / key.rsplit("/", 1)[1]))
    assert {f.journey for f in read_findings(stored) if f.kind == Kind.DIFFERENCE} == {"j1", "j2"}

    # the replacement holds nothing of the run; its report comes from the store
    code = _main("report", "--project", str(web_project), "--workdir", str(second),
                 "--run", "r1")  # fmt: skip
    assert code == EXIT_RUN_FAILED
    report = json.loads((second / "acme/runs/r1/report.json").read_text())
    assert (report["mode"], report["verdict"], report["failure"]) == (
        "replay", "failed", cli.UNFINISHED)
    started = json.loads((second / "acme/runs/r1" / ckpt.RUN_INFO).read_text())["started_at"]
    assert report["run"]["started_at"] == started
    assert report["run"]["finished_at"] >= started
    assert report["coverage"]["journeys_coverage_pct"] == 50
    assert [j["status"] for j in report["journeys"]] == ["different"] * 2 + ["not_run"] * 2
    assert report["coverage"]["not_covered"] == [
        {"object": "journey j3", "reason": webrun.REASON_STOPPED},
        {"object": "journey j4", "reason": webrun.REASON_STOPPED}]
    assert {f["journey"] for f in report["findings"] if f["kind"] == "difference"} == {"j1", "j2"}
    assert "acme/runs/r1/report.json" in _keys(s3, "acme/runs/r1/")


@pytest.mark.usefixtures("s3")
def test_a_failed_replay_reports_what_it_finished(tmp_path, web_project, monkeypatch):
    work = tmp_path / "w"
    _journeys_on(work, "j1", "j2", "j3", "j4")
    _stop_replay_at(monkeypatch, "j3", RuntimeError("Browser has been closed"))
    argv = ["--project", str(web_project), "--workdir", str(work)]
    assert _main("replay", *argv, "--run-id", "r2") == EXIT_RUN_FAILED
    report = json.loads((work / "acme/runs/r2/report.json").read_text())
    assert report["coverage"]["journeys_coverage_pct"] == 50
    assert report["counts"]["journeys"] == 4 and report["counts"]["not_checked"] == 2
    assert {f["journey"] for f in report["findings"] if f["kind"] == "difference"} == {"j1", "j2"}
    assert any(f["summary"].startswith("run did not complete: RuntimeError")
               for f in report["findings"])  # fmt: skip
    journeys = [c for c in report["coverage"]["not_covered"] if c["object"].startswith("journey")]
    assert journeys == [{"object": "journey j3", "reason": webrun.REASON_STOPPED},
                        {"object": "journey j4", "reason": webrun.REASON_STOPPED}]  # fmt: skip
    # regenerating carries the run's own "stopped" entries over, and none is a journey's
    assert _main("report", *argv, "--run", "r2") == EXIT_RUN_FAILED
    again = json.loads((work / "acme/runs/r2/report.json").read_text())
    assert again["coverage"]["not_covered"] == report["coverage"]["not_covered"]


def test_a_replay_checkpoint_waits_for_its_findings(tmp_path):
    class Flaky(S3Store):
        def __init__(self, failures):
            self.failures, self.keys = failures, []

        def put_file(self, key, path):
            if self.failures:
                self.failures -= 1
                from liftproof.errors import RunFailed

                raise RunFailed("S3 write failed")
            self.keys.append(key)

    store = Flaky(failures=2)  # the segment as it closes, and again as the checkpoint checks
    uploads = ckpt.SegmentUploads(store, "r")
    writer = FindingWriter(tmp_path, "r", on_segment=uploads)
    checkpoint = ckpt.ReplayCheckpoint(store, tmp_path, "r", writer, uploads)
    writer.write(Finding(Comparator.UI, Kind.DIFFERENCE, 50, "j1 step 1", "x", journey="j1"))
    result = WebResult([JourneyResult("j1", None, "different", 1, 1, 1, 0, 1, 40.0, 60.0)],
                       complete=False)  # fmt: skip
    checkpoint.save(result)
    assert store.keys == [] and not (tmp_path / ckpt.WEB_RESULTS).exists()
    checkpoint.save(result)
    assert store.keys == ["runs/r/findings-00001.jsonl", "runs/r/web-results.json"]
    assert WebResult.from_dict(json.loads((tmp_path / ckpt.WEB_RESULTS).read_text())) == result


def test_a_copy_from_the_store_keeps_when_it_was_written(tmp_path, s3):
    s3.put_object(Bucket=BUCKET, Key="acme/runs/r1/run.json", Body=b"{}")
    written = dt.datetime(2026, 10, 1, 9, 30, tzinfo=dt.UTC)

    class Client:  # moto stamps objects with the time they were put
        def get_object(self, **kw):
            return {**s3.get_object(**kw), "LastModified": written}

    local = tmp_path / "r1" / "run.json"
    assert S3Store(BUCKET, "acme", client=Client()).get_file("runs/r1/run.json", local)
    assert local.stat().st_mtime == written.timestamp()
    assert cli._last_activity(local.parent) == "2026-10-01T09:30:00Z"  # a stopped run's end


def test_list_keys(s3):
    store = S3Store(BUCKET, "acme", client=s3)
    for key in ("acme/runs/r1/report.json", "acme/runs/r2/report.json", "other/runs/x"):
        s3.put_object(Bucket=BUCKET, Key=key, Body=b"{}")
    assert store.list_keys("runs/") == ["runs/r1/report.json", "runs/r2/report.json"]
    assert S3Store(BUCKET, "", client=s3).list_keys("other/") == ["other/runs/x"]
