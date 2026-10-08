"""Pipeline and scheduled runs (PRD F11, F12, Technical Spec 14).

PRD F12 done when: a nightly schedule runs unattended, and a run that would overlap the
previous one is skipped and reported, never run twice at once.
"""

from __future__ import annotations

import datetime as dt
import json
import threading

import pytest
import yaml

from liftproof import aws, cli
from liftproof.config import load_project
from liftproof.errors import ConfigError
from liftproof.runlock import LocalRunLock, RunInProgress, S3RunLock
from liftproof.schedule import Cron, Scheduler, command_line, parse_schedules

UTC = dt.UTC


def at(s: str) -> dt.datetime:
    return dt.datetime.fromisoformat(s)


# ------------------------------------------------------------------------- cron
@pytest.mark.parametrize(
    ("expr", "after", "expected"),
    [
        ("0 2 * * *", "2026-10-06 01:59", "2026-10-06 02:00"),
        ("0 2 * * *", "2026-10-06 02:00", "2026-10-07 02:00"),  # strictly after
        ("*/15 * * * *", "2026-10-06 10:07", "2026-10-06 10:15"),
        ("30 23 * * mon-fri", "2026-10-09 23:30", "2026-10-12 23:30"),  # Friday to Monday
        ("0 0 1 * *", "2026-12-15 00:00", "2027-01-01 00:00"),
        ("0 9 29 feb *", "2026-03-01 00:00", "2028-02-29 09:00"),  # next leap day
        ("0 6 1,15 * 0", "2026-10-02 00:00", "2026-10-04 06:00"),  # day OR weekday
        ("0 6 * * 7", "2026-10-06 00:00", "2026-10-11 06:00"),  # 7 is Sunday
        ("5-10/5 4 * jan *", "2026-10-06 00:00", "2027-01-01 04:05"),
    ],
)
def test_cron_next(expr, after, expected):
    assert Cron(expr).next_after(at(after)) == at(expected)


@pytest.mark.parametrize(
    ("expr", "message"),
    [
        ("0 2 * *", "five fields"),
        ("60 * * * *", "between 0 and 59"),
        ("*/0 * * * *", "positive"),
        ("10-5 * * * *", "backwards"),
        ("0 0 31 feb *", "never fires"),
        ("0 0 * * funday", "between 0 and 7"),
    ],
)
def test_cron_rejects(expr, message):
    with pytest.raises(ConfigError, match=message):
        Cron(expr)


def test_schedule_timezone_is_wall_clock():
    [s] = parse_schedules([{"name": "nightly", "cron": "0 2 * * *",
                            "timezone": "Asia/Kolkata"}])  # fmt: skip
    # 02:00 in Mumbai is 20:30 UTC the evening before
    assert s.next_after(at("2026-10-06 12:00+00:00")) == at("2026-10-06 20:30+00:00")
    [ny] = parse_schedules([{"name": "n", "cron": "30 1 * * *", "timezone": "America/New_York"}])
    # across the November change from daylight saving time
    assert ny.next_after(at("2026-10-31 12:00+00:00")) == at("2026-11-01 05:30+00:00")
    # 01:30 happens twice that night (05:30 and 06:30 UTC): the run fires once
    assert ny.next_after(at("2026-11-01 05:30+00:00")) == at("2026-11-02 06:30+00:00")
    assert ny.next_after(at("2026-11-01 06:00+00:00")) == at("2026-11-02 06:30+00:00")
    # 02:30 does not happen on the night the clocks go forward: it fires at 03:30 EDT
    [spring] = parse_schedules([{"name": "s", "cron": "30 2 * * *",
                                 "timezone": "America/New_York"}])  # fmt: skip
    assert spring.next_after(at("2026-03-08 05:00+00:00")) == at("2026-03-08 07:30+00:00")


def test_schedule_config_rules(tmp_path):
    f = tmp_path / "p.yaml"

    def load(schedules):
        f.write_text(yaml.safe_dump({"project": "p", "files": [
            {"name": "a", "source": "/a", "target": "/b"}], "schedules": schedules}))  # fmt: skip
        return load_project(f)

    p = load([{"name": "nightly", "cron": "0 2 * * *", "command": "files",
               "args": ["--fail-on", "errors"]}])  # fmt: skip
    assert [(s.name, s.command, s.args) for s in p.schedules] == [
        ("nightly", "files", ["--fail-on", "errors"])
    ]
    with pytest.raises(ConfigError, match="used twice"):
        load([{"name": "n", "cron": "0 2 * * *"}] * 2)
    with pytest.raises(ConfigError, match="must be one of"):
        load([{"name": "n", "cron": "0 2 * * *", "command": "record"}])
    with pytest.raises(ConfigError, match="time zone"):
        load([{"name": "n", "cron": "0 2 * * *", "timezone": "Mars/Olympus"}])
    with pytest.raises(ConfigError, match="sets --project"):
        load([{"name": "n", "cron": "0 2 * * *", "args": ["--run-id", "x"]}])


# --------------------------------------------------------------------- run lock
def test_local_lock_excludes_a_second_run(tmp_path):
    path = tmp_path / "locks" / "run.lock"
    with LocalRunLock(path, "r-1", "validate"):
        with pytest.raises(RunInProgress) as exc, LocalRunLock(path, "r-2", "reconcile"):
            pass
        assert exc.value.holder["run_id"] == "r-1"
        assert "r-1 (validate)" in str(exc.value)
    with LocalRunLock(path, "r-3", "validate"):  # released: free again
        pass


@pytest.fixture
def s3():
    moto = pytest.importorskip("moto")
    import boto3

    with moto.mock_aws():
        client = boto3.client("s3", region_name="ap-south-1")
        client.create_bucket(
            Bucket="acme-runs", CreateBucketConfiguration={"LocationConstraint": "ap-south-1"}
        )
        yield client


def test_s3_lock(s3):
    key = "proj/locks/run.lock"

    def lock(run_id, lease=900):
        return S3RunLock(s3, "acme-runs", key, run_id, "validate", lease, put_args={})

    first = lock("r-1")
    with first:
        with pytest.raises(RunInProgress) as exc, lock("r-2"):
            pass
        assert exc.value.holder["run_id"] == "r-1"
        first.renew()  # the heartbeat: a conditional put on our own ETag
        stale = lock("r-1")
        stale.etag = '"not-the-current-etag"'
        with pytest.raises(s3.exceptions.ClientError):
            stale.renew()  # someone else's lock is never overwritten
    with pytest.raises(s3.exceptions.ClientError):
        s3.head_object(Bucket="acme-runs", Key=key)  # released

    # a lost run's lock is taken over once its lease has expired
    lost = lock("r-lost", lease=-1)
    lost.acquire()
    taker = lock("r-new")
    with taker:
        assert taker.body["took_over"] == "r-lost"
        lost.release()  # the lost run coming back must not delete the new holder's lock
        holder = json.loads(s3.get_object(Bucket="acme-runs", Key=key)["Body"].read())
        assert holder["run_id"] == "r-new"


def test_s3_lock_only_one_of_many_wins(s3):
    won, lost = [], []

    def contend(i):
        try:
            S3RunLock(s3, "acme-runs", "p/locks/run.lock", f"r-{i}", "validate",
                      put_args={}).acquire()  # fmt: skip
            won.append(i)
        except RunInProgress:
            lost.append(i)

    threads = [threading.Thread(target=contend, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(won) == 1 and len(lost) == 7


# ------------------------------------------------------------------- CLI and runs
@pytest.fixture
def project(tmp_path):
    src, tgt = tmp_path / "src", tmp_path / "tgt"
    for d in (src, tgt):
        d.mkdir()
        (d / "a.txt").write_text("same\n")
    f = tmp_path / "projects" / "docs.yaml"
    f.parent.mkdir()
    f.write_text(yaml.safe_dump({
        "project": "docs",
        "files": [{"name": "documents", "source": str(src), "target": str(tgt)}],
        "schedules": [{"name": "nightly", "cron": "0 2 * * *", "command": "files"}],
    }))  # fmt: skip
    return f


def test_overlapping_runs(project, tmp_path, capsys, monkeypatch):
    work = tmp_path / "work"
    base = ["--project", str(project), "--workdir", str(work), "--format", "json"]
    metrics = []
    monkeypatch.setattr(aws, "put_metric", lambda *a, **k: metrics.append((a, k)))
    monkeypatch.setattr(cli, "_instance_config", lambda: {"deployment": "acme-prod"})
    with LocalRunLock(work / "docs" / "locks" / "run.lock", "r-busy", "validate"):
        # by hand: refused with exit code 2, and nothing is written
        assert cli.main(["files", *base, "--run-id", "r-hand"]) == 2
        assert "r-busy (validate)" in capsys.readouterr().err
        assert not (work / "docs" / "runs" / "r-hand").exists()
        assert cli.main(["baseline", *base]) == 3  # no database: configuration, not the lock
        # scheduled: skipped, and the skip is a run with a report and a metric
        args = ["files", *base, "--run-id", "s-skip", "--scheduled", "nightly"]
        assert cli.main(args) == 2
    capsys.readouterr()
    report = json.loads((work / "docs" / "runs" / "s-skip" / "report.json").read_text())
    assert report["run"]["schedule"] == "nightly"
    [finding] = [f for f in report["findings"] if f["comparator"] == "run"]
    assert finding["kind"] == "error" and "r-busy" in finding["summary"]
    # one data point for the deployment's alarm, one naming the project
    assert metrics == [
        (("ScheduledRunSkipped", 1, {"Deployment": "acme-prod"}), {}),
        (("ScheduledRunSkipped", 1, {"Deployment": "acme-prod", "Project": "docs"}), {}),
    ]

    # the lock is free again: the run goes ahead and the history shows both
    assert cli.main(["files", *base, "--run-id", "r-ok", "--scheduled", "nightly"]) == 0
    capsys.readouterr()
    assert cli.main(["runs", *base]) == 0
    runs = json.loads(capsys.readouterr().out)["runs"]
    assert {r["run_id"]: r["verdict"] for r in runs}["r-ok"] == "passed"
    assert {r["run_id"] for r in runs} == {"s-skip", "r-ok"}
    assert all(r["schedule"] == "nightly" for r in runs)


def test_schedule_list(project, capsys):
    assert cli.main(["schedule", "--project", str(project), "--format", "json"]) == 0
    [row] = json.loads(capsys.readouterr().out)["schedules"]
    assert row["name"] == "nightly" and row["next_run_utc"].endswith("T02:00Z")


def test_scheduler_fires_due_runs_once(project, tmp_path):
    work = tmp_path / "work"
    clock = [at("2026-10-06 01:00+00:00")]
    fired = []
    sched = Scheduler(project.parent, work, launch=lambda d, w: fired.append(d) or 0,
                      now=lambda: clock[0])  # fmt: skip
    assert sched.tick(wait=True) == []  # first sight: counts from now, fires nothing
    clock[0] = at("2026-10-06 01:59+00:00")
    assert sched.tick(wait=True) == []
    clock[0] = at("2026-10-06 02:00+00:00")
    [due] = sched.tick(wait=True)
    assert (due.project, due.schedule.name, due.at) == ("docs", "nightly", clock[0])
    assert sched.tick(wait=True) == []  # not twice

    # a restarted scheduler does not repeat the run; three missed nights fire once
    clock[0] = at("2026-10-09 03:00+00:00")
    again = Scheduler(project.parent, work, launch=lambda d, w: fired.append(d) or 0,
                      now=lambda: clock[0])  # fmt: skip
    [late] = again.tick(wait=True)
    assert late.at == at("2026-10-09 02:00+00:00") and len(fired) == 2

    cmd = command_line(late, work)
    assert cmd[3:5] == ["files", "--project"]
    assert cmd[cmd.index("--scheduled") + 1] == "nightly"
    assert cmd[cmd.index("--run-id") + 1] == "s-20261009-0200-nightly"


def test_scheduler_runs_the_real_command(project, tmp_path):
    """--once end to end: the scheduler starts a separate liftproof process."""
    work = tmp_path / "work"
    state = work / "scheduler-state.json"
    work.mkdir()
    state.write_text(json.dumps({"docs/nightly": "2026-01-01T00:00:00+00:00"}))
    assert cli.main(["scheduler", "--projects-dir", str(project.parent), "--workdir",
                     str(work), "--once"]) == 0  # fmt: skip
    [run] = (work / "docs" / "runs").iterdir()
    report = json.loads((run / "report.json").read_text())
    assert run.name.startswith("s-") and report["run"]["schedule"] == "nightly"
    assert report["verdict"] == "passed"
