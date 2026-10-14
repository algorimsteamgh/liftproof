"""Record and replay end to end (PRD F1, F3, F4, F5; Technical Spec 5 to 8 and 18).

A journey is recorded against the sample shop, then replayed against a second copy of
the shop: unchanged, and deliberately changed. Ids, CSRF tokens and timestamps differ
between the two on every run, as they would between a source and its migrated target.
"""

import copy
import json
import os
import signal
import sys
import threading
from pathlib import Path

import pytest

from liftproof.errors import ConfigError
from liftproof.findings import Comparator, Kind
from liftproof.web.browser import BodyPolicy, launch
from liftproof.web.compare import WebOptions
from liftproof.web.journey import Journey
from liftproof.web.recorder import Recorder
from liftproof.web.replay import JourneyRun, Replayer
from liftproof.web.run import run_journeys
from tests.webapp import PASSWORD, ShopApp

pytestmark = pytest.mark.browser


def drive(s):
    s.act(lambda p: p.get_by_label("Username").fill("alice"))
    s.act(lambda p: p.get_by_label("Password").fill(PASSWORD))
    s.act(lambda p: p.get_by_role("button", name="Sign in").click())
    s.act(lambda p: p.get_by_label("Item").fill("Widget"))
    s.act(lambda p: p.get_by_role("button", name="Place order").click())


@pytest.fixture(scope="module")
def recorded(browser_available, tmp_path_factory):
    assets_dir = tmp_path_factory.mktemp("assets")
    with ShopApp() as app:
        journey, assets = Recorder(
            app.url, policy=BodyPolicy(["/api/*"]), headless=True
        ).record("checkout", start="/login", story="ORD-14", drive=drive)
    for sha, body in assets.items():
        (assets_dir / sha).write_bytes(body)
    return journey, assets_dir


def replay(journey, assets_dir, variant, *, secrets=None, timeout=10_000):
    findings = []
    with ShopApp(variant) as target:
        result = run_journeys(
            [journey],
            target_url=target.url,
            options=WebOptions(),
            emit=findings.append,
            assets_dir=lambda j: assets_dir,
            secret_values=secrets or (lambda j: {t: PASSWORD for t in j.secrets}),
            step_timeout_ms=timeout,
        )
    return result, findings


def test_recording_redacts_and_correlates(recorded):
    journey, _ = recorded
    text = json.dumps(journey.to_dict())
    assert PASSWORD not in text
    [(token, binding)] = journey.secrets.items()
    assert binding.field == "Password" and binding.arn is None
    assert [s.action for s in journey.steps] == ["goto", "fill", "fill", "click", "fill", "click"]
    assert journey.steps[2].value == token
    assert journey.steps[3].non_idempotent and journey.non_idempotent
    names = {c.name: c for c in journey.correlations}
    assert names["orders.id"].source == "POST /api/orders" and names["orders.id"].confirmed
    assert any(c.extractor == "form_field" for c in journey.correlations)  # the CSRF token
    kept = {e.url: e.body_asset for s in journey.steps for e in s.exchanges}
    assert kept["/login"] is None  # default deny: HTML documents are hash and shape only
    assert kept["/api/orders"] is not None
    roundtrip = Journey.from_dict(json.loads(text))
    assert roundtrip.to_dict() == journey.to_dict()


def test_unchanged_target_replays_clean(recorded):
    journey, assets = recorded
    result, findings = replay(journey, assets, "same")
    [j] = result.journeys
    assert j.status == "passed", [f.summary for f in findings]
    assert not [f for f in findings if f.kind in (Kind.DIFFERENCE, Kind.ERROR)]
    assert result.endpoints and all(e["target_ms"] is not None for e in result.endpoints)


def test_changed_target_reports_exactly_the_changes(recorded):
    journey, assets = recorded
    result, findings = replay(journey, assets, "changed")
    assert result.journeys[0].status == "different"
    got = {(f.comparator, f.object, f.summary) for f in findings if f.kind == Kind.DIFFERENCE}
    assert (Comparator.API, "POST /api/orders", "value of $.status differs") in got
    assert (Comparator.API, "POST /api/orders", "field $.currency added on the target") in got
    assert (Comparator.UI, "checkout step 6", "page content differs after the step") in got
    assert (Comparator.UI, "checkout step 6",
            "locator degraded: the primary locator no longer matches") in got
    # ids the replay created and 10.50 against 10.5 are not differences
    assert not [f for f in findings if f.column in ("$.id", "$.total")]
    assert all(f.story == "ORD-14" for f in findings if f.kind == Kind.DIFFERENCE)


def test_unbound_secret_means_not_run(recorded):
    journey, assets = recorded

    def unbound(j):
        raise ConfigError("token not bound to a secret")

    result, findings = replay(journey, assets, "same", secrets=unbound)
    assert result.journeys[0].status == "not_run"
    assert [f.kind for f in findings] == [Kind.ERROR]


def test_missing_element_is_a_difference_and_the_journey_is_the_retry_unit(recorded):
    journey, assets = recorded
    j = copy.deepcopy(journey)
    j.steps[4].locator.candidates = [{"kind": "label", "value": "Product code"}]
    result, findings = replay(j, assets, "same", timeout=1500)
    [r] = result.journeys
    assert r.status == "different" and r.attempts == 2  # non idempotent: whole journey
    assert any(f.kind == Kind.FLAKE and f.detail.get("unit") == "journey" for f in findings)
    assert any(
        f.summary == "element the journey uses was not found on the target" for f in findings
    )


def test_ambiguous_locator_is_never_acted_on(recorded):
    journey, assets = recorded
    j = copy.deepcopy(journey)
    j.steps[1].locator.candidates = [{"kind": "css", "value": "input"}]
    result, findings = replay(j, assets, "same")
    [r] = result.journeys
    assert r.status == "failed" and r.attempts == 1
    [err] = [f for f in findings if f.kind == Kind.ERROR]
    assert err.summary.startswith("ambiguous locator")


def browser_pids() -> list[int]:
    """The Chromium processes this process started: a browser's main process is the one
    given the debugging pipe, its helpers carry --type."""
    parents, found = {}, []
    for stat in Path("/proc").glob("[0-9]*/stat"):
        try:
            pid, rest = stat.read_text().split(" ", 1)
            parents[int(pid)] = int(rest.rsplit(")", 1)[1].split()[1])
        except (OSError, ValueError, IndexError):
            continue
    for pid in parents:
        ancestor = parents[pid]
        while ancestor > 1 and ancestor != os.getpid():
            ancestor = parents.get(ancestor, 0)
        try:
            cmd = Path(f"/proc/{pid}/cmdline").read_bytes()
        except OSError:
            continue
        if ancestor > 1 and b"--remote-debugging-pipe" in cmd and b"--type=" not in cmd:
            found.append(pid)
    return found


def kill_browser(pid: int | None = None):
    """SIGKILL a Chromium this process started, as a crash ends it."""
    pids = browser_pids()
    assert pids, "no browser process to kill"
    os.kill(pid if pid in pids else pids[0], signal.SIGKILL)


@pytest.mark.skipif(sys.platform != "linux", reason="finds the browser process in /proc")
@pytest.mark.parametrize(("method", "step", "kill_on"), [
    ("_step", 4, {1}),  # before the step acts
    ("_step", 4, {1, 2}),
    ("_await_requests", 6, {1}),  # the last step, after it acted: nothing raises
])  # fmt: skip
def test_a_browser_crash_fails_that_journey_and_the_run_goes_on(
    recorded, monkeypatch, method, step, kill_on
):
    """Spec 18: the journey is retried once in a new browser, then recorded as an error;
    the journeys after it run in the new browser."""
    journey, assets = recorded
    journeys = []
    for name in ("before", "crashes", "after"):
        j = copy.deepcopy(journey)
        j.journey_id = name
        journeys.append(j)
    original, killed = getattr(Replayer, method), set()

    def crashing(self, page, net, s, *rest):
        run = next(a for a in rest if isinstance(a, JourneyRun))
        if (run.journey_id, s.n) == ("crashes", step) and run.attempts in kill_on - killed:
            killed.add(run.attempts)
            kill_browser()
        return original(self, page, net, s, *rest)

    monkeypatch.setattr(Replayer, method, crashing)
    findings = []
    with ShopApp() as target:
        result = run_journeys(journeys, target_url=target.url, options=WebOptions(),
                              emit=findings.append, assets_dir=lambda j: assets,
                              secret_values=lambda j: {t: PASSWORD for t in j.secrets})  # fmt: skip
    before, crashes, after = result.journeys
    assert killed == kill_on and result.complete
    assert (before.status, after.status) == ("passed", "passed"), [f.summary for f in findings]
    assert (crashes.attempts, crashes.browser_crashes) == (2, len(kill_on))
    assert [j["browser_crashes"] for j in result.to_dict()["journeys"]] == [0, len(kill_on), 0]
    # never a difference made up from the evidence of a dead browser
    assert not [f for f in findings if f.kind in (Kind.DIFFERENCE, Kind.NOTICE)]
    ours = [f for f in findings if f.journey == "crashes"]
    assert [f.detail.get("cause") for f in ours if f.kind == Kind.FLAKE] == ["browser_crash"]
    errors = [f for f in findings if f.kind == Kind.ERROR]
    if kill_on == {1}:
        assert crashes.status == "passed" and not errors
    else:
        [error] = errors
        assert crashes.status == "failed" and error.journey == "crashes"
        assert error.summary == "the browser process crashed during this journey"


@pytest.mark.skipif(sys.platform != "linux", reason="finds the browser process in /proc")
@pytest.mark.parametrize("workers", [1, 2])
def test_a_browser_that_exits_between_journeys_is_started_again(recorded, monkeypatch, workers):
    """A browser killed after its journey, while the run is compared and written: no
    Playwright call is made until the next journey asks for its context, so is_connected
    still says connected, and that is the call that finds the exit."""
    journey, assets = recorded
    journeys = []
    for n in range(4):
        j = copy.deepcopy(journey)
        j.journey_id = f"j{n}"
        journeys.append(j)
    pids, launching = {}, threading.Lock()

    def launch_one(*args, **kwargs):
        with launching:  # one at a time, so the new process is this browser's
            before = set(browser_pids())
            browser = launch(*args, **kwargs)
            [pids[id(browser)]] = set(browser_pids()) - before
        return browser

    journey_once, killed = Replayer._journey, []

    def kill_after(self, browser, j):
        run = journey_once(self, browser, j)
        with launching:
            if not killed:  # the first journey to finish, whichever worker ran it
                killed.append(j.journey_id)
                kill_browser(pids[id(browser.browser)])
        return run

    monkeypatch.setattr("liftproof.web.replay.launch", launch_one)
    monkeypatch.setattr(Replayer, "_journey", kill_after)
    findings = []
    with ShopApp() as target:
        result = run_journeys(journeys, target_url=target.url, options=WebOptions(),
                              emit=findings.append, assets_dir=lambda j: assets,
                              secret_values=lambda j: {t: PASSWORD for t in j.secrets},
                              workers=workers)  # fmt: skip
    assert result.complete and len(pids) == workers + 1
    assert [(r.status, r.browser_crashes) for r in result.journeys] == [("passed", 0)] * 4, [
        f.summary for f in findings]  # fmt: skip
    assert not [f for f in findings if f.kind in (Kind.ERROR, Kind.DIFFERENCE)]
    [notice] = [f for f in findings if f.kind == Kind.NOTICE]
    assert notice.journey != killed[0]
    assert notice.summary.startswith("the browser had exited before this journey started")


@pytest.mark.parametrize(("variant", "exit_code"), [("same", 0), ("changed", 10)])
def test_cli_bind_and_replay(recorded, tmp_path, monkeypatch, capsys, variant, exit_code):
    import shutil

    import yaml

    from liftproof import cli

    journey, assets = recorded
    work = tmp_path / "work"
    jdir = work / "shop" / "journeys"
    j = copy.deepcopy(journey)
    j.save(jdir / "checkout.json")
    shutil.copytree(assets, jdir / "checkout" / "assets")
    arn = "arn:aws:secretsmanager:ap-south-1:000000000000:secret:shop-login"
    monkeypatch.setattr(cli, "secret_value", lambda a, k: PASSWORD if a == arn else None)
    with ShopApp(variant) as target:
        project = tmp_path / "shop.yaml"
        project.write_text(yaml.safe_dump({"project": "shop", "web": {
            "source_url": "http://source.invalid", "target_url": target.url,
            "capture_bodies": ["/api/*"]}}))
        base = ["--project", str(project), "--workdir", str(work), "--format", "json"]
        # the password token is not bound yet: the journey is reported as not run
        assert cli.main(["replay", *base, "--run-id", "r-unbound"]) == 10
        [token] = j.secrets
        assert cli.main(["bind", *base, "--journey", "checkout", "--token", token,
                         "--secret-arn", arn]) == 0
        capsys.readouterr()
        assert cli.main(["validate", *base, "--run-id", "r-web"]) == exit_code
    out = json.loads(capsys.readouterr().out)
    report = json.loads((work / "shop" / "runs" / "r-web" / "report.json").read_text())
    unbound = json.loads((work / "shop" / "runs" / "r-unbound" / "report.json").read_text())
    assert unbound["journeys"][0]["status"] == "not_run"
    assert unbound["coverage"]["journeys_coverage_pct"] == 0.0
    assert report["mode"] == "validate" and out["counts"]["journeys"] == 1
    assert report["coverage"]["journeys_coverage_pct"] == 100.0
    assert report["coverage"]["journeys_success_pct"] == (100.0 if variant == "same" else 0.0)
    assert report["traceability"][0]["story"] == "ORD-14"
    assert report["timings"]["journeys"][0]["target_ms"] is not None
    assert PASSWORD not in (work / "shop" / "runs" / "r-web" / "report.html").read_text()


def test_parallel_journeys_opt_in(recorded):
    """Independent journeys at once: each keeps its own steps in order, results keep the
    journeys' order, and the result records that the run was parallel (spec 6)."""
    journey, assets = recorded
    journeys = []
    for i in range(4):
        j = copy.deepcopy(journey)
        j.journey_id = f"checkout-{i}"
        journeys.append(j)

    snapshots = []

    def run(workers):
        snapshots.clear()
        with ShopApp(latency_ms=100) as target:
            result = run_journeys(
                journeys,
                target_url=target.url,
                options=WebOptions(),
                emit=lambda _f: None,
                assets_dir=lambda j: assets,
                secret_values=lambda j: {t: PASSWORD for t in j.secrets},
                workers=workers,
                on_journey=lambda make: snapshots.append(make()),
            )
            return result, target.peak_sessions

    # whether the journeys overlapped, not how much faster they were: wall clock on a
    # small CI runner is mostly four browsers starting
    seq, seq_peak = run(1)
    par, par_peak = run(4)
    assert (seq.parallel, seq.workers) == (False, 1)
    assert (par.parallel, par.workers) == (True, 4)
    assert [j.journey for j in par.journeys] == [j.journey_id for j in journeys]
    assert {j.status for j in par.journeys} == {"passed"}
    assert (seq_peak, par_peak >= 2) == (1, True), (seq_peak, par_peak)
    # each journey is compared as it finishes, in whatever order they finish
    assert [sum(j.status == "passed" for j in s.journeys) for s in snapshots] == [1, 2, 3, 4]
    assert not any(s.complete for s in snapshots) and par.complete


@pytest.mark.parametrize("value", [0, 9, "many"])
def test_parallel_journeys_is_bounded(tmp_path, value):
    from liftproof.config import load_project

    p = tmp_path / "p.yaml"
    p.write_text(f"project: t\nweb: {{source_url: http://a, parallel_journeys: {value}}}\n")
    with pytest.raises(ConfigError, match="parallel_journeys"):
        load_project(p)
