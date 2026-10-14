"""A browser that crashes during a replay (Technical Spec 18): the journey it was running
is retried once in a new browser, then recorded as an error, and the run goes on.

No browser: the fakes stand in for Playwright with only what its oldest supported version
has, Browser.is_connected and Page.is_closed. A browser that exits closes its pages.
"""

import contextlib

import pytest

from liftproof.findings import Kind, Severity
from liftproof.report.builder import build_report, render_html
from liftproof.web import replay
from liftproof.web.compare import WebOptions
from liftproof.web.journey import Journey, Step
from liftproof.web.replay import Replayer
from liftproof.web.run import WebResult, run_journeys

CLOSED = "Target page, context or browser has been closed"


class Browser:
    version = "0-test"

    def __init__(self, launched: list) -> None:
        self.alive, self.contexts = True, []
        launched.append(self)

    def is_connected(self) -> bool:
        return self.alive

    def new_context(self):
        if not self.alive:
            raise RuntimeError(CLOSED)
        self.contexts.append(Context(self))
        return self.contexts[-1]

    def close(self) -> None:
        self.alive = False


class Context:
    on_close = None  # what closing it does to its browser

    def __init__(self, browser: Browser) -> None:
        self.browser = browser

    def new_page(self):
        return Page(self.browser)

    def close(self) -> None:
        if self.on_close:
            self.on_close(self.browser)


class Page:
    def __init__(self, browser: Browser) -> None:
        self.browser, self.closed = browser, False

    def route(self, *a) -> None:
        pass

    def on(self, *a) -> None:
        pass

    def is_closed(self) -> bool:
        return self.closed or not self.browser.alive


@pytest.fixture
def launched(monkeypatch):
    browsers: list[Browser] = []
    monkeypatch.setattr(replay, "launch", lambda p, **kw: Browser(browsers))
    monkeypatch.setattr("playwright.sync_api.sync_playwright", contextlib.nullcontext)
    return browsers


def journey(journey_id: str, *, writes: bool = False) -> Journey:
    steps = [Step(n, "goto", url=f"/{n}", region=f'- heading "{n}"', non_idempotent=writes)
             for n in (1, 2, 3)]  # fmt: skip
    return Journey(journey_id, "http://source.invalid", story=f"S-{journey_id}", steps=steps)


def scripted(monkeypatch, act):
    """Every step calls act(journey id, step, journey attempt, page) and, unless that
    raises, records what the recording saw. The real step loop runs around it."""
    attempts: dict[str, int] = {}
    journey_once = Replayer._journey

    def counted(self, browser, j):
        attempts[j.journey_id] = 0
        return journey_once(self, browser, j)

    steps_once = Replayer._steps

    def attempt(self, context, j, run, secrets):
        attempts[j.journey_id] += 1
        return steps_once(self, context, j, run, secrets)

    def step(self, page, net, s, sr, j, run, secrets):
        act(j.journey_id, s.n, attempts[j.journey_id], page)
        # a browser that exited during the step leaves an empty snapshot, not an error
        sr.region = "" if page.is_closed() else s.region

    monkeypatch.setattr(Replayer, "_journey", counted)
    monkeypatch.setattr(Replayer, "_steps", attempt)
    monkeypatch.setattr(Replayer, "_step", step)


def crash(page: Page) -> None:
    page.browser.alive = False
    raise RuntimeError(f"Page.goto: {CLOSED}")


def replay_all(journeys, *, workers=1):
    findings = []
    result = run_journeys(journeys, target_url="http://target.invalid", options=WebOptions(),
                          emit=findings.append, assets_dir=lambda j: None,
                          secret_values=lambda j: {}, workers=workers)  # fmt: skip
    return result, findings


def kinds(findings, journey_id):
    return sorted(str(f.kind) for f in findings if f.journey == journey_id)


def test_a_browser_crash_fails_only_that_journey(monkeypatch, launched):
    def act(j, n, attempt, page):
        if (j, n) == ("b", 2):
            crash(page)

    scripted(monkeypatch, act)
    result, findings = replay_all([journey("a"), journey("b"), journey("c")])
    a, b, c = result.journeys
    assert (a.status, c.status) == ("passed", "passed")
    assert (b.status, b.attempts, b.browser_crashes, b.steps_run) == ("failed", 2, 2, 1)
    assert (a.browser_crashes, c.browser_crashes) == (0, 0)
    # once for the retry, once for the journey after it
    assert len(launched) == 3 and launched[2].contexts
    [error] = [f for f in findings if f.kind == Kind.ERROR]
    assert (error.journey, error.locator, error.severity) == ("b", "step 2", Severity.HIGH)
    assert error.summary == "the browser process crashed during this journey"
    assert error.detail["browser_crashes"] == 2 and CLOSED in error.detail["error"]
    # the step is not retried in a dead browser: one journey retry, no step flakes
    [flake] = [f for f in findings if f.kind == Kind.FLAKE]
    assert flake.detail["unit"] == "journey" and flake.detail["cause"] == "browser_crash"
    assert kinds(findings, "a") == kinds(findings, "c") == []

    report = build_report(run_id="r", project="p", mode="replay", started_at="t",
                          finished_at="t", db=None, web=result, findings=findings,
                          metadata={}, range_block={})  # fmt: skip
    assert report["verdict"] == "failed"
    assert report["journeys"][1]["browser_crashes"] == 2
    assert "failed (browser crashed 2 times)</td>" in render_html(report)


def test_a_crashed_journey_is_retried_once_in_a_new_browser(monkeypatch, launched):
    def act(j, n, attempt, page):
        if (j, n, attempt) == ("b", 2, 1):
            crash(page)

    scripted(monkeypatch, act)
    result, findings = replay_all([journey("a"), journey("b", writes=True)])
    b = result.journeys[1]
    assert (b.status, b.attempts, b.browser_crashes, b.flakes) == ("passed", 2, 1, 1)
    assert len(launched) == 2
    [flake] = findings
    assert (flake.kind, flake.journey, flake.locator) == (Kind.FLAKE, "b", "step 2")
    assert flake.summary == "retried in a new browser after the browser process crashed (journey)"


@pytest.mark.parametrize("on_attempts", [{1}, {1, 2}])
def test_a_browser_that_exits_during_a_step_fails_that_step(monkeypatch, launched, on_attempts):
    """The step's waits and its snapshot return normally on a page whose browser has gone,
    so the step reads as done with nothing captured unless it is checked."""

    def act(j, n, attempt, page):
        if (j, n) == ("a", 3) and attempt in on_attempts:
            page.browser.alive = False

    scripted(monkeypatch, act)
    result, findings = replay_all([journey("a"), journey("b")])
    a, b = result.journeys
    assert a.browser_crashes == len(on_attempts) and a.attempts == 2
    assert a.status == ("passed" if on_attempts == {1} else "failed")
    assert b.status == "passed" and len(launched) == 2 + (on_attempts == {1, 2})
    # never a difference made up from the empty snapshot, nor a restart charged to none
    assert not [f for f in findings if f.kind in (Kind.DIFFERENCE, Kind.NOTICE)]
    assert kinds(findings, "b") == []


def test_a_browser_that_exits_between_journeys_is_charged_to_none(monkeypatch, launched):
    def act(j, n, attempt, page):
        if (j, n) == ("a", 3):
            page.browser.contexts[-1].on_close = Browser.close

    scripted(monkeypatch, act)
    result, findings = replay_all([journey("a"), journey("b")])
    assert [(r.status, r.attempts, r.browser_crashes) for r in result.journeys] == [
        ("passed", 1, 0), ("passed", 1, 0)]
    assert len(launched) == 2
    [notice] = findings
    assert (notice.kind, notice.journey) == (Kind.NOTICE, "b")
    assert notice.summary.startswith("the browser had exited before this journey started")


def test_a_closed_page_in_a_live_browser_keeps_the_crash_path(monkeypatch, launched):
    def act(j, n, attempt, page):
        if (n, attempt) == (2, 1):
            page.closed = True

    scripted(monkeypatch, act)
    result, findings = replay_all([journey("a")])
    [a] = result.journeys
    assert (a.status, a.attempts, a.browser_crashes) == ("passed", 2, 0)
    assert len(launched) == 1  # the browser was fine: not started again
    [flake] = findings
    assert "cause" not in flake.detail and "crashed or was closed" in flake.detail["error"]


def test_parallel_workers_survive_a_browser_crash(monkeypatch, launched):
    def act(j, n, attempt, page):
        if (j, n) == ("j2", 1):
            crash(page)

    scripted(monkeypatch, act)
    result, findings = replay_all([journey(f"j{n}") for n in range(1, 5)], workers=2)
    assert result.complete
    assert [(r.journey, r.status) for r in result.journeys] == [
        ("j1", "passed"), ("j2", "failed"), ("j3", "passed"), ("j4", "passed")]
    assert result.journeys[1].browser_crashes == 2
    assert [f.journey for f in findings if f.kind == Kind.ERROR] == ["j2"]


def test_results_written_before_this_have_no_browser_crashes():
    old = {"journey": "j1", "story": None, "status": "passed", "steps": 1, "steps_run": 1,
           "attempts": 1, "flakes": 0, "differences": 0, "recorded_ms": 40.0,
           "replayed_ms": 50.0}  # fmt: skip
    assert WebResult.from_dict({"journeys": [old]}).journeys[0].browser_crashes == 0
