"""Comparison and correlation rules, and the replay's handling of finished journeys,
that need no browser."""

import gc
import threading
import weakref
from types import SimpleNamespace

import pytest

from liftproof.findings import Kind, Severity
from liftproof.web import correlate, replay
from liftproof.web import run as webrun
from liftproof.web.browser import NetworkLog, Write, normalise_path
from liftproof.web.compare import Comparison, WebOptions
from liftproof.web.journey import Correlation, Journey, Step, shape
from liftproof.web.replay import JourneyRun, Replayer
from liftproof.web.run import REASON_STOPPED, WebResult, run_journeys
from tests import fakereplay


def cmp(correlations=(), values=None, **opts):
    j = Journey("j", "http://x", correlations=list(correlations))
    run = JourneyRun("j", values=values or {})
    out = []
    return Comparison(j, run, WebOptions(**opts), out.append, lambda ref: None), out


def test_numbers_compare_as_numbers():
    c, out = cmp()
    c._json("GET /a", {"total": 10.50, "n": 3, "s": "10.50"}, {"total": 10.5, "n": 3.0,
                                                                 "s": "10.5"}, "$", 1)
    assert out == []
    c._json("GET /a", {"total": 10.5}, {"total": "10.5"}, "$", 1)  # a type change is real
    assert [f.column for f in out] == ["$.total"]


def test_shape_reports_added_and_missing_fields():
    c, out = cmp()
    c._shape("GET /a", shape({"a": 1, "b": "x"}), shape({"a": 2, "c": True}), "$", 1)
    assert sorted(f.summary for f in out) == [
        "field $.b missing on the target", "field $.c added on the target"]
    assert all(f.kind == Kind.DIFFERENCE for f in out)


def test_correlated_values_are_masked_everywhere():
    corr = Correlation("orders.id", "json_path", "POST /api/orders", "$.id", "12345")
    c, out = cmp([corr], {"12345": "99999"})
    c._json("POST /api/orders", {"id": 12345}, {"id": 99999}, "$", 1)
    c._json("GET /api/orders/{orders.id}", {"id": 12345, "ref": "ord-12345"},
            {"id": 99999, "ref": "ord-99999"}, "$", 2)
    c.ui("- heading \"Order 12345\"", "- heading \"Order 99999\"", 3)
    assert out == []
    assert normalise_path("/orders/99999/items", {"99999": "orders.id"}) == \
        "/orders/{orders.id}/items"


def test_default_volatile_values_and_ignore_rules():
    c, out = cmp(ignore_text=[r"Build \w+"], ignore_json_paths=["GET /a $.etag"])
    c.ui("- text: Placed 2026-10-05T09:00:01Z Build abc", "- text: Placed 2026-10-06T10:11:12Z "
         "Build def", 1)
    c._json("GET /a", {"etag": "1"}, {"etag": "2"}, "$", 1)
    assert out == []


def test_values_hidden_unless_asked():
    c, out = cmp()
    c._json("GET /a", {"s": "secret-ish"}, {"s": "other"}, "$", 1)
    assert out[0].expected.startswith("sha256:")
    c, out = cmp(show_values=True)
    c._json("GET /a", {"s": "a"}, {"s": "b"}, "$", 1)
    assert (out[0].expected, out[0].actual) == ("a", "b")


def test_correlation_confidence_and_extractors():
    assert correlate.confident("839201") and correlate.confident("a8f0c2d9e7b14c33")
    assert not correlate.confident("1") and not correlate.confident("OPEN")
    assert correlate.json_get({"a": [{"b": 7}]}, "$.a[0].b") == 7
    html = '<form><input type="hidden" name="__VIEWSTATE" value="dDwtMTA="></form>'
    assert correlate.extract("form_field", "__VIEWSTATE", json=None, body=html.encode(),
                             headers={}) == "dDwtMTA="
    assert correlate.extract("header_segment", "location:2", json=None, body=None,
                             headers={"location": "/orders/4411?x=1"}) == "4411"


def test_detect_skips_coincidences():
    traffic = [
        [{"endpoint": "POST /api/orders", "json": {"id": 48213, "qty": 1, "status": "OPEN"},
          "body": None, "headers": {}, "content_type": "application/json",
          "request_text": "/api/orders\n{\"qty\": 1}"}],
        [{"endpoint": "GET /api/orders/{id}", "json": None, "body": None, "headers": {},
          "content_type": "", "request_text": "/api/orders/48213?status=OPEN\n"}],
    ]
    found = correlate.detect(traffic, [[""], [""]])
    assert [(c.recorded_value, c.confirmed) for c in found] == [("48213", True), ("OPEN", False)]


# ---------------------------------------------------- findings as journeys finish
def _replay(journeys, emit, *, workers=1, on_journey=None):
    return run_journeys(journeys, target_url="http://target.invalid", options=WebOptions(),
                        emit=emit, assets_dir=lambda j: None, secret_values=lambda j: {},
                        workers=workers, on_journey=on_journey)  # fmt: skip


@pytest.mark.parametrize("workers", [1, 3])
def test_a_worker_holds_one_journey_at_a_time(monkeypatch, workers):
    journeys = [fakereplay.journey(f"j{n}") for n in range(1, 7)]
    runs: list[weakref.ref] = []
    findings, saved = [], []
    j2_written = threading.Event()

    def replay_one(j):
        gc.collect()
        # the run this worker finished last is gone; other workers may still hold theirs
        alive = [r().journey_id for r in runs if r() is not None]
        assert len(alive) <= workers - 1, alive
        if workers > 1 and j.journey_id == "j1":
            assert j2_written.wait(5)  # j1 finishes after j2
        run = fakereplay.replayed(j, body=b"x" * 1_000_000)
        runs.append(weakref.ref(run))
        return run

    def emit(f):
        findings.append(f)
        if f.journey == "j2":
            j2_written.set()

    fakereplay.no_browser(monkeypatch, replay_one)
    def journey_done(make):
        saved.append((sum(f.kind == Kind.DIFFERENCE for f in findings), make()))

    result = _replay(journeys, emit, workers=workers, on_journey=journey_done)
    assert result.complete and (result.parallel, result.workers) == (workers > 1, workers)
    assert [r.journey for r in result.journeys] == [j.journey_id for j in journeys]
    assert {r.status for r in result.journeys} == {"different"}
    assert result.browser == "chromium 0-test"
    assert result.endpoints == [{"endpoint": "GET /api/orders", "source_ms": 40.0,
                                 "target_ms": 60.0, "change_pct": 50.0}]  # fmt: skip
    # each journey's findings are written when it finishes, not at the end of the run
    assert [(n, sum(r.status != "not_run" for r in s.journeys)) for n, s in saved] == [
        (k, k) for k in range(1, 7)]
    assert not any(s.complete for _, s in saved)
    written = [f.journey for f in findings if f.kind == Kind.DIFFERENCE]
    assert sorted(written) == sorted(j.journey_id for j in journeys)
    if workers > 1:
        assert written.index("j2") < written.index("j1")


def test_a_failure_keeps_the_journeys_that_finished(monkeypatch):
    journeys = [fakereplay.journey(f"j{n}") for n in range(1, 5)]

    def replay_one(j):
        if j.journey_id == "j3":
            raise RuntimeError("Browser has been closed")
        return fakereplay.replayed(j)

    fakereplay.no_browser(monkeypatch, replay_one)
    findings = []
    with pytest.raises(RuntimeError) as exc:
        _replay(journeys, findings.append)
    partial = exc.value.partial_result
    assert not partial.complete
    assert [(r.journey, r.status) for r in partial.journeys] == [
        ("j1", "different"), ("j2", "different"), ("j3", "not_run"), ("j4", "not_run")]
    assert [r.reason for r in partial.journeys[2:]] == [REASON_STOPPED] * 2
    assert partial.journeys[3].steps == 1 and partial.journeys[3].recorded_ms == 40.0
    assert {f.object for f in findings if f.kind == Kind.DIFFERENCE} == {
        "j1 step 1", "j2 step 1"}


def test_other_workers_finish_the_queue_when_one_fails(monkeypatch):
    journeys = [fakereplay.journey(f"j{n}") for n in range(1, 7)]
    replayed = []

    def replay_one(j):
        if j.journey_id == "j1":
            raise RuntimeError("Browser has been closed")
        replayed.append(j.journey_id)
        return fakereplay.replayed(j)

    fakereplay.no_browser(monkeypatch, replay_one)
    with pytest.raises(RuntimeError) as exc:
        _replay(journeys, lambda f: None, workers=2)
    assert sorted(replayed) == ["j2", "j3", "j4", "j5", "j6"]
    assert [r.status for r in exc.value.partial_result.journeys] == (
        ["not_run"] + ["different"] * 5)


def test_a_comparison_that_fails_is_not_a_journey_never_reached(monkeypatch):
    journeys = [fakereplay.journey(f"j{n}") for n in range(1, 4)]
    fakereplay.no_browser(monkeypatch, fakereplay.replayed)
    compare = webrun.compare_journey

    def broken(j, *a):
        if j.journey_id == "j2":
            raise KeyError("$.items")
        return compare(j, *a)

    monkeypatch.setattr(webrun, "compare_journey", broken)
    with pytest.raises(KeyError) as exc:
        _replay(journeys, lambda f: None)
    j1, j2, j3 = exc.value.partial_result.journeys
    assert (j1.status, j2.status, j3.status) == ("different", "failed", "not_run")
    assert j2.reason.startswith("comparison failed: KeyError") and j2.steps_run == 1


def test_journeys_finishing_after_an_interrupt_are_dropped(monkeypatch):
    journeys = [fakereplay.journey(f"j{n}") for n in range(1, 4)]
    release, replayed = threading.Event(), []

    def replay_one(j):
        replayed.append(j.journey_id)
        release.wait(5)
        return fakereplay.replayed(j)

    fakereplay.no_browser(monkeypatch, replay_one)
    join = replay._Worker.join

    def interrupted(self, timeout=None):
        raise KeyboardInterrupt

    monkeypatch.setattr(replay._Worker, "join", interrupted)
    handed = []
    with pytest.raises(KeyboardInterrupt):
        Replayer("http://target.invalid", secret_values=lambda j: {}).run(
            journeys, lambda i, j, run: handed.append(i), workers=2)
    release.set()
    for t in [t for t in threading.enumerate() if isinstance(t, replay._Worker)]:
        join(t, 5)
    # the run was being closed: nothing is written alongside it, and nothing more replayed
    assert handed == [] and "j3" not in replayed


def test_a_step_that_flakes_repeatedly_is_reported_with_its_journey(monkeypatch):
    flaky = [{"step": 1, "attempt": n, "error": "Timeout 15000ms exceeded", "unit": "step"}
             for n in (1, 2)]  # fmt: skip
    journeys = [fakereplay.journey("j1"), fakereplay.journey("j2")]
    fakereplay.no_browser(monkeypatch, lambda j: fakereplay.replayed(
        j, flakes=flaky if j.journey_id == "j1" else None))
    findings = []
    result = _replay(journeys, findings.append)
    [repeated] = [f for f in findings if f.kind == Kind.FLAKE and f.severity == Severity.MEDIUM]
    assert (repeated.journey, repeated.locator, repeated.detail) == ("j1", "step 1", {"flakes": 2})
    assert findings.index(repeated) < min(i for i, f in enumerate(findings) if f.journey == "j2")
    assert [r.flakes for r in result.journeys] == [2, 0]


def test_web_results_written_before_this_read_as_complete():
    assert WebResult.from_dict({"target_url": "http://t", "journeys": []}).complete
    assert not WebResult.from_dict(WebResult(complete=False).to_dict()).complete


# ------------------------------------------- a failed attempt that sent a write (spec 6, 19)
@pytest.mark.parametrize(("kind", "writes", "repeat"), [
    ("not_found", [], True),
    ("transport", [], True),
    ("not_found", [("POST /login", 302)], False),
    ("not_found", [("POST /api/orders", None)], False),  # sent, not answered yet
    ("transport", [("POST /login", 302), ("POST /api/orders", 201)], True),
    ("transport", [("POST /api/orders", None)], True),
    ("transport", [("POST /login", 302), ("POST /api/orders", 500)], False),
    ("crash", [("PUT /api/cart", 409)], False),
    ("browser_crash", [("POST /api/orders", 201)], True),
])  # fmt: skip
def test_an_attempt_that_sent_a_write_repeats_only_after_a_transport_failure(
    kind, writes, repeat
):
    assert replay.may_repeat(kind, [Write(e, s) for e, s in writes]) is repeat


class _Page:
    """Enough of a page for the network log and the step loop."""

    def __init__(self) -> None:
        self.handlers = {}

    def route(self, *a) -> None:
        pass

    def on(self, event, handler) -> None:
        self.handlers[event] = handler

    def unroute_all(self, **kw) -> None:
        pass

    def is_closed(self) -> bool:
        return False


def _request(method, path, resource_type="fetch", status=None):
    """A request the page sends; with a status, the target answers it."""
    resp = SimpleNamespace(status=status, headers={}, body=lambda: b"") if status else None
    return SimpleNamespace(method=method, url=f"http://t{path}", resource_type=resource_type,
                           response=lambda: resp, headers={}, timing={}, post_data=None)


def test_a_write_counts_from_when_it_is_sent():
    """One still unanswered may yet go through; one that failed may have gone through."""
    page = _Page()
    net = NetworkLog(page)
    order, failed = _request("POST", "/api/orders", status=201), _request("DELETE", "/api/cart/42")
    for req in (order, failed, _request("GET", "/api/orders"), _request("POST", "/b", "ping")):
        page.handlers["request"](req)
    assert net.writes == [Write("POST /api/orders"), Write("DELETE /api/cart/{id}")]
    page.handlers["requestfinished"](order)
    page.handlers["requestfailed"](failed)
    net.drain()  # the writes are kept apart from what a step drains
    assert net.writes == [Write("POST /api/orders", 201), Write("DELETE /api/cart/{id}")]


@pytest.mark.parametrize(("status", "error", "repeated"), [
    (201, RuntimeError("Locator.click: Timeout 15000ms exceeded."), True),
    (409, RuntimeError("Locator.click: Timeout 15000ms exceeded."), False),
    (201, replay.ElementNotFound("Confirm"), False),
])  # fmt: skip
def test_a_step_that_sent_a_write_repeats_only_as_a_journey_would(
    monkeypatch, status, error, repeated
):
    """A journey recorded without a write is retried a step at a time. When the target
    writes in that step all the same, what the step sent decides as it would for a
    journey."""
    tries = []

    def step(self, page, net, s, sr, j, run, secrets):
        tries.append(s.n)
        if len(tries) == 1:
            net.writes.append(Write("POST /api/cart", status))
            raise error

    monkeypatch.setattr(Replayer, "_step", step)
    context = SimpleNamespace(new_page=_Page, browser=SimpleNamespace(is_connected=lambda: True))
    j = Journey("j", "http://x", steps=[Step(1, "goto", url="/a"), Step(2, "goto", url="/b")])
    run = JourneyRun("j", attempts=1)
    assert Replayer("http://t", secret_values=lambda j: {})._steps(context, j, run, {}) is False
    if repeated:
        assert (run.status, tries, len(run.flakes), run.not_repeated) == (
            "completed", [1, 1, 2], 1, None)
    else:
        assert (run.status, tries, run.flakes) == ("failed", [1], [])
        assert run.not_repeated == (f"the step sent POST /api/cart ({status}); running it "
                                    "again would submit it a second time")
