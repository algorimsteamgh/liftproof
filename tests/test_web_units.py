"""Comparison and correlation rules, and the replay's handling of finished journeys,
that need no browser."""

import gc
import json
import threading
import weakref
from dataclasses import asdict
from types import SimpleNamespace

import pytest
import yaml

from liftproof import support
from liftproof.config import TEMPLATE, load_project
from liftproof.errors import ConfigError
from liftproof.findings import Kind, Severity
from liftproof.report.builder import PASSED_WITH_DIFFERENCES, build_report, render_html, verdict
from liftproof.web import correlate, replay
from liftproof.web import run as webrun
from liftproof.web.browser import (
    VOLATILE,
    BodyPolicy,
    Captured,
    NetworkLog,
    Write,
    applied_regions,
    in_force,
    normalise_path,
)
from liftproof.web.compare import Comparison, WebOptions, compare_journey
from liftproof.web.journey import (
    REGION_SHAPE_VERSION,
    Correlation,
    Exchange,
    IgnoreRegion,
    Journey,
    Locator,
    Step,
    region_shape,
    sha256,
    shape,
)
from liftproof.web.recorder import NavigationWatch, RecordingSession, old_chromium, typed_url
from liftproof.web.replay import JourneyRun, Replayer, StepRun, WrongPage
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


MEDIUM, LOW = Severity.MEDIUM, Severity.LOW


def shapes(recorded, replayed, **opts):
    c, out = cmp(**opts)
    c._shape("GET /api/orders", shape(recorded), shape(replayed), "$", 1)
    return [(f.severity, f.summary) for f in out]


def test_shape_compares_array_elements():
    c, out = cmp()
    recorded = {"orders": [{"id": 1, "total": 10.5}, {"id": 2, "total": 3}]}
    c._shape("GET /api/orders", shape(recorded), shape({"orders": [{"id": 1}, {"id": 2}]}), "$", 1)
    assert [(f.kind, f.severity, f.column, f.summary) for f in out] == [
        (Kind.DIFFERENCE, MEDIUM, "$.orders[*].total",
         "field $.orders[*].total missing on the target")]
    assert shapes({"orders": [{"id": 1}]}, {"orders": [{"id": 1, "tax": 0.5}]}) == [
        (MEDIUM, "field $.orders[*].tax added on the target")]
    assert shapes([{"id": 1, "total": 1}], [{"id": 1}]) == [
        (MEDIUM, "field $[*].total missing on the target")]
    nested = {"o": [{"lines": [{"sku": "a", "qty": 1}]}, {"lines": []}]}
    assert shapes(nested, {"o": [{"lines": [{"sku": "b"}]}]}) == [
        (MEDIUM, "field $.o[*].lines[*].qty missing on the target")]


def test_shape_field_missing_from_some_elements_is_low():
    assert shapes({"orders": [{"total": 1}, {"total": 2}]}, {"orders": [{"total": 1}, {}]}) == [
        (LOW, "field $.orders[*].total missing from some elements on the target")]
    # optional on the source: which elements have it is data
    assert shapes({"orders": [{"total": 1}, {}]}, {"orders": [{"total": 1}, {}]}) == []
    assert shapes({"orders": [{"total": 1}, {}]}, {"orders": [{"total": 1}]}) == []


def test_shape_of_drifted_data_is_low():
    # an optional field gone, an optional field added, a value where every one was null
    assert shapes({"orders": [{"id": 1, "shipped_at": "x"}, {"id": 2}]},
                  {"orders": [{"id": 3}]}) == [
        (LOW, "field $.orders[*].shipped_at missing on the target")]
    assert shapes({"orders": [{"id": 1}]}, {"orders": [{"id": 3, "discount": 1}, {"id": 4}]}) == [
        (LOW, "field $.orders[*].discount added on the target")]
    assert shapes({"orders": [{"shipped_at": None}]}, {"orders": [{"shipped_at": "x"}]}) == [
        (LOW, "type of $.orders[*].shipped_at differs")]
    assert shapes({"o": [{"t": 1}, {"t": "x"}]}, {"o": [{"t": 1}]}) == [
        (LOW, "type of $.o[*].t differs")]


def test_shape_array_element_types():
    c, out = cmp()
    c._shape("GET /a", shape({"orders": [{"total": 1}]}), shape({"orders": [{"total": "1"}]}),
             "$", 1)
    assert [(f.severity, f.summary, f.expected, f.actual) for f in out] == [
        (MEDIUM, "type of $.orders[*].total differs", "number", "string")]
    assert shapes({"o": [{"a": 1}]}, {"o": ["a"]}) == [(MEDIUM, "type of $.o[*] differs")]
    # null goes with any type
    assert shapes({"o": [{"t": 1}, {"t": None}]}, {"o": [{"t": 1}]}) == []
    assert shapes({"o": [{"t": None}]}, {"o": [{"t": None}, {"t": 2}]}) == []
    # an empty array has no element shape
    assert shapes({"o": []}, {"o": [{"a": 1}]}) == shapes({"o": [{"a": 1}]}, {"o": []}) == []


def test_shape_of_single_values_is_unchanged():
    assert shapes({"t": None}, {"t": 1}) == [(MEDIUM, "type of $.t differs")]
    assert shapes({"t": 1}, {"t": None}) == [(MEDIUM, "type of $.t differs")]
    assert shapes({"a": {"b": 1}, "c": [1]}, {"a": {"d": 1}, "c": "x"}) == [
        (MEDIUM, "field $.a.b missing on the target"), (MEDIUM, "field $.a.d added on the target"),
        (MEDIUM, "type of $.c differs")]


def test_ignore_json_paths_every_element():
    recorded, replayed = {"orders": [{"id": 1, "total": 1}]}, {"orders": [{"id": 1}]}
    for rule in ("GET /api/orders $.orders[*].total", "$.orders[].total", "$.orders[*]"):
        assert shapes(recorded, replayed, ignore_json_paths=[rule]) == [], rule
    for rule in ("$.orders[0].total", "GET /api/other $.orders[*].total"):
        assert shapes(recorded, replayed, ignore_json_paths=[rule]) != [], rule
    a, b = {"orders": [{"total": 1}, {"total": 2}]}, {"orders": [{"total": 5}, {"total": 6}]}
    for rule in ("$.orders[*].total", "$.orders[].total"):
        c, out = cmp(ignore_json_paths=[rule])
        c._json("GET /api/orders", a, b, "$", 1)
        assert out == [], rule
    c, out = cmp(ignore_json_paths=["$.orders[0].total"])
    c._json("GET /api/orders", a, b, "$", 1)
    assert [f.column for f in out] == ["$.orders[1].total"]


def test_unkept_body_array_field_reported_through_api():
    c, out = cmp()
    rec = Exchange("GET", "/api/orders", 200, body_shape=shape({"orders": [{"id": 1, "total": 2}]}))
    got = Captured(Exchange("GET", "/api/orders", 200), 0.0, None, {"orders": [{"id": 1}]}, None)
    c.api([rec], [got], 3)
    assert [(f.object, f.column, f.locator, f.severity) for f in out] == [
        ("GET /api/orders", "$.orders[*].total", "step 3", MEDIUM)]


def test_a_low_shape_difference_passes_the_run_but_not_the_journey(monkeypatch):
    rec = Exchange("GET", "/api/orders", 200, body_shape=shape({"orders": [{"total": 1}]}))
    step = Step(1, "goto", url="/orders", region="- heading", exchanges=[rec])
    j = Journey("j1", "http://source.invalid", story="S-1", steps=[step])
    got = Captured(Exchange("GET", "/api/orders", 200), 0.0, None, {"orders": [{"total": 1}, {}]},
                   None)
    ran = StepRun(1, "goto", status="ok", region="- heading", exchanges=[got], attempts=1)
    fakereplay.no_browser(monkeypatch, lambda j: JourneyRun(
        j.journey_id, status="completed", steps=[ran], attempts=1))
    findings = []
    result = _replay([j], findings.append)
    assert [(f.severity, f.summary) for f in findings] == [
        (LOW, "field $.orders[*].total missing from some elements on the target")]
    assert [r.status for r in result.journeys] == ["different"]
    assert verdict(findings) == PASSED_WITH_DIFFERENCES


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
def _replay(journeys, emit, *, workers=1, on_journey=None, options=None):
    return run_journeys(journeys, target_url="http://target.invalid",
                        options=options or WebOptions(), emit=emit, assets_dir=lambda j: None,
                        secret_values=lambda j: {}, workers=workers,
                        on_journey=on_journey)  # fmt: skip


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
        self.handlers, self.unrouted = {}, []

    def route(self, *a) -> None:
        pass

    def on(self, event, handler) -> None:
        self.handlers[event] = handler

    def unroute_all(self, behavior=None) -> None:
        self.unrouted.append(behavior)

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


def _route(req, meanwhile):
    """The route an API call is fetched through: the target answers it 500 once meanwhile
    has run."""

    def fetch():
        meanwhile()
        return SimpleNamespace(status=500, headers={}, body=lambda: b"{}")

    return SimpleNamespace(request=req, fetch=fetch, fulfill=lambda response: None)


def test_a_write_the_page_gave_up_on_keeps_its_answer():
    """The page navigated away while its order was being fetched, so the request failed
    in the page before the target answered it 500 (spec 19)."""
    page = _Page()
    net = NetworkLog(page)
    order = _request("POST", "/api/orders")
    page.handlers["request"](order)
    net._route(_route(order, lambda: page.handlers["requestfailed"](order)))
    assert net.writes == [Write("POST /api/orders", 500)]


@pytest.mark.parametrize(("method", "behavior"), [("POST", "wait"), ("GET", "ignoreErrors")])
def test_a_page_closes_waiting_only_for_the_writes_being_fetched(method, behavior):
    """Closing under a write sends it again. A read is not waited for: it may be a long
    poll the server holds open, which held every journey for the fetch's 30 s timeout."""
    page = _Page()
    net = NetworkLog(page)
    req = _request(method, "/api/updates")
    page.handlers["request"](req)
    net._route(_route(req, net.close))  # closed while it is being fetched
    net.close()  # and once it has been answered
    assert page.unrouted == [behavior, "ignoreErrors"]


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


# ------------------------------------------------- correlations left unresolved (spec 6)
RID = "482913"


def _order_journey(**rule):
    """Step 1 places an order, step 2 goes to it: the order id is a correlation."""
    c = Correlation("orders.id", "json_path", "POST /api/orders", "$.id", RID, used_in=["step 2"])
    for k, v in rule.items():
        setattr(c, k, v)
    steps = [Step(1, "click", exchanges=[Exchange("POST", "/api/orders", 201)]),
             Step(2, "goto", url=f"/orders/{RID}", region=f'- heading "Order {RID}"',
                  exchanges=[Exchange("GET", f"/orders/{RID}", 200),
                             Exchange("GET", f"/api/orders/{RID}", 200)])]  # fmt: skip
    return Journey("checkout", "http://source.invalid", story="ORD-14", steps=steps,
                   correlations=[c])  # fmt: skip


def _captured(method, url, status, json_body=None, headers=None, sent=None):
    body = json.dumps(json_body).encode() if json_body is not None else None
    ex = Exchange(method, url, status, response_headers=headers or {})
    return Captured(ex, 0.0, body, json_body, sent)


def _order_run(placed, *opened, region=None, failed_at=None, failure_kind="not_found"):
    """The target's answer to the order (None: never asked), then step 2's requests."""
    steps = [StepRun(1, "click", "ok", exchanges=[placed] if placed else []),
             StepRun(2, "goto", "ok", exchanges=list(opened), region=region)]  # fmt: skip
    run = JourneyRun("checkout", status="completed", steps=steps, attempts=1)
    if failed_at:
        steps.append(StepRun(failed_at, "click", "failed"))
        run.status, run.failure_kind = "failed", failure_kind
    return run


def _compare(journey, run, **opts):
    out = []
    compare_journey(journey, run, WebOptions(**opts), out.append, None)
    return out


def _unresolved(findings):
    return [f for f in findings if "correlation" in f.detail]


def test_an_unresolved_correlation_names_the_failure_it_caused():
    j = _order_journey()
    run = _order_run(_captured("POST", "/api/orders", 201, {"order_id": 517001}),
                     _captured("GET", f"/orders/{RID}", 200),
                     _captured("GET", f"/api/orders/{RID}", 404, {}))  # fmt: skip
    findings = _compare(j, run)
    [status] = [f for f in findings if f.summary == "status code differs"]
    assert (status.object, status.detail["unresolved_correlations"]) == (
        "GET /api/orders/{orders.id}", ["orders.id"])
    [u] = _unresolved(findings)
    assert (u.kind, u.severity, u.column, u.locator, u.journey) == (
        Kind.NOT_CHECKED, Severity.MEDIUM, "orders.id", "step 1", "checkout")
    assert u.summary == (
        "correlation orders.id not resolved: json_path $.id found no value in the target's "
        "POST /api/orders response (status 201); step 2 sent the recorded value; it explains "
        "1 finding in step 2")
    assert {k: u.detail[k] for k in ("cause", "source_step", "source_status", "sent_in")} == {
        "cause": "not_in_response", "source_step": 1, "source_status": 201, "sent_in": [2]}
    assert u.detail["caused"] == [
        {"step": 2, "object": "GET /api/orders/{orders.id}", "summary": "status code differs"}]
    # the value stays out of the finding unless values are shown, and out of a bundle
    assert u.expected.startswith("sha256:") and RID not in json.dumps(u.to_dict())
    bundled = support.redact_finding(u.to_dict())
    assert (bundled["summary"], bundled["detail"]) == (u.summary, u.detail)
    assert bundled["expected"] == support.REDACTED
    [u] = _unresolved(_compare(j, run, show_values=True))
    assert (u.expected, u.actual) == (RID, None)
    report = build_report(run_id="r", project="p", mode="replay", started_at="t",
                          finished_at="t", db=None, findings=findings, metadata={},
                          range_block={})  # fmt: skip
    assert report["verdict"] == "failed"
    html = render_html(report)
    assert ("status code differs<br><span class=\"sub\">unresolved correlations: orders.id"
            in html)  # fmt: skip


@pytest.mark.parametrize(("rule", "placed", "cause", "says"), [
    ({}, {"id": ""}, "empty_value", "json_path $.id found an empty value in the target's"),
    ({"transforms": ["base64_decode"]}, {"id": "not-encoded"}, "transform_failed",
     "what json_path $.id found in the target's POST /api/orders response (status 201) did "
     "not decode with base64_decode"),
    ({"extractor": "header", "expression": "X-CSRF-Token"}, {}, "header_redacted",
     "the x-csrf-token header of the target's POST /api/orders response (status 201) is "
     "redacted before replay reads it"),
    ({}, None, "source_not_requested",
     "the target never made the POST /api/orders request (recorded in step 1)"),
])  # fmt: skip
def test_why_a_correlation_was_not_resolved(rule, placed, cause, says):
    j = _order_journey(**rule)
    headers = {"x-csrf-token": "@@REDACTED"}
    placed = None if placed is None else _captured("POST", "/api/orders", 201, placed, headers)
    run = _order_run(placed,
                     _captured("GET", f"/orders/{RID}", 200),
                     _captured("GET", f"/api/orders/{RID}", 200, {}))  # fmt: skip
    if rule.get("extractor") == "header":
        Replayer._correlate(None, j, run.steps[0], run)  # a redacted header carries nothing
        assert run.values == {}
    [u] = _unresolved(_compare(j, run, show_values=True))
    assert u.detail["cause"] == cause and says in u.summary
    # nothing failed for it: the recorded value was sent and answered as at recording
    assert (u.kind, u.severity, u.detail["sent_in"]) == (Kind.NOT_CHECKED, Severity.LOW, [2])
    assert u.actual == ("not-encoded" if cause == "transform_failed" else None)


def test_a_journey_stopped_before_the_value_existed_reports_nothing():
    j = _order_journey()
    run = JourneyRun("checkout", status="failed", failure_kind="transport", attempts=2,
                     steps=[StepRun(1, "click", "failed")])  # fmt: skip
    assert _unresolved(_compare(j, run)) == []
    run = _order_run(_captured("POST", "/api/orders", 201, {"id": 517001}))
    run.values[RID] = "517001"  # resolved
    assert _unresolved(_compare(j, run)) == []


def test_the_page_carried_the_targets_own_value():
    """Unresolved, but the page used the id the target sent: nothing sent the recorded
    value, and the differences it leaves unmasked are traced to it."""
    j = _order_journey(expression="$.order_id")
    run = _order_run(_captured("POST", "/api/orders", 201, {"id": 517001}),
                     _captured("GET", "/orders/517001", 200),
                     _captured("GET", "/api/orders/517001", 200, {}),
                     region='- heading "Order 517001"')  # fmt: skip
    findings = _compare(j, run)
    named = {(f.object, f.summary) for f in findings
             if f.detail.get("unresolved_correlations") == ["orders.id"]}  # fmt: skip
    assert named == {
        ("GET /orders/{orders.id}", "request made on the source was not made on the target"),
        ("GET /api/orders/{orders.id}", "request made on the source was not made on the target"),
        ("GET /orders/{id}", "request made on the target that the source did not make"),
        ("GET /api/orders/{id}", "request made on the target that the source did not make"),
        ("checkout step 2", "page content differs after the step"),
    }
    [u] = _unresolved(findings)
    assert (u.kind, u.severity, u.detail["sent_in"]) == (Kind.NOT_CHECKED, Severity.MEDIUM, [])
    assert u.summary.endswith("; it explains 5 findings in step 2")
    # with nothing traced to it, a notice that still names it
    j.steps[1] = Step(2, "goto", url="/orders", exchanges=[Exchange("GET", "/orders", 200)])
    run.steps[1] = StepRun(2, "goto", "ok", exchanges=[_captured("GET", "/orders", 200)])
    findings = _compare(j, run)
    [u] = _unresolved(findings)
    assert (u.kind, u.severity) == (Kind.NOTICE, Severity.INFO)
    web = WebResult(journeys=[webrun.JourneyResult("checkout", "ORD-14", "passed", 2, 2, 1, 0,
                                                   0, 1.0, 1.0)])  # fmt: skip
    report = build_report(run_id="r", project="p", mode="replay", started_at="t",
                          finished_at="t", db=None, findings=findings, metadata={},
                          range_block={}, web=web)  # fmt: skip
    assert report["coverage"]["exclusions"] == [] and report["verdict"] == "passed"
    assert "unresolved correlations: orders.id</span>" in render_html(report)


def test_a_candidate_never_confirmed_only_when_the_target_changed_it_and_it_was_sent():
    j = _order_journey(recorded_value="4821", confirmed=False)
    j.steps[1] = Step(2, "goto", url="/orders/4821",
                      exchanges=[Exchange("GET", "/api/orders/4821", 200)])  # fmt: skip

    def replayed(target_id, sent_id, status):
        run = _order_run(_captured("POST", "/api/orders", 201, {"id": target_id}),
                         _captured("GET", f"/api/orders/{sent_id}", status, {}))  # fmt: skip
        return _unresolved(_compare(j, run, show_values=True))

    assert replayed(4821, 4821, 200) == []  # the same value on the target: data, not an id
    assert replayed(5173, 5173, 200) == []  # the page carried the target's own
    [u] = replayed(5173, 4821, 404)
    assert (u.kind, u.severity, u.detail["cause"], u.actual) == (
        Kind.NOT_CHECKED, Severity.MEDIUM, "unconfirmed", "5173")
    assert "carried a different value" in u.summary and "confirm it" in u.summary


@pytest.mark.parametrize(("rid", "rule", "line_id", "cause", "found"), [
    ("4821", {"confirmed": False}, 5173, "unconfirmed", "5173"),
    (RID, {"transforms": ["base64_decode"]}, "not-encoded", "transform_failed", "not-encoded"),
])  # fmt: skip
def test_every_answer_to_the_source_request_is_read(rid, rule, line_id, cause, found):
    """The cart is read before the line exists, as replay reads every answer to it: the
    answer the value comes from is judged, not the first one."""
    c = Correlation("cart.line_id", "json_path", "GET /api/cart", "$.items[0].line_id", rid,
                    used_in=["DELETE /api/cart/items/{id}"], **rule)  # fmt: skip
    j = Journey("cart", "http://source.invalid", correlations=[c], steps=[
        Step(1, "goto", url="/cart", exchanges=[Exchange("GET", "/api/cart", 200)]),
        Step(2, "click", exchanges=[Exchange("POST", "/api/cart/items", 201),
                                    Exchange("GET", "/api/cart", 200)]),
        Step(3, "click", exchanges=[Exchange("DELETE", f"/api/cart/items/{rid}", 204)]),
    ])  # fmt: skip
    run = JourneyRun("cart", status="completed", attempts=1, steps=[
        StepRun(1, "goto", "ok", exchanges=[_captured("GET", "/api/cart", 200, {"items": []})]),
        StepRun(2, "click", "ok", exchanges=[
            _captured("POST", "/api/cart/items", 201, {}),
            _captured("GET", "/api/cart", 200, {"items": [{"line_id": line_id}]})]),
        StepRun(3, "click", "ok", exchanges=[
            _captured("DELETE", f"/api/cart/items/{rid}", 404, {})]),
    ])  # fmt: skip
    for sr in run.steps:
        Replayer._correlate(None, j, sr, run)
    assert run.values == {}
    findings = _compare(j, run, show_values=True)
    [status] = [f for f in findings if f.summary == "status code differs"]
    assert status.detail["unresolved_correlations"] == ["cart.line_id"]
    [u] = _unresolved(findings)
    assert (u.kind, u.severity, u.locator, u.actual) == (
        Kind.NOT_CHECKED, Severity.MEDIUM, "step 2", found)
    assert {k: u.detail[k] for k in ("cause", "source_step", "source_status", "sent_in")} == {
        "cause": cause, "source_step": 2, "source_status": 200, "sent_in": [3]}


def _total_run(checkout, beacon, ts):
    """Step 1 reads the cart, whose short total is a candidate never confirmed that
    recording saw reused in the checkout; step 2 checks out and sends an analytics beacon
    whose timestamp happens to hold the total's digits."""
    return JourneyRun("checkout", status="completed", attempts=1, steps=[
        StepRun(1, "goto", "ok", exchanges=[
            _captured("GET", "/api/cart", 200, {"total": "125", "ts": ts})]),
        StepRun(2, "click", "ok", exchanges=[
            _captured("POST", "/api/checkout", checkout[0], {}, sent=checkout[1]),
            _captured("POST", "/api/events", beacon, None, sent='{"ts":1760001203}')]),
    ])  # fmt: skip


def test_a_value_sent_only_by_coincidence_is_not_named(tmp_path):
    c = Correlation("total", "json_path", "GET /api/cart", "$.total", "120",
                    used_in=["POST /api/checkout"], confirmed=False)  # fmt: skip
    (tmp_path / "cart").write_bytes(json.dumps({"total": "120", "ts": 1760001203}).encode())
    j = Journey("checkout", "http://source.invalid", correlations=[c], steps=[
        Step(1, "goto", url="/cart",
             exchanges=[Exchange("GET", "/api/cart", 200, body_asset="assets/cart")]),
        Step(2, "click", exchanges=[Exchange("POST", "/api/checkout", 201),
                                    Exchange("POST", "/api/events", 204)]),
    ])  # fmt: skip

    def compared(run):
        findings = []
        compare_journey(j, run, WebOptions(), findings.append, tmp_path)
        return findings

    # the page checked out with the target's own total: nothing sent the recorded one
    findings = compared(_total_run((201, '{"amount":"125"}'), 503, 1760001203))
    assert _unresolved(findings) == []
    assert not [f for f in findings if "unresolved_correlations" in f.detail]
    # the checkout sent the recorded total, and the failures with nothing of it are not its
    findings = compared(_total_run((422, '{"amount":"120"}'), 503, 1760001299))
    blamed = {f.object: f.detail.get("unresolved_correlations") for f in findings
              if f.summary in ("status code differs", "value of $.ts differs")}  # fmt: skip
    assert blamed == {"POST /api/checkout": ["total"], "POST /api/events": None,
                      "GET /api/cart": None}  # fmt: skip
    [u] = _unresolved(findings)
    assert (u.detail["cause"], u.detail["sent_in"], u.severity) == (
        "unconfirmed", [2], Severity.MEDIUM)
    assert u.summary.count("it explains 1 finding in step 2") == 1


def test_the_failure_after_a_stale_value_names_it(monkeypatch):
    j = _order_journey()
    j.steps.append(Step(3, "click", locator=None))
    run = _order_run(_captured("POST", "/api/orders", 201, {}),
                     _captured("GET", f"/api/orders/{RID}", 404, {}), failed_at=3)  # fmt: skip
    fakereplay.no_browser(monkeypatch, lambda journey: run)
    findings = []
    [r] = _replay([j], findings.append).journeys
    [failure] = [f for f in findings if f.summary.startswith("element the journey uses")]
    assert failure.detail["unresolved_correlations"] == ["orders.id"]
    [u] = _unresolved(findings)
    assert u.summary.endswith("; the journey then failed at step 3")
    assert r.status == "different"
    # a crash is not the page's doing
    run.failure_kind = "browser_crash"
    findings = []
    _replay([j], findings.append)
    [u] = _unresolved(findings)
    assert "failed" not in u.summary
    assert not [f for f in findings if "unresolved_correlations" in f.detail
                and f.kind == Kind.ERROR]  # fmt: skip


# ------------------------------------------------------- page snapshots (spec 5, decision 99)
SNAPSHOT = """\
- main:
  - heading "Order 4021" [level=1]
  - 'heading "Order: 4021 for Alice" [level=2]'
  - 'heading "Alice''s order: 4021" [level=2]'
  - heading "It's \\"quoted\\" [x]" [level=3]
  - textbox "Username": alice
  - textbox "Email":
    - /placeholder: alice@example.com
  - checkbox "Agree" [checked=mixed] [disabled]
  - link "Back to orders":
    - /url: /orders/4021?x=1
  - paragraph: "Total: 10.50 EUR"
  - img "Alice Smith" [alt=Alice Smith] [ref=e12]
  - Alice
  - heading [level=4]
  - text: Alice Smith"""


def test_region_shape_keeps_structure_not_content():
    got = region_shape(SNAPSHOT)
    assert got.splitlines() == [
        "- main:",
        '  - heading "*" [level=1]',
        '  - heading "*" [level=2]',  # YAML quotes a key holding ": "
        '  - heading "*" [level=2]',
        '  - heading "*" [level=3]',
        '  - textbox "*": *',
        '  - textbox "*":',
        "    - /placeholder: *",
        '  - checkbox "*" [checked=mixed] [disabled]',
        '  - link "*":',
        "    - /url: *",
        "  - paragraph: *",
        '  - img "*"',  # attributes Playwright does not use for state are dropped
        "  ?",  # no known role: nothing of the line is kept
        "  - heading [level=4]",
        "  - text: *",
    ]
    for content in ("4021", "Alice", "alice", "quoted", "orders", "10.50", "e12", "Agree"):
        assert content not in got


def _session(policy):
    page = SimpleNamespace(route=lambda *a: None, on=lambda *a: None, is_closed=lambda: True)
    return RecordingSession(page, Journey("j1", "http://source.invalid"), policy, 0)


def test_snapshots_are_kept_only_for_pages_opted_in():
    s = _session(BodyPolicy(["/api/*"], snapshots=["/orders/*"]))
    token = s._token("Password", "s3cret-pass")
    s.journey.steps = [
        Step(1, "goto", url="/login", page_url="/login",
             region='- textbox "Password": s3cret-pass\n- button "Sign in"'),
        Step(2, "click", page_url="/orders/4021?tab=1",
             region='- heading "Order 4021 for s3cret-pass" [level=1]'),
    ]  # fmt: skip
    s._times = [0.0, 1.0]
    journey, assets = s.finish()
    login, order = journey.steps
    assert (login.region, order.region) == (None, None)
    assert login.region_shape == '- textbox "*": *\n- button "*"'
    scrubbed = f'- textbox "Password": {token}\n- button "Sign in"'
    assert (login.region_sha256, login.region_asset) == (sha256(scrubbed.encode()), None)
    kept = f'- heading "Order 4021 for {token}" [level=1]'.encode()
    assert (order.region_sha256, order.region_asset) == (sha256(kept), f"assets/{sha256(kept)}")
    assert assets == {sha256(kept): kept}
    assert journey.region_shape_version == REGION_SHAPE_VERSION
    text = json.dumps(journey.to_dict())
    assert not [t for t in ("s3cret-pass", "Order 4021", "Sign in") if t in text]
    assert Journey.from_dict(json.loads(text)).to_dict() == journey.to_dict()
    assert BodyPolicy([], snapshots=["/orders"]).keeps_snapshot("/orders?page=2")  # no query


ORDER_PAGE = "\n".join([
    '- heading "Order 7" [level=1]', '- checkbox "Gift wrap" [checked]', "- text: DISPATCHED",
    '- button "Cancel"'])  # fmt: skip


def _page_journey(**step):
    return Journey("j", "http://source.invalid", region_shape_version=REGION_SHAPE_VERSION,
                   steps=[Step(1, "goto", url="/orders/7", **step)])  # fmt: skip


def _pages(journey, region, assets_dir=None, exchanges=()):
    run = JourneyRun("j", status="completed", attempts=1,
                     steps=[StepRun(1, "goto", "ok", region=region, exchanges=list(exchanges))])
    findings = []
    cmp = compare_journey(journey, run, WebOptions(), findings.append, assets_dir)
    return findings, cmp.ui_compared


def test_a_page_not_kept_is_compared_by_structure():
    j = _page_journey(region_shape=region_shape(ORDER_PAGE))
    # other text and other values: the same structure
    other = ORDER_PAGE.replace("DISPATCHED", "dispatched").replace("Order 7", "Order 9")
    assert _pages(j, other) == ([], {"text": 0, "shape": 1, "expired": 0})
    for page, expected, actual in [
        (ORDER_PAGE.replace('\n- button "Cancel"', ""), '- button "*"', ""),
        (ORDER_PAGE.replace(" [checked]", ""), '- checkbox "*" [checked]', '- checkbox "*"'),
    ]:
        [f], counts = _pages(j, page)
        assert (f.kind, f.severity, f.object, f.summary) == (
            Kind.DIFFERENCE, MEDIUM, "j step 1", "page structure differs after the step")
        assert (f.expected, f.actual, f.detail["compared"]) == (expected, actual, "shape")
        assert counts == {"text": 0, "shape": 1, "expired": 0}


def test_a_kept_snapshot_is_compared_as_text_until_it_expires(tmp_path):
    raw = ORDER_PAGE.encode()
    body = json.dumps({"id": 7, "status": "DISPATCHED"}).encode()
    (tmp_path / sha256(raw)).write_bytes(raw)
    (tmp_path / sha256(body)).write_bytes(body)
    j = _page_journey(region_shape=region_shape(ORDER_PAGE), region_sha256=sha256(raw),
                      region_asset=f"assets/{sha256(raw)}", exchanges=[
                          Exchange("GET", "/api/orders/7", 200, body_asset=f"assets/{sha256(body)}",
                                   body_shape=shape(json.loads(body)))])  # fmt: skip
    answer = _captured("GET", "/api/orders/7", 200, {"id": 7, "status": "OPEN"})
    relabelled = ORDER_PAGE.replace('"Cancel"', '"Cancel order"')
    findings, counts = _pages(j, relabelled, tmp_path, [answer])
    assert sorted((f.summary, f.detail.get("compared")) for f in findings) == [
        ("page content differs after the step", "text"), ("value of $.status differs", None)]
    assert counts == {"text": 1, "shape": 0, "expired": 0}
    # the bucket expired both, and fetching the journey's assets dropped the copies here
    for f in tmp_path.iterdir():
        f.unlink()
    [notice], counts = _pages(j, relabelled, tmp_path, [answer])  # the same structure, shape
    assert counts == {"text": 0, "shape": 0, "expired": 1}
    assert (notice.kind, notice.severity, notice.object, notice.detail) == (
        Kind.NOTICE, Severity.INFO, "j", {"snapshots_expired": 1, "bodies_expired": 1})
    assert notice.summary.endswith("compared 1 page by structure and 1 response by shape")
    findings, _ = _pages(j, relabelled.replace(" [checked]", ""), tmp_path, [answer])
    assert [f.summary for f in findings if f.kind == Kind.DIFFERENCE] == [
        "page structure differs after the step"]


def test_a_journey_recorded_with_its_snapshots_inline_compares_their_text():
    d = Journey("j", "http://source.invalid", steps=[Step(1, "goto", url="/orders/7")]).to_dict()
    for k in ("region_sha256", "region_shape", "region_asset"):
        del d["steps"][0][k]
    del d["region_shape_version"]
    d["format"], d["steps"][0]["region"] = "1.0", ORDER_PAGE
    j = Journey.from_dict(d)
    findings, counts = _pages(j, ORDER_PAGE.replace('"Cancel"', '"Cancel order"'))
    assert [f.summary for f in findings] == ["page content differs after the step"]
    assert counts == {"text": 1, "shape": 0, "expired": 0}


def test_a_structure_made_by_another_version_is_not_compared():
    j = _page_journey(region_shape=region_shape(ORDER_PAGE))
    j.region_shape_version = REGION_SHAPE_VERSION + 1
    [f], counts = _pages(j, '- heading "Orders"')
    assert (f.kind, f.severity, f.object, f.detail["steps"]) == (Kind.NOT_CHECKED, LOW, "j", 1)
    assert "record the journey again" in f.summary
    assert counts == {"text": 0, "shape": 0, "expired": 0}


def test_the_report_says_how_pages_were_compared():
    compared = webrun.JourneyResult("checkout", "ORD-14", "passed", 6, 6, 1, 0, 0, 1.0, 1.0,
                                    ui_compared={"text": 1, "shape": 4, "expired": 1})
    before = asdict(webrun.JourneyResult("login", None, "passed", 2, 2, 1, 0, 0, 1.0, 1.0))
    del before["ui_compared"]  # a run reported before pages were counted
    web = WebResult.from_dict({"journeys": [asdict(compared), before]})
    report = build_report(run_id="r", project="p", mode="replay", started_at="t",
                          finished_at="t", db=None, findings=[], metadata={},
                          range_block={}, web=web)  # fmt: skip
    assert report["coverage"]["ui_compared"] == {"text": 1, "shape": 4, "expired": 1}
    assert [j["ui_compared"] for j in report["journeys"]] == [compared.ui_compared, {}]
    assert ">1 / 5 (1 expired)</td>" in render_html(report)


# ------------------------------------------------------------- ignore regions (spec 7)
GREETING = IgnoreRegion("personalised", ".greeting")


def _project(tmp_path, web):
    p = tmp_path / "p.yaml"
    p.write_text(yaml.safe_dump({"project": "t", "web": {"source_url": "http://a", **web}}))
    return load_project(p).web


@pytest.mark.parametrize("regions", [
    ".greeting", [".greeting"], [{"selector": ".greeting"}], [{"reason": "personalised"}],
    [{"selector": "", "reason": "personalised"}], [{"selector": 7, "reason": "personalised"}],
])  # fmt: skip
def test_an_ignore_region_needs_a_selector_and_a_reason(tmp_path, regions):
    with pytest.raises(ConfigError, match="web.ignore_regions"):
        _project(tmp_path, {"ignore_regions": regions})


def test_ignore_regions_in_the_project(tmp_path):
    assert _project(tmp_path, {}).ignore_regions == []
    web = _project(tmp_path, {"ignore_regions": [
        {"selector": ".greeting", "reason": "personalised"},
        {"source_selector": "#legacy-ad", "target_selector": "[data-ad]", "reason": "ads"},
    ]})  # fmt: skip
    marked = IgnoreRegion("ads", source_selector="#legacy-ad", target_selector="[data-ad]")
    assert web.ignore_regions == [GREETING, marked]
    assert (marked.on("source"), marked.on("target")) == ("#legacy-ad", "[data-ad]")
    assert marked.label == "source #legacy-ad, target [data-ad]" and GREETING.label == ".greeting"
    template = tmp_path / "t.yaml"
    template.write_text(TEMPLATE.format(name="x"))
    assert load_project(template).web.ignore_regions == []
    project = SimpleNamespace(name="t", source=None, target=None, store=None,
                              database=load_project(template).database, web=web, files=[],
                              schedules=[])  # fmt: skip
    assert support.project_summary(project)["web"]["ignore_regions"][1] == {
        "selector": None, "source_selector": "#legacy-ad", "target_selector": "[data-ad]",
        "reason": "ads"}  # fmt: skip


def test_a_journey_keeps_the_ignore_regions_it_was_recorded_with():
    j = Journey("j", "http://source.invalid", ignore_regions=[VOLATILE, GREETING],
                steps=[Step(1, "goto", url="/", region_hidden=[".greeting"])])  # fmt: skip
    again = Journey.from_dict(json.loads(json.dumps(j.to_dict())))
    assert again == j
    d = j.to_dict()
    del d["ignore_regions"], d["steps"][0]["region_hidden"], d["steps"][0]["region_ignored"]
    before = Journey.from_dict(d)  # recorded before ignore regions
    assert (before.ignore_regions, before.steps[0].region_hidden) == ([], [])


def test_an_ignore_region_applies_to_the_journeys_recorded_with_it():
    """The source is read only at recording, so a rule with a source side applies to a
    journey recorded with it, and to it only; a rule for the target alone, to every one."""
    chat = IgnoreRegion("added since", ".chat")
    banner = IgnoreRegion("target only", target_selector=".banner")
    reworded = IgnoreRegion("personalised for the user", ".greeting")
    recorded = [VOLATILE, GREETING]
    assert in_force([chat]) == [VOLATILE, chat]
    own = IgnoreRegion("our own reason", VOLATILE.selector)
    assert in_force([own]) == [own]  # the project's reason for the built-in selector
    assert applied_regions(recorded, in_force([reworded, chat, banner])) == (
        [VOLATILE, reworded, banner], [chat])
    # dropped from the project, it still applies as recorded: the target hides what the
    # source did
    assert applied_regions(recorded, in_force([])) == ([VOLATILE, GREETING], [])
    # recorded before ignore regions
    assert applied_regions([], in_force([chat, banner])) == ([banner], [VOLATILE, chat])


def _hiding(source: dict, target: dict, region: str = ORDER_PAGE):
    j = Journey("j", "http://source.invalid", ignore_regions=[VOLATILE, GREETING],
                steps=[Step(1, "goto", url="/orders/7", **{"region": ORDER_PAGE, **source})])
    run = JourneyRun("j", status="completed", attempts=1,
                     steps=[StepRun(1, "goto", "ok", region=region, **target)])
    findings = []
    cmp = compare_journey(j, run, WebOptions(), findings.append, None)
    return findings, cmp


def test_a_page_inside_an_ignore_region_is_not_checked():
    """A selector that matches the page's main element (or one around it) leaves nothing
    to compare: not checked, so the run cannot read as a plain pass."""
    for source, target in [({"region": None, "region_ignored": ".greeting"}, {}),
                           ({}, {"region_ignored": ".greeting"})]:  # fmt: skip
        [f], cmp = _hiding(source, target, "" if target else ORDER_PAGE)
        assert (f.kind, f.severity, f.object, f.detail) == (
            Kind.NOT_CHECKED, LOW, "j", {"steps": [1], "ignore_regions": [".greeting"]})
        assert f.summary == "page after step 1 not compared: the whole page is inside " \
                            "ignore region .greeting"
        assert cmp.ui_compared == {"text": 0, "shape": 0, "expired": 0}
        assert cmp.hidden_by[GREETING]["source" if source else "target"] == [1]
        assert verdict([f]) == PASSED_WITH_DIFFERENCES


def test_a_difference_names_the_ignore_region_that_hid_content_on_one_side_only():
    """The application marks a part volatile on one side only, or a selector matches one
    side's markup: the likely cause of the difference is named with it."""
    without = ORDER_PAGE.replace("- text: DISPATCHED\n", "")
    [f], cmp = _hiding({}, {"region_hidden": [VOLATILE.selector]}, without)
    assert f.summary == "page content differs after the step"
    assert f.detail["hidden_on_one_side"] == {VOLATILE.selector: "target"}
    assert cmp.hidden_by[VOLATILE] == {"source": [], "target": [1], "unhideable": []}
    report = build_report(run_id="r", project="p", mode="replay", started_at="t",
                          finished_at="t", db=None, findings=[f], metadata={},
                          range_block={})  # fmt: skip
    assert f"content on one side only: {VOLATILE.selector} (target)" in render_html(report)
    # hidden on both sides, nothing differs
    assert _hiding({"region_hidden": [".greeting"]}, {"region_hidden": [".greeting"]})[0] == []


def test_each_ignore_region_is_listed_with_its_reason(monkeypatch):
    """One notice a rule over the run, which the report lists among the exclusions (spec
    9.12): where it hid content, that it matched nothing, or that no journey replayed was
    recorded with it. The built-in rule only once it hid something."""
    banner = IgnoreRegion("never shown", ".banner")
    chat = IgnoreRegion("added since", ".chat")
    contents = IgnoreRegion("rendered as contents", target_selector=".promo")
    journeys = [fakereplay.journey("j1"), fakereplay.journey("j2")]
    for j in journeys:
        j.ignore_regions = in_force([GREETING, banner])
    journeys[0].steps[0].region_hidden = [".greeting"]

    def replay_one(j):
        run = fakereplay.replayed(j)
        if j.journey_id == "j1":
            run.steps[0].region_hidden, run.steps[0].region_unhideable = [".greeting"], [".promo"]
        return run

    fakereplay.no_browser(monkeypatch, replay_one)
    findings = []
    result = _replay(journeys, findings.append,
                     options=WebOptions(ignore_regions=[GREETING, banner, chat, contents]))
    notices = {f.column: f for f in findings if f.object == "page region"}
    assert sorted(notices) == [
        ".banner (matched nothing)", ".chat (not applied)", ".greeting", "target .promo"]
    greeting = notices[".greeting"]
    assert (greeting.kind, greeting.severity, greeting.summary) == (
        Kind.NOTICE, Severity.INFO,
        "ignore region .greeting: what it matched was not compared: personalised")
    assert {k: greeting.detail[k] for k in ("journeys", "steps_on_source", "steps_on_target")} \
        == {"journeys": ["j1"], "steps_on_source": 1, "steps_on_target": 1}
    assert notices[".chat (not applied)"].detail["not_applied"] == ["j1", "j2"]
    assert notices[".chat (not applied)"].summary == (
        "ignore region .chat not applied: the journeys were recorded without it; "
        "record them again")
    assert notices["target .promo"].summary.endswith(
        "in 1 step an element it matched kept its own text, which is compared "
        "(display: contents)")
    report = build_report(run_id="r", project="p", mode="replay", started_at="t",
                          finished_at="t", db=None, findings=findings, metadata={},
                          range_block={}, web=result)  # fmt: skip
    assert sorted((e["object"], e["column"], e["reason"]) for e in
                  report["coverage"]["exclusions"]) == [
        ("page region", ".banner (matched nothing)", "never shown"),
        ("page region", ".chat (not applied)", "added since"),
        ("page region", ".greeting", "personalised"),
        ("page region", "target .promo", "rendered as contents")]  # fmt: skip
    assert "<td>.greeting</td><td>personalised</td>" in render_html(report)


def test_record_says_what_each_ignore_region_hid_on_the_source(tmp_path, monkeypatch, capsys):
    """The source is read only now: a selector that matched nothing there is worth
    knowing before it is gone."""
    from liftproof import cli
    from liftproof.web.recorder import Recorder

    def record(self, journey_id, **kw):
        steps = [Step(1, "goto", url="/", region_hidden=[VOLATILE.selector, ".greeting"]),
                 Step(2, "click", region_ignored=".greeting"), Step(3, "click")]  # fmt: skip
        return Journey(journey_id, "http://a", steps=steps,
                       ignore_regions=in_force(self.regions)), {}  # fmt: skip

    monkeypatch.setattr(Recorder, "record", record)
    p = tmp_path / "p.yaml"
    regions = [{"selector": ".greeting", "reason": "personalised"},
               {"source_selector": "#legacy-ad", "reason": "ads"}]  # fmt: skip
    p.write_text(yaml.safe_dump({"project": "t",
                                 "web": {"source_url": "http://a", "ignore_regions": regions}}))
    work = ["--workdir", str(tmp_path / "work"), "--format", "json"]
    assert cli.main(["record", "--project", str(p), "--journey", "j1", *work]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["ignore_regions_hid"] == {VOLATILE.selector: 1, ".greeting": 2, "#legacy-ad": 0}
    saved = Journey.load(tmp_path / "work" / "t" / "journeys" / "j1.json")
    assert saved.ignore_regions == in_force(load_project(p).web.ignore_regions)


# -------------------------------------------------- navigations made in the browser itself
class _Cdp:
    """A CDP session: navigation history, or gone with its window."""

    def __init__(self, index=0, closed=False) -> None:
        self.index, self.closed = index, closed

    def send(self, method, params=None):
        if self.closed:
            raise RuntimeError("Target page, context or browser has been closed")
        return {"currentIndex": self.index, "entries": []}


def _started(url, kind="differentDocument", frame="main", loader="L1"):
    return {"frameId": frame, "url": url, "loaderId": loader, "navigationType": kind}


def _committed(url, frame="main", loader="L1"):
    return {"frame": {"id": frame, "loaderId": loader, "url": url}}


def test_navigation_watch_tells_browser_from_page():
    w = NavigationWatch(_Cdp(), "main")
    page = "http://a/orders"
    # the page asked for it first (a link, a form, a script, location.reload())
    w._requested({"frameId": "main", "url": page, "disposition": "currentTab"})
    w._start(_started(page, "reload"))
    w._navigated(_committed(page))
    assert w.navs == []
    # the browser's own: an address, Reload, an address with only a new fragment
    w._start(_started(page))
    w._navigated(_committed(page))
    w._start(_started(page, "reload", loader="L2"))
    w._navigated(_committed(page, loader="L2"))
    w._start(_started(page + "#x", "sameDocument", loader="L3"))
    w._within({"frameId": "main", "url": page + "#x"})
    assert [(n["action"], n["url"]) for n in w.navs] == [
        ("goto", page), ("reload", page), ("goto", page + "#x")]  # fmt: skip
    w.navs.clear()
    # a traversal is capture.js's; a frame's navigation and a browser page are not steps
    w._start(_started(page, "historyDifferentDocument"))
    w._start(_started(page, frame="frame"))
    w._start(_started("chrome://settings/"))
    w._navigated(_committed(page))
    # a page asking for a new tab does not hide the browser's next navigation
    w._requested({"frameId": "main", "url": page, "disposition": "newTab"})
    w._start(_started(page, loader="L4"))
    w._navigated(_committed(page, loader="L4"))
    assert [n["action"] for n in w.navs] == ["goto"]
    w.navs.clear()
    # never shown: an address that did not resolve, a download (another navigation
    # follows), and one started as the window closes
    w._start(_started("http://nowhere.invalid/", loader="L5"))
    w._navigated(_committed("chrome-error://chromewebdata/", loader="L5"))
    w._start(_started("http://a/export", loader="L6"))
    w._start(_started("http://a/b", loader="L7"))
    w.abandon()
    assert w.navs == []
    assert [n["url"] for n in w.abandoned] == [
        "http://nowhere.invalid/", "http://a/export", "http://a/b"]  # fmt: skip
    assert w.history_index() == 0
    assert NavigationWatch(_Cdp(closed=True), "main").history_index() is None


def test_a_page_request_hides_its_navigation_across_one_taking_of_steps():
    w = NavigationWatch(_Cdp(), "main")
    page = "http://a/orders"
    # steps were taken between the page asking and the navigation starting
    w._requested({"frameId": "main", "url": page, "disposition": "currentTab"})
    w.forget()
    w._start(_started(page))
    w._navigated(_committed(page))
    assert w.navs == []
    # a request that never started does not hide the same address typed later
    w._requested({"frameId": "main", "url": page, "disposition": "currentTab"})
    w.forget()
    w.forget()
    w._start(_started(page, loader="L2"))
    w._navigated(_committed(page, loader="L2"))
    assert [n["action"] for n in w.navs] == ["goto"]


def test_typed_url_keeps_path_query_fragment_or_full_url():
    assert typed_url("http://src:8080/a?b=1#/c", "http://src:8080") == "/a?b=1#/c"
    assert typed_url("http://src:8080", "http://src:8080") == "/"
    for other in ("https://src:8080/a", "http://localhost:8080/a", "https://example.com/?q=x"):
        assert typed_url(other, "http://src:8080") == other
    # the origin as the browser compares it; a user and password are never kept
    assert typed_url("http://bob:hunter2@src:8080/a", "http://src:8080") == "/a"
    assert typed_url("http://src/a", "http://SRC:80/app") == "/a"
    assert typed_url("https://bob:hunter2@docs.example.com/x?y=1", "http://src:8080") == (
        "https://docs.example.com/x?y=1")  # fmt: skip


def test_record_warns_of_a_chromium_older_than_the_navigation_signals():
    assert old_chromium("141.0.7390.37") is None and old_chromium("unknown") is None
    assert old_chromium("120.0.6099.28").startswith("Chromium 120.0.6099.28 is older than 141")


def _watched(index=0, closed=False):
    s = _session(BodyPolicy())
    s.journey.steps = [Step(1, "goto", url="/orders")]
    s._times, s.watch, s._history = [0.0], NavigationWatch(_Cdp(index, closed), "main"), 3
    s._snapshot = lambda: None
    return s


@pytest.mark.parametrize(("index", "closed", "events", "taken", "warned"), [
    (1, False, [{"action": "traverse", "delta": -1, "t": 5}], ("back", "2"), True),
    (5, False, [{"action": "traverse", "delta": 2, "t": 5}], ("forward", "2"), False),
    (3, False, [{"action": "traverse", "delta": 0, "t": 5}], None, False),  # went nowhere
    # the page moved on by itself after the step before (a timer, a redirect): the window
    # moved less, or the other way, so the page's count, and the engineer is told
    (3, False, [{"action": "traverse", "delta": -1, "t": 5}], ("back", None), True),
    (5, False, [{"action": "traverse", "delta": -1, "t": 5}], ("back", None), True),
    # the window closed straight after: the page's count, and the recording is kept
    (0, True, [{"action": "traverse", "delta": -1, "t": 5}], ("back", None), True),
    (0, True, [{"action": "traverse", "delta": None, "t": 5}], None, True),
])  # fmt: skip
def test_a_traversal_moves_as_the_window_did(index, closed, events, taken, warned):
    s = _watched(index, closed)
    s._events = list(events)
    s._take()
    got = [(st.action, st.value) for st in s.journey.steps[1:]]
    assert got == ([taken] if taken else [])
    assert bool(s.warnings) is warned


def test_a_traversal_with_other_navigations_uses_the_pages_count():
    s = _watched(index=5)
    s.watch.navs.append({"action": "goto", "url": "http://source.invalid/help", "t": 1})
    s._events = [{"action": "traverse", "delta": -1, "t": 5}]
    s._take()
    assert [(st.action, st.url, st.value) for st in s.journey.steps] == [
        ("goto", "/orders", None), ("goto", "/help", None), ("back", None, None)]  # fmt: skip
    assert s.warnings == [
        "step 3: Back came with other actions before the page settled, so how far it went is "
        "the page's count; record the journey again, waiting for each page, if it does not "
        "replay"]  # fmt: skip


def test_the_engineer_is_told_what_a_browser_navigation_repeats_or_leaves():
    s = _watched()
    s.journey.steps += [
        Step(2, "reload", exchanges=[Exchange("POST", "/api/orders", 201)]),
        Step(3, "goto", url="https://docs.example.com/help?q=s3cret-pass"),
        Step(4, "goto", url="/search?q=s3cret-pass", page_url="/search?q=s3cret-pass"),
    ]
    s._token("Password", "s3cret-pass")
    s._times += [1.0, 2.0, 3.0]
    journey, _ = s.finish()
    token = next(iter(journey.secrets))
    assert journey.format == "2.0" and journey.steps[2].url.endswith("?q=" + token)
    assert (journey.steps[3].url, journey.steps[3].page_url) == (f"/search?q={token}",) * 2
    assert s.warnings == [
        "step 2 (reload) sent POST /api/orders again on the source, and replay will send it "
        "to the target; record the journey again without it if that was not meant",
        "step 3 opens https://docs.example.com from the instance at replay, not the target; "
        "record the journey again without it if it was a detour"]  # fmt: skip


def test_the_request_of_a_navigation_never_shown_is_no_steps():
    s = _watched()
    s.watch.abandoned = [{"url": "http://source.invalid/export", "t": 5000.0}]

    def doc(url, started):
        return Captured(Exchange("GET", url, 0, resource_type="document"), started, None, None,
                        None)  # fmt: skip

    kept = [doc("/export", 100.0), doc("/orders", 0.0)]
    s._captured = [kept[0], doc("/export", 5003.0), kept[1]]
    s._drop_abandoned()
    assert s._captured == kept
    s.watch.abandoned = [{"url": "http://source.invalid/orders", "t": 9000.0}]
    s._drop_abandoned()  # a failed request has no start time
    assert s._captured == kept[:1]


def _journey_file(tmp_path, steps, fmt="2.0"):
    from liftproof.cli import _journey_dir

    j = Journey("j", "http://source.invalid", steps=steps, format=fmt)
    j.save(_journey_dir(tmp_path) / "j.json")
    return j


@pytest.mark.parametrize(("step", "fmt", "says"), [
    (Step(2, "hover", locator=Locator([{"kind": "text", "value": "Help"}])), "2.0",
     "step 2: unknown action 'hover'"),
    (Step(2, "back", value="0"), "2.0", "step 2: back by '0' entries"),
    (Step(2, "forward", value="two"), "2.0", "step 2: forward by 'two' entries"),
    (Step(2, "goto"), "1.1", "step 2: goto without a url"),
    (Step(2, "reload"), "1.1", "step 2: reload needs journey format 2.0"),
])  # fmt: skip
def test_a_step_this_build_cannot_replay_refuses_to_load(tmp_path, step, fmt, says):
    from liftproof.cli import _load_journey
    from liftproof.store import LocalStore

    _journey_file(tmp_path, [Step(1, "goto", url="/"), step], fmt)
    with pytest.raises(ConfigError, match=f"^journey j, {says}$"):
        _load_journey(LocalStore(tmp_path), tmp_path, "j")


def test_journeys_load_in_both_formats(tmp_path, monkeypatch):
    from liftproof.cli import _load_journey
    from liftproof.store import LocalStore
    from liftproof.web import journey as journey_mod

    old = {"journey_id": "j", "base_url": "http://s", "format": "1.0",
           "steps": [{"n": 1, "action": "goto", "url": "/"}]}  # fmt: skip
    assert Journey.from_dict(old).to_dict()["steps"] == Journey.from_dict(
        Journey.from_dict(old).to_dict()).to_dict()["steps"]  # fmt: skip
    j = _journey_file(tmp_path, [Step(1, "goto", url="/"), Step(2, "back", value="2")])
    assert _load_journey(LocalStore(tmp_path), tmp_path, "j").to_dict() == j.to_dict()
    # a build that reads 1.x only refuses it as it loads, not as it replays
    monkeypatch.setattr(journey_mod, "READ_FORMATS", ("1",))
    with pytest.raises(ConfigError, match="journey j has format 2.0; this build reads"):
        Journey.from_dict(j.to_dict())


def test_doctor_says_what_to_do_with_a_journey_that_does_not_load(tmp_path, monkeypatch, capsys):
    from liftproof import cli

    monkeypatch.setattr(cli, "INSTANCE_CONFIG", tmp_path / "instance.yaml")
    p = tmp_path / "p.yaml"
    web = {"source_url": "http://s.invalid", "target_url": "http://t.invalid"}
    p.write_text(yaml.safe_dump({"project": "t", "web": web}))
    _journey_file(tmp_path / "w" / "t", [Step(1, "goto", url="/"), Step(2, "hover")])
    cli.main(["doctor", "--project", str(p), "--workdir", str(tmp_path / "w"), "--format", "json"])
    checks = {c["check"]: c for c in json.loads(capsys.readouterr().out)["checks"]}
    loads = checks["journey j loads"]
    assert (loads["result"], loads["detail"]) == (
        "fail", "journey j, step 2: unknown action 'hover'")  # fmt: skip
    assert loads["remedy"].startswith("record the journey with liftproof record")
    assert "journey j secrets resolve" not in checks


class _Context:
    """A browser context whose page Back times out."""

    browser = SimpleNamespace(is_connected=lambda: True)

    def new_page(self):
        return _Page()

    def close(self) -> None:
        pass


def test_a_traversal_is_never_retried_on_its_own(monkeypatch):
    """Run again after a timeout, a Back that did go through would move twice."""
    tries = []

    def step(self, page, net, s, sr, j, run, secrets):
        tries.append(s.n)
        if s.action == "back":
            raise RuntimeError("Timeout 3000ms exceeded.")

    monkeypatch.setattr(Replayer, "_step", step)
    browser = SimpleNamespace(new_context=lambda: (_Context(), False), gone=False)
    j = Journey("j", "http://x", steps=[Step(1, "goto", url="/a"), Step(2, "back")])
    run = Replayer("http://t", secret_values=lambda j: {})._journey(browser, j)
    assert tries == [1, 2, 1, 2]  # once in each attempt of the journey
    assert (run.status, run.failure_kind, run.attempts) == ("failed", "transport", 2)
    assert [(f["step"], f["unit"]) for f in run.flakes] == [(2, "journey")]


def test_the_engineer_is_told_when_a_traversal_is_counted_by_the_page():
    s = _watched(index=3)  # the page moved on by itself, then Back took it where it was
    s._events = [{"action": "traverse", "delta": -1, "t": 5}]
    s._take()
    assert s.warnings == [
        "step 2: Back came after the page navigated by itself, so how far it went is the "
        "page's count; record the journey again, waiting for each page, if it does not "
        "replay"]  # fmt: skip
    s = _watched(closed=True)
    s._events = [{"action": "traverse", "delta": None, "t": 5}]
    s._take()
    assert len(s.journey.steps) == 1 and s.warnings == [
        "after step 1: a Back or Forward to another site came as the window closed, so how "
        "far it went is not known and it is no step; record the journey again, waiting for "
        "each page"]  # fmt: skip


class _History:
    """A CDP session on the target: one entry in its history."""

    def send(self, method, params=None):
        return {"currentIndex": 0, "entries": [{"id": 1}]}

    def detach(self) -> None:
        pass


def _navigate(step, base_url, target_url, secrets=None):
    opened = []
    context = SimpleNamespace(new_cdp_session=lambda p: _History())
    page = SimpleNamespace(goto=lambda url, **kw: opened.append(url), url="http://t/orders/55",
                           context=context)  # fmt: skip
    journey = Journey("j", base_url, steps=[step])
    Replayer(target_url, secret_values=lambda j: {})._navigate(
        page, step, journey, JourneyRun("j"), secrets or {}, 1000)
    return opened


@pytest.mark.parametrize(("base_url", "target_url", "url", "opened"), [
    # source and target on one origin (another path, or the same): nothing is refused
    ("http://h:8000/old", "http://h:8000/new", "http://h:8000/x", "http://h:8000/x"),
    ("http://h:8000", "http://h:8000", "http://h:8000/x", "http://h:8000/x"),
    # a path, step 1's included, goes to the target, whatever the source's path
    ("http://src/app", "http://tgt/app", "/app/login", "http://tgt/app/app/login"),
    ("http://src", "http://tgt", "/login", "http://tgt/login"),
    ("http://src", "http://tgt", "https://docs.example.com/a", "https://docs.example.com/a"),
])  # fmt: skip
def test_a_goto_opens_the_target_or_where_it_was_typed(base_url, target_url, url, opened):
    assert _navigate(Step(2, "goto", url=url), base_url, target_url) == [opened]


@pytest.mark.parametrize("url", [
    "http://src.example/x", "http://SRC.example:80/x", "http://bob:pw@src.example/x"])  # fmt: skip
def test_a_goto_to_the_source_is_refused(url):
    with pytest.raises(RuntimeError, match=r"^step 2 opens the source \(http://src.example/app\)"):
        _navigate(Step(2, "goto", url=url), "http://src.example/app", "http://tgt.example")


def test_where_back_led_is_reported_without_secret_values():
    step = Step(2, "back", page_url="/notes/@@REDACTED_1")
    with pytest.raises(WrongPage) as caught:
        _navigate(step, "http://src", "http://t", {"@@REDACTED_1": "s3cret-pass"})
    assert (caught.value.expected, caught.value.actual) == ("/notes/@@REDACTED_1", "/orders/{id}")
    assert "s3cret-pass" not in str(caught.value)
