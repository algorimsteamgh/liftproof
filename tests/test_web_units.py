"""Comparison and correlation rules, and the replay's handling of finished journeys,
that need no browser."""

import gc
import json
import threading
import weakref
from types import SimpleNamespace

import pytest

from liftproof import support
from liftproof.findings import Kind, Severity
from liftproof.report.builder import build_report, render_html
from liftproof.web import correlate, replay
from liftproof.web import run as webrun
from liftproof.web.browser import Captured, NetworkLog, Write, normalise_path
from liftproof.web.compare import Comparison, WebOptions, compare_journey
from liftproof.web.journey import Correlation, Exchange, Journey, Step, shape
from liftproof.web.replay import JourneyRun, Replayer, StepRun
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
