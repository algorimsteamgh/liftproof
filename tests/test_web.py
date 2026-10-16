"""Record and replay end to end (PRD F1, F3, F4, F5; Technical Spec 5 to 8, 18 and 19).

A journey is recorded against the sample shop, then replayed against a second copy of
the shop: unchanged, and deliberately changed. Ids, CSRF tokens and timestamps differ
between the two on every run, as they would between a source and its migrated target.
"""

import contextlib
import copy
import json
import os
import signal
import sys
import threading
import time
from collections import Counter
from pathlib import Path

import pytest

from liftproof.errors import EXIT_CONFIG, ConfigError
from liftproof.findings import Comparator, Kind, Severity
from liftproof.web.browser import (
    HIDE_JS,
    VOLATILE,
    BodyPolicy,
    launch,
    region_snapshot,
    unhide,
)
from liftproof.web.compare import WebOptions
from liftproof.web.journey import Exchange, IgnoreRegion, Journey, Locator, Step
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
            app.url, policy=BodyPolicy(["/api/*"], snapshots=["/orders/*"]), headless=True
        ).record("checkout", start="/login", story="ORD-14", drive=drive)
    for sha, body in assets.items():
        (assets_dir / sha).write_bytes(body)
    return journey, assets_dir


def replay(journey, assets_dir, variant, *, secrets=None, timeout=10_000, posts=None,
           options=None, **app):  # fmt: skip
    """posts, when given, gets the POSTs that reached the target, by path."""
    findings = []
    with ShopApp(variant, **app) as target:
        result = run_journeys(
            [journey],
            target_url=target.url,
            options=options or WebOptions(),
            emit=findings.append,
            assets_dir=lambda j: assets_dir,
            secret_values=secrets or (lambda j: {t: PASSWORD for t in j.secrets}),
            step_timeout_ms=timeout,
        )
    if posts is not None:
        posts.update(target.posts)
    return result, findings


def with_step(journey, action, **step):
    """The journey with one more step after the order is placed."""
    j = copy.deepcopy(journey)
    j.steps.append(Step(len(j.steps) + 1, action, **step))
    return j


def test_recording_redacts_and_correlates(recorded):
    journey, assets = recorded
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
    # page snapshots too: the order page (step 6) was opted in, the others are structure
    assert all(s.region is None and s.region_sha256 and s.region_shape for s in journey.steps)
    assert [s.n for s in journey.steps if s.region_asset] == [6]
    assert journey.steps[5].region_asset == f"assets/{journey.steps[5].region_sha256}"
    assert "Back to orders" in (assets / journey.steps[5].region_sha256).read_text()
    assert "Back to orders" not in text and 'heading "' not in text  # no snapshot text
    # the node that served a page is marked volatile: left out of what was recorded
    assert journey.ignore_regions == [VOLATILE]
    assert [s.n for s in journey.steps if s.region_hidden] == [4, 6]
    assert journey.steps[5].region_hidden == ["[data-liftproof-volatile]"]
    assert "Served by" not in (assets / journey.steps[5].region_sha256).read_text()
    assert journey.steps[2].region_shape.splitlines() == [  # the password filled in
        "- text: *", '- textbox "*": *', "- text: *", '- textbox "*": *', '- button "*"']
    roundtrip = Journey.from_dict(json.loads(text))
    assert roundtrip.to_dict() == journey.to_dict()


def test_unchanged_target_replays_clean(recorded):
    journey, assets = recorded
    result, findings = replay(journey, assets, "same")
    [j] = result.journeys
    assert j.status == "passed", [f.summary for f in findings]
    assert j.ui_compared == {"text": 1, "shape": 5, "expired": 0}
    assert not [f for f in findings if f.kind in (Kind.DIFFERENCE, Kind.ERROR)]
    assert result.endpoints and all(e["target_ms"] is not None for e in result.endpoints)
    # the node names differ, and are left out on both sides, with the reason given
    [volatile] = [f for f in findings if f.object == "page region"]
    assert (volatile.kind, volatile.column, volatile.detail["reason"]) == (
        Kind.NOTICE, "[data-liftproof-volatile]", VOLATILE.reason)
    assert (volatile.detail["steps_on_source"], volatile.detail["steps_on_target"]) == (2, 2)


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


def test_a_page_not_kept_is_compared_by_structure(recorded, tmp_path):
    """Default deny (spec 5): the changed status on the order page is not reported when
    its snapshot was not kept, nor once the kept one has expired; the API still is."""
    journey, assets = recorded
    j = copy.deepcopy(journey)
    j.steps[5].region_asset = None
    result, findings = replay(j, assets, "changed")
    got = {(f.comparator, f.object, f.summary) for f in findings if f.kind == Kind.DIFFERENCE}
    assert (Comparator.API, "POST /api/orders", "value of $.status differs") in got
    assert not [f for f in findings if f.summary.startswith("page ")]
    assert result.journeys[0].ui_compared == {"text": 0, "shape": 6, "expired": 0}
    result, findings = replay(journey, tmp_path, "changed")  # no asset: the bucket expired it
    assert result.journeys[0].ui_compared == {"text": 0, "shape": 5, "expired": 1}
    [notice] = [f for f in findings if f.kind == Kind.NOTICE and f.object != "page region"]
    assert notice.detail == {"snapshots_expired": 1, "bodies_expired": 2}
    assert not [f for f in findings if f.summary.startswith("page ")]


# ------------------------------------------------ navigations made in the browser itself
def jump(s, by):
    """Back or Forward by several entries at once, as the browser's history menu does."""
    history = s.watch.cdp.send("Page.getNavigationHistory")
    entry = history["entries"][history["currentIndex"] + by]["id"]
    with s.page.expect_navigation():
        s.watch.cdp.send("Page.navigateToHistoryEntry", {"entryId": entry})


def drive_navigations(s):
    drive(s)
    base, oid = s.journey.base_url, s.page.url.rsplit("/", 1)[1]
    s.act(lambda p: p.go_back())
    s.act(lambda p: p.go_forward())
    s.act(lambda p: p.reload())
    s.act(lambda p: p.get_by_role("button", name="Refresh").click())  # the page's own reload
    s.act(lambda p: p.goto(f"{base}/orders"))  # typed
    s.act(lambda p: p.goto(f"{base}/orders/{oid}"))
    s.act(lambda p: p.get_by_role("button", name="Previous page").click())  # history.back()
    s.act(lambda p: jump(s, -2))
    s.act(lambda p: jump(s, 2))
    s.act(lambda p: p.get_by_label("Item").fill("Gadget"))


@pytest.fixture(scope="module")
def recorded_nav(browser_available):
    with ShopApp() as app:
        recorder = Recorder(app.url, policy=BodyPolicy(["/api/*"]), headless=True)
        journey, _ = recorder.record("browsing", start="/login", drive=drive_navigations)
    return journey, recorder.warnings


def test_browser_navigations_are_recorded(recorded_nav, recorded):
    journey, warnings = recorded_nav
    steps = journey.steps[6:]
    assert [(s.action, s.url, s.value) for s in steps] == [
        ("back", None, None), ("forward", None, None), ("reload", None, None),
        ("click", None, None), ("goto", "/orders", None), ("goto", steps[5].url, None),
        ("click", None, None), ("back", None, "2"), ("forward", None, "2"),
        ("fill", None, "Gadget")]  # fmt: skip
    oid = journey.steps[5].page_url.rsplit("/", 1)[1]
    assert steps[5].url == f"/orders/{oid}"
    # each navigation's own requests are its step's, not the step before
    endpoints = [[e.endpoint for e in s.exchanges] for s in steps[:3]]
    assert endpoints == [["GET /orders"], [f"GET /orders/{oid}", f"GET /api/orders/{oid}"],
                         [f"GET /orders/{oid}", f"GET /api/orders/{oid}"]]  # fmt: skip
    [order_id] = [c for c in journey.correlations if c.name == "orders.id"]
    assert "step 12" in order_id.used_in  # the typed address carries the order id
    assert (journey.format, warnings) == ("2.0", [])
    assert recorded[0].format == "1.1"  # a journey without them stays readable by older builds


def test_browser_navigations_replay_clean(recorded_nav):
    journey, _ = recorded_nav
    result, findings = replay(journey, None, "same")
    [r] = result.journeys
    assert r.status == "passed", [f.summary for f in findings]
    assert (r.steps_run, r.attempts, r.flakes) == (16, 1, 0)
    assert not [f for f in findings if f.kind in (Kind.DIFFERENCE, Kind.ERROR)]


def test_a_navigation_that_never_shows_a_page_is_not_a_step(browser_available):
    """A download, an empty answer and an address that does not resolve: none can be
    replayed, and neither can their requests. A link to an anchor and a page's own
    pushState are the click that made them."""

    def go(url):
        def act(p):
            with contextlib.suppress(Exception):  # Download is starting, net::ERR_...
                p.goto(url)

        return act

    def browse(s):
        drive(s)
        s.act(lambda p: p.get_by_role("link", name="Details").click())
        s.act(lambda p: p.get_by_role("button", name="More").click())
        for path in ("/export", "/empty"):
            s.act(go(s.journey.base_url + path))
        s.act(go("http://liftproof-test.invalid/orders"))

    with ShopApp() as app:
        journey, _ = Recorder(app.url, headless=True).record("detours", start="/login",
                                                            drive=browse)  # fmt: skip
    assert [s.action for s in journey.steps[6:]] == ["click", "click"]
    assert journey.steps[-1].page_url.endswith("?tab=more") and journey.format == "1.1"
    requested = Counter(e.url for s in journey.steps for e in s.exchanges)
    assert (requested["/export"], requested["/empty"], requested["/orders"]) == (0, 0, 1)
    result, findings = replay(journey, None, "same")
    assert result.journeys[0].status == "passed", [f.summary for f in findings]


def test_a_window_closed_right_after_a_reload_keeps_the_journey(browser_available):
    def close(s):
        drive(s)
        s.act(lambda p: (p.reload(), p.close()))

    with ShopApp() as app:
        journey, _ = Recorder(app.url, headless=True).record("closed", start="/login",
                                                            drive=close)  # fmt: skip
    assert [s.action for s in journey.steps[5:]] == ["click", "reload"]


def test_back_counts_the_entries_a_frame_added(browser_available):
    """A frame that moves on adds an entry of its own: Back across it is two entries in
    the browser's history and one in the page's, and replay moves as the browser did."""

    def framed(s):
        drive(s)
        s.act(lambda p: p.goto(s.journey.base_url + "/framed"))
        s.act(lambda p: jump(s, -2))

    with ShopApp() as app:
        recorder = Recorder(app.url, policy=BodyPolicy(["/api/*"]), headless=True)
        journey, _ = recorder.record("framed", start="/login", drive=framed)
    back = journey.steps[-1]
    assert (back.action, back.value, back.page_url) == ("back", "2", journey.steps[5].page_url)
    assert recorder.warnings == [
        "step 8: the page moved -1 entries and the window -2; replay moves as the window "
        "did. Check the step, or record the journey again"]  # fmt: skip
    result, findings = replay(journey, None, "same")
    assert result.journeys[0].status == "passed", [f.summary for f in findings]


@pytest.mark.parametrize(("value", "page_url", "expected", "actual"), [
    ("9", "/orders", "/orders", "/orders/{id}"),  # no entry that far back on the target
    (None, "/help", "/help", "/orders"),  # an entry, but another page
])  # fmt: skip
def test_back_that_leads_elsewhere_on_the_target_is_a_difference(
    recorded, value, page_url, expected, actual
):
    journey, assets = recorded
    j = with_step(journey, "back", value=value, page_url=page_url)
    result, findings = replay(j, assets, "same")
    [r] = result.journeys
    assert (r.status, r.attempts, r.flakes, r.differences) == ("different", 1, 0, 1)
    [wrong] = [f for f in findings if f.kind == Kind.DIFFERENCE]
    assert (wrong.severity, wrong.summary, wrong.locator) == (
        Severity.HIGH, "Back or Forward led to a different page on the target", "step 7")
    assert (wrong.expected, wrong.actual) == (expected, actual)


def test_replay_never_opens_the_source(recorded):
    journey, assets = recorded
    j = with_step(journey, "goto", url=journey.base_url + "/orders")
    result, findings = replay(j, assets, "same")
    [r] = result.journeys
    assert (r.status, r.attempts) == ("failed", 1)
    [error] = [f for f in findings if f.kind == Kind.ERROR]
    assert error.locator == "step 7"
    assert error.detail["error"].startswith(f"step 7 opens the source ({journey.base_url})")


# ------------------------------------------------------------- ignore regions (spec 7)
GREETING = IgnoreRegion("personalised for whoever signed in", ".greeting")


@pytest.fixture(scope="module")
def greeted(browser_available, tmp_path_factory):
    """The checkout recorded on a shop whose order page greets the user by a name that
    differs on every visit: with the project's ignore region for it, and without."""
    assets_dir = tmp_path_factory.mktemp("greeted")
    journeys = {}
    with ShopApp(greeting="plain") as app:
        for name, regions in (("with", [GREETING]), ("without", [])):
            journey, assets = Recorder(
                app.url, policy=BodyPolicy(["/api/*"], snapshots=["/orders/*"]),
                headless=True, regions=regions,
            ).record(f"greeted-{name}", start="/login", drive=drive)  # fmt: skip
            journeys[name] = journey
            for sha, body in assets.items():
                (assets_dir / sha).write_bytes(body)
    return journeys, assets_dir


def region_notices(findings):
    return {f.column: f for f in findings if f.object == "page region"}


def test_an_ignore_region_leaves_the_same_part_out_on_both_sides(greeted):
    journeys, assets = greeted
    j = journeys["with"]
    assert j.ignore_regions == [VOLATILE, GREETING]
    assert j.steps[5].region_hidden == [VOLATILE.selector, ".greeting"]
    assert "Welcome back" not in (assets / j.steps[5].region_sha256).read_text()
    options = WebOptions(ignore_regions=[GREETING])
    result, findings = replay(j, assets, "same", greeting="plain", options=options)
    assert result.journeys[0].status == "passed", [f.summary for f in findings]
    notice = region_notices(findings)[".greeting"]
    assert (notice.kind, notice.detail["reason"], notice.detail["journeys"]) == (
        Kind.NOTICE, GREETING.reason, ["greeted-with"])
    assert (notice.detail["steps_on_source"], notice.detail["steps_on_target"]) == (1, 1)
    # once the project drops it, the target still leaves out what the source did
    result, findings = replay(j, assets, "same", greeting="plain")
    assert result.journeys[0].status == "passed", [f.summary for f in findings]
    assert region_notices(findings)[".greeting"].detail["reason"] == (
        f"{GREETING.reason} (as recorded; no longer in web.ignore_regions)")
    # the migrated application marks it instead: a selector for each side
    marked = IgnoreRegion("personalised", source_selector=".greeting",
                          target_selector=VOLATILE.selector)  # fmt: skip
    result, findings = replay(j, assets, "same", greeting="marked",
                              options=WebOptions(ignore_regions=[marked]))  # fmt: skip
    assert result.journeys[0].status == "passed", [f.summary for f in findings]
    assert f"source .greeting, target {VOLATILE.selector}" in region_notices(findings)


def test_a_journey_recorded_without_an_ignore_region_is_compared_in_full(greeted):
    """The source is read only when a journey is recorded, so a rule added since does not
    apply to it: the greeting is compared, and the notice says to record it again."""
    journeys, assets = greeted
    j = journeys["without"]
    assert j.ignore_regions == [VOLATILE] and j.steps[5].region_hidden == [VOLATILE.selector]
    options = WebOptions(ignore_regions=[GREETING])
    result, findings = replay(j, assets, "same", greeting="plain", options=options)
    assert result.journeys[0].status == "different"
    [diff] = [f for f in findings if f.kind == Kind.DIFFERENCE]
    assert (diff.object, diff.summary) == (
        "greeted-without step 6", "page content differs after the step")
    notice = region_notices(findings)[".greeting (not applied)"]
    assert notice.detail["not_applied"] == ["greeted-without"]
    assert notice.summary.endswith("the journey was recorded without it; record it again")
    # nor does a marker only the target carries: the source showed the greeting
    result, findings = replay(j, assets, "same", greeting="marked")
    [diff] = [f for f in findings if f.kind == Kind.DIFFERENCE]
    assert (diff.detail["lines_only_on_source"], diff.detail["lines_only_on_target"]) == (1, 0)


def test_a_part_of_the_page_is_left_out_only_while_it_is_read(browser_available):
    """aria-hidden for one snapshot: a block, a span in a heading's name, a field, inside an
    open shadow root; an element with display: contents keeps its own text. What the page
    had is put back, and a touched region inside an ignore region gives the page."""
    from playwright.sync_api import sync_playwright

    html = """<main><section data-liftproof-region="1"><h1>Order <span class="v">4821</span>
      placed</h1><p class="v">Served by node ab12</p><input class="v" value="typed">
      <p class="v" aria-hidden="false">was shown</p>
      <div class="v" style="display: contents">own text <b>bold</b></div>
      <shadowed-note></shadowed-note><a href="#more">More</a></section></main>
      <script>customElements.define('shadowed-note', class extends HTMLElement {
        constructor() { super(); this.attachShadow({mode: 'open'}).innerHTML =
          '<p class="v">in the shadow</p><p>shadow kept</p>'; } });</script>"""
    marks = """() => [...document.querySelectorAll('[aria-hidden]'),
                      ...document.querySelector('shadowed-note').shadowRoot.children]
                     .map((e) => e.getAttribute('aria-hidden'))"""
    with sync_playwright() as p:
        browser = launch(p)
        page = browser.new_page()
        page.set_content(html)
        before = page.evaluate(marks)
        snap = region_snapshot(page, [".v", ".absent"])
        assert 'heading "Order placed" [level=1]' in snap.text
        assert "text: own text" in snap.text  # display: contents: its own text is read
        left_out = ("4821", "Served by", "typed", "was shown", "bold", "in the shadow")
        assert not [t for t in left_out if t in snap.text], snap.text
        assert "shadow kept" in snap.text and 'link "More"' in snap.text
        assert (snap.hidden, snap.unhideable, snap.whole) == ([".v"], [".v"], None)
        assert page.evaluate(marks) == before == ["false", None, None]
        # a snapshot that did not finish leaves its part hidden until it is put back
        page.locator("main").evaluate_all(HIDE_JS, ["a"])
        assert page.get_by_role("link", name="More").count() == 0
        unhide(page)
        assert page.get_by_role("link", name="More").count() == 1
        # the touched region inside an ignore region: the page, without it
        snap = region_snapshot(page, ["section"])
        assert (snap.text, snap.hidden, snap.whole) == ("- main", ["section"], None)
        # the page inside one: nothing is read
        snap = region_snapshot(page, ["main"])
        assert (snap.text, snap.whole) == ("", "main")
        assert page.evaluate(marks) == before
        browser.close()


def test_an_ignore_region_reaches_across_shadow_roots(browser_available):
    """A touched region in a component's shadow root is inside what marks the component
    volatile, and a region that is itself a shadow host is searched in its shadow root."""
    from playwright.sync_api import sync_playwright

    widget = """<main><h1>Shop</h1><chat-box data-liftproof-volatile></chat-box></main>
      <script>customElements.define('chat-box', class extends HTMLElement {
        constructor() { super(); this.attachShadow({mode: 'open'}).innerHTML =
          '<form data-liftproof-region="1"><p>agent Bob</p><button>Send</button></form>'; }
      });</script>"""
    host = """<main><section id="s" data-liftproof-region="1"></section></main><script>
      document.getElementById('s').attachShadow({mode: 'open'}).innerHTML =
        '<p class="v">Served by node ab12</p><p>kept</p>';</script>"""
    with sync_playwright() as p:
        browser = launch(p)
        page = browser.new_page()
        page.set_content(widget)
        snap = region_snapshot(page, [VOLATILE.selector])
        assert "agent Bob" not in snap.text and 'heading "Shop"' in snap.text, snap.text
        assert (snap.hidden, snap.whole) == ([VOLATILE.selector], None)
        page.set_content(host)
        snap = region_snapshot(page, [".v"])
        assert (snap.text, snap.hidden) == ("- paragraph: kept", [".v"])
        browser.close()


def test_a_step_finds_its_element_after_a_snapshot_left_it_hidden(browser_available, monkeypatch):
    """An element left aria-hidden is not found by its role, so each step puts back what
    the snapshot before it hid, should that snapshot not have."""
    monkeypatch.setattr("liftproof.web.browser.unhide", lambda page: None)
    sign_in = Locator([{"kind": "role", "role": "link", "name": "Sign in"}], "Sign in")
    journey = Journey("help", "http://source", ignore_regions=[VOLATILE],
                      steps=[Step(1, "goto", url="/help"), Step(2, "click", locator=sign_in)])
    runs = []
    with ShopApp() as target:
        Replayer(target.url, secret_values=lambda j: {}, step_timeout_ms=3000).run(
            [journey], lambda i, j, run: runs.append(run))  # fmt: skip
    [run] = runs
    assert (run.status, run.flakes) == ("completed", []), run.error
    assert run.steps[0].region_hidden == [VOLATILE.selector]
    assert target.pages["/login"] == 1


BAD = IgnoreRegion("a typo", "div[")


def test_a_selector_that_is_not_css_is_refused_before_anything_runs(browser_available, tmp_path):
    with ShopApp() as app:
        with pytest.raises(ConfigError, match=r"not a CSS selector: 'div\['"):
            Recorder(app.url, headless=True, regions=[BAD]).record("j", drive=drive)
        with pytest.raises(ConfigError, match=r"not a CSS selector: 'div\['"):
            run_journeys([Journey("j", app.url, steps=[Step(1, "goto", url="/login")])],
                         target_url=app.url, options=WebOptions(ignore_regions=[BAD]),
                         emit=lambda f: None, assets_dir=lambda j: None,
                         secret_values=lambda j: {})  # fmt: skip
    assert not app.pages and not app.posts


def test_a_selector_that_is_not_css_stops_a_validation_before_it_reconciles(
    browser_available, tmp_path, monkeypatch, capsys
):
    """Found by the replay, after a reconciliation that may have run for hours, the error
    would end the run with no report of what it did."""
    import yaml

    from liftproof import cli

    monkeypatch.setattr(cli, "_reconcile_into", lambda *a: pytest.fail("reconciled"))
    web = {"source_url": "http://source.invalid", "target_url": "http://target.invalid",
           "ignore_regions": [{"selector": "div[", "reason": "a typo"}]}
    conn = {"engine": "postgresql", "host": "db.invalid", "database": "app",
            "secret_arn": "arn:aws:secretsmanager:ap-south-1:000000000000:secret:db"}
    project = tmp_path / "shop.yaml"
    project.write_text(yaml.safe_dump({"project": "shop", "source": conn, "target": conn,
                                       "web": web}))  # fmt: skip
    work = ["--workdir", str(tmp_path / "work"), "--format", "json"]
    assert cli.main(["validate", "--project", str(project), *work]) == EXIT_CONFIG
    assert "not a CSS selector: 'div['" in capsys.readouterr().err
    assert not (tmp_path / "work" / "shop" / "runs").exists()
    # doctor says so too, with how to write one
    project.write_text(yaml.safe_dump({"project": "shop", "web": web}))
    cli.main(["doctor", "--project", str(project), *work])
    checks = {c["check"]: c for c in json.loads(capsys.readouterr().out)["checks"]}
    regions = checks["web.ignore_regions are CSS selectors"]
    assert regions["result"] == "fail" and "querySelector" in regions["remedy"]


@pytest.mark.parametrize("resolved", [True, False])
def test_an_unresolved_correlation_is_named_with_what_it_broke(recorded, resolved):
    """Spec 6: a rule that finds nothing on the target is named, and so are the findings
    it explains: the page left with the target's id unmasked, and a later step that went
    to the recorded order, which the target does not have."""
    journey, assets = recorded
    j = copy.deepcopy(journey)
    order = next(c for c in j.correlations if c.name == "orders.id")
    rid = order.recorded_value
    if not resolved:
        order.expression = "$.order_id"
    j.steps.append(Step(7, "goto", url=f"/orders/{rid}", exchanges=[
        Exchange("GET", f"/orders/{rid}", 200), Exchange("GET", f"/api/orders/{rid}", 200)]))
    result, findings = replay(j, assets, "same")
    named = [f for f in findings if "correlation" in f.detail]
    status = [f for f in findings if f.summary == "status code differs"]
    if resolved:
        assert result.journeys[0].status == "passed" and not named and not status
        return
    [u] = named
    assert (u.kind, u.severity, u.column, u.locator) == (
        Kind.NOT_CHECKED, Severity.MEDIUM, "orders.id", "step 6")
    assert (u.detail["cause"], u.detail["source_status"], u.detail["sent_in"]) == (
        "not_in_response", 201, [7])
    [s7] = status
    assert (s7.object, s7.locator, s7.expected, s7.actual) == (
        "GET /api/orders/{orders.id}", "step 7", "200", "404")
    # every difference in the run is traced to it, and it says so
    diffs = [f for f in findings if f.kind == Kind.DIFFERENCE]
    assert all(f.detail.get("unresolved_correlations") == ["orders.id"] for f in diffs), [
        (f.object, f.summary) for f in diffs if "unresolved_correlations" not in f.detail]
    assert ("POST /api/orders", "value of $.id differs") in {(f.object, f.summary) for f in diffs}
    assert u.summary.endswith(f"it explains {len(diffs)} findings in steps 6 and 7")
    assert rid not in json.dumps([f.to_dict() for f in findings])


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
    j.steps[1].locator.candidates = [{"kind": "label", "value": "Login name"}]  # before a write
    posts = Counter()
    result, findings = replay(j, assets, "same", timeout=1500, posts=posts)
    [r] = result.journeys
    assert r.status == "different" and r.attempts == 2  # non idempotent: whole journey
    assert any(f.kind == Kind.FLAKE and f.detail.get("unit") == "journey" for f in findings)
    assert any(
        f.summary == "element the journey uses was not found on the target" for f in findings
    )
    assert posts == Counter()


# Spec 19: a failed assertion never triggers a retry that submits a second transaction.
def test_a_failed_comparison_never_submits_the_order_twice(recorded):
    journey, assets = recorded
    posts = Counter()
    result, findings = replay(journey, assets, "changed", posts=posts)
    [r] = result.journeys
    assert (r.status, r.attempts, r.flakes) == ("different", 1, 0)
    got = {(f.object, f.summary) for f in findings if f.kind == Kind.DIFFERENCE}
    assert ("POST /api/orders", "value of $.status differs") in got
    assert posts["/api/orders"] == 1 and not [f for f in findings if f.kind == Kind.FLAKE]


def test_a_missing_element_after_the_order_never_submits_it_twice(recorded):
    journey, assets = recorded
    confirmed = Locator([{"kind": "text", "value": "Order confirmed"}], "Order confirmed")
    j = with_step(journey, "click", locator=confirmed)
    posts = Counter()
    result, findings = replay(j, assets, "same", timeout=1500, posts=posts)
    [r] = result.journeys
    assert (r.status, r.attempts, r.flakes) == ("different", 1, 0)
    assert posts["/api/orders"] == 1
    [missing] = [f for f in findings if f.summary.startswith("element the journey uses")]
    assert missing.locator == "step 7"
    assert "POST /login (302), POST /api/orders (201)" in missing.detail["not_repeated"]


@pytest.mark.parametrize("missing_step", [False, True])
def test_a_slow_order_is_submitted_once(recorded, missing_step):
    """The order is answered seconds after the step that placed it has timed out. Closing
    the journey's page while it was still being fetched sent it to the target again."""
    journey, assets = recorded
    if missing_step:
        confirmed = Locator([{"kind": "text", "value": "Order confirmed"}], "Order confirmed")
        journey = with_step(journey, "click", locator=confirmed)
    posts = Counter()
    result, findings = replay(journey, assets, "same", timeout=1500, posts=posts,
                              post_delay_ms={"/api/orders": 5000})  # fmt: skip
    [r] = result.journeys
    assert (r.status, r.attempts) == ("different", 1)
    assert posts == Counter({"/login": 1, "/api/orders": 1})
    if missing_step:  # decided once the order was answered
        [missing] = [f for f in findings if f.summary.startswith("element the journey uses")]
        assert "POST /api/orders (201)" in missing.detail["not_repeated"]


@pytest.mark.parametrize(("status", "delay", "attempts"), [
    (None, 0, 2),
    (500, 0, 1),
    (500, 5000, 1),  # answered after the page had navigated away from it
])  # fmt: skip
def test_a_transport_failure_after_the_order_repeats_it_only_when_it_succeeded(
    recorded, status, delay, attempts
):
    """Spec 6: a transport failure is retried, the whole journey being the unit, but never
    after a write the target answered with an error, which may have gone through."""
    journey, assets = recorded
    j = with_step(journey, "goto", url="/dropped")
    posts = Counter()
    result, findings = replay(j, assets, "same", timeout=3000, posts=posts,
                              post_status={"/api/orders": status} if status else None,
                              post_delay_ms={"/api/orders": delay})  # fmt: skip
    [r] = result.journeys
    assert (r.status, r.attempts) == ("failed", attempts)
    assert posts["/api/orders"] == attempts  # one order an attempt, never two in one
    [error] = [f for f in findings if f.kind == Kind.ERROR]
    assert ("not_repeated" in error.detail) == (status is not None)
    if status:
        assert "POST /api/orders (500)" in error.detail["not_repeated"]


def test_a_long_poll_left_open_does_not_hold_up_the_journey(browser_available):
    """Only a write still being fetched is waited for as the journey's page closes: the
    long poll the server holds open held every attempt for the fetch's 30 s timeout."""
    inbox = Journey("inbox", "http://source", steps=[Step(1, "goto", url="/inbox")])
    runs = []
    with ShopApp() as target:
        began = time.monotonic()
        Replayer(target.url, secret_values=lambda j: {}, step_timeout_ms=5000).run(
            [inbox, copy.deepcopy(inbox)], lambda i, j, run: runs.append(run)
        )
        took = time.monotonic() - began
    assert [r.status for r in runs] == ["completed", "completed"]
    assert target.polls >= 2  # each page's was in flight as it closed
    assert took < 20  # the browser starting, and two short journeys


def test_recording_a_slow_order_submits_it_once(browser_available):
    """The order is answered after the recorder stopped waiting for the step to settle.
    Closing the window while it was still being fetched sent it to the source again."""
    with ShopApp(post_delay_ms={"/api/orders": 3000}) as source:
        Recorder(source.url, policy=BodyPolicy(["/api/*"]), headless=True,
                 settle_ms=1500).record("checkout", start="/login", drive=drive)  # fmt: skip
    assert source.posts == Counter({"/login": 1, "/api/orders": 1})


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
    """The Chromium this process started: its main process is the one given the debugging
    pipe, its helpers carry --type."""
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


def kill_browser(pid: int | None = None) -> None:
    """SIGKILL a Chromium this process started, the first found unless one is named, as a
    crash ends it."""
    if pid is None:
        pids = browser_pids()
        assert pids, "no browser process to kill"
        pid = pids[0]
    os.kill(pid, signal.SIGKILL)


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
    assert not [f for f in findings
                if f.kind in (Kind.DIFFERENCE, Kind.NOTICE) and f.object != "page region"]
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
def test_a_browser_that_dies_between_journeys_is_started_again(recorded, monkeypatch, workers):
    """Playwright hears of an exit only during a call, and none runs while a finished
    journey is compared and written: the next journey's context finds it, charged to none."""
    journey, assets = recorded
    journeys = []
    for name in ("first", "second", "third"):
        j = copy.deepcopy(journey)
        j.journey_id = name
        journeys.append(j)
    launched, launching = [], threading.Lock()  # (browser, its main process)

    def launch_one(*a, **kw):
        with launching:  # one at a time, so the main process that appears is this one's
            running = set(browser_pids())
            browser = launch(*a, **kw)
            [pid] = set(browser_pids()) - running
            launched.append((browser, pid))
        return browser

    journey_once = Replayer._journey

    def then_dies(self, browser, j):
        run = journey_once(self, browser, j)
        pid = next(pid for b, pid in launched if b is browser.browser)
        deadline = time.monotonic() + 10
        kill_browser(pid)
        while Path(f"/proc/{pid}").exists() and time.monotonic() < deadline:
            time.sleep(0.01)  # gone, not still dying when the next journey starts
        return run

    monkeypatch.setattr("liftproof.web.replay.launch", launch_one)
    monkeypatch.setattr(Replayer, "_journey", then_dies)
    findings = []
    with ShopApp() as target:
        result = run_journeys(journeys, target_url=target.url, options=WebOptions(),
                              emit=findings.append, assets_dir=lambda j: assets,
                              secret_values=lambda j: {t: PASSWORD for t in j.secrets},
                              workers=workers)  # fmt: skip
    assert result.complete
    assert [(r.status, r.attempts, r.browser_crashes) for r in result.journeys] == [
        ("passed", 1, 0)] * 3, [f.summary for f in findings]
    # each worker's first journey has the browser it launched; every later one restarts it
    notices = [f.journey for f in findings if f.kind == Kind.NOTICE and f.journey]
    assert len(notices) == len(launched) - workers >= 1 and "first" not in notices
    assert not [f for f in findings if f.kind in (Kind.DIFFERENCE, Kind.ERROR, Kind.FLAKE)]


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
            "capture_bodies": ["/api/*"],
            "ignore_regions": [{"selector": ".greeting", "reason": "personalised"}]}}))
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
    assert report["journeys"][0]["ui_compared"] == {"text": 1, "shape": 5, "expired": 0}
    assert report["coverage"]["ui_compared"] == report["journeys"][0]["ui_compared"]
    # each ignore region with its reason: the journey was recorded before .greeting
    assert report["coverage"]["exclusions"] == [
        {"object": "page region", "column": VOLATILE.selector, "reason": VOLATILE.reason},
        {"object": "page region", "column": ".greeting (not applied)", "reason": "personalised"},
    ]
    html = (work / "shop" / "runs" / "r-web" / "report.html").read_text()
    assert PASSWORD not in html and "<td>.greeting (not applied)</td><td>personalised" in html


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
