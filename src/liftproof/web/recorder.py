"""The recorder (PRD F1, Technical Spec 5).

The engineer opens the source application through a Chromium window that Liftproof
controls and carries out a real journey. Three layers are captured at once: the
interactions (with several locators per element), the network traffic behind them, and
timings. Sensitive values are swapped for random tokens before anything is written, and
response bodies and page snapshots are kept only for URL patterns the project opted in to.
Page snapshots never hold what the ignore regions match (spec 7).
"""

from __future__ import annotations

import datetime as dt
import json
import secrets
import time
from collections.abc import Callable, Sequence
from importlib import resources
from typing import Any
from urllib.parse import quote, quote_plus, urljoin, urlsplit, urlunsplit

from liftproof.web import correlate
from liftproof.web.browser import (
    WRITE_METHODS,
    BodyPolicy,
    Captured,
    NetworkLog,
    check_selectors,
    clear_region,
    in_force,
    launch,
    normalise_path,
    origin_of,
    path_of,
    region_snapshot,
    step_settled,
)
from liftproof.web.journey import (
    BROWSER_NAVIGATIONS,
    NAVIGATION_FORMAT,
    REGION_SHAPE_VERSION,
    TOKEN_PREFIX,
    IgnoreRegion,
    Journey,
    Locator,
    SecretBinding,
    Step,
    region_shape,
    sha256,
)

CAPTURE_JS = resources.files("liftproof.web").joinpath("capture.js").read_text("utf-8")
# CDP's navigationType for a navigation the browser started; a traversal is capture.js's
NAVIGATION_TYPES = {"differentDocument": "goto", "sameDocument": "goto", "reload": "reload",
                    "reloadBypassingCache": "reload"}  # fmt: skip
# the Chromium the navigation signals were verified on (decision 106); an older one set by
# web.chromium_path or LIFTPROOF_CHROMIUM may not send them
NAVIGATION_CHROMIUM = 141


def typed_url(url: str, base_url: str) -> str:
    """An address typed in the recording window, as its step's url: on the source's origin
    its path, query and fragment, which replay puts on the target; elsewhere the whole URL,
    with no user or password."""
    parts = urlsplit(url)
    if origin_of(url) != origin_of(base_url):
        return urlunsplit(parts._replace(netloc=parts.netloc.rpartition("@")[2]))
    return urlunsplit(("", "", parts.path or "/", parts.query, parts.fragment))


def old_chromium(version: str) -> str | None:
    """A warning when the browser predates the navigation signals the recorder relies on."""
    try:
        major = int(version.split(".", 1)[0])
    except ValueError:
        return None
    if major >= NAVIGATION_CHROMIUM:
        return None
    return (
        f"Chromium {version} is older than {NAVIGATION_CHROMIUM}: an address typed in the "
        "window or a Reload may not have been recorded; record with the Chromium Playwright "
        "installs"
    )


class NavigationWatch:
    """The navigations the browser itself makes in the recording window: an address typed
    or a bookmark opened (goto) and Reload. Those the page makes (a link, a form, a script,
    a redirect) follow from a step already recorded and happen again by themselves at
    replay. The page asks for its own first (CDP frameRequestedNavigation), so one started
    without asking is the browser's. It is taken once it commits an http(s) page, so a
    download, an empty answer, an address that does not resolve or one left with Esc is not.
    """

    def __init__(self, cdp: Any, main_frame: str) -> None:
        self.cdp, self.main = cdp, main_frame
        self.navs: list[dict[str, Any]] = []  # committed, not yet taken as steps
        self.abandoned: list[dict[str, Any]] = []  # never committed
        self.asked: set[str] = set()  # where the page asked to go
        self._asked_before: set[str] = set()  # and before the last steps were taken
        self._started: dict[str, Any] | None = None  # the browser's, until it commits

    @classmethod
    def attach(cls, page: Any) -> NavigationWatch:
        cdp = page.context.new_cdp_session(page)
        cdp.send("Page.enable")
        watch = cls(cdp, cdp.send("Page.getFrameTree")["frameTree"]["frame"]["id"])
        cdp.on("Page.frameRequestedNavigation", watch._requested)
        cdp.on("Page.frameStartedNavigating", watch._start)
        cdp.on("Page.frameNavigated", watch._navigated)
        cdp.on("Page.navigatedWithinDocument", watch._within)
        return watch

    def _requested(self, e: dict[str, Any]) -> None:
        if e["frameId"] == self.main and e.get("disposition", "currentTab") == "currentTab":
            self.asked.add(e["url"])

    def _start(self, e: dict[str, Any]) -> None:
        if e["frameId"] != self.main:
            return
        by_page = e["url"] in self.asked or e["url"] in self._asked_before
        self.asked, self._asked_before = set(), set()
        action = NAVIGATION_TYPES.get(e.get("navigationType", ""))
        self.abandon()  # one started before it no longer commits
        if by_page or action is None or urlsplit(e["url"]).scheme not in ("http", "https"):
            return
        self._started = {"action": action, "url": e["url"], "t": time.time() * 1000,
                         "loader": e.get("loaderId"),
                         "same": e.get("navigationType") == "sameDocument"}  # fmt: skip

    def _navigated(self, e: dict[str, Any]) -> None:
        frame = e["frame"]
        if frame["id"] != self.main:
            return
        started = self._started
        if (
            started is not None
            and not started["same"]
            and started["loader"] == frame.get("loaderId")
            and urlsplit(frame["url"]).scheme in ("http", "https")  # not chrome-error://
        ):
            self.navs.append(started)
            self._started = None
        self.abandon()

    def _within(self, e: dict[str, Any]) -> None:
        if e["frameId"] == self.main and self._started is not None and self._started["same"]:
            self.navs.append(self._started)
            self._started = None

    def forget(self) -> None:
        """Steps were taken: a page's request that never started hides nothing for long. It
        is kept one round more, since the navigation it asked for may start just after."""
        self._asked_before, self.asked = self.asked, set()

    def abandon(self) -> None:
        """The navigation started has not committed, and now will not."""
        if self._started is not None:
            self.abandoned.append(self._started)
            self._started = None

    def history_index(self) -> int | None:
        """Where the window is in its history, which counts the entries frames added; None
        once the window has closed, which must not cost the recording."""
        try:
            return self.cdp.send("Page.getNavigationHistory")["currentIndex"]
        except Exception:  # noqa: BLE001 - closed: the caller does without it
            return None


class RecordingSession:
    """One journey being recorded. Use act() to drive it from code (tests, the sample
    project) or wait_until_closed() to let an engineer drive the window."""

    def __init__(
        self,
        page: Any,
        journey: Journey,
        policy: BodyPolicy,
        settle_ms: int,
        hide: Sequence[str] = (),
    ) -> None:
        self.page = page
        self.journey = journey
        self.policy = policy
        self.settle_ms = settle_ms
        self.hide = list(hide)  # the source side of the journey's ignore regions
        self._events: list[dict[str, Any]] = []
        self._times: list[float] = []  # event time of each step, epoch ms
        self._captured: list[Captured] = []
        self._sensitive: dict[str, str] = {}  # token -> real value; memory only
        self._token_for_field: dict[str, str] = {}
        self.net = NetworkLog(page)
        self.watch: NavigationWatch | None = None
        self._history: int | None = None  # the window's history index at the last step
        self._taken = 0  # requests captured before the last steps were taken
        self.warnings: list[str] = []  # for the engineer, as recording ends

    # events arrive from capture.js through the exposed binding --------------------
    def on_event(self, payload: str) -> None:
        self._events.append(json.loads(payload))

    def _settle(self) -> None:
        step_settled(self.page, self.net, self.settle_ms)  # a page never idle still records
        self._captured += self.net.drain()
        self._settled = time.perf_counter()

    def start(self, url: str) -> None:
        t = time.time() * 1000
        self._began = time.perf_counter()
        self.page.goto(url, wait_until="load")
        self._settle()
        self.journey.steps.append(Step(n=1, action="goto", url=path_of(url)))
        self._times.append(t)
        self.watch = NavigationWatch.attach(self.page)  # after the recorder's own goto
        self._snapshot()

    def _snapshot(self) -> None:
        step = self.journey.steps[-1]
        if step.action in ("goto", *BROWSER_NAVIGATIONS):
            clear_region(self.page)  # as replay does
        snap = region_snapshot(self.page, self.hide)
        step.region = None if snap.whole else snap.text
        step.region_hidden, step.region_ignored = snap.hidden, snap.whole
        step.page_url = path_of(self.page.url)
        if self.watch is not None:
            self._history = self.watch.history_index()

    def _token(self, field: str, value: str) -> str:
        token = self._token_for_field.get(field)
        if token is None:
            # random per journey, never derived from the value (spec 5)
            token = f"{TOKEN_PREFIX}{secrets.token_hex(4)}"
            self._token_for_field[field] = token
            self.journey.secrets[token] = SecretBinding(field=field)
        self._sensitive[token] = value
        return token

    def _browser_navigations(self) -> list[dict[str, Any]]:
        """The navigations the browser made since the last steps, as capture events. Each is
        timed no later than its own page's request, so that request is its step's."""
        if self.watch is None:
            return []
        navs, self.watch.navs[:] = list(self.watch.navs), []
        self.watch.forget()
        events = []
        for nav in navs:
            path, t = path_of(nav["url"]), nav["t"]
            own = (
                c.started
                for c in self._captured[self._taken :]
                if c.exchange.resource_type == "document"
                and c.exchange.url == path
                and c.started >= self._times[-1]
            )
            t = min(t, next(own, t))
            url = typed_url(nav["url"], self.journey.base_url) if nav["action"] == "goto" else None
            events.append({"action": nav["action"], "url": url, "t": t})
        return events

    def _traversal(self, ev: dict[str, Any], alone: bool) -> dict[str, Any] | None:
        """Back or Forward in the window, as a step event. How far it went is the move in the
        window's history since the last step, which counts the entries frames added, as
        replay does; the page's own count, which does not, is used when other navigations
        came with it, the page navigated by itself since, or the window has closed, and the
        engineer is told."""
        n = len(self.journey.steps) + 1
        now = self.watch.history_index() if self.watch is not None else None
        moved = now - self._history if now is not None and self._history is not None else None
        counted = ev.get("delta")  # the page's: None when it went to another origin
        if alone and moved and (counted is None or (moved < 0) == (counted < 0)):
            delta = moved
            if counted not in (None, moved):
                self.warnings.append(
                    f"step {n}: the page moved {counted} entries and the window {moved}; "
                    "replay moves as the window did. Check the step, or record the journey again"
                )
        else:
            # the window's move is not known, or holds more than this traversal: the page
            # navigated by itself since the step before (a timer, a redirect), or the window
            # has closed
            delta = counted
            if not alone:
                why = "came with other actions before the page settled"
            elif moved is None:
                why = "came as the window closed"
            else:
                why = "came after the page navigated by itself"
            if delta:
                self.warnings.append(
                    f"step {n}: {'Back' if delta < 0 else 'Forward'} {why}, so how far it went "
                    "is the page's count; record the journey again, waiting for each page, if "
                    "it does not replay"
                )
            elif counted is None:
                self.warnings.append(
                    f"after step {n - 1}: a Back or Forward to another site {why}, so how far "
                    "it went is not known and it is no step; record the journey again, waiting "
                    "for each page"
                )
        if not delta:
            return None  # it went nowhere, or how far is not known
        value = str(abs(delta)) if abs(delta) > 1 else None
        return {"action": "back" if delta < 0 else "forward", "value": value, "t": ev["t"]}

    def _take(self) -> None:
        """Turn pending capture events, and the browser's own navigations, into steps, then
        snapshot the result."""
        events, self._events[:] = list(self._events), []
        events = sorted(events + self._browser_navigations(), key=lambda ev: float(ev["t"]))
        others = [ev for ev in events if ev["action"] not in ("fill", "select", "check", "uncheck")]
        took = False
        for ev in events:
            if ev["action"] == "traverse":
                ev = self._traversal(ev, alone=len(others) == 1)
                if ev is None:
                    continue
            took = True
            loc = Locator(**ev["locator"]) if ev.get("locator") else None
            value = ev.get("value")
            if ev["action"] == "fill" and ev.get("sensitive") and value:
                value = self._token(ev.get("field") or loc.description, value)
            last = self.journey.steps[-1]
            if (
                ev["action"] == "fill"
                and last.action == "fill"
                and last.locator is not None
                and loc is not None
                and last.locator.candidates == loc.candidates
            ):
                last.value = value  # one field, several change events: keep the last
                continue
            n = len(self.journey.steps) + 1
            self.journey.steps.append(
                Step(n=n, action=ev["action"], url=ev.get("url"), locator=loc, value=value)
            )
            self._times.append(float(ev["t"]))
        self._taken = len(self._captured)
        if took:
            self._snapshot()

    def act(self, fn: Callable[[Any], Any]) -> None:
        """Run one engineer action against the page and record what it caused."""
        fn(self.page)
        try:
            self.page.evaluate("0")  # a round trip delivers the capture events sent before it
        except Exception:  # noqa: BLE001, S110 - the action navigated; events still arrive
            pass
        self._settle()
        self._take()

    def wait_until_closed(self, poll_ms: int = 250) -> None:
        """Interactive recording: steps are taken as they happen until the window closes."""
        while not self.page.is_closed():
            try:
                self.page.wait_for_timeout(poll_ms)
            except Exception:  # noqa: BLE001 - the window was closed mid wait
                break
            if self._events or (self.watch is not None and self.watch.navs):
                self._settle()
                self._take()

    # finishing ------------------------------------------------------------------
    def _scrub(self, text: str | None) -> str | None:
        if text is None:
            return None
        for token, value in self._sensitive.items():
            for form in {value, quote(value, safe=""), quote_plus(value)}:
                text = text.replace(form, token)
        return text

    def _drop_abandoned(self) -> None:
        """A navigation the browser started that never became a page (a download, an empty
        answer, an address that does not resolve, Esc) is no step, and its request is no
        step's: replay never makes it. A request that failed has no start time."""
        self.watch.abandon()
        for nav in self.watch.abandoned:
            path, t = path_of(nav["url"]), nav["t"]
            near = sorted(
                (abs((c.started or t) - t), i)
                for i, c in enumerate(self._captured)
                if c.exchange.resource_type == "document" and c.exchange.url == path
            )
            if near and near[0][0] < 1000:
                del self._captured[near[0][1]]
        self.watch.abandoned.clear()

    def finish(self) -> tuple[Journey, dict[str, bytes]]:
        if not self.page.is_closed():
            self._captured += self.net.drain()
        if self.watch is not None:
            self._drop_abandoned()
        if hasattr(self, "_began"):
            self.journey.wall_ms = round((self._settled - self._began) * 1000, 1)
        steps = self.journey.steps
        traffic: list[list[dict[str, Any]]] = [[] for _ in steps]
        assets: dict[str, bytes] = {}
        for c in sorted(self._captured, key=lambda c: c.started):
            idx = max((i for i, t in enumerate(self._times) if t <= c.started + 1), default=0)
            ex = c.exchange
            ex.url = self._scrub(ex.url) or ex.url
            request_body = self._scrub(c.request_body)
            path = ex.url.split("?", 1)[0]
            traffic[idx].append(
                {
                    "endpoint": f"{ex.method} {normalise_path(ex.url)}",
                    "json": c.json,
                    "body": c.body,
                    "headers": ex.response_headers,
                    "content_type": ex.content_type,
                    "request_text": f"{ex.url}\n{request_body or ''}",
                }
            )
            if self.policy.keeps(path):
                ex.request_body = request_body
                if c.body is not None and ex.body_sha256:
                    ex.body_asset = f"assets/{ex.body_sha256}"
                    assets[ex.body_sha256] = c.body
            steps[idx].exchanges.append(ex)
            end = c.started + (ex.duration_ms or 0.0)
            steps[idx].duration_ms = max(steps[idx].duration_ms or 0.0, end - self._times[idx])
        for s in steps:
            # a typed address, and so the page it showed, can hold a redacted value
            s.url, s.page_url = self._scrub(s.url), self._scrub(s.page_url)
            self._reduce_region(s, assets)
            s.non_idempotent = any(e.method in WRITE_METHODS for e in s.exchanges)
            if s.duration_ms is not None:
                s.duration_ms = round(max(s.duration_ms, 0.0), 1)
            self._warn(s)
        if any(s.action in BROWSER_NAVIGATIONS for s in steps):
            self.journey.format = NAVIGATION_FORMAT  # an older build refuses it as it loads
        self.journey.region_shape_version = REGION_SHAPE_VERSION
        later = [[s.url or "", s.value or ""] for s in steps]
        self.journey.correlations = correlate.detect(traffic, later)
        self._sensitive.clear()
        return self.journey, assets

    def _warn(self, step: Step) -> None:
        """What the engineer should know about a navigation the browser made."""
        if step.action in BROWSER_NAVIGATIONS and step.non_idempotent:
            # Playwright's Chromium sends a form again without asking
            writes = sorted({e.endpoint for e in step.exchanges if e.method in WRITE_METHODS})
            self.warnings.append(
                f"step {step.n} ({step.action}) sent {', '.join(writes)} again on the source, "
                "and replay will send it to the target; record the journey again without it "
                "if that was not meant"
            )
        if step.action == "goto" and step.n > 1 and step.url and not step.url.startswith("/"):
            origin = urlunsplit(urlsplit(step.url)[:2] + ("", "", ""))
            self.warnings.append(
                f"step {step.n} opens {origin} from the instance at replay, not the target; "
                "record the journey again without it if it was a detour"
            )

    def _reduce_region(self, step: Step, assets: dict[str, bytes]) -> None:
        """Default deny, as for bodies (spec 5): the snapshot's text is kept, as an asset
        the bucket expires, only for a page the project opted in to; every snapshot is a
        hash and its structure in the journey file."""
        text = self._scrub(step.region)  # a textbox shows its value in the tree
        step.region = None
        if text is None:
            return
        raw = text.encode("utf-8")
        step.region_sha256 = sha256(raw)
        step.region_shape = region_shape(text)
        if self.policy.keeps_snapshot(step.page_url or ""):
            step.region_asset = f"assets/{step.region_sha256}"
            assets[step.region_sha256] = raw


class Recorder:
    def __init__(
        self,
        base_url: str,
        *,
        policy: BodyPolicy | None = None,
        headless: bool = False,
        executable_path: str | None = None,
        settle_ms: int = 5000,
        regions: Sequence[IgnoreRegion] = (),
    ) -> None:
        self.base_url = base_url.rstrip("/") + "/"
        self.policy = policy or BodyPolicy()
        self.headless = headless
        self.executable_path = executable_path
        self.settle_ms = settle_ms
        self.regions = list(regions)  # the project's ignore regions (web.ignore_regions)
        self.warnings: list[str] = []  # the last recording's, for the engineer

    def record(
        self,
        journey_id: str,
        *,
        start: str = "/",
        story: str | None = None,
        drive: Callable[[RecordingSession], None] | None = None,
    ) -> tuple[Journey, dict[str, bytes]]:
        """Record one journey. With drive, code performs the steps through
        session.act(); without it the engineer does, and closing the window ends it."""
        from playwright.sync_api import sync_playwright

        regions = in_force(self.regions)
        journey = Journey(journey_id=journey_id, base_url=self.base_url.rstrip("/"), story=story,
                          ignore_regions=regions)  # fmt: skip
        hide = list(dict.fromkeys(s for r in regions if (s := r.on("source"))))
        with sync_playwright() as p:
            browser = launch(p, headless=self.headless, executable_path=self.executable_path)
            check_selectors(browser, [s for r in self.regions for s in r.selectors])
            journey.browser = f"chromium {browser.version}"
            context = browser.new_context()
            page = context.new_page()
            session = RecordingSession(page, journey, self.policy, self.settle_ms, hide)
            if old := old_chromium(browser.version):
                session.warnings.append(old)
            context.expose_function("__liftproofRecord", session.on_event)
            context.add_init_script(CAPTURE_JS)
            session.start(urljoin(self.base_url, start.lstrip("/")))
            if drive is not None:
                drive(session)
            else:
                session.wait_until_closed()
            result = session.finish()
            self.warnings = session.warnings
            session.net.close()  # a write still being fetched would reach the source twice
            context.close()
            browser.close()
        journey.recorded_at = dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        return result
