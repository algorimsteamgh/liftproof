"""Browser plumbing shared by the recorder and the replay engine.

Network capture, header redaction, what is kept as content (default deny, spec 5),
endpoint normalisation, the snapshot of the page region a step touched and the ignore
regions left out of it (spec 7).
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from liftproof.errors import ConfigError
from liftproof.web.journey import Exchange, IgnoreRegion, sha256, shape

CAPTURED_TYPES = {"document", "xhr", "fetch"}
REDACTED_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
}
REDACTED = "@@REDACTED"  # what a redacted header reads, at recording and at replay
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

ID_SEGMENT = re.compile(
    r"^(\d{2,}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{16,})$", re.I
)


def chromium_path(configured: str | None = None) -> str | None:
    """An explicit Chromium binary; None lets Playwright use its own bundled build."""
    return configured or os.environ.get("LIFTPROOF_CHROMIUM") or None


def launch(playwright: Any, *, headless: bool = True, executable_path: str | None = None):
    return playwright.chromium.launch(
        headless=headless, executable_path=chromium_path(executable_path)
    )


@dataclass
class BodyPolicy:
    """Which response bodies, and which pages' snapshots, are kept as content (spec 5).
    Everything else: hash and shape. Both are URL path glob patterns."""

    capture: list[str] = field(default_factory=list)
    snapshots: list[str] = field(default_factory=list)  # matched on the page a step ended on

    def keeps(self, path: str) -> bool:
        return any(fnmatch.fnmatch(path, p) for p in self.capture)

    def keeps_snapshot(self, url: str) -> bool:
        return any(fnmatch.fnmatch(url.split("?", 1)[0], p) for p in self.snapshots)


def path_of(url: str) -> str:
    parts = urlsplit(url)
    return parts.path + (f"?{parts.query}" if parts.query else "")


def origin_of(url: str) -> tuple[str, str, int | None]:
    """Scheme, host and port as the browser compares them: no user or password, the host
    in lower case, the default port written out."""
    parts = urlsplit(url)
    try:
        port = parts.port
    except ValueError:
        port = None
    return parts.scheme, parts.hostname or "", port or {"http": 80, "https": 443}.get(parts.scheme)


def normalise_path(path: str, values: dict[str, str] | None = None) -> str:
    """Endpoint identity across environments: generated ids become {id}, and values a
    correlation names become {name}. The query string is not part of the identity."""
    path = path.split("?", 1)[0]
    for value, name in sorted((values or {}).items(), key=lambda kv: -len(kv[0])):
        if value:
            path = path.replace(value, "{" + name + "}")
    return "/".join("{id}" if ID_SEGMENT.match(s) else s for s in path.split("/"))


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        k.lower(): (REDACTED if k.lower() in REDACTED_HEADERS else v)
        for k, v in sorted(headers.items())
    }


def decode_json(body: bytes | None, content_type: str) -> Any:
    if body is None or "json" not in content_type:
        return None
    try:
        return json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return None


@dataclass
class Captured:
    """One finished request, with everything held in memory until it is reduced."""

    exchange: Exchange
    started: float  # epoch ms
    body: bytes | None
    json: Any
    request_body: str | None


@dataclass
class Write:
    """A state changing request the page sent, and the status it was answered with: None
    while it is in flight, and for one that failed."""

    endpoint: str
    status: int | None = None


class NetworkLog:
    """Collects requests as they finish.

    API calls (xhr, fetch) are fetched through a route so their bodies are held before
    the page sees them: a page that navigates straight after a call (a form posting to
    an API, then location.href) would otherwise discard the body before it is read.
    """

    def __init__(self, page: Any) -> None:
        self.page = page
        self._pending: list[tuple[Any, Any, bytes | None]] = []
        self._fetched: dict[int, tuple[bytes | None, float]] = {}
        self._open: set[int] = set()
        self._writes: dict[int, Write] = {}
        self._writing: set[int] = set()  # writes being fetched through the route
        self.started = 0  # requests begun so far: a change means the page did more
        self.writes: list[Write] = []  # every one sent, in order; drain() leaves them
        page.route("**/*", self._route)
        page.on("request", self._begin)
        page.on("requestfinished", self._add)
        page.on("requestfailed", self._add)

    @property
    def inflight(self) -> int:
        return len(self._open)

    def _begin(self, req: Any) -> None:
        if req.resource_type in CAPTURED_TYPES:
            self._open.add(id(req))
            self.started += 1
            if req.method in WRITE_METHODS:
                # counted as it is sent: one still unanswered may yet go through
                write = Write(f"{req.method} {normalise_path(path_of(req.url))}")
                self._writes[id(req)] = write
                self.writes.append(write)

    def _route(self, route: Any) -> None:
        req = route.request
        if req.resource_type not in ("xhr", "fetch"):
            route.fallback()
            return
        write = self._writes.get(id(req))
        if write is not None:
            self._writing.add(id(req))
        try:
            self._fetch(route, write)
        finally:
            self._writing.discard(id(req))

    def _fetch(self, route: Any, write: Write | None) -> None:
        t0 = time.perf_counter()
        try:
            resp = route.fetch()
        except Exception:  # noqa: BLE001 - let the browser see the same failure
            route.abort("failed")
            return
        if write is not None:
            # the answer is known here even when the page has given up on the request (it
            # navigated away), and failed it without one
            write.status = resp.status
        body = resp.body()
        self._fetched[id(route.request)] = (body, round((time.perf_counter() - t0) * 1000, 1))
        route.fulfill(response=resp)

    def _add(self, req: Any) -> None:
        if req.resource_type not in CAPTURED_TYPES:
            return
        self._open.discard(id(req))
        resp = body = None
        try:
            resp = req.response()
            if resp is not None and id(req) not in self._fetched:
                body = resp.body()
        except Exception:  # noqa: BLE001, S110 - failed requests and redirects have no body
            pass
        write = self._writes.pop(id(req), None)
        if write is not None and resp is not None:
            write.status = resp.status
        self._pending.append((req, resp, body))

    def close(self) -> None:
        """Let the writes being fetched through the route finish: closing the page, or its
        context, while one is in flight sends it to the server a second time. Reads are
        waited for only alongside a write, since a page may hold a long poll open until the
        fetch times out (30 s): a read in flight is sent again, which repeats no write."""
        try:
            self.page.unroute_all(behavior="wait" if self._writing else "ignoreErrors")
        except Exception:  # noqa: BLE001, S110 - the page or its browser has gone
            pass

    def drain(self) -> list[Captured]:
        pending, self._pending[:] = list(self._pending), []
        out = []
        for req, resp, body in pending:
            timing = req.timing or {}
            start = float(timing.get("startTime") or 0.0)
            end = timing.get("responseEnd")
            if id(req) in self._fetched:
                body, end = self._fetched.pop(id(req))
            ctype = (resp.headers.get("content-type", "") if resp else "").split(";")[0]
            ex = Exchange(
                method=req.method,
                url=path_of(req.url),
                status=resp.status if resp else 0,
                request_headers=redact_headers(req.headers),
                response_headers=redact_headers(resp.headers) if resp else {},
                content_type=ctype,
                duration_ms=round(float(end), 1) if end and end > 0 else None,
                resource_type=req.resource_type,
            )
            parsed = decode_json(body, ctype)
            ex.body_sha256 = sha256(body) if body is not None else None
            ex.body_shape = shape(parsed) if parsed is not None else None
            out.append(Captured(ex, start, body, parsed, req.post_data))
        out.sort(key=lambda c: c.started)
        return out


REGION_JS = """
(el) => {
  const r = el.closest('form, dialog, [role=dialog], [role=form], table, section, article, main');
  document.querySelectorAll('[data-liftproof-region]').forEach(
    (n) => n.removeAttribute('data-liftproof-region'));
  if (r) r.setAttribute('data-liftproof-region', '1');
  return !!r;
}
"""


def mark_region(locator: Any) -> None:
    """Tag the region the step is about to touch, so it can be read after the step."""
    try:
        locator.evaluate(REGION_JS)
    except Exception:  # noqa: S110 - the region is a best effort aid to comparison
        pass


def clear_region(page: Any) -> None:
    """Forget the region an earlier step touched: after a navigation the page is what is
    compared, also where a single page application kept the element."""
    try:
        page.evaluate(
            "() => document.querySelectorAll('[data-liftproof-region]').forEach("
            "(n) => n.removeAttribute('data-liftproof-region'))"
        )
    except Exception:  # noqa: BLE001, S110 - the page navigated: the marker went with it
        pass


QUIET_JS = """
(quietMs) => new Promise((resolve) => {
  let timer = setTimeout(done, quietMs);
  const obs = new MutationObserver(() => {
    clearTimeout(timer);
    timer = setTimeout(done, quietMs);
  });
  function done() { obs.disconnect(); resolve(true); }
  obs.observe(document, { subtree: true, childList: true, characterData: true, attributes: true });
})
"""


def dom_settled(page: Any, quiet_ms: int = 150, timeout_ms: int = 5000) -> None:
    """Wait for the page's own scripts to finish rendering what the step's responses
    returned: the condition is no DOM change for quiet_ms, bounded by timeout_ms."""
    try:
        page.wait_for_function(f"({QUIET_JS})({quiet_ms})", timeout=timeout_ms)
    except Exception:  # noqa: BLE001, S110 - a page that never settles is compared as it is
        pass


POLL_S = 0.1  # longest wait before the request log is checked again


def step_settled(page: Any, net: NetworkLog, timeout_ms: int, quiet_ms: int = 150) -> None:
    """While recording, wait until what an action started has finished: no captured
    request in flight, the page loaded, and no DOM change for quiet_ms, with no new
    request or navigation during that quiet period. An action that posts to an API and
    then navigates to a page which fetches its own data settles only once that data is
    rendered. Waiting for "networkidle" instead returned at once whenever the page had
    been idle before the action, so the step was snapshotted half rendered."""
    deadline = time.monotonic() + timeout_ms / 1000
    while (remaining := deadline - time.monotonic()) > 0:
        if net.inflight:
            try:
                page.wait_for_event("requestfinished", timeout=min(remaining, POLL_S) * 1000)
            except Exception:  # noqa: BLE001, S110 - a slice ended: look again
                pass
            continue
        try:
            page.wait_for_load_state("load", timeout=remaining * 1000)
        except Exception:  # noqa: BLE001, S110 - out of time: snapshot what is there
            return
        url, started = page.url, net.started
        dom_settled(page, quiet_ms, timeout_ms=max(int(remaining * 1000), 1))
        if not net.inflight and net.started == started and page.url == url:
            return


VOLATILE = IgnoreRegion(
    "marked volatile in the application (data-liftproof-volatile)", "[data-liftproof-volatile]"
)


def in_force(rules: Iterable[IgnoreRegion]) -> list[IgnoreRegion]:
    """The built-in ignore region, then the project's. A project rule with the same
    selectors takes the built-in one's place, with its own reason."""
    rules = list(rules)
    if any(r.on("source") == r.on("target") == VOLATILE.selector for r in rules):
        return rules
    return [VOLATILE, *rules]


def applied_regions(
    recorded: Iterable[IgnoreRegion], rules: Iterable[IgnoreRegion]
) -> tuple[list[IgnoreRegion], list[IgnoreRegion]]:
    """The ignore regions a replay of a journey applies, and those it leaves out. The
    source page is read only when the journey is recorded, so a rule with a source side
    applies only to a journey recorded with it (the rule now in force with that source
    selector, else, once the project has dropped it, the rule as recorded, so the target
    still hides what the source did). A rule for the target alone always applies."""
    at_source = {s: r for r in recorded if (s := r.on("source"))}
    applied: list[IgnoreRegion] = []
    left_out: list[IgnoreRegion] = []
    for r in rules:
        source = r.on("source")
        (applied if source is None or source in at_source else left_out).append(r)
    named = {r.on("source") for r in applied}
    return applied + [r for s, r in at_source.items() if s not in named], left_out


# An ignore region's elements are left out of the accessible tree with aria-hidden, set
# only while the snapshot is read. The page holds them and the aria-hidden each had, so
# they are put back wherever they are (in an open shadow root too), also by the next
# snapshot or step when a page did not let this one finish.
UNHIDE_JS = """
() => {
  for (const [el, was] of window.__liftproofHidden || []) {
    if (was === null) el.removeAttribute('aria-hidden');
    else el.setAttribute('aria-hidden', was);
  }
  window.__liftproofHidden = [];
}
"""

HIDE_JS = """
(roots, selectors) => {
  (UNHIDE)();
  if (roots.length !== 1) return null;
  const root = roots[0];
  // a root in an open shadow root is also inside its host and the host's ancestors
  const inside = (s) => {
    for (let n = root; n; n = n.getRootNode().host) if (n.closest(s)) return true;
    return false;
  };
  const whole = selectors.find(inside);
  if (whole) return {hidden: [], unhideable: [], whole};
  // the tree reads into open shadow roots, the root's own too, so they are searched
  const scopes = root.shadowRoot ? [root, root.shadowRoot] : [root];
  for (let i = 0; i < scopes.length; i++) {
    for (const el of scopes[i].querySelectorAll('*')) {
      if (el.shadowRoot) scopes.push(el.shadowRoot);
    }
  }
  const hidden = new Set(), unhideable = new Set(), done = new Set();
  for (const s of selectors) {
    for (const scope of scopes) {
      for (const el of scope.querySelectorAll(s)) {
        // display: contents renders no box: aria-hidden hides its elements, not its own text
        const own = getComputedStyle(el).display === 'contents' &&
          [...el.childNodes].some((n) => n.nodeType === 3 && n.data.trim());
        (own ? unhideable : hidden).add(s);
        if (done.has(el)) continue;
        done.add(el);
        window.__liftproofHidden.push([el, el.getAttribute('aria-hidden')]);
        el.setAttribute('aria-hidden', 'true');
      }
    }
  }
  return {hidden: [...hidden], unhideable: [...unhideable], whole: null};
}
""".replace("UNHIDE", UNHIDE_JS.strip())


@dataclass
class RegionSnapshot:
    """The accessible tree of a region, and what the ignore regions left out of it."""

    text: str
    hidden: list[str] = field(default_factory=list)  # selectors that hid an element
    # selectors matching an element with display: contents whose own text is still read
    unhideable: list[str] = field(default_factory=list)
    whole: str | None = None  # the selector the page itself is inside: nothing was read


def unhide(page: Any) -> None:
    """Put back what an ignore region hid."""
    try:
        page.evaluate(UNHIDE_JS)
    except Exception:  # noqa: BLE001, S110 - the page navigated: what was hidden went with it
        pass


def region_snapshot(page: Any, hide: Sequence[str] = ()) -> RegionSnapshot:
    """Accessible tree of the touched region if it survived the step and is not inside an
    ignore region, else the page, without the elements the hide selectors match."""
    for selector in ("[data-liftproof-region]", "main", "body"):
        loc = page.locator(selector)
        try:
            if hide:
                # None unless exactly one element: finding it and hiding are one round trip
                got = loc.evaluate_all(HIDE_JS, list(hide))
            else:
                got = {} if loc.count() == 1 else None
            if got is None:
                continue
            if got.get("whole"):
                if selector == "[data-liftproof-region]":
                    continue  # what the step touched is ignored, the rest of the page is not
                return RegionSnapshot("", whole=got["whole"])
            try:
                text = loc.aria_snapshot(timeout=5000)
            finally:
                if got.get("hidden") or got.get("unhideable"):
                    unhide(page)
            return RegionSnapshot(text, got.get("hidden", []), got.get("unhideable", []))
        except Exception:  # noqa: S112 - page navigating; fall through to the next
            continue
    return RegionSnapshot("")


SELECTOR_JS = """
(selectors) => selectors.filter((s) => {
  try { document.createDocumentFragment().querySelector(s); return false; }
  catch (e) { return true; }
})
"""


def check_selectors(browser: Any, selectors: Iterable[str]) -> None:
    """Refuse an ignore region the browser does not take as a CSS selector (Playwright's
    own text= and >> are not CSS), before anything is recorded or replayed."""
    wanted = list(dict.fromkeys(selectors))
    if not wanted:
        return
    page = browser.new_page()
    try:
        bad = page.evaluate(SELECTOR_JS, wanted)
    finally:
        page.close()
    if bad:
        raise ConfigError("web.ignore_regions: not a CSS selector: " + ", ".join(map(repr, bad)))


def check_regions(rules: Iterable[IgnoreRegion], executable_path: str | None = None) -> None:
    """check_selectors in a browser of its own, for a run that does other work first."""
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = launch(p, executable_path=executable_path)
        try:
            check_selectors(browser, [s for r in rules for s in r.selectors])
        finally:
            browser.close()


def endpoints(exchanges: Iterable[Exchange], values: dict[str, str] | None = None) -> list[str]:
    return [f"{e.method} {normalise_path(e.url, values)}" for e in exchanges]
