"""Browser plumbing shared by the recorder and the replay engine.

Network capture, header redaction, body policy (default deny, spec 5), endpoint
normalisation and the snapshot of the page region a step touched.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from liftproof.web.journey import Exchange, sha256, shape

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
    """Which response bodies are kept as content. Everything else: hash and shape."""

    capture: list[str] = field(default_factory=list)  # URL path glob patterns

    def keeps(self, path: str) -> bool:
        return any(fnmatch.fnmatch(path, p) for p in self.capture)


def path_of(url: str) -> str:
    parts = urlsplit(url)
    return parts.path + (f"?{parts.query}" if parts.query else "")


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
        k.lower(): ("@@REDACTED" if k.lower() in REDACTED_HEADERS else v)
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


class NetworkLog:
    """Collects requests as they finish.

    API calls (xhr, fetch) are fetched through a route so their bodies are held before
    the page sees them: a page that navigates straight after a call (a form posting to
    an API, then location.href) would otherwise discard the body before it is read.
    """

    def __init__(self, page: Any) -> None:
        self._pending: list[tuple[Any, Any, bytes | None]] = []
        self._fetched: dict[int, tuple[bytes | None, float]] = {}
        page.route("**/*", self._route)
        page.on("requestfinished", self._add)
        page.on("requestfailed", self._add)

    def _route(self, route: Any) -> None:
        req = route.request
        if req.resource_type not in ("xhr", "fetch"):
            route.fallback()
            return
        t0 = time.perf_counter()
        try:
            resp = route.fetch()
        except Exception:  # noqa: BLE001 - let the browser see the same failure
            route.abort("failed")
            return
        body = resp.body()
        self._fetched[id(req)] = (body, round((time.perf_counter() - t0) * 1000, 1))
        route.fulfill(response=resp)

    def _add(self, req: Any) -> None:
        if req.resource_type not in CAPTURED_TYPES:
            return
        resp = body = None
        try:
            resp = req.response()
            if resp is not None and id(req) not in self._fetched:
                body = resp.body()
        except Exception:  # noqa: BLE001, S110 - failed requests and redirects have no body
            pass
        self._pending.append((req, resp, body))

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


def region_snapshot(page: Any) -> str:
    """Accessible tree of the touched region if it survived the step, else the page."""
    for selector in ("[data-liftproof-region]", "main", "body"):
        loc = page.locator(selector)
        try:
            if loc.count() == 1:
                return loc.aria_snapshot(timeout=5000)
        except Exception:  # noqa: S112 - page navigating; fall through to the next
            continue
    return ""


def endpoints(exchanges: Iterable[Exchange], values: dict[str, str] | None = None) -> list[str]:
    return [f"{e.method} {normalise_path(e.url, values)}" for e in exchanges]
