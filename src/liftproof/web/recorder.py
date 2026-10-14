"""The recorder (PRD F1, Technical Spec 5).

The engineer opens the source application through a Chromium window that Liftproof
controls and carries out a real journey. Three layers are captured at once: the
interactions (with several locators per element), the network traffic behind them, and
timings. Sensitive values are swapped for random tokens before anything is written, and
response bodies are kept only for URL patterns the project opted in to.
"""

from __future__ import annotations

import datetime as dt
import json
import secrets
import time
from collections.abc import Callable
from importlib import resources
from typing import Any
from urllib.parse import quote, quote_plus, urljoin

from liftproof.web import correlate
from liftproof.web.browser import (
    WRITE_METHODS,
    BodyPolicy,
    Captured,
    NetworkLog,
    launch,
    normalise_path,
    path_of,
    region_snapshot,
    step_settled,
)
from liftproof.web.journey import TOKEN_PREFIX, Journey, Locator, SecretBinding, Step

CAPTURE_JS = resources.files("liftproof.web").joinpath("capture.js").read_text("utf-8")


class RecordingSession:
    """One journey being recorded. Use act() to drive it from code (tests, the sample
    project) or wait_until_closed() to let an engineer drive the window."""

    def __init__(self, page: Any, journey: Journey, policy: BodyPolicy, settle_ms: int) -> None:
        self.page = page
        self.journey = journey
        self.policy = policy
        self.settle_ms = settle_ms
        self._events: list[dict[str, Any]] = []
        self._times: list[float] = []  # event time of each step, epoch ms
        self._captured: list[Captured] = []
        self._sensitive: dict[str, str] = {}  # token -> real value; memory only
        self._token_for_field: dict[str, str] = {}
        self.net = NetworkLog(page)

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
        self._snapshot()

    def _snapshot(self) -> None:
        step = self.journey.steps[-1]
        step.region = region_snapshot(self.page)
        step.page_url = path_of(self.page.url)

    def _token(self, field: str, value: str) -> str:
        token = self._token_for_field.get(field)
        if token is None:
            # random per journey, never derived from the value (spec 5)
            token = f"{TOKEN_PREFIX}{secrets.token_hex(4)}"
            self._token_for_field[field] = token
            self.journey.secrets[token] = SecretBinding(field=field)
        self._sensitive[token] = value
        return token

    def _take(self) -> None:
        """Turn pending capture events into steps, then snapshot the result."""
        events, self._events[:] = list(self._events), []
        for ev in events:
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
            self.journey.steps.append(
                Step(n=len(self.journey.steps) + 1, action=ev["action"], locator=loc, value=value)
            )
            self._times.append(float(ev["t"]))
        if events:
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
            if self._events:
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

    def finish(self) -> tuple[Journey, dict[str, bytes]]:
        if not self.page.is_closed():
            self._captured += self.net.drain()
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
            s.region = self._scrub(s.region)  # a textbox shows its value in the tree
            s.non_idempotent = any(e.method in WRITE_METHODS for e in s.exchanges)
            if s.duration_ms is not None:
                s.duration_ms = round(max(s.duration_ms, 0.0), 1)
        later = [[s.url or "", s.value or ""] for s in steps]
        self.journey.correlations = correlate.detect(traffic, later)
        self._sensitive.clear()
        return self.journey, assets


class Recorder:
    def __init__(
        self,
        base_url: str,
        *,
        policy: BodyPolicy | None = None,
        headless: bool = False,
        executable_path: str | None = None,
        settle_ms: int = 5000,
    ) -> None:
        self.base_url = base_url.rstrip("/") + "/"
        self.policy = policy or BodyPolicy()
        self.headless = headless
        self.executable_path = executable_path
        self.settle_ms = settle_ms

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

        journey = Journey(journey_id=journey_id, base_url=self.base_url.rstrip("/"), story=story)
        with sync_playwright() as p:
            browser = launch(p, headless=self.headless, executable_path=self.executable_path)
            journey.browser = f"chromium {browser.version}"
            context = browser.new_context()
            page = context.new_page()
            session = RecordingSession(page, journey, self.policy, self.settle_ms)
            context.expose_function("__liftproofRecord", session.on_event)
            context.add_init_script(CAPTURE_JS)
            session.start(urljoin(self.base_url, start.lstrip("/")))
            if drive is not None:
                drive(session)
            else:
                session.wait_until_closed()
            result = session.finish()
            session.net.close()  # a write still being fetched would reach the source twice
            context.close()
            browser.close()
        journey.recorded_at = dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        return result
