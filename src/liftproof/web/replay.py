"""The replay engine (PRD F3, Technical Spec 6).

Replays each journey against the target in recorded order, in a fresh browser context
per journey, and captures the same evidence again. The rules that keep replay honest:

- wait on conditions (the element, the requests the step made when recorded), never on
  fixed sleeps;
- a locator must resolve to exactly one element; a weaker fallback is reported;
- retry only transport and timing failures, never an HTTP status or a comparison;
- a journey containing a state changing step is retried as a whole, never per step;
- every retry is counted as a flake, and a step that flakes repeatedly is reported.
"""

from __future__ import annotations

import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

from liftproof.web import correlate
from liftproof.web.browser import (
    Captured,
    NetworkLog,
    dom_settled,
    endpoints,
    launch,
    mark_region,
    normalise_path,
    path_of,
    region_snapshot,
)
from liftproof.web.journey import Journey, Locator, Step

TRANSPORT_MARKERS = (
    "Timeout",
    "net::ERR_",
    "detached",
    "Target closed",
    "Target page, context or browser has been closed",
    "Navigation failed because page crashed",
    "interrupted by another navigation",
    "ECONNRESET",
)
STEP_ATTEMPTS = 3
JOURNEY_ATTEMPTS = 2


class AmbiguousLocator(Exception):
    pass


class ElementNotFound(Exception):
    pass


def transport_failure(exc: BaseException) -> bool:
    text = f"{type(exc).__name__}: {exc}"
    return any(m in text for m in TRANSPORT_MARKERS)


@dataclass
class StepRun:
    n: int
    action: str
    status: str = "not_run"  # ok | failed | not_run
    used_locator: dict[str, str] | None = None
    degraded_from: dict[str, str] | None = None
    exchanges: list[Captured] = field(default_factory=list)
    region: str | None = None
    page_url: str | None = None
    duration_ms: float | None = None
    error: str | None = None
    attempts: int = 0


@dataclass
class JourneyRun:
    journey_id: str
    status: str = "not_run"  # completed | failed | not_run
    steps: list[StepRun] = field(default_factory=list)
    values: dict[str, str] = field(default_factory=dict)  # recorded value -> replayed value
    attempts: int = 0
    flakes: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    failure_kind: str | None = None  # ambiguous | not_found | transport | secret | crash

    @property
    def total_ms(self) -> float:
        return sum(s.duration_ms or 0.0 for s in self.steps)


def _candidate(page: Any, c: dict[str, str]) -> Any:
    match c["kind"]:
        case "testid":
            return page.get_by_test_id(c["value"])
        case "role":
            return page.get_by_role(c["role"], name=c["name"], exact=True)
        case "label":
            return page.get_by_label(c["value"], exact=True)
        case "text":
            return page.get_by_text(c["value"], exact=True)
        case _:
            return page.locator(c["value"])


def resolve(page: Any, locator: Locator, timeout_ms: int) -> tuple[Any, int]:
    """First candidate that matches; must match exactly one element. Waits (without
    sleeping) until any candidate is attached or the step timeout passes."""
    candidates = [_candidate(page, c) for c in locator.candidates]
    anyone = candidates[0]
    for c in candidates[1:]:
        anyone = anyone.or_(c)
    try:
        anyone.first.wait_for(state="attached", timeout=timeout_ms)
    except Exception as exc:
        if "Timeout" in str(exc):
            raise ElementNotFound(locator.description) from exc
        raise
    for i, c in enumerate(candidates):
        n = c.count()
        if n == 1:
            return c, i
        if n > 1:
            raise AmbiguousLocator(
                f"{locator.candidates[i]} matches {n} elements; refusing to act on the first"
            )
    raise ElementNotFound(locator.description)


class Replayer:
    def __init__(
        self,
        target_url: str,
        *,
        secret_values: Callable[[Journey], dict[str, str]],
        step_timeout_ms: int = 15_000,
        headless: bool = True,
        executable_path: str | None = None,
    ) -> None:
        self.target_url = target_url.rstrip("/") + "/"
        self.secret_values = secret_values
        self.step_timeout_ms = step_timeout_ms
        self.headless = headless
        self.executable_path = executable_path
        self.step_flakes: Counter[tuple[str, int]] = Counter()

    def run(self, journeys: list[Journey]) -> list[JourneyRun]:
        from playwright.sync_api import sync_playwright

        runs = []
        with sync_playwright() as p:
            # one browser process for the run, a fresh context per journey (spec 13)
            browser = launch(p, headless=self.headless, executable_path=self.executable_path)
            self.browser_version = browser.version
            try:
                for j in journeys:
                    runs.append(self._journey(browser, j))
            finally:
                browser.close()
        return runs

    # ------------------------------------------------------------------ journeys
    def _journey(self, browser: Any, journey: Journey) -> JourneyRun:
        run = JourneyRun(journey.journey_id)
        try:
            secrets = self.secret_values(journey)
        except Exception as exc:  # noqa: BLE001 - reported, the run continues
            run.status, run.failure_kind, run.error = "failed", "secret", str(exc)
            return run
        for attempt in range(1, JOURNEY_ATTEMPTS + 1):
            run = JourneyRun(journey.journey_id, attempts=attempt, flakes=run.flakes)
            context = browser.new_context()
            try:
                retry_journey = self._steps(context, journey, run, secrets)
            except Exception as exc:  # noqa: BLE001 - a crashed context is retried once
                retry_journey = transport_failure(exc) or "crash" in str(exc).lower()
                run.status, run.failure_kind, run.error = "failed", "crash", str(exc)
            finally:
                try:
                    context.close()
                except Exception:  # noqa: BLE001, S110 - the browser may already be gone
                    pass
            if not retry_journey or attempt == JOURNEY_ATTEMPTS:
                return run
            failed_step = next((s.n for s in run.steps if s.status == "failed"), None)
            if failed_step is not None:
                self.step_flakes[(journey.journey_id, failed_step)] += 1
            run.flakes.append(
                {"step": failed_step, "attempt": attempt, "error": run.error, "unit": "journey"}
            )
        return run

    def _substitute(self, text: str | None, run: JourneyRun, secrets: dict[str, str]) -> str:
        text = text or ""
        for token, value in secrets.items():
            text = text.replace(token, value)
        for recorded, new in sorted(run.values.items(), key=lambda kv: -len(kv[0])):
            text = text.replace(recorded, new)
        return text

    def _steps(
        self, context: Any, journey: Journey, run: JourneyRun, secrets: dict[str, str]
    ) -> bool:
        """Run every step. Returns True when the whole journey should be retried."""
        page = context.new_page()
        net = NetworkLog(page)
        whole = journey.non_idempotent
        for step in journey.steps:
            sr = StepRun(step.n, step.action)
            run.steps.append(sr)
            for attempt in range(1, STEP_ATTEMPTS + 1):
                sr.attempts = attempt
                try:
                    self._step(page, net, step, sr, journey, run, secrets)
                    sr.status = "ok"
                    break
                except AmbiguousLocator as exc:
                    sr.status, sr.error = "failed", str(exc)
                    run.status, run.failure_kind, run.error = "failed", "ambiguous", str(exc)
                    return False
                except Exception as exc:
                    sr.status, sr.error = "failed", str(exc).splitlines()[0][:300]
                    if not transport_failure(exc) and not isinstance(exc, ElementNotFound):
                        raise
                    kind = "not_found" if isinstance(exc, ElementNotFound) else "transport"
                    if whole or attempt == STEP_ATTEMPTS:
                        # a journey that changes state is never repeated one step at a
                        # time; the journey is the retry unit (spec 6)
                        run.status, run.failure_kind, run.error = "failed", kind, sr.error
                        return whole
                    self.step_flakes[(journey.journey_id, step.n)] += 1
                    run.flakes.append(
                        {"step": step.n, "attempt": attempt, "error": sr.error, "unit": "step"}
                    )
        run.status = "completed"
        return False

    def _step(
        self,
        page: Any,
        net: NetworkLog,
        step: Step,
        sr: StepRun,
        journey: Journey,
        run: JourneyRun,
        secrets: dict[str, str],
    ) -> None:
        net.drain()  # anything left from a failed attempt is not this step's
        t0 = time.perf_counter()
        timeout = self.step_timeout_ms
        if step.action == "goto":
            url = urljoin(self.target_url, self._substitute(step.url, run, secrets).lstrip("/"))
            page.goto(url, wait_until="load", timeout=timeout)
        else:
            target, index = resolve(page, step.locator, timeout)
            sr.used_locator = step.locator.candidates[index]
            if index > 0:
                sr.degraded_from = step.locator.candidates[0]
            mark_region(target)
            value = self._substitute(step.value, run, secrets)
            match step.action:
                case "click":
                    target.click(timeout=timeout)
                case "fill":
                    target.fill(value, timeout=timeout)
                case "select":
                    target.select_option(value, timeout=timeout)
                case "check":
                    target.check(timeout=timeout)
                case "uncheck":
                    target.uncheck(timeout=timeout)
                case "press":
                    target.press(value or "Enter", timeout=timeout)
        sr.exchanges = self._await_requests(page, net, step, run, timeout)
        page.wait_for_load_state("load", timeout=timeout)
        sr.exchanges += net.drain()
        sr.duration_ms = round((time.perf_counter() - t0) * 1000, 1)
        dom_settled(page)
        sr.region = region_snapshot(page)
        for token, value in secrets.items():  # a textbox shows its value in the tree
            sr.region = sr.region.replace(value, token)
        sr.page_url = path_of(page.url)
        self._correlate(journey, sr, run)

    def _await_requests(
        self, page: Any, net: NetworkLog, step: Step, run: JourneyRun, timeout: int
    ) -> list[Captured]:
        """Wait until the requests this step made when recorded have finished here too,
        matched by endpoint. A request that never comes is the API comparator's finding,
        not a replay failure, so running out of time is not an error."""
        expected = Counter(endpoints(step.exchanges))
        if not expected:
            return []
        got: list[Captured] = []
        deadline = time.monotonic() + timeout / 1000
        while True:
            got += net.drain()
            seen = Counter(f"{c.exchange.method} {normalise_path(c.exchange.url)}" for c in got)
            if all(seen[e] >= n for e, n in expected.items()):
                return got
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return got
            try:
                page.wait_for_event("requestfinished", timeout=remaining * 1000)
            except Exception:  # noqa: BLE001 - out of time: compare what arrived
                return got + net.drain()

    def _correlate(self, journey: Journey, sr: StepRun, run: JourneyRun) -> None:
        for c in journey.correlations:
            if not c.confirmed or c.recorded_value in run.values:
                continue
            for cap in sr.exchanges:
                if f"{cap.exchange.method} {normalise_path(cap.exchange.url)}" != c.source:
                    continue
                new = correlate.extract(
                    c.extractor,
                    c.expression,
                    json=cap.json,
                    body=cap.body,
                    headers=cap.exchange.response_headers,
                )
                if new:
                    run.values[c.recorded_value] = new
                    break
