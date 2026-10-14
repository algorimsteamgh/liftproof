"""The replay engine (PRD F3, Technical Spec 6).

Replays each journey against the target in recorded order, in a fresh browser context
per journey, and captures the same evidence again. The rules that keep replay honest:

- wait on conditions (the element, the requests the step made when recorded), never on
  fixed sleeps;
- a locator must resolve to exactly one element; a weaker fallback is reported;
- retry only transport and timing failures, never an HTTP status or a comparison;
- a journey containing a state changing step is retried as a whole, never per step;
- every retry is counted as a flake, and a step that flakes repeatedly is reported;
- a browser that crashes fails only the journey it was running: that journey is retried
  once in a new browser (spec 18), and the journeys after it run in that browser.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

from liftproof.web import correlate
from liftproof.web.browser import (
    POLL_S,
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

log = logging.getLogger(__name__)

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


class BrowserCrashed(Exception):
    """The browser process exited while a journey was running."""


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
    # ambiguous | not_found | transport | secret | crash | browser_crash
    failure_kind: str | None = None
    wall_ms: float | None = None  # this attempt, first step to last settled step
    browser_crashes: int = 0  # attempts the browser process exited during
    browser_restarted: bool = False  # it had exited before this journey, charged to none

    @property
    def total_ms(self) -> float:
        return sum(s.duration_ms or 0.0 for s in self.steps)


def step_duration(acted_ms: float, exchanges: list[Captured]) -> float | None:
    """From the action to the end of the last request it caused, as the recorder measures
    a step, so a source to target timing compares the applications and not the tool
    (finding the element, filling a field). None for a step that made no request."""
    ends = [c.started + (c.exchange.duration_ms or 0.0) for c in exchanges]
    return round(max(max(ends) - acted_ms, 0.0), 1) if ends else None


OnDone = Callable[[int, Journey, JourneyRun], None]


class _Worker(threading.Thread):
    def __init__(self, replayer: Replayer, todo: queue.SimpleQueue, on_done: OnDone) -> None:
        super().__init__(daemon=True)
        self.replayer, self.todo, self.on_done = replayer, todo, on_done
        self.error: BaseException | None = None

    def run(self) -> None:
        try:
            self.replayer._worker(self.todo, self.on_done)
        except BaseException as exc:  # noqa: BLE001 - raised again on the calling thread
            self.error = exc


class _Browser:
    """One worker's browser process. One that has exited is started again when the next
    context is asked for, so a crash costs only the journey it was running."""

    def __init__(self, playwright: Any, replayer: Replayer) -> None:
        self.playwright, self.replayer = playwright, replayer
        self.crashed = False  # its exit has been charged to the journey it was running
        self.browser = self._launch()

    def _launch(self) -> Any:
        r = self.replayer
        browser = launch(self.playwright, headless=r.headless, executable_path=r.executable_path)
        r.browser_version = browser.version
        return browser

    @property
    def gone(self) -> bool:
        return not self.browser.is_connected()

    def new_context(self) -> tuple[Any, bool]:
        """A context, and whether the browser was started again for it after an exit no
        journey was charged with."""
        if not self.gone:
            try:
                return self.browser.new_context(), False
            except Exception:
                # Playwright hears of an exit only during a call, so one while no journey
                # ran (its run compared and written, the next one's secrets fetched) shows here
                if not self.gone:
                    raise
        restarted = not self.crashed
        try:
            self.browser.close()
        except Exception:  # noqa: BLE001, S110 - it has already exited
            pass
        self.browser, self.crashed = self._launch(), False
        return self.browser.new_context(), restarted

    def close(self) -> None:
        self.browser.close()


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
        self.browser_version: str | None = None
        self._done = threading.Lock()
        self._closed = False  # the caller has stopped listening

    def run(self, journeys: list[Journey], on_done: OnDone, workers: int = 1) -> None:
        """Replay journeys, in order by default, handing each one's run to on_done (with
        its index) as it finishes, one journey at a time; nothing here keeps it after
        that. workers > 1 replays independent journeys at once (spec 6: an opt in, only
        where the journeys do not interfere); steps inside a journey always run in
        recorded order. A worker that fails stops, the others finish the queue, and the
        first failure is then raised."""
        if workers <= 1 or len(journeys) <= 1:
            self._worker(list(enumerate(journeys)), on_done)
            return
        todo: queue.SimpleQueue[tuple[int, Journey]] = queue.SimpleQueue()
        for item in enumerate(journeys):
            todo.put(item)
        # Playwright's sync API is per thread: each worker has its own driver and browser
        threads = [_Worker(self, todo, on_done) for _ in range(min(workers, len(journeys)))]
        for t in threads:
            t.start()
        try:
            for t in threads:
                t.join()
        except BaseException:
            # interrupted while the workers go on: the caller is about to close the run,
            # so a journey finishing from now on must not be written alongside it
            with self._done:
                self._closed = True
            raise
        for t in threads:
            if t.error is not None:
                raise t.error

    def _hand_over(self, on_done: OnDone, i: int, journey: Journey, run: JourneyRun) -> None:
        with self._done:
            if not self._closed:
                on_done(i, journey, run)

    def _worker(
        self,
        todo: list[tuple[int, Journey]] | queue.SimpleQueue[tuple[int, Journey]],
        on_done: OnDone,
    ) -> None:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            # one browser process per worker, a fresh context per journey (spec 13)
            browser = _Browser(p, self)
            try:
                while not self._closed:  # an interrupted run takes no more journeys
                    if isinstance(todo, list):
                        if not todo:
                            break
                        i, j = todo.pop(0)
                    else:
                        try:
                            i, j = todo.get_nowait()
                        except queue.Empty:
                            break
                    # no name holds the run here, so it goes once on_done returns
                    self._hand_over(on_done, i, j, self._journey(browser, j))
            finally:
                browser.close()

    # ------------------------------------------------------------------ journeys
    def _journey(self, browser: _Browser, journey: Journey) -> JourneyRun:
        run = JourneyRun(journey.journey_id)
        try:
            secrets = self.secret_values(journey)
        except Exception as exc:  # noqa: BLE001 - reported, the run continues
            run.status, run.failure_kind, run.error = "failed", "secret", str(exc)
            return run
        for attempt in range(1, JOURNEY_ATTEMPTS + 2):
            run = JourneyRun(journey.journey_id, attempts=attempt, flakes=run.flakes,
                             browser_crashes=run.browser_crashes,
                             browser_restarted=run.browser_restarted)  # fmt: skip
            context, restarted = browser.new_context()
            if restarted:
                # it exited while no journey was running: not this journey's failure
                log.warning("the browser had exited before journey %s; it was started again",
                            journey.journey_id)  # fmt: skip
                run.browser_restarted = True
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
            crashed = run.status != "completed" and browser.gone
            if crashed:
                # the browser process exited during this attempt: charged to this journey,
                # which is retried once in a new browser (spec 18)
                log.warning("journey %s attempt %d: the browser crashed", journey.journey_id,
                            attempt)  # fmt: skip
                browser.crashed, retry_journey = True, True
                first = (run.error or "").splitlines()[:1]
                run.failure_kind, run.browser_crashes = "browser_crash", run.browser_crashes + 1
                run.error = "the browser process crashed" + (f": {first[0][:300]}" if first else "")
            # the first crash keeps its retry when an ordinary failure used the other attempt
            last = JOURNEY_ATTEMPTS + (crashed and run.browser_crashes == 1)
            if not retry_journey or attempt >= last:
                return run
            failed_step = next((s.n for s in run.steps if s.status == "failed"), None)
            flake = {"step": failed_step, "attempt": attempt, "error": run.error, "unit": "journey"}
            if run.failure_kind == "browser_crash":
                flake["cause"] = "browser_crash"
            run.flakes.append(flake)
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
        began = time.perf_counter()
        for step in journey.steps:
            sr = StepRun(step.n, step.action)
            run.steps.append(sr)
            for attempt in range(1, STEP_ATTEMPTS + 1):
                sr.attempts = attempt
                try:
                    self._step(page, net, step, sr, journey, run, secrets)
                    if page.is_closed():
                        # the step's waits and its snapshot do not fail on a closed page
                        raise RuntimeError("the page crashed or was closed during the step")
                    sr.status = "ok"
                    break
                except AmbiguousLocator as exc:
                    sr.status, sr.error = "failed", str(exc)
                    run.status, run.failure_kind, run.error = "failed", "ambiguous", str(exc)
                    return False
                except Exception as exc:
                    sr.status, sr.error = "failed", str(exc).splitlines()[0][:300]
                    if not context.browser.is_connected():
                        raise BrowserCrashed(sr.error) from exc  # no step retries in it
                    if not transport_failure(exc) and not isinstance(exc, ElementNotFound):
                        raise
                    kind = "not_found" if isinstance(exc, ElementNotFound) else "transport"
                    if whole or attempt == STEP_ATTEMPTS:
                        # a journey that changes state is never repeated one step at a
                        # time; the journey is the retry unit (spec 6)
                        run.status, run.failure_kind, run.error = "failed", kind, sr.error
                        return whole
                    run.flakes.append(
                        {"step": step.n, "attempt": attempt, "error": sr.error, "unit": "step"}
                    )
        run.status = "completed"
        run.wall_ms = round((time.perf_counter() - began) * 1000, 1)
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
        timeout = self.step_timeout_ms
        if step.action == "goto":
            # the recorded path, before tokens and correlated values are put in
            log.debug("journey %s step %s: goto %s", journey.journey_id, step.n, step.url)
            url = urljoin(self.target_url, self._substitute(step.url, run, secrets).lstrip("/"))
            acted = time.time() * 1000
            page.goto(url, wait_until="load", timeout=timeout)
        else:
            target, index = resolve(page, step.locator, timeout)
            sr.used_locator = step.locator.candidates[index]
            log.debug("journey %s step %s: %s on %s (candidate %d of %d)", journey.journey_id,
                      step.n, step.action, sr.used_locator, index + 1,
                      len(step.locator.candidates))  # fmt: skip
            if index > 0:
                sr.degraded_from = step.locator.candidates[0]
            mark_region(target)
            value = self._substitute(step.value, run, secrets)
            acted = time.time() * 1000  # the element is found: the action happens now
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
        sr.duration_ms = step_duration(acted, sr.exchanges)
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
            if remaining <= 0 or page.is_closed():
                return got
            # Short slices, then look again: a request that finished before this wait
            # began (a navigation's own document, typically) is delivered to the log
            # while waiting but never satisfies the waiter, which used to sit out the
            # whole step timeout.
            try:
                page.wait_for_event("requestfinished", timeout=min(remaining, POLL_S) * 1000)
            except Exception:  # noqa: BLE001, S110 - a slice ended: drain and check again
                pass

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
                new = correlate.apply(c.transforms, new)
                if new:
                    for recorded_form, encoding in correlate.forms(c, c.recorded_value).items():
                        if encoding != "source":  # what the server sent is not reused
                            run.values[recorded_form] = (
                                correlate.encode(encoding, new) if encoding else new
                            )
                    break
