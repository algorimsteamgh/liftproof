"""A replay without a browser: the replay engine's own loop over journeys and workers,
with each journey's run made up by the test."""

from __future__ import annotations

import contextlib
from collections.abc import Callable

from liftproof.web import replay
from liftproof.web.browser import Captured
from liftproof.web.journey import Exchange, Journey, Step
from liftproof.web.replay import JourneyRun, StepRun


class Browser:
    version = "0-test"

    def close(self) -> None:
        pass


def journey(journey_id: str) -> Journey:
    """One step that loads a page and calls an API."""
    step = Step(1, "goto", url="/orders", region='- heading "Orders"', duration_ms=40.0,
                exchanges=[Exchange("GET", "/api/orders", 200, duration_ms=40.0)])  # fmt: skip
    return Journey(journey_id, "http://source.invalid", story=f"S-{journey_id}", steps=[step])


def replayed(j: Journey, *, body: bytes = b"[]", flakes: list | None = None) -> JourneyRun:
    """Completed, with the page showing something else: one UI difference."""
    got = Captured(Exchange("GET", "/api/orders", 200, duration_ms=60.0), 0.0, body, None, None)
    step = StepRun(1, "goto", status="ok", region='- heading "Orders (new)"', exchanges=[got],
                   duration_ms=60.0, attempts=1)  # fmt: skip
    return JourneyRun(j.journey_id, status="completed", steps=[step], attempts=1,
                      flakes=flakes or [], wall_ms=80.0)  # fmt: skip


def no_browser(monkeypatch, make_run: Callable[[Journey], JourneyRun]) -> None:
    monkeypatch.setattr(replay, "launch", lambda p, **kw: Browser())
    monkeypatch.setattr("playwright.sync_api.sync_playwright", contextlib.nullcontext)
    monkeypatch.setattr(replay.Replayer, "_journey", lambda self, browser, j: make_run(j))
