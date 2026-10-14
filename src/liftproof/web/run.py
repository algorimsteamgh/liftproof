"""One replay run over a set of journeys: replay, compare, and the journey results the
report needs (coverage, traceability, timings). Turns replay failures into findings in
the common shape; nothing here decides the verdict.

Each journey is compared as soon as it has been replayed: its findings are written then
and its captured responses dropped, so a run that stops keeps every journey it finished
and a long run holds one journey's evidence per worker (spec 4 and 17).
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from liftproof import logs
from liftproof.findings import Comparator, Finding, Kind, Severity
from liftproof.web.browser import normalise_path
from liftproof.web.compare import WebOptions, compare_journey
from liftproof.web.journey import Journey
from liftproof.web.replay import JourneyRun, Replayer

REPEATED_FLAKE = 2
# deliberately not the run's own "stopped" reason, which a regenerated report carries
# over from the run's report: a journey is named once, from the journey results
REASON_STOPPED = "the run stopped before this journey was compared"


@dataclass
class JourneyResult:
    journey: str
    story: str | None
    status: str  # passed | different | failed | not_run
    steps: int
    steps_run: int
    attempts: int
    flakes: int
    differences: int
    recorded_ms: float
    replayed_ms: float | None
    reason: str | None = None
    # whole journey wall clock, recording and replay (the replay KPI, docs/kpis.md)
    recorded_wall_ms: float | None = None
    replayed_wall_ms: float | None = None
    browser_crashes: int = 0  # attempts the browser process exited during (spec 18)


@dataclass
class WebResult:
    journeys: list[JourneyResult] = field(default_factory=list)
    endpoints: list[dict[str, Any]] = field(default_factory=list)
    parallel: bool = False
    workers: int = 1  # journeys replayed at once; above 1 only when the project opts in
    target_url: str = ""
    browser: str | None = None
    complete: bool = True  # False while the replay goes on, and when it stopped

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> WebResult:
        return cls(
            journeys=[JourneyResult(**j) for j in d.get("journeys", [])],
            endpoints=list(d.get("endpoints", [])),
            parallel=bool(d.get("parallel", False)),
            workers=int(d.get("workers", 1)),
            target_url=d.get("target_url", ""),
            browser=d.get("browser"),
            complete=bool(d.get("complete", True)),
        )


def _failure_finding(j: Journey, run: JourneyRun) -> Finding:
    obj = j.journey_id
    failed = next((s for s in run.steps if s.status == "failed"), None)
    where = f"step {failed.n}" if failed else None
    match run.failure_kind:
        case "not_found":
            return Finding(
                Comparator.UI,
                Kind.DIFFERENCE,
                Severity.HIGH,
                obj,
                "element the journey uses was not found on the target",
                locator=where,
                journey=obj,
                story=j.story,
                detail={"error": run.error, "attempts": run.attempts},
            )
        case "ambiguous":
            return Finding(
                Comparator.UI,
                Kind.ERROR,
                Severity.HIGH,
                obj,
                "ambiguous locator: more than one element matches",
                locator=where,
                journey=obj,
                story=j.story,
                detail={"error": run.error},
            )
        case "secret":
            return Finding(
                Comparator.UI,
                Kind.ERROR,
                Severity.HIGH,
                obj,
                f"journey not replayed: {run.error}",
                journey=obj,
                story=j.story,
            )
        case "browser_crash":
            return Finding(
                Comparator.UI,
                Kind.ERROR,
                Severity.HIGH,
                obj,
                "the browser process crashed during this journey",
                locator=where,
                journey=obj,
                story=j.story,
                detail={
                    "error": run.error,
                    "attempts": run.attempts,
                    "browser_crashes": run.browser_crashes,
                },
            )
        case _:
            return Finding(
                Comparator.UI,
                Kind.ERROR,
                Severity.HIGH,
                obj,
                "journey could not complete on the target",
                locator=where,
                journey=obj,
                story=j.story,
                detail={"error": run.error, "attempts": run.attempts},
            )


Timing = dict[str, dict[str, list[float]]]  # endpoint -> side -> [total ms, requests]


def _time(timing: Timing, endpoint: str, side: str, ms: float | None) -> None:
    if ms is not None:
        t = timing[endpoint][side]
        t[0] += ms
        t[1] += 1


def _endpoints(timing: Timing) -> list[dict[str, Any]]:
    rows = []
    for endpoint, t in sorted(timing.items()):
        (src_ms, src_n), (tgt_ms, tgt_n) = t["source"], t["target"]
        src = src_ms / src_n if src_n else None
        tgt = tgt_ms / tgt_n if tgt_n else None
        rows.append(
            {
                "endpoint": endpoint,
                "source_ms": round(src, 1) if src is not None else None,
                "target_ms": round(tgt, 1) if tgt is not None else None,
                "change_pct": round(100 * (tgt - src) / src, 1) if src and tgt else None,
            }
        )
    return rows


def _journey_done(
    j: Journey,
    run: JourneyRun,
    options: WebOptions,
    emit: Callable[[Finding], None],
    assets: Path | None,
    timing: Timing,
) -> JourneyResult:
    """Every finding of one replayed journey, and its result."""
    if run.browser_restarted:
        emit(
            Finding(
                Comparator.UI,
                Kind.NOTICE,
                Severity.INFO,
                j.journey_id,
                "the browser had exited before this journey started and was started again",
                journey=j.journey_id,
                story=j.story,
            )
        )
    for f in run.flakes:
        crash = f.get("cause") == "browser_crash"
        emit(
            Finding(
                Comparator.UI,
                Kind.FLAKE,
                Severity.INFO,
                j.journey_id,
                f"retried in a new browser after the browser process crashed ({f['unit']})"
                if crash
                else f"retried after a transport or timing failure ({f['unit']})",
                locator=f"step {f['step']}" if f["step"] else None,
                journey=j.journey_id,
                story=j.story,
                detail=f,
            )
        )
    # a browser crash is the tool's failure, not the step's
    repeated = Counter(f["step"] for f in run.flakes if f["step"] is not None and "cause" not in f)
    for step, n in sorted(repeated.items()):
        if n >= REPEATED_FLAKE:
            # a defect that fails intermittently must not become a statistic (spec 6)
            emit(
                Finding(
                    Comparator.UI,
                    Kind.FLAKE,
                    Severity.MEDIUM,
                    j.journey_id,
                    f"the same step flaked {n} times in this run",
                    locator=f"step {step}",
                    journey=j.journey_id,
                    story=j.story,
                    detail={"flakes": n},
                )
            )
    differences = compare_journey(j, run, options, emit, assets)
    if run.status != "completed":
        emit(_failure_finding(j, run))
        differences += run.failure_kind == "not_found"
    for step, sr in zip(j.steps, run.steps, strict=False):
        for e in step.exchanges:
            _time(timing, f"{e.method} {normalise_path(e.url)}", "source", e.duration_ms)
        for c in sr.exchanges:
            key = f"{c.exchange.method} {normalise_path(c.exchange.url)}"
            _time(timing, key, "target", c.exchange.duration_ms)
    if run.status == "not_run" or (run.status == "failed" and run.failure_kind == "secret"):
        status = "not_run"
    elif run.status != "completed":
        status = "failed" if run.failure_kind != "not_found" else "different"
    else:
        status = "different" if differences else "passed"
    return _result(j, run, status, differences, run.error)


def _result(
    j: Journey, run: JourneyRun, status: str, differences: int, reason: str | None
) -> JourneyResult:
    return JourneyResult(
        journey=j.journey_id,
        story=j.story,
        status=status,
        steps=len(j.steps),
        steps_run=sum(1 for s in run.steps if s.status == "ok"),
        attempts=run.attempts,
        flakes=len(run.flakes),
        differences=differences,
        recorded_ms=round(j.total_ms, 1),
        replayed_ms=round(run.total_ms, 1) if run.steps else None,
        reason=reason,
        recorded_wall_ms=j.wall_ms,
        replayed_wall_ms=run.wall_ms,
        browser_crashes=run.browser_crashes,
    )


def run_journeys(
    journeys: list[Journey],
    *,
    target_url: str,
    options: WebOptions,
    emit: Callable[[Finding], None],
    assets_dir: Callable[[Journey], Path | None],
    secret_values: Callable[[Journey], dict[str, str]],
    step_timeout_ms: int = 15_000,
    executable_path: str | None = None,
    workers: int = 1,
    on_journey: Callable[[Callable[[], WebResult]], None] | None = None,
) -> WebResult:
    """`on_journey` is called after each journey with a function that builds the result
    so far, for a checkpoint to call when one is due. A failure carries that result as
    `partial_result`: the journeys finished, then the others as not run."""
    replayer = Replayer(
        target_url,
        secret_values=secret_values,
        step_timeout_ms=step_timeout_ms,
        executable_path=executable_path,
    )
    workers = max(1, min(workers, len(journeys)))
    done: list[JourneyResult | None] = [None] * len(journeys)
    timing: Timing = defaultdict(lambda: {"source": [0.0, 0], "target": [0.0, 0]})

    def result(complete: bool) -> WebResult:
        return WebResult(
            # every journey asked for, in the journeys' order whichever finished first
            journeys=[r or _not_reached(j) for j, r in zip(journeys, done, strict=True)],
            endpoints=_endpoints(timing),
            parallel=workers > 1,
            workers=workers,
            target_url=target_url,
            browser=f"chromium {replayer.browser_version}" if replayer.browser_version else None,
            complete=complete,
        )

    def finished(i: int, j: Journey, run: JourneyRun) -> None:
        try:
            done[i] = _journey_done(j, run, options, emit, assets_dir(j), timing)
        except Exception as exc:
            # replayed, but its comparison failed: not a journey the run never reached
            reason = f"comparison failed: {type(exc).__name__}: {logs.scrub(str(exc))}"
            done[i] = _result(j, run, "failed", 0, reason[:300])
            raise
        if on_journey is not None:
            on_journey(lambda: result(False))

    try:
        replayer.run(journeys, finished, workers=workers)
    except BaseException as exc:
        exc.partial_result = result(False)  # type: ignore[attr-defined]
        raise
    return result(True)


def _not_reached(j: Journey) -> JourneyResult:
    return JourneyResult(
        journey=j.journey_id,
        story=j.story,
        status="not_run",
        steps=len(j.steps),
        steps_run=0,
        attempts=0,
        flakes=0,
        differences=0,
        recorded_ms=round(j.total_ms, 1),
        replayed_ms=None,
        reason=REASON_STOPPED,
        recorded_wall_ms=j.wall_ms,
    )
