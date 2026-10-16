"""One replay run over a set of journeys: replay, compare, and the journey results the
report needs (coverage, traceability, timings). Turns replay failures into findings in
the common shape, and names each ignore region with its reason; nothing here decides the
verdict.

Each journey is compared as soon as it has been replayed: its findings are written then
and its captured responses dropped, so a run that stops keeps every journey it finished
and a long run holds one journey's evidence per worker (spec 4 and 17).
"""

from __future__ import annotations

import contextlib
from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from liftproof import logs
from liftproof.findings import Comparator, Finding, Kind, Severity
from liftproof.web.browser import VOLATILE, in_force, normalise_path
from liftproof.web.compare import Comparison, WebOptions, compare_journey
from liftproof.web.journey import IgnoreRegion, Journey
from liftproof.web.replay import JourneyRun, Replayer

REPEATED_FLAKE = 2
DIFFERENT = ("not_found", "wrong_page")  # failures that are the target's differences
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
    # pages compared as text (snapshot kept), by shape (structure) and by structure once
    # the kept snapshot expired; empty for a journey never compared
    ui_compared: dict[str, int] = field(default_factory=dict)


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
    detail: dict[str, Any] = {"error": run.error, "attempts": run.attempts}
    if run.not_repeated:
        detail["not_repeated"] = run.not_repeated  # it sent a write (spec 6 and 19)
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
                detail=detail,
            )
        case "wrong_page":
            expected, actual = run.wrong_page or (None, None)
            return Finding(
                Comparator.UI,
                Kind.DIFFERENCE,
                Severity.HIGH,
                obj,
                "Back or Forward led to a different page on the target",
                locator=where,
                expected=expected,
                actual=actual,
                journey=obj,
                story=j.story,
                detail=detail,
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
                detail={**detail, "browser_crashes": run.browser_crashes},
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
                detail=detail,
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


@dataclass
class RegionUse:
    """What one ignore region did over the journeys a run compared."""

    applied: int = 0  # journeys compared with it
    journeys: list[str] = field(default_factory=list)  # those it hid content in
    left_out: list[str] = field(default_factory=list)  # those recorded without it
    source: int = 0  # steps it hid content in, on the source
    target: int = 0  # and on the target
    unhideable: int = 0  # steps where an element it matched kept its own text in the tree


def _note_regions(uses: dict[IgnoreRegion, RegionUse], j: Journey, cmp: Comparison) -> None:
    for rule, steps in cmp.hidden_by.items():
        use = uses.setdefault(rule, RegionUse())
        use.applied += 1
        if any(steps.values()):
            use.journeys.append(j.journey_id)
        use.source += len(steps["source"])
        use.target += len(steps["target"])
        use.unhideable += len(steps["unhideable"])
    for rule in cmp.regions_left_out:
        uses.setdefault(rule, RegionUse()).left_out.append(j.journey_id)


def _region_notices(
    uses: dict[IgnoreRegion, RegionUse], options: WebOptions, emit: Callable[[Finding], None]
) -> None:
    """One notice for each ignore region, with its reason, so the report lists it among the
    exclusions (spec 9.12): where it hid content, or, in its column, that it matched
    nothing or was applied to no journey. The built-in one only where it hid content."""
    configured = in_force(options.ignore_regions)
    for rule, use in uses.items():
        hid = use.source + use.target + use.unhideable
        if rule == VOLATILE and not hid:
            continue
        reason = rule.reason
        if rule not in configured:
            reason += " (as recorded; no longer in web.ignore_regions)"
        n = len(use.left_out)
        again = f"record {'them' if n > 1 else 'it'} again"
        if hid:
            column = rule.label
            summary = f"ignore region {rule.label}: what it matched was not compared: {reason}"
        elif use.applied:
            column = f"{rule.label} (matched nothing)"
            summary = f"ignore region {rule.label} matched nothing in this run"
        else:
            column = f"{rule.label} (not applied)"
            which = "the journeys were" if n > 1 else "the journey was"
            summary = (
                f"ignore region {rule.label} not applied: {which} recorded without it; {again}"
            )
        if n and use.applied:
            summary += f"; not applied to {n} journey{'s' * (n > 1)} recorded without it ({again})"
        if use.unhideable:
            summary += (
                f"; in {use.unhideable} step{'s' * (use.unhideable > 1)} an element it matched "
                "kept its own text, which is compared (display: contents)"
            )
        emit(
            Finding(
                Comparator.UI,
                Kind.NOTICE,
                Severity.INFO,
                "page region",
                summary,
                column=column,
                detail={
                    "reason": reason,
                    "source_selector": rule.on("source"),
                    "target_selector": rule.on("target"),
                    "journeys": use.journeys[:50],
                    "steps_on_source": use.source,
                    "steps_on_target": use.target,
                    "steps_unhideable": use.unhideable,
                    "not_applied": use.left_out[:50],
                },
            )
        )


def _journey_done(
    j: Journey,
    run: JourneyRun,
    options: WebOptions,
    emit: Callable[[Finding], None],
    assets: Path | None,
    timing: Timing,
    uses: dict[IgnoreRegion, RegionUse],
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
    comparison = compare_journey(j, run, options, emit, assets)
    _note_regions(uses, j, comparison)
    differences = comparison.differences
    if run.status != "completed":
        failure = _failure_finding(j, run)
        if comparison.stale_at_failure:
            # a correlation left unresolved sent its recorded value before the step failed
            failure.detail["unresolved_correlations"] = comparison.stale_at_failure
        emit(failure)
        differences += run.failure_kind in DIFFERENT
    for step, sr in zip(j.steps, run.steps, strict=False):
        for e in step.exchanges:
            _time(timing, f"{e.method} {normalise_path(e.url)}", "source", e.duration_ms)
        for c in sr.exchanges:
            key = f"{c.exchange.method} {normalise_path(c.exchange.url)}"
            _time(timing, key, "target", c.exchange.duration_ms)
    if run.status == "not_run" or (run.status == "failed" and run.failure_kind == "secret"):
        status = "not_run"
    elif run.status != "completed":
        status = "different" if run.failure_kind in DIFFERENT else "failed"
    else:
        status = "different" if differences else "passed"
    return _result(j, run, status, differences, run.error, comparison.ui_compared)


def _result(
    j: Journey,
    run: JourneyRun,
    status: str,
    differences: int,
    reason: str | None,
    ui_compared: dict[str, int] | None = None,
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
        ui_compared=dict(ui_compared or {}),
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
    `partial_result`: the journeys finished, then the others as not run. The ignore
    regions are reported once the replay ends, over the journeys it compared."""
    replayer = Replayer(
        target_url,
        secret_values=secret_values,
        step_timeout_ms=step_timeout_ms,
        executable_path=executable_path,
        regions=options.ignore_regions,
    )
    workers = max(1, min(workers, len(journeys)))
    done: list[JourneyResult | None] = [None] * len(journeys)
    timing: Timing = defaultdict(lambda: {"source": [0.0, 0], "target": [0.0, 0]})
    uses: dict[IgnoreRegion, RegionUse] = {}

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
            done[i] = _journey_done(j, run, options, emit, assets_dir(j), timing, uses)
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
        with contextlib.suppress(Exception):  # the failure is what the run reports
            _region_notices(uses, options, emit)
        raise
    _region_notices(uses, options, emit)
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
