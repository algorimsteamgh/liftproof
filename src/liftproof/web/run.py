"""One replay run over a set of journeys: replay, compare, and the journey results the
report needs (coverage, traceability, timings). Turns replay failures into findings in
the common shape; nothing here decides the verdict.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from liftproof.findings import Comparator, Finding, Kind, Severity
from liftproof.web.browser import normalise_path
from liftproof.web.compare import WebOptions, compare_journey
from liftproof.web.journey import Journey
from liftproof.web.replay import JourneyRun, Replayer

REPEATED_FLAKE = 2


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


@dataclass
class WebResult:
    journeys: list[JourneyResult] = field(default_factory=list)
    endpoints: list[dict[str, Any]] = field(default_factory=list)
    parallel: bool = False
    target_url: str = ""
    browser: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> WebResult:
        return cls(
            journeys=[JourneyResult(**j) for j in d.get("journeys", [])],
            endpoints=list(d.get("endpoints", [])),
            parallel=bool(d.get("parallel", False)),
            target_url=d.get("target_url", ""),
            browser=d.get("browser"),
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
) -> WebResult:
    replayer = Replayer(
        target_url,
        secret_values=secret_values,
        step_timeout_ms=step_timeout_ms,
        executable_path=executable_path,
    )
    runs = replayer.run(journeys)
    result = WebResult(target_url=target_url, browser=f"chromium {replayer.browser_version}")
    timing: dict[str, dict[str, list[float]]] = defaultdict(lambda: {"source": [], "target": []})
    for j, run in zip(journeys, runs, strict=True):
        for f in run.flakes:
            emit(
                Finding(
                    Comparator.UI,
                    Kind.FLAKE,
                    Severity.INFO,
                    j.journey_id,
                    f"retried after a transport or timing failure ({f['unit']})",
                    locator=f"step {f['step']}" if f["step"] else None,
                    journey=j.journey_id,
                    story=j.story,
                    detail=f,
                )
            )
        differences = compare_journey(j, run, options, emit, assets_dir(j))
        if run.status != "completed":
            emit(_failure_finding(j, run))
            differences += run.failure_kind == "not_found"
        for step, sr in zip(j.steps, run.steps, strict=False):
            for e in step.exchanges:
                if e.duration_ms is not None:
                    timing[f"{e.method} {normalise_path(e.url)}"]["source"].append(e.duration_ms)
            for c in sr.exchanges:
                if c.exchange.duration_ms is not None:
                    key = f"{c.exchange.method} {normalise_path(c.exchange.url)}"
                    timing[key]["target"].append(c.exchange.duration_ms)
        if run.status == "not_run" or (run.status == "failed" and run.failure_kind == "secret"):
            status = "not_run"
        elif run.status != "completed":
            status = "failed" if run.failure_kind != "not_found" else "different"
        else:
            status = "different" if differences else "passed"
        result.journeys.append(
            JourneyResult(
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
                reason=run.error,
                recorded_wall_ms=j.wall_ms,
                replayed_wall_ms=run.wall_ms,
            )
        )
    for (journey_id, step), n in sorted(replayer.step_flakes.items()):
        if n >= REPEATED_FLAKE:
            # a defect that fails intermittently must not become a statistic (spec 6)
            emit(
                Finding(
                    Comparator.UI,
                    Kind.FLAKE,
                    Severity.MEDIUM,
                    journey_id,
                    f"the same step flaked {n} times in this run",
                    locator=f"step {step}",
                    journey=journey_id,
                    detail={"flakes": n},
                )
            )
    for endpoint, t in sorted(timing.items()):
        src = sum(t["source"]) / len(t["source"]) if t["source"] else None
        tgt = sum(t["target"]) / len(t["target"]) if t["target"] else None
        result.endpoints.append(
            {
                "endpoint": endpoint,
                "source_ms": round(src, 1) if src is not None else None,
                "target_ms": round(tgt, 1) if tgt is not None else None,
                "change_pct": round(100 * (tgt - src) / src, 1) if src and tgt else None,
            }
        )
    return result
