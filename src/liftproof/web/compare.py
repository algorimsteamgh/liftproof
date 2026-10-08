"""User interface and API comparison (PRD F4, F5; Technical Spec 7, 8).

UI: the accessible tree of the region each step touched, compared as text after
volatile values (dates, times, generated ids, correlated values) are masked. Never
pixels.

API: for every request the journey made, status exactly, response shape structurally,
values (only for bodies the project opted in to keep) value by value with numbers
compared as numbers, and only the headers the project names.

Every correlation is ignored at its source and masked everywhere it reappears, so the
ids a replay legitimately creates are never reported (spec 6).
"""

from __future__ import annotations

import difflib
import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from liftproof.findings import Comparator, Finding, Kind, Severity
from liftproof.web.browser import Captured, normalise_path
from liftproof.web.journey import Exchange, Journey, shape
from liftproof.web.replay import JourneyRun

DEFAULT_VOLATILE = [
    (r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?", "<datetime>"),
    (r"\b\d{4}-\d{2}-\d{2}\b", "<date>"),
    (r"\b\d{1,2}/\d{1,2}/\d{2,4}\b", "<date>"),
    (r"\b\d{1,2}:\d{2}(:\d{2})?\s?([AaPp][Mm])?\b", "<time>"),
    (r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", "<uuid>"),
    (r"@@REDACTED_[0-9a-f]+", "<secret>"),
]


@dataclass
class WebOptions:
    compare_headers: list[str] = field(default_factory=list)
    ignore_json_paths: list[str] = field(default_factory=list)  # "$.placed_at" or "GET /x $.y"
    ignore_text: list[str] = field(default_factory=list)  # regular expressions, UI
    volatile_defaults: bool = True
    float_rel_tolerance: float = 1e-9
    show_values: bool = False


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(str(value).encode()).hexdigest()[:16]


def _number(v: Any) -> Decimal | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return Decimal(str(v))
    if isinstance(v, str):
        try:
            return Decimal(v)
        except InvalidOperation:
            return None
    return None


class Comparison:
    def __init__(
        self,
        journey: Journey,
        run: JourneyRun,
        options: WebOptions,
        emit: Callable[[Finding], None],
        asset: Callable[[str], bytes | None],
    ) -> None:
        self.j = journey
        self.run = run
        self.o = options
        self.emit_finding = emit
        self.asset = asset
        self.differences = 0
        # correlated values on both sides -> {name}
        self.masks: dict[str, str] = {}
        by_value = {c.recorded_value: c.name for c in journey.correlations}
        for recorded, name in by_value.items():
            self.masks[recorded] = name
            new = run.values.get(recorded)
            if new:
                self.masks[new] = name
        self.ignored_at_source = {
            (c.source, c.expression) for c in journey.correlations if c.extractor == "json_path"
        }

    def emit(
        self,
        comparator: Comparator,
        kind: Kind,
        severity: int,
        obj: str,
        summary: str,
        step: int | None = None,
        **kw: Any,
    ) -> None:
        if kind == Kind.DIFFERENCE:
            self.differences += 1
        self.emit_finding(
            Finding(
                comparator,
                kind,
                severity,
                obj,
                summary,
                locator=f"step {step}" if step else None,
                journey=self.j.journey_id,
                story=self.j.story,
                **kw,
            )
        )

    def _value(self, v: Any) -> str | None:
        if v is None:
            return None
        return str(v) if self.o.show_values else _digest(v)

    # ------------------------------------------------------------------- UI
    def mask(self, text: str) -> str:
        for value, name in sorted(self.masks.items(), key=lambda kv: -len(kv[0])):
            text = text.replace(value, "{" + name + "}")
        if self.o.volatile_defaults:
            for pattern, repl in DEFAULT_VOLATILE:
                text = re.sub(pattern, repl, text)
        for pattern in self.o.ignore_text:
            text = re.sub(pattern, "<ignored>", text)
        return text

    def ui(self, recorded: str | None, replayed: str | None, step: int) -> None:
        if recorded is None or replayed is None:
            return
        a, b = self.mask(recorded).splitlines(), self.mask(replayed).splitlines()
        if a == b:
            return
        diff = [
            line
            for line in difflib.unified_diff(a, b, "source", "target", lineterm="", n=0)
            if line[:1] in "+-" and not line.startswith(("+++", "---"))
        ]
        removed = [d[1:].strip() for d in diff if d.startswith("-")]
        added = [d[1:].strip() for d in diff if d.startswith("+")]
        self.emit(
            Comparator.UI,
            Kind.DIFFERENCE,
            Severity.MEDIUM,
            f"{self.j.journey_id} step {step}",
            "page content differs after the step",
            step,
            expected=self._value(removed[0] if removed else ""),
            actual=self._value(added[0] if added else ""),
            detail={
                "lines_only_on_source": len(removed),
                "lines_only_on_target": len(added),
                **({"diff": diff[:40]} if self.o.show_values else {}),
            },
        )

    # ------------------------------------------------------------------- API
    def _endpoint(self, ex: Exchange) -> str:
        return f"{ex.method} {normalise_path(ex.url, self.masks)}"

    def api(self, recorded: list[Exchange], replayed: list[Captured], step: int) -> None:
        pool = list(replayed)
        for rec in recorded:
            key = self._endpoint(rec)
            match = next((c for c in pool if self._endpoint(c.exchange) == key), None)
            if match is None:
                self.emit(
                    Comparator.API,
                    Kind.DIFFERENCE,
                    Severity.MEDIUM,
                    key,
                    "request made on the source was not made on the target",
                    step,
                    detail={"recorded_status": rec.status},
                )
                continue
            pool.remove(match)
            self._exchange(key, rec, match, step)
        for extra in pool:
            self.emit(
                Comparator.API,
                Kind.DIFFERENCE,
                Severity.LOW,
                self._endpoint(extra.exchange),
                "request made on the target that the source did not make",
                step,
                detail={"status": extra.exchange.status},
            )

    def _exchange(self, key: str, rec: Exchange, rep: Captured, step: int) -> None:
        ex = rep.exchange
        if rec.status != ex.status:
            self.emit(
                Comparator.API,
                Kind.DIFFERENCE,
                Severity.HIGH,
                key,
                "status code differs",
                step,
                expected=str(rec.status),
                actual=str(ex.status),
                detail={"expected": rec.status, "actual": ex.status},
            )
        for h in self.o.compare_headers:
            a, b = rec.response_headers.get(h.lower()), ex.response_headers.get(h.lower())
            if a != b:
                self.emit(
                    Comparator.API,
                    Kind.DIFFERENCE,
                    Severity.LOW,
                    key,
                    f"response header {h} differs",
                    step,
                    column=h,
                    expected=a,
                    actual=b,
                )
        recorded_body = self.asset(rec.body_asset) if rec.body_asset else None
        if recorded_body is not None and rep.json is not None:
            try:
                expected = json.loads(recorded_body)
            except ValueError:
                expected = None
            if expected is not None:
                self._json(key, expected, rep.json, "$", step)
                return
        if rec.body_shape is not None and rep.json is not None:
            self._shape(key, rec.body_shape, shape(rep.json), "$", step)

    def _ignored(self, key: str, path: str) -> bool:
        if (key, path) in self.ignored_at_source:
            return True
        for rule in self.o.ignore_json_paths:
            endpoint, _, p = rule.rpartition(" ") if " $" in rule else ("", "", rule)
            if p == path and (not endpoint or endpoint == key):
                return True
        return False

    def _shape(self, key: str, a: Any, b: Any, path: str, step: int) -> None:
        if isinstance(a, dict) and isinstance(b, dict):
            for k in sorted(set(a) | set(b)):
                p = f"{path}.{k}"
                if self._ignored(key, p):
                    continue
                if k not in b:
                    self.emit(
                        Comparator.API,
                        Kind.DIFFERENCE,
                        Severity.MEDIUM,
                        key,
                        f"field {p} missing on the target",
                        step,
                        column=p,
                    )
                elif k not in a:
                    self.emit(
                        Comparator.API,
                        Kind.DIFFERENCE,
                        Severity.MEDIUM,
                        key,
                        f"field {p} added on the target",
                        step,
                        column=p,
                    )
                else:
                    self._shape(key, a[k], b[k], p, step)
        elif a != b and not (isinstance(a, list) and isinstance(b, list)):
            self.emit(
                Comparator.API,
                Kind.DIFFERENCE,
                Severity.MEDIUM,
                key,
                f"type of {path} differs",
                step,
                column=path,
                expected=str(a),
                actual=str(b),
            )

    def _json(self, key: str, a: Any, b: Any, path: str, step: int) -> None:
        if self._ignored(key, path):
            return
        if isinstance(a, dict) and isinstance(b, dict):
            for k in sorted(set(a) | set(b)):
                p = f"{path}.{k}"
                if self._ignored(key, p):
                    continue
                if k not in b:
                    self.emit(
                        Comparator.API,
                        Kind.DIFFERENCE,
                        Severity.MEDIUM,
                        key,
                        f"field {p} missing on the target",
                        step,
                        column=p,
                        expected=self._value(a[k]),
                    )
                elif k not in a:
                    self.emit(
                        Comparator.API,
                        Kind.DIFFERENCE,
                        Severity.MEDIUM,
                        key,
                        f"field {p} added on the target",
                        step,
                        column=p,
                        actual=self._value(b[k]),
                    )
                else:
                    self._json(key, a[k], b[k], p, step)
            return
        if isinstance(a, list) and isinstance(b, list):
            if len(a) != len(b):
                self.emit(
                    Comparator.API,
                    Kind.DIFFERENCE,
                    Severity.MEDIUM,
                    key,
                    f"length of {path} differs",
                    step,
                    column=path,
                    expected=str(len(a)),
                    actual=str(len(b)),
                )
            for i, (x, y) in enumerate(zip(a, b, strict=False)):
                self._json(key, x, y, f"{path}[{i}]", step)
            return
        if self._equal(a, b):
            return
        self.emit(
            Comparator.API,
            Kind.DIFFERENCE,
            Severity.MEDIUM,
            key,
            f"value of {path} differs",
            step,
            column=path,
            expected=self._value(a),
            actual=self._value(b),
        )

    def _equal(self, a: Any, b: Any) -> bool:
        if a == b and type(a) is type(b):
            return True
        if isinstance(a, str) and isinstance(b, str) and self.mask(a) == self.mask(b):
            return True
        if str(a) in self.masks and str(b) in self.masks:
            return self.masks[str(a)] == self.masks[str(b)]  # the same correlated value
        na, nb = _number(a), _number(b)
        if na is not None and nb is not None and (isinstance(a, str) == isinstance(b, str)):
            if na == nb:
                return True  # 10.50 and 10.5 are the same number (spec 8)
            scale = max(abs(na), abs(nb))
            return scale > 0 and abs(na - nb) / scale <= Decimal(str(self.o.float_rel_tolerance))
        return False


def compare_journey(
    journey: Journey,
    run: JourneyRun,
    options: WebOptions,
    emit: Callable[[Finding], None],
    assets_dir: Path | None,
) -> int:
    """Emit every UI and API finding for one replayed journey; returns the number of
    differences."""

    def asset(ref: str) -> bytes | None:
        if assets_dir is None:
            return None
        p = assets_dir / Path(ref).name
        return p.read_bytes() if p.exists() else None

    cmp = Comparison(journey, run, options, emit, asset)
    replayed = {s.n: s for s in run.steps}
    for step in journey.steps:
        sr = replayed.get(step.n)
        if sr is None or sr.status != "ok":
            continue
        if sr.degraded_from:
            cmp.emit(
                Comparator.UI,
                Kind.DIFFERENCE,
                Severity.LOW,
                f"{journey.journey_id} step {step.n}",
                "locator degraded: the primary locator no longer matches",
                step.n,
                detail={"recorded": sr.degraded_from, "used": sr.used_locator},
                expected=json.dumps(sr.degraded_from),
                actual=json.dumps(sr.used_locator),
            )
        cmp.ui(step.region, sr.region, step.n)
        cmp.api(step.exchanges, sr.exchanges, step.n)
    return cmp.differences
