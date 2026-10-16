"""User interface and API comparison (PRD F4, F5; Technical Spec 7, 8).

UI: the accessible tree of the region each step touched, compared as text after
volatile values (dates, times, generated ids, correlated values) are masked, where the
project kept the page's snapshot (web.capture_snapshots); every other page, and a kept
one the bucket has since expired, by structure: roles, states and nesting. Never pixels.
What the ignore regions match (web.ignore_regions, and any element marked
data-liftproof-volatile) is left out of the tree on both sides before either.

API: for every request the journey made, status exactly, response shape structurally
(an array by the union of its elements' shapes, so $.orders[*].total is one field),
values (only for bodies the project opted in to keep) value by value with numbers
compared as numbers, and only the headers the project names.

Every correlation is ignored at its source and masked everywhere it reappears, so the
ids a replay legitimately creates are never reported (spec 6). A correlation the replay
did not resolve is named, with why, and so are the findings it explains: a request that
sent its recorded value and was answered differently, a request or value that carries it
(spec 6: which unresolved values caused a failure, so the engineer knows what to add).
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
from liftproof.web import correlate
from liftproof.web.browser import (
    REDACTED,
    Captured,
    applied_regions,
    endpoints,
    in_force,
    normalise_path,
)
from liftproof.web.journey import (
    REGION_SHAPE_VERSION,
    Correlation,
    Exchange,
    IgnoreRegion,
    Journey,
    Step,
    region_shape,
    shape,
)
from liftproof.web.replay import JourneyRun, StepRun

DEFAULT_VOLATILE = [
    (r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?", "<datetime>"),
    (r"\b\d{4}-\d{2}-\d{2}\b", "<date>"),
    (r"\b\d{1,2}/\d{1,2}/\d{2,4}\b", "<date>"),
    (r"\b\d{1,2}:\d{2}(:\d{2})?\s?([AaPp][Mm])?\b", "<time>"),
    (r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", "<uuid>"),
    (r"@@REDACTED_[0-9a-f]+", "<secret>"),
]


# a failure the page's content can cause, so one a stale value sent before it may explain
STALE_FAILURES = ("not_found", "ambiguous", "wrong_page", "transport")


@dataclass
class WebOptions:
    compare_headers: list[str] = field(default_factory=list)
    ignore_json_paths: list[str] = field(default_factory=list)  # "$.a[*].b" or "GET /x $.y"
    ignore_text: list[str] = field(default_factory=list)  # regular expressions, UI
    ignore_regions: list[IgnoreRegion] = field(default_factory=list)  # CSS selectors, UI
    volatile_defaults: bool = True
    float_rel_tolerance: float = 1e-9
    show_values: bool = False


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(str(value).encode()).hexdigest()[:16]


@dataclass
class Unresolved:
    """A correlation the replay did not carry forward: why, the steps that sent its
    recorded value instead, and the findings it explains."""

    correlation: Correlation
    # not_in_response | empty_value | transform_failed | header_redacted |
    # source_not_requested | unconfirmed
    cause: str
    source_step: int | None  # the step whose answer to the source request was read
    since: int | None = None  # the first step to make the source request at recording
    status: int | None = None  # the target's answer to the source request
    found: str | None = None  # what the rule found there: undecodable, or not confirmed
    sent_in: list[int] = field(default_factory=list)
    caused: list[dict[str, Any]] = field(default_factory=list)


def _alone(value: str, written: str | None = None) -> re.Pattern[str]:
    """written (value itself by default) where it does not continue a run of digits or of
    letters that value starts or ends: 120 is not in 1760001203, but 4821 is in %3A4821."""

    def run(ch: str) -> str:
        if not ch.isascii():
            return ""
        return "0-9" if ch.isdigit() else "A-Za-z" if ch.isalpha() else ""

    before, after = run(value[:1]), run(value[-1:])
    return re.compile(
        (f"(?<![{before}])" if before else "")
        + re.escape(value if written is None else written)
        + (f"(?![{after}])" if after else "")
    )


def _carries(c: Correlation, text: str) -> bool:
    return any(_alone(form).search(text) for form in correlate.forms(c, c.recorded_value))


# what a rule found in one response, best first: replay takes the first value found
READS = ("found", "transform_failed", "empty_value", "header_redacted", "not_in_response")


def _read(c: Correlation, cap: Captured) -> tuple[str, str | None]:
    """What the rule finds in one response, as replay reads it: (found, the value), or
    why it finds none, with what it found when that did not decode."""
    headers = cap.exchange.response_headers
    raw = correlate.extract(c.extractor, c.expression, json=cap.json, body=cap.body,
                            headers=headers)  # fmt: skip
    header = c.expression.partition(":")[0].lower()
    if c.extractor in ("header", "header_segment") and headers.get(header) == REDACTED:
        return "header_redacted", None
    if raw is None:
        return "not_in_response", None
    if raw == "":
        return "empty_value", None
    new = correlate.apply(c.transforms, raw)
    return ("found", new) if new else ("transform_failed", raw)


def _diff(a: list[str], b: list[str]) -> tuple[list[str], list[str], list[str]]:
    """The lines that changed between two snapshots, then those only on each side."""
    diff = [
        line
        for line in difflib.unified_diff(a, b, "source", "target", lineterm="", n=0)
        if line[:1] in "+-" and not line.startswith(("+++", "---"))
    ]
    removed = [d[1:].strip() for d in diff if d.startswith("-")]
    added = [d[1:].strip() for d in diff if d.startswith("+")]
    return diff, removed, added


def _steps(ns: list[int]) -> str:
    return f"step {ns[0]}" if len(ns) == 1 else f"steps {', '.join(map(str, ns[:-1]))} and {ns[-1]}"


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


def _json_path(rule: str) -> re.Pattern[str]:
    """An ignore rule's JSON path: [*] (or []) stands for every element of an array, so
    it matches $.orders[2].total and the shape's $.orders[*].total; [2] only itself."""
    return re.compile(re.sub(r"\\\[(\\\*)?\\\]", lambda m: r"\[(\d+|\*)?\]", re.escape(rule)))


def _kind(s: Any) -> str:
    return "object" if isinstance(s, dict) else "array" if isinstance(s, list) else str(s)


def _type_change(a: set[str], b: set[str], in_array: bool) -> int | None:
    """How much a change between the types a value had on each side counts, None when
    they agree. null is data, so it goes with any type, except a side only ever null
    against one never null: medium for a single value, low among an array's elements."""
    na, nb = a - {"null"}, b - {"null"}
    if na and nb:
        return None if na == nb else Severity.LOW if na & nb else Severity.MEDIUM
    if (not na and not nb) or "null" in (b if not na else a):
        return None
    return Severity.LOW if in_array else Severity.MEDIUM


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
        # how each page was compared: text (its snapshot kept), shape (by structure), or
        # expired (kept, but gone from the bucket, so by structure)
        self.ui_compared = dict.fromkeys(("text", "shape", "expired"), 0)
        self.bodies_expired = 0
        self.shapes_outdated = 0  # recorded by another version of region_shape()
        # the ignore regions this journey is compared with, the steps each hid content in on
        # each side (and those where an element kept its own text), and those left out
        self.regions, self.regions_left_out = applied_regions(
            journey.ignore_regions, in_force(options.ignore_regions)
        )
        self.hidden_by: dict[IgnoreRegion, dict[str, list[int]]] = {
            r: {"source": [], "target": [], "unhideable": []} for r in self.regions
        }
        self.pages_ignored: dict[int, str] = {}  # step -> the ignore region it was inside
        # correlated values on both sides -> {name}
        self.masks: dict[str, str] = {}
        for c in journey.correlations:
            for form in correlate.forms(c, c.recorded_value):
                self.masks[form] = c.name
            new = run.values.get(c.recorded_value)
            if new:
                for form in correlate.forms(c, new):
                    self.masks[form] = c.name
        self.ignored_at_source = {
            (c.source, c.expression) for c in journey.correlations if c.extractor == "json_path"
        }
        self.ignore_rules = [
            (endpoint, _json_path(path))
            for endpoint, _, path in (
                rule.rpartition(" ") if " $" in rule else ("", "", rule)
                for rule in options.ignore_json_paths
            )
        ]
        self.unresolved: dict[str, Unresolved] = {}
        for c in journey.correlations:
            u = self._diagnose(c)
            if u is not None:
                self.unresolved[c.name] = u
        self.stale_at_failure: list[str] = []  # set by report_unresolved

    def _diagnose(self, c: Correlation) -> Unresolved | None:
        """Why a correlation was not carried forward, worked out from what the target
        answered: every response to the rule's request, read as replay reads them, and
        the one replay would take the value from or the one that came closest. None when
        it was carried; when the journey stopped before its value existed (that stop is
        reported); and for a candidate never confirmed, unless the target sent a
        different value and a request where recording saw it reused the recorded one."""
        if c.recorded_value in self.run.values:
            return None
        recorded = next((s.n for s in self.j.steps if c.source in endpoints(s.exchanges)), None)
        u = Unresolved(c, "source_not_requested", recorded, since=recorded)
        reads = [
            (_read(c, cap), s.n, cap.exchange.status)
            for s in self.run.steps
            if s.status == "ok"
            for cap in s.exchanges
            if f"{cap.exchange.method} {normalise_path(cap.exchange.url)}" == c.source
        ]
        if reads:
            (cause, value), u.source_step, u.status = min(reads, key=lambda r: READS.index(r[0][0]))
            if cause != "found":
                u.cause, u.found = cause, value
            elif c.confirmed or value == c.recorded_value:
                return None
            else:
                u.cause, u.found = "unconfirmed", value
        else:
            # never requested: the step that made the request at recording ran, or, for a
            # rule whose source no recorded step names, the whole journey did
            reached = (
                self.run.status == "completed"
                if recorded is None
                else any(s.n == recorded and s.status == "ok" for s in self.run.steps)
            )
            if not reached:
                return None
        if not c.confirmed and u.cause != "unconfirmed":
            return None
        u.sent_in = [s.n for s in self.run.steps if any(self._sent(u, s.n, x) for x in s.exchanges)]
        if not c.confirmed and not u.sent_in:
            return None
        return u

    def _sent(self, u: Unresolved, n: int, cap: Captured) -> bool:
        """Whether a request of step n sent the recorded value: not before its source was
        requested at recording, and for a candidate never confirmed, only where recording
        saw it reused (an endpoint, or the step the engineer typed it in)."""
        c, ex = u.correlation, cap.exchange
        if u.since is not None and n < u.since:
            return False
        reused = {f"{ex.method} {normalise_path(ex.url)}", f"step {n}"}
        if not c.confirmed and not reused & set(c.used_in):
            return False
        return _carries(c, f"{ex.url}\n{cap.request_body or ''}")

    def _carrying(self, cap: Captured, step: int) -> list[str]:
        """The unresolved correlations whose recorded value the request sent."""
        return [n for n, u in self.unresolved.items() if self._sent(u, step, cap)]

    def _named(self, *masked: str) -> list[str]:
        """The unresolved correlations these masked texts name, where the value masked
        stood on its own."""
        return [
            n
            for n, u in self.unresolved.items()
            if any(_alone(u.correlation.recorded_value, "{" + n + "}").search(t) for t in masked)
        ]

    def emit(
        self,
        comparator: Comparator,
        kind: Kind,
        severity: int,
        obj: str,
        summary: str,
        step: int | None = None,
        *,
        blame: list[str] | None = None,
        **kw: Any,
    ) -> None:
        if kind == Kind.DIFFERENCE:
            self.differences += 1
        if blame:
            # the correlations left unresolved that explain it (spec 6)
            kw["detail"] = {**kw.get("detail", {}), "unresolved_correlations": blame}
            for name in blame:
                self.unresolved[name].caused.append(
                    {"step": step, "object": obj, "summary": summary}
                )
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

    # ---------------------------------------------------- unresolved correlations
    def report_unresolved(self) -> None:
        """One finding for each correlation the replay left unresolved, once the steps
        are compared: not checked when its recorded value was sent or it explains other
        findings, a notice when the page carried the target's own value and nothing
        differed. Sets stale_at_failure, those whose recorded value was sent at or
        before the step the journey failed at."""
        failed = next((s.n for s in self.run.steps if s.status == "failed"), None)
        if self.run.failure_kind not in STALE_FAILURES:
            failed = None
        for name, u in self.unresolved.items():
            c = u.correlation
            summary = f"correlation {name} not resolved: {self._cause(u)}"
            if u.sent_in:
                summary += f"; {_steps(u.sent_in)} sent the recorded value"
            if u.caused:
                k, steps = len(u.caused), sorted({x["step"] for x in u.caused})
                summary += f"; it explains {k} finding{'s' * (k > 1)} in {_steps(steps)}"
            if failed is not None and u.sent_in and u.sent_in[0] <= failed:
                self.stale_at_failure.append(name)
                summary += f"; the journey then failed at step {failed}"
            if not c.confirmed:
                summary += (
                    "; if the server generates it, confirm it (liftproof bind --confirm, "
                    "or the journey's page)"
                )
            if u.caused or name in self.stale_at_failure:
                kind, severity = Kind.NOT_CHECKED, Severity.MEDIUM
            elif u.sent_in:
                kind, severity = Kind.NOT_CHECKED, Severity.LOW
            else:
                kind, severity = Kind.NOTICE, Severity.INFO
            # no "reason" key: a notice with one is listed as an exclusion
            self.emit(
                Comparator.UI,
                kind,
                severity,
                self.j.journey_id,
                summary,
                u.source_step,
                column=name,
                expected=self._value(c.recorded_value),
                actual=self._value(u.found),
                detail={
                    "correlation": name,
                    "cause": u.cause,
                    "confirmed": c.confirmed,
                    "extractor": c.extractor,
                    "expression": c.expression,
                    "transforms": c.transforms,
                    "source_endpoint": self._source(c),
                    "source_step": u.source_step,
                    "source_status": u.status,
                    "sent_in": u.sent_in,
                    "caused": u.caused,
                },
            )

    def _source(self, c: Correlation) -> str:
        method, _, path = c.source.partition(" ")
        return f"{method} {normalise_path(path, self.masks)}"

    def _cause(self, u: Unresolved) -> str:
        c = u.correlation
        rule = f"{c.extractor} {c.expression}"
        where = f"the target's {self._source(c)} response (status {u.status})"
        match u.cause:
            case "not_in_response":
                return f"{rule} found no value in {where}"
            case "empty_value":
                return f"{rule} found an empty value in {where}"
            case "transform_failed":
                chain = " then ".join(c.transforms)
                return f"what {rule} found in {where} did not decode with {chain}"
            case "header_redacted":
                header = c.expression.partition(":")[0].lower()
                return (
                    f"the {header} header of {where} is redacted before replay reads it; "
                    "take the value from the body instead"
                )
            case "source_not_requested":
                recorded = f" (recorded in step {u.source_step})" if u.source_step else ""
                return f"the target never made the {self._source(c)} request{recorded}"
        return (
            "detected at recording but not confirmed, so not applied, and "
            f"{where} carried a different value"
        )

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

    def page(self, step: Step, sr: StepRun) -> None:
        """The region a step touched, after it ran: as text when its snapshot is held (an
        asset the page was opted in for, or inline in a journey recorded before 1.1),
        otherwise by structure; not at all when an ignore region covered the page."""
        replayed = sr.region
        if replayed is None:
            return
        one_side = self._hiding(step, sr)
        covered = step.region_ignored or sr.region_ignored
        if covered:
            self.pages_ignored[step.n] = covered
            return
        text = step.region
        if text is None and step.region_asset:
            raw = self.asset(step.region_asset)
            text = raw.decode("utf-8", "replace") if raw is not None else None
        if text is not None:
            self.ui_compared["text"] += 1
            self.ui(text, replayed, step.n, one_side)
        elif step.region_shape is not None:
            if self.j.region_shape_version != REGION_SHAPE_VERSION:
                self.shapes_outdated += 1
                return
            self.ui_compared["expired" if step.region_asset else "shape"] += 1
            self.ui_shape(step.region_shape, replayed, step.n, one_side)

    def _hiding(self, step: Step, sr: StepRun) -> dict[str, str]:
        """Note where each ignore region hid content at this step, on each side. Returns
        those that hid content on one side only (by label: the side), the likely cause of
        a difference there: a selector that matches one side's markup and not the other's."""
        hid_on = {
            "source": {*step.region_hidden, step.region_ignored} - {None},
            "target": {*sr.region_hidden, sr.region_ignored} - {None},
        }
        one_side = {}
        for r, steps in self.hidden_by.items():
            hid = {side: r.on(side) in selectors for side, selectors in hid_on.items()}
            for side in (side for side in hid if hid[side]):
                steps[side].append(step.n)
            if r.on("target") in sr.region_unhideable:
                steps["unhideable"].append(step.n)
            if r.on("source") and r.on("target") and hid["source"] != hid["target"]:
                one_side[r.label] = "source" if hid["source"] else "target"
        return one_side

    def ui(
        self,
        recorded: str | None,
        replayed: str | None,
        step: int,
        one_side: dict[str, str] | None = None,
    ) -> None:
        if recorded is None or replayed is None:
            return
        a, b = self.mask(recorded).splitlines(), self.mask(replayed).splitlines()
        if a == b:
            return
        diff, removed, added = _diff(a, b)
        self.emit(
            Comparator.UI,
            Kind.DIFFERENCE,
            Severity.MEDIUM,
            f"{self.j.journey_id} step {step}",
            "page content differs after the step",
            step,
            blame=self._named(*removed, *added),
            expected=self._value(removed[0] if removed else ""),
            actual=self._value(added[0] if added else ""),
            detail={
                "compared": "text",
                "lines_only_on_source": len(removed),
                "lines_only_on_target": len(added),
                **({"diff": diff[:40]} if self.o.show_values else {}),
                **({"hidden_on_one_side": one_side} if one_side else {}),
            },
        )

    def ui_shape(
        self, recorded: str, replayed: str, step: int, one_side: dict[str, str] | None = None
    ) -> None:
        """A page whose text was not kept, by structure (region_shape). Its lines hold no
        values, so they are shown as they are; masks and ignore_text have no text here."""
        a, b = recorded.splitlines(), region_shape(replayed).splitlines()
        if a == b:
            return
        diff, removed, added = _diff(a, b)
        self.emit(
            Comparator.UI,
            Kind.DIFFERENCE,
            Severity.MEDIUM,
            f"{self.j.journey_id} step {step}",
            "page structure differs after the step",
            step,
            expected=removed[0] if removed else "",
            actual=added[0] if added else "",
            detail={
                "compared": "shape",
                "lines_only_on_source": len(removed),
                "lines_only_on_target": len(added),
                "diff": diff[:40],
                **({"hidden_on_one_side": one_side} if one_side else {}),
            },
        )

    def report_unkept(self) -> None:
        """What the journey could not compare as recorded: content kept at recording that
        the bucket has since expired (compared by structure and shape instead), and page
        structures recorded by another build (not compared)."""
        pages, bodies = self.ui_compared["expired"], self.bodies_expired
        if pages or bodies:
            what = [
                f"{n} {noun}{'s' * (n > 1)} by {how}"
                for n, noun, how in ((pages, "page", "structure"), (bodies, "response", "shape"))
                if n
            ]
            # no "reason" key: a notice with one is listed as an exclusion
            self.emit(
                Comparator.UI,
                Kind.NOTICE,
                Severity.INFO,
                self.j.journey_id,
                "content kept at recording has expired (asset retention); compared "
                + " and ".join(what),
                detail={"snapshots_expired": pages, "bodies_expired": bodies},
            )
        if self.shapes_outdated:
            n = self.shapes_outdated
            self.emit(
                Comparator.UI,
                Kind.NOT_CHECKED,
                Severity.LOW,
                self.j.journey_id,
                f"page structure after {n} step{'s' * (n > 1)} not compared: recorded by "
                "another version of liftproof; record the journey again",
                detail={
                    "steps": n,
                    "region_shape_version": self.j.region_shape_version,
                    "this_version": REGION_SHAPE_VERSION,
                },
            )

    def report_ignored(self) -> None:
        """The pages not compared because an ignore region matched the page's main
        element or body, or an element around it, on either side: not checked, so a
        selector that hides more than was meant cannot pass for a comparison."""
        if not self.pages_ignored:
            return
        steps, regions = sorted(self.pages_ignored), sorted(set(self.pages_ignored.values()))
        self.emit(
            Comparator.UI,
            Kind.NOT_CHECKED,
            Severity.LOW,
            self.j.journey_id,
            f"page after {_steps(steps)} not compared: the whole page is inside ignore "
            f"region {' or '.join(regions)}",
            detail={"steps": steps, "ignore_regions": regions},
        )

    # ------------------------------------------------------------------- API
    def _endpoint(self, ex: Exchange) -> str:
        return f"{ex.method} {normalise_path(ex.url, self.masks)}"

    def api(self, recorded: list[Exchange], replayed: list[Captured], step: int) -> None:
        pool = list(replayed)
        # a request not made because its URL carries a value left unresolved, and the
        # pattern the one made in its place matches
        unmatched: list[tuple[re.Pattern[str], list[str]]] = []
        for rec in recorded:
            key = self._endpoint(rec)
            match = next((c for c in pool if self._endpoint(c.exchange) == key), None)
            if match is None:
                names = self._named(key)
                if names:
                    loose = re.escape(key)
                    for n in names:
                        loose = loose.replace(re.escape("{" + n + "}"), "[^/]+")
                    unmatched.append((re.compile(loose), names))
                self.emit(
                    Comparator.API,
                    Kind.DIFFERENCE,
                    Severity.MEDIUM,
                    key,
                    "request made on the source was not made on the target",
                    step,
                    blame=names,
                    detail={"recorded_status": rec.status},
                )
                continue
            pool.remove(match)
            self._exchange(key, rec, match, step)
        for extra in pool:
            key = self._endpoint(extra.exchange)
            self.emit(
                Comparator.API,
                Kind.DIFFERENCE,
                Severity.LOW,
                key,
                "request made on the target that the source did not make",
                step,
                blame=self._named(key) or next((n for p, n in unmatched if p.fullmatch(key)), []),
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
                blame=self._carrying(rep, step),
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
        if rec.body_asset and recorded_body is None:
            self.bodies_expired += 1  # the bucket has expired it: compared by shape
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
        return any(
            p.fullmatch(path) and (not endpoint or endpoint == key)
            for endpoint, p in self.ignore_rules
        )

    def _shape(self, key: str, a: Any, b: Any, path: str, step: int) -> None:
        self._shapes(key, [a], [b], path, step, False)

    def _shapes(
        self, key: str, a: list[Any], b: list[Any], path: str, step: int, in_array: bool
    ) -> None:
        """The shapes a value had on each side: one, or every distinct shape of an array's
        elements (path $.orders[*]). Medium when the evidence is structural: a field in
        every element on one side and in none on the other, a type that shares nothing
        with the recorded one. A field optional on one side, or null against a value, is
        what different data looks like too, so it is low."""
        if not a or not b or self._ignored(key, path):
            return  # an empty array has no element shape; how many elements is a value
        ka, kb = {_kind(s) for s in a}, {_kind(s) for s in b}
        severity = _type_change(ka, kb, in_array)
        if severity is not None:
            self.emit(
                Comparator.API,
                Kind.DIFFERENCE,
                severity,
                key,
                f"type of {path} differs",
                step,
                column=path,
                expected=", ".join(sorted(ka)),
                actual=", ".join(sorted(kb)),
            )
        oa = [s for s in a if isinstance(s, dict)]
        ob = [s for s in b if isinstance(s, dict)]
        for k in sorted(set().union(*oa, *ob)) if oa and ob else []:
            p = f"{path}.{k}"
            if self._ignored(key, p):
                continue
            xa, xb = [o[k] for o in oa if k in o], [o[k] for o in ob if k in o]
            every_a, every_b = len(xa) == len(oa), len(xb) == len(ob)
            if not xa or not xb:
                what, strong = ("missing", every_a) if xa else ("added", every_b)
            elif every_a and not every_b:
                what, strong = "missing from some elements", False
            else:
                what, strong = "", False
            if what:
                self.emit(
                    Comparator.API,
                    Kind.DIFFERENCE,
                    Severity.MEDIUM if strong else Severity.LOW,
                    key,
                    f"field {p} {what} on the target",
                    step,
                    column=p,
                )
            self._shapes(key, xa, xb, p, step, in_array)
        ea = [e for s in a if isinstance(s, list) for e in s]
        eb = [e for s in b if isinstance(s, list) for e in s]
        self._shapes(key, ea, eb, f"{path}[*]", step, True)

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
            blame=self._named(self.mask(str(a)), self.mask(str(b))),
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
) -> Comparison:
    """Emit every UI and API finding for one replayed journey, and one for each
    correlation it left unresolved; returns the comparison, which counts the differences
    and how each page was compared, and holds where each ignore region hid content."""

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
        cmp.page(step, sr)
        cmp.api(step.exchanges, sr.exchanges, step.n)
    cmp.report_unresolved()
    cmp.report_unkept()
    cmp.report_ignored()
    return cmp
