"""Validation, coverage and traceability reports (PRD F8, F9, F10).

One pass over the findings produces a JSON report with a versioned schema, for other
tools, and one self contained HTML file, for people. The HTML is rendered from a
template the customer may override; the JSON carries every finding the HTML shows.
"""

from __future__ import annotations

import datetime as dt
import getpass
import json
import os
import socket
from collections import Counter, defaultdict
from dataclasses import asdict
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, PackageLoader, select_autoescape

from liftproof import __version__, aws
from liftproof.canonical import CANONICAL_VERSION, HASH_ALGORITHM
from liftproof.findings import Finding, Kind, Severity
from liftproof.reconcile.engine import ReconcileResult

SCHEMA_VERSION = "1.0"

PASSED = "passed"
PASSED_WITH_DIFFERENCES = "passed_with_differences"
FAILED = "failed"


def verdict(findings: list[Finding], run_failed: bool = False) -> str:
    """Verdict rules for this build (the spec leaves them open; see docs/decisions.md).

    failed:                  the run failed, an error was raised, or any difference of
                             severity MEDIUM (3) or higher
    passed_with_differences: only low severity differences, or anything not checked
                             or compared partially
    passed:                  everything in scope was checked and matched
    """
    if run_failed or any(f.kind == Kind.ERROR for f in findings):
        return FAILED
    diffs = [f for f in findings if f.kind == Kind.DIFFERENCE]
    if any(f.severity >= Severity.MEDIUM for f in diffs):
        return FAILED
    if diffs or any(f.kind in (Kind.NOT_CHECKED, Kind.PARTIAL) for f in findings):
        return PASSED_WITH_DIFFERENCES
    return PASSED


def _pct(n: int, d: int) -> float | None:
    return round(100.0 * n / d, 1) if d else None


def build_report(
    *,
    run_id: str,
    project: str,
    mode: str,
    findings: list[Finding],
    db: ReconcileResult | None,
    started_at: str,
    finished_at: str,
    metadata: dict[str, Any],
    range_block: dict[str, Any],
    run_failed: bool = False,
    failure: str | None = None,
) -> dict[str, Any]:
    tables = db.tables if db else []
    status = Counter(t.status for t in tables)
    exists = len(tables)
    attempted = status["matched"] + status["different"]
    not_covered = [
        {"object": t.table, "reason": t.reason or t.status}
        for t in tables
        if t.status in ("not_checked", "excluded")
    ]
    ordered = sorted(
        findings, key=lambda f: (-f.severity, f.comparator, f.object, f.finding_id or "")
    )
    kinds = Counter(f.kind for f in findings)

    stories: dict[str, Counter] = defaultdict(Counter)
    for f in findings:
        if f.story:
            stories[f.story]["differences" if f.kind == Kind.DIFFERENCE else "other"] += 1

    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "project": project,
        "mode": mode,
        "verdict": verdict(findings, run_failed),
        "failure": failure,
        "classification": (
            "contains row values"
            if metadata.get("values_shown")
            else "hashes and column names only; no row values"
        ),
        "counts": {
            "journeys": 0,
            "tables": exists,
            "tables_matched": status["matched"],
            "tables_different": status["different"],
            "differences": kinds[Kind.DIFFERENCE],
            "not_checked": kinds[Kind.NOT_CHECKED] + status["excluded"],
            "partial": kinds[Kind.PARTIAL],
            "flakes": kinds[Kind.FLAKE],
            "errors": kinds[Kind.ERROR],
        },
        # coverage = attempted / exists; success = passed / attempted. Never conflated.
        "coverage": {
            "tables_coverage_pct": _pct(attempted, exists),
            "tables_success_pct": _pct(status["matched"], attempted),
            "journeys_coverage_pct": None,
            "journeys_success_pct": None,
            "not_covered": not_covered,
            "partially_compared": [
                {"object": t.table, "excluded_columns": t.excluded_columns}
                for t in tables
                if t.partial
            ],
            "exclusions": [
                {"object": f.object, "column": f.column, "reason": f.detail.get("reason")}
                for f in findings
                if f.kind == Kind.NOTICE and "reason" in f.detail
            ],
        },
        "range": range_block,
        "tables": [asdict(t) for t in tables],
        "traceability": [
            {"story": s, "tests": sum(c.values()), "differences": c["differences"]}
            for s, c in sorted(stories.items())
        ],
        "timings": [],
        "run": {
            "started_at": started_at,
            "finished_at": finished_at,
            "product_version": __version__,
            "canonical_version": CANONICAL_VERSION,
            "hash_algorithm": HASH_ALGORITHM,
            "aws_sdk": aws.sdk_versions(),
            **metadata,
        },
        "findings": [f.to_dict() for f in ordered],
    }


def who_ran_it() -> str:
    user = os.environ.get("LIFTPROOF_INVOKED_BY") or getpass.getuser()
    return f"{user}@{socket.gethostname()}"


def render_html(report: dict[str, Any], template_dir: Path | None = None) -> str:
    loader = (
        FileSystemLoader(str(template_dir))
        if template_dir
        else PackageLoader("liftproof.report", "templates")
    )
    env = Environment(loader=loader, autoescape=select_autoescape(["html", "j2"]))
    env.filters["num"] = lambda v: "n/a" if v is None else f"{v:,}"
    env.filters["pct"] = lambda v: "n/a" if v is None else f"{v:.1f}%"
    env.filters["tojson_pretty"] = lambda v: json.dumps(v, indent=2, default=str)
    return env.get_template("report.html.j2").render(
        r=report, generated=dt.datetime.now(dt.UTC).strftime("%Y-%m-%d %H:%M UTC")
    )


def write_reports(
    report: dict[str, Any], directory: Path, template_dir: Path | None = None
) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    j = directory / "report.json"
    h = directory / "report.html"
    j.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    h.write_text(render_html(report, template_dir), encoding="utf-8")
    return j, h
