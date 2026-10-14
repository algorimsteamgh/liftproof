"""Support bundle (Technical Spec 13): one file a customer can attach to a ticket.

On a Customer Deployed product we cannot reach the instance, so this is the only
diagnostic surface we have. It carries the run log, the report and findings, the
baseline manifest and an environment report, and never a row value, a response body,
a key value or a credential:

- findings keep their shape, but `expected`, `actual`, database locators (which name key
  values) and value bearing detail fields are replaced by a marker;
- logs are already scrubbed of registered secrets and are scrubbed again here;
- baseline manifests hold bucket aggregates (hashes and counts), never values;
- the HTML report, journeys, recorded bodies and file contents are not included.
"""

from __future__ import annotations

import datetime as dt
import importlib.metadata
import json
import platform
import sys
import zipfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from liftproof import __version__, logs
from liftproof.canonical import CANONICAL_REVISION, CANONICAL_VERSION, HASH_ALGORITHM
from liftproof.config import Project

REDACTED = "[redacted]"
# detail fields that can carry customer data: key values, row values, float statistics
VALUE_FIELDS = frozenset({"key", "source", "target", "expected", "actual", "value", "values"})
LOG_TAIL = 5000  # lines kept when a log has no lines for the run
PACKAGES = (
    "boto3", "botocore", "psycopg", "pymysql", "oracledb", "python-tds", "playwright",
    "pypdf", "jinja2", "pyyaml",
)  # fmt: skip


def redact_finding(f: dict[str, Any]) -> dict[str, Any]:
    out = dict(f)
    for k in ("expected", "actual"):
        if out.get(k) is not None:
            out[k] = REDACTED
    if out.get("comparator") == "database" and out.get("locator"):
        out["locator"] = REDACTED  # "id = 1042": a key value
    if isinstance(out.get("detail"), dict):
        out["detail"] = _redact_detail(out["detail"])
    return out


def _redact_detail(d: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in d.items():
        if k in VALUE_FIELDS:
            out[k] = REDACTED
        elif isinstance(v, dict):
            out[k] = _redact_detail(v)
        else:
            out[k] = v
    return out


def redact_report(report: dict[str, Any]) -> dict[str, Any]:
    out = dict(report)
    if isinstance(out.get("findings"), list):
        out["findings"] = [redact_finding(f) for f in out["findings"]]
    return out


def run_log(log_file: Path | None, run_id: str | None) -> str:
    """The lines of the shared log written by this run; the tail when there are none."""
    if log_file is None or not log_file.exists():
        return ""
    lines = log_file.read_text(encoding="utf-8", errors="replace").splitlines()
    if run_id:
        mine = [ln for ln in lines if f'"run_id": "{run_id}"' in ln]
        if mine:
            lines = mine
    return logs.scrub("\n".join(lines[-LOG_TAIL:]) + "\n")


def environment(instance_config: dict[str, Any]) -> dict[str, Any]:
    versions = {}
    for name in PACKAGES:
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions[name] = None
    os_release = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                os_release[k] = v.strip('"')
    except OSError:
        pass
    return {
        "product_version": __version__,
        "canonical_version": CANONICAL_VERSION,
        "canonical_revision": CANONICAL_REVISION,
        "hash_algorithm": HASH_ALGORITHM,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "os": os_release.get("PRETTY_NAME"),
        "packages": versions,
        "instance_config": instance_config,
    }


def project_summary(project: Project) -> dict[str, Any]:
    """The project's shape: engines, hosts, secret ARNs, rules. No credential is held in a
    project file, so nothing here needs scrubbing beyond the log scrubber's pass."""

    def conn(c):
        if c is None:
            return None
        return {
            "engine": c.engine,
            "endpoint": c.describe(),
            "sslmode": c.sslmode,
            "secret_arn": c.secret_arn,
        }

    o = project.database
    return {
        "name": project.name,
        "source": conn(project.source),
        "target": conn(project.target),
        "database": {
            "schemas": o.schemas,
            "tables": o.tables,
            "rows_per_bucket": o.rows_per_bucket,
            "precision": o.precision,
            "ignore": [
                {
                    "table": r.table,
                    "column": r.column,
                    "where": r.where,
                    "source_where": r.source_where,
                    "target_where": r.target_where,
                    "reason": r.reason,
                }
                for r in o.ignore
            ],
            "business_keys": o.business_keys,
            "show_values": o.show_values,
        },
        "web": None
        if project.web is None
        else {
            "source_url": project.web.source_url,
            "target_url": project.web.target_url,
            "journeys": project.web.journeys,
        },
        "file_sets": [f.name for f in project.files],
        "schedules": [
            {"name": s.name, "cron": s.cron.expr, "timezone": s.timezone, "command": s.command}
            for s in project.schedules
        ],
    }


def latest_run(runs_dir: Path) -> str | None:
    best: tuple[str, str] | None = None
    for d in runs_dir.iterdir() if runs_dir.exists() else []:
        try:
            r = json.loads((d / "report.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        key = (r.get("run", {}).get("started_at") or "", d.name)
        if best is None or key > best:
            best = key
    return best[1] if best else None


def _jsonl(rows: Iterable[dict[str, Any]]) -> str:
    return "".join(json.dumps(r, sort_keys=True) + "\n" for r in rows)


def build(
    out: Path,
    *,
    project: Project,
    workdir: Path,
    run_id: str | None,
    log_file: Path | None,
    instance_config: dict[str, Any],
    doctor: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Writes the bundle and returns its table of contents."""
    contents: dict[str, str] = {}

    def add(name: str, text: str, what: str) -> None:
        zf.writestr(name, logs.scrub(text))
        contents[name] = what

    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        add("environment.json", json.dumps(environment(instance_config), indent=2),
            "product, Python, OS and package versions; instance settings")  # fmt: skip
        add("project.json", json.dumps(project_summary(project), indent=2, default=str),
            "project shape: engines, endpoints, secret ARNs, rules, schedules")  # fmt: skip
        if doctor is not None:
            add("doctor.json", json.dumps(doctor, indent=2), "doctor checks run for the bundle")
        run_dir = workdir / "runs" / run_id if run_id else None
        if run_dir is not None and run_dir.exists():
            report_path = run_dir / "report.json"
            if report_path.exists():
                report = json.loads(report_path.read_text(encoding="utf-8"))
                add("run/report.json", json.dumps(redact_report(report), indent=2),
                    "the run's report, values redacted")  # fmt: skip
                baseline = _baseline_id(report)
                manifest = workdir / "baselines" / str(baseline) / "manifest.json"
                if baseline and manifest.exists():
                    add("run/baseline-manifest.json", manifest.read_text(encoding="utf-8"),
                        f"manifest of baseline {baseline}: aggregates only")  # fmt: skip
            findings: list[dict[str, Any]] = []
            for seg in sorted(run_dir.glob("findings-*.jsonl")):
                for line in seg.read_text(encoding="utf-8").splitlines():
                    if line.strip():
                        findings.append(redact_finding(json.loads(line)))
            if findings:
                add("run/findings.jsonl", _jsonl(findings), "every finding, values redacted")
            for name in ("db-results.json", "files-results.json", "web-results.json"):
                p = run_dir / name
                if p.exists():
                    add(f"run/{name}", p.read_text(encoding="utf-8"), "per object results")
        log_text = run_log(log_file, run_id)
        if log_text.strip():
            add("run.log", log_text, "log lines of the run (or the log's tail), scrubbed")
        manifest_doc = {
            "created_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
            "project": project.name,
            "run_id": run_id,
            "contents": contents,
            "redaction": "expected and actual values, database locators and value bearing "
            "detail fields are replaced by " + REDACTED + "; no HTML report, recording, "
            "response body or file content is included",
        }
        zf.writestr("MANIFEST.json", json.dumps(manifest_doc, indent=2))
    return manifest_doc


def _baseline_id(report: dict[str, Any]) -> str | None:
    ref = (report.get("range") or {}).get("reference") or ""
    return ref.rsplit(" ", 1)[-1] if "baseline" in ref else None
