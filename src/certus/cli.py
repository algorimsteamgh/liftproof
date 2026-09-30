"""The command line: the only complete interface to the product (PRD F11, ATS-005).

Every command runs without an interactive prompt. Exit codes are documented in
certus.errors; a pipeline can always tell "we checked and found problems" (10) from
"we could not check" (2, 3).
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import os
import sys
import traceback
from pathlib import Path
from typing import Any

import yaml

from certus import __version__, aws, logs
from certus.adapters.postgres import PostgresAdapter
from certus.canonical import CANONICAL_VERSION, HASH_ALGORITHM
from certus.config import TEMPLATE, Connection, Project, load_project
from certus.credentials import from_secrets_manager
from certus.errors import (
    EXIT_CONFIG,
    EXIT_DIFFERENCES,
    EXIT_OK,
    EXIT_RUN_FAILED,
    CertusError,
    ConfigError,
    RunFailed,
)
from certus.findings import Comparator, Finding, FindingWriter, Kind, Severity, read_findings
from certus.reconcile.baseline import Baseline, take_baseline
from certus.reconcile.engine import Reconciler, ReconcileResult, TableResult
from certus.report.builder import build_report, who_ran_it, write_reports
from certus.store import LocalStore, S3Store, Store

log = logging.getLogger("certus.cli")

DEFAULT_WORKDIR = Path(os.environ.get("CERTUS_WORKDIR", "/var/lib/mvt/projects"))


def _now() -> str:
    return dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _new_id(prefix: str) -> str:
    return dt.datetime.now(dt.UTC).strftime(f"{prefix}-%Y%m%d-%H%M%S")


def _out(args: argparse.Namespace, payload: dict[str, Any], text: str) -> None:
    if args.format == "json":
        print(json.dumps(payload, indent=2, default=str))
    else:
        print(text)


# --------------------------------------------------------------------- plumbing
def _refuse_env_credentials() -> None:
    """Database credentials only ever come from AWS Secrets Manager (PRD F14)."""
    for var in ("PGPASSWORD", "MYSQL_PWD"):
        if os.environ.get(var):
            raise ConfigError(
                f"{var} is set. Certus never takes database credentials from environment "
                "variables; they come from AWS Secrets Manager."
            )
    if os.environ.get("AWS_SECRET_ACCESS_KEY"):
        log.warning(
            "static AWS access keys found in the environment; on the product AMI "
            "use the instance role instead (IAM-002)"
        )


def connect(conn: Connection) -> PostgresAdapter:
    creds = from_secrets_manager(conn.secret_arn) if conn.secret_arn else None
    return PostgresAdapter(
        host=conn.host,
        port=conn.port,
        database=conn.database,
        user=(creds.username if creds and creds.username else conn.user),
        password=creds.password if creds else None,
        sslmode=conn.sslmode,
        sslrootcert=conn.sslrootcert,
        statement_timeout_ms=conn.statement_timeout_ms,
        rows_per_second=conn.rows_per_second,
        read_only=True,
    )


INSTANCE_CONFIG = Path(os.environ.get("CERTUS_INSTANCE_CONFIG", "/etc/mvt/config.yaml"))


def _instance_config() -> dict[str, Any]:
    """Instance level settings written at launch by the deployment template."""
    try:
        return yaml.safe_load(INSTANCE_CONFIG.read_text(encoding="utf-8")) or {}
    except (FileNotFoundError, PermissionError):
        return {}


def _store(project: Project, workdir: Path) -> Store:
    inst = _instance_config()
    bucket = project.store.s3_bucket or inst.get("bucket")
    if bucket:
        return S3Store(
            bucket,
            project.store.s3_prefix,
            project.store.kms_key_id or inst.get("kms_key"),
            report_lock_days=int(inst.get("report_lock_days", 0)),
        )
    return LocalStore(workdir / project.name)


def _project(args: argparse.Namespace) -> Project:
    return load_project(Path(args.project))


def _tables(args: argparse.Namespace) -> list[str] | None:
    return [t.strip() for t in args.tables.split(",") if t.strip()] if args.tables else None


# --------------------------------------------------------------------- commands
def cmd_version(args: argparse.Namespace) -> int:
    info = {
        "certus": __version__,
        "canonical_version": CANONICAL_VERSION,
        "hash_algorithm": HASH_ALGORITHM,
        **aws.sdk_versions(),
        "python": sys.version.split()[0],
    }
    _out(args, info, "\n".join(f"{k}: {v}" for k, v in info.items()))
    return EXIT_OK


def cmd_init(args: argparse.Namespace) -> int:
    path = Path(args.dir) / f"{args.name}.yaml"
    if path.exists():
        raise ConfigError(f"{path} already exists")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(TEMPLATE.format(name=args.name), encoding="utf-8")
    _out(
        args,
        {"project_file": str(path)},
        f"created {path}\nnext: fill in the connections, then run: certus doctor --project {path}",
    )
    return EXIT_OK


def cmd_baseline(args: argparse.Namespace) -> int:
    project = _project(args)
    workdir = Path(args.workdir) / project.name
    store = _store(project, Path(args.workdir))
    baseline_id = args.baseline_id or _new_id("b")
    manifest = workdir / "baselines" / baseline_id / "manifest.json"
    key = f"baselines/{baseline_id}/manifest.json"
    if args.resume:
        store.get_file(key, manifest)
    o = project.database
    with connect(project.source) as source:
        b = take_baseline(
            source,
            manifest,
            baseline_id=baseline_id,
            schemas=o.schemas,
            tables=_tables(args) or o.tables,
            ignore=o.ignore,
            business_keys=o.business_keys,
            rows_per_bucket=o.rows_per_bucket,
            precision=o.precision,
            resume=args.resume,
            progress=lambda m: log.info(m),
        )
    store.put_file(key, manifest)
    (workdir / "baselines" / "latest").write_text(baseline_id, encoding="utf-8")
    payload = {
        "baseline_id": baseline_id,
        "tables": len(b.tables),
        "rows": sum(t.row_count for t in b.tables.values()),
        "consistency": b.position,
        "manifest": store.location(key),
    }
    _out(
        args,
        payload,
        f"baseline {baseline_id}: {payload['tables']} tables, {payload['rows']:,} rows\n"
        f"consistency position: {b.position.get('position')}\nmanifest: {payload['manifest']}",
    )
    return EXIT_OK


def _load_baseline(args, project: Project, store: Store, workdir: Path) -> Baseline | None:
    if not args.baseline:
        return None
    bid = args.baseline
    if bid == "latest":
        marker = workdir / "baselines" / "latest"
        if not marker.exists():
            raise ConfigError("no baseline has been taken for this project")
        bid = marker.read_text(encoding="utf-8").strip()
    path = workdir / "baselines" / bid / "manifest.json"
    if not path.exists() and not store.get_file(f"baselines/{bid}/manifest.json", path):
        raise ConfigError(f"baseline {bid} not found")
    return Baseline.load(path)


def _save_results(run_dir: Path, result: ReconcileResult) -> None:
    (run_dir / "db-results.json").write_text(
        json.dumps(
            {"systemic": result.systemic, "tables": [t.__dict__ for t in result.tables]}, indent=2
        ),
        encoding="utf-8",
    )


def _load_results(run_dir: Path) -> ReconcileResult:
    p = run_dir / "db-results.json"
    if not p.exists():
        return ReconcileResult()
    d = json.loads(p.read_text(encoding="utf-8"))
    return ReconcileResult([TableResult(**t) for t in d["tables"]], d["systemic"])


def cmd_reconcile(args: argparse.Namespace) -> int:
    project = _project(args)
    workdir = Path(args.workdir) / project.name
    store = _store(project, Path(args.workdir))
    run_id = args.run_id or _new_id("r")
    run_dir = workdir / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    logs.set_context(run_id=run_id, project=project.name)
    o = project.database
    if args.tables:
        o.tables = _tables(args)
    if args.show_values:
        o.show_values = True
    baseline = _load_baseline(args, project, store, workdir)
    started = _now()
    writer = FindingWriter(run_dir, run_id)
    result = ReconcileResult()
    failure: str | None = None
    target = source = None
    try:
        target = connect(project.target)
        if not args.no_source:
            try:
                source = connect(project.source)
            except ConfigError:
                if baseline is None:
                    raise
                log.warning("source unreachable; comparing against the baseline only")
        for conn in (project.source, project.target):
            if not conn.tls_verified:
                writer.write(
                    Finding(
                        Comparator.DATABASE,
                        Kind.NOTICE,
                        Severity.LOW,
                        conn.describe(),
                        f"TLS certificate verification lowered to {conn.sslmode}",
                        detail={"sslmode": conn.sslmode},
                    )
                )
        rec = Reconciler(
            target, writer, o, source=source, baseline=baseline, progress=lambda m: log.info(m)
        )
        try:
            result = rec.run()
        finally:
            result = rec.result  # keep whatever finished before a failure
    except ConfigError:
        raise
    except CertusError as exc:
        failure = str(exc)
    except Exception as exc:  # the run failed; still write what we have
        failure = f"{type(exc).__name__}: {logs.scrub(str(exc))}"
        log.error("run failed", exc_info=True)
    finally:
        for a in (source, target):
            if a is not None:
                a.close()
        if failure:
            writer.write(
                Finding(
                    Comparator.DATABASE,
                    Kind.ERROR,
                    Severity.CRITICAL,
                    "run",
                    f"run did not complete: {failure}",
                )
            )
        writer.close()
        _save_results(run_dir, result)

    report = _report(
        project,
        run_id,
        "reconcile",
        run_dir,
        result,
        started,
        baseline,
        failure=failure,
        template=args.template,
    )
    for f in sorted(run_dir.iterdir()):
        store.put_file(f"runs/{run_id}/{f.name}", f)
    return _conclude(args, report, store, run_id)


def _report(
    project, run_id, mode, run_dir, result, started, baseline, *, failure=None, template=None
) -> dict[str, Any]:
    findings = list(read_findings(run_dir))
    o = project.database
    range_block = {
        "schemas": ", ".join(o.schemas),
        "tables": [t.table for t in result.tables],
        "source": project.source.describe(),
        "target": project.target.describe(),
        "reference": f"baseline {baseline.baseline_id}" if baseline else "live source",
        "consistency_position": baseline.position if baseline else "live read",
        "run_window": f"{started} to {_now()}",
    }
    metadata = {
        "invoked_by": who_ran_it(),
        "values_shown": o.show_values,
        "tls": {"source": project.source.sslmode, "target": project.target.sslmode},
        "rows_per_bucket": o.rows_per_bucket,
        "timestamp_precision": o.precision,
    }
    report = build_report(
        run_id=run_id,
        project=project.name,
        mode=mode,
        findings=findings,
        db=result,
        started_at=started,
        finished_at=_now(),
        metadata=metadata,
        range_block=range_block,
        run_failed=failure is not None,
        failure=failure,
    )
    write_reports(report, run_dir, Path(template) if template else None)
    return report


def _conclude(args, report: dict[str, Any], store: Store, run_id: str) -> int:
    html = store.location(f"runs/{run_id}/report.html")
    c = report["counts"]
    cov = report["coverage"]
    _out(
        args,
        {
            "run_id": run_id,
            "verdict": report["verdict"],
            "counts": c,
            "coverage": {k: cov[k] for k in ("tables_coverage_pct", "tables_success_pct")},
            "report_html": html,
            "report_json": store.location(f"runs/{run_id}/report.json"),
        },
        f"verdict: {report['verdict']}\n"
        f"tables: {c['tables']} ({c['tables_matched']} matched, {c['tables_different']} "
        f"different), differences: {c['differences']}, not checked: {c['not_checked']}\n"
        f"report: {html}",
    )
    if report["failure"]:
        return EXIT_RUN_FAILED
    if args.fail_on == "never":
        return EXIT_OK
    if args.fail_on == "errors":
        return EXIT_OK
    return EXIT_DIFFERENCES if c["differences"] else EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    project = _project(args)
    workdir = Path(args.workdir) / project.name
    run_dir = workdir / "runs" / args.run
    if not run_dir.exists():
        raise ConfigError(f"run {args.run} not found under {workdir / 'runs'}")
    prior = (
        json.loads((run_dir / "report.json").read_text())
        if (run_dir / "report.json").exists()
        else {}
    )
    started = prior.get("run", {}).get("started_at", _now())
    report = _report(
        project,
        args.run,
        prior.get("mode", "reconcile"),
        run_dir,
        _load_results(run_dir),
        started,
        None,
        failure=prior.get("failure"),
        template=args.template,
    )
    store = _store(project, Path(args.workdir))
    for name in ("report.html", "report.json"):
        store.put_file(f"runs/{args.run}/{name}", run_dir / name)
    return _conclude(args, report, store, args.run)


def cmd_doctor(args: argparse.Namespace) -> int:
    project = _project(args)
    checks: list[dict[str, str]] = []

    def check(name: str, fn, remedy: str) -> None:
        try:
            detail = fn() or "ok"
            checks.append({"check": name, "result": "pass", "detail": str(detail)})
        except Exception as exc:  # every failure is reported, none stops the others
            msg = str(exc) if isinstance(exc, CertusError) else f"{type(exc).__name__}: {exc}"
            checks.append(
                {"check": name, "result": "fail", "detail": logs.scrub(msg), "remedy": remedy}
            )

    for role, conn in (("source", project.source), ("target", project.target)):
        if conn.secret_arn:
            check(
                f"{role} secret resolves",
                lambda c=conn: from_secrets_manager(c.secret_arn) and c.secret_arn,
                "grant secretsmanager:GetSecretValue on the secret and kms:Decrypt on its key",
            )
        check(
            f"{role} TLS verifies the server certificate",
            lambda c=conn: (
                _assert(c.tls_verified, f"sslmode={c.sslmode} does not verify") or c.sslmode
            ),
            "set sslmode: verify-full and point sslrootcert at the CA bundle",
        )

        def _conn_check(c=conn, r=role):
            with connect(c) as a:
                a.list_tables(project.database.schemas)
                if r == "source":
                    _assert(a.verify_read_only(), "the source user can write; it must be read only")
                with a.conn.cursor() as cur:
                    cur.execute("SELECT md5('certus')")
                return f"connected to {c.describe()}"

        check(
            f"{role} database connection" + (" and read only user" if role == "source" else ""),
            _conn_check,
            "check the route (VPN, Direct Connect, security groups) and the grants: the "
            "source user needs SELECT only",
        )
    if project.store.s3_bucket:

        def _s3():
            import tempfile

            store = S3Store(
                project.store.s3_bucket, project.store.s3_prefix, project.store.kms_key_id
            )
            with tempfile.NamedTemporaryFile() as tmp:
                tmp.write(b"certus doctor probe")
                tmp.flush()
                store.put_file("doctor/probe.txt", Path(tmp.name))
            return store.location("doctor/probe.txt")

        check(
            "S3 bucket writable with KMS encryption",
            _s3,
            "grant s3:PutObject on the bucket and kms:GenerateDataKey on the key; for a "
            "customer managed key the key policy must also allow the instance role",
        )
    failed = [c for c in checks if c["result"] == "fail"]
    text = "\n".join(
        f"[{'PASS' if c['result'] == 'pass' else 'FAIL'}] {c['check']}: "
        f"{c['detail']}" + (f"\n       fix: {c['remedy']}" if c.get("remedy") else "")
        for c in checks
    )
    _out(args, {"checks": checks, "ok": not failed}, text)
    return EXIT_CONFIG if failed else EXIT_OK


def _assert(cond: bool, message: str) -> None:
    if not cond:
        raise ConfigError(message)


# ----------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--format", choices=["text", "json"], default="text")
    common.add_argument("--log-level", default="info")
    common.add_argument("--workdir", default=str(DEFAULT_WORKDIR))
    common.add_argument(
        "--fail-on", choices=["differences", "errors", "never"], default="differences"
    )

    p = argparse.ArgumentParser(
        prog="certus", description="Certus migration validation", parents=[common]
    )
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("version", parents=[common], help="show versions").set_defaults(fn=cmd_version)

    s = sub.add_parser("init", parents=[common], help="create a project file")
    s.add_argument("name")
    s.add_argument("--dir", default=".")
    s.set_defaults(fn=cmd_init)

    def with_project(name: str, help_: str):
        s = sub.add_parser(name, parents=[common], help=help_)
        s.add_argument("--project", required=True, help="project YAML file")
        return s

    s = with_project("doctor", "check connections, permissions and prerequisites")
    s.set_defaults(fn=cmd_doctor)

    s = with_project("baseline", "capture the source database state")
    s.add_argument("--tables", help="comma separated subset")
    s.add_argument("--baseline-id")
    s.add_argument("--resume", action="store_true", help="continue an interrupted baseline")
    s.set_defaults(fn=cmd_baseline)

    s = with_project("reconcile", "compare the target database against the source")
    s.add_argument("--baseline", help="baseline id, or 'latest'; default: live source only")
    s.add_argument(
        "--no-source",
        action="store_true",
        help="do not connect to the source; bucket level comparison only",
    )
    s.add_argument("--tables", help="comma separated subset")
    s.add_argument(
        "--show-values",
        action="store_true",
        help="print row values in the report (the report becomes an egress path)",
    )
    s.add_argument("--run-id")
    s.add_argument("--template", help="directory holding a custom report.html.j2")
    s.set_defaults(fn=cmd_reconcile)

    s = with_project("report", "regenerate a report from a run's findings")
    s.add_argument("--run", required=True)
    s.add_argument("--template", help="directory holding a custom report.html.j2")
    s.set_defaults(fn=cmd_report)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    log_dir = Path(os.environ.get("CERTUS_LOG_DIR", "/var/log/mvt"))
    logs.setup(args.log_level, str(log_dir / "certus.log") if os.access(log_dir, os.W_OK) else None)
    try:
        _refuse_env_credentials()
        return args.fn(args)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    except RunFailed as exc:
        print(f"run failed: {exc}", file=sys.stderr)
        return EXIT_RUN_FAILED
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return EXIT_RUN_FAILED
    except Exception:  # never exit 1: a crash must not look like a verdict
        print(
            "unexpected failure; run `certus` with --log-level debug and raise a ticket",
            file=sys.stderr,
        )
        print(logs.scrub(traceback.format_exc()), file=sys.stderr)
        return EXIT_RUN_FAILED


if __name__ == "__main__":
    sys.exit(main())
