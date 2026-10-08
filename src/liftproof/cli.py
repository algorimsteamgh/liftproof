"""The command line: the only complete interface to the product (PRD F11, ATS-005).

Every command runs without an interactive prompt. Exit codes are documented in
liftproof.errors; a pipeline can always tell "we checked and found problems" (10) from
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

from liftproof import __version__, aws, logs, support
from liftproof.adapters.base import Adapter
from liftproof.adapters.mysql import MySQLAdapter
from liftproof.adapters.oracle import OracleAdapter
from liftproof.adapters.postgres import PostgresAdapter
from liftproof.adapters.sqlserver import SQLServerAdapter
from liftproof.canonical import CANONICAL_VERSION, HASH_ALGORITHM
from liftproof.config import TEMPLATE, Connection, Project, load_project
from liftproof.credentials import from_secrets_manager, secret_value
from liftproof.errors import (
    EXIT_CONFIG,
    EXIT_DIFFERENCES,
    EXIT_OK,
    EXIT_RUN_FAILED,
    ConfigError,
    LiftproofError,
    RunFailed,
)
from liftproof.files.compare import FileResult
from liftproof.findings import Comparator, Finding, FindingWriter, Kind, Severity, read_findings
from liftproof.reconcile.baseline import Baseline, take_baseline
from liftproof.reconcile.engine import Reconciler, ReconcileResult, TableResult
from liftproof.reconcile.replication import SOURCE_SIDE
from liftproof.report.builder import build_report, who_ran_it, write_reports
from liftproof.runlock import RunInProgress
from liftproof.store import LocalStore, S3Store, Store
from liftproof.web.journey import Journey
from liftproof.web.run import WebResult

log = logging.getLogger("liftproof.cli")

DEFAULT_WORKDIR = Path(os.environ.get("LIFTPROOF_WORKDIR", "/var/lib/mvt/projects"))


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
                f"{var} is set. Liftproof never takes database credentials from environment "
                "variables; they come from AWS Secrets Manager."
            )
    if os.environ.get("AWS_SECRET_ACCESS_KEY"):
        log.warning(
            "static AWS access keys found in the environment; on the product AMI "
            "use the instance role instead (IAM-002)"
        )


def connect(conn: Connection) -> Adapter:
    creds = from_secrets_manager(conn.secret_arn) if conn.secret_arn else None
    cls = {"mysql": MySQLAdapter, "oracle": OracleAdapter, "sqlserver": SQLServerAdapter}.get(
        conn.engine, PostgresAdapter
    )
    return cls(
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


INSTANCE_CONFIG = Path(os.environ.get("LIFTPROOF_INSTANCE_CONFIG", "/etc/mvt/config.yaml"))


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
        "liftproof": __version__,
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
        f"created {path}\n"
        f"next: fill in the connections, then run: liftproof doctor --project {path}",
    )
    return EXIT_OK


def cmd_baseline(args: argparse.Namespace) -> int:
    return _take_baseline(args, "source")


def cmd_rebaseline(args: argparse.Namespace) -> int:
    """Snapshot the target as the new reference (spec 14), after cutover or once a set of
    differences has been accepted. Only the target is read; the source may be gone."""
    return _take_baseline(args, "target")


# The id `--baseline` resolves for each side's newest baseline.
LATEST = {"source": "latest", "target": "latest-target"}


def _take_baseline(args: argparse.Namespace, side: str) -> int:
    project = _project(args)
    project.require_database()
    store = _store(project, Path(args.workdir))
    baseline_id = args.baseline_id or _new_id("b" if side == "source" else "t")
    if baseline_id in LATEST.values():
        raise ConfigError(f"{baseline_id!r} is reserved; choose another baseline id")
    mode = "baseline" if side == "source" else "rebaseline"
    return _locked(
        args, project, store, baseline_id, mode,
        lambda: _baseline_locked(args, project, store, baseline_id, side),
    )  # fmt: skip


def _baseline_locked(args, project: Project, store: Store, baseline_id: str, side: str) -> int:
    workdir = Path(args.workdir) / project.name
    manifest = workdir / "baselines" / baseline_id / "manifest.json"
    key = f"baselines/{baseline_id}/manifest.json"
    if args.resume:
        store.get_file(key, manifest)
    o = project.database
    source_conn, target_conn = project.require_database()
    with connect(source_conn if side == "source" else target_conn) as db:
        b = take_baseline(
            db,
            manifest,
            baseline_id=baseline_id,
            schemas=o.schemas,
            tables=_tables(args) or o.tables,
            ignore=o.ignore,
            business_keys=o.business_keys,
            rows_per_bucket=o.rows_per_bucket,
            precision=o.precision,
            resume=args.resume,
            side=side,
            progress=lambda m: log.info(m),
            workers=o.workers,
        )
    store.put_file(key, manifest)
    # The marker goes to the store too, so a replacement instance still finds it.
    marker = workdir / "baselines" / LATEST[side]
    marker.write_text(baseline_id, encoding="utf-8")
    store.put_file(f"baselines/{LATEST[side]}", marker)
    payload = {
        "baseline_id": baseline_id,
        "side": side,
        "tables": len(b.tables),
        "rows": sum(t.row_count for t in b.tables.values()),
        "consistency": b.position,
        "manifest": store.location(key),
    }
    _out(
        args,
        payload,
        f"{side} baseline {baseline_id}: {payload['tables']} tables, {payload['rows']:,} rows\n"
        f"consistency position: {b.position.get('position')}\nmanifest: {payload['manifest']}"
        + (f"\ncompare against it with: --baseline {LATEST['target']}" if side == "target" else ""),
    )
    return EXIT_OK


def _load_baseline(args, project: Project, store: Store, workdir: Path) -> Baseline | None:
    if not args.baseline:
        return None
    bid = args.baseline
    if bid in LATEST.values():
        # The store's marker wins: another instance may have taken a newer baseline.
        marker = workdir / "baselines" / bid
        if not store.get_file(f"baselines/{bid}", marker) and not marker.exists():
            side = "target" if bid == LATEST["target"] else "source"
            how = "liftproof rebaseline" if side == "target" else "liftproof baseline"
            raise ConfigError(f"no {side} baseline has been taken for this project ({how})")
        bid = marker.read_text(encoding="utf-8").strip()
    path = workdir / "baselines" / bid / "manifest.json"
    if not path.exists() and not store.get_file(f"baselines/{bid}/manifest.json", path):
        raise ConfigError(f"baseline {bid} not found")
    return Baseline.load(path)


def _save_results(run_dir: Path, result: ReconcileResult) -> None:
    (run_dir / "db-results.json").write_text(
        json.dumps(
            {
                "systemic": result.systemic,
                "replication": result.replication,
                "sample_seed": result.sample_seed,
                "tables": [t.__dict__ for t in result.tables],
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def _load_results(run_dir: Path) -> ReconcileResult:
    p = run_dir / "db-results.json"
    if not p.exists():
        return ReconcileResult()
    d = json.loads(p.read_text(encoding="utf-8"))
    return ReconcileResult(
        [TableResult(**t) for t in d["tables"]],
        d["systemic"],
        d.get("replication"),
        d.get("sample_seed"),
    )


def _reconcile_into(
    args: argparse.Namespace, project: Project, store: Store, workdir: Path, writer: FindingWriter
) -> tuple[ReconcileResult, Baseline | None]:
    """The database comparison of a run. Failures propagate to _run, which records them."""
    src_conn, tgt_conn = project.require_database()
    o = project.database
    if getattr(args, "tables", None):
        o.tables = _tables(args)
    if args.show_values:
        o.show_values = True
    baseline = _load_baseline(args, project, store, workdir)
    target = source = None
    rec = None
    try:
        target = connect(tgt_conn)
        # A target baseline is the reference on its own: reading the source would compare
        # the target with something other than its accepted state.
        if not args.no_source and not (baseline is not None and baseline.side == "target"):
            try:
                source = connect(src_conn)
            except ConfigError:
                if baseline is None:
                    raise
                log.warning("source unreachable; comparing against the baseline only")
        for conn in (src_conn, tgt_conn):
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
        return rec.run(), baseline
    except Exception as exc:
        exc.partial_result = rec.result if rec else ReconcileResult()  # type: ignore[attr-defined]
        exc.baseline = baseline  # type: ignore[attr-defined]
        raise
    finally:
        for a in (source, target):
            if a is not None:
                a.close()


def _files_into(args: argparse.Namespace, project: Project, writer: FindingWriter) -> FileResult:
    from dataclasses import replace

    from liftproof.files.compare import compare_files
    from liftproof.files.sources import open_source

    sets = project.require_files()
    wanted = [x.strip() for x in (getattr(args, "sets", None) or "").split(",") if x.strip()]
    if wanted:
        unknown = sorted(set(wanted) - {c.name for c in sets})
        if unknown:
            raise ConfigError(f"no file set named {', '.join(unknown)} in the project")
        sets = [c for c in sets if c.name in wanted]
    if getattr(args, "show_values", False):
        sets = [replace(c, show_content=True) for c in sets]

    def side(c, which: str):
        return open_source(
            getattr(c, which),
            endpoint_url=getattr(c, f"{which}_endpoint_url"),
            secret_arn=getattr(c, f"{which}_secret_arn"),
        )

    return compare_files(sets, writer.write, side)


def _locked(args, project: Project, store: Store, run_id: str, mode: str, body) -> int:
    """Runs of one project never overlap (spec 14). A scheduled run that finds another run
    going is skipped, and the skip is itself a run: a report with an error finding, plus a
    CloudWatch metric to alarm on. A run started by hand just fails with exit code 2."""
    lock = store.run_lock(run_id, mode)
    try:
        lock.__enter__()
    except RunInProgress as exc:
        if getattr(args, "scheduled", None):
            return _skipped(args, project, store, run_id, mode, exc)
        raise
    try:
        if lock.body.get("took_over"):
            log.warning("took over the run lock of lost run %s", lock.body["took_over"])
        return body()
    finally:
        lock.__exit__(None, None, None)


def _skipped(args, project: Project, store: Store, run_id: str, mode: str, exc) -> int:
    run_dir = Path(args.workdir) / project.name / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    started = _now()
    writer = FindingWriter(run_dir, run_id)
    holder = exc.holder
    writer.write(
        Finding(
            Comparator.RUN,
            Kind.ERROR,
            Severity.HIGH,
            f"schedule:{args.scheduled}",
            f"scheduled {mode} skipped: run {holder.get('run_id', '?')} of this project was "
            f"still in progress (started {holder.get('acquired_at', '?')})",
            detail={"holder": holder, "schedule": args.scheduled},
        )
    )
    writer.close()
    # The deployment's alarm watches the Deployment dimension alone; the second data point
    # says which project skipped.
    deployment = _instance_config().get("deployment")
    dimensions = [{"Deployment": deployment}, {"Deployment": deployment, "Project": project.name}]
    try:
        for dims in dimensions if deployment else [{"Project": project.name}]:
            aws.put_metric("ScheduledRunSkipped", 1, dims)
    except Exception as e:  # noqa: BLE001 - the report still records the skip
        log.warning("could not publish the ScheduledRunSkipped metric: %s", e)
    report = _report(
        project, run_id, mode, run_dir, None, started, None,
        failure=f"skipped: run {holder.get('run_id', '?')} still in progress",
        template=getattr(args, "template", None), scheduled=args.scheduled,
    )  # fmt: skip
    for f in sorted(run_dir.iterdir()):
        store.put_file(f"runs/{run_id}/{f.name}", f)
    return _conclude(args, report, store, run_id)


def _run(
    args: argparse.Namespace, mode: str, *, database: bool, web: bool, files: bool = False
) -> int:
    """One run: database first, then files, then replay (spec 6: replay creates data,
    and must not then be reconciled or compared against), then one report over every
    finding."""
    project = _project(args)
    store = _store(project, Path(args.workdir))
    run_id = args.run_id or _new_id("r")
    return _locked(
        args, project, store, run_id, mode,
        lambda: _run_locked(args, mode, project, store, run_id, database, web, files),
    )  # fmt: skip


def _run_locked(args, mode, project, store, run_id, database, web, files) -> int:
    workdir = Path(args.workdir) / project.name
    run_dir = workdir / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    logs.set_context(run_id=run_id, project=project.name)
    started = _now()
    writer = FindingWriter(run_dir, run_id)
    result: ReconcileResult | None = ReconcileResult() if database else None
    web_result = None
    files_result: FileResult | None = None
    baseline = None
    failure: str | None = None
    stage = Comparator.DATABASE
    try:
        if database:
            try:
                result, baseline = _reconcile_into(args, project, store, workdir, writer)
            except Exception as exc:
                result = getattr(exc, "partial_result", result)
                baseline = getattr(exc, "baseline", None)
                raise
        if files:
            stage = Comparator.FILE
            files_result = _files_into(args, project, writer)
        if web:
            stage = Comparator.UI
            web_result = _replay_into(args, project, store, workdir, writer)
    except ConfigError:
        raise
    except LiftproofError as exc:
        failure = str(exc)
    except Exception as exc:  # the run failed; still write what we have
        failure = f"{type(exc).__name__}: {logs.scrub(str(exc))}"
        log.error("run failed", exc_info=True)
    finally:
        if failure:
            writer.write(
                Finding(
                    stage,
                    Kind.ERROR,
                    Severity.CRITICAL,
                    "run",
                    f"run did not complete: {failure}",
                )
            )
        writer.close()
        if result is not None:
            _save_results(run_dir, result)
        if web_result is not None:
            (run_dir / "web-results.json").write_text(
                json.dumps(web_result.to_dict(), indent=2), encoding="utf-8"
            )
        if files_result is not None:
            (run_dir / "files-results.json").write_text(
                json.dumps(files_result.to_dict(), indent=2), encoding="utf-8"
            )

    report = _report(
        project,
        run_id,
        mode,
        run_dir,
        result,
        started,
        baseline,
        web_result=web_result,
        files_result=files_result,
        failure=failure,
        template=args.template,
        scheduled=getattr(args, "scheduled", None),
    )
    for f in sorted(run_dir.iterdir()):
        store.put_file(f"runs/{run_id}/{f.name}", f)
    return _conclude(args, report, store, run_id)


def cmd_reconcile(args: argparse.Namespace) -> int:
    return _run(args, "reconcile", database=True, web=False)


def cmd_replay(args: argparse.Namespace) -> int:
    return _run(args, args.command, database=False, web=True)


def cmd_files(args: argparse.Namespace) -> int:
    return _run(args, "files", database=False, web=False, files=True)


def cmd_validate(args: argparse.Namespace) -> int:
    project = _project(args)
    return _run(
        args,
        "validate",
        database=project.source is not None,
        web=project.web is not None,
        files=bool(project.files),
    )


# ------------------------------------------------------------------- journeys
def _journey_dir(workdir: Path) -> Path:
    return workdir / "journeys"


def _journey_ids(args: argparse.Namespace, project: Project, workdir: Path) -> list[str]:
    if getattr(args, "journeys", None):
        return [j.strip() for j in args.journeys.split(",") if j.strip()]
    web = project.require_web()
    if web.journeys:
        return list(web.journeys)
    return sorted(p.stem for p in _journey_dir(workdir).glob("*.json"))


def _load_journey(store: Store, workdir: Path, journey_id: str) -> Journey:
    path = _journey_dir(workdir) / f"{journey_id}.json"
    if not path.exists() and not store.get_file(f"journeys/{journey_id}.json", path):
        raise ConfigError(f"journey {journey_id} not found; record it with liftproof record")
    journey = Journey.load(path)
    assets = _journey_dir(workdir) / journey_id / "assets"
    for step in journey.steps:
        for ex in step.exchanges:
            if ex.body_asset:
                local = assets / ex.body_asset.split("/")[-1]
                if not local.exists():
                    store.get_file(f"journeys/{journey_id}/{ex.body_asset}", local)
    return journey


def _save_journey(store: Store, workdir: Path, journey: Journey, assets: dict[str, bytes]) -> Path:
    base = _journey_dir(workdir)
    path = journey.save(base / f"{journey.journey_id}.json")
    store.put_file(f"journeys/{journey.journey_id}.json", path)
    for sha, body in assets.items():
        local = base / journey.journey_id / "assets" / sha
        local.parent.mkdir(parents=True, exist_ok=True)
        local.write_bytes(body)
        store.put_file(f"journeys/{journey.journey_id}/assets/{sha}", local)
    return path


def _journey_secrets(journey: Journey) -> dict[str, str]:
    unbound = journey.unbound_tokens()
    if unbound:
        fields = ", ".join(f"{t} ({journey.secrets[t].field})" for t in unbound)
        raise ConfigError(
            f"journey {journey.journey_id}: redaction tokens not bound to a secret: {fields}. "
            f"Bind each with: liftproof bind --journey {journey.journey_id} --token TOKEN "
            "--secret-arn ARN --key KEY"
        )
    return {t: secret_value(b.arn, b.key) for t, b in journey.secrets.items() if b.arn}


def _replay_into(
    args: argparse.Namespace, project: Project, store: Store, workdir: Path, writer: FindingWriter
) -> WebResult:
    from liftproof.web.compare import WebOptions
    from liftproof.web.run import run_journeys

    web = project.require_web()
    if not web.target_url:
        raise ConfigError("web.target_url is required to replay")
    journeys = [_load_journey(store, workdir, j) for j in _journey_ids(args, project, workdir)]
    if not journeys:
        raise ConfigError("no journeys recorded for this project; record one with liftproof record")
    options = WebOptions(
        compare_headers=web.compare_headers,
        ignore_json_paths=web.ignore_json_paths,
        ignore_text=web.ignore_text,
        show_values=bool(args.show_values or project.database.show_values),
    )
    return run_journeys(
        journeys,
        target_url=web.target_url,
        options=options,
        emit=writer.write,
        assets_dir=lambda j: _journey_dir(workdir) / j.journey_id / "assets",
        secret_values=_journey_secrets,
        step_timeout_ms=web.step_timeout_ms,
        executable_path=web.chromium_path,
        workers=web.parallel_journeys,
    )


def cmd_record(args: argparse.Namespace) -> int:
    from liftproof.web.browser import BodyPolicy
    from liftproof.web.recorder import Recorder

    project = _project(args)
    web = project.require_web()
    workdir = Path(args.workdir) / project.name
    store = _store(project, Path(args.workdir))
    recorder = Recorder(
        web.source_url,
        policy=BodyPolicy(web.capture_bodies),
        headless=False,
        executable_path=web.chromium_path,
    )
    print(
        "Recording. Carry out the journey in the browser window, then close the window.",
        file=sys.stderr,
    )
    journey, assets = recorder.record(args.journey, start=args.start, story=args.story)
    if args.writes:
        journey.writes_tables = [t.strip() for t in args.writes.split(",") if t.strip()]
    path = _save_journey(store, workdir, journey, assets)
    unconfirmed = [c.name for c in journey.correlations if not c.confirmed]
    _out(
        args,
        {
            "journey": journey.journey_id,
            "file": store.location(f"journeys/{journey.journey_id}.json"),
            "steps": len(journey.steps),
            "correlations": [c.name for c in journey.correlations],
            "unconfirmed_correlations": unconfirmed,
            "unbound_tokens": journey.unbound_tokens(),
        },
        f"recorded {journey.journey_id}: {len(journey.steps)} steps, "
        f"{len(journey.correlations)} correlations ({len(unconfirmed)} to confirm)\n"
        + "".join(
            f"bind {t} ({journey.secrets[t].field}): liftproof bind --project {args.project} "
            f"--journey {journey.journey_id} --token {t} --secret-arn ARN --key KEY\n"
            for t in journey.unbound_tokens()
        )
        + f"saved: {path}",
    )
    return EXIT_OK


def cmd_bind(args: argparse.Namespace) -> int:
    """Bind a redaction token to a secret, or confirm a correlation, in a journey file."""
    project = _project(args)
    workdir = Path(args.workdir) / project.name
    store = _store(project, Path(args.workdir))
    journey = _load_journey(store, workdir, args.journey)
    done = []
    if args.token:
        if args.token not in journey.secrets:
            raise ConfigError(f"journey {args.journey} has no token {args.token}")
        if not args.secret_arn:
            raise ConfigError("--secret-arn is required with --token")
        b = journey.secrets[args.token]
        b.arn, b.key = args.secret_arn, args.key
        done.append(f"{args.token} bound to {args.secret_arn} key {args.key}")
    for name in args.confirm or []:
        match = [c for c in journey.correlations if c.name == name]
        if not match:
            raise ConfigError(f"journey {args.journey} has no correlation {name}")
        match[0].confirmed = True
        done.append(f"correlation {name} confirmed")
    if not done:
        raise ConfigError("nothing to do: give --token with --secret-arn, or --confirm NAME")
    _save_journey(store, workdir, journey, {})
    _out(args, {"journey": args.journey, "changes": done}, "\n".join(done))
    return EXIT_OK


def _report(
    project,
    run_id,
    mode,
    run_dir,
    result,
    started,
    baseline,
    *,
    web_result=None,
    files_result=None,
    failure=None,
    template=None,
    scheduled=None,
) -> dict[str, Any]:
    findings = list(read_findings(run_dir))
    o = project.database
    range_block: dict[str, Any] = {"run_window": f"{started} to {_now()}"}
    metadata: dict[str, Any] = {
        "invoked_by": who_ran_it(),
        "values_shown": o.show_values,
    }
    if scheduled:
        metadata["schedule"] = scheduled
    if result is not None and project.source is not None:
        range_block.update(
            {
                "schemas": ", ".join(o.schemas),
                "tables": [t.table for t in result.tables],
                "source": project.source.describe(),
                "target": project.target.describe(),
                "reference": (
                    f"{baseline.side} baseline {baseline.baseline_id}"
                    if baseline
                    else "live source"
                ),
                "consistency_position": baseline.position if baseline else "live read",
                "replication": result.replication,
                "sampling": None
                if result.sample_seed is None
                else {
                    "above_rows": o.sample_above_rows,
                    "percent": o.sample_percent,
                    "seed": result.sample_seed,
                },
            }
        )
        metadata.update(
            {
                "tls": {"source": project.source.sslmode, "target": project.target.sslmode},
                "rows_per_bucket": o.rows_per_bucket,
                "timestamp_precision": o.precision,
            }
        )
    if web_result is not None:
        range_block.update(
            {
                "journeys": [j.journey for j in web_result.journeys],
                "web_source": project.web.source_url if project.web else None,
                "web_target": web_result.target_url,
                "journeys_in_parallel": web_result.parallel,
                "parallel_workers": web_result.workers,
            }
        )
        metadata["browser"] = web_result.browser
    if files_result is not None:
        range_block["file_sets"] = [
            {"name": s.name, "source": s.source, "target": s.target} for s in files_result.sets
        ]
    report = build_report(
        run_id=run_id,
        project=project.name,
        mode=mode,
        findings=findings,
        db=result,
        web=web_result,
        files=files_result,
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
    lines = [f"verdict: {report['verdict']}"]
    if c["tables"]:
        lines.append(
            f"tables: {c['tables']} ({c['tables_matched']} matched, {c['tables_different']} "
            "different)"
        )
    if c["journeys"]:
        lines.append(
            f"journeys: {c['journeys']} ({c['journeys_passed']} passed, "
            f"{c['journeys_different']} different, {c['journeys_failed']} failed)"
        )
    if c["files"]:
        lines.append(
            f"files: {c['files']} ({c['files_matched']} matched, {c['files_different']} "
            f"different, {c['files_missing']} missing)"
        )
    lines.append(f"differences: {c['differences']}, not checked: {c['not_checked']}")
    lines.append(f"report: {html}")
    _out(
        args,
        {
            "run_id": run_id,
            "verdict": report["verdict"],
            "counts": c,
            "coverage": {k: v for k, v in cov.items() if k.endswith("_pct")},
            "report_html": html,
            "report_json": store.location(f"runs/{run_id}/report.json"),
        },
        "\n".join(lines),
    )
    if report["failure"]:
        return EXIT_RUN_FAILED
    if args.fail_on == "never":
        return EXIT_OK
    if args.fail_on == "errors":
        return EXIT_DIFFERENCES if c["errors"] else EXIT_OK
    return EXIT_DIFFERENCES if c["differences"] or c["errors"] else EXIT_OK


def cmd_runs(args: argparse.Namespace) -> int:
    """Run history from the reports on this instance (spec 14)."""
    project = _project(args)
    runs_dir = Path(args.workdir) / project.name / "runs"
    rows = []
    for d in runs_dir.iterdir() if runs_dir.exists() else []:
        try:
            r = json.loads((d / "report.json").read_text(encoding="utf-8"))
        except (FileNotFoundError, ValueError):
            continue
        rows.append(
            {
                "run_id": r.get("run_id", d.name),
                "mode": r.get("mode"),
                "started_at": r.get("run", {}).get("started_at"),
                "verdict": r.get("verdict"),
                "differences": r.get("counts", {}).get("differences"),
                "schedule": r.get("run", {}).get("schedule"),
            }
        )
    rows.sort(key=lambda x: x["started_at"] or "", reverse=True)
    rows = rows[: args.limit]
    text = "\n".join(
        f"{x['started_at']}  {x['run_id']:<34} {x['mode'] or '':<10} {x['verdict'] or '':<16} "
        f"{x['schedule'] or 'by hand'}"
        for x in rows
    )
    _out(args, {"runs": rows}, text or "no runs yet")
    return EXIT_OK


def cmd_schedule(args: argparse.Namespace) -> int:
    from liftproof.schedule import next_runs

    project = _project(args)
    rows = next_runs(project.schedules, dt.datetime.now(dt.UTC))
    text = "\n".join(
        f"{r['name']:<16} {r['cron']:<18} {r['timezone']:<16} next {r['next_run_utc']}  "
        f"{r['command']}"
        for r in rows
    )
    _out(args, {"schedules": rows}, text or "this project has no schedules")
    return EXIT_OK


def cmd_scheduler(args: argparse.Namespace) -> int:
    from liftproof.schedule import Scheduler

    sched = Scheduler(Path(args.projects_dir), Path(args.workdir))
    if args.once:
        fired = sched.tick(wait=True)
        _out(
            args,
            {"fired": [f"{d.project}/{d.schedule.name}" for d in fired]},
            "\n".join(f"fired {d.project}/{d.schedule.name}" for d in fired) or "nothing due",
        )
        return EXIT_OK
    sched.serve(args.interval)
    return EXIT_OK


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
    web_file = run_dir / "web-results.json"
    files_file = run_dir / "files-results.json"
    report = _report(
        project,
        args.run,
        prior.get("mode", "reconcile"),
        run_dir,
        _load_results(run_dir) if (run_dir / "db-results.json").exists() else None,
        started,
        None,
        web_result=(
            WebResult.from_dict(json.loads(web_file.read_text(encoding="utf-8")))
            if web_file.exists()
            else None
        ),
        files_result=(
            FileResult.from_dict(json.loads(files_file.read_text(encoding="utf-8")))
            if files_file.exists()
            else None
        ),
        failure=prior.get("failure"),
        template=args.template,
    )
    store = _store(project, Path(args.workdir))
    for name in ("report.html", "report.json"):
        store.put_file(f"runs/{args.run}/{name}", run_dir / name)
    return _conclude(args, report, store, args.run)


def cmd_doctor(args: argparse.Namespace) -> int:
    checks = _doctor_checks(args, _project(args))
    failed = [c for c in checks if c["result"] == "fail"]
    text = "\n".join(
        f"[{'PASS' if c['result'] == 'pass' else 'FAIL'}] {c['check']}: "
        f"{c['detail']}" + (f"\n       fix: {c['remedy']}" if c.get("remedy") else "")
        for c in checks
    )
    _out(args, {"checks": checks, "ok": not failed}, text)
    return EXIT_CONFIG if failed else EXIT_OK


def _doctor_checks(args: argparse.Namespace, project: Project) -> list[dict[str, str]]:
    checks: list[dict[str, str]] = []

    def check(name: str, fn, remedy: str) -> None:
        try:
            detail = fn() or "ok"
            checks.append({"check": name, "result": "pass", "detail": str(detail)})
        except Exception as exc:  # every failure is reported, none stops the others
            msg = str(exc) if isinstance(exc, LiftproofError) else f"{type(exc).__name__}: {exc}"
            checks.append(
                {"check": name, "result": "fail", "detail": logs.scrub(msg), "remedy": remedy}
            )

    connections = [("source", project.source), ("target", project.target)]
    for role, conn in [(r, c) for r, c in connections if c is not None]:
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
                    cur.execute(a.hash_probe)
                if r == "source" and hasattr(a, "snapshot_available"):
                    _assert(
                        a.snapshot_available(),
                        "snapshot isolation is off: a baseline of a live source is not "
                        "consistent (ALTER DATABASE ... SET ALLOW_SNAPSHOT_ISOLATION ON)",
                    )
                return f"connected to {c.describe()}"

        check(
            f"{role} database connection" + (" and read only user" if role == "source" else ""),
            _conn_check,
            "check the route (VPN, Direct Connect, security groups) and the grants: the "
            "source user needs SELECT only",
        )
    rep = project.database.replication
    if rep.method != "none" and project.source is not None and project.target is not None:

        def _replication():
            conn = project.source if rep.method in SOURCE_SIDE else project.target
            with connect(conn) as a:
                if rep.method not in a.replication_methods:
                    raise ConfigError(f"{rep.method} is not available for {a.engine}")
                if rep.method == "dms":
                    row = a.dms_status(rep.control_schema or a.dms_schema, rep.name or "")
                    _assert(row is not None, f"DMS task {rep.name!r} not in awsdms_status")
                    return (
                        f"dms task {rep.name}: {str(row['task_status']).strip().lower()}, "
                        f"{row['pending_changes']} changes pending"
                    )
                applied = a.replication_applied(rep.method, rep.name or "")
                _assert(applied is not None, f"{rep.method} {rep.name or ''!r} not found")
                return f"{rep.method} {rep.name or ''} has applied {applied}".replace("  ", " ")

        check(
            f"replication {rep.method} readable",
            _replication,
            {
                "dms": "turn on StatusTableEnabled in the task settings, set control_schema "
                "if the task sets ControlSchema, and grant SELECT on awsdms_status",
                "replica": "SHOW REPLICA STATUS needs the REPLICATION CLIENT privilege",
            }.get(
                rep.method,
                "check the name; reading pg_stat_subscription or pg_replication_slots needs "
                "the pg_monitor role (or pg_read_all_stats)",
            ),
        )
    if project.web is not None:
        workdir = Path(args.workdir) / project.name
        store = _store(project, Path(args.workdir))
        for jid in _journey_ids(args, project, workdir):

            def _tokens(j=jid):
                journey = _load_journey(store, workdir, j)
                values = _journey_secrets(journey)
                return f"{len(values)} secret(s) resolve" if values else "no secrets needed"

            check(
                f"journey {jid} secrets resolve",
                _tokens,
                "bind every redaction token with liftproof bind, and grant "
                "secretsmanager:GetSecretValue on the secrets",
            )

        def _browser():
            from playwright.sync_api import sync_playwright

            from liftproof.web.browser import launch

            with sync_playwright() as pw:
                b = launch(pw, executable_path=project.web.chromium_path)
                version = b.version
                b.close()
            return f"chromium {version}"

        check("browser starts", _browser, "the AMI ships Chromium; set web.chromium_path")
    for fs in project.files:
        for which in ("source", "target"):

            def _listing(c=fs, w=which):
                from liftproof.files.sources import open_source

                src = open_source(
                    getattr(c, w),
                    endpoint_url=getattr(c, f"{w}_endpoint_url"),
                    secret_arn=getattr(c, f"{w}_secret_arn"),
                )
                n = 0
                for _ in src.entries():
                    n += 1
                    if n >= 1000:
                        break
                return f"{src.describe()}: {n if n < 1000 else '1000+'} file(s) listed"

            check(
                f"file set {fs.name} {which} readable",
                _listing,
                "mount the share on the instance read only, or grant s3:ListBucket and "
                "s3:GetObject on the prefix to the instance role",
            )
    if project.store.s3_bucket:

        def _s3():
            import tempfile

            store = S3Store(
                project.store.s3_bucket, project.store.s3_prefix, project.store.kms_key_id
            )
            with tempfile.NamedTemporaryFile() as tmp:
                tmp.write(b"liftproof doctor probe")
                tmp.flush()
                store.put_file("doctor/probe.txt", Path(tmp.name))
            return store.location("doctor/probe.txt")

        check(
            "S3 bucket writable with KMS encryption",
            _s3,
            "grant s3:PutObject on the bucket and kms:GenerateDataKey on the key; for a "
            "customer managed key the key policy must also allow the instance role",
        )
    return checks


def cmd_support_bundle(args: argparse.Namespace) -> int:
    """One file for a support ticket (spec 13), values redacted. See liftproof.support."""
    project = _project(args)
    workdir = Path(args.workdir) / project.name
    run_id = args.run or support.latest_run(workdir / "runs")
    if args.run and not (workdir / "runs" / args.run).exists():
        raise ConfigError(f"run {args.run} not found under {workdir / 'runs'}")
    name = f"support-{project.name}-{_new_id('s')[2:]}.zip"
    out = Path(args.out) if args.out else workdir / "support" / name
    log_file = Path(os.environ.get("LIFTPROOF_LOG_DIR", "/var/log/mvt")) / "liftproof.log"
    manifest = support.build(
        out,
        project=project,
        workdir=workdir,
        run_id=run_id,
        log_file=log_file,
        instance_config=_instance_config(),
        doctor=_doctor_checks(args, project) if args.doctor else None,
    )
    store = _store(project, Path(args.workdir))
    key = f"support/{out.name}"
    store.put_file(key, out)
    payload = {"bundle": str(out), "stored": store.location(key), **manifest}
    _out(
        args,
        payload,
        f"support bundle: {out}\nalso stored at: {store.location(key)}\n"
        f"run: {run_id or 'none'}; {len(manifest['contents'])} files, values redacted\n"
        "attach the file to your support ticket",
    )
    return EXIT_OK


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
        prog="liftproof", description="Liftproof migration validation", parents=[common]
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
    s.add_argument("--scheduled", metavar="SCHEDULE", help=argparse.SUPPRESS)
    s.set_defaults(fn=cmd_baseline)

    s = with_project("rebaseline", "snapshot the target as the new reference, after cutover")
    s.add_argument("--tables", help="comma separated subset")
    s.add_argument("--baseline-id")
    s.add_argument("--resume", action="store_true", help="continue an interrupted rebaseline")
    s.add_argument("--scheduled", metavar="SCHEDULE", help=argparse.SUPPRESS)
    s.set_defaults(fn=cmd_rebaseline)

    s = with_project("reconcile", "compare the target database against the source")
    s.add_argument(
        "--baseline",
        help="baseline id, 'latest' (source) or 'latest-target' (rebaseline); "
        "default: live source only",
    )
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
    s.add_argument("--scheduled", metavar="SCHEDULE", help=argparse.SUPPRESS)
    s.set_defaults(fn=cmd_reconcile)

    def run_flags(s, database: bool) -> None:
        s.add_argument("--journeys", help="comma separated journey ids; default: all")
        s.add_argument(
            "--show-values",
            action="store_true",
            help="print values in the report (the report becomes an egress path)",
        )
        s.add_argument("--run-id")
        s.add_argument("--template", help="directory holding a custom report.html.j2")
        s.add_argument("--scheduled", metavar="SCHEDULE", help=argparse.SUPPRESS)
        if database:
            s.add_argument("--baseline", help="baseline id, 'latest' or 'latest-target'")
            s.add_argument("--no-source", action="store_true")
            s.add_argument("--tables", help="comma separated subset")

    s = with_project("record", "record a user journey on the source application")
    s.add_argument("--journey", required=True, help="journey id, e.g. checkout-flow")
    s.add_argument("--start", default="/", help="path to open first")
    s.add_argument("--story", help="user story label, for traceability")
    s.add_argument("--writes", help="comma separated tables the journey writes to")
    s.set_defaults(fn=cmd_record)

    s = with_project("bind", "bind a redaction token to a secret, or confirm a correlation")
    s.add_argument("--journey", required=True)
    s.add_argument("--token")
    s.add_argument("--secret-arn")
    s.add_argument("--key", default="password")
    s.add_argument("--confirm", action="append", help="correlation name to confirm")
    s.set_defaults(fn=cmd_bind)

    s = with_project("replay", "replay journeys against the target and compare")
    run_flags(s, database=False)
    s.set_defaults(fn=cmd_replay)

    s = with_project("smoke", "replay a named subset of journeys (cutover pipelines)")
    run_flags(s, database=False)
    s.set_defaults(fn=cmd_replay)

    s = with_project("files", "compare the files of each file set, source against target")
    s.add_argument("--sets", help="comma separated file set names; default: all")
    s.add_argument(
        "--show-values",
        action="store_true",
        help="print differing text in the report (the report becomes an egress path)",
    )
    s.add_argument("--run-id")
    s.add_argument("--template", help="directory holding a custom report.html.j2")
    s.add_argument("--scheduled", metavar="SCHEDULE", help=argparse.SUPPRESS)
    s.set_defaults(fn=cmd_files)

    s = with_project("validate", "full run: reconcile, compare files, then replay, then one report")
    run_flags(s, database=True)
    s.add_argument("--sets", help="comma separated file set names; default: all")
    s.set_defaults(fn=cmd_validate)

    s = with_project("runs", "list this project's runs, newest first")
    s.add_argument("--limit", type=int, default=20)
    s.set_defaults(fn=cmd_runs)

    s = sub.add_parser("schedule", parents=[common], help="show a project's schedules")
    s.add_argument("--project", required=True, help="project YAML file")
    s.set_defaults(fn=cmd_schedule)

    s = sub.add_parser("scheduler", parents=[common], help="run scheduled runs (the service)")
    s.add_argument("--projects-dir", default=str(DEFAULT_WORKDIR))
    s.add_argument("--once", action="store_true", help="fire what is due now, then exit")
    s.add_argument("--interval", type=float, default=30.0, help=argparse.SUPPRESS)
    s.set_defaults(fn=cmd_scheduler)

    s = with_project("support-bundle", "package logs and findings, values redacted, for support")
    s.add_argument("--run", help="run id; default: the latest run")
    s.add_argument("--doctor", action="store_true", help="also run doctor and include it")
    s.add_argument("--out", help="bundle path; default: under the work directory")
    s.set_defaults(fn=cmd_support_bundle)

    s = with_project("report", "regenerate a report from a run's findings")
    s.add_argument("--run", required=True)
    s.add_argument("--template", help="directory holding a custom report.html.j2")
    s.set_defaults(fn=cmd_report)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    log_dir = Path(os.environ.get("LIFTPROOF_LOG_DIR", "/var/log/mvt"))
    logs.setup(
        args.log_level, str(log_dir / "liftproof.log") if os.access(log_dir, os.W_OK) else None
    )
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
            "unexpected failure; run `liftproof` with --log-level debug and raise a ticket",
            file=sys.stderr,
        )
        print(logs.scrub(traceback.format_exc()), file=sys.stderr)
        return EXIT_RUN_FAILED


if __name__ == "__main__":
    sys.exit(main())
