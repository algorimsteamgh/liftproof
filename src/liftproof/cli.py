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
from liftproof import checkpoint as ckpt
from liftproof.adapters.base import Adapter
from liftproof.adapters.mysql import MySQLAdapter
from liftproof.adapters.oracle import OracleAdapter
from liftproof.adapters.postgres import PostgresAdapter
from liftproof.adapters.sqlserver import SQLServerAdapter
from liftproof.canonical import CANONICAL_REVISION, CANONICAL_VERSION, HASH_ALGORITHM
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
from liftproof.reconcile import watermark
from liftproof.reconcile.baseline import Baseline, take_baseline
from liftproof.reconcile.engine import Reconciler, ReconcileResult, TableResult
from liftproof.reconcile.replication import SOURCE_SIDE
from liftproof.report.builder import build_report, who_ran_it, write_reports
from liftproof.runlock import RunInProgress
from liftproof.store import LocalStore, S3Store, Store
from liftproof.web import correlate
from liftproof.web.journey import Journey
from liftproof.web.run import WebResult

log = logging.getLogger("liftproof.cli")

DEFAULT_WORKDIR = Path(os.environ.get("LIFTPROOF_WORKDIR", "/var/lib/mvt/projects"))
PROJECT_KEY = "project.yaml"  # the project file, in the store (spec 4)
# Every project's file again, at the bucket root, where `liftproof restore` finds them all
# whatever prefix each project uses.
PROJECT_INDEX = ".liftproof/projects"


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


# The AMI ships the system CA certificates and the Amazon RDS CA bundle in one file
# (spec 15), so RDS and publicly signed endpoints verify with no setting. A project's
# own sslrootcert (a private CA) takes its place.
CA_BUNDLE = Path(os.environ.get("LIFTPROOF_CA_BUNDLE", "/opt/mvt/certs/ca-bundle.pem"))


def _sslrootcert(conn: Connection) -> str | None:
    if conn.sslrootcert or not conn.tls_verified:
        return conn.sslrootcert
    return str(CA_BUNDLE) if CA_BUNDLE.is_file() else None


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
        sslrootcert=_sslrootcert(conn),
        statement_timeout_ms=conn.statement_timeout_ms,
        lock_timeout_ms=conn.lock_timeout_ms,
        rows_per_second=conn.rows_per_second,
        pause_ms=conn.pause_ms,
        read_only=True,
    )


INSTANCE_CONFIG = Path(os.environ.get("LIFTPROOF_INSTANCE_CONFIG", "/etc/mvt/config.yaml"))


def _instance_config() -> dict[str, Any]:
    """Instance level settings written at launch by the deployment template."""
    try:
        return yaml.safe_load(INSTANCE_CONFIG.read_text(encoding="utf-8")) or {}
    except FileNotFoundError:
        return {}
    except PermissionError:
        # Carrying on without them would quietly drop the deployment's bucket, key and
        # report lock, so this is a configuration error, not a default.
        raise ConfigError(
            f"cannot read the instance settings in {INSTANCE_CONFIG}; run Liftproof as "
            "the mvt user (sudo -u mvt liftproof ...)"
        ) from None


def _configure_aws() -> None:
    """The deployment's region, and its ceiling on AWS calls per second (AWSAPI-002)."""
    try:
        inst = _instance_config()
    except ConfigError:
        inst = {}  # a command that needs the settings says so itself
    aws.configure_region(inst.get("region"))
    rate = inst.get("aws_requests_per_second")
    try:
        aws.configure_rate_limit(float(rate) if rate else aws.DEFAULT_RATE)
    except (TypeError, ValueError):
        raise ConfigError(
            f"aws_requests_per_second in {INSTANCE_CONFIG} is not a number: {rate!r}"
        ) from None


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
        "canonical_revision": CANONICAL_REVISION,
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
    marker = Path(args.workdir) / project.name / ckpt.baseline_marker(side)
    baseline_id = args.baseline_id
    if baseline_id is None and args.resume:
        # the interrupted one, wherever it ran: the marker is in the store
        baseline_id = ckpt.read_marker(store, marker, ckpt.baseline_marker(side))
        if baseline_id is None:
            raise ConfigError(f"no interrupted {side} baseline to resume; give --baseline-id")
    baseline_id = baseline_id or _new_id("b" if side == "source" else "t")
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
    marker_key = ckpt.baseline_marker(side)
    marker_local = workdir / marker_key
    ckpt.set_marker(store, marker_local, marker_key, baseline_id)
    throttle = ckpt.Throttle()
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
            # each finished table reaches the store, so a lost instance resumes (9.16)
            checkpoint=lambda: throttle.due() and ckpt.keep(store, key, manifest),
            with_ranges=o.ranges,
        )
    store.put_file(key, manifest)
    ckpt.set_marker(store, marker_local, marker_key, "")
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
    baseline = Baseline.load(path)
    if not baseline.complete:
        how = "baseline" if baseline.side == "source" else "rebaseline"
        raise ConfigError(
            f"baseline {bid} is unfinished ({len(baseline.tables)} of "
            f"{len(baseline.selection)} tables); finish it with "
            f"liftproof {how} --resume --baseline-id {bid}"
        )
    return baseline


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
    args: argparse.Namespace,
    project: Project,
    store: Store,
    workdir: Path,
    writer: FindingWriter,
    checkpoint: ckpt.RunCheckpoint | None = None,
) -> tuple[ReconcileResult, Baseline | None]:
    """The database comparison of a run. Failures propagate to _run, which records them.
    With a checkpoint, finished tables reach the store as the run goes, and a resumed run
    carries on after them."""
    src_conn, tgt_conn = project.require_database()
    o = project.database
    if getattr(args, "tables", None):
        o.tables = _tables(args)
    if args.show_values:
        o.show_values = True
    baseline = _load_baseline(args, project, store, workdir)
    progress = checkpoint.progress if checkpoint is not None else None
    resuming = progress is not None and progress.prelude_done
    if progress is not None:
        progress.baseline = baseline.baseline_id if baseline is not None else None
        if resuming and progress.sample_seed is not None:
            o.sample_seed = progress.sample_seed
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
        for conn in (src_conn, tgt_conn) if not resuming else ():  # written the first time
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
        if not getattr(args, "include_replay_rows", False):
            o = _without_replay_rows(o, store, workdir, target, baseline)
        rec = Reconciler(
            target, writer, o, source=source, baseline=baseline, progress=lambda m: log.info(m),
            on_table=checkpoint.table_done if checkpoint is not None else None,
            done=progress.done() if resuming else (),
            resumed=resuming,
            systemic=progress.systemic if resuming else False,
        )  # fmt: skip
        # what limited the load on each database this run read (spec 9.15)
        rec.result.protection = {
            **({"source": source.protection()} if source is not None else {}),
            "target": target.protection(),
            "workers": o.workers,
        }
        if progress is not None:
            progress.sample_seed = rec.seed
        result = rec.run()
        if checkpoint is not None:
            checkpoint.save(result, complete=True)
            try:
                ckpt.set_marker(store, workdir / ckpt.RUN_MARKER, ckpt.RUN_MARKER, "")
            except LiftproofError as exc:  # --resume then finds the run complete and says so
                log.warning("could not clear the in-progress run marker: %s", exc)
        return result, baseline
    except Exception as exc:
        if rec is not None:
            # coverage counts what exists, not only what finished (spec 12, 18)
            rec.mark_unfinished(f"{type(exc).__name__}: {logs.scrub(str(exc))}"[:300])
        exc.partial_result = rec.result if rec else ReconcileResult()  # type: ignore[attr-defined]
        exc.baseline = baseline  # type: ignore[attr-defined]
        raise
    finally:
        for a in (source, target):
            if a is not None:
                a.close()


def _without_replay_rows(o, store: Store, workdir: Path, target: Adapter, baseline):
    """The options with the rows earlier replays created left out on the target."""
    from dataclasses import replace

    local = workdir / watermark.STORE_KEY
    store.get_file(watermark.STORE_KEY, local)
    since = baseline.taken_at if baseline is not None and baseline.side == "target" else None
    extra = watermark.rules(watermark.load(local), target, since)
    return replace(o, ignore=[*o.ignore, *extra]) if extra else o


def _replay_watermarks(project: Project, journeys: list[Journey], writer: FindingWriter):
    """Open the target database and read the watermark of every table the journeys
    write, before the replay. None when there is nothing to read; trouble is reported,
    never fatal to the replay."""
    wanted = [t for j in journeys for t in j.writes_tables]
    if not wanted or project.target is None:
        return None
    o = project.database
    try:
        target = connect(project.target)
    except Exception as exc:  # noqa: BLE001 - the replay goes ahead without marks
        _replay_mark_notice(writer, exc)
        return None
    try:
        schemas = list(dict.fromkeys(o.schema_map.get(x, x) for x in o.schemas))
        tables, problems = watermark.resolve(target, schemas, wanted, o.replay_watermarks)
        for p in problems:
            _replay_mark_notice(writer, p)
        return target, tables, watermark.read(target, tables)
    except Exception as exc:  # noqa: BLE001 - as above
        target.close()
        _replay_mark_notice(writer, exc)
        return None


def _replay_mark_notice(writer: FindingWriter, problem: object) -> None:
    writer.write(Finding(Comparator.DATABASE, Kind.NOTICE, Severity.LOW, "replay",
                         f"replay rows cannot be marked: {problem}"))  # fmt: skip


REPLAY_ROWS_HELP = "compare the rows earlier replays created on the target too (default: left out)"


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
        _publish_project(project, store)
        return body()
    finally:
        lock.__exit__(None, None, None)


def _publish_project(project: Project, store: Store) -> None:
    """Every run copies its project file to the store (spec 3, 4): connections (secret
    ARNs, never credentials), rules and schedules then outlive the instance, and
    `liftproof restore` brings them back on a replacement."""
    if project.path is None or not Path(project.path).is_file():
        return
    ckpt.keep(store, PROJECT_KEY, Path(project.path))
    if isinstance(store, S3Store):
        index = S3Store(store.bucket, "", store.kms_key_id, client=store.s3)
        ckpt.keep(index, f"{PROJECT_INDEX}/{project.name}.yaml", Path(project.path))


def cmd_restore(args: argparse.Namespace) -> int:
    """Put the deployment's project files back on this instance from the bucket. A
    replacement instance runs this at boot (mvt-restore.service), so the scheduler and
    the UI find every project again; recordings, baselines and reports are read from the
    bucket as they are needed. A project file already on the instance is never replaced."""
    inst = _instance_config()
    bucket = args.bucket or inst.get("bucket")
    if not bucket:
        raise ConfigError("no bucket: this instance has no deployment settings; give --bucket")
    store = S3Store(bucket, "", inst.get("kms_key"))
    projects_dir = Path(args.projects_dir)
    projects_dir.mkdir(parents=True, exist_ok=True)
    restored: list[str] = []
    kept: list[str] = []
    unreadable: list[str] = []
    for key in store.list_keys(f"{PROJECT_INDEX}/"):
        name = key[len(PROJECT_INDEX) + 1 :]
        if "/" in name or not name.endswith(".yaml"):
            continue
        dest = projects_dir / name
        if dest.exists():
            kept.append(name)
            continue
        partial = dest.with_suffix(".partial")
        if not store.get_file(key, partial):
            continue
        try:
            load_project(partial)
        except ConfigError as exc:
            log.warning("not restoring %s: %s", name, exc)
            partial.unlink(missing_ok=True)
            unreadable.append(name)
            continue
        partial.replace(dest)
        restored.append(name)
    payload = {"bucket": bucket, "restored": restored, "kept": kept, "unreadable": unreadable}
    text = [f"restored {len(restored)} project file(s) from s3://{bucket} to {projects_dir}"]
    text += [f"  restored {n}" for n in restored]
    text += [f"  kept {n} (already on this instance)" for n in kept]
    text += [f"  skipped {n} (not a valid project file)" for n in unreadable]
    _out(args, payload, "\n".join(text))
    return EXIT_OK


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
    if getattr(args, "resume", False) and not args.run_id:
        marker = Path(args.workdir) / project.name / ckpt.RUN_MARKER
        run_id = ckpt.read_marker(store, marker, ckpt.RUN_MARKER) or ""
        if not run_id:
            raise ConfigError("no interrupted reconciliation to resume; give --run-id")
    return _locked(
        args, project, store, run_id, mode,
        lambda: _run_locked(args, mode, project, store, run_id, database, web, files),
    )  # fmt: skip


# Findings reach the store at least this often while a run goes (spec 3).
SEGMENT_SECONDS = 60.0
# What a resumed reconciliation must be asked again, exactly as the first time.
RESUMED_OPTIONS = ("tables", "no_source", "show_values", "include_replay_rows")


def _restore_run(store: Store, run_dir: Path, run_id: str) -> ckpt.RunProgress:
    """The progress of an interrupted reconciliation and the findings it had written,
    from the store: the instance that ran it may be gone."""
    local = run_dir / ckpt.PROGRESS
    run_dir.mkdir(parents=True, exist_ok=True)
    if not store.get_file(f"runs/{run_id}/{ckpt.PROGRESS}", local) and not local.exists():
        raise ConfigError(f"run {run_id} has no saved progress to resume")
    progress = ckpt.RunProgress.load(local)
    if progress.complete:
        raise ConfigError(f"run {run_id} finished every table; there is nothing to resume")
    if progress.canonical_revision != CANONICAL_REVISION:
        # its finished tables were hashed under other rules than the rest would be
        raise ConfigError(
            f"run {run_id} was started under canonical revision {progress.canonical_revision} "
            f"and this build hashes under revision {CANONICAL_REVISION}; start a new run"
        )
    for name in progress.segments:
        seg = run_dir / name
        if not store.get_file(f"runs/{run_id}/{name}", seg) and not seg.exists():
            raise ConfigError(f"run {run_id}: findings segment {name} is missing from the store")
    return progress


def _void_later_segments(store: Store, run_dir: Path, run_id: str, keep: list[str]) -> None:
    """Segments the interrupted attempt wrote after its last checkpoint hold findings of
    tables that are compared again; emptied in the store so they are not read twice."""
    empty = run_dir / "empty.partial"
    empty.write_text("", encoding="utf-8")
    for key in store.list_keys(f"runs/{run_id}/findings-"):
        if key.rsplit("/", 1)[-1] not in keep and key.endswith(".jsonl"):
            store.put_file(key, empty)
    empty.unlink()


def _run_locked(args, mode, project, store, run_id, database, web, files) -> int:
    workdir = Path(args.workdir) / project.name
    run_dir = workdir / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    logs.set_context(run_id=run_id, project=project.name)
    started = _now()
    progress = None
    if getattr(args, "resume", False):
        progress = _restore_run(store, run_dir, run_id)
        for name in RESUMED_OPTIONS:
            setattr(args, name, progress.options.get(name))
        args.baseline = progress.baseline
        started = progress.started_at
        progress.resumed_at.append(_now())
    uploads = ckpt.SegmentUploads(store, run_id, progress.segments if progress else ())
    writer = FindingWriter(
        run_dir, run_id, flush_seconds=SEGMENT_SECONDS, on_segment=uploads,
        keep=progress.segments if progress is not None else None,
    )  # fmt: skip
    if progress is not None:
        _void_later_segments(store, run_dir, run_id, progress.segments)
    checkpoint = None
    if mode == "reconcile":
        progress = progress or ckpt.RunProgress(
            run_id, started, {k: getattr(args, k, None) for k in RESUMED_OPTIONS}
        )
        checkpoint = ckpt.RunCheckpoint(store, run_dir, progress, writer, uploads)
        ckpt.set_marker(store, workdir / ckpt.RUN_MARKER, ckpt.RUN_MARKER, run_id)
    result: ReconcileResult | None = ReconcileResult() if database else None
    web_result = None
    files_result: FileResult | None = None
    baseline = None
    failure: str | None = None
    stage = Comparator.DATABASE
    try:
        if database:
            try:
                result, baseline = _reconcile_into(
                    args, project, store, workdir, writer, checkpoint
                )
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

    not_reached: list[dict[str, str]] = []
    if failure and files and files_result is None:
        not_reached += [{"object": f"file set {c.name}", "reason": STOPPED} for c in project.files]
    if failure and web and web_result is None:
        try:
            ids = _journey_ids(args, project, workdir, store)
        except LiftproofError:  # the report still names the failure itself
            ids = []
        not_reached += [{"object": f"journey {j}", "reason": STOPPED} for j in ids]
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
        not_reached=not_reached,
        resumed_at=progress.resumed_at if progress is not None else None,
        values_shown=bool(
            getattr(args, "show_values", False)
            or project.database.show_values
            or (files and any(c.show_content for c in project.files))
        ),
    )
    for f in sorted(run_dir.iterdir()):
        if f.name not in uploads.done:  # segments went up as they closed
            store.put_file(f"runs/{run_id}/{f.name}", f)
    return _conclude(args, report, store, run_id)


STOPPED = "the run stopped before this was compared"


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


def _journey_ids(
    args: argparse.Namespace, project: Project, workdir: Path, store: Store
) -> list[str]:
    if getattr(args, "journeys", None):
        return [j.strip() for j in args.journeys.split(",") if j.strip()]
    web = project.require_web()
    if web.journeys:
        return list(web.journeys)
    return journey_index(store, workdir)


def journey_index(store: Store, workdir: Path) -> list[str]:
    """Every journey recorded for the project: those on this instance and those in the
    store, recorded on another machine or before this instance replaced one (spec 4)."""
    local = {p.stem for p in _journey_dir(workdir).glob("*.json")}
    stored = {
        key.split("/")[1][: -len(".json")]
        for key in store.list_keys("journeys/")
        if key.count("/") == 1 and key.endswith(".json")
    }
    return sorted(local | stored)


def _load_journey(store: Store, workdir: Path, journey_id: str) -> Journey:
    path = _journey_dir(workdir) / f"{journey_id}.json"
    if not path.exists() and not store.get_file(f"journeys/{journey_id}.json", path):
        raise ConfigError(f"journey {journey_id} not found; record it with liftproof record")
    journey = Journey.load(path)
    for c in journey.correlations:
        try:
            correlate.check_chain(c.transforms, c.encodings)
        except ValueError as exc:
            raise ConfigError(f"journey {journey_id}, correlation {c.name}: {exc}") from None
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
    journeys = [
        _load_journey(store, workdir, j) for j in _journey_ids(args, project, workdir, store)
    ]
    if not journeys:
        raise ConfigError("no journeys recorded for this project; record one with liftproof record")
    options = WebOptions(
        compare_headers=web.compare_headers,
        ignore_json_paths=web.ignore_json_paths,
        ignore_text=web.ignore_text,
        show_values=bool(args.show_values or project.database.show_values),
    )
    marks = _replay_watermarks(project, journeys, writer)
    try:
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
    finally:
        if marks is not None:
            _record_replay_windows(marks, store, workdir, writer)


def _record_replay_windows(marks, store: Store, workdir: Path, writer: FindingWriter) -> None:
    """Read the watermarks again and keep the windows with the project, for the
    reconciliations that follow. Trouble is a notice, never the replay's failure."""
    target, tables, before = marks
    try:
        after = watermark.read(target, tables)
        new, problems = watermark.windows(tables, before, after, writer.run_id)
        for p in problems:
            _replay_mark_notice(writer, p)
        if new:
            local = workdir / watermark.STORE_KEY
            store.get_file(watermark.STORE_KEY, local)
            watermark.save(local, [*watermark.load(local), *new])
            store.put_file(watermark.STORE_KEY, local)
    except Exception as exc:  # noqa: BLE001 - the replay's own results still stand
        _replay_mark_notice(writer, exc)
    finally:
        target.close()


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
    not_reached=None,
    resumed_at=None,
    values_shown=None,
    finished_at=None,
    prior=None,
    canonical_revision=None,
) -> dict[str, Any]:
    """`prior` is the run's own report when one is regenerated: what the run was (its
    reference, window, schedule, who ran it, versions) is taken from it as recorded,
    never restated from today's project file. `canonical_revision`: the one a run that
    wrote no report hashed under, from its checkpoint."""
    findings = list(read_findings(run_dir))
    o = project.database
    finished_at = finished_at or _now()
    if prior:
        return _rewrite_report(project, run_id, mode, run_dir, findings, result, started,
                               web_result, files_result, failure, template, prior)  # fmt: skip
    range_block: dict[str, Any] = {"run_window": f"{started} to {finished_at}"}
    metadata: dict[str, Any] = {
        "invoked_by": who_ran_it(),
        "values_shown": bool(o.show_values if values_shown is None else values_shown),
    }
    if scheduled:
        metadata["schedule"] = scheduled
    if canonical_revision is not None:
        metadata["canonical_revision"] = canonical_revision
    if resumed_at:
        # tables finished before a resume were read then; the rest after it
        metadata["resumed_at"] = list(resumed_at)
        range_block["resumed_at"] = list(resumed_at)
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
                # lowest and highest key and dates of the rows compared, per side
                "data_ranges": {t.table: t.ranges for t in result.tables if t.ranges},
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
        if result.protection:
            metadata["source_protection"] = result.protection
    if web_result is not None:
        range_block.update(
            {
                "journeys": [j.journey for j in web_result.journeys],
                "endpoints": [e["endpoint"] for e in web_result.endpoints],
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
        finished_at=finished_at,
        metadata=metadata,
        range_block=range_block,
        run_failed=failure is not None,
        failure=failure,
        not_reached=not_reached,
    )
    write_reports(report, run_dir, Path(template) if template else None)
    return report


def _rewrite_report(project, run_id, mode, run_dir, findings, result, started, web_result,
                    files_result, failure, template, prior) -> dict[str, Any]:  # fmt: skip
    run = dict(prior.get("run", {}))
    run.setdefault("canonical_revision", 0)  # a run from before canonical revisions
    finished = run.pop("finished_at", None) or _now()
    run.pop("started_at", None)
    run["regenerated"] = {"at": _now(), "by": who_ran_it(), "product_version": __version__}
    not_reached = [
        c for c in prior.get("coverage", {}).get("not_covered", [])
        if c.get("reason") == STOPPED
    ]  # fmt: skip
    report = build_report(
        run_id=run_id,
        project=project.name,
        mode=mode,
        findings=findings,
        db=result,
        web=web_result,
        files=files_result,
        started_at=started,
        finished_at=finished,
        metadata=run,
        range_block=dict(prior.get("range", {})),
        run_failed=failure is not None,
        failure=failure,
        not_reached=not_reached,
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
    """Run history (spec 14): every report in the store, whichever instance ran it."""
    project = _project(args)
    runs_dir = Path(args.workdir) / project.name / "runs"
    sync_reports(_store(project, Path(args.workdir)), runs_dir)
    rows = run_history(runs_dir)[: args.limit]
    text = "\n".join(
        f"{x['started_at']}  {x['run_id']:<34} {x['mode'] or '':<10} {x['verdict'] or '':<16} "
        f"{x['schedule'] or 'by hand'}"
        for x in rows
    )
    _out(args, {"runs": rows}, text or "no runs yet")
    return EXIT_OK


def sync_reports(store: Store, runs_dir: Path) -> None:
    """Copy the reports of runs this instance does not hold (another instance's, or a
    replaced one's) from the store."""
    for key in store.list_keys("runs/"):
        parts = key.split("/")
        if len(parts) == 3 and parts[2] == "report.json":
            local = runs_dir / parts[1] / "report.json"
            if not local.exists():
                store.get_file(key, local)


def run_history(runs_dir: Path) -> list[dict[str, Any]]:
    """The runs whose reports are on this instance, newest first."""
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
                "invoked_by": r.get("run", {}).get("invoked_by"),
            }
        )
    rows.sort(key=lambda x: x["started_at"] or "", reverse=True)
    return rows


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


UI_PORT = 8080  # the port the deployment templates forward


def cmd_ui(args: argparse.Namespace) -> int:
    """The local web UI (spec 4): 127.0.0.1 only, reached through SSM port forwarding."""
    from liftproof.ui.server import UI, make_server, new_login

    workdir = Path(args.workdir)
    server = make_server(UI(Path(args.projects_dir), workdir), args.host, args.port)
    print(f"Liftproof UI on http://127.0.0.1:{server.server_address[1]}", file=sys.stderr)
    if sys.stderr.isatty():  # a login link goes to a terminal, never to a service's log
        print(f"sign in: {_login_url(server.server_address[1], new_login(workdir))}",
              file=sys.stderr)  # fmt: skip
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return EXIT_OK


def _login_url(port: int, code: str) -> str:
    return f"http://127.0.0.1:{port}/login?code={code}"


def cmd_ui_login(args: argparse.Namespace) -> int:
    """A one time login link for the UI: ten minutes, one use."""
    from liftproof.ui.server import LOGIN_SECONDS, new_login

    url = _login_url(args.port, new_login(Path(args.workdir)))
    minutes = LOGIN_SECONDS // 60
    text = f"{url}\n(one use, within {minutes} minutes, through the port forwarding session)"
    _out(args, {"login_url": url, "valid_minutes": minutes, "uses": 1}, text)
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
    store = _store(project, Path(args.workdir))
    baseline = None
    revision = None
    progress_file = run_dir / ckpt.PROGRESS
    if not prior and progress_file.exists():
        # no report was written (the run stopped): its checkpoint names the reference
        # and the rules it hashed under
        progress = ckpt.RunProgress.load(progress_file)
        started = progress.started_at
        revision = progress.canonical_revision
        if progress.baseline:
            baseline = _baseline_by_id(store, workdir, progress.baseline)
    else:
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
        baseline,
        finished_at=None if prior else _last_activity(run_dir),
        prior=prior or None,
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
        canonical_revision=revision,
    )
    for name in ("report.html", "report.json"):
        store.put_file(f"runs/{args.run}/{name}", run_dir / name)
    return _conclude(args, report, store, args.run)


def _last_activity(run_dir: Path) -> str:
    """When a run that wrote no report last wrote anything: the end of its window."""
    times = [f.stat().st_mtime for f in run_dir.iterdir() if not f.name.startswith("report.")]
    when = dt.datetime.fromtimestamp(max(times), dt.UTC) if times else dt.datetime.now(dt.UTC)
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def _baseline_by_id(store: Store, workdir: Path, bid: str) -> Baseline | None:
    path = workdir / "baselines" / bid / "manifest.json"
    if not path.exists() and not store.get_file(f"baselines/{bid}/manifest.json", path):
        return None
    return Baseline.load(path)


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
                return f"connected to {c.describe()}: {a.product} {a.version}"

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
                if rep.method == "goldengate":
                    st = a.goldengate_status(rep.checkpoint_table, rep.heartbeat_table,
                                             rep.name or "")  # fmt: skip
                    _assert(st is not None, f"Replicat {rep.name!r} not in the GoldenGate tables")
                    return (
                        f"goldengate {rep.name}: source CSN {st['csn']}, "
                        f"heartbeat from {st['heartbeat']}"
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
                "goldengate": "check the Replicat name and the CHECKPOINTTABLE and heartbeat "
                "table names, and grant SELECT on them",
                "availability_group": "name the target's replica (or, for a distributed "
                "availability group, the target's group) and grant VIEW SERVER STATE on the "
                "source",
            }.get(
                rep.method,
                "check the name; reading pg_stat_subscription or pg_replication_slots needs "
                "the pg_monitor role (or pg_read_all_stats)",
            ),
        )
    try:
        store: Store | None = _store(project, Path(args.workdir))
    except ConfigError:
        raise  # instance settings this user cannot read stop the command (decision 67)
    except Exception as exc:  # an SDK set up wrongly (a missing AWS_PROFILE): one failure
        store = None
        checks.append(
            {"check": "results storage", "result": "fail",
             "detail": logs.scrub(f"{type(exc).__name__}: {exc}"),
             "remedy": "fix the AWS profile (AWS_PROFILE, ~/.aws/config) or unset it to "
                       "use the instance role"}
        )  # fmt: skip
    if project.web is not None and store is not None:
        workdir = Path(args.workdir) / project.name
        for jid in _journey_ids(args, project, workdir, store):

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
    if isinstance(store, S3Store):  # the project's bucket, or the deployment's

        def _s3(st=store):
            import tempfile

            probe = f"liftproof doctor probe {dt.datetime.now(dt.UTC).isoformat()}".encode()
            with tempfile.TemporaryDirectory() as tmp:
                sent, back = Path(tmp) / "sent", Path(tmp) / "back"
                sent.write_bytes(probe)
                st.put_file("doctor/probe.txt", sent)
                # reading it back decrypts it: the key allows Decrypt as well as
                # GenerateDataKey, which a resume and the report history need
                _assert(st.get_file("doctor/probe.txt", back), "the probe was not found again")
                _assert(back.read_bytes() == probe, "the probe read back differs")
            key = st.kms_key_id or "the bucket's default key"
            return f"{st.location('doctor/probe.txt')} written and read back, encrypted with {key}"

        check(
            "S3 bucket writable and readable with KMS encryption",
            _s3,
            "grant s3:PutObject and s3:GetObject on the bucket, and kms:GenerateDataKey and "
            "kms:Decrypt on the key; for a customer managed key the key policy must also "
            "allow the instance role",
        )
    elif store is not None:
        where = store.location("")
        checks.append(
            {"check": "results storage", "result": "pass",
             "detail": f"no S3 bucket set: results stay in {where}"}
        )  # fmt: skip
    inst = _instance_config()
    if inst.get("region"):
        vpc_cidrs = (str(inst["vpc_cidr"]),) if inst.get("vpc_cidr") else ()

        def _endpoints(r=inst["region"], cidrs=vpc_cidrs):
            routes, failed = {}, []
            for svc in aws.ENDPOINT_SERVICES:
                try:
                    routes[svc] = aws.reach(svc, r, vpc_cidrs=cidrs)
                except OSError as exc:
                    failed.append(f"{svc} ({exc.strerror or type(exc).__name__})")
            if failed:
                raise ConfigError(f"not reachable in {r}: " + ", ".join(failed))
            detail = f"all {len(routes)} services answer in {r}"
            public = [svc for svc, how in routes.items() if how == "public address"]
            if public:
                # works through a NAT gateway, but that traffic leaves the VPC
                detail += f"; through a public address, not a VPC endpoint: {', '.join(public)}"
            gateways = [svc for svc, how in routes.items() if how == "gateway"]
            if gateways:
                detail += (
                    f"; {', '.join(gateways)} keeps public addresses through a gateway "
                    "endpoint, so its route is not checked here: the private route tables "
                    "need that endpoint"
                )
            return detail

        check(
            "AWS service endpoints reachable",
            _endpoints,
            "create the VPC endpoints (CreateVpcEndpoints, or create_vpc_endpoints in "
            "Terraform), turn on private DNS for them, and allow HTTPS from the instance's "
            "security group to the endpoints' security group",
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
LOG_LEVELS = ("debug", "info", "warning", "error")


def _common_flags(*, defaults: bool) -> argparse.ArgumentParser:
    """The flags every command takes, before or after the command name. Only the top
    level parser sets their defaults: a subcommand's default would otherwise overwrite
    a flag given before the command (`liftproof --format json reconcile ...`)."""

    def default(value: str) -> str:
        return value if defaults else argparse.SUPPRESS

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--format", choices=["text", "json"], default=default("text"))
    common.add_argument(
        "--log-level", type=str.lower, choices=LOG_LEVELS, default=default("info"),
        help="debug also logs each SQL statement (never its values) and each locator used",
    )  # fmt: skip
    common.add_argument("--workdir", default=default(str(DEFAULT_WORKDIR)))
    common.add_argument(
        "--fail-on", choices=["differences", "errors", "never"], default=default("differences")
    )
    return common


def build_parser() -> argparse.ArgumentParser:
    common = _common_flags(defaults=False)
    p = argparse.ArgumentParser(
        prog="liftproof",
        description="Liftproof migration validation",
        parents=[_common_flags(defaults=True)],
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
    s.add_argument("--include-replay-rows", action="store_true", help=REPLAY_ROWS_HELP)
    s.add_argument(
        "--resume",
        action="store_true",
        help="continue an interrupted reconciliation (the latest one, or --run-id), "
        "on this instance or a replacement",
    )
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
            s.add_argument("--include-replay-rows", action="store_true", help=REPLAY_ROWS_HELP)

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

    s = sub.add_parser("restore", parents=[common], help="bring project files back from S3")
    s.add_argument("--projects-dir", default=str(DEFAULT_WORKDIR))
    s.add_argument("--bucket", help="default: this deployment's bucket")
    s.set_defaults(fn=cmd_restore)

    s = sub.add_parser("ui", parents=[common], help="the local web UI (127.0.0.1 only)")
    s.add_argument("--projects-dir", default=str(DEFAULT_WORKDIR))
    s.add_argument("--host", default="127.0.0.1", help=argparse.SUPPRESS)
    s.add_argument("--port", type=int, default=UI_PORT)
    s.set_defaults(fn=cmd_ui)

    s = sub.add_parser("ui-login", parents=[common], help="a one time login link for the UI")
    s.add_argument("--port", type=int, default=UI_PORT, help="the UI's port, for the link")
    s.set_defaults(fn=cmd_ui_login)

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
        _configure_aws()
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
