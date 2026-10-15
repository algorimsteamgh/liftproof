"""Project configuration (PRD F13).

A project holds the source and target connections, the database rules and, later, the
journeys. It is a plain YAML file meant to be handed to a colleague. It references
secrets by ARN and refuses to load if anything that looks like a credential appears in
it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from liftproof.errors import ConfigError
from liftproof.files.compare import FileSetConfig, IgnoreFile
from liftproof.reconcile.baseline import SNAPSHOT_MODES
from liftproof.reconcile.engine import ReconcileOptions
from liftproof.reconcile.plan import IgnoreRule
from liftproof.reconcile.replication import ReplicationConfig
from liftproof.reconcile.structure import CHECKS, StructureChecks
from liftproof.schedule import Schedule, parse_schedules

FORBIDDEN_KEYS = re.compile(
    r"(password|passwd|secret_access_key|access_key_id|session_token)", re.I
)
DEFAULT_PORTS = {"postgresql": 5432, "mysql": 3306, "oracle": 1521, "sqlserver": 1433}
ENGINES = set(DEFAULT_PORTS)
VERIFYING_TLS = {"verify-full", "verify-ca"}
# Spec 9.15: the source is the machine not to saturate. Left out of the project file, its
# connections read at most this many rows a second each, on one core, and pause between
# statements; the target's do neither. Every connection gives up a lock wait after 10 s.
SOURCE_ROWS_PER_SECOND = 125_000
SOURCE_PAUSE_MS = 100
LOCK_TIMEOUT_MS = 10_000


@dataclass
class Connection:
    engine: str
    host: str
    database: str
    port: int = 5432
    user: str | None = None
    secret_arn: str | None = None
    sslmode: str = "verify-full"
    sslrootcert: str | None = None
    statement_timeout_ms: int = 0
    rows_per_second: int = 0  # 0: no cap
    pause_ms: int = 0  # least time between two statements on a connection
    lock_timeout_ms: int = LOCK_TIMEOUT_MS  # 0: wait for a lock as long as it takes
    # a baseline of this database: one snapshot over every table, or one per table
    snapshot: str = "whole"

    @property
    def tls_verified(self) -> bool:
        return self.sslmode in VERIFYING_TLS

    def describe(self) -> str:
        return f"{self.engine}://{self.host}:{self.port}/{self.database}"


@dataclass
class StoreConfig:
    s3_bucket: str | None = None
    s3_prefix: str = ""
    kms_key_id: str | None = None


@dataclass
class WebConfig:
    """Record and replay settings (spec 5 to 8). Bodies are kept only for capture_bodies
    URL patterns; everything else is reduced to a hash and a shape."""

    source_url: str
    target_url: str | None = None
    journeys: list[str] | None = None  # default: every recorded journey
    capture_bodies: list[str] = field(default_factory=list)
    compare_headers: list[str] = field(default_factory=list)
    ignore_json_paths: list[str] = field(default_factory=list)
    ignore_text: list[str] = field(default_factory=list)
    step_timeout_ms: int = 15_000
    chromium_path: str | None = None
    # journeys replayed at once (spec 6). 1, the default, is sequential; more is an opt in
    # for journeys the customer confirms do not interfere, and the report records it
    parallel_journeys: int = 1


@dataclass
class Project:
    name: str
    source: Connection | None  # None: the project validates web journeys only
    target: Connection | None
    store: StoreConfig = field(default_factory=StoreConfig)
    database: ReconcileOptions = field(default_factory=ReconcileOptions)
    path: Path | None = None
    web: WebConfig | None = None
    files: list[FileSetConfig] = field(default_factory=list)
    schedules: list[Schedule] = field(default_factory=list)

    def require_database(self) -> tuple[Connection, Connection]:
        if self.source is None or self.target is None:
            raise ConfigError("this project has no source and target database configured")
        return self.source, self.target

    def require_files(self) -> list[FileSetConfig]:
        if not self.files:
            raise ConfigError("this project has no files section (file sets to compare)")
        return self.files

    def require_web(self) -> WebConfig:
        if self.web is None:
            raise ConfigError("this project has no web section (source_url, target_url)")
        return self.web


def _scan_for_credentials(node: Any, where: str = "") -> None:
    if isinstance(node, dict):
        for k, v in node.items():
            if FORBIDDEN_KEYS.search(str(k)):
                raise ConfigError(
                    f"{where}{k}: credentials must not appear in the project file. "
                    "Store them in AWS Secrets Manager and reference the secret with secret_arn."
                )
            _scan_for_credentials(v, f"{where}{k}.")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _scan_for_credentials(v, f"{where}{i}.")


def _whole(d: dict[str, Any], key: str, default: int, where: str) -> int:
    v = d.get(key, default)
    if isinstance(v, bool) or not isinstance(v, int) or v < 0:
        raise ConfigError(f"{where}.{key} is a whole number, 0 or more (0 turns it off)")
    return v


def _connection(d: dict[str, Any], role: str) -> Connection:
    if not isinstance(d, dict):
        raise ConfigError(f"{role}: connection settings missing")
    engine = d.get("engine", "postgresql")
    if engine not in ENGINES:
        raise ConfigError(
            f"{role}.engine {engine!r} is not supported in this build "
            f"(supported: {', '.join(sorted(ENGINES))})"
        )
    cap, pause = (SOURCE_ROWS_PER_SECOND, SOURCE_PAUSE_MS) if role == "source" else (0, 0)
    snapshot = d.get("snapshot", "whole")
    if snapshot not in SNAPSHOT_MODES:
        raise ConfigError(
            f"{role}.snapshot is whole (a baseline holds one snapshot over every table, the "
            "default) or per_table (one snapshot per table, where the database cannot hold "
            "one that long; the report then says cross table consistency was not held)"
        )
    try:
        return Connection(
            engine=engine,
            host=str(d["host"]),
            database=str(d["database"]),
            port=int(d.get("port", DEFAULT_PORTS[engine])),
            user=d.get("user"),
            secret_arn=d.get("secret_arn"),
            sslmode=d.get("sslmode", "verify-full"),
            sslrootcert=d.get("sslrootcert"),
            statement_timeout_ms=int(d.get("statement_timeout_ms", 0)),
            rows_per_second=_whole(d, "rows_per_second", cap, role),
            pause_ms=_whole(d, "pause_ms", pause, role),
            lock_timeout_ms=_whole(d, "lock_timeout_ms", LOCK_TIMEOUT_MS, role),
            snapshot=snapshot,
        )
    except KeyError as exc:
        raise ConfigError(f"{role}.{exc.args[0]} is required") from None


def _home_schema(conn: Connection | None) -> str:
    """Where tables live by default: PostgreSQL's public schema, the MySQL database, or
    the Oracle login's own schema (upper case, as Oracle stores unquoted names), or
    SQL Server's dbo."""
    if conn is None:
        return "public"
    if conn.engine == "mysql":
        return conn.database
    if conn.engine == "sqlserver":
        return "dbo"
    if conn.engine == "oracle":
        if not conn.user:
            raise ConfigError(
                "Oracle has no default schema without a user name: set database.schemas "
                "(and database.schema_map), or source.user / target.user"
            )
        return conn.user.upper()
    return "public"


MAX_WORKERS = 8  # spec 9.15: a ceiling to be measured against the source, not a target
UNSAFE_SQL = re.compile(r";|--|/\*|\*/")


def _options(
    d: dict[str, Any], source: Connection | None, target: Connection | None
) -> ReconcileOptions:
    ignore = []
    for i, r in enumerate(d.get("ignore", []) or []):
        if not r.get("reason"):
            raise ConfigError(
                f"database.ignore.{i}: every ignore rule needs a reason; "
                "the reasons are printed in the report"
            )
        rule = IgnoreRule(
            r["table"],
            r["reason"],
            r.get("column"),
            r.get("where"),
            r.get("source_where"),
            r.get("target_where"),
            r.get("structure"),
        )
        if rule.rows and rule.column:
            raise ConfigError(f"database.ignore.{i}: a rule leaves out a column or rows, not both")
        if rule.structure is not None and (rule.structure not in CHECKS or rule.rows):
            raise ConfigError(
                f"database.ignore.{i}.structure is one of {', '.join(CHECKS)}, accepted for the "
                "table or, with column, for what holds that column; it takes no row predicate"
            )
        for key in ("where", "source_where", "target_where"):
            pred = getattr(rule, key)
            if pred is not None and (not str(pred).strip() or UNSAFE_SQL.search(str(pred))):
                raise ConfigError(
                    f"database.ignore.{i}.{key}: a row predicate is one SQL condition, "
                    "without ';' or comments"
                )
        ignore.append(rule)
    opts = ReconcileOptions(
        schemas=list(d.get("schemas") or [_home_schema(source)]),
        schema_map=_schema_map(d.get("schema_map"), source, target, d.get("schemas")),
        tables=list(d["tables"]) if d.get("tables") else None,
        ignore=ignore,
        business_keys={k: list(v) for k, v in (d.get("business_keys") or {}).items()},
        rows_per_bucket=int(d.get("rows_per_bucket", 50_000)),
        precision=int(d.get("timestamp_precision", 6)),
        diff_row_limit=int(d.get("diff_row_limit", 100)),
        show_values=bool(d.get("show_values", False)),
        ranges=bool(d.get("ranges", True)),
    )
    opts.replication = ReplicationConfig.from_dict(d.get("replication"))
    opts.structure = _structure(d.get("structure", True))
    breaker = d.get("circuit_breaker") or {}
    opts.breaker_bucket_ratio = float(breaker.get("bucket_ratio", opts.breaker_bucket_ratio))
    opts.breaker_table_ratio = float(breaker.get("table_ratio", opts.breaker_table_ratio))
    workers = d.get("workers", 1)
    if not isinstance(workers, int) or not 1 <= workers <= MAX_WORKERS:
        raise ConfigError(
            f"database.workers is 1 (one table at a time, the default) to {MAX_WORKERS}; "
            "each worker is another connection reading the source"
        )
    opts.workers = workers
    marks = d.get("replay_watermarks") or {}
    if not isinstance(marks, dict):
        raise ConfigError("database.replay_watermarks maps a table to its growing column")
    opts.replay_watermarks = {str(k): str(v) for k, v in marks.items()}
    sampling = d.get("sampling")
    if sampling:
        if not isinstance(sampling, dict) or "above_rows" not in sampling:
            raise ConfigError("database.sampling needs above_rows: tables larger than this are "
                              "sampled, smaller ones are always compared in full")  # fmt: skip
        opts.sample_above_rows = int(sampling["above_rows"])
        opts.sample_percent = float(sampling.get("percent", opts.sample_percent))
        if not 0 < opts.sample_percent < 100:
            raise ConfigError("database.sampling.percent is between 0 and 100")
        if sampling.get("seed") is not None:
            opts.sample_seed = int(sampling["seed"])
    return opts


def _structure(v: Any) -> StructureChecks:
    """database.structure: true (every check, the default), false, or a map of checks."""
    if isinstance(v, bool):
        return StructureChecks(**dict.fromkeys(CHECKS, v))
    if (
        not isinstance(v, dict)
        or set(v) - set(CHECKS)
        or not all(isinstance(x, bool) for x in v.values())
    ):
        raise ConfigError(
            f"database.structure is true, false or a map of {', '.join(CHECKS)} to true or "
            "false (each true when left out)"
        )
    return StructureChecks(**v)


def _web(d: Any) -> WebConfig | None:
    if not d:
        return None
    if not isinstance(d, dict) or not d.get("source_url"):
        raise ConfigError("web.source_url is required when a web section is present")

    def strings(key: str) -> list[str]:
        v = d.get(key) or []
        if not isinstance(v, list):
            raise ConfigError(f"web.{key} must be a list")
        return [str(x) for x in v]

    return WebConfig(
        source_url=str(d["source_url"]),
        target_url=d.get("target_url"),
        journeys=strings("journeys") or None,
        capture_bodies=strings("capture_bodies"),
        compare_headers=strings("compare_headers"),
        ignore_json_paths=strings("ignore_json_paths"),
        ignore_text=strings("ignore_text"),
        step_timeout_ms=int(d.get("step_timeout_ms", 15_000)),
        chromium_path=d.get("chromium_path"),
        parallel_journeys=_parallel(d.get("parallel_journeys", 1)),
    )


MAX_PARALLEL_JOURNEYS = 8  # each runs its own browser on the instance


def _parallel(v: Any) -> int:
    try:
        n = int(v)
    except (TypeError, ValueError):
        n = 0
    if not 1 <= n <= MAX_PARALLEL_JOURNEYS:
        raise ConfigError(
            f"web.parallel_journeys is 1 (in sequence, the default) to {MAX_PARALLEL_JOURNEYS}"
        )
    return n


def _side(d: Any, where: str) -> tuple[str, str | None, str | None]:
    """A file location: a string, or {location, endpoint_url, secret_arn} for an S3
    compatible store outside AWS."""
    if isinstance(d, str) and d:
        return d, None, None
    if isinstance(d, dict) and d.get("location"):
        if d.get("secret_arn") and not d.get("endpoint_url"):
            # keys in a secret would mean an IAM user with long lived keys (IAM-002)
            raise ConfigError(
                f"{where}.secret_arn is for an S3 compatible store outside AWS, with its "
                "endpoint_url; a bucket in AWS is read with the instance role, so leave "
                "secret_arn out and grant the role s3:ListBucket and s3:GetObject"
            )
        return str(d["location"]), d.get("endpoint_url"), d.get("secret_arn")
    raise ConfigError(f"{where} must be a path, an s3:// location, or {{location: ...}}")


def _files(d: Any) -> list[FileSetConfig]:
    if not d:
        return []
    if not isinstance(d, list):
        raise ConfigError("files must be a list of file sets (name, source, target)")
    sets, names = [], set()
    for i, f in enumerate(d):
        where = f"files.{i}"
        if not isinstance(f, dict) or not f.get("name"):
            raise ConfigError(f"{where}: every file set needs a name")
        name = str(f["name"])
        if name in names:
            raise ConfigError(f"{where}: file set name {name!r} is used twice")
        names.add(name)
        src, src_ep, src_secret = _side(f.get("source"), f"{where}.source")
        tgt, tgt_ep, tgt_secret = _side(f.get("target"), f"{where}.target")
        ignore = []
        for j, r in enumerate(f.get("ignore") or []):
            if not isinstance(r, dict) or not r.get("path") or not r.get("reason"):
                raise ConfigError(
                    f"{where}.ignore.{j}: every ignore rule needs a path and a reason; "
                    "the reasons are printed in the report"
                )
            ignore.append(IgnoreFile(str(r["path"]), str(r["reason"])))
        path_map = []
        for j, pair in enumerate(f.get("path_map") or []):
            if not isinstance(pair, list) or len(pair) != 2:
                raise ConfigError(f"{where}.path_map.{j}: use [source regex, target replacement]")
            path_map.append((str(pair[0]), str(pair[1])))
        for pattern in [p for p, _ in path_map] + list(f.get("ignore_text") or []):
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ConfigError(f"{where}: {pattern!r} is not a valid regular expression: "
                                  f"{exc}") from None  # fmt: skip
        sets.append(
            FileSetConfig(
                name=name,
                source=src,
                target=tgt,
                include=[str(x) for x in f.get("include") or []],
                ignore=ignore,
                ignore_text=[str(x) for x in f.get("ignore_text") or []],
                path_map=path_map,
                case_insensitive=bool(f.get("case_insensitive", False)),
                show_content=bool(f.get("show_content", False)),
                max_text_mb=int(f.get("max_text_mb", 64)),
                workers=int(f.get("workers", 8)),
                source_endpoint_url=src_ep,
                target_endpoint_url=tgt_ep,
                source_secret_arn=src_secret,
                target_secret_arn=tgt_secret,
            )
        )
    return sets


def _schema_map(
    given: Any, source: Connection | None, target: Connection | None, schemas: Any = None
) -> dict[str, str]:
    """Explicit schema_map, else map the source home schema onto the target's when they
    differ (MySQL 'shop' to PostgreSQL 'public', Oracle 'APP' to 'public')."""
    if given is not None:
        if not isinstance(given, dict):
            raise ConfigError("database.schema_map must map source schema to target schema")
        return {str(k): str(v) for k, v in given.items()}
    if source is None or target is None:
        return {}
    known = all(c.engine != "oracle" or c.user for c in (source, target))
    if schemas and not known:
        return {}  # an Oracle login named only in its secret: schema_map must be given
    s, t = _home_schema(source), _home_schema(target)
    return {s: t} if s != t else {}


def load_project(path: Path) -> Project:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except FileNotFoundError:
        raise ConfigError(f"project file not found: {path}") from None
    except yaml.YAMLError as exc:
        raise ConfigError(f"project file {path} is not valid YAML: {exc}") from None
    _scan_for_credentials(raw)
    if "project" not in raw:
        raise ConfigError(f"{path}: 'project' (the project name) is required")
    store = raw.get("store") or {}
    web = _web(raw.get("web"))
    files = _files(raw.get("files"))
    has_db = raw.get("source") is not None or raw.get("target") is not None
    if not has_db and web is None and not files:
        raise ConfigError(
            f"{path}: configure source and target databases, a web section, file sets, "
            "or any combination"
        )
    source = _connection(raw.get("source"), "source") if has_db else None
    target = _connection(raw.get("target"), "target") if has_db else None
    return Project(
        name=str(raw["project"]),
        source=source,
        target=target,
        web=web,
        files=files,
        schedules=parse_schedules(raw.get("schedules")),
        store=StoreConfig(
            store.get("s3_bucket"), store.get("s3_prefix", raw["project"]), store.get("kms_key_id")
        ),
        database=_options(raw.get("database") or {}, source, target),
        path=path,
    )


TEMPLATE = """\
# Liftproof project file. Hand this to a colleague: it holds no credentials.
project: {name}

store:
  s3_bucket: REPLACE-with-your-bucket     # KMS encrypted, in your account
  s3_prefix: {name}
  # kms_key_id: arn:aws:kms:REGION:ACCOUNT:key/ID   # customer managed key (optional)

source:                         # a read replica where there is one (README: Protecting the source)
  engine: postgresql
  host: source.db.example.internal
  port: 5432
  database: app
  secret_arn: arn:aws:secretsmanager:REGION:ACCOUNT:secret:liftproof/source   # username, password
  sslmode: verify-full          # full certificate verification; lowering it is reported
                                # Oracle: TLS is TCPS, usually on port 2484
                                # SQL Server: verify-ca or verify-full
  # sslrootcert: /var/lib/mvt/certs/private-ca.pem   # only for a private CA; the AMI
                                # already trusts Amazon RDS and public certificate authorities
  statement_timeout_ms: 600000
  lock_timeout_ms: 10000        # a read kept waiting this long for a lock fails the run
  rows_per_second: 125000       # rows read a second, on one core, by each connection (each
                                # worker has its own); 0 = no cap, e.g. for a read replica
  pause_ms: 100                 # at least this long between two statements on a connection
  # snapshot: per_table         # a baseline holds one snapshot over every table; per_table
                                # when the source cannot (README: Protecting the source)

target:
  engine: postgresql            # postgresql, mysql, oracle or sqlserver; may differ
  host: target.cluster-xyz.REGION.rds.amazonaws.com
  port: 5432
  database: app
  secret_arn: arn:aws:secretsmanager:REGION:ACCOUNT:secret:liftproof/target
  sslmode: verify-full          # RDS certificates verify against the bundle on the AMI
  lock_timeout_ms: 10000
  rows_per_second: 0            # no cap; set one once the target is production
  pause_ms: 0
  # snapshot: per_table         # rebaseline: one snapshot per table instead

web:                            # record and replay; omit for database only projects
  source_url: https://app.example.internal
  target_url: https://app.example.com
  capture_bodies: ["/api/*"]    # bodies kept for value comparison; others: hash and shape
  compare_headers: []           # only these response headers are compared
  ignore_json_paths: []         # e.g. "$.generated_at" or "GET /api/orders/{{id}} $.etag"
  ignore_text: []               # regular expressions masked in page content
  step_timeout_ms: 15000
  parallel_journeys: 1          # 1 = in sequence; more only for journeys that do not interfere

files:                          # compare files the application generates or stores
  - name: invoices
    source: /mnt/source-share/invoices    # a path on this instance, or s3://bucket/prefix
    target: s3://REPLACE-target-bucket/invoices/
    include: ["*.pdf", "*.csv"]           # default: every file; * crosses folders
    ignore_text: []                       # regular expressions masked in extracted text
    show_content: false                   # the report shows where text differs, not what
    # path_map: [["^archive/", "old/"]]   # rewrite source paths: regex -> replacement
    # case_insensitive: false             # true when a Windows share moves to S3
    # ignore:
    #   - path: "tmp/*"
    #     reason: scratch files, not migrated

database:
  schemas: [public]             # MySQL: the database; Oracle: the owner; SQL Server: dbo
  # schema_map: {{shop: public}}  # source schema -> target schema, when renamed
  # tables: [orders, customers]   # default: every table in the schemas
  rows_per_bucket: 50000
  timestamp_precision: 6
  diff_row_limit: 100
  show_values: false            # the report is an egress path; values need an explicit opt in
  ranges: true                  # lowest/highest integer key and dates per table, in the report
  business_keys: {{}}           # e.g. orders: [order_number] where keys were renumbered
  workers: 1                    # tables hashed at once; each is another source connection
  # structure:                  # compared before data; false turns all of it off
  #   nullability: true
  #   keys: true                # primary and unique keys
  #   foreign_keys: true        # false where the target's are added after the load
  #   indexes: true             # false where the target's are built after the load
  # sampling:                    # large tables: compare a random share of the buckets;
  #   above_rows: 500000000      # the report gives the share and marks the rest not checked
  #   percent: 10
  ignore:
    # - table: sessions
    #   reason: session tokens are not migrated
    # - table: orders
    #   column: last_synced_at
    #   reason: rewritten by ETL
    # - table: orders               # rows left out on both sides: one SQL condition
    #   where: "status = 'ARCHIVED'"
    #   reason: archived orders are not migrated
    # - table: accounts             # or per side, each in its own dialect
    #   source_where: "tenant = 'test'"
    #   target_where: "tenant = 'qa'"
    #   reason: test tenant renamed in the target
    # - table: events               # a structural difference accepted (keys, nullability,
    #   structure: keys             # foreign_keys or indexes; with column, only what holds it)
    #   reason: partitioned target; its primary key includes created_at
  # replay_watermarks:          # rows a replay creates are left out of later reconciliations,
  #   orders: id                # told apart by a column that only grows; default: a single
  #   events: created_at        # column primary key (journeys name tables: record --writes)
  # replication:                # has replication applied everything up to the reference point?
  #   method: slot              # slot (on a PostgreSQL source, e.g. read by AWS DMS),
  #                             # subscription (PostgreSQL logical replication, on the target),
  #                             # replica (MySQL replication, on the target; name: channel),
  #                             # dms (any engines: the task's awsdms_status table on the
  #                             # target; name: the task's resource ID; control_schema if
  #                             # the task sets ControlSchema),
  #                             # goldengate (any engines: name: the Replicat;
  #                             # checkpoint_table and/or heartbeat_table on the target),
  #                             # availability_group (SQL Server, on the source; name: the
  #                             # target's replica, or its group in a distributed one)
  #   name: dms_slot
  #   wait_seconds: 300         # wait this long for it to catch up; then not_checked

# schedules:                    # run by mvt-scheduler.service; runs never overlap
#   - name: nightly
#     cron: "0 2 * * *"         # minute hour day-of-month month day-of-week
#     timezone: Asia/Kolkata    # default UTC
#     command: validate         # validate, reconcile, files, replay, smoke or baseline
#     args: [--baseline, latest]
"""
