"""Project configuration (PRD F13).

A project holds the source and target connections, the database rules and, later, the
journeys. It is a plain YAML file meant to be handed to a colleague. It references
secrets by ARN and refuses to load if anything that looks like a credential appears in
it.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from liftproof.canonical.typemap import DEFAULT_TYPE_MAP
from liftproof.errors import ConfigError
from liftproof.files.compare import FileSetConfig, IgnoreFile
from liftproof.files.rows import ENCODINGS, RowFiles
from liftproof.files.sources import is_azure
from liftproof.reconcile.baseline import SNAPSHOT_MODES
from liftproof.reconcile.engine import ReconcileOptions
from liftproof.reconcile.plan import IgnoreRule
from liftproof.reconcile.replication import ReplicationConfig
from liftproof.reconcile.structure import CHECKS, StructureChecks
from liftproof.schedule import Schedule, parse_schedules
from liftproof.web.journey import IgnoreRegion

FORBIDDEN_KEYS = re.compile(
    r"(password|passwd|secret_access_key|access_key_id|session_token)", re.I
)
DEFAULT_PORTS = {"postgresql": 5432, "mysql": 3306, "oracle": 1521, "sqlserver": 1433}
# SQLite is a file, read from a copy: a source only, with path in place of a server
FILE_ENGINES = {"sqlite"}
ENGINES = set(DEFAULT_PORTS) | FILE_ENGINES
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
    sslrootcert: str | None = None  # a path on this instance, or s3://bucket/key
    # PostgreSQL: the address to connect to, with host the name its certificate is
    # verified against (a server reached across a VPN by an address only)
    hostaddr: str | None = None
    statement_timeout_ms: int = 0
    rows_per_second: int = 0  # 0: no cap
    pause_ms: int = 0  # least time between two statements on a connection
    lock_timeout_ms: int = LOCK_TIMEOUT_MS  # 0: wait for a lock as long as it takes
    # a baseline of this database: one snapshot over every table, or one per table
    snapshot: str = "whole"
    # a file engine (SQLite): the database file, a path on this instance or s3://bucket/key,
    # and optionally the SHA-256 it must have
    path: str | None = None
    sha256: str | None = None

    @property
    def is_file(self) -> bool:
        return self.engine in FILE_ENGINES

    @property
    def tls_verified(self) -> bool:
        return self.is_file or self.sslmode in VERIFYING_TLS  # a file crosses no network

    def describe(self) -> str:
        if self.is_file:
            return f"{self.engine}:{self.path}"
        return f"{self.engine}://{self.host}:{self.port}/{self.database}"


@dataclass
class StoreConfig:
    s3_bucket: str | None = None
    s3_prefix: str = ""
    kms_key_id: str | None = None


@dataclass
class WebConfig:
    """Record and replay settings (spec 5 to 8). Bodies are kept only for capture_bodies
    URL patterns, and page snapshots only for capture_snapshots patterns (matched on the
    page a step ended on); everything else is reduced to a hash and a shape."""

    source_url: str
    target_url: str | None = None
    journeys: list[str] | None = None  # default: every recorded journey
    capture_bodies: list[str] = field(default_factory=list)
    capture_snapshots: list[str] = field(default_factory=list)
    compare_headers: list[str] = field(default_factory=list)
    ignore_json_paths: list[str] = field(default_factory=list)
    ignore_text: list[str] = field(default_factory=list)
    # page parts never compared, by CSS selector, each with its reason (spec 7, 9.12)
    ignore_regions: list[IgnoreRegion] = field(default_factory=list)
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
    if engine in FILE_ENGINES:
        return _file_connection(d, role, engine)
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
            hostaddr=_hostaddr(d, role, engine),
            statement_timeout_ms=int(d.get("statement_timeout_ms", 0)),
            rows_per_second=_whole(d, "rows_per_second", cap, role),
            pause_ms=_whole(d, "pause_ms", pause, role),
            lock_timeout_ms=_whole(d, "lock_timeout_ms", LOCK_TIMEOUT_MS, role),
            snapshot=snapshot,
        )
    except KeyError as exc:
        raise ConfigError(f"{role}.{exc.args[0]} is required") from None


SERVER_SETTINGS = {"host", "port", "database", "user", "secret_arn", "sslmode", "sslrootcert",
                   "hostaddr", "rows_per_second", "pause_ms", "snapshot"}  # fmt: skip


def _hostaddr(d: dict[str, Any], role: str, engine: str) -> str | None:
    value = d.get("hostaddr")
    if value is None:
        return None
    if engine != "postgresql":
        raise ConfigError(
            f"{role}.hostaddr is for PostgreSQL; for {engine}, make host resolve on the "
            "instance (a Route 53 private hosted zone or Resolver rule in its VPC)"
        )
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        raise ConfigError(
            f"{role}.hostaddr is the server's IP address; host stays the name its "
            "certificate is verified against"
        ) from None


def _file_connection(d: dict[str, Any], role: str, engine: str) -> Connection:
    """A database file: the source only, read from a copy taken once the application
    stopped writing. Server settings have no meaning for it and are refused."""
    if role != "source":
        raise ConfigError(f"{role}.engine {engine}: a {engine} database can be the source only")
    path = d.get("path")
    if not path or not isinstance(path, str):
        raise ConfigError(
            f"{role}.path is required for {engine}: the database file, a path on this "
            "instance or s3://bucket/key (a copy taken once the application stopped writing)"
        )
    server = sorted(set(d) & SERVER_SETTINGS)
    if server:
        raise ConfigError(
            f"{role}: {', '.join(server)} do not apply to a {engine} file; give path only"
        )
    sha = d.get("sha256")
    if sha is not None and not re.fullmatch(r"(sha256:)?[0-9a-fA-F]{64}", str(sha)):
        raise ConfigError(f"{role}.sha256 is the file's SHA-256, 64 hexadecimal characters")
    return Connection(engine=engine, host="", database="main", port=0, path=path,
                      sha256=str(sha) if sha else None, lock_timeout_ms=0)  # fmt: skip


def _home_schema(conn: Connection | None) -> str:
    """Where tables live by default: PostgreSQL's public schema, the MySQL database, or
    the Oracle login's own schema (upper case, as Oracle stores unquoted names), or
    SQL Server's dbo."""
    if conn is None:
        return "public"
    if conn.engine == "mysql":
        return conn.database
    if conn.engine == "sqlite":
        return "main"
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
    if d.get("type_map") is not None:
        engines = {c.engine for c in (source, target) if c is not None}
        opts.type_map = DEFAULT_TYPE_MAP.with_overrides(d["type_map"], engines)
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
        capture_snapshots=strings("capture_snapshots"),
        compare_headers=strings("compare_headers"),
        ignore_json_paths=strings("ignore_json_paths"),
        ignore_text=strings("ignore_text"),
        ignore_regions=_regions(d.get("ignore_regions")),
        step_timeout_ms=int(d.get("step_timeout_ms", 15_000)),
        chromium_path=d.get("chromium_path"),
        parallel_journeys=_parallel(d.get("parallel_journeys", 1)),
    )


SELECTOR_KEYS = ("selector", "source_selector", "target_selector")


def _regions(v: Any) -> list[IgnoreRegion]:
    """web.ignore_regions: `selector` (both sides) or `source_selector` / `target_selector`
    (one side each), and a reason. The browser checks that each is CSS before a run."""
    if not v:
        return []
    if not isinstance(v, list):
        raise ConfigError("web.ignore_regions must be a list of {selector, reason}")
    rules = []
    for i, r in enumerate(v):
        if not isinstance(r, dict) or not r.get("reason") or not any(map(r.get, SELECTOR_KEYS)):
            raise ConfigError(
                f"web.ignore_regions.{i}: every ignore region needs a selector (CSS; quote one "
                "that starts with [ or #) and a reason; the reasons are printed in the report"
            )
        for k in SELECTOR_KEYS:
            if r.get(k) is not None and not isinstance(r[k], str):
                raise ConfigError(
                    f"web.ignore_regions.{i}.{k} must be a string: quote a selector that "
                    "starts with [ or #"
                )
        rules.append(IgnoreRegion(str(r["reason"]), *(r.get(k) or None for k in SELECTOR_KEYS)))
    return rules


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


@dataclass
class _Side:
    location: str
    endpoint_url: str | None = None
    secret_arn: str | None = None
    kind: str | None = None
    rows: RowFiles | None = None


def _side(d: Any, where: str) -> _Side:
    """A file location: a string, or {location, endpoint_url, secret_arn} for an S3
    compatible store outside AWS, {location, secret_arn} for Azure Blob Storage, or
    {database, table, content or object, path} for the files a database table holds or
    names."""
    if isinstance(d, str) and d:
        return _Side(d)
    if isinstance(d, dict) and d.get("database"):
        return _Side(f"{d['database']} database", rows=_rows(d, where))
    if isinstance(d, dict) and d.get("location"):
        kind = d.get("kind")
        if kind not in (None, "azure_blob"):
            raise ConfigError(f"{where}.kind is azure_blob, or left out")
        location = str(d["location"])
        azure = kind == "azure_blob" or is_azure(location)
        if d.get("secret_arn") and not d.get("endpoint_url") and not azure:
            # keys in a secret would mean an IAM user with long lived keys (IAM-002)
            raise ConfigError(
                f"{where}.secret_arn is for an S3 compatible store outside AWS, with its "
                "endpoint_url, or for Azure Blob Storage; a bucket in AWS is read with the "
                "instance role, so leave secret_arn out and grant the role s3:ListBucket and "
                "s3:GetObject"
            )
        if azure and not d.get("secret_arn"):
            raise ConfigError(
                f"{where}: Azure Blob Storage is read with a SAS token (Read and List) kept "
                "in a Secrets Manager secret under the key sas_token; give its secret_arn"
            )
        return _Side(location, d.get("endpoint_url"), d.get("secret_arn"),
                     "azure_blob" if azure else None)  # fmt: skip
    raise ConfigError(
        f"{where} must be a path, an s3:// location, {{location: ...}}, or {{database: source "
        "or target, table, content or object, path}"
    )


def _rows(d: dict[str, Any], where: str) -> RowFiles:
    database = d.get("database")
    if database not in ("source", "target"):
        raise ConfigError(f"{where}.database is source or target: the project's connection")
    if bool(d.get("content")) == bool(d.get("object")):
        raise ConfigError(
            f"{where}: give content, the column holding each file, or object, the template of "
            'the location each row names ("s3://bucket/{cv_key}", or "{photo_url}"); not both'
        )
    missing = [k for k in ("table", "path") if not d.get(k)]
    if missing:
        raise ConfigError(
            f"{where}: {', '.join(missing)} required; the table, and each file's path from "
            'the row\'s columns, as the other side names it (path: "{id}/{file_name}")'
        )
    encoding = d.get("encoding", "binary")
    if encoding not in ENCODINGS:
        raise ConfigError(f"{where}.encoding is one of {', '.join(ENCODINGS)}")
    pred = d.get("where")
    if pred is not None and (not str(pred).strip() or UNSAFE_SQL.search(str(pred))):
        raise ConfigError(f"{where}.where is one SQL condition, without ';' or comments")
    obj = str(d["object"]) if d.get("object") else None
    store = _Side("", d.get("endpoint_url"), d.get("secret_arn"), d.get("kind"))
    object_map = None
    if obj is None:
        stray = sorted(set(d) & {"object_map", "endpoint_url", "secret_arn", "kind"})
        if stray:
            raise ConfigError(f"{where}: {', '.join(stray)} apply to object, not content")
    else:
        if store.kind not in (None, "azure_blob"):
            raise ConfigError(f"{where}.kind is azure_blob, or left out")
        azure = store.kind == "azure_blob" or is_azure(obj)
        if azure and not store.secret_arn:
            raise ConfigError(
                f"{where}: Azure Blob Storage is read with a SAS token (Read) kept in a "
                "Secrets Manager secret under the key sas_token; give its secret_arn"
            )
        if store.secret_arn and not store.endpoint_url and not azure:
            raise ConfigError(
                f"{where}.secret_arn is for an S3 compatible store outside AWS, with its "
                "endpoint_url, or for Azure Blob Storage (kind: azure_blob); a bucket in AWS "
                "is read with the instance role"
            )
        pair = d.get("object_map")
        if pair is not None:
            if not isinstance(pair, list) or len(pair) != 2:
                raise ConfigError(f"{where}.object_map: use [regex, replacement]")
            try:
                re.compile(str(pair[0]))
            except re.error as exc:
                raise ConfigError(f"{where}.object_map: {pair[0]!r} is not a valid regular "
                                  f"expression: {exc}") from None  # fmt: skip
            object_map = (str(pair[0]), str(pair[1]))
    rows = RowFiles(
        str(database), str(d["table"]), str(d["content"]) if obj is None else None,
        str(d["path"]), str(pred) if pred else None, encoding, obj, object_map,
        store.endpoint_url, store.secret_arn,
        "azure_blob" if obj and (store.kind or is_azure(obj)) else None,
    )  # fmt: skip
    for key, template in (("path", rows.path), ("object", obj)):
        if template is None:
            continue
        try:
            if not rows.path_columns if key == "path" else not rows.object_columns:
                raise ValueError("it names no column")
        except ValueError as exc:
            raise ConfigError(f"{where}.{key} {template!r} is not a template of the row's "
                              f"columns: {exc}") from None  # fmt: skip
    return rows


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
        src = _side(f.get("source"), f"{where}.source")
        tgt = _side(f.get("target"), f"{where}.target")
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
                source=src.location,
                target=tgt.location,
                include=[str(x) for x in f.get("include") or []],
                ignore=ignore,
                ignore_text=[str(x) for x in f.get("ignore_text") or []],
                path_map=path_map,
                case_insensitive=bool(f.get("case_insensitive", False)),
                show_content=bool(f.get("show_content", False)),
                max_text_mb=int(f.get("max_text_mb", 64)),
                workers=int(f.get("workers", 8)),
                source_endpoint_url=src.endpoint_url,
                target_endpoint_url=tgt.endpoint_url,
                source_secret_arn=src.secret_arn,
                target_secret_arn=tgt.secret_arn,
                source_kind=src.kind,
                target_kind=tgt.kind,
                source_rows=src.rows,
                target_rows=tgt.rows,
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
    # a file set reading the files a table holds needs that database alone
    used = {r.database for f in files for r in (f.source_rows, f.target_rows) if r is not None}
    both = has_db and not used
    source = _connection(raw.get("source"), "source") if both or raw.get("source") else None
    target = _connection(raw.get("target"), "target") if both or raw.get("target") else None
    for database in sorted(used):
        if raw.get(database) is None:
            raise ConfigError(
                f"{path}: a file set reads files from the {database} database, which the "
                f"project does not configure ({database}: ...)"
            )
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
  # sslrootcert: s3://REPLACE-with-your-bucket/certs/server-ca.pem   # a private CA (a
                                # Cloud SQL server CA), or a path on the instance; the AMI
                                # already trusts Amazon RDS and public certificate authorities
  # hostaddr: 10.20.0.4         # PostgreSQL: connect to this address and verify the
                                # certificate against host (a name only a VPN's DNS knows)
  statement_timeout_ms: 600000
  lock_timeout_ms: 10000        # a read kept waiting this long for a lock fails the run
  rows_per_second: 125000       # rows read a second, on one core, by each connection (each
                                # worker has its own); 0 = no cap, e.g. for a read replica
  pause_ms: 100                 # at least this long between two statements on a connection
  # snapshot: per_table         # a baseline holds one snapshot over every table; per_table
                                # when the source cannot (README: Protecting the source)
# source:                       # an application that kept its data in a SQLite file: a copy
#   engine: sqlite              # taken once it stopped writing (litestream restore, or
#   path: s3://REPLACE-with-your-bucket/inputs/app.db    # sqlite3 .backup); or a local path
#   # sha256: ...               # optional: the copy must be this file

target:
  engine: postgresql            # postgresql, mysql, oracle or sqlserver; may differ
                                # (sqlite is a source only)
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
  capture_snapshots: []         # pages whose text is kept for comparison, e.g. ["/orders/*"];
                                # others: hash and structure. Kept ones expire with the bucket
  compare_headers: []           # only these response headers are compared
  ignore_json_paths: []         # e.g. "$.generated_at" or "GET /api/orders/{{id}} $.etag";
                                # [*] is every element: "$.orders[*].updated_at"
  ignore_text: []               # regular expressions masked in page content
  ignore_regions: []            # page parts never compared, by CSS selector, with a reason:
                                # {{selector: ".recently-viewed", reason: personalised}};
                                # or source_selector / target_selector where markup differs.
                                # Elements marked data-liftproof-volatile are never compared
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
  # - name: uploads             # Azure Blob Storage: the container URL, read with a SAS token
  #   source:                   # (Read and List) kept in a secret under the key sas_token
  #     location: https://ACCOUNT.blob.core.windows.net/uploads
  #     secret_arn: arn:aws:secretsmanager:REGION:ACCOUNT:secret:liftproof/azure-blob
  #   target: s3://REPLACE-target-bucket/uploads/
  # - name: stored-files        # files the source database holds, one a row, moved to S3
  #   source:
  #     database: source        # the project's source (or target) connection
  #     table: documents
  #     content: data           # the column holding each file (BLOB, bytea)
  #     path: "{{id}}/{{file_name}}"  # each file's key under target, from the row's columns
  #     # encoding: base64      # when the column holds base64 text; default binary
  #     # where: "deleted = 0"  # only these rows
  #   target: s3://REPLACE-target-bucket/documents/
  # - name: media               # Google Cloud Storage, through its S3 interface: an HMAC
  #   source:                   # key in a secret (access_key_id, secret_access_key)
  #     location: s3://REPLACE-gcs-bucket/media/
  #     endpoint_url: https://storage.googleapis.com
  #     secret_arn: arn:aws:secretsmanager:REGION:ACCOUNT:secret:liftproof/gcs-hmac
  #   target: s3://REPLACE-target-bucket/media/
  # - name: named-files         # the files each row names: each record's file before and
  #   source:                   # after the move, whatever keys the migration gave them
  #     database: source
  #     table: documents
  #     content: data
  #     path: "{{id}}"
  #   target:
  #     database: target
  #     table: documents
  #     object: "s3://REPLACE-target-bucket/{{file_key}}"   # or "{{file_url}}", an object URL
  #     # object_map: ["^https://cdn\\.example\\.com/([^?]*).*$", "s3://REPLACE-target-bucket/\\1"]
  #     path: "{{id}}"

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
  # type_map:                  # how native types compare (docs/canonical-v1.md); the
  #   mysql:                    # report names each column compared otherwise
  #     tinyint(1): integer     # the target column is a smallint, not a boolean
  #     datetime: timestamptz   # it holds UTC times; the target's are zone aware
  #   oracle:
  #     NUMBER(1): boolean      # 0 is false, any other value true
  #     DATE: date              # a DATE with a time of day differs from every date
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
