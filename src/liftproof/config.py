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
from liftproof.reconcile.engine import ReconcileOptions
from liftproof.reconcile.plan import IgnoreRule

FORBIDDEN_KEYS = re.compile(
    r"(password|passwd|secret_access_key|access_key_id|session_token)", re.I
)
ENGINES = {"postgresql"}
VERIFYING_TLS = {"verify-full", "verify-ca"}


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
    rows_per_second: int = 0

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


@dataclass
class Project:
    name: str
    source: Connection | None  # None: the project validates web journeys only
    target: Connection | None
    store: StoreConfig = field(default_factory=StoreConfig)
    database: ReconcileOptions = field(default_factory=ReconcileOptions)
    path: Path | None = None
    web: WebConfig | None = None

    def require_database(self) -> tuple[Connection, Connection]:
        if self.source is None or self.target is None:
            raise ConfigError("this project has no source and target database configured")
        return self.source, self.target

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


def _connection(d: dict[str, Any], role: str) -> Connection:
    if not isinstance(d, dict):
        raise ConfigError(f"{role}: connection settings missing")
    engine = d.get("engine", "postgresql")
    if engine not in ENGINES:
        raise ConfigError(
            f"{role}.engine {engine!r} is not supported in this build "
            f"(supported: {', '.join(sorted(ENGINES))})"
        )
    try:
        return Connection(
            engine=engine,
            host=str(d["host"]),
            database=str(d["database"]),
            port=int(d.get("port", 5432)),
            user=d.get("user"),
            secret_arn=d.get("secret_arn"),
            sslmode=d.get("sslmode", "verify-full"),
            sslrootcert=d.get("sslrootcert"),
            statement_timeout_ms=int(d.get("statement_timeout_ms", 0)),
            rows_per_second=int(d.get("rows_per_second", 0)),
        )
    except KeyError as exc:
        raise ConfigError(f"{role}.{exc.args[0]} is required") from None


def _options(d: dict[str, Any]) -> ReconcileOptions:
    ignore = []
    for i, r in enumerate(d.get("ignore", []) or []):
        if not r.get("reason"):
            raise ConfigError(
                f"database.ignore.{i}: every ignore rule needs a reason; "
                "the reasons are printed in the report"
            )
        ignore.append(IgnoreRule(r["table"], r["reason"], r.get("column")))
    opts = ReconcileOptions(
        schemas=list(d.get("schemas", ["public"])),
        tables=list(d["tables"]) if d.get("tables") else None,
        ignore=ignore,
        business_keys={k: list(v) for k, v in (d.get("business_keys") or {}).items()},
        rows_per_bucket=int(d.get("rows_per_bucket", 50_000)),
        precision=int(d.get("timestamp_precision", 6)),
        diff_row_limit=int(d.get("diff_row_limit", 100)),
        show_values=bool(d.get("show_values", False)),
    )
    breaker = d.get("circuit_breaker") or {}
    opts.breaker_bucket_ratio = float(breaker.get("bucket_ratio", opts.breaker_bucket_ratio))
    opts.breaker_table_ratio = float(breaker.get("table_ratio", opts.breaker_table_ratio))
    return opts


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
    )


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
    has_db = raw.get("source") is not None or raw.get("target") is not None
    if not has_db and web is None:
        raise ConfigError(f"{path}: configure source and target databases, a web section, or both")
    return Project(
        name=str(raw["project"]),
        source=_connection(raw.get("source"), "source") if has_db else None,
        target=_connection(raw.get("target"), "target") if has_db else None,
        web=web,
        store=StoreConfig(
            store.get("s3_bucket"), store.get("s3_prefix", raw["project"]), store.get("kms_key_id")
        ),
        database=_options(raw.get("database") or {}),
        path=path,
    )


TEMPLATE = """\
# Liftproof project file. Hand this to a colleague: it holds no credentials.
project: {name}

store:
  s3_bucket: REPLACE-with-your-bucket     # KMS encrypted, in your account
  s3_prefix: {name}
  # kms_key_id: arn:aws:kms:REGION:ACCOUNT:key/ID   # customer managed key (optional)

source:
  engine: postgresql
  host: source.db.example.internal
  port: 5432
  database: app
  secret_arn: arn:aws:secretsmanager:REGION:ACCOUNT:secret:liftproof/source   # username, password
  sslmode: verify-full          # full certificate verification; lowering it is reported
  # sslrootcert: /opt/liftproof/certs/private-ca.pem
  statement_timeout_ms: 600000
  rows_per_second: 0            # application side hashing only; 0 = unlimited

target:
  engine: postgresql
  host: target.cluster-xyz.REGION.rds.amazonaws.com
  port: 5432
  database: app
  secret_arn: arn:aws:secretsmanager:REGION:ACCOUNT:secret:liftproof/target
  sslmode: verify-full
  sslrootcert: /opt/liftproof/certs/rds-global-bundle.pem

web:                            # record and replay; omit for database only projects
  source_url: https://app.example.internal
  target_url: https://app.example.com
  capture_bodies: ["/api/*"]    # bodies kept for value comparison; others: hash and shape
  compare_headers: []           # only these response headers are compared
  ignore_json_paths: []         # e.g. "$.generated_at" or "GET /api/orders/{{id}} $.etag"
  ignore_text: []               # regular expressions masked in page content
  step_timeout_ms: 15000

database:
  schemas: [public]
  # tables: [orders, customers]   # default: every table in the schemas
  rows_per_bucket: 50000
  timestamp_precision: 6
  diff_row_limit: 100
  show_values: false            # the report is an egress path; values need an explicit opt in
  business_keys: {{}}           # e.g. orders: [order_number] where keys were renumbered
  ignore:
    # - table: sessions
    #   reason: session tokens are not migrated
    # - table: orders
    #   column: last_synced_at
    #   reason: rewritten by ETL
"""
