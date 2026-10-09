"""Has replication caught up? (Technical Spec 9.2, 18)

The question the product is sold to answer is whether the target holds everything the
source held at the cutover point. A row still in flight through replication is not a
lost row, so before any difference is reported the target side asserts that replication
has applied through the reference position: the baseline's, or the live source's at the
start of the run. When it has not, the tables are reported not_checked with the reason,
never as differences.

Methods (project file, database.replication):
- subscription: PostgreSQL native logical replication; read on the target.
- slot: a logical replication slot on a PostgreSQL source, whoever consumes it (AWS DMS
  included); read on the source.
- replica: MySQL replication (GTID or binlog position); read on a MySQL target.
- dms: an AWS DMS task, from any source engine to any target engine; read on the target
  from the task's awsdms_status control table (StatusTableEnabled in the task settings).
  DMS reports times, not positions, so the reference is the time the snapshot was taken,
  on the source's clock: replication has caught up when the task has applied a commit
  made at or after it, or has read past it with nothing pending.
- goldengate: an Oracle GoldenGate Replicat, from any source engine to any target engine;
  read on the target. Its checkpoint table (CHECKPOINTTABLE) says up to which source CSN
  every transaction is applied, which for an Oracle source is the SCN the snapshot was
  taken at. Its heartbeat table (ADD HEARTBEATTABLE) carries a source timestamp through
  the Replicat about once a minute, so it also answers for other source engines and for
  an idle source, whose CSN stops moving: caught up when either says so.
- availability_group: a SQL Server Always On availability group (a distributed one
  included) with the target as a secondary replica; read on the source (the primary),
  where every replica's last redone commit LSN is visible. The reference is the
  primary's last commit LSN when the snapshot was taken.
- none: no check. The report says the position was not verified.
"""

from __future__ import annotations

import datetime as dt
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from liftproof.adapters.base import Adapter
from liftproof.errors import ConfigError

METHODS = ("none", "subscription", "slot", "replica", "dms", "goldengate", "availability_group")
# which side each method is read on
SOURCE_SIDE = ("slot", "availability_group")
NAME_OPTIONAL = ("replica",)  # MySQL's default replication channel has no name
REASON_BEHIND = "replication behind the baseline point"
PLAIN = r"[A-Za-z_][A-Za-z0-9_$#]*"


@dataclass
class ReplicationConfig:
    method: str = "none"
    name: str | None = None  # the subscription, slot, replica channel or DMS task
    wait_seconds: int = 0  # how long to wait for it to catch up before giving up
    poll_seconds: int = 5
    control_schema: str | None = None  # dms: the task's ControlSchema, when it sets one
    checkpoint_table: str | None = None  # goldengate: the Replicat's CHECKPOINTTABLE
    heartbeat_table: str | None = None  # goldengate: GG_HEARTBEAT, schema qualified

    @classmethod
    def from_dict(cls, d: Any) -> ReplicationConfig:
        if not d:
            return cls()
        if not isinstance(d, dict):
            raise ConfigError("database.replication must be a mapping (method, name)")
        method = str(d.get("method", "none"))
        if method not in METHODS:
            raise ConfigError(f"database.replication.method must be one of {', '.join(METHODS)}")
        name = d.get("name")
        if method not in ("none", *NAME_OPTIONAL) and not name:
            raise ConfigError(f"database.replication.name is required for method {method}")
        schema = d.get("control_schema")
        if schema is not None and not re.fullmatch(PLAIN, str(schema)):
            raise ConfigError("database.replication.control_schema must be a plain name")
        tables = {}
        for key in ("checkpoint_table", "heartbeat_table"):
            v = d.get(key)
            if v is not None and not re.fullmatch(rf"({PLAIN}\.)?{PLAIN}", str(v)):
                raise ConfigError(f"database.replication.{key} must be table or schema.table")
            tables[key] = str(v) if v else None
        if method == "goldengate" and not any(tables.values()):
            raise ConfigError(
                "database.replication needs checkpoint_table, heartbeat_table or both for "
                "method goldengate"
            )
        return cls(
            method,
            str(name) if name else None,
            int(d.get("wait_seconds", 0)),
            control_schema=str(schema) if schema else None,
            **tables,
        )


@dataclass
class ReplicationResult:
    status: str  # caught_up | behind | unverified
    position: str | None
    applied: str | None
    method: str
    detail: str
    waited_seconds: float = 0.0

    @property
    def behind(self) -> bool:
        return self.status == "behind"


def check(
    cfg: ReplicationConfig,
    position: dict[str, Any] | None,
    *,
    source: Adapter | None,
    target: Adapter,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> ReplicationResult:
    pos = (position or {}).get("position")
    kind = (position or {}).get("type")
    if cfg.method == "none":
        return ReplicationResult("unverified", pos, None, "none",
                                 "no replication check is configured")  # fmt: skip
    if cfg.method == "dms":
        taken = (position or {}).get("taken_at")
        if not taken:
            return ReplicationResult("unverified", None, None, "dms",
                                     "the reference has no snapshot time")  # fmt: skip
        pos, kind = str(taken), "time"
    elif cfg.method == "goldengate":
        if not (position or {}).get("taken_at") and kind != "scn":
            return ReplicationResult("unverified", None, None, "goldengate",
                                     "the reference has neither an SCN nor a snapshot "
                                     "time")  # fmt: skip
        if kind != "scn" and not cfg.heartbeat_table:
            return ReplicationResult("unverified", None, None, "goldengate",
                                     "the checkpoint table holds source CSNs, which only an "
                                     "Oracle source's SCN can be compared with; set "
                                     "heartbeat_table for other sources")  # fmt: skip
        pos = pos if kind == "scn" else str(position["taken_at"])
    elif cfg.method == "availability_group":
        pos, kind = (position or {}).get("commit_lsn"), "commit_lsn"
        if not pos:
            return ReplicationResult("unverified", None, None, cfg.method,
                                     "the reference has no availability group commit LSN: "
                                     "the source database is not in an availability group, "
                                     "or the login lacks VIEW SERVER STATE")  # fmt: skip
    elif not pos or not kind:
        return ReplicationResult("unverified", None, None, cfg.method,
                                 "the reference has no consistency position")  # fmt: skip
    where = "source" if cfg.method in SOURCE_SIDE else "target"
    side = source if where == "source" else target
    if side is None:
        return ReplicationResult("unverified", pos, None, cfg.method,
                                 f"the {where} is not connected, so the {cfg.method} "
                                 "cannot be read")  # fmt: skip
    if cfg.method not in side.replication_methods:
        raise ConfigError(
            f"replication method {cfg.method} is not available for the {where} engine {side.engine}"
        )
    label = f"{cfg.method} {cfg.name}" if cfg.name else f"{cfg.method} (default channel)"
    started = clock()
    while True:
        if cfg.method == "dms":
            got = _dms_reached(side, cfg, pos)
        elif cfg.method == "goldengate":
            got = _gg_reached(side, cfg, position or {})
        else:
            got = side.replication_reached(cfg.method, cfg.name or "", kind, pos)
        if got is None:
            raise ConfigError(f"{label} not found on the {where}")
        applied, reached = got
        waited = clock() - started
        if reached:
            return ReplicationResult("caught_up", pos, applied, cfg.method,
                                     f"{label} has applied {applied}, at or "
                                     f"past {pos}", round(waited, 1))  # fmt: skip
        if waited >= cfg.wait_seconds:
            return ReplicationResult("behind", pos, applied, cfg.method,
                                     f"{label} has applied {applied}; the "
                                     f"reference position is {pos}", round(waited, 1))  # fmt: skip
        sleep(min(cfg.poll_seconds, max(cfg.wait_seconds - waited, 0.1)))


def _utc(value: Any) -> dt.datetime | None:
    if value is None:
        return None
    if isinstance(value, str):
        value = dt.datetime.fromisoformat(value)
    # DMS writes its control tables in UTC
    return value.replace(tzinfo=dt.UTC) if value.tzinfo is None else value


def _dms_reached(target: Adapter, cfg: ReplicationConfig, taken_at: str) -> tuple[str, bool] | None:
    row = target.dms_status(cfg.control_schema or target.dms_schema, cfg.name or "")
    if row is None:
        return None
    ref = _utc(taken_at)
    applied = _utc(row["source_timestamp_applied"])
    read = _utc(row["source_current_timestamp"])
    pending = row["pending_changes"]
    reached = (applied is not None and applied >= ref) or (
        pending == 0 and read is not None and read >= ref
    )
    text = (
        f"source commits up to {applied.isoformat() if applied else 'none'} "
        f"(task {str(row['task_status']).strip().lower()}, {pending} changes pending)"
    )
    return text, reached


def _gg_reached(
    target: Adapter, cfg: ReplicationConfig, position: dict[str, Any]
) -> tuple[str, bool] | None:
    st = target.goldengate_status(cfg.checkpoint_table, cfg.heartbeat_table, cfg.name or "")
    if st is None:
        return None
    scn = position.get("position") if position.get("type") == "scn" else None
    taken = _utc(position.get("taken_at"))
    csn, beat = st["csn"], _utc(st["heartbeat"])
    by_csn = scn is not None and csn is not None and csn >= int(scn)
    by_beat = taken is not None and beat is not None and beat >= taken
    parts = []
    if cfg.checkpoint_table:
        parts.append(f"source CSN {csn if csn is not None else 'none'}")
    if cfg.heartbeat_table:
        parts.append(f"heartbeat from {beat.isoformat() if beat else 'none'}")
    return ", ".join(parts), by_csn or by_beat
