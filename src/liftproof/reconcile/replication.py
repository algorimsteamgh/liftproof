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

METHODS = ("none", "subscription", "slot", "replica", "dms")
# which side each method is read on
SOURCE_SIDE = ("slot",)
NAME_OPTIONAL = ("replica",)  # MySQL's default replication channel has no name
REASON_BEHIND = "replication behind the baseline point"


@dataclass
class ReplicationConfig:
    method: str = "none"
    name: str | None = None  # the subscription, slot, replica channel or DMS task
    wait_seconds: int = 0  # how long to wait for it to catch up before giving up
    poll_seconds: int = 5
    control_schema: str | None = None  # dms: the task's ControlSchema, when it sets one

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
        if schema is not None and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_$]*", str(schema)):
            raise ConfigError("database.replication.control_schema must be a plain name")
        return cls(
            method,
            str(name) if name else None,
            int(d.get("wait_seconds", 0)),
            control_schema=str(schema) if schema else None,
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
