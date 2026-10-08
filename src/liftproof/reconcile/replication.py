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
- none: no check. The report says the position was not verified.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from liftproof.adapters.base import Adapter
from liftproof.errors import ConfigError

METHODS = ("none", "subscription", "slot")
REASON_BEHIND = "replication behind the baseline point"


@dataclass
class ReplicationConfig:
    method: str = "none"
    name: str | None = None  # the subscription (target) or slot (source)
    wait_seconds: int = 0  # how long to wait for it to catch up before giving up
    poll_seconds: int = 5

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
        if method != "none" and not name:
            raise ConfigError(f"database.replication.name is required for method {method}")
        return cls(method, str(name) if name else None, int(d.get("wait_seconds", 0)))


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
    if not pos or not kind:
        return ReplicationResult("unverified", None, None, cfg.method,
                                 "the reference has no consistency position")  # fmt: skip
    side = target if cfg.method == "subscription" else source
    where = "target" if cfg.method == "subscription" else "source"
    if side is None:
        return ReplicationResult("unverified", pos, None, cfg.method,
                                 f"the {where} is not connected, so the {cfg.method} "
                                 "cannot be read")  # fmt: skip
    if cfg.method not in side.replication_methods:
        raise ConfigError(
            f"replication method {cfg.method} is not available for the {where} engine {side.engine}"
        )
    want = side.position_key(kind, pos)
    started = clock()
    while True:
        applied = side.replication_applied(cfg.method, cfg.name or "")
        if applied is None:
            raise ConfigError(f"{cfg.method} {cfg.name!r} not found on the {where}")
        waited = clock() - started
        if side.position_key(kind, applied) >= want:
            return ReplicationResult("caught_up", pos, applied, cfg.method,
                                     f"{cfg.method} {cfg.name} has applied {applied}, at or "
                                     f"past {pos}", round(waited, 1))  # fmt: skip
        if waited >= cfg.wait_seconds:
            return ReplicationResult("behind", pos, applied, cfg.method,
                                     f"{cfg.method} {cfg.name} has applied {applied}; the "
                                     f"reference position is {pos}", round(waited, 1))  # fmt: skip
        sleep(min(cfg.poll_seconds, max(cfg.wait_seconds - waited, 0.1)))
