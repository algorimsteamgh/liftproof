"""Baselines (PRD F2, Technical Spec 9.2, 9.16, 14).

A baseline is taken inside one consistent snapshot and records its consistency position.
Each table is checkpointed as it completes, so a lost instance or session resumes from
the last finished table instead of starting again.

A source baseline freezes the source before cutover. A target baseline (`rebaseline`)
snapshots the target after cutover, so scheduled regression compares the target with its
own accepted state rather than with a pre migration source that live traffic has long
since moved away from.

A baseline holds per bucket aggregates, not per row hashes. Row level drill-down at
validate time therefore needs the source database to still be readable, and is not
possible at all against a target baseline: the past state of the target cannot be re-read.
"""

from __future__ import annotations

import datetime as dt
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from liftproof import __version__
from liftproof.adapters.base import (
    Adapter,
    BucketAggregate,
    Column,
    HashPlan,
    TableRef,
    TableSchema,
)
from liftproof.canonical import CANONICAL_VERSION, HASH_ALGORITHM, CanonicalType, reduce_total
from liftproof.errors import ConfigError
from liftproof.reconcile.plan import IgnoreRule, plan_table

SIDES = ("source", "target")


@dataclass
class BaselineTable:
    schema: TableSchema
    plan: HashPlan
    row_count: int
    buckets: dict[int, BucketAggregate]
    completed_at: str

    @property
    def aggregate(self) -> str:
        return reduce_total(sum(b.total for b in self.buckets.values()))

    def to_dict(self) -> dict[str, Any]:
        return {
            "columns": [
                [c.name, c.native_type, str(c.canonical), c.fixed_width]
                for c in self.schema.columns
            ],
            "primary_key": self.schema.primary_key,
            "plan": {
                "columns": [[n, str(t)] for n, t in self.plan.columns],
                "key_columns": self.plan.key_columns,
                "buckets": self.plan.buckets,
                "precision": self.plan.precision,
                "strategy": self.plan.strategy,
                "filter": self.plan.filter,
            },
            "row_count": self.row_count,
            "aggregate": self.aggregate,
            # totals as strings: they exceed 64 bits and JSON readers lose precision
            "bucket_aggregates": {
                str(b): [a.count, str(a.total)] for b, a in sorted(self.buckets.items())
            },
            "completed_at": self.completed_at,
        }

    @classmethod
    def from_dict(cls, qualified: str, d: dict[str, Any]) -> BaselineTable:
        ref = TableRef(*qualified.split(".", 1))
        schema = TableSchema(
            ref,
            [Column(n, nt, CanonicalType(ct), fw) for n, nt, ct, fw in d["columns"]],
            list(d["primary_key"]),
        )
        p = d["plan"]
        plan = HashPlan(
            ref,
            [(n, CanonicalType(t)) for n, t in p["columns"]],
            list(p["key_columns"]),
            int(p["buckets"]),
            int(p["precision"]),
            p.get("strategy", "hash"),
            p.get("filter"),
        )
        buckets = {
            int(b): BucketAggregate(int(c), int(t)) for b, (c, t) in d["bucket_aggregates"].items()
        }
        return cls(schema, plan, int(d["row_count"]), buckets, d["completed_at"])


@dataclass
class Baseline:
    baseline_id: str
    engine: str
    position: dict[str, Any]
    session: dict[str, str]
    taken_at: str
    canonical_version: str = CANONICAL_VERSION
    hash_algorithm: str = HASH_ALGORITHM
    product_version: str = __version__
    selection: list[str] = field(default_factory=list)
    tables: dict[str, BaselineTable] = field(default_factory=dict)
    side: str = "source"  # target: taken by rebaseline

    @property
    def complete(self) -> bool:
        return all(q in self.tables for q in self.selection)

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline_id": self.baseline_id,
            "canonical_version": self.canonical_version,
            "hash_algorithm": self.hash_algorithm,
            "product_version": self.product_version,
            "engine": self.engine,
            "side": self.side,
            "consistency": self.position,
            "session": self.session,
            "taken_at": self.taken_at,
            "selection": self.selection,
            "complete": self.complete,
            "tables": {q: t.to_dict() for q, t in sorted(self.tables.items())},
        }

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(path)

    @classmethod
    def load(cls, path: Path) -> Baseline:
        try:
            d = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise ConfigError(f"baseline manifest not found: {path}") from exc
        if d["canonical_version"] != CANONICAL_VERSION or d["hash_algorithm"] != HASH_ALGORITHM:
            raise ConfigError(
                f"baseline {d['baseline_id']} was computed under canonical "
                f"{d['canonical_version']}/{d['hash_algorithm']}; this build uses "
                f"{CANONICAL_VERSION}/{HASH_ALGORITHM}. They cannot be compared."
            )
        b = cls(
            d["baseline_id"],
            d["engine"],
            d["consistency"],
            d["session"],
            d["taken_at"],
            d["canonical_version"],
            d["hash_algorithm"],
            d["product_version"],
            list(d["selection"]),
            side=d.get("side", "source"),  # manifests from before rebaseline existed
        )
        b.tables = {q: BaselineTable.from_dict(q, t) for q, t in d["tables"].items()}
        return b


def take_baseline(
    source: Adapter,
    manifest_path: Path,
    *,
    baseline_id: str,
    schemas: list[str],
    tables: list[str] | None,
    ignore: list[IgnoreRule],
    business_keys: dict[str, list[str]],
    rows_per_bucket: int,
    precision: int,
    resume: bool = False,
    side: str = "source",
    progress: Callable[[str], None] = lambda _m: None,
) -> Baseline:
    if side not in SIDES:
        raise ValueError(f"side must be one of {SIDES}")
    existing = Baseline.load(manifest_path) if resume and manifest_path.exists() else None
    if existing is not None and existing.side != side:
        raise ConfigError(
            f"baseline {existing.baseline_id} is a {existing.side} baseline; "
            f"it cannot be resumed as a {side} baseline"
        )
    position = source.begin_snapshot()
    try:
        refs = source.list_tables(schemas)
        if tables:
            wanted = {t.lower() for t in tables}
            refs = [r for r in refs if r.qualified.lower() in wanted or r.name.lower() in wanted]
        if existing is not None:
            baseline = existing
            if not existing.complete:
                progress(
                    f"resuming baseline {existing.baseline_id}; "
                    f"{len(existing.tables)} of {len(existing.selection)} tables done"
                )
            # A resumed baseline keeps its original position only if the source still
            # holds that point; record the new one per table otherwise.
            baseline.position.setdefault("resumed_at", []).append(position)
        else:
            baseline = Baseline(
                baseline_id,
                source.engine,
                position,
                source.session_settings(),
                dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
                selection=[r.qualified for r in refs],
                side=side,
            )
        for ref in refs:
            if ref.qualified in baseline.tables:
                continue
            ignored = any(r.whole_table and r.matches_table(ref.qualified) for r in ignore)
            if ignored:
                continue
            progress(f"baselining {ref}")
            schema = source.describe(ref)
            rows = source.row_count(ref)
            tp = plan_table(
                schema,
                None,
                rows=rows,
                rows_per_bucket=rows_per_bucket,
                precision=precision,
                ignore=ignore,
                business_key=business_keys.get(ref.qualified) or business_keys.get(ref.name),
                side=side,
            )
            if tp.plan.filter and not source.supports_row_filters:
                raise ConfigError(f"{ref}: row ignore rules are not supported for {source.engine}")
            buckets = source.bucket_aggregates(tp.plan) if tp.plan.columns else {}
            if tp.plan.filter:  # the rows the baseline holds, not the table's
                rows = sum(b.count for b in buckets.values())
            baseline.tables[ref.qualified] = BaselineTable(
                schema,
                tp.plan,
                rows,
                buckets,
                dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
            )
            baseline.save(manifest_path)  # checkpoint per table
        baseline.selection = [r.qualified for r in refs if r.qualified in baseline.tables]
        baseline.save(manifest_path)
        return baseline
    finally:
        source.end_snapshot()
