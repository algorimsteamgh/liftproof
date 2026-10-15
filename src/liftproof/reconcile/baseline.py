"""Baselines (PRD F2, Technical Spec 9.2, 9.16, 14).

A baseline is taken inside one consistent snapshot and records its consistency position.
Where a database cannot hold one snapshot that long, each table is read in a snapshot of
its own, and the baseline then says that cross table consistency was not held. Each table
is checkpointed as it completes, so a lost instance or session resumes from the last
finished table instead of starting again.

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
import queue
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from liftproof import __version__
from liftproof.adapters.base import (
    Adapter,
    BucketAggregate,
    Column,
    ForeignKey,
    HashPlan,
    Index,
    TableRef,
    TableSchema,
)
from liftproof.canonical import (
    CANONICAL_REVISION,
    CANONICAL_VERSION,
    HASH_ALGORITHM,
    CanonicalType,
    RenderError,
    reduce_total,
)
from liftproof.canonical.typemap import DEFAULT_TYPE_MAP, TypeMap, legacy_record, shown
from liftproof.errors import ConfigError, RunFailed
from liftproof.reconcile import ranges
from liftproof.reconcile.plan import (
    NOT_CANONICALISABLE,
    NOT_IN_BASELINE,
    IgnoreRule,
    map_types,
    plan_table,
)

SIDES = ("source", "target")
# how a baseline holds its snapshot (spec 9.2): one over every table, or one per table
SNAPSHOT_MODES = ("whole", "per_table")
# native types the adapters map to xml since canonical revision 2 (MySQL has none)
XML_NATIVE = {"xml", "xmltype"}
REASON_XML = (
    "the baseline was taken before XML was compared (canonical revision 2); "
    "take it again to compare this column"
)


@dataclass
class BaselineTable:
    schema: TableSchema
    plan: HashPlan
    row_count: int
    buckets: dict[int, BucketAggregate]
    completed_at: str
    # the report's data ranges of this side when the baseline was taken (ranges.py)
    ranges: dict[str, list[Any]] = field(default_factory=dict)
    # the canonical revision it was hashed under; 0 for entries from before revisions
    canonical_revision: int = CANONICAL_REVISION
    # columns of a compared type it did not hash: lower cased name -> (issue, why)
    unhashed: dict[str, tuple[str, str]] = field(default_factory=dict)
    # when the snapshot it was read in was taken, and which: the baseline's (whole), its
    # own (per_table), or none (SQL Server without snapshot isolation); None for entries
    # from before they were kept
    read_at: str | None = None
    snapshot: str | None = None

    @property
    def aggregate(self) -> str:
        return reduce_total(sum(b.total for b in self.buckets.values()))

    def to_dict(self) -> dict[str, Any]:
        d = {
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
            "ranges": self.ranges,
            "canonical_revision": self.canonical_revision,
            "unhashed": {c: list(v) for c, v in sorted(self.unhashed.items())},
        }
        if self.snapshot:
            d.update(read_at=self.read_at, snapshot=self.snapshot)
        # structure (spec 9.13), each part only when known: an entry from an older manifest,
        # saved again by a resume, must not claim every column nullable
        schema = self.schema
        if all(c.nullable is not None for c in schema.columns):
            d["not_null"] = [c.name for c in schema.columns if not c.nullable]
        if schema.indexes is not None:
            d["indexes"] = [
                {"name": i.name, "columns": list(i.columns), "unique": i.unique, "kind": i.kind}
                for i in schema.indexes
            ]
        if schema.foreign_keys is not None:
            d["foreign_keys"] = [
                {
                    "name": f.name,
                    "columns": list(f.columns),
                    "references": [f.references.schema, f.references.name],
                    "referenced_columns": list(f.referenced_columns),
                }
                for f in schema.foreign_keys
            ]
        return d

    @classmethod
    def from_dict(cls, qualified: str, d: dict[str, Any]) -> BaselineTable:
        ref = TableRef(*qualified.split(".", 1))
        revision = int(d.get("canonical_revision", 0))
        unhashed = {c: (i, why) for c, (i, why) in d.get("unhashed", {}).items()}
        columns = []
        not_null = set(d["not_null"]) if "not_null" in d else None
        for n, nt, ct, fw in d["columns"]:
            ctype = CanonicalType(ct)
            if revision < 2 and ctype is CanonicalType.UNSUPPORTED and nt.lower() in XML_NATIVE:
                # typed as this build types it, so a target that retyped it is still told
                # apart; it was never hashed, so it is not compared until taken again
                ctype = CanonicalType.XML
                unhashed[n.lower()] = (NOT_IN_BASELINE, REASON_XML)
            nullable = None if not_null is None else n not in not_null
            columns.append(Column(n, nt, ctype, fw, nullable))
        indexes = None
        if "indexes" in d:
            indexes = [
                Index(i["name"], tuple(i["columns"]), bool(i["unique"]), i["kind"])
                for i in d["indexes"]
            ]
        fks = None
        if "foreign_keys" in d:
            fks = [
                ForeignKey(f["name"], tuple(f["columns"]), TableRef(*f["references"]),
                           tuple(f["referenced_columns"]))
                for f in d["foreign_keys"]
            ]  # fmt: skip
        schema = TableSchema(ref, columns, list(d["primary_key"]), indexes, fks)
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
        return cls(
            schema,
            plan,
            int(d["row_count"]),
            buckets,
            d["completed_at"],
            d.get("ranges", {}),
            revision,
            unhashed,
            d.get("read_at"),
            d.get("snapshot"),
        )


def hashed_infinity_as_null(engine: str, entry: BaselineTable) -> bool:
    """Whether a PostgreSQL entry from before canonical revision 1 can hold an infinity
    date or timestamp hashed as NULL. Not when it was hashed here (a JSON column): loading
    infinity failed then. Nor when its data ranges cover every date column: reading the
    ranges of a column holding infinity failed too."""
    if engine != "postgresql" or entry.canonical_revision >= 1:
        return False
    if any(t == CanonicalType.JSON for _, t in entry.plan.columns):
        return False
    return any(t in ranges.DATES and n not in entry.ranges for n, t in entry.plan.columns)


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
    # whole, per_table, or mixed: resumed in the other mode
    snapshot_mode: str = "whole"
    # per table: a position read after the last table, which replication must reach
    end_position: dict[str, Any] | None = None
    # the type map it was taken under (TypeMap.record); a manifest from before it was
    # recorded was taken under version 1.0 without overrides
    type_map: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.type_map is None:
            self.type_map = legacy_record(self.engine)

    @property
    def complete(self) -> bool:
        return all(q in self.tables for q in self.selection)

    @property
    def reference_position(self) -> dict[str, Any]:
        """What replication must have applied through (spec 9.2): the latest point a table
        was read at. Per table, the position read after the last table; otherwise the
        snapshot the last tables were read in, the first one or a resume's."""
        if self.end_position is not None:
            return self.end_position
        snapshots = [self.position, *self.position.get("resumed_at", [])]
        read = [t.read_at for t in self.tables.values() if t.read_at]
        if not read:  # entries from before read_at: the last snapshot opened
            return snapshots[-1]
        last = max(read, key=dt.datetime.fromisoformat)
        return next((s for s in snapshots if s.get("taken_at") == last), snapshots[-1])

    def consistency(self) -> dict[str, Any]:
        """Whether every table was read at one point (spec 9.2), and in plain words why
        not: tables read per table, after a resume, or without a snapshot at all."""
        tables = list(self.tables.values())
        if self.position.get("consistent") is False or any(t.snapshot == "none" for t in tables):
            return {
                "held": False,
                "snapshot": "none",
                "summary": f"Cross table consistency was not held: the {self.side} was read "
                "without a snapshot (SQL Server snapshot isolation is off), so neither the "
                "tables nor one table's count and hashes were read at one point.",
            }
        resumed = [str(p.get("taken_at")) for p in self.position.get("resumed_at", [])]
        if resumed and not all(t.snapshot for t in tables):  # entries that did not say where
            return {
                "held": False,
                "snapshot": self.snapshot_mode,
                "summary": "Cross table consistency was not held: the baseline was resumed at "
                f"{', '.join(resumed)}, and the tables finished after a resume were read in "
                "a later snapshot.",
            }
        # snapshots, not times: two can be taken within one tick of the database's clock
        own = sum(t.snapshot == "per_table" for t in tables)
        points = own + len({t.read_at for t in tables if t.snapshot != "per_table"})
        if points > 1:
            times = sorted({t.read_at for t in tables if t.read_at}, key=dt.datetime.fromisoformat)
            how = (
                "each in its own snapshot" if own == len(tables)
                else "part of them each in its own snapshot, after a resume" if own
                else "in a new snapshot after a resume"
            )  # fmt: skip
            return {
                "held": False,
                "snapshot": self.snapshot_mode,
                "read_between": [times[0], times[-1]],
                "summary": f"Cross table consistency was not held: the {self.side}'s tables "
                f"were read at {points} points from {times[0]} to {times[-1]} ({how}), so a "
                "row that refers to another table may have been read at a different point "
                "than that table.",
            }
        return {
            "held": True,
            "snapshot": self.snapshot_mode,
            "summary": f"Every table of the {self.side} was read in one snapshot.",
        }

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
            "snapshot_mode": self.snapshot_mode,
            "end_position": self.end_position,
            "type_map": self.type_map,
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
        revision = max(
            (int(t.get("canonical_revision", 0)) for t in d["tables"].values()), default=0
        )
        if revision > CANONICAL_REVISION:
            raise ConfigError(
                f"baseline {d['baseline_id']} was hashed under canonical revision {revision}; "
                f"this build knows revision {CANONICAL_REVISION} and cannot compare it. "
                "Use a build at least as new as the one that took it."
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
            snapshot_mode=d.get("snapshot_mode", "whole"),
            end_position=d.get("end_position"),
            type_map=d.get("type_map"),
        )
        b.tables = {q: BaselineTable.from_dict(q, t) for q, t in d["tables"].items()}
        return b


def _snapshot_too_old(exc: Exception) -> bool:
    """The database could not keep the snapshot: PostgreSQL's snapshot too old (SQLSTATE
    72000, old_snapshot_threshold), Oracle's ORA-01555 (undo retention)."""
    return getattr(exc, "sqlstate", None) == "72000" or "ORA-01555" in str(exc)


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
    workers: int = 1,
    checkpoint: Callable[[], object] = lambda: None,
    with_ranges: bool = True,
    snapshot: str = "whole",
    type_map: TypeMap = DEFAULT_TYPE_MAP,
) -> Baseline:
    """`checkpoint` runs after each table's entry is saved to the manifest; the CLI
    copies the manifest to the store there. `snapshot`: whole holds one snapshot over
    every table; per_table opens one for each table instead, for a database that cannot
    hold one that long (spec 9.2). `type_map` types the columns, as a comparison does."""
    if side not in SIDES:
        raise ValueError(f"side must be one of {SIDES}")
    if snapshot not in SNAPSHOT_MODES:
        raise ValueError(f"snapshot must be one of {SNAPSHOT_MODES}")
    per_table = snapshot == "per_table"
    existing = Baseline.load(manifest_path) if resume and manifest_path.exists() else None
    if existing is not None and existing.side != side:
        raise ConfigError(
            f"baseline {existing.baseline_id} is a {existing.side} baseline; "
            f"it cannot be resumed as a {side} baseline"
        )
    mapping = type_map.record(source.engine)
    if existing is not None and existing.type_map["fingerprints"] != mapping["fingerprints"]:
        # its finished tables were typed otherwise than the rest would be
        raise ConfigError(
            f"baseline {existing.baseline_id} was started under {shown(existing.type_map)}, "
            f"not {shown(mapping)}; resume it with the database.type_map it was started "
            "with, or take a new baseline"
        )
    position = source.begin_snapshot()
    try:
        refs = source.list_tables(schemas)
        if tables:
            wanted = {t.lower() for t in tables}
            refs = [r for r in refs if r.qualified.lower() in wanted or r.name.lower() in wanted]
        if existing is not None and not tables:
            # resumed without a table list: the tables it set out to take, no more
            planned = set(existing.selection)
            refs = [r for r in refs if r.qualified in planned]
        if existing is not None:
            baseline = existing
            if not existing.complete:
                progress(
                    f"resuming baseline {existing.baseline_id}; "
                    f"{len(existing.tables)} of {len(existing.selection)} tables done"
                )
        else:
            baseline = Baseline(
                baseline_id,
                source.engine,
                position,
                source.session_settings(),
                dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
                selection=[r.qualified for r in refs],
                side=side,
                snapshot_mode=snapshot,
                type_map=mapping,
            )
        todo = [
            ref
            for ref in refs
            if ref.qualified not in baseline.tables
            and not any(r.whole_table and r.matches_table(ref.qualified) for r in ignore)
        ]
        if existing is not None and todo:
            # the rest is read at a later point than the tables done; each table records
            # when, so the baseline says that consistency was not held
            baseline.position.setdefault("resumed_at", []).append(position)
            if baseline.snapshot_mode != snapshot:
                baseline.snapshot_mode = "mixed"
        if per_table:
            source.end_snapshot()  # it held the table list; each table opens its own

        def one(a: Adapter, ref: TableRef) -> BaselineTable:
            if not per_table:
                return read(a, ref, position)
            own = a.begin_snapshot()  # the table's schema, count, hashes and ranges
            try:
                return read(a, ref, own)
            finally:
                a.end_snapshot()

        def read(a: Adapter, ref: TableRef, snap: dict[str, Any]) -> BaselineTable:
            progress(f"baselining {ref}")
            schema, _ = map_types(a.describe(ref), a.engine, type_map, side)
            with a.pacer.statement() as scan:  # each read of the table is charged (9.15)
                rows = scan.rows = a.row_count(ref)
            unhashed: dict[str, tuple[str, str]] = {}
            while True:
                tp = plan_table(
                    schema,
                    None,
                    rows=rows,
                    rows_per_bucket=rows_per_bucket,
                    precision=precision,
                    ignore=ignore,
                    business_key=business_keys.get(ref.qualified) or business_keys.get(ref.name),
                    side=side,
                    unhashed=unhashed,
                )
                if tp.plan.filter and not a.supports_row_filters:
                    raise ConfigError(f"{ref}: row ignore rules are not supported for {a.engine}")
                buckets: dict[int, BucketAggregate] = {}
                try:
                    if tp.plan.columns:
                        with a.pacer.statement(scan.rows):
                            buckets = a.bucket_aggregates(tp.plan)
                    break
                except RenderError as exc:
                    # a value that cannot be canonicalised: the table is hashed again without
                    # its column, which runs against this baseline report as not checked
                    if exc.column is None or exc.column.lower() in unhashed:
                        raise
                    progress(f"{ref}: column {exc.column} is not hashed: {exc.reason}")
                    unhashed[exc.column.lower()] = (
                        NOT_CANONICALISABLE,
                        f"when the baseline was taken, {exc.reason}",
                    )
            if tp.plan.filter:  # the rows the baseline holds, not the table's
                rows = sum(b.count for b in buckets.values())
            spans = {}
            names = list(ranges.columns_for(tp.plan)) if with_ranges else []
            if names:
                with a.pacer.statement(scan.rows):
                    spans = ranges.read(a, ref, schema, names, tp.plan.filter)
            return BaselineTable(
                schema,
                tp.plan,
                rows,
                buckets,
                dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
                spans,
                unhashed=unhashed,
                read_at=snap.get("taken_at"),
                snapshot="none" if snap.get("consistent") is False else snapshot,
            )

        n = min(workers, len(todo))
        # A whole baseline is one state of the database: workers only when every
        # connection can read the snapshot this one holds. Per table each worker opens its
        # own, unless the database has none to open: each would be another locking reader.
        if n > 1 and per_table and position.get("consistent") is False:
            progress(
                f"{source.engine} reads this database without a snapshot; "
                "tables are baselined one at a time"
            )
            n = 1
        elif n > 1 and not (
            source.supports_workers and (per_table or source.shares_snapshot(position))
        ):
            progress(
                f"{source.engine} cannot share this snapshot between connections; "
                "tables are baselined one at a time"
            )
            n = 1
        if n <= 1:
            for ref in todo:
                baseline.tables[ref.qualified] = one(source, ref)
                baseline.save(manifest_path)  # checkpoint per table
                checkpoint()
        else:
            # every worker imports the snapshot exported above, or opens one per table
            free: queue.SimpleQueue[Adapter] = queue.SimpleQueue()
            free.put(source)
            forks: list[Adapter] = []
            try:
                for _ in range(n - 1):
                    forks.append(source.fork(None if per_table else position))
                    free.put(forks[-1])

                def job(ref: TableRef) -> tuple[TableRef, BaselineTable]:
                    a = free.get()
                    try:
                        return ref, one(a, ref)
                    finally:
                        free.put(a)

                with ThreadPoolExecutor(max_workers=n) as pool:
                    for f in as_completed([pool.submit(job, ref) for ref in todo]):
                        ref, entry = f.result()
                        baseline.tables[ref.qualified] = entry
                        baseline.save(manifest_path)  # checkpoint per table
                        checkpoint()
            finally:
                for a in forks:
                    a.end_snapshot()
                    a.close()
        if todo:
            # replication must reach the latest point a table was read at; per table, that
            # is a position read after the last one
            none = {"type": "none", "position": None}
            baseline.end_position = (source.current_position() or none) if per_table else None
        baseline.selection = [r.qualified for r in refs if r.qualified in baseline.tables]
        baseline.save(manifest_path)
        return baseline
    except Exception as exc:
        if per_table or not _snapshot_too_old(exc):
            raise
        raise RunFailed(
            f"{exc}. The {side} could not keep one snapshot for the whole baseline: set "
            f"{side}.snapshot: per_table in the project file and finish it with --resume"
        ) from exc
    finally:
        source.end_snapshot()
