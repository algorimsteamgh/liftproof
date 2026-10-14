"""Database reconciliation (Technical Spec 9.9 to 9.13).

Sequence per table: schema, row counts, table aggregate, bucket aggregates, row key and
hash pairs for differing buckets, then column digests and (optionally) values for rows
present on both sides. On a healthy migration most tables stop at the aggregate.

The reference side is either a live source adapter or a stored baseline. Drill-down
below the bucket level always needs the live source: a baseline holds aggregates only.
Against a target baseline (rebaseline) there is no live reference at all: the comparison
says what has changed in the target since it was accepted, down to the bucket.
"""

from __future__ import annotations

import copy
import heapq
import math
import queue
import random
import secrets
import threading
from collections import Counter
from collections.abc import Callable, Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, replace
from typing import Any

from liftproof.adapters.base import Adapter, BucketAggregate, HashPlan, TableRef, TableSchema
from liftproof.canonical import RowHasher, column_digest, reduce_total
from liftproof.findings import Comparator, Finding, FindingWriter, Kind, Severity
from liftproof.reconcile import ranges
from liftproof.reconcile.baseline import Baseline, hashed_infinity_as_null
from liftproof.reconcile.plan import IgnoreRule, TablePlan, plan_table, row_filter
from liftproof.reconcile.replication import REASON_BEHIND, ReplicationConfig, check

DB = Comparator.DATABASE
INFINITY = {"infinity", "-infinity"}
REASON_STOPPED = "the run stopped before this table was compared"
REASON_INFINITY = "the baseline may hold PostgreSQL infinity dates hashed as NULL"


@dataclass
class ReconcileOptions:
    schemas: list[str] = field(default_factory=lambda: ["public"])
    # source schema -> target schema, for migrations that rename the schema (a MySQL
    # database 'shop' becoming the PostgreSQL schema 'public'); unmapped names match as is
    schema_map: dict[str, str] = field(default_factory=dict)
    tables: list[str] | None = None  # explicit selection, schema.table or table
    ignore: list[IgnoreRule] = field(default_factory=list)
    business_keys: dict[str, list[str]] = field(default_factory=dict)
    rows_per_bucket: int = 50_000
    precision: int = 6
    diff_row_limit: int = 100
    show_values: bool = False
    float_rel_tolerance: float = 1e-9
    breaker_bucket_ratio: float = 0.9
    breaker_min_buckets: int = 4
    breaker_table_ratio: float = 0.8
    breaker_min_tables: int = 5
    replication: ReplicationConfig = field(default_factory=ReplicationConfig)
    # Sampled reconciliation (spec 9.18): tables with more rows than this compare
    # sample_percent of their buckets, chosen at random. None: every table in full.
    sample_above_rows: int | None = None
    sample_percent: float = 10.0
    sample_seed: int | None = None  # None: a fresh seed per run, recorded in the report
    # tables reconciled at once, each worker on its own connections (spec 9.15: worker
    # concurrency multiplies source load, so this is a ceiling to be measured)
    workers: int = 1
    # table -> a column that only grows (identity key, creation time), to tell rows a
    # replay created apart; default: a single column primary key
    replay_watermarks: dict[str, str] = field(default_factory=dict)
    # the range block's data ranges (one MIN/MAX statement per table and side)
    ranges: bool = True


@dataclass
class TableResult:
    table: str
    status: str  # matched | different | not_checked | excluded
    source_rows: int | None = None
    target_rows: int | None = None
    partial: bool = False
    buckets: int = 0
    mismatched_buckets: int = 0
    missing_rows: int = 0
    extra_rows: int = 0
    changed_rows: int = 0
    strategy: str = "hash"
    key: str = ""
    excluded_columns: list[str] = field(default_factory=list)
    approximate_columns: list[str] = field(default_factory=list)
    reason: str | None = None
    # set when only a sample was compared: the share of the table's rows that was
    sampled_percent: float | None = None
    # column -> {"role": key|date, "source": [lowest, highest], "target": [...]}
    ranges: dict[str, dict[str, Any]] = field(default_factory=dict)


@dataclass
class ReconcileResult:
    tables: list[TableResult] = field(default_factory=list)
    systemic: bool = False
    replication: dict[str, Any] | None = None  # the position check, for the report
    sample_seed: int | None = None  # set when a table was sampled: reruns the same sample
    # each database's cap, pause and timeouts as the run read it; no source when it was
    # not read (spec 9.15)
    protection: dict[str, Any] | None = None

    def status_counts(self) -> Counter:
        return Counter(t.status for t in self.tables)


def _short(h: str) -> str:
    return f"md5:{h[:12]}"


def _target_plan(plan: HashPlan, target: TableSchema) -> HashPlan:
    """The same plan, with column names resolved to the target's own spelling."""

    def name(n: str) -> str:
        col = target.column(n)
        return col.name if col else n

    return replace(
        plan,
        table=target.table,
        columns=[(name(n), t) for n, t in plan.columns],
        key_columns=[name(k) for k in plan.key_columns],
    )


class Reconciler:
    def __init__(
        self,
        target: Adapter,
        writer: FindingWriter,
        options: ReconcileOptions,
        *,
        source: Adapter | None = None,
        baseline: Baseline | None = None,
        progress: Callable[[str], None] | None = None,
        on_table: Callable[[ReconcileResult], None] | None = None,
        done: Sequence[TableResult] = (),
        resumed: bool = False,
        systemic: bool = False,
    ) -> None:
        """`on_table` runs after each table, with the findings of every finished table
        written (a checkpoint). `done` and `resumed` continue an interrupted run: those
        tables are not compared again and their findings are already written."""
        if source is None and baseline is None:
            raise ValueError("a live source or a baseline is required")
        self.against_target = baseline is not None and baseline.side == "target"
        if self.against_target and source is not None:
            raise ValueError("a target baseline is compared with the target alone")
        self.reference = "target baseline" if self.against_target else "source"
        self.source = source
        self.baseline = baseline
        self.target = target
        self.writer = writer
        self.o = options
        self.progress = progress or (lambda _msg: None)
        self.on_table = on_table or (lambda _result: None)
        self.result = ReconcileResult(list(done), systemic)
        self.resumed = resumed
        self.planned: list[str] = []
        # shared by the workers, which are shallow copies of this object
        self._flags = {"drill": not systemic}
        self._lock = threading.Lock()
        counted = [t for t in done if t.status in ("matched", "different")]
        self._tally = [sum(t.status == "different" for t in counted), len(counted)]
        # per thread: the findings of the table in hand, written when the table completes,
        # so the written findings only ever cover whole tables
        self._local = threading.local()
        self._seed = (
            options.sample_seed if options.sample_seed is not None else secrets.randbelow(2**31)
        )

    # ------------------------------------------------------------------ helpers
    @property
    def seed(self) -> int:
        """The sampling seed: a resumed run passes it back so it samples alike."""
        return self._seed

    @property
    def _drill(self) -> bool:
        return self._flags["drill"]

    def emit(self, kind: Kind, severity: int, obj: str, summary: str, **kw: Any) -> None:
        finding = Finding(DB, kind, severity, obj, summary, **kw)
        pending = getattr(self._local, "pending", None)
        if pending is not None:
            pending.append(finding)
            return
        with self._lock:
            self.writer.write(finding)

    def _write_table(self, res: TableResult, found: list[Finding]) -> None:
        with self._lock:
            for f in found:
                self.writer.write(f)
        self.result.tables.append(res)
        self._count(res)
        self.on_table(self.result)

    def mark_unfinished(self, why: str) -> None:
        """After a failure: every planned table without a result is named as not
        checked, so coverage counts what exists, not only what finished (spec 12)."""
        seen = {t.table for t in self.result.tables}
        for q in self.planned:
            if q not in seen:
                self.emit(Kind.NOT_CHECKED, Severity.MEDIUM, q, f"{REASON_STOPPED}: {why}",
                          detail={"reason": REASON_STOPPED})  # fmt: skip
                self.result.tables.append(TableResult(q, "not_checked", reason=REASON_STOPPED))

    def _selected(self, tables: Sequence[TableRef]) -> list[TableRef]:
        if not self.o.tables:
            return list(tables)
        wanted = {t.lower() for t in self.o.tables}
        return [t for t in tables if t.qualified.lower() in wanted or t.name.lower() in wanted]

    def _table_ignored(self, table: TableRef) -> IgnoreRule | None:
        for r in self.o.ignore:
            if r.whole_table and r.matches_table(table.qualified):
                return r
        return None

    def _target_key(self, table: TableRef) -> str:
        return f"{self.o.schema_map.get(table.schema, table.schema)}.{table.name}".lower()

    # ---------------------------------------------------------------------- run
    def run(self) -> ReconcileResult:
        if self.baseline is not None:
            source_tables = [TableRef(*q.split(".", 1)) for q in self.baseline.tables]
        else:
            source_tables = self.source.list_tables(self.o.schemas)
        target_schemas = list(dict.fromkeys(self.o.schema_map.get(x, x) for x in self.o.schemas))
        target_tables = {t.qualified.lower(): t for t in self.target.list_tables(target_schemas)}
        source_tables = self._selected(source_tables)
        self.planned = [t.qualified for t in source_tables]
        finished = {t.table for t in self.result.tables}
        remaining = [t for t in source_tables if t.qualified not in finished]
        # Resumed against a live source, the remaining tables are read as of now, so
        # replication must have applied through the source's position now.
        if self._replication_behind(remaining):
            return self.result

        for t in sorted(set(target_tables) - {self._target_key(s) for s in source_tables}):
            if self.o.tables or self.resumed:  # a resumed run already reported these
                break
            self.emit(
                Kind.DIFFERENCE,
                Severity.LOW,
                target_tables[t].qualified,
                "table exists on the target only",
            )

        order = {t.qualified: i for i, t in enumerate(source_tables)}
        work: list[tuple[TableRef, TableRef]] = []
        for table in remaining:
            rule = self._table_ignored(table)
            if rule:
                self.emit(
                    Kind.NOTICE,
                    Severity.INFO,
                    table.qualified,
                    f"table excluded by ignore rule: {rule.reason}",
                    detail={"reason": rule.reason},
                )
                self.result.tables.append(
                    TableResult(table.qualified, "excluded", reason=rule.reason)
                )
                continue
            ttable = target_tables.get(self._target_key(table))
            if ttable is None:
                self.emit(
                    Kind.DIFFERENCE, Severity.HIGH, table.qualified, "table missing in target"
                )
                res = TableResult(table.qualified, "different", reason="missing in target")
                self.result.tables.append(res)
                self._count(res)
                continue
            work.append((table, ttable))
        self.on_table(self.result)  # what is known before any table is compared
        for res, found in self._each(work):
            self._write_table(res, found)
        self.result.tables.sort(key=lambda r: order.get(r.table, len(order)))
        return self.result

    def _count(self, res: TableResult) -> None:
        """Circuit breaker across tables: most tables differing means a systemic cause."""
        self._tally[1] += 1
        if res.status == "different":
            self._tally[0] += 1
        mismatched, done = self._tally
        if (
            self._drill
            and done >= self.o.breaker_min_tables
            and mismatched / done > self.o.breaker_table_ratio
        ):
            self._flags["drill"] = False
            self.result.systemic = True
            self.emit(
                Kind.DIFFERENCE,
                Severity.CRITICAL,
                "database",
                f"{mismatched} of {done} tables differ; row level drill-down stopped. "
                "This pattern usually means a systemic cause (character set, collation, "
                "time zone or type mapping) rather than lost data. See the per table "
                "findings for the columns involved.",
                detail={"tables_checked": done, "tables_different": mismatched},
            )

    def _ranges(self, table, ttable, plan, tplan, sschema, tschema, base_entry, scan, *,
                reference_live: bool) -> dict[str, dict[str, Any]]:  # fmt: skip
        """Lowest and highest key and dates of the rows compared, per side; the reference
        side's from the baseline when the baseline was the reference."""
        if not self.o.ranges:
            return {}
        roles = ranges.columns_for(plan, self.o.show_values)
        if not roles:
            return {}
        names = list(roles)
        if reference_live:
            with self.source.pacer.statement(scan[0]):
                ref = ranges.read(self.source, table, sschema, names, plan.filter)
        else:
            ref = base_entry.ranges if base_entry is not None else {}
        with self.target.pacer.statement(scan[1]):
            tgt = ranges.read(self.target, ttable, tschema, names, tplan.filter)
        side = "target baseline" if self.against_target else "source"
        return {
            c: {"role": role, side: ref.get(c), "target": tgt.get(c)} for c, role in roles.items()
        }

    def _one(self, table: TableRef, ttable: TableRef) -> tuple[TableResult, list[Finding]]:
        self._local.pending = found = []
        try:
            return self._table(table, ttable), found
        finally:
            self._local.pending = None

    def _each(
        self, work: list[tuple[TableRef, TableRef]]
    ) -> Iterator[tuple[TableResult, list[Finding]]]:
        """Reconcile the tables, in order on one worker, or on several at once when the
        project asks for it and both engines can open more connections."""
        n = min(self.o.workers, len(work))
        if n > 1:
            lacking = [a.engine for a in (self.source, self.target) if a and not a.supports_workers]
            if lacking:
                self.emit(
                    Kind.NOTICE,
                    Severity.INFO,
                    "database",
                    f"parallel workers are not available for {', '.join(lacking)}; "
                    "tables are reconciled one at a time",
                )
                n = 1
        if n <= 1:
            for table, ttable in work:
                self.progress(f"reconciling {table}")
                yield self._one(table, ttable)
            return
        free: queue.SimpleQueue[Reconciler] = queue.SimpleQueue()
        free.put(self)
        clones: list[Reconciler] = []
        try:
            for _ in range(n - 1):
                c = copy.copy(self)  # shares the writer, the result, the lock and the flags
                c.source = self.source.fork() if self.source is not None else None
                c.target = self.target.fork()
                clones.append(c)
                free.put(c)

            def job(table: TableRef, ttable: TableRef) -> tuple[TableResult, list[Finding]]:
                w = free.get()
                try:
                    self.progress(f"reconciling {table}")
                    return w._one(table, ttable)
                finally:
                    free.put(w)

            with ThreadPoolExecutor(max_workers=n) as pool:
                futures = [pool.submit(job, t, tt) for t, tt in work]
                for f in as_completed(futures):
                    yield f.result()
        finally:
            for c in clones:
                for a in (c.source, c.target):
                    if a is not None:
                        a.close()

    def _replication_behind(self, tables: Sequence[TableRef]) -> bool:
        """Spec 9.2: before any difference is reported, replication must have applied
        through the reference position. Not compared against a target baseline: there
        the reference is the target itself."""
        if self.against_target:
            return False
        if self.baseline is not None:
            position = self.baseline.position
        else:
            position = self.source.current_position() if self.source else None
        r = check(self.o.replication, position, source=self.source, target=self.target)
        self.result.replication = {
            "status": r.status,
            "method": r.method,
            "position": r.position,
            "applied": r.applied,
            "detail": r.detail,
            "waited_seconds": r.waited_seconds,
        }
        if not r.behind:
            return False
        for table in tables:
            self.emit(
                Kind.NOT_CHECKED,
                Severity.MEDIUM,
                table.qualified,
                f"{REASON_BEHIND}: {r.detail}",
                detail={"reason": REASON_BEHIND, "position": r.position, "applied": r.applied},
            )
            self.result.tables.append(
                TableResult(table.qualified, "not_checked", reason=REASON_BEHIND)
            )
        return True

    # -------------------------------------------------------------------- table
    def _table(self, table: TableRef, ttable: TableRef) -> TableResult:
        q = table.qualified
        tschema = self.target.describe(ttable)
        base_entry = self.baseline.tables.get(q) if self.baseline else None
        if base_entry is not None:
            sschema = base_entry.schema
            source_rows = base_entry.row_count
        else:
            sschema = self.source.describe(table)
            with self.source.pacer.statement() as counted:
                source_rows = counted.rows = self.source.row_count(table)

        tp: TablePlan = plan_table(
            sschema,
            tschema,
            rows=source_rows,
            rows_per_bucket=self.o.rows_per_bucket,
            precision=self.o.precision,
            ignore=self.o.ignore,
            business_key=self.o.business_keys.get(q) or self.o.business_keys.get(table.name),
            side="target" if self.against_target else "source",
        )
        plan = tp.plan
        if base_entry is not None:
            plan = replace(plan, buckets=base_entry.plan.buckets)
        res = TableResult(
            q,
            "matched",
            source_rows=source_rows,
            buckets=plan.buckets,
            strategy=plan.strategy,
            key=", ".join(plan.key_columns) or tp.key_source,
            excluded_columns=tp.excluded_columns,
            approximate_columns=list(tp.float_columns),
        )

        for issue in tp.issues:
            sev = (
                Severity.LOW
                if issue.issue in ("added_in_target", "unsupported")
                else (Severity.MEDIUM)
            )
            kind = Kind.NOT_CHECKED if issue.issue == "unsupported" else Kind.DIFFERENCE
            self.emit(
                kind,
                sev,
                q,
                f"column {issue.issue.replace('_', ' ')}: {issue.detail}",
                column=issue.column,
                expected=issue.source_type,
                actual=issue.target_type,
                detail={"issue": issue.issue},
            )
        for col, reason in tp.ignored.items():
            self.emit(
                Kind.NOTICE,
                Severity.INFO,
                q,
                f"column excluded: {reason}",
                column=col,
                detail={"reason": reason},
            )
        if tp.partial:
            res.partial = True
            self.emit(
                Kind.PARTIAL,
                Severity.LOW,
                q,
                "data compared on the mapped columns only; excluded: "
                + ", ".join(tp.excluded_columns),
                detail={"excluded_columns": tp.excluded_columns},
            )
        if not plan.columns:
            res.status, res.reason = "not_checked", "no comparable columns"
            self.emit(Kind.NOT_CHECKED, Severity.MEDIUM, q, "no comparable columns")
            return res

        # Row ignore rules: each side leaves out its own rows, in its own dialect.
        tfilter = row_filter(self.o.ignore, q, "target")
        for r in (r for r in self.o.ignore if r.rows and r.matches_table(q)):
            self.emit(
                Kind.NOTICE,
                Severity.INFO,
                q,
                f"rows excluded by ignore rule: {r.reason}",
                detail={
                    "reason": r.reason,
                    "source_where": r.predicate("source"),
                    "target_where": r.predicate("target"),
                },
            )
        unsupported = [
            a.engine
            for a, f in ((self.source, plan.filter), (self.target, tfilter))
            if a is not None and f and not a.supports_row_filters
        ]
        if unsupported:
            res.status = "not_checked"
            res.reason = f"row ignore rules are not supported for {', '.join(unsupported)}"
            self.emit(Kind.NOT_CHECKED, Severity.MEDIUM, q, res.reason)
            return res
        plan = self._sample(q, plan, source_rows)
        full_rows = source_rows

        # Reference aggregates: a live source, or the baseline when its plan still applies.
        if (
            base_entry is not None
            and base_entry.plan.columns == plan.columns
            and base_entry.plan.key_columns == plan.key_columns
            and base_entry.plan.filter == plan.filter
        ):
            if hashed_infinity_as_null(self.baseline.engine, base_entry):
                # taken before canonical revision 1, with nothing to show it held no infinity
                res.status = "not_checked"
                res.reason = f"{REASON_INFINITY}; " + (
                    "take a new target baseline (liftproof rebaseline)"
                    if self.against_target
                    else "take a new baseline, or compare with the live source without --baseline"
                )
                self.emit(
                    Kind.NOT_CHECKED,
                    Severity.MEDIUM,
                    q,
                    res.reason,
                    detail={
                        "reason": REASON_INFINITY,
                        "baseline_canonical_revision": base_entry.canonical_revision,
                    },
                )
                return res
            s_aggs = base_entry.buckets
            if plan.sample is not None:
                s_aggs = {b: a for b, a in s_aggs.items() if b in plan.sample}
        elif self.source is not None:
            s_aggs = None  # hashed below, at the same time as the target
        else:
            res.status = "not_checked"
            res.reason = (
                "schema changed since the target baseline; rebaseline once the change is accepted"
                if self.against_target
                else "schema changed since the baseline; the live source is needed to re-hash"
            )
            self.emit(Kind.NOT_CHECKED, Severity.MEDIUM, q, res.reason)
            return res

        tplan = replace(_target_plan(plan, tschema), filter=tfilter)
        s_live = s_aggs is None
        if s_aggs is None:
            # Two databases, two connections: hashing both at once halves the wall time,
            # and each database's own load is unchanged (spec 17: the source is the
            # resource to protect, not the clock).
            with ThreadPoolExecutor(max_workers=2) as pool:
                s_job = pool.submit(_aggregates, self.source, plan, full_rows)
                t_aggs = _aggregates(self.target, tplan, full_rows)
                s_aggs = s_job.result()
        else:
            t_aggs = _aggregates(self.target, tplan, full_rows)
        res.target_rows = sum(a.count for a in t_aggs.values())
        # the rows each later read of the table is charged on each side (spec 9.15)
        scan = (full_rows, max(full_rows, res.target_rows))
        res.ranges = self._ranges(table, ttable, plan, tplan, sschema, tschema, base_entry,
                                  scan, reference_live=s_live)  # fmt: skip
        if plan.filter or plan.sample is not None:
            # the table's row count includes rows the rules leave out or the sample skips
            source_rows = res.source_rows = sum(a.count for a in s_aggs.values())
        compared = plan.buckets if plan.sample is None else len(plan.sample)
        if plan.sample is not None:
            res.sampled_percent = round(100 * source_rows / full_rows, 1) if full_rows else 0.0
            self.result.sample_seed = self._seed
            self.emit(
                Kind.NOT_CHECKED,
                Severity.MEDIUM,
                q,
                f"sampled: {compared} of {plan.buckets} buckets compared, "
                f"{res.sampled_percent}% of the rows; the rest of the table is not checked",
                detail={
                    "sampled_buckets": compared,
                    "buckets": plan.buckets,
                    "sampled_percent": res.sampled_percent,
                    "seed": self._seed,
                },
            )

        # 1. row counts
        if res.target_rows != source_rows:
            self.emit(
                Kind.DIFFERENCE,
                Severity.HIGH,
                q,
                f"row count differs: {self.reference} {source_rows:,}, "
                f"target {res.target_rows:,} "
                f"({res.target_rows - source_rows:+,})",
                expected=str(source_rows),
                actual=str(res.target_rows),
                detail={"difference": res.target_rows - source_rows},
            )

        # 2. table aggregate
        s_total = reduce_total(sum(a.total for a in s_aggs.values()))
        t_total = reduce_total(sum(a.total for a in t_aggs.values()))
        self._floats(table, ttable, tp, res, tschema, scan, plan.filter, tfilter)
        if s_total == t_total and res.target_rows == source_rows:
            return res
        res.status = "different"

        # 3. buckets
        bad = sorted(
            b for b in set(s_aggs) | set(t_aggs) if _norm(s_aggs.get(b)) != _norm(t_aggs.get(b))
        )
        res.mismatched_buckets = len(bad)
        self.emit(
            Kind.DIFFERENCE,
            Severity.MEDIUM,
            q,
            f"table aggregate differs; {len(bad)} of {compared} "
            f"{'sampled ' if plan.sample is not None else ''}buckets mismatched",
            expected=s_total,
            actual=t_total,
            detail={"buckets": bad[:50], "bucket_count": plan.buckets},
        )
        if not self._drill:
            return res
        if self.source is None:
            self.emit(
                Kind.NOT_CHECKED,
                Severity.MEDIUM,
                q,
                "the target baseline holds bucket aggregates only and the target's past state "
                "cannot be re-read; only bucket level differences are reported"
                if self.against_target
                else "row level drill-down needs the live source database; "
                "only bucket level differences are reported",
            )
            return res

        # 4. rows. Circuit breaker: nearly every bucket differs means a systemic cause.
        systemic = (
            compared >= self.o.breaker_min_buckets
            and len(bad) / compared > self.o.breaker_bucket_ratio
        )
        drill = bad[:1] if systemic else bad
        if plan.key_columns:
            self._keyed(q, plan, tplan, set(drill), res, systemic, scan)
        else:
            self._keyless(q, plan, tplan, set(drill), res, scan)
        return res

    def _sample(self, q: str, plan: HashPlan, rows: int) -> HashPlan:
        """The random buckets a large table is compared on, the same for a given seed."""
        above = self.o.sample_above_rows
        if above is None or rows <= above or plan.buckets < 2:
            return plan
        k = max(1, math.ceil(plan.buckets * self.o.sample_percent / 100))
        if k >= plan.buckets:
            return plan
        lacking = [
            a.engine
            for a in (self.source, self.target)
            if a is not None and not a.supports_sampling
        ]
        if lacking:
            self.emit(
                Kind.NOTICE,
                Severity.INFO,
                q,
                f"sampling is not available for {', '.join(lacking)}; compared in full",
            )
            return plan
        rng = random.Random(f"{self._seed}:{q}")  # noqa: S311 - a sample, not a secret
        return replace(plan, sample=tuple(sorted(rng.sample(range(plan.buckets), k))))

    # ------------------------------------------------------------------ details
    def _keyed(self, q, plan, tplan, buckets, res, systemic, scan) -> None:
        """Bucket by bucket, both sides in step: one bucket's keys are held at a time, and
        of each kind of difference only the rows that can be shown are kept."""
        limit = self.o.diff_row_limit
        keep = 5 if systemic else limit
        missing: list[tuple] = []
        extra: list[tuple] = []
        changed: list[tuple] = []
        counts = [0, 0, 0]
        pairs = zip(
            self.source.paced_bucket_rows(plan, buckets, scan[0]),
            self.target.paced_bucket_rows(tplan, buckets, scan[1]),
            strict=True,
        )
        for (sb, s), (tb, t) in pairs:
            if sb != tb:
                raise RuntimeError(f"adapters yielded buckets {sb} and {tb} out of step")
            found = (
                [k for k in s if k not in t],
                [k for k in t if k not in s],
                [k for k in s if k in t and s[k] != t[k]],
            )
            for i, (kept, new) in enumerate(zip((missing, extra, changed), found, strict=True)):
                counts[i] += len(new)
                kept[:] = heapq.nsmallest(keep, kept + new, key=_natural)
        res.missing_rows, res.extra_rows, res.changed_rows = counts
        n_missing, n_extra, n_changed = counts
        keyname = ", ".join(plan.key_columns)

        def fmt(k: tuple) -> str:
            return f"{keyname} = {', '.join('NULL' if v is None else v for v in k)}"

        if systemic:
            self._systemic(q, plan, tplan, changed[:5], n_changed, res, scan)
            return
        shown = 0
        for k in missing:
            if shown >= limit:
                break
            self.emit(
                Kind.DIFFERENCE,
                Severity.MEDIUM,
                q,
                "row missing in target",
                locator=fmt(k),
                detail={"key": list(k)},
            )
            shown += 1
        for k in extra:
            if shown >= limit:
                break
            self.emit(
                Kind.DIFFERENCE,
                Severity.MEDIUM,
                q,
                "row exists in target only",
                locator=fmt(k),
                detail={"key": list(k)},
            )
            shown += 1
        remaining = max(0, limit - shown)
        if changed and remaining:
            self._changed(q, plan, tplan, changed[:remaining], fmt, scan)
            shown += min(len(changed), remaining)
        total = n_missing + n_extra + n_changed
        self.emit(
            Kind.DIFFERENCE,
            Severity.HIGH,
            q,
            f"{total:,} differing rows: {n_missing:,} missing in target, "
            f"{n_extra:,} only in target, {n_changed:,} changed "
            f"(showing {min(total, limit):,})",
            detail={
                "missing": n_missing,
                "extra": n_extra,
                "changed": n_changed,
                "shown": min(total, limit),
                "limit": limit,
            },
        )

    def _column_diffs(
        self, plan, tplan, keys, scan
    ) -> list[tuple[tuple, str, str | None, str | None]]:
        # keys are matched on their rendering, which no index serves: a read of the table
        with self.source.pacer.statement(scan[0]):
            s_vals = self.source.fetch_rows(plan, keys)
        with self.target.pacer.statement(scan[1]):
            t_vals = self.target.fetch_rows(tplan, keys)
        hasher = RowHasher(plan.columns, plan.key_positions, plan.precision)
        out = []
        for k in keys:
            if k not in s_vals or k not in t_vals:
                continue
            sr = hasher.rendered(s_vals[k])
            tr = hasher.rendered(t_vals[k])
            for (name, _), a, b in zip(plan.columns, sr, tr, strict=True):
                if column_digest(a) != column_digest(b):
                    out.append((k, name, a, b))
        return out

    def _show(self, value: str | None) -> str:
        if value is None:
            return "NULL"
        if self.o.show_values:
            return value
        return _short(column_digest(value))

    def _changed(self, q, plan, tplan, keys, fmt, scan) -> None:
        for k, col, a, b in self._column_diffs(plan, tplan, keys, scan):
            self.emit(
                Kind.DIFFERENCE,
                Severity.MEDIUM,
                q,
                f"value differs in column {col}",
                column=col,
                locator=fmt(k),
                expected=self._show(a),
                actual=self._show(b),
                detail={"key": list(k), "values_shown": self.o.show_values},
            )

    def _systemic(self, q, plan, tplan, sample_keys, changed_total, res, scan) -> None:
        diffs = self._column_diffs(plan, tplan, sample_keys, scan)
        cols = Counter(col for _, col, _, _ in diffs)
        types = dict(plan.columns)
        likely = {
            "text": "character set, collation or case handling",
            "char": "character set, collation or padding",
            "timestamp": "time zone or timestamp precision",
            "timestamptz": "time zone or timestamp precision",
            "time": "time precision",
            "decimal": "numeric scale or rounding",
            "json": "JSON normalisation",
        }
        # PostgreSQL infinity on one side: an open ended date mapped to or from NULL or a
        # sentinel date in the move, not a time zone or type mapping
        infinite = {c for _, c, a, b in diffs if types[c] in ranges.DATES and {a, b} & INFINITY}
        causes = sorted(
            {
                "PostgreSQL infinity dates mapped to NULL or a sentinel date (ignore the "
                "column if intended)"
                if c in infinite
                else likely.get(str(types[c]), "type mapping")
                for c in cols
            }
        )
        examples = [
            {"key": list(k), "column": c, "source": self._show(a), "target": self._show(b)}
            for k, c, a, b in diffs[:3]
        ]
        self.emit(
            Kind.DIFFERENCE,
            Severity.CRITICAL,
            q,
            f"{res.mismatched_buckets} of {len(plan.sample or range(plan.buckets))} "
            f"{'sampled ' if plan.sample is not None else ''}buckets differ, which points to a "
            f"systemic cause rather than lost rows. Columns involved in the sample: "
            f"{', '.join(sorted(cols)) or 'none identified'}. Likely cause: "
            f"{'; '.join(causes) or 'unknown'}. Drill-down stopped.",
            detail={
                "columns": dict(cols),
                "examples": examples,
                "sampled_rows": len(sample_keys),
                "changed_rows_in_sampled_bucket": changed_total,
            },
        )

    def _keyless(self, q, plan, tplan, buckets, res, scan) -> None:
        """A multiset of row hashes per bucket (identical rows share a bucket), one bucket
        at a time, each a read of the table; only the first hashes of each kind are kept
        for the report."""
        missing: list[str] = []
        extra: list[str] = []
        for b in sorted(buckets):
            with self.source.pacer.statement(scan[0]):
                s = Counter(h for _, h in self.source.row_hashes(plan, {b}))
            with self.target.pacer.statement(scan[1]):
                t = Counter(h for _, h in self.target.row_hashes(tplan, {b}))
            m, e = s - t, t - s
            res.missing_rows += sum(m.values())
            res.extra_rows += sum(e.values())
            missing += list(m)[: 20 - len(missing)]
            extra += list(e)[: 20 - len(extra)]
        self.emit(
            Kind.DIFFERENCE,
            Severity.HIGH,
            q,
            f"table has no key; compared as a multiset of rows: "
            f"{res.missing_rows:,} rows missing in target, {res.extra_rows:,} only in target",
            detail={
                "missing_hashes": [_short(h) for h in missing],
                "extra_hashes": [_short(h) for h in extra],
            },
        )

    def _floats(
        self,
        table: TableRef,
        ttable: TableRef,
        tp: TablePlan,
        res: TableResult,
        tschema: TableSchema,
        scan: tuple[int, int],
        sfilter: str | None = None,
        tfilter: str | None = None,
    ) -> None:
        if not tp.float_columns or self.source is None:
            if tp.float_columns:
                self.emit(
                    Kind.NOT_CHECKED,
                    Severity.LOW,
                    table.qualified,
                    "approximate columns need a live reference: " + ", ".join(tp.float_columns)
                    if self.against_target
                    else "approximate columns need the live source: " + ", ".join(tp.float_columns),
                )
            return
        tol = self.o.float_rel_tolerance
        for col in tp.float_columns:
            with self.source.pacer.statement(scan[0]):
                a = self.source.float_stats(table, col, **({"where": sfilter} if sfilter else {}))
            tcol = tschema.column(col)  # the target's own spelling (Oracle: upper case)
            with self.target.pacer.statement(scan[1]):
                b = self.target.float_stats(
                    ttable, tcol.name if tcol else col, **({"where": tfilter} if tfilter else {})
                )
            problems = []
            for name in ("non_null", "nan_count", "inf_count"):
                if getattr(a, name) != getattr(b, name):
                    problems.append(name)
            for name in ("minimum", "maximum", "total"):
                x, y = getattr(a, name), getattr(b, name)
                if (x is None) != (y is None) or (
                    x is not None and not math.isclose(x, y, rel_tol=tol, abs_tol=tol)
                ):
                    problems.append(name)
            if problems:
                res.status = "different"
                self.emit(
                    Kind.DIFFERENCE,
                    Severity.MEDIUM,
                    table.qualified,
                    f"approximate column differs ({', '.join(problems)})",
                    column=col,
                    detail={"source": a.__dict__, "target": b.__dict__, "rel_tolerance": tol},
                )
            else:
                self.emit(
                    Kind.NOTICE,
                    Severity.INFO,
                    table.qualified,
                    "column compared approximately (count, min, max, sum, NaN, infinity)",
                    column=col,
                    detail={"rel_tolerance": tol},
                )


def _aggregates(a: Adapter, plan: HashPlan, rows: int) -> dict[int, BucketAggregate]:
    """One side's bucket aggregates: a read of the whole table whatever the row rules and
    the sample keep, so charged at least the table's rows (spec 9.15)."""
    with a.pacer.statement(rows) as s:
        aggs = a.bucket_aggregates(plan)
        s.rows = max(rows, sum(x.count for x in aggs.values()))
    return aggs


def _norm(a: BucketAggregate | None) -> tuple[int, str]:
    if a is None:
        return (0, reduce_total(0))
    return (a.count, reduce_total(a.total))


def _natural(key: tuple) -> tuple:
    """Order rendered keys numerically where they are numbers, so 88213 precedes 300001."""
    out = []
    for v in key:
        if v is None:
            out.append((0, 0, ""))
            continue
        try:
            out.append((1, float(v), v))
        except ValueError:
            out.append((2, 0, v))
    return tuple(out)
