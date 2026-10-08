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

import heapq
import math
from collections import Counter
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from typing import Any

from liftproof.adapters.base import Adapter, BucketAggregate, HashPlan, TableRef, TableSchema
from liftproof.canonical import RowHasher, column_digest, reduce_total
from liftproof.findings import Comparator, Finding, FindingWriter, Kind, Severity
from liftproof.reconcile.baseline import Baseline
from liftproof.reconcile.plan import IgnoreRule, TablePlan, plan_table
from liftproof.reconcile.replication import REASON_BEHIND, ReplicationConfig, check

DB = Comparator.DATABASE


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


@dataclass
class ReconcileResult:
    tables: list[TableResult] = field(default_factory=list)
    systemic: bool = False
    replication: dict[str, Any] | None = None  # the position check, for the report

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
    ) -> None:
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
        self.result = ReconcileResult()
        self._drill = True

    # ------------------------------------------------------------------ helpers
    def emit(self, kind: Kind, severity: int, obj: str, summary: str, **kw: Any) -> None:
        self.writer.write(Finding(DB, kind, severity, obj, summary, **kw))

    def _selected(self, tables: Sequence[TableRef]) -> list[TableRef]:
        if not self.o.tables:
            return list(tables)
        wanted = {t.lower() for t in self.o.tables}
        return [t for t in tables if t.qualified.lower() in wanted or t.name.lower() in wanted]

    def _table_ignored(self, table: TableRef) -> IgnoreRule | None:
        for r in self.o.ignore:
            if r.column is None and r.matches_table(table.qualified):
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
        if self._replication_behind(source_tables):
            return self.result

        for t in sorted(set(target_tables) - {self._target_key(s) for s in source_tables}):
            if self.o.tables:
                break
            self.emit(
                Kind.DIFFERENCE,
                Severity.LOW,
                target_tables[t].qualified,
                "table exists on the target only",
            )

        mismatched = 0
        done = 0
        for table in source_tables:
            self.progress(f"reconciling {table}")
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
                self.result.tables.append(
                    TableResult(table.qualified, "different", reason="missing in target")
                )
                mismatched += 1
                done += 1
                continue
            res = self._table(table, ttable)
            self.result.tables.append(res)
            done += 1
            if res.status == "different":
                mismatched += 1
            if (
                self._drill
                and done >= self.o.breaker_min_tables
                and mismatched / done > self.o.breaker_table_ratio
            ):
                self._drill = False
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
        return self.result

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
            source_rows = self.source.row_count(table)

        tp: TablePlan = plan_table(
            sschema,
            tschema,
            rows=source_rows,
            rows_per_bucket=self.o.rows_per_bucket,
            precision=self.o.precision,
            ignore=self.o.ignore,
            business_key=self.o.business_keys.get(q) or self.o.business_keys.get(table.name),
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

        # Reference aggregates: a live source, or the baseline when its plan still applies.
        if (
            base_entry is not None
            and base_entry.plan.columns == plan.columns
            and (base_entry.plan.key_columns == plan.key_columns)
        ):
            s_aggs = base_entry.buckets
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

        tplan = _target_plan(plan, tschema)
        if s_aggs is None:
            # Two databases, two connections: hashing both at once halves the wall time,
            # and each database's own load is unchanged (spec 17: the source is the
            # resource to protect, not the clock).
            with ThreadPoolExecutor(max_workers=2) as pool:
                s_job = pool.submit(self.source.bucket_aggregates, plan)
                t_aggs = self.target.bucket_aggregates(tplan)
                s_aggs = s_job.result()
        else:
            t_aggs = self.target.bucket_aggregates(tplan)
        res.target_rows = sum(a.count for a in t_aggs.values())

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
        self._floats(table, ttable, tp, res, tschema)
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
            f"table aggregate differs; {len(bad)} of {plan.buckets} buckets mismatched",
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
            plan.buckets >= self.o.breaker_min_buckets
            and len(bad) / plan.buckets > self.o.breaker_bucket_ratio
        )
        drill = bad[:1] if systemic else bad
        if plan.key_columns:
            self._keyed(q, plan, tplan, set(drill), res, systemic)
        else:
            self._keyless(q, plan, tplan, set(drill), res)
        return res

    # ------------------------------------------------------------------ details
    def _keyed(self, q, plan, tplan, buckets, res, systemic) -> None:
        """Bucket by bucket, both sides in step: one bucket's keys are held at a time, and
        of each kind of difference only the rows that can be shown are kept."""
        limit = self.o.diff_row_limit
        keep = 5 if systemic else limit
        missing: list[tuple] = []
        extra: list[tuple] = []
        changed: list[tuple] = []
        counts = [0, 0, 0]
        pairs = zip(
            self.source.bucket_rows(plan, buckets),
            self.target.bucket_rows(tplan, buckets),
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
            self._systemic(q, plan, tplan, changed[:5], n_changed, res)
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
            self._changed(q, plan, tplan, changed[:remaining], fmt)
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

    def _column_diffs(self, plan, tplan, keys) -> list[tuple[tuple, str, str | None, str | None]]:
        s_vals = self.source.fetch_rows(plan, keys)
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

    def _changed(self, q, plan, tplan, keys, fmt) -> None:
        for k, col, a, b in self._column_diffs(plan, tplan, keys):
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

    def _systemic(self, q, plan, tplan, sample_keys, changed_total, res) -> None:
        diffs = self._column_diffs(plan, tplan, sample_keys)
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
        causes = sorted({likely.get(str(types[c]), "type mapping") for c in cols})
        examples = [
            {"key": list(k), "column": c, "source": self._show(a), "target": self._show(b)}
            for k, c, a, b in diffs[:3]
        ]
        self.emit(
            Kind.DIFFERENCE,
            Severity.CRITICAL,
            q,
            f"{res.mismatched_buckets} of {plan.buckets} buckets differ, which points to a "
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

    def _keyless(self, q, plan, tplan, buckets, res) -> None:
        """A multiset of row hashes per bucket (identical rows share a bucket), one bucket
        at a time; only the first hashes of each kind are kept for the report."""
        missing: list[str] = []
        extra: list[str] = []
        for b in sorted(buckets):
            s = Counter(h for _, h in self.source.row_hashes(plan, {b}))
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
            a = self.source.float_stats(table, col)
            tcol = tschema.column(col)  # the target's own spelling (Oracle: upper case)
            b = self.target.float_stats(ttable, tcol.name if tcol else col)
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
