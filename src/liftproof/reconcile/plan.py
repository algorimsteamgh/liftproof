"""Schema comparison and hash planning (Technical Spec 9.8, 9.12, 9.13, 9.14)."""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from liftproof.adapters.base import HashPlan, TableSchema
from liftproof.canonical import CanonicalType


@dataclass
class IgnoreRule:
    """Excludes a table, a column, or the rows a predicate matches (spec 9.11). A row
    predicate is SQL in each side's own dialect: `where` for both sides, or
    `source_where` and `target_where` where the engines differ."""

    table: str  # schema.table or table
    reason: str
    column: str | None = None
    where: str | None = None
    source_where: str | None = None
    target_where: str | None = None

    def matches_table(self, qualified: str) -> bool:
        t = self.table.lower()
        q = qualified.lower()
        return t == q or t == q.split(".", 1)[-1]

    @property
    def rows(self) -> bool:
        return bool(self.where or self.source_where or self.target_where)

    @property
    def whole_table(self) -> bool:
        return self.column is None and not self.rows

    def predicate(self, side: str) -> str | None:
        return (self.source_where if side == "source" else self.target_where) or self.where


def row_filter(ignore: list[IgnoreRule], qualified: str, side: str) -> str | None:
    """The rows of one side to leave out: any matching rule's predicate."""
    preds = [
        p for r in ignore if r.rows and r.matches_table(qualified) and (p := r.predicate(side))
    ]
    return " OR ".join(f"({p})" for p in preds) or None


@dataclass
class ColumnIssue:
    column: str
    issue: str  # missing_in_target | added_in_target | type_changed | unsupported | ignored
    detail: str
    source_type: str | None = None
    target_type: str | None = None


@dataclass
class TablePlan:
    plan: HashPlan
    float_columns: list[str] = field(default_factory=list)
    issues: list[ColumnIssue] = field(default_factory=list)
    ignored: dict[str, str] = field(default_factory=dict)  # column -> reason
    key_source: str = "primary key"

    @property
    def excluded_columns(self) -> list[str]:
        return sorted(
            {i.column for i in self.issues if i.issue != "added_in_target"} | set(self.ignored)
        )

    @property
    def partial(self) -> bool:
        return bool(self.excluded_columns)


def canonical_order(names: list[str]) -> list[str]:
    return sorted(names, key=lambda n: n.lower().encode("utf-8"))


def bucket_count(rows: int, rows_per_bucket: int) -> int:
    return max(1, math.ceil(rows / max(1, rows_per_bucket)))


def plan_table(
    source: TableSchema,
    target: TableSchema | None,
    *,
    rows: int,
    rows_per_bucket: int,
    precision: int,
    ignore: list[IgnoreRule],
    business_key: list[str] | None = None,
    side: str = "source",
) -> TablePlan:
    """Plan the comparison of one table over the intersection of mapped columns.

    target may be None when planning a baseline before the target exists; the plan is
    then over every source column.
    """
    ignored = {
        r.column.lower(): r.reason
        for r in ignore
        if r.column and r.matches_table(source.table.qualified)
    }
    rows_filter = row_filter(ignore, source.table.qualified, side)  # the reference's rows
    issues: list[ColumnIssue] = []
    hashed: list[tuple[str, CanonicalType]] = []
    floats: list[str] = []
    for col in source.columns:
        key = col.name.lower()
        if key in ignored:
            continue
        ctype = col.canonical
        if target is not None:
            tcol = target.column(col.name)
            if tcol is None:
                issues.append(
                    ColumnIssue(
                        col.name,
                        "missing_in_target",
                        "column exists on the source only",
                        col.native_type,
                    )
                )
                continue
            if tcol.canonical != ctype:
                if {ctype, tcol.canonical} <= {CanonicalType.CHAR, CanonicalType.TEXT}:
                    ctype = CanonicalType.TEXT  # strip rule only fires when both are fixed width
                else:
                    issues.append(
                        ColumnIssue(
                            col.name,
                            "type_changed",
                            f"{col.native_type} ({ctype}) became {tcol.native_type} "
                            f"({tcol.canonical})",
                            col.native_type,
                            tcol.native_type,
                        )
                    )
                    continue
        if ctype is CanonicalType.UNSUPPORTED:
            issues.append(
                ColumnIssue(
                    col.name,
                    "unsupported",
                    f"type {col.native_type} has no canonical rendering",
                    col.native_type,
                )
            )
            continue
        if ctype is CanonicalType.FLOAT:
            floats.append(col.name)
            continue
        hashed.append((col.name, ctype))
    if target is not None:
        for tcol in target.columns:
            if source.column(tcol.name) is None and tcol.name.lower() not in ignored:
                issues.append(
                    ColumnIssue(
                        tcol.name,
                        "added_in_target",
                        "column exists on the target only",
                        target_type=tcol.native_type,
                    )
                )

    order = canonical_order([n for n, _ in hashed])
    types = dict(hashed)
    columns = [(n, types[n]) for n in order]

    key_source = "primary key"
    key = business_key or source.primary_key
    if business_key:
        key_source = "declared business key"
    key_ok = bool(key) and all(k in types for k in key)
    if target is not None and key_ok and not business_key:
        key_ok = {k.lower() for k in key} == {k.lower() for k in target.primary_key} or all(
            target.column(k) is not None for k in key
        )
    if not key_ok:
        key, key_source = [], "none (bucketed on the whole row)"

    return TablePlan(
        plan=HashPlan(
            table=source.table,
            columns=columns,
            key_columns=canonical_order(list(key)),
            buckets=bucket_count(rows, rows_per_bucket),
            precision=precision,
            filter=rows_filter,
        ),
        float_columns=floats,
        issues=issues,
        ignored={c: r for c, r in ignored.items()},
        key_source=key_source,
    )
