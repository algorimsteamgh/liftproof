"""Schema comparison and hash planning (Technical Spec 9.8, 9.12, 9.13, 9.14)."""

from __future__ import annotations

import math
from dataclasses import dataclass, field, replace

from liftproof.adapters.base import HashPlan, TableSchema
from liftproof.canonical import CanonicalType
from liftproof.canonical.typemap import DEFAULT_TYPE_MAP, TypeMap


@dataclass
class IgnoreRule:
    """Excludes a table, a column, or the rows a predicate matches (spec 9.11). A row
    predicate is SQL in each side's own dialect: `where` for both sides, or
    `source_where` and `target_where` where the engines differ. A structure rule accepts
    a known structural difference instead (spec 9.13): one check of the table, or of what
    holds its column, is not compared; its data still is."""

    table: str  # schema.table or table
    reason: str
    column: str | None = None
    where: str | None = None
    source_where: str | None = None
    target_where: str | None = None
    structure: str | None = None  # nullability | keys | foreign_keys | indexes

    def matches_table(self, qualified: str) -> bool:
        t = self.table.lower()
        q = qualified.lower()
        return t == q or t == q.split(".", 1)[-1]

    @property
    def rows(self) -> bool:
        return bool(self.where or self.source_where or self.target_where)

    @property
    def whole_table(self) -> bool:
        return self.column is None and not self.rows and not self.structure

    @property
    def excludes_column(self) -> bool:
        return bool(self.column) and not self.structure

    def predicate(self, side: str) -> str | None:
        return (self.source_where if side == "source" else self.target_where) or self.where


def row_filter(ignore: list[IgnoreRule], qualified: str, side: str) -> str | None:
    """The rows of one side to leave out: any matching rule's predicate."""
    preds = [
        p for r in ignore if r.rows and r.matches_table(qualified) and (p := r.predicate(side))
    ]
    return " OR ".join(f"({p})" for p in preds) or None


# A column that is not compared, with the reason, rather than guessed at (spec 9.6): its
# values cannot be canonicalised, or the baseline it is compared with did not hash it.
NOT_CANONICALISABLE = "not_canonicalisable"
NOT_IN_BASELINE = "not_in_baseline"
NOT_CHECKED_ISSUES = ("unsupported", NOT_CANONICALISABLE, NOT_IN_BASELINE)


@dataclass
class ColumnIssue:
    column: str
    # missing_in_target | added_in_target | type_changed | unsupported | not_canonicalisable
    # | not_in_baseline
    issue: str
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


@dataclass
class TypeOverride:
    """A column the project's type map compares otherwise than the default (spec 9.13)."""

    column: str
    side: str
    native: str
    canonical: str
    default: str


def map_types(
    schema: TableSchema, engine: str, type_map: TypeMap, side: str
) -> tuple[TableSchema, list[TypeOverride]]:
    """The schema with each column typed by the project's type map, and the columns typed
    otherwise than by the default. A baseline's stored schema is typed again too, so a
    changed map changes the plan and the baseline's aggregates are not reused under it."""
    columns, overridden = [], []
    for c in schema.columns:
        ctype = type_map.canonical(engine, c.native_type)
        default = type_map.default(engine, c.native_type)
        if ctype != default:
            overridden.append(TypeOverride(c.name, side, c.native_type, str(ctype), str(default)))
        columns.append(replace(c, canonical=ctype))
    return replace(schema, columns=columns), overridden


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
    unhashed: dict[str, tuple[str, str]] | None = None,
    type_map: TypeMap = DEFAULT_TYPE_MAP,
) -> TablePlan:
    """Plan the comparison of one table over the intersection of mapped columns.

    target may be None when planning a baseline before the target exists; the plan is
    then over every source column. unhashed: columns left out though both sides have them
    alike, lower cased name -> (issue, why): a baseline that did not hash them, or values
    that cannot be canonicalised.
    """
    unhashed = unhashed or {}
    ignored = {
        r.column.lower(): r.reason
        for r in ignore
        if r.excludes_column and r.matches_table(source.table.qualified)
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
                if common := type_map.common(ctype, tcol.canonical):
                    ctype = common  # a compatible pair: char and text, integer and decimal
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
        if key in unhashed:
            issue, why = unhashed[key]
            issues.append(
                ColumnIssue(
                    col.name,
                    issue,
                    why,
                    col.native_type,
                    tcol.native_type if target is not None else None,
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
    elif any(types[k] is CanonicalType.XML for k in key):
        # keys are matched on their rendering in SQL, which XML has none of; no engine
        # allows one in a primary key, so only a declared business key gets here
        key, key_source = [], "none (an xml column cannot be a key; bucketed on the whole row)"

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
