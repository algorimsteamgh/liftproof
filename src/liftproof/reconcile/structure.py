"""Structure compared before data (Technical Spec 9.13): nullability, keys, foreign keys
and indexes, beyond the columns and types plan.py compares.

Keys and indexes are matched by their columns, names lower cased, never by their own
names, which each engine and tool makes up its own way (SYS_C0012, t_pkey,
PK__t__3213E83F). A key is compared as what it guarantees: a unique key of the reference
is kept when the target enforces uniqueness of the same columns or of fewer of them, so a
primary key moved to a surrogate column, with the old key still unique, is no difference.
An index is compared as a B-tree: it is there when a B-tree index or the primary key of
the target starts with its columns, in order. Partial and expression indexes, and other
kinds (GIN, full text, bitmap), are named, not compared; a partial unique index is a key
lost when the target enforces uniqueness of neither its columns nor fewer of them.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from liftproof.adapters.base import ForeignKey, Index, TableSchema
from liftproof.findings import Kind, Severity
from liftproof.reconcile.plan import IgnoreRule

CHECKS = ("nullability", "keys", "foreign_keys", "indexes")
NOT_COMPARED = {
    "partial": "a partial index; its condition is not compared",
    "expression": "an expression index; its expressions are not compared",
    "other": "not a B-tree index; its kind is not compared across engines",
}
PRIMARY = "primary key"


@dataclass(frozen=True)
class StructureChecks:
    """What database.structure compares; everything by default."""

    nullability: bool = True
    keys: bool = True  # primary and unique keys
    foreign_keys: bool = True
    indexes: bool = True

    def as_dict(self) -> dict[str, bool]:
        return {c: getattr(self, c) for c in CHECKS}


@dataclass
class StructureIssue:
    issue: str
    kind: Kind
    severity: int
    summary: str
    column: str | None = None
    expected: str | None = None
    actual: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)


# (check, an object's columns, the side holding them: 0 reference, 1 target) -> compared
Compared = Callable[[str, Iterable[str], int], bool]
Unique = tuple[str, tuple[str, ...], Index | None]  # label, columns, the index (None: PK)


def _low(names: Iterable[str]) -> tuple[str, ...]:
    return tuple(n.lower() for n in names)


def _list(names: Iterable[str]) -> str:
    return ", ".join(names)


def compare_structure(
    reference: TableSchema,
    target: TableSchema,
    checks: StructureChecks | None = None,
    *,
    rules: Sequence[IgnoreRule] = (),
    reference_name: str = "source",
    schema_map: dict[str, str] | None = None,
) -> list[StructureIssue]:
    """The structural differences of one table: nullability in column order, then keys,
    foreign keys and indexes. `rules` are the table's ignore rules: a column rule leaves
    out whatever holds its column, a structure rule one check, for the table or for what
    holds its column. `schema_map` maps the schemas the reference's foreign keys refer to
    onto the target's. What either side does not know (a baseline from before structure
    was recorded) is not compared; the primary key always is."""
    checks = checks or StructureChecks()
    excluded = {r.column.lower() for r in rules if r.excludes_column}
    accepted = {
        c: {r.column.lower() for r in rules if r.structure == c and r.column} for c in CHECKS
    }
    on = {c for c in CHECKS if getattr(checks, c)}
    on -= {r.structure for r in rules if r.structure and not r.column}
    names = ({c.name.lower() for c in reference.columns}, {c.name.lower() for c in target.columns})

    def compared(check: str, columns: Iterable[str], side: int) -> bool:
        """The check is on and the object's columns are compared: each on the other side
        too (a column one side lacks is a difference of its own) and none left out."""
        cs = set(_low(columns))
        return check in on and cs <= names[1 - side] and not cs & (excluded | accepted[check])

    ref = reference_name
    keys, lost, gone = _keys(reference, target, compared, ref)
    out = _nullability(reference, target, compared, ref, lost) + keys
    if reference.foreign_keys is not None and target.foreign_keys is not None:
        out += _foreign_keys(reference, target, compared, ref, schema_map or {})
    if reference.indexes is not None and target.indexes is not None:
        out += _indexes(reference, target, compared, gone)
    return out


def _nullability(
    reference: TableSchema, target: TableSchema, compared: Compared, ref: str, lost: set[str]
) -> list[StructureIssue]:
    out = []
    for col in reference.columns:
        tcol = target.column(col.name)
        if (
            tcol is None
            or col.nullable is None
            or tcol.nullable is None
            or col.nullable == tcol.nullable
            or col.name.lower() in lost  # reported once, as the primary key
            or not compared("nullability", [col.name], 0)
        ):
            continue
        out.append(
            StructureIssue(
                "nullability_changed",
                Kind.DIFFERENCE,
                Severity.MEDIUM if tcol.nullable else Severity.LOW,
                f"column {col.name} is NOT NULL on the {ref} and nullable on the target"
                if tcol.nullable
                else f"column {col.name} is nullable on the {ref} and NOT NULL on the target",
                column=col.name,
                expected="NULL" if col.nullable else "NOT NULL",
                actual="NULL" if tcol.nullable else "NOT NULL",
            )
        )
    return out


def _unique(schema: TableSchema, kinds: tuple[str, ...]) -> list[Unique]:
    """What enforces uniqueness on a side: its primary key and its unique indexes of these
    kinds, each set of columns once."""
    found: list[Unique] = [(PRIMARY, tuple(schema.primary_key), None)]
    found += [
        (f"unique key {i.name}", i.columns, i)
        for i in schema.indexes or []
        if i.unique and i.kind in kinds and i.columns
    ]
    out, seen = [], set()
    for label, columns, index in found:
        if columns and frozenset(_low(columns)) not in seen:
            seen.add(frozenset(_low(columns)))
            out.append((label, columns, index))
    return out


def _within(columns: Iterable[str], group: list[Unique]) -> Unique | None:
    """The first of the group enforcing uniqueness of these columns or of fewer of them."""
    cs = set(_low(columns))
    return next((u for u in group if set(_low(u[1])) <= cs), None)


def _keys(
    reference: TableSchema, target: TableSchema, compared: Compared, ref: str
) -> tuple[list[StructureIssue], set[str], set[Index]]:
    """The unique keys of the reference the target no longer enforces, and the target's
    the reference did not; also the columns of a primary key lost and the partial unique
    indexes of the reference lost."""
    out: list[StructureIssue] = []
    lost: set[str] = set()
    gone: set[Index] = set()
    # with the target's unique keys unknown, only a primary key is held against it
    ours = _unique(reference, ("btree",) if target.indexes is not None else ())
    theirs = _unique(target, ("btree",))
    partial = [u for u in _unique(target, ("partial",)) if u[2] is not None]
    tpk = f"primary key ({_list(target.primary_key)})" if target.primary_key else "none"
    for label, columns, _ in ours:
        if not compared("keys", columns, 0):
            continue
        key = f"{label} ({_list(columns)})"
        detail = {"constraint": label, "columns": list(columns)}
        if _within(columns, theirs) is not None:
            if label == PRIMARY and set(_low(target.primary_key)) != set(_low(columns)):
                moved = (
                    f"the primary key is ({_list(target.primary_key)}) on the target"
                    if target.primary_key
                    else "the target has no primary key"
                )
                out.append(
                    StructureIssue(
                        "primary_key_moved",
                        Kind.NOTICE,
                        Severity.INFO,
                        f"{moved}; the {ref}'s, ({_list(columns)}), is still unique on the target",
                        expected=key,
                        actual=tpk,
                        detail=detail,
                    )
                )
            continue
        by = _within(columns, partial)
        if by is not None:
            out.append(
                StructureIssue(
                    "key_partial_in_target",
                    Kind.DIFFERENCE,
                    Severity.LOW,
                    f"{key} is enforced on the target only by the partial index {by[2].name}; "
                    "its condition is not compared",
                    expected=key,
                    actual=f"partial unique index {by[2].name}",
                    detail={**detail, "index": by[2].name},
                )
            )
            continue
        if label == PRIMARY:
            lost |= set(_low(columns))
        out.append(
            StructureIssue(
                "key_missing_in_target",
                Kind.DIFFERENCE,
                Severity.MEDIUM,
                f"{key} is not enforced on the target",
                expected=key,
                actual=tpk if label == PRIMARY else "not unique",
                detail=detail,
            )
        )
    if reference.indexes is None or target.indexes is None:
        return out, lost, gone
    # a partial unique key is unique only where its condition holds: any unique key of the
    # target on its columns or fewer may keep it, condition not compared; none loses it
    for label, columns, index in _unique(reference, ("partial",)):
        if (
            index is None
            or not compared("keys", columns, 0)
            or _within(columns, ours) is not None  # reported as the key that implies it
            or _within(columns, theirs + partial) is not None
        ):
            continue
        gone.add(index)
        key = f"partial {label} ({_list(columns)})"
        detail = {"constraint": f"partial {label}", "columns": list(columns), "index": index.name}
        out.append(
            StructureIssue(
                "key_missing_in_target",
                Kind.DIFFERENCE,
                Severity.MEDIUM,
                f"{key} is not enforced on the target",
                expected=key,
                actual="not unique",
                detail=detail,
            )
        )
    implied = ours + _unique(reference, ("partial",))
    for label, columns, _ in theirs:
        if compared("keys", columns, 1) and _within(columns, implied) is None:
            out.append(
                StructureIssue(
                    "key_added_in_target",
                    Kind.DIFFERENCE,
                    Severity.LOW,
                    f"{label} ({_list(columns)}) of the target is not enforced on the {ref}",
                    expected="not unique",
                    actual=f"{label} ({_list(columns)})",
                    detail={"constraint": label, "columns": list(columns)},
                )
            )
    return out, lost, gone


def _foreign_keys(
    reference: TableSchema,
    target: TableSchema,
    compared: Compared,
    ref: str,
    schema_map: dict[str, str],
) -> list[StructureIssue]:
    """Foreign keys matched on their column pairs and the table they refer to, that
    table's schema mapped as the reconciliation maps it."""

    def ident(fk: ForeignKey, mapped: bool) -> tuple[str, frozenset[tuple[str, str]]]:
        schema = fk.references.schema
        if mapped:
            schema = schema_map.get(schema, schema)
        pairs = zip(_low(fk.columns), _low(fk.referenced_columns), strict=True)
        return f"{schema}.{fk.references.name}".lower(), frozenset(pairs)

    def issue(fk: ForeignKey, missing: bool) -> StructureIssue:
        to = f"{fk.references} ({_list(fk.referenced_columns)})"
        shown = f"foreign key {fk.name} ({_list(fk.columns)}) to {to}"
        return StructureIssue(
            "foreign_key_missing_in_target" if missing else "foreign_key_added_in_target",
            Kind.DIFFERENCE,
            Severity.MEDIUM if missing else Severity.LOW,
            f"{shown} is not on the target" if missing else f"{shown} is on the target only",
            expected=f"({_list(fk.columns)}) to {to}" if missing else "none",
            actual="none" if missing else f"({_list(fk.columns)}) to {to}",
            detail={
                "foreign_key": fk.name,
                "columns": list(fk.columns),
                "references": fk.references.qualified,
                "referenced_columns": list(fk.referenced_columns),
            },
        )

    theirs = {ident(fk, False) for fk in target.foreign_keys or []}
    ours = {ident(fk, True) for fk in reference.foreign_keys or []}
    out = [
        issue(fk, True)
        for fk in reference.foreign_keys or []
        if ident(fk, True) not in theirs and compared("foreign_keys", fk.columns, 0)
    ]
    out += [
        issue(fk, False)
        for fk in target.foreign_keys or []
        if ident(fk, False) not in ours and compared("foreign_keys", fk.columns, 1)
    ]
    return out


def _orders(schema: TableSchema) -> list[tuple[str, ...]]:
    """The column orders a side's B-trees offer: its primary key and B-tree indexes."""
    out = [_low(schema.primary_key)] if schema.primary_key else []
    return out + [_low(i.columns) for i in schema.indexes or [] if i.kind == "btree"]


def _indexes(
    reference: TableSchema, target: TableSchema, compared: Compared, gone: set[Index]
) -> list[StructureIssue]:
    """The reference's B-tree indexes the target has no B-tree for, those the target has
    and the reference does not, and the reference's indexes that are not compared, but
    for the partial unique ones in `gone`, reported as keys lost. A unique index is compared
    as a key, so only as an order here."""
    out: list[StructureIssue] = []
    for i in reference.indexes or []:
        check = "keys" if i.unique else "indexes"
        if i.kind != "btree" and i not in gone and compared(check, i.columns, 0):
            out.append(
                StructureIssue(
                    "index_not_compared",
                    Kind.NOTICE,
                    Severity.INFO,
                    f"index {i.name} is not compared: {NOT_COMPARED[i.kind]}",
                    detail={"reason": NOT_COMPARED[i.kind], "structure": check, "index": i.name},
                )
            )
    theirs = _orders(target)
    seen: set[tuple[str, ...]] = set()
    for i in reference.indexes or []:
        cols = _low(i.columns)
        if i.unique or i.kind != "btree" or cols in seen:
            continue
        if not compared("indexes", i.columns, 0):
            continue
        seen.add(cols)
        if any(o[: len(cols)] == cols for o in theirs):
            continue
        detail = {"index": i.name, "columns": list(i.columns)}
        # a target index of another kind on the same leading column may stand in for it
        other = next(
            (
                t
                for t in target.indexes or []
                if t.kind != "btree" and _low(t.columns)[:1] == cols[:1]
            ),
            None,
        )
        if other is not None:
            why = f"target index {other.name} may serve it: {NOT_COMPARED[other.kind]}"
            out.append(
                StructureIssue(
                    "index_not_compared",
                    Kind.NOTICE,
                    Severity.INFO,
                    f"index {i.name} ({_list(i.columns)}) has no B-tree on the target; {why}",
                    detail={**detail, "reason": why, "structure": "indexes"},
                )
            )
            continue
        out.append(
            StructureIssue(
                "index_missing_in_target",
                Kind.DIFFERENCE,
                Severity.LOW,
                f"index {i.name} ({_list(i.columns)}) is not on the target",
                expected=f"({_list(i.columns)})",
                actual="none",
                detail=detail,
            )
        )
    ours = _orders(reference)
    seen = set()
    for t in target.indexes or []:
        cols = _low(t.columns)
        if t.unique or t.kind != "btree" or cols in seen:
            continue
        if not compared("indexes", t.columns, 1):
            continue
        seen.add(cols)
        if not any(o[: len(cols)] == cols for o in ours):
            out.append(
                StructureIssue(
                    "index_added_in_target",
                    Kind.NOTICE,
                    Severity.INFO,
                    f"index {t.name} ({_list(t.columns)}) is on the target only",
                    detail={"index": t.name, "columns": list(t.columns)},
                )
            )
    return out
