"""The data ranges in the report's range block (spec 12): per table and side, the lowest
and highest key and the earliest and latest value of each date and time column, over the
rows compared.

These are aggregates, and only of integer and exact keys and of dates and times; the
ends of a text key are row values, shown only when the project shows values. Each side
costs one MIN/MAX statement per table, under the same row ignore rules as the comparison.
A baseline records its side's ranges when it is taken.
"""

from __future__ import annotations

import datetime as dt
import decimal
from typing import Any

from liftproof.adapters.base import Adapter, HashPlan, TableRef, TableSchema
from liftproof.canonical.types import CanonicalType as C

DATES = {C.DATE, C.TIMESTAMP, C.TIMESTAMPTZ}
ORDERED = {C.INTEGER, C.DECIMAL, *DATES}
ORDERED_WITH_VALUES = ORDERED | {C.TEXT, C.CHAR, C.UUID}


def columns_for(plan: HashPlan, show_values: bool = False) -> dict[str, str]:
    """Column -> role ("key" or "date"): the first key column, then each date and time
    column the comparison hashes."""
    types = {n.lower(): (n, t) for n, t in plan.columns}
    out: dict[str, str] = {}
    if plan.key_columns:
        name, ctype = types.get(plan.key_columns[0].lower(), (None, None))
        if name and ctype in (ORDERED_WITH_VALUES if show_values else ORDERED):
            out[name] = "key"
    for name, ctype in plan.columns:
        if ctype in DATES:
            out.setdefault(name, "date")
    return out


def _render(value: Any) -> Any:
    if value is None or isinstance(value, int):
        return value
    if isinstance(value, dt.datetime):
        if value.tzinfo is not None:
            value = value.astimezone(dt.UTC)
        return value.isoformat()
    if isinstance(value, dt.date):
        return value.isoformat()
    if isinstance(value, decimal.Decimal) and value == value.to_integral_value():
        return int(value)  # Oracle NUMBER keys read the same as integer keys elsewhere
    return str(value)  # exact numbers, and text keys when values are shown


def read(
    adapter: Adapter,
    table: TableRef,
    schema: TableSchema,
    columns: list[str],
    predicate: str | None,
) -> dict[str, list[Any]]:
    """Column (as the plan names it) -> [lowest, highest] on this side."""
    named = {c: schema.column(c) for c in columns}
    present = [(c, col.name) for c, col in named.items() if col is not None]
    if not present:
        return {}
    found = adapter.value_ranges(table, [n for _, n in present], predicate)
    return {c: [_render(v) for v in found[n]] for c, n in present}
