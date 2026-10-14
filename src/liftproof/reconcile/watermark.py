"""Rows a replay created (Technical Spec 6, 9.11).

Replay drives the target application, so a journey that places an order leaves an order
in the target database that the source never had. validate reconciles before it replays,
but a reconciliation run after a replay (a scheduled replay, then a reconcile) would
report those rows as extra. So around every replay the target's watermark is read for
each table the journeys write (record --writes): the largest value of a column that only
grows (an identity key or a creation time), before and after. Rows inside that window
were created while the replay ran, and later reconciliations leave them out on the
target side, with the reason in the report.

Two limits, both in the report: rows other users created inside the same window are left
out too (a replay window is short), and changes a replay made to existing rows (a stock
count going down) are not windows and still show as differences.
"""

from __future__ import annotations

import datetime as dt
import decimal
import json
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from liftproof.adapters.base import Adapter, TableRef
from liftproof.canonical import CanonicalType
from liftproof.reconcile.plan import IgnoreRule

STORE_KEY = "replay/windows.json"
GROWING = (CanonicalType.INTEGER, CanonicalType.DECIMAL, CanonicalType.TIMESTAMP,
           CanonicalType.TIMESTAMPTZ)  # fmt: skip


@dataclass
class Window:
    """Rows of table with column in (after, upto] were created by replay run_id."""

    table: str  # the target's schema.table
    column: str
    after: str | None  # None: the table was empty
    upto: str
    kind: str  # number | timestamp
    run_id: str
    recorded_at: str

    def predicate(self, target: Adapter) -> str:
        c = target.quote_name(self.column)
        upto = target.literal(_value(self.kind, self.upto))
        if self.after is None:
            return f"{c} <= {upto}"
        return f"{c} > {target.literal(_value(self.kind, self.after))} AND {c} <= {upto}"


def _value(kind: str, text: str) -> Any:
    return dt.datetime.fromisoformat(text) if kind == "timestamp" else decimal.Decimal(text)


def _text(value: Any) -> tuple[str, str]:
    if isinstance(value, dt.datetime):
        return value.isoformat(), "timestamp"
    return str(value), "number"


def _usable(value: Any) -> bool:
    """A time or a finite number. Not PostgreSQL's infinity timestamps (read as Verbatim)
    or numeric Infinity: no window can be written with them."""
    if isinstance(value, decimal.Decimal):
        return value.is_finite()
    return isinstance(value, (int, dt.datetime))


def _utc(text: str) -> dt.datetime:
    """A stored time as an aware UTC datetime (texts differ in precision and offset, so
    they are not compared as strings); a time without an offset is UTC."""
    at = dt.datetime.fromisoformat(text)
    return at.replace(tzinfo=dt.UTC) if at.tzinfo is None else at.astimezone(dt.UTC)


def resolve(
    target: Adapter, schemas: Sequence[str], wanted: Sequence[str], columns: dict[str, str]
) -> tuple[dict[TableRef, str], list[str]]:
    """The target tables the journeys write, each with its watermark column: the one the
    project names (database.replay_watermarks), else a single column primary key that
    only grows. Returns them and the reasons for the tables left without one."""
    tables = target.list_tables(schemas)
    out: dict[TableRef, str] = {}
    problems: list[str] = []
    for name in dict.fromkeys(wanted):
        n = name.lower()
        matches = [t for t in tables if n in (t.qualified.lower(), t.name.lower())]
        if not matches:
            problems.append(f"{name}: no such table on the target")
            continue
        for t in matches:
            schema = target.describe(t)
            named = columns.get(t.qualified) or columns.get(t.name) or columns.get(name)
            if named:
                col = schema.column(named)
                if col is None:
                    problems.append(f"{t}: no column {named}")
                    continue
            elif len(schema.primary_key) == 1:
                col = schema.column(schema.primary_key[0])
            else:
                col = None
            if col is None or col.canonical not in GROWING:
                problems.append(
                    f"{t}: no growing key to tell replay rows apart; "
                    "name one in database.replay_watermarks"
                )
                continue
            out[t] = col.name
    return out, problems


def read(target: Adapter, tables: dict[TableRef, str]) -> dict[TableRef, Any]:
    return {t: target.column_max(t, c) for t, c in tables.items()}


def windows(
    tables: dict[TableRef, str],
    before: dict[TableRef, Any],
    after: dict[TableRef, Any],
    run_id: str,
) -> tuple[list[Window], list[str]]:
    """The windows of the tables the replay created rows in, and the reasons for the
    tables whose watermark no window can be written with."""
    now = dt.datetime.now(dt.UTC).isoformat(timespec="seconds")
    out: list[Window] = []
    problems: list[str] = []
    for t, col in tables.items():
        hi = after.get(t)
        lo = before.get(t)
        if hi is None:
            continue  # the table is empty
        bad = [v for v in (hi, lo) if v is not None and not _usable(v)]
        if bad:
            problems.append(f"{t}: watermark {col} reads {bad[0]}; "
                            "name another column in database.replay_watermarks")  # fmt: skip
            continue
        if lo is not None and hi <= lo:
            continue  # nothing created
        upto, kind = _text(hi)
        out.append(Window(t.qualified, col, None if lo is None else _text(lo)[0], upto, kind,
                          run_id, now))  # fmt: skip
    return out, problems


def load(path: Path) -> list[Window]:
    if not path.exists():
        return []
    return [Window(**w) for w in json.loads(path.read_text(encoding="utf-8"))]


def save(path: Path, items: list[Window]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([asdict(w) for w in items], indent=2), encoding="utf-8")


def rules(items: Sequence[Window], target: Adapter, since: str | None = None) -> list[IgnoreRule]:
    """Target side row rules for the windows. since: only windows recorded after it (a
    target baseline already holds the rows of replays before it was taken)."""
    cutoff = None if since is None else _utc(since)
    by_table: dict[str, list[Window]] = {}
    for w in items:
        if cutoff is None or _utc(w.recorded_at) > cutoff:
            by_table.setdefault(w.table, []).append(w)
    out = []
    for table, ws in by_table.items():
        runs = ", ".join(dict.fromkeys(w.run_id for w in ws))
        pred = " OR ".join(f"({w.predicate(target)})" for w in ws)
        out.append(
            IgnoreRule(
                table.split(".", 1)[-1],
                f"rows created by replay ({runs}): {ws[0].column} inside the replay window",
                target_where=pred,
            )
        )
    return out
