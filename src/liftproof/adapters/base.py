"""The database adapter interface (Technical Spec 20).

A new engine means one adapter implementing this interface, plus a full set of cross
engine fixtures. Nothing outside the adapter changes.
"""

from __future__ import annotations

import abc
import datetime as dt
import decimal
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from typing import Any

from liftproof.canonical import CanonicalType


@dataclass(frozen=True)
class TableRef:
    schema: str
    name: str

    @property
    def qualified(self) -> str:
        return f"{self.schema}.{self.name}"

    def __str__(self) -> str:
        return self.qualified


@dataclass
class Column:
    name: str
    native_type: str
    canonical: CanonicalType
    fixed_width: bool = False


@dataclass
class TableSchema:
    table: TableRef
    columns: list[Column]
    primary_key: list[str] = field(default_factory=list)

    def column(self, name: str) -> Column | None:
        for c in self.columns:
            if c.name.lower() == name.lower():
                return c
        return None


@dataclass
class HashPlan:
    """How one table is hashed. Identical on both sides, and recorded in the manifest.

    columns are the hashed columns, in canonical order (lower cased name, byte order).
    key_columns are the bucketing and row matching key, in canonical order; empty means
    the table is bucketed on the whole row and matched as a multiset of row hashes.
    """

    table: TableRef
    columns: list[tuple[str, CanonicalType]]
    key_columns: list[str]
    buckets: int
    precision: int = 6
    strategy: str = "hash"
    # SQL predicate, in this side's dialect, of rows left out (row ignore rules). Each side
    # has its own; only adapters with supports_row_filters apply it.
    filter: str | None = None
    # Sampled reconciliation (spec 9.18): only these buckets are hashed. None: all of them.
    sample: tuple[int, ...] | None = None

    @property
    def key_positions(self) -> list[int]:
        names = [c for c, _ in self.columns]
        return [names.index(k) for k in self.key_columns]


@dataclass
class BucketAggregate:
    count: int
    total: int  # exact SUM of value64 over the bucket, before reduction


@dataclass
class FloatStats:
    count: int
    non_null: int
    minimum: float | None
    maximum: float | None
    total: float | None
    nan_count: int
    inf_count: int


def all_of(*conditions: str | None) -> str | None:
    """SQL conditions joined with AND, skipping the absent ones; None when none is left."""
    present = [c for c in conditions if c]
    if len(present) <= 1:
        return present[0] if present else None
    return " AND ".join(f"({c})" for c in present)


def in_list(expr: str, values: Sequence[int], chunk: int | None = None) -> str:
    """expr IN (values), split into OR'ed lists of at most chunk values (Oracle takes
    1000 expressions in one list)."""
    vals = [str(int(v)) for v in values]
    if not vals:
        return "1 = 0"
    size = chunk or len(vals)
    parts = [f"{expr} IN ({', '.join(vals[i : i + size])})" for i in range(0, len(vals), size)]
    return parts[0] if len(parts) == 1 else "(" + " OR ".join(parts) + ")"


class Adapter(abc.ABC):
    engine: str = "abstract"
    hash_probe: str = "SELECT md5('liftproof')"  # doctor: MD5 is usable on this server

    @abc.abstractmethod
    def close(self) -> None: ...

    @abc.abstractmethod
    def begin_snapshot(self) -> dict[str, Any]:
        """Start one consistent read only snapshot and return its consistency position."""

    @abc.abstractmethod
    def end_snapshot(self) -> None: ...

    @abc.abstractmethod
    def list_tables(self, schemas: Sequence[str]) -> list[TableRef]: ...

    @abc.abstractmethod
    def describe(self, table: TableRef) -> TableSchema: ...

    @abc.abstractmethod
    def row_count(self, table: TableRef) -> int: ...

    @abc.abstractmethod
    def bucket_aggregates(self, plan: HashPlan) -> dict[int, BucketAggregate]: ...

    @abc.abstractmethod
    def row_hashes(
        self, plan: HashPlan, buckets: set[int]
    ) -> Iterator[tuple[tuple[Any, ...], str]]:
        """Yield (key values, row hash) for every row in the given buckets.

        For a keyless plan the key values are the empty tuple.
        """

    def bucket_rows(
        self, plan: HashPlan, buckets: set[int]
    ) -> Iterator[tuple[int, dict[tuple[Any, ...], str]]]:
        """Yield (bucket, {key values: row hash}) for each wanted bucket in ascending order,
        including empty ones, one bucket in memory at a time (spec 17: nothing loads a
        table). For a keyless plan use row_hashes: keys are not unique there.

        This default issues one query per bucket; an adapter can do it in one pass."""
        for b in sorted(buckets):
            yield b, dict(self.row_hashes(plan, {b}))

    @abc.abstractmethod
    def fetch_rows(
        self, plan: HashPlan, keys: Sequence[tuple[Any, ...]]
    ) -> dict[tuple[Any, ...], list[Any]]:
        """Fetch raw values for the hashed columns of the given keys. Bounded by the caller."""

    @abc.abstractmethod
    def float_stats(self, table: TableRef, column: str) -> FloatStats: ...

    def session_settings(self) -> dict[str, str]:
        """Pinned session parameters, recorded in the manifest."""
        return {}

    # replication position (spec 9.2) -----------------------------------------------
    # Engines that cannot answer leave these as they are; the check then reports that
    # it is not available rather than guessing. Every engine can be an AWS DMS or an Oracle
    # GoldenGate target.
    replication_methods: tuple[str, ...] = ("dms", "goldengate")
    # Where AWS DMS puts its control tables on this engine when the task does not set
    # ControlSchema. None: the login's own schema.
    dms_schema: str | None = None

    # Row ignore rules (spec 9.11). An adapter without them gets not_checked tables rather
    # than silently comparing rows it was told to leave out.
    supports_row_filters: bool = False
    # Sampled reconciliation: bucket_aggregates honours HashPlan.sample. Without it a
    # table is compared in full, and the report says why.
    supports_sampling: bool = False
    # Parallel workers (spec 9.1, 9.15): fork opens another connection like this one.
    supports_workers: bool = False

    def fork(self, snapshot: dict[str, Any] | None = None) -> Adapter:
        """Another connection to the same database, for a worker. Given the position
        begin_snapshot returned, it reads the same snapshot, so a baseline taken by several
        workers is still the hash of one state of the database."""
        raise NotImplementedError(self.engine)

    def current_position(self) -> dict[str, Any] | None:
        """This database's consistency position now, in the shape begin_snapshot returns."""
        return None

    def replication_applied(self, method: str, name: str) -> str | None:
        """How far replication has got, in this engine's position format. Called on the
        target for a subscription and on the source for a slot. None: nothing found."""
        raise NotImplementedError(method)

    @staticmethod
    def position_key(kind: str, position: str) -> Any:
        """A sortable form of a position of the given type."""
        raise NotImplementedError(kind)

    def replication_reached(
        self, method: str, name: str, kind: str, position: str
    ) -> tuple[str, bool] | None:
        """(how far replication has got, whether that is at or past position). None:
        nothing found under that name. Engines whose positions are not ordered (a GTID
        set) answer the second part themselves."""
        applied = self.replication_applied(method, name)
        if applied is None:
            return None
        return applied, self.position_key(kind, applied) >= self.position_key(kind, position)

    def _rows(self, q: str, args: Sequence[Any]) -> list[tuple[Any, ...]]:
        """Run a query with positional parameters written as {0}, {1}...; for the few
        statements shared by every engine."""
        raise NotImplementedError(self.engine)

    def dms_status(self, schema: str | None, task: str) -> dict[str, Any] | None:
        """The AWS DMS task's row in its awsdms_status control table on this (target)
        database, with lower case keys. None: no such row."""
        table = f"{schema}.awsdms_status" if schema else "awsdms_status"
        rows = self._rows(
            "SELECT task_status, status_time, pending_changes, source_current_timestamp, "
            f"source_timestamp_applied FROM {table} WHERE task_name = {{0}}",  # noqa: S608
            [task],
        )
        if not rows:
            return None
        keys = ("task_status", "status_time", "pending_changes", "source_current_timestamp",
                "source_timestamp_applied")  # fmt: skip
        return dict(zip(keys, rows[0], strict=True))

    def goldengate_status(
        self, checkpoint_table: str | None, heartbeat_table: str | None, group: str
    ) -> dict[str, Any] | None:
        """How far an Oracle GoldenGate Replicat writing to this (target) database has got:
        csn, the lowest source CSN up to which its checkpoint table says every transaction
        is applied (the threads of a coordinated or parallel Replicat checkpoint as the
        group name plus three digits, and the slowest one counts); heartbeat, the newest
        source time of a heartbeat it has applied. None: the group is in neither table."""
        name = group.strip().upper()

        def ours(g: Any) -> bool:
            g = str(g or "").strip().upper()
            return g == name or (g[: len(name)] == name and len(g) == len(name) + 3
                                 and g[len(name):].isdigit())  # fmt: skip

        found, csn, beat = False, None, None
        if checkpoint_table:
            q = f"SELECT group_name, log_cmplt_csn FROM {checkpoint_table}"  # noqa: S608
            csns = [r[1] for r in self._rows(q, []) if ours(r[0])]
            found = bool(csns)
            if csns and all(c is not None and str(c).strip().isdigit() for c in csns):
                csn = min(int(str(c).strip()) for c in csns)
        if heartbeat_table:
            q = f"SELECT incoming_replicat, incoming_heartbeat_ts FROM {heartbeat_table}"  # noqa: S608
            beats = [r[1] for r in self._rows(q, []) if ours(r[0])]
            found = found or bool(beats)
            beat = max((b for b in beats if b is not None), default=None)
        if not found:
            return None
        return {"csn": csn, "heartbeat": beat}

    # names and values in this engine's SQL (watermark predicates) ----------------
    def quote_name(self, name: str) -> str:
        return '"' + name.replace('"', '""') + '"'

    def qualified_name(self, table: TableRef) -> str:
        return f"{self.quote_name(table.schema)}.{self.quote_name(table.name)}"

    def literal(self, value: Any) -> str:
        """An integer, exact number or timestamp as a SQL literal."""
        if isinstance(value, dt.datetime):
            if value.tzinfo is not None:  # sessions are pinned to UTC
                value = value.astimezone(dt.UTC).replace(tzinfo=None)
            return f"TIMESTAMP '{value.isoformat(sep=' ', timespec='microseconds')}'"
        if isinstance(value, (int, decimal.Decimal)) and not isinstance(value, bool):
            return str(value)
        raise ValueError(f"no literal for {type(value).__name__}")

    def excluding(self, predicate: str) -> str:
        """The rows a row ignore rule leaves in, as a condition in this engine's SQL; a
        NULL (unknown) result keeps the row."""
        return f"({predicate}) IS NOT TRUE"

    def value_ranges(
        self, table: TableRef, columns: Sequence[str], predicate: str | None = None
    ) -> dict[str, tuple[Any, Any]]:
        """Lowest and highest value of each column, over the rows a row ignore rule
        leaves in (the report's data ranges)."""
        cols = [self.quote_name(c) for c in columns]
        if not cols:
            return {}
        aggregates = ", ".join(f"MIN({c}), MAX({c})" for c in cols)
        where = f" WHERE {self.excluding(predicate)}" if predicate else ""
        q = f"SELECT {aggregates} FROM {self.qualified_name(table)}{where}"  # noqa: S608
        [row] = self._rows(q.replace("{", "{{").replace("}", "}}"), [])  # no placeholders
        return {c: (row[2 * i], row[2 * i + 1]) for i, c in enumerate(columns)}

    def column_max(self, table: TableRef, column: str) -> Any:
        q = f"SELECT MAX({self.quote_name(column)}) FROM {self.qualified_name(table)}"  # noqa: S608
        return self._rows(q, [])[0][0]

    def shares_snapshot(self, position: dict[str, Any]) -> bool:
        """Can fork(position) open connections reading the same state as this one? Called
        before any table is read; an engine may switch this connection to a form of the
        snapshot it can share. False: a baseline is taken on one connection."""
        return False

    def __enter__(self) -> Adapter:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
