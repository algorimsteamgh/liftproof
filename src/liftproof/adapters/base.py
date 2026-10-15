"""The database adapter interface (Technical Spec 20).

A new engine means one adapter implementing this interface, plus a full set of cross
engine fixtures. Nothing outside the adapter changes.
"""

from __future__ import annotations

import abc
import contextlib
import datetime as dt
import decimal
import itertools
import math
import re
import time
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from typing import Any

from liftproof.canonical import CanonicalType
from liftproof.errors import ConfigError


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
    nullable: bool | None = None  # None: not known (a baseline from before it was recorded)


@dataclass(frozen=True)
class Index:
    """An index or unique constraint other than the primary key's own (spec 9.13)."""

    name: str
    # key columns in key order, as the engine spells them; included columns left out. An
    # expression index keeps the plain columns before its first expression.
    columns: tuple[str, ...]
    unique: bool
    # btree: a B-tree over plain columns; partial: one with a condition (SQL Server:
    # filtered); expression: one over expressions; other: GIN, BRIN, hash, full text,
    # spatial, bitmap, columnstore, XML. Only B-trees compare across engines.
    kind: str = "btree"


def plain_prefix(keys: Iterable[str | None]) -> tuple[str, ...]:
    """An index's key columns up to its first expression (None)."""
    return tuple(itertools.takewhile(lambda k: k is not None, keys))


@dataclass(frozen=True)
class ForeignKey:
    name: str
    columns: tuple[str, ...]
    references: TableRef
    referenced_columns: tuple[str, ...]  # paired with columns, in order


@dataclass
class TableSchema:
    table: TableRef
    columns: list[Column]
    primary_key: list[str] = field(default_factory=list)  # in key order
    # None: not known (a baseline from before they were recorded)
    indexes: list[Index] | None = None
    foreign_keys: list[ForeignKey] | None = None

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


XML_BATCH = 25  # rows fetched at once to hash here from a table with an XML column


def fetch_batch(plan: HashPlan, rows: int) -> int:
    """Rows a stream fetches at once: fewer from a table with an XML column, whose
    documents can run to megabytes each (spec 17: nothing loads a table)."""
    return XML_BATCH if any(t is CanonicalType.XML for _, t in plan.columns) else rows


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


@dataclass
class Statement:
    rows: int  # rows the statement reads; raised in the block once more is known
    start: float = 0.0  # when its latest read began
    before: int = 0  # rows charged before its latest read


class Pacer:
    """The rows per second cap and the pause of one connection (spec 9.15).

    Every statement that reads a table is charged the rows it reads, and the connection
    pays for them before its next statement: none starts before the rows read so far fit
    under the cap, nor sooner than the pause after the last one ended. Nothing waits after
    the last statement, and time spent idle earns no credit for a burst. The database runs
    each statement at its own speed; only rows streamed here to be hashed are charged as
    they arrive, which slows the read itself."""

    def __init__(
        self,
        rows_per_second: int = 0,
        pause_ms: int = 0,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.rate = rows_per_second
        self.pause = pause_ms / 1000
        self.clock = clock
        self.sleep = sleep
        self.charged = 0  # rows charged so far
        self.waited = 0.0  # seconds spent waiting
        self._paid = -math.inf  # when the rows charged so far fit under the cap
        self._ended = -math.inf  # when the last statement ended
        self._open: Statement | None = None  # the statement running now

    def _wait(self, until: float) -> None:
        delay = until - self.clock()
        if delay > 0:
            self.sleep(delay)
            self.waited += delay

    def _charge(self, since: float, rows: int) -> None:
        if rows <= 0:
            return
        self.charged += rows
        if self.rate:
            self._paid = max(self._paid, since) + rows / self.rate

    @contextlib.contextmanager
    def statement(self, rows: int = 0) -> Iterator[Statement]:
        """Around one statement: waits for the rows before it and the pause, then charges
        what it read, less what a stream inside it already paid."""
        s, outer = Statement(rows), self._open
        self._begin(s)
        self._open = s
        try:
            yield s
        finally:
            self._open = outer
            self._end(s)

    def again(self) -> None:
        """The statement running now reads the table again, as a statement of its own (an
        adapter that hashes most rows in the database, then streams the rest to hash
        here): the first read is paid for, and the pause kept, before the second starts,
        which is charged the same rows."""
        if self._open is not None:
            self._end(self._open)
            self._begin(self._open)

    def _begin(self, s: Statement) -> None:
        self._wait(max(self._paid, self._ended + self.pause))
        s.start, s.before = self.clock(), self.charged

    def _end(self, s: Statement) -> None:
        self._ended = self.clock()
        self._charge(s.start, s.rows - (self.charged - s.before))

    def each(self, rows: Iterable[Any], batch: int = 1000) -> Iterator[Any]:
        """Rows streamed here to be hashed, charged a batch at a time as they arrive."""
        if not self.rate:
            # not yield from: stopped early, that would close the cursor, which the
            # stream's own with block closes (oracledb refuses a second close)
            for row in rows:
                yield row
            return
        start, n = self.clock(), 0
        try:
            for row in rows:
                yield row
                n += 1
                if n == batch:
                    self._charge(start, n)
                    self._wait(self._paid)
                    start, n = self.clock(), 0
        finally:
            self._charge(start, n)


UNPACED = Pacer()  # an adapter that never set its own: no cap, no pause


class Adapter(abc.ABC):
    engine: str = "abstract"
    hash_probe: str = "SELECT md5('liftproof')"  # doctor: MD5 is usable on this server
    product: str = "the database"
    minimum_version: tuple[int, ...] = ()  # the oldest server the adapter supports
    minimum_shown: str = ""
    version: str = ""
    # spec 9.15: every statement that reads a table goes through this connection's pacer
    pacer: Pacer = UNPACED
    lock_timeout_ms: int | str = 0  # as the connection applies it; 0: none

    def require_version(self, found: str) -> None:
        """Refuse a server older than the oldest supported when connecting, rather than
        fail halfway through a baseline on a function it lacks."""
        self.version = found
        n = len(self.minimum_version)
        parts = tuple(int(x) for x in re.findall(r"\d+", found)[:n])
        if parts and parts + (0,) * (n - len(parts)) < self.minimum_version:
            self.close()
            raise ConfigError(
                f"{self.product} {found} is not supported; Liftproof needs "
                f"{self.minimum_shown} or later"
            )

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

    def drill_passes(self, plan: HashPlan, buckets: int) -> int:
        """How many times bucket_rows reads the whole table for this many buckets."""
        return buckets

    def paced_bucket_rows(
        self, plan: HashPlan, buckets: set[int], rows: int
    ) -> Iterator[tuple[int, dict[tuple[Any, ...], str]]]:
        """bucket_rows under this connection's cap and pause, each read of the table a
        statement charged its rows. A single pass is one statement, never paused inside:
        its cursor holds a transaction open."""
        found = self.bucket_rows(plan, buckets)
        try:
            if self.drill_passes(plan, len(buckets)) == 1:
                with self.pacer.statement(rows):
                    yield from found
                return
            for _ in range(len(buckets)):
                with self.pacer.statement(rows):
                    item = next(found)
                yield item
        finally:
            found.close()

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

    def protection(self) -> dict[str, Any]:
        """What limits this connection's load on its database (spec 9.15), as applied, for
        the report; 0 is off."""
        given = getattr(self, "_kwargs", {})
        return {
            "rows_per_second": self.pacer.rate,
            "pause_ms": round(self.pacer.pause * 1000),
            "statement_timeout_ms": int(given.get("statement_timeout_ms") or 0),  # as given
            "lock_timeout_ms": self.lock_timeout_ms,
        }

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
