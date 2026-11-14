"""SQLite adapter: a database file, as the source of a migration only.

An application that keeps its data in a SQLite file has no server to connect to. The file
is read from a copy, on this instance or in S3 (the deployment's bucket), taken once the
application stopped writing: `litestream restore`, `sqlite3 app.db ".backup copy.db"` or
`VACUUM INTO`, never a copy of the file of a running application, which can miss what is
still in its write-ahead log. The copy is opened read only and immutable, so it is one
consistent state by construction; its SHA-256 is the baseline's consistency position, and
a later comparison against the baseline checks it reads the same file.

SQLite types are declared loosely: any value can sit in any column, dates are text or
numbers, booleans are 0 and 1. Each column is typed by its declared type and, failing
that, by its type affinity (typemap.yaml), and compared as its target column's type when
that is one of the alternatives the type map lists for it (a TEXT column holding ISO 8601
times against a timestamptz column). Every value is parsed and hashed here by the
reference implementation; a value that does not parse under its column's type leaves the
column out, reported as not checked, never guessed at.

Nothing is read from the application, so the source protections (rows per second, pause)
do not apply; the report shows them off.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import decimal
import hashlib
import json
import os
import re
import sqlite3
import tempfile
import uuid
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

from liftproof.adapters.base import (
    Adapter,
    BucketAggregate,
    Column,
    FloatStats,
    ForeignKey,
    HashPlan,
    Index,
    TableRef,
    TableSchema,
)
from liftproof.canonical import CanonicalType, RenderError, RowHasher, Verbatim
from liftproof.canonical import value64 as _value64
from liftproof.canonical.typemap import DEFAULT_TYPE_MAP
from liftproof.errors import ConfigError

SCHEMA = "main"  # SQLite's only schema here; mapped onto the target's home schema
HEADER = b"SQLite format 3\x00"
# Litestream's own bookkeeping, inside the application's file: not application data.
BOOKKEEPING = {"_litestream_seq", "_litestream_lock"}
# Unix time in an integer column: seconds, or milliseconds from this magnitude on (a value
# of seconds this large is after the year 5000, one of milliseconds after 1973).
MILLISECONDS_FROM = 100_000_000_000
TRUE = {"1", "true", "t", "yes", "y"}
FALSE = {"0", "false", "f", "no", "n"}
WHOLE = re.compile(r"[+-]?\d+")
TIME = re.compile(r"(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,9}))?)?")
DRILL_GROUP = 16  # buckets held in memory per pass when rows are drilled into


# ------------------------------------------------------------------ the file
def cache_dir() -> Path:
    d = Path(os.environ.get("LIFTPROOF_CACHE") or tempfile.gettempdir()) / "liftproof-sqlite"
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    return d


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def local_copy(location: str) -> Path:
    """The file at location on this instance: itself for a path, a download for s3://.
    A download is kept, under the object's ETag, for the next connection to the same one."""
    if not location.startswith("s3://"):
        p = Path(location)
        if not p.is_file():
            raise ConfigError(f"source.path {location}: no such file on this instance")
        return p
    from liftproof import aws

    bucket, _, key = location[len("s3://") :].partition("/")
    if not bucket or not key:
        raise ConfigError(f"source.path {location}: give s3://bucket/key of the database file")
    s3 = aws.client("s3")
    try:
        head = s3.head_object(Bucket=bucket, Key=key)
    except Exception as exc:  # noqa: BLE001 - the SDK's errors, said in one line
        raise ConfigError(f"source.path {location}: cannot read it: {exc}") from None
    tag = hashlib.sha256(f"{bucket}/{key}/{head.get('ETag', '')}".encode()).hexdigest()[:24]
    dest = cache_dir() / f"{tag}.db"
    if not dest.is_file():
        part = dest.with_suffix(".part")
        s3.download_file(bucket, key, str(part))
        part.replace(dest)
    return dest


# ------------------------------------------------------------------ values
def _epoch(value: int | float) -> dt.datetime:
    seconds = value / 1000 if abs(value) >= MILLISECONDS_FROM else value
    try:
        return dt.datetime(1970, 1, 1, tzinfo=dt.UTC) + dt.timedelta(seconds=seconds)
    except OverflowError:
        raise RenderError("a number out of range for a date and time") from None


def _datetime(value: Any) -> dt.datetime:
    """A text or number as a date and time: ISO 8601 text (SQLite's own date functions,
    JavaScript's toISOString), aware where it carries a zone, or Unix time, in UTC."""
    if isinstance(value, bool):
        raise RenderError("a boolean where a date and time was expected")
    if isinstance(value, (int, float)):
        return _epoch(value)
    if isinstance(value, bytes):
        raise RenderError("binary data where a date and time was expected")
    text = str(value).strip()
    if WHOLE.fullmatch(text):
        return _epoch(int(text))
    try:
        return dt.datetime.fromisoformat(text)
    except ValueError:
        raise RenderError("text that is not an ISO 8601 date and time") from None


def _utc(at: dt.datetime) -> dt.datetime:
    return at.replace(tzinfo=dt.UTC) if at.tzinfo is None else at.astimezone(dt.UTC)


def _text(value: Any) -> str:
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RenderError(f"binary data that is not UTF-8 text (byte {exc.start})") from None
    if isinstance(value, float):
        return repr(value)
    return str(value)


def prepare(value: Any, ctype: CanonicalType) -> Any:
    """A stored SQLite value (None, int, float, str or bytes) as the reference renderer
    takes a value of the column's canonical type. Raises RenderError when it is not one."""
    if value is None:
        return None
    match ctype:
        case CanonicalType.INTEGER:
            if isinstance(value, int):
                return value
            if isinstance(value, float) and value.is_integer():
                return int(value)
            if isinstance(value, str) and WHOLE.fullmatch(value.strip()):
                return int(value.strip())
            raise RenderError("a value that is not a whole number")
        case CanonicalType.DECIMAL:
            if isinstance(value, (int, float)):
                return decimal.Decimal(repr(value) if isinstance(value, float) else value)
            try:
                return decimal.Decimal(_text(value).strip())
            except decimal.InvalidOperation:
                raise RenderError("a value that is not a number") from None
        case CanonicalType.BOOLEAN:
            if isinstance(value, (int, float)):
                return value != 0
            text = _text(value).strip().lower()
            if text in TRUE or text in FALSE:
                return text in TRUE
            raise RenderError("a value that is not true or false")
        case CanonicalType.TEXT | CanonicalType.CHAR:
            return _text(value)
        case CanonicalType.BINARY:
            if isinstance(value, bytes):
                return value
            if isinstance(value, str):
                return value.encode("utf-8")
            raise RenderError("a number where binary data was expected")
        case CanonicalType.UUID:
            try:
                if isinstance(value, bytes) and len(value) == 16:
                    return uuid.UUID(bytes=value)
                return uuid.UUID(_text(value).strip())
            except ValueError:
                raise RenderError("a value that is not a UUID") from None
        case CanonicalType.JSON:
            if isinstance(value, (int, float)):
                return value
            try:
                return json.loads(_text(value))
            except ValueError:
                raise RenderError("text that is not JSON") from None
        case CanonicalType.DATE:
            at = _datetime(value)
            if isinstance(value, (int, float)) or at.tzinfo is not None:
                at = _utc(at).replace(tzinfo=None)
            if at.time() == dt.time(0):
                return at.date()
            # a time of day: it renders as a timestamp, and so differs from every date
            return Verbatim(at.strftime("%Y-%m-%dT%H:%M:%S") + _fraction(at.microsecond))
        case CanonicalType.TIME:
            m = TIME.fullmatch(_text(value).strip())
            if not m:
                raise RenderError("text that is not a time of day")
            hh, mm, ss, frac = m.groups()
            try:
                return dt.time(int(hh), int(mm), int(ss or 0), int((frac or "0").ljust(6, "0")[:6]))
            except ValueError:
                raise RenderError("text that is not a time of day") from None
        case CanonicalType.TIMESTAMP:
            at = _datetime(value)
            # a zone given (or Unix time) is converted to UTC, then dropped
            return (
                at
                if at.tzinfo is None and not isinstance(value, (int, float))
                else (_utc(at).replace(tzinfo=None))
            )
        case CanonicalType.TIMESTAMPTZ:
            # no zone given: UTC, as SQLite's CURRENT_TIMESTAMP and datetime('now') write
            return _utc(_datetime(value))
    return value


def _fraction(microsecond: int) -> str:
    return f".{microsecond:06d}" if microsecond else ""


# ------------------------------------------------------------------ the adapter
class SQLiteAdapter(Adapter):
    engine = "sqlite"
    product = "SQLite"
    supports_row_filters = True
    supports_sampling = True
    supports_workers = True  # every connection reads the same immutable file
    replication_methods = ()  # a file: nothing replicates from it

    def __init__(self, *, path: str, sha256: str | None = None, **_ignored: Any) -> None:
        self.location = path
        self.local = local_copy(path)
        with self.local.open("rb") as f:
            if f.read(len(HEADER)) != HEADER:
                raise ConfigError(
                    f"{path} is not a SQLite database file. Restore it first (litestream "
                    "restore, or sqlite3 .backup) and give the restored file"
                )
        self.sha256 = sha256_of(self.local)
        if sha256 and sha256.lower().removeprefix("sha256:") != self.sha256:
            raise ConfigError(
                f"{path} is not the file named by source.sha256: its SHA-256 is {self.sha256}"
            )
        self._kwargs: dict[str, Any] = {}
        self.conn = self._open()
        self.version = sqlite3.sqlite_version
        self._opened = dt.datetime.now(dt.UTC).isoformat()

    def _open(self) -> sqlite3.Connection:
        uri = f"{self.local.resolve().as_uri()}?mode=ro&immutable=1"
        # the reconciler hashes the two sides on two threads; one uses this at a time
        conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
        try:
            conn.execute("SELECT count(*) FROM sqlite_schema")
        except sqlite3.DatabaseError as exc:
            conn.close()
            raise ConfigError(f"{self.location} cannot be read as SQLite: {exc}") from None
        return conn

    def describe_location(self) -> str:
        return f"sqlite:{self.location}"

    def close(self) -> None:
        with contextlib.suppress(sqlite3.Error):
            self.conn.close()

    def fork(self, snapshot: dict[str, Any] | None = None) -> SQLiteAdapter:
        other = object.__new__(SQLiteAdapter)
        other.__dict__.update(self.__dict__)
        other.conn = self._open()
        return other

    def shares_snapshot(self, position: dict[str, Any]) -> bool:
        return True

    def session_settings(self) -> dict[str, str]:
        return {"sqlite_version": self.version, "file": self.location,
                "file_sha256": self.sha256, "opened": "read only, immutable"}  # fmt: skip

    def _position(self) -> dict[str, Any]:
        return {
            "type": "file",
            "position": f"sha256:{self.sha256}",
            "exact": True,
            "file": self.location,
            "bytes": self.local.stat().st_size,
            "taken_at": self._opened,
        }

    def begin_snapshot(self) -> dict[str, Any]:
        return self._position()

    def end_snapshot(self) -> None:
        pass

    def current_position(self) -> dict[str, Any] | None:
        return self._position()

    def probe(self) -> str:
        """doctor: the whole file reads as SQLite."""
        (result,) = self.conn.execute("PRAGMA quick_check").fetchone()
        if result != "ok":
            raise ConfigError(f"{self.location} is damaged: quick_check says {result}")
        return "quick_check ok"

    def verify_read_only(self) -> bool:
        return True  # opened read only and immutable; nothing writes to the application

    def _rows(self, q: str, args: Sequence[Any]) -> list[tuple[Any, ...]]:
        return self.conn.execute(q.format(*["?"] * len(args)), list(args)).fetchall()

    def literal(self, value: Any) -> str:
        if isinstance(value, dt.datetime):
            return "'" + value.isoformat(sep=" ") + "'"
        return super().literal(value)

    # catalogue ------------------------------------------------------------------
    def list_tables(self, schemas: Sequence[str]) -> list[TableRef]:
        """Ordinary tables, without SQLite's own, Litestream's, virtual tables (full text
        search) and their shadow tables, all of which the application derives."""
        if SCHEMA not in [s.lower() for s in schemas]:
            return []
        try:
            rows = self.conn.execute(
                "SELECT name FROM pragma_table_list WHERE schema = 'main' AND type = 'table'"
            ).fetchall()
        except sqlite3.OperationalError:  # before 3.37: no table_list, no shadow flag
            rows = self.conn.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'table' "
                "AND sql NOT LIKE 'CREATE VIRTUAL%'"
            ).fetchall()
        names = sorted(n for (n,) in rows
                       if not n.lower().startswith("sqlite_") and n not in BOOKKEEPING)  # fmt: skip
        return [TableRef(SCHEMA, n) for n in names]

    def _q(self, name: str) -> str:
        return self.quote_name(name)

    def describe(self, table: TableRef) -> TableSchema:
        t = self._lit(table.name)
        info = self.conn.execute(
            f'SELECT name, type, "notnull", pk, hidden FROM pragma_table_xinfo({t})'
        ).fetchall()
        if not info:
            raise ConfigError(f"table {table} not found")
        pk = [n for n, _t, _nn, k, _h in sorted(info, key=lambda r: r[3]) if k]
        cols = []
        for name, declared, notnull, key, hidden in info:
            if hidden == 1:  # a virtual table's hidden column
                continue
            native = " ".join(str(declared or "").lower().split())
            ctype = DEFAULT_TYPE_MAP.canonical(self.engine, native)
            # a key column is NOT NULL in every target; SQLite lets NULL into all but an
            # INTEGER PRIMARY KEY, a NULL there shows up as a row difference
            cols.append(Column(name, native, ctype, nullable=not (notnull or key)))
        indexes = []
        for _seq, name, unique, origin, partial in self.conn.execute(
            f'SELECT seq, name, "unique", origin, partial FROM pragma_index_list({t})'
        ).fetchall():
            if origin == "pk":
                continue
            parts = self.conn.execute(
                f"SELECT cid, name FROM pragma_index_info({self._lit(name)}) ORDER BY seqno"
            ).fetchall()
            keys = [None if cid < 0 else n for cid, n in parts]
            kind = "partial" if partial else "expression" if None in keys else "btree"
            plain = (
                tuple(k for k in keys if k is not None)
                if kind != "expression"
                else tuple(k for k in keys[: keys.index(None)])
            )
            indexes.append(Index(name, plain, bool(unique), kind))
        fks: dict[int, list[tuple[str, str, str | None]]] = {}
        for fid, _seq, ref, frm, to in self.conn.execute(
            'SELECT id, seq, "table", "from", "to" '
            f"FROM pragma_foreign_key_list({t}) ORDER BY id, seq"
        ).fetchall():
            fks.setdefault(fid, []).append((ref, frm, to))
        foreign_keys = []
        for fid, parts in fks.items():
            ref = parts[0][0]
            to = [t for _r, _f, t in parts]
            if any(t is None for t in to):  # REFERENCES t with no columns: its primary key
                ref_pk = [r[1] for r in sorted(self.conn.execute(
                    f"SELECT pk, name FROM pragma_table_info({self._lit(ref)}) WHERE pk > 0"
                ).fetchall())]  # fmt: skip
                to = ref_pk
            foreign_keys.append(ForeignKey(f"fk_{table.name}_{fid}",
                                           tuple(f for _r, f, _t in parts),
                                           TableRef(SCHEMA, ref), tuple(to)))  # fmt: skip
        return TableSchema(table, cols, pk, indexes, foreign_keys)

    @staticmethod
    def _lit(text: str) -> str:
        return "'" + text.replace("'", "''") + "'"

    def _ident(self, table: TableRef) -> str:
        return f"{self._q(SCHEMA)}.{self._q(table.name)}"

    def row_count(self, table: TableRef) -> int:
        return int(self.conn.execute(f"SELECT count(*) FROM {self._ident(table)}").fetchone()[0])

    def _cursor_rows(self, q: str, batch: int) -> Iterator[tuple[Any, ...]]:
        cur = self.conn.execute(q)
        try:
            while rows := cur.fetchmany(batch):
                yield from rows
        finally:
            cur.close()

    # hashing --------------------------------------------------------------------
    def _stream(self, plan: HashPlan) -> Iterator[list[Any]]:
        cols = ", ".join(self._q(c) for c, _ in plan.columns)
        q = f"SELECT {cols} FROM {self._ident(plan.table)}"  # noqa: S608
        if plan.filter:
            q += f" WHERE {self.excluding(plan.filter)}"
        columns = plan.columns
        cur = self.conn.execute(q)
        try:
            while batch := cur.fetchmany(1000):
                for row in batch:
                    out = []
                    for value, (name, ctype) in zip(row, columns, strict=True):
                        try:
                            out.append(prepare(value, ctype))
                        except RenderError as exc:
                            raise RenderError(exc.reason, name) from None
                    yield out
        finally:
            cur.close()

    def bucket_aggregates(self, plan: HashPlan) -> dict[int, BucketAggregate]:
        hasher = RowHasher(plan.columns, plan.key_positions, plan.precision)
        sample = None if plan.sample is None else set(plan.sample)
        out: dict[int, BucketAggregate] = {}
        with contextlib.closing(self._stream(plan)) as rows:
            for row in rows:
                placed = hasher.placed(row, plan.buckets, sample)
                if placed is None:
                    continue
                b, rh = placed
                agg = out.setdefault(b, BucketAggregate(0, 0))
                agg.count += 1
                agg.total += _value64(rh)
        return out

    def row_hashes(
        self, plan: HashPlan, buckets: set[int]
    ) -> Iterator[tuple[tuple[Any, ...], str]]:
        if not buckets:
            return
        hasher = RowHasher(plan.columns, plan.key_positions, plan.precision)
        wanted = set(buckets)
        found = []
        with contextlib.closing(self._stream(plan)) as rows:
            for row in rows:
                placed = hasher.placed(row, plan.buckets, wanted)
                if placed is not None:
                    found.append((hasher.key_values(row), placed[1]))
        yield from found

    def drill_passes(self, plan: HashPlan, buckets: int) -> int:
        return max(1, -(-buckets // DRILL_GROUP))

    def bucket_rows(
        self, plan: HashPlan, buckets: set[int]
    ) -> Iterator[tuple[int, dict[tuple[Any, ...], str]]]:
        """A pass of the table for each DRILL_GROUP buckets, in ascending order."""
        hasher = RowHasher(plan.columns, plan.key_positions, plan.precision)
        ordered = sorted(buckets)
        for i in range(0, len(ordered), DRILL_GROUP):
            group = ordered[i : i + DRILL_GROUP]
            held: dict[int, dict[tuple[Any, ...], str]] = {b: {} for b in group}
            with contextlib.closing(self._stream(plan)) as rows:
                for row in rows:
                    placed = hasher.placed(row, plan.buckets, held)
                    if placed is not None:
                        held[placed[0]][hasher.key_values(row)] = placed[1]
            yield from held.items()

    def fetch_rows(
        self, plan: HashPlan, keys: Sequence[tuple[Any, ...]]
    ) -> dict[tuple[Any, ...], list[Any]]:
        if not keys or not plan.key_columns:
            return {}
        hasher = RowHasher(plan.columns, plan.key_positions, plan.precision)
        wanted = {tuple(k) for k in keys}
        out = {}
        with contextlib.closing(self._stream(plan)) as rows:
            for row in rows:
                k = hasher.key_values(row)
                if k in wanted:
                    out[k] = row
        return out

    def float_stats(self, table: TableRef, column: str, where: str | None = None) -> FloatStats:
        c = self._q(column)
        num = f"(CASE WHEN typeof({c}) IN ('real', 'integer') THEN {c} END)"
        w = f" WHERE {self.excluding(where)}" if where else ""
        n, nn, lo, hi, total, inf = self.conn.execute(
            f"SELECT count(*), count({c}), min({num}), max({num}), total({num}), "
            f"sum({num} IN (9e999, -9e999)) FROM {self._ident(table)}{w}"  # noqa: S608
        ).fetchone()
        return FloatStats(int(n), int(nn), lo, hi, float(total) if nn else None, 0, int(inf or 0))

    def value_ranges(
        self, table: TableRef, columns: Sequence[str], predicate: str | None = None
    ) -> dict[str, tuple[Any, Any]]:
        """As the base does, with ISO 8601 text read as the date and time it is."""
        found = super().value_ranges(table, columns, predicate)

        def read(v: Any) -> Any:
            if isinstance(v, str):
                with contextlib.suppress(ValueError):
                    return dt.datetime.fromisoformat(v.strip())
            return v

        return {c: (read(lo), read(hi)) for c, (lo, hi) in found.items()}
