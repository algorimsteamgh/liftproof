"""MySQL adapter (MySQL 8.0 and later, including Aurora MySQL 3).

Pushdown computes the canonical hashes inside MySQL, the same way the PostgreSQL adapter
does. MySQL has no Unicode normalisation function, so a row whose text columns are all
ASCII (already NFC by definition) is hashed in the database, and any other row is
streamed and hashed application side by the reference implementation. Both halves are
summed, so the result is byte identical to a full fallback; the parity tests hold them
to that. Tables with a JSON column are hashed application side, because MySQL's JSON
text form is not the canonical one.

In MySQL a schema is a database, so TableRef.schema is the database name.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import json
import math
import ssl
from collections.abc import Iterator, Sequence
from typing import Any

import pymysql
import pymysql.cursors

from liftproof.adapters import sqllog
from liftproof.adapters.base import (
    Adapter,
    BucketAggregate,
    Column,
    FloatStats,
    HashPlan,
    Pacer,
    TableRef,
    TableSchema,
    all_of,
    in_list,
)
from liftproof.canonical import GROUP_SIZE, CanonicalType, RowHasher, Verbatim, column_digest
from liftproof.canonical import value64 as _value64
from liftproof.errors import ConfigError

TYPE_MAP: dict[str, CanonicalType] = {
    "tinyint": CanonicalType.INTEGER,
    "smallint": CanonicalType.INTEGER,
    "mediumint": CanonicalType.INTEGER,
    "int": CanonicalType.INTEGER,
    "bigint": CanonicalType.INTEGER,
    "year": CanonicalType.INTEGER,
    "decimal": CanonicalType.DECIMAL,
    "float": CanonicalType.FLOAT,
    "double": CanonicalType.FLOAT,
    "varchar": CanonicalType.TEXT,
    "tinytext": CanonicalType.TEXT,
    "text": CanonicalType.TEXT,
    "mediumtext": CanonicalType.TEXT,
    "longtext": CanonicalType.TEXT,
    "enum": CanonicalType.TEXT,
    "set": CanonicalType.TEXT,
    "char": CanonicalType.CHAR,
    "date": CanonicalType.DATE,
    "time": CanonicalType.TIME,
    "datetime": CanonicalType.TIMESTAMP,  # no zone: rendered as stored
    "timestamp": CanonicalType.TIMESTAMPTZ,  # stored as UTC, read in a UTC session
    "binary": CanonicalType.BINARY,
    "varbinary": CanonicalType.BINARY,
    "tinyblob": CanonicalType.BINARY,
    "blob": CanonicalType.BINARY,
    "mediumblob": CanonicalType.BINARY,
    "longblob": CanonicalType.BINARY,
    "json": CanonicalType.JSON,
}

TEXT_TYPES = {CanonicalType.TEXT, CanonicalType.CHAR}
PUSHDOWN_TYPES = {t for t in CanonicalType if t.hashed} - {
    CanonicalType.JSON,
    CanonicalType.XML,  # no MySQL type maps to it
    CanonicalType.UUID,
}

NULL_DIGEST = column_digest(None)

SESSION = {
    "time_zone": "+00:00",
    # A fixed mode: no ANSI_QUOTES, PIPES_AS_CONCAT or PAD_CHAR_TO_FULL_LENGTH, any of
    # which would change how the hashing SQL parses or what CHAR columns return.
    "sql_mode": "NO_ENGINE_SUBSTITUTION",
}


def quote(name: str) -> str:
    return "`" + name.replace("`", "``") + "`"


def render_sql(col: str, ctype: CanonicalType, precision: int) -> str:
    """MySQL expression producing the canonical rendering of one column, or NULL.

    TEXT and CHAR are not NFC normalised here; only ASCII rows reach this expression.
    """
    p = min(precision, 6)
    match ctype:
        case CanonicalType.INTEGER:
            return f"CAST({col} AS CHAR)"
        case CanonicalType.BOOLEAN:
            return f"CASE WHEN {col} IS NULL THEN NULL WHEN {col} <> 0 THEN '1' ELSE '0' END"
        case CanonicalType.DECIMAL:
            s = f"CAST({col} AS CHAR)"
            return (
                f"CASE WHEN {col} IS NULL THEN NULL WHEN {col} = 0 THEN '0' "
                f"WHEN LOCATE('.', {s}) > 0 "
                f"THEN TRIM(TRAILING '.' FROM TRIM(TRAILING '0' FROM {s})) ELSE {s} END"
            )
        case CanonicalType.TEXT:
            return f"CONVERT({col} USING utf8mb4)"
        case CanonicalType.CHAR:
            return f"TRIM(TRAILING ' ' FROM CONVERT({col} USING utf8mb4))"
        case CanonicalType.DATE:
            return f"DATE_FORMAT({col}, '%Y-%m-%d')"
        case CanonicalType.BINARY:
            return f"LOWER(HEX({col}))"
        case CanonicalType.TIME:
            fn, fmt = "TIME_FORMAT", "%H:%i:%s"
        case CanonicalType.TIMESTAMP | CanonicalType.TIMESTAMPTZ:
            fn, fmt = "DATE_FORMAT", "%Y-%m-%dT%H:%i:%s"
        case _:
            raise ValueError(f"no pushdown rendering for {ctype}")
    expr = f"{fn}({col}, '{fmt}')"
    if p > 0:
        # MICROSECOND, not '%f': TIME_FORMAT puts the sign of a negative TIME into '%f'.
        expr = f"CONCAT({expr}, '.', SUBSTR(LPAD(MICROSECOND({col}), 6, '0'), 1, {p}))"
    return expr


def digest_sql(rendered: str) -> str:
    return (
        f"CASE WHEN {rendered} IS NULL THEN '{NULL_DIGEST}' "
        f"ELSE MD5(CONCAT(LENGTH({rendered}), CHAR(31 USING utf8mb4), {rendered})) END"
    )


def combine_sql(digests: Sequence[str]) -> str:
    groups = [
        f"MD5(CONCAT({', '.join(digests[i : i + GROUP_SIZE])}))"
        for i in range(0, len(digests), GROUP_SIZE)
    ]
    return f"MD5(CONCAT({', '.join(groups)}))"


def unsigned64_sql(hex_hash: str) -> str:
    """First 16 hex characters as BIGINT UNSIGNED."""
    return f"CAST(CONV(SUBSTR({hex_hash}, 1, 16), 16, 10) AS UNSIGNED)"


def _ascii_sql(columns: Sequence[tuple[str, CanonicalType]]) -> str | None:
    """Condition true when every text value in the row is ASCII; None if no text columns."""
    parts = []
    for n, t in columns:
        if t in TEXT_TYPES:
            c = quote(n)
            parts.append(f"({c} IS NULL OR LENGTH(CONVERT({c} USING utf8mb4)) = CHAR_LENGTH({c}))")
    return " AND ".join(parts) if parts else None


def _excluding(predicate: str | None) -> str | None:
    """Keep the rows a row ignore rule's predicate does not match; a NULL result keeps
    the row too. The predicate comes from the project file (config refuses statement
    separators and comments) and runs in a read only transaction."""
    return f"({predicate}) IS NOT TRUE" if predicate else None


def _fraction(text: str, precision: int) -> str:
    p = min(precision, 6)
    return "." + (text + "000000")[:p] if p > 0 else ""


def _zero_datetime(text: str, precision: int) -> Verbatim:
    """MySQL zero or partial dates ('0000-00-00 00:00:00') rendered as DATE_FORMAT does."""
    base, _, frac = text.partition(".")
    return Verbatim(base[:19].replace(" ", "T") + _fraction(frac, precision))


def _time_value(td: dt.timedelta, precision: int) -> dt.time | Verbatim:
    """MySQL TIME is a duration. Inside one day it is a time of day; outside it has no
    canonical value and is rendered as TIME_FORMAT does ('-01:02:03', '125:00:00')."""
    if dt.timedelta(0) <= td < dt.timedelta(days=1):
        return (dt.datetime.min + td).time()
    sign = "-" if td < dt.timedelta(0) else ""
    micros = abs(td) // dt.timedelta(microseconds=1)
    secs, us = divmod(micros, 1_000_000)
    hours, rem = divmod(secs, 3600)
    return Verbatim(
        f"{sign}{hours:02d}:{rem // 60:02d}:{rem % 60:02d}" + _fraction(f"{us:06d}", precision)
    )


def prepare(value: Any, ctype: CanonicalType, precision: int) -> Any:
    """Turn a PyMySQL value into what the reference renderer expects."""
    if value is None:
        return None
    match ctype:
        case CanonicalType.TIMESTAMPTZ | CanonicalType.TIMESTAMP:
            if isinstance(value, str):
                return _zero_datetime(value, precision)
            if ctype is CanonicalType.TIMESTAMPTZ:
                return value.replace(tzinfo=dt.UTC)  # the session reads TIMESTAMP in UTC
        case CanonicalType.DATE:
            if isinstance(value, str):
                return Verbatim(value)
        case CanonicalType.TIME:
            if isinstance(value, dt.timedelta):
                return _time_value(value, precision)
        case CanonicalType.TEXT | CanonicalType.CHAR:
            if isinstance(value, bytes):
                return value.decode("utf-8")
        case CanonicalType.JSON:
            return json.loads(value) if isinstance(value, (str, bytes)) else value
    return value


def _ssl_args(sslmode: str, sslrootcert: str | None) -> dict[str, Any]:
    match sslmode:
        case "disable":
            return {"ssl_disabled": True}
        case "require" | "prefer":
            return {"ssl": {"check_hostname": False, "verify_mode": ssl.CERT_NONE}}
        case "verify-ca" | "verify-full":
            # A context, not PyMySQL's dict: given a dict with no "ca", PyMySQL turns
            # certificate and host name checks off. With no sslrootcert this context
            # trusts the system CAs, as Oracle and SQL Server do.
            ctx = ssl.create_default_context(cafile=sslrootcert)
            ctx.check_hostname = sslmode == "verify-full"
            return {"ssl": ctx}
    raise ConfigError(f"sslmode {sslmode!r} is not one of disable, require, verify-ca, verify-full")


class MySQLAdapter(Adapter):
    engine = "mysql"
    product = "MySQL"
    minimum_version = (8, 0)
    minimum_shown = "MySQL 8.0 (Aurora MySQL 3)"
    supports_row_filters = True
    supports_sampling = True
    # Each connection opens its own snapshot: workers reconcile live tables, a baseline
    # is taken on one connection (see shares_snapshot).
    supports_workers = True
    replication_methods = ("replica", "dms", "goldengate")
    dms_schema = "awsdms_control"

    def quote_name(self, name: str) -> str:
        return quote(name)

    def __init__(
        self,
        *,
        host: str,
        port: int = 3306,
        database: str,
        user: str | None = None,
        password: str | None = None,
        sslmode: str = "verify-full",
        sslrootcert: str | None = None,
        statement_timeout_ms: int = 0,
        lock_timeout_ms: int = 0,
        read_only: bool = True,
        rows_per_second: int = 0,
        pause_ms: int = 0,
        connect_timeout: int = 10,
    ) -> None:
        self._kwargs = {k: v for k, v in locals().items() if k not in ("self", "__class__")}
        params: dict[str, Any] = {
            "host": host,
            "port": port,
            "database": database,
            "charset": "utf8mb4",
            "connect_timeout": connect_timeout,
            "autocommit": True,
            "program_name": "liftproof",
            **_ssl_args(sslmode, sslrootcert),
        }
        if user:
            params["user"] = user
        if password:
            params["password"] = password
        try:
            self.conn = pymysql.connect(**params)
        except pymysql.err.MySQLError as exc:
            raise ConfigError(
                f"cannot connect to MySQL at {host}:{port}/{database}: {exc}"
            ) from exc
        self.conn = sqllog.wrap(self.conn, self.engine)
        self.read_only = read_only
        self.pacer = Pacer(rows_per_second, pause_ms)
        with self.conn.cursor() as cur:
            cur.execute("SELECT VERSION()")
            version = cur.fetchone()[0]
        if "mariadb" in version.lower():
            # different session variables (max_statement_time) and functions; never tested
            self.close()
            raise ConfigError(f"MariaDB ({version}) is not supported yet; only MySQL 8.0 and "
                              "later, including Aurora MySQL 3")  # fmt: skip
        self.require_version(version)
        protect = {}
        if lock_timeout_ms:  # whole seconds, at least one; it covers metadata locks
            protect["lock_wait_timeout"] = math.ceil(lock_timeout_ms / 1000)
        self.lock_timeout_ms = protect.get("lock_wait_timeout", 0) * 1000
        if rows_per_second:  # one thread: the cap is per connection
            protect["innodb_parallel_read_threads"] = 1
        with self.conn.cursor() as cur:
            for name, value in SESSION.items():
                cur.execute(f"SET SESSION {name} = %s", (value,))
            cur.execute("SET SESSION max_execution_time = %s", (int(statement_timeout_ms),))
            for name, value in protect.items():
                cur.execute(f"SET SESSION {name} = %s", (value,))
            if read_only:
                cur.execute("SET SESSION TRANSACTION READ ONLY")
        settings = dict(
            SESSION,
            max_execution_time=str(statement_timeout_ms),
            lock_wait_timeout="server default",
        )
        settings.update(
            {k: str(v) for k, v in protect.items()},
            rows_per_second=str(rows_per_second),
            pause_ms=str(pause_ms),
        )
        if read_only:
            settings["transaction_read_only"] = "ON"
        self._settings = settings
        self._in_snapshot = False

    def close(self) -> None:
        if self.conn.open:
            self.conn.close()

    def session_settings(self) -> dict[str, str]:
        return dict(self._settings, version=self.version)

    def _query(self, q: str, args: Any = None) -> list[tuple[Any, ...]]:
        with self.conn.cursor() as cur:
            cur.execute(q, args)
            return list(cur.fetchall())

    def _rows(self, q: str, args: Sequence[Any]) -> list[tuple[Any, ...]]:
        return self._query(q.format(*["%s"] * len(args)), list(args))

    def fork(self, snapshot: dict[str, Any] | None = None) -> MySQLAdapter:
        if snapshot is not None:
            raise NotImplementedError("MySQL cannot share a snapshot between connections")
        return MySQLAdapter(**self._kwargs)

    # replication ----------------------------------------------------------------
    def _replica_status(self, channel: str) -> dict[str, Any] | None:
        for stmt in ("SHOW REPLICA STATUS", "SHOW SLAVE STATUS"):
            try:
                with self.conn.cursor(pymysql.cursors.DictCursor) as cur:
                    cur.execute(stmt)
                    rows = list(cur.fetchall())
            except pymysql.err.MySQLError:
                continue
            for r in rows:
                if (r.get("Channel_Name") or "") == channel:
                    return r
            return None
        return None

    def _executed(self, channel: str) -> str | None:
        """The replica channel's executed source binlog position, as file:offset."""
        r = self._replica_status(channel)
        if r is None:
            return None
        log = r.get("Relay_Source_Log_File") or r.get("Relay_Master_Log_File")
        pos = r.get("Exec_Source_Log_Pos") or r.get("Exec_Master_Log_Pos")
        return f"{log}:{pos}" if log else None

    def replication_applied(self, method: str, name: str) -> str | None:
        """replica: run on the target. The GTID set it has executed when GTIDs are on,
        else the replica channel's executed source position (name; empty for the
        default channel). SHOW REPLICA STATUS needs the REPLICATION CLIENT privilege."""
        if method != "replica":
            raise NotImplementedError(method)
        (executed,) = self._query("SELECT @@GLOBAL.gtid_executed")[0]
        executed = (executed or "").replace("\n", "")
        return executed or self._executed(name)

    def replication_reached(
        self, method: str, name: str, kind: str, position: str
    ) -> tuple[str, bool] | None:
        """With a GTID position the target must have executed every transaction in the
        source's set (an RDS or Aurora read replica promoted at cutover included); with a
        binlog position the replica channel must have executed up to it."""
        if method != "replica":
            raise NotImplementedError(method)
        if kind == "gtid":
            (executed,) = self._query("SELECT @@GLOBAL.gtid_executed")[0]
            executed = (executed or "").replace("\n", "")
            (subset,) = self._query("SELECT GTID_SUBSET(%s, %s)", (position, executed))[0]
            return executed or "(no transactions)", bool(subset)
        if kind != "binlog":
            raise NotImplementedError(kind)
        applied = self._executed(name)
        if applied is None:
            return None
        return applied, self.position_key(kind, applied) >= self.position_key(kind, position)

    @staticmethod
    def position_key(kind: str, position: str) -> Any:
        if kind != "binlog":
            raise NotImplementedError(kind)
        log, _, pos = position.rpartition(":")
        return int(log.rpartition(".")[2] or 0), int(pos)

    # snapshot -----------------------------------------------------------------
    def begin_snapshot(self) -> dict[str, Any]:
        with self.conn.cursor() as cur:
            cur.execute("SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            cur.execute("START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY")
            cur.execute("SELECT NOW(6), @@GLOBAL.read_only, @@GLOBAL.gtid_executed")
            at, ro, gtid = cur.fetchone()
        gtid = gtid.replace("\n", "") if gtid else gtid
        self._in_snapshot = True
        position = {"type": "gtid", "position": gtid} if gtid else self._binlog_position()
        # MySQL does not report the binlog position of a consistent snapshot atomically
        # (MariaDB does). The position is read immediately after the snapshot opened, so
        # it can trail the snapshot by the writes committed in between.
        return {
            **position,
            "exact": False,
            "replica": bool(ro),
            "taken_at": at.replace(tzinfo=dt.UTC).isoformat(),
        }

    def current_position(self) -> dict[str, Any] | None:
        at, gtid = self._query("SELECT UTC_TIMESTAMP(6), @@GLOBAL.gtid_executed")[0]
        gtid = gtid.replace("\n", "") if gtid else gtid
        position = {"type": "gtid", "position": gtid} if gtid else self._binlog_position()
        return {**position, "taken_at": at.replace(tzinfo=dt.UTC).isoformat()}

    def _binlog_position(self) -> dict[str, Any]:
        for stmt in ("SHOW BINARY LOG STATUS", "SHOW MASTER STATUS"):
            try:
                rows = self._query(stmt)
            except pymysql.err.MySQLError:
                continue
            if rows:
                return {"type": "binlog", "position": f"{rows[0][0]}:{rows[0][1]}"}
        return {"type": "none", "position": None}

    def end_snapshot(self) -> None:
        if self._in_snapshot:
            self.conn.rollback()
            self._in_snapshot = False

    # catalogue ----------------------------------------------------------------
    def list_tables(self, schemas: Sequence[str]) -> list[TableRef]:
        if not schemas:
            return []
        marks = ", ".join(["%s"] * len(schemas))
        rows = self._query(
            "SELECT TABLE_SCHEMA, TABLE_NAME FROM information_schema.TABLES "
            f"WHERE TABLE_TYPE = 'BASE TABLE' AND TABLE_SCHEMA IN ({marks}) ORDER BY 1, 2",
            list(schemas),
        )
        return [TableRef(s, n) for s, n in rows]

    def describe(self, table: TableRef) -> TableSchema:
        rows = self._query(
            "SELECT COLUMN_NAME, DATA_TYPE, COLUMN_TYPE FROM information_schema.COLUMNS "
            "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s ORDER BY ORDINAL_POSITION",
            (table.schema, table.name),
        )
        if not rows:
            raise ConfigError(f"table {table} not found")
        cols = []
        for name, data_type, column_type in rows:
            native = str(column_type).lower()
            ctype = TYPE_MAP.get(str(data_type).lower(), CanonicalType.UNSUPPORTED)
            if native.startswith("tinyint(1)"):
                ctype = CanonicalType.BOOLEAN  # MySQL's BOOLEAN is TINYINT(1)
            cols.append(Column(name, native, ctype, fixed_width=data_type == "char"))
        pk = [
            r[0]
            for r in self._query(
                "SELECT COLUMN_NAME FROM information_schema.KEY_COLUMN_USAGE "
                "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s AND CONSTRAINT_NAME = 'PRIMARY' "
                "ORDER BY ORDINAL_POSITION",
                (table.schema, table.name),
            )
        ]
        return TableSchema(table, cols, pk)

    def _ident(self, table: TableRef) -> str:
        return f"{quote(table.schema)}.{quote(table.name)}"

    def row_count(self, table: TableRef) -> int:
        return int(self._query(f"SELECT COUNT(*) FROM {self._ident(table)}")[0][0])

    # hashing ------------------------------------------------------------------
    def _pushdown(self, plan: HashPlan) -> bool:
        return all(ctype in PUSHDOWN_TYPES for _, ctype in plan.columns)

    def _key_sql(self, plan: HashPlan) -> list[str]:
        types = dict(plan.columns)
        return [render_sql(quote(k), types[k], plan.precision) for k in plan.key_columns]

    def _hash_query(self, plan: HashPlan, where: str | None) -> str:
        digests = [digest_sql(render_sql(quote(n), t, plan.precision)) for n, t in plan.columns]
        row = combine_sql(digests)
        key = combine_sql([digests[i] for i in plan.key_positions]) if plan.key_columns else row
        keys = "".join(f", {e} AS k{i}" for i, e in enumerate(self._key_sql(plan)))
        q = f"SELECT {row} AS rh, {key} AS kh{keys} FROM {self._ident(plan.table)}"
        where = all_of(where, _excluding(plan.filter))
        return q + (f" WHERE {where}" if where else "")

    def bucket_aggregates(self, plan: HashPlan) -> dict[int, BucketAggregate]:
        if not self._pushdown(plan):
            return self._bucket_aggregates_fallback(plan)
        ascii_rows = _ascii_sql(plan.columns)
        bucket = f"MOD({unsigned64_sql('kh')}, {int(plan.buckets)})"
        # the bucket test sits on the scan, so rows outside a sample are never hashed
        # past the key
        sample = "" if plan.sample is None else f" WHERE {in_list(bucket, plan.sample)}"
        q = (
            f"SELECT {bucket} AS b, COUNT(*), SUM({unsigned64_sql('rh')}) "
            f"FROM ({self._hash_query(plan, ascii_rows)}) h{sample} GROUP BY b"
        )
        out = {int(b): BucketAggregate(int(c), int(t)) for b, c, t in self._query(q)}
        if ascii_rows:  # another read of the table (spec 9.15)
            self.pacer.again()
            self._bucket_aggregates_fallback(plan, where=f"NOT ({ascii_rows})", into=out)
        return out

    def _stream(self, plan: HashPlan, where: str | None = None) -> Iterator[list[Any]]:
        cols = ", ".join(quote(c) for c, _ in plan.columns)
        where = all_of(where, _excluding(plan.filter))
        q = f"SELECT {cols} FROM {self._ident(plan.table)}" + (f" WHERE {where}" if where else "")
        types = [t for _, t in plan.columns]
        with self.conn.cursor(pymysql.cursors.SSCursor) as cur:
            cur.execute(q)
            for row in self.pacer.each(cur):
                yield [prepare(v, t, plan.precision) for v, t in zip(row, types, strict=True)]

    def _bucket_aggregates_fallback(
        self,
        plan: HashPlan,
        where: str | None = None,
        into: dict[int, BucketAggregate] | None = None,
    ) -> dict[int, BucketAggregate]:
        hasher = RowHasher(plan.columns, plan.key_positions, plan.precision)
        out = into if into is not None else {}
        sample = None if plan.sample is None else set(plan.sample)
        # closed at once when a value cannot be hashed, so the connection reads on
        with contextlib.closing(self._stream(plan, where)) as rows:
            for row in rows:
                placed = hasher.placed(row, plan.buckets, sample)
                if placed is None:
                    continue
                b, rh = placed
                agg = out.setdefault(b, BucketAggregate(0, 0))
                agg.count += 1
                agg.total += _value64(rh)
        return out

    def _fallback_row_hashes(
        self, plan: HashPlan, wanted: set[int], where: str | None = None
    ) -> list[tuple[tuple[Any, ...], str]]:
        hasher = RowHasher(plan.columns, plan.key_positions, plan.precision)
        out = []
        with contextlib.closing(self._stream(plan, where)) as rows:
            for row in rows:
                placed = hasher.placed(row, plan.buckets, wanted)
                if placed is not None:
                    out.append((hasher.key_values(row), placed[1]))
        return out

    def row_hashes(
        self, plan: HashPlan, buckets: set[int]
    ) -> Iterator[tuple[tuple[Any, ...], str]]:
        if not buckets:
            return
        wanted = set(buckets)
        if not self._pushdown(plan):
            yield from self._fallback_row_hashes(plan, wanted)
            return
        ascii_rows = _ascii_sql(plan.columns)
        marks = ", ".join(str(int(b)) for b in sorted(wanted))
        q = (
            f"SELECT * FROM ({self._hash_query(plan, ascii_rows)}) h "
            f"WHERE MOD({unsigned64_sql('kh')}, {int(plan.buckets)}) IN ({marks})"
        )
        rows = [(tuple(r[2:]), r[0]) for r in self._query(q)]
        if ascii_rows:  # another read of the table (spec 9.15)
            self.pacer.again()
            rows += self._fallback_row_hashes(plan, wanted, where=f"NOT ({ascii_rows})")
        yield from rows

    def fetch_rows(
        self, plan: HashPlan, keys: Sequence[tuple[Any, ...]]
    ) -> dict[tuple[Any, ...], list[Any]]:
        if not keys or not plan.key_columns:
            return {}
        key_exprs = self._key_sql(plan)
        nk = len(plan.key_columns)
        tuple_marks = "(" + ", ".join(["%s"] * nk) + ")"
        q = (
            f"SELECT {', '.join(key_exprs)}, {', '.join(quote(c) for c, _ in plan.columns)} "
            f"FROM {self._ident(plan.table)} WHERE ({', '.join(key_exprs)}) IN "
            f"({', '.join([tuple_marks] * len(keys))})"
        )
        args = [v for k in keys for v in k]
        types = [t for _, t in plan.columns]
        return {
            tuple(r[:nk]): [
                prepare(v, t, plan.precision) for v, t in zip(r[nk:], types, strict=True)
            ]
            for r in self._query(q, args)
        }

    def float_stats(self, table: TableRef, column: str, where: str | None = None) -> FloatStats:
        c = quote(column)
        w = f" WHERE {_excluding(where)}" if where else ""
        n, nn, lo, hi, total = self._query(
            f"SELECT COUNT(*), COUNT({c}), MIN({c}), MAX({c}), SUM({c}) "
            f"FROM {self._ident(table)}{w}"
        )[0]
        return FloatStats(
            int(n), int(nn), lo, hi, float(total) if total is not None else None, 0, 0
        )  # MySQL floats hold no NaN or infinity

    # doctor -------------------------------------------------------------------
    def verify_read_only(self) -> bool:
        """True when the login holds no write privilege at any level. Reads the grants
        only; never attempts a write against the source. A privilege that reaches the
        login only through a MySQL role is not expanded here."""
        rows = self._query("SHOW GRANTS")
        writes = ("ALL PRIVILEGES", "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE")
        for (grant,) in rows:
            text = str(grant).upper()
            if not text.startswith("GRANT "):
                continue
            privs = text[len("GRANT ") :].split(" ON ", 1)[0]
            if any(w in privs for w in writes):
                return False
        return True
