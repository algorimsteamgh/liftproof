"""SQL Server adapter (SQL Server 2016 and later, Amazon RDS for SQL Server, Azure SQL).

Connects with python-tds, a pure Python TDS driver, so the image needs no ODBC driver.

Pushdown computes the canonical hashes inside SQL Server with HASHBYTES, the same way
the other adapters do. SQL Server has no Unicode NFC function and hashes nvarchar as
UTF-16, so only rows whose text values are all ASCII are hashed in the database (ASCII
is the same in every code page and in UTF-8, and is already NFC). Every other row is
streamed and hashed application side by the reference implementation; both halves are
summed, so the result is byte identical to a full fallback (the parity tests hold them
to that).

A datetime value is stored in units of 1/300 second and shown rounded to the
millisecond (.003, .007). It is hashed as shown, which is what an export or a
migration tool writes to the target.

The snapshot is a SNAPSHOT isolation transaction, which needs ALLOW_SNAPSHOT_ISOLATION
on the database. Without it the source is read under READ COMMITTED, the baseline
records that it is not consistent, and doctor says so.
"""

from __future__ import annotations

import datetime as dt
import ssl
import time
from collections.abc import Iterator, Sequence
from typing import Any

import pytds
from OpenSSL import SSL

from liftproof.adapters.base import (
    Adapter,
    BucketAggregate,
    Column,
    FloatStats,
    HashPlan,
    TableRef,
    TableSchema,
    all_of,
    in_list,
)
from liftproof.canonical import GROUP_SIZE, CanonicalType, RowHasher, column_digest
from liftproof.canonical import value64 as _value64
from liftproof.errors import ConfigError

TYPE_MAP: dict[str, CanonicalType] = {
    "tinyint": CanonicalType.INTEGER,
    "smallint": CanonicalType.INTEGER,
    "int": CanonicalType.INTEGER,
    "bigint": CanonicalType.INTEGER,
    "decimal": CanonicalType.DECIMAL,
    "numeric": CanonicalType.DECIMAL,
    "money": CanonicalType.DECIMAL,
    "smallmoney": CanonicalType.DECIMAL,
    "real": CanonicalType.FLOAT,
    "float": CanonicalType.FLOAT,
    "bit": CanonicalType.BOOLEAN,
    "varchar": CanonicalType.TEXT,
    "nvarchar": CanonicalType.TEXT,
    "text": CanonicalType.TEXT,
    "ntext": CanonicalType.TEXT,
    "sysname": CanonicalType.TEXT,
    "char": CanonicalType.CHAR,
    "nchar": CanonicalType.CHAR,
    "date": CanonicalType.DATE,
    "time": CanonicalType.TIME,
    "datetime": CanonicalType.TIMESTAMP,
    "datetime2": CanonicalType.TIMESTAMP,
    "smalldatetime": CanonicalType.TIMESTAMP,
    "datetimeoffset": CanonicalType.TIMESTAMPTZ,
    "binary": CanonicalType.BINARY,
    "varbinary": CanonicalType.BINARY,
    "image": CanonicalType.BINARY,
    "timestamp": CanonicalType.BINARY,  # rowversion
    "uniqueidentifier": CanonicalType.UUID,
    "json": CanonicalType.JSON,  # SQL Server 2025 and Azure SQL
    # xml, sql_variant, geography, geometry, hierarchyid: unsupported (not checked)
}

TEXT_TYPES = {CanonicalType.TEXT, CanonicalType.CHAR}
PUSHDOWN_TYPES = {t for t in CanonicalType if t.hashed} - {CanonicalType.JSON}
MONEY = {"money", "smallmoney"}
MAX_PARAMS = 2000  # SQL Server allows 2100 parameters per request
TWO64 = "18446744073709551616"
# Text is pushed down only when every character is in U+0001 to U+007F. A binary
# collation makes LIKE compare code points.
ASCII_ONLY = "NOT LIKE N'%[^' + NCHAR(1) + N'-' + NCHAR(127) + N']%'"
BIN = "Latin1_General_100_BIN2"

NULL_DIGEST = column_digest(None)

SESSION = [
    "SET LANGUAGE us_english",
    "SET DATEFORMAT ymd",
    "SET ANSI_NULLS ON",
    "SET ANSI_PADDING ON",
    "SET ANSI_WARNINGS ON",
    "SET ARITHABORT ON",
    "SET CONCAT_NULL_YIELDS_NULL ON",
    "SET QUOTED_IDENTIFIER ON",
    "SET NUMERIC_ROUNDABORT OFF",
    "SET DEADLOCK_PRIORITY LOW",  # a deadlock with the application is ours to lose
]


def quote(name: str) -> str:
    return "[" + name.replace("]", "]]") + "]"


def canonical_type(data_type: str) -> CanonicalType:
    return TYPE_MAP.get(data_type.lower(), CanonicalType.UNSUPPORTED)


def native_name(data_type: str, max_length: int, precision: int, scale: int) -> str:
    t = data_type.lower()
    if t in ("varchar", "char", "varbinary", "binary"):
        return f"{t}({'max' if max_length == -1 else max_length})"
    if t in ("nvarchar", "nchar"):
        return f"{t}({'max' if max_length == -1 else max_length // 2})"
    if t in ("decimal", "numeric"):
        return f"{t}({precision},{scale})"
    if t in ("datetime2", "datetimeoffset", "time"):
        return f"{t}({scale})"
    return t


def _fraction(expr: str, p: int) -> str:
    """'.' and the first p digits of the microseconds (truncated, as the drivers do)."""
    if p <= 0:
        return ""
    micros = f"RIGHT('000000' + CAST(DATEPART(MICROSECOND, {expr}) AS varchar(7)), 6)"
    return f" + '.' + LEFT({micros}, {p})"


def _decimal(col: str, native: str) -> str:
    s = f"CAST(CAST({col} AS decimal(19,4)) AS varchar(60))" if native in MONEY else (
        f"CAST({col} AS varchar(60))"
    )  # fmt: skip
    # SQL Server prints the column's full scale: strip trailing zeros, then the point
    stripped = f"LEFT({s}, LEN({s}) - PATINDEX('%[^0]%', REVERSE({s})) + 1)"
    return (
        f"CASE WHEN {col} = 0 THEN '0' WHEN CHARINDEX('.', {s}) = 0 THEN {s} "
        f"WHEN RIGHT({stripped}, 1) = '.' THEN LEFT({stripped}, LEN({stripped}) - 1) "
        f"ELSE {stripped} END"
    )


def render_sql(col: str, ctype: CanonicalType, precision: int, native: str = "") -> str:
    """SQL Server expression producing the canonical rendering of one column.

    Text renders as nvarchar, so the same expression can match a key holding any text;
    digest_sql converts it to bytes, which is exact only for the ASCII rows that reach
    it (see _pushable_sql).
    """
    p = min(precision, 6)
    native = native.lower()
    match ctype:
        case CanonicalType.INTEGER:
            return f"CAST({col} AS varchar(20))"
        case CanonicalType.DECIMAL:
            return _decimal(col, native)
        case CanonicalType.BOOLEAN:
            return f"CASE WHEN {col} = 1 THEN '1' ELSE '0' END"
        case CanonicalType.TEXT:
            return f"CAST({col} AS nvarchar(max))"
        case CanonicalType.CHAR:
            return f"RTRIM(CAST({col} AS nvarchar(max)))"
        case CanonicalType.DATE:
            return f"CONVERT(varchar(10), {col}, 23)"
        case CanonicalType.TIME:
            return f"CONVERT(varchar(8), {col}, 108){_fraction(col, p)}"
        case CanonicalType.TIMESTAMP | CanonicalType.TIMESTAMPTZ:
            if ctype is CanonicalType.TIMESTAMPTZ:
                ts = f"CAST(SWITCHOFFSET({col}, '+00:00') AS datetime2(7))"
            elif native == "datetime":
                ts = f"CAST({col} AS datetime2(3))"  # the value as SQL Server shows it
            else:
                ts = col
            return f"LEFT(CONVERT(varchar(30), {ts}, 126), 19){_fraction(ts, p)}"
        case CanonicalType.BINARY:
            return f"LOWER(CONVERT(varchar(max), CONVERT(varbinary(max), {col}), 2))"
        case CanonicalType.UUID:
            return f"LOWER(CAST({col} AS char(36)))"
        case _:
            raise ValueError(f"no pushdown rendering for {ctype}")


def _md5(expr: str) -> str:
    return f"LOWER(CONVERT(varchar(32), HASHBYTES('MD5', {expr}), 2))"


def digest_sql(col: str, rendered: str) -> str:
    """Framed column digest. Rendered values are ASCII, so characters are bytes."""
    r = f"CAST({rendered} AS varchar(max))"
    return (
        f"CASE WHEN {col} IS NULL THEN '{NULL_DIGEST}' "
        f"ELSE {_md5(f'CAST(DATALENGTH({r}) AS varchar(20)) + CHAR(31) + {r}')} END"
    )


def combine_sql(digests: Sequence[str]) -> str:
    groups = [
        _md5("CAST(" + " + ".join(digests[i : i + GROUP_SIZE]) + " AS varchar(max))")
        for i in range(0, len(digests), GROUP_SIZE)
    ]
    return _md5("CAST(" + " + ".join(groups) + " AS varchar(max))")


def unsigned64_sql(hex_hash: str) -> str:
    """First 16 hex characters as an unsigned 64 bit number (decimal(20,0), exact)."""
    signed = f"CAST(CONVERT(binary(8), LEFT({hex_hash}, 16), 2) AS bigint)"
    return f"(CAST({signed} AS decimal(20,0)) + CASE WHEN {signed} < 0 THEN {TWO64} ELSE 0 END)"


def _pushable_sql(columns: Sequence[tuple[str, CanonicalType]]) -> str | None:
    """Condition true when SQL Server can render every value of the row exactly; None
    when every row qualifies."""
    parts = [
        f"({quote(n)} IS NULL OR CAST({quote(n)} AS nvarchar(max)) COLLATE {BIN} {ASCII_ONLY})"
        for n, t in columns
        if t in TEXT_TYPES
    ]
    return " AND ".join(parts) if parts else None


def _excluding(predicate: str | None) -> str | None:
    """Keep the rows a row ignore rule's predicate does not match; a NULL (unknown)
    result keeps the row too. The predicate comes from the project file (config refuses
    statement separators and comments); the adapter only ever reads."""
    return f"CASE WHEN ({predicate}) THEN 1 ELSE 0 END = 0" if predicate else None


def prepare(value: Any, ctype: CanonicalType) -> Any:
    """python-tds already returns what the reference renderer expects: Decimal for exact
    numbers, zone aware datetimes for datetimeoffset, UUID, bytes."""
    return value


def _tls_args(host: str, sslmode: str, sslrootcert: str | None) -> dict[str, Any]:
    """python-tds encrypts only with a CA bundle, and always verifies the chain."""
    match sslmode:
        case "disable":
            return {"dsn": host}
        case "verify-ca" | "verify-full":
            cafile = sslrootcert or ssl.get_default_verify_paths().cafile
            if not cafile:
                raise ConfigError("SQL Server TLS needs sslrootcert (a CA bundle file)")
            full = sslmode == "verify-full"
            # names in certificates are lower case; the driver compares them exactly
            return {"dsn": host.lower(), "cafile": cafile, "validate_host": full}
        case "require" | "prefer":
            raise ConfigError(
                f"sslmode {sslmode} (encryption without checking the certificate) is not "
                "available for SQL Server; use verify-ca with sslrootcert set to the "
                "server's certificate or its CA, or verify-full"
            )
    raise ConfigError(f"sslmode {sslmode!r} is not one of disable, verify-ca, verify-full")


class SQLServerAdapter(Adapter):
    engine = "sqlserver"
    hash_probe = "SELECT HASHBYTES('MD5', 'liftproof')"
    supports_row_filters = True
    supports_sampling = True
    # Each connection opens its own snapshot: workers reconcile live tables, a baseline
    # is taken on one connection (SQL Server cannot share a snapshot).
    supports_workers = True
    dms_schema = "dbo"

    def __init__(
        self,
        *,
        host: str,
        port: int = 1433,
        database: str,
        user: str | None = None,
        password: str | None = None,
        sslmode: str = "verify-full",
        sslrootcert: str | None = None,
        statement_timeout_ms: int = 0,
        read_only: bool = True,
        rows_per_second: int = 0,
        connect_timeout: int = 10,
    ) -> None:
        self._kwargs = {k: v for k, v in locals().items() if k not in ("self", "__class__")}
        try:
            self.conn = pytds.connect(
                port=port,
                database=database,
                user=user,
                password=password,
                login_timeout=connect_timeout,
                timeout=statement_timeout_ms / 1000 if statement_timeout_ms else None,
                appname="liftproof",
                autocommit=True,  # transactions are opened explicitly (begin_snapshot)
                disable_connect_retry=True,
                **_tls_args(host, sslmode, sslrootcert),
            )
        except (pytds.Error, OSError, SSL.Error) as exc:
            raise ConfigError(
                f"cannot connect to SQL Server at {host}:{port}/{database}: {exc}"
            ) from exc
        self.read_only = read_only
        self.rows_per_second = rows_per_second
        with self.conn.cursor() as cur:
            for stmt in SESSION:
                cur.execute(stmt)
        (self.version,) = self._query("SELECT CAST(SERVERPROPERTY('ProductVersion') AS varchar)")[0]
        self._settings = {
            s.removeprefix("SET ").split(" ", 1)[0]: s.split(" ")[-1] for s in SESSION
        }
        self._settings["statement_timeout_ms"] = str(statement_timeout_ms)
        # SQL Server has no read only session. The adapter only ever reads, and doctor
        # checks the login holds no write permission.
        self._natives: dict[TableRef, dict[str, str]] = {}
        self._in_snapshot = False

    def close(self) -> None:
        try:
            self.end_snapshot()
            self.conn.close()
        except (pytds.Error, OSError):
            pass

    def session_settings(self) -> dict[str, str]:
        return dict(self._settings, version=self.version)

    def _query(self, q: str, args: Sequence[Any] | None = None) -> list[tuple[Any, ...]]:
        with self.conn.cursor() as cur:
            if args:
                cur.execute(q, tuple(args))
            else:
                cur.execute(q)  # no parameters: % in LIKE patterns is literal
            return list(cur.fetchall())

    def _rows(self, q: str, args: Sequence[Any]) -> list[tuple[Any, ...]]:
        return self._query(q.format(*["%s"] * len(args)), list(args))

    def fork(self, snapshot: dict[str, Any] | None = None) -> SQLServerAdapter:
        if snapshot is not None:
            raise NotImplementedError("SQL Server cannot share a snapshot between connections")
        return SQLServerAdapter(**self._kwargs)

    # snapshot -----------------------------------------------------------------
    def begin_snapshot(self) -> dict[str, Any]:
        """A SNAPSHOT isolation transaction: every query in it sees the database as it was
        when the transaction first read data."""
        allowed, rcsi, ro, at, dbts = self._query(
            "SELECT snapshot_isolation_state, is_read_committed_snapshot_on, "
            "CAST(DATABASEPROPERTYEX(DB_NAME(), 'Updateability') AS varchar(20)), "
            "SYSUTCDATETIME(), CONVERT(varchar(18), @@DBTS, 1) "
            "FROM sys.databases WHERE database_id = DB_ID()"
        )[0]
        position: dict[str, Any] = {
            "replica": ro == "READ_ONLY",
            "taken_at": at.replace(tzinfo=dt.UTC).isoformat(),
            "exact": False,
        }
        if allowed != 1:
            self._settings["snapshot"] = "none: ALLOW_SNAPSHOT_ISOLATION is off"
            return {
                **position,
                "type": "none",
                "position": None,
                "consistent": False,
                "isolation": "read committed snapshot" if rcsi else "read committed",
            }
        with self.conn.cursor() as cur:
            cur.execute("SET TRANSACTION ISOLATION LEVEL SNAPSHOT")
            cur.execute("BEGIN TRANSACTION")
        self._in_snapshot = True
        self._settings["snapshot"] = "SNAPSHOT isolation"
        # @@DBTS (the database's last rowversion) is read just before the transaction's
        # first data read, so it can trail the snapshot by the changes in between.
        return {**position, "type": "dbts", "position": dbts}

    def end_snapshot(self) -> None:
        if self._in_snapshot:
            with self.conn.cursor() as cur:
                cur.execute("IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION")
                cur.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
            self._in_snapshot = False

    # catalogue ----------------------------------------------------------------
    def list_tables(self, schemas: Sequence[str]) -> list[TableRef]:
        if not schemas:
            return []
        marks = ", ".join(["%s"] * len(schemas))
        rows = self._query(
            "SELECT s.name, t.name FROM sys.tables t JOIN sys.schemas s "
            "ON s.schema_id = t.schema_id "
            f"WHERE s.name IN ({marks}) AND t.is_ms_shipped = 0 ORDER BY 1, 2",
            list(schemas),
        )
        return [TableRef(s, n) for s, n in rows]

    def describe(self, table: TableRef) -> TableSchema:
        rows = self._query(
            "SELECT c.name, CASE WHEN ty.is_user_defined = 1 THEN TYPE_NAME(c.system_type_id) "
            "ELSE ty.name END, c.max_length, c.precision, c.scale "
            "FROM sys.columns c JOIN sys.types ty ON ty.user_type_id = c.user_type_id "
            "WHERE c.object_id = OBJECT_ID(%s) ORDER BY c.column_id",
            [self._ident(table)],
        )
        if not rows:
            raise ConfigError(f"table {table} not found")
        cols = []
        natives = {}
        for name, data_type, max_length, precision, scale in rows:
            data_type = str(data_type).lower()
            natives[name] = data_type
            cols.append(
                Column(
                    name,
                    native_name(data_type, int(max_length), int(precision), int(scale)),
                    canonical_type(data_type),
                    fixed_width=data_type in ("char", "nchar"),
                )
            )
        self._natives[table] = natives
        pk = [
            r[0]
            for r in self._query(
                "SELECT c.name FROM sys.indexes i JOIN sys.index_columns ic "
                "ON ic.object_id = i.object_id AND ic.index_id = i.index_id "
                "JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id "
                "WHERE i.object_id = OBJECT_ID(%s) AND i.is_primary_key = 1 "
                "ORDER BY ic.key_ordinal",
                [self._ident(table)],
            )
        ]
        return TableSchema(table, cols, pk)

    def _native(self, table: TableRef) -> dict[str, str]:
        if table not in self._natives:
            self.describe(table)
        return self._natives[table]

    def _ident(self, table: TableRef) -> str:
        return f"{quote(table.schema)}.{quote(table.name)}"

    def row_count(self, table: TableRef) -> int:
        return int(self._query(f"SELECT COUNT_BIG(*) FROM {self._ident(table)}")[0][0])

    # hashing ------------------------------------------------------------------
    def _pushdown(self, plan: HashPlan) -> bool:
        return all(ctype in PUSHDOWN_TYPES for _, ctype in plan.columns)

    def _render(self, plan: HashPlan, name: str, ctype: CanonicalType) -> str:
        native = self._native(plan.table).get(name, "")
        return render_sql(quote(name), ctype, plan.precision, native)

    def _key_sql(self, plan: HashPlan) -> list[str]:
        types = dict(plan.columns)
        return [self._render(plan, k, types[k]) for k in plan.key_columns]

    def _hash_query(self, plan: HashPlan, where: str | None) -> str:
        """Row hash, key hash, its bucket and the rendered key, one row per table row."""
        digests = [digest_sql(quote(n), self._render(plan, n, t)) for n, t in plan.columns]
        row = combine_sql(digests)
        key = combine_sql([digests[i] for i in plan.key_positions]) if plan.key_columns else row
        keys = "".join(f", {e} AS k{i}" for i, e in enumerate(self._key_sql(plan)))
        q = f"SELECT {row} AS rh, {key} AS kh{keys} FROM {self._ident(plan.table)}"
        where = all_of(where, _excluding(plan.filter))
        q += f" WHERE {where}" if where else ""
        n = int(plan.buckets)
        return (
            f"SELECT h.*, x.b, x.v FROM ({q}) h CROSS APPLY (SELECT "
            f"{unsigned64_sql('h.kh')} % {n} AS b, {unsigned64_sql('h.rh')} AS v) x"
        )

    def bucket_aggregates(self, plan: HashPlan) -> dict[int, BucketAggregate]:
        if not self._pushdown(plan):
            return self._bucket_aggregates_fallback(plan)
        pushable = _pushable_sql(plan.columns)
        sample = "" if plan.sample is None else f" WHERE {in_list('b', plan.sample)}"
        q = (
            "SELECT CAST(b AS varchar(20)), COUNT_BIG(*), CAST(SUM(v) AS varchar(50)) "
            f"FROM ({self._hash_query(plan, pushable)}) a{sample} GROUP BY b"
        )
        out = {int(b): BucketAggregate(int(c), int(t)) for b, c, t in self._query(q)}
        if pushable:
            self._bucket_aggregates_fallback(plan, where=f"NOT ({pushable})", into=out)
        return out

    def _stream(self, plan: HashPlan, where: str | None = None) -> Iterator[list[Any]]:
        cols = ", ".join(quote(n) for n, _ in plan.columns)
        where = all_of(where, _excluding(plan.filter))
        q = f"SELECT {cols} FROM {self._ident(plan.table)}" + (f" WHERE {where}" if where else "")
        interval = 1.0 / self.rows_per_second if self.rows_per_second else 0.0
        types = [t for _, t in plan.columns]
        with self.conn.cursor() as cur:
            cur.execute(q)
            for row in cur:
                if interval:
                    time.sleep(interval)
                yield [prepare(v, t) for v, t in zip(row, types, strict=True)]

    def _bucket_aggregates_fallback(
        self,
        plan: HashPlan,
        where: str | None = None,
        into: dict[int, BucketAggregate] | None = None,
    ) -> dict[int, BucketAggregate]:
        hasher = RowHasher(plan.columns, plan.key_positions, plan.precision)
        out = into if into is not None else {}
        sample = None if plan.sample is None else set(plan.sample)
        for row in self._stream(plan, where):
            rh, kh = hasher.hash_row(row)
            b = _value64(kh) % plan.buckets
            if sample is not None and b not in sample:
                continue
            agg = out.setdefault(b, BucketAggregate(0, 0))
            agg.count += 1
            agg.total += _value64(rh)
        return out

    def _fallback_row_hashes(
        self, plan: HashPlan, wanted: set[int], where: str | None = None
    ) -> list[tuple[tuple[Any, ...], str]]:
        hasher = RowHasher(plan.columns, plan.key_positions, plan.precision)
        out = []
        for row in self._stream(plan, where):
            rh, kh = hasher.hash_row(row)
            if _value64(kh) % plan.buckets in wanted:
                rendered = hasher.rendered(row)
                out.append((tuple(rendered[i] for i in plan.key_positions), rh))
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
        pushable = _pushable_sql(plan.columns)
        nk = len(plan.key_columns)
        keys = "".join(f", k{i}" for i in range(nk))
        marks = ", ".join(str(int(b)) for b in sorted(wanted))
        q = f"SELECT rh{keys} FROM ({self._hash_query(plan, pushable)}) a WHERE b IN ({marks})"
        rows = [(tuple(r[1:]), r[0]) for r in self._query(q)]
        if pushable:
            rows += self._fallback_row_hashes(plan, wanted, where=f"NOT ({pushable})")
        yield from rows

    def fetch_rows(
        self, plan: HashPlan, keys: Sequence[tuple[Any, ...]]
    ) -> dict[tuple[Any, ...], list[Any]]:
        if not keys or not plan.key_columns:
            return {}
        key_exprs = self._key_sql(plan)
        nk = len(plan.key_columns)
        types = [t for _, t in plan.columns]
        cols = ", ".join(quote(n) for n, _ in plan.columns)
        # parameters are pyformat: the % signs in the rendering SQL must be doubled
        match = "(" + " AND ".join(f"{e.replace('%', '%%')} = %s" for e in key_exprs) + ")"
        out: dict[tuple[Any, ...], list[Any]] = {}
        per = max(1, MAX_PARAMS // nk)
        for start in range(0, len(keys), per):
            chunk = keys[start : start + per]
            q = (
                f"SELECT {', '.join(key_exprs).replace('%', '%%')}, {cols} "
                f"FROM {self._ident(plan.table)} "
                f"WHERE {' OR '.join([match] * len(chunk))}"
            )
            args = [v for k in chunk for v in k]
            for r in self._query(q, args):
                out[tuple(r[:nk])] = [prepare(v, t) for v, t in zip(r[nk:], types, strict=True)]
        return out

    def float_stats(self, table: TableRef, column: str, where: str | None = None) -> FloatStats:
        c = quote(column)
        w = f" WHERE {_excluding(where)}" if where else ""
        n, nn, lo, hi, total = self._query(
            f"SELECT COUNT_BIG(*), COUNT_BIG({c}), MIN({c}), MAX({c}), SUM(CAST({c} AS float)) "
            f"FROM {self._ident(table)}{w}"
        )[0]
        return FloatStats(  # SQL Server stores no NaN and no infinity
            int(n),
            int(nn),
            float(lo) if lo is not None else None,
            float(hi) if hi is not None else None,
            float(total) if total is not None else None,
            0,
            0,
        )

    # doctor -------------------------------------------------------------------
    def snapshot_available(self) -> bool:
        return (
            self._query(
                "SELECT snapshot_isolation_state FROM sys.databases WHERE database_id = DB_ID()"
            )[0][0]
            == 1
        )

    def verify_read_only(self) -> bool:
        """True when the login can change no table. Reads effective permissions only;
        never attempts a write. Covers server roles, database roles and grants on
        the database, its schemas and each table."""
        writes = "('INSERT', 'UPDATE', 'DELETE', 'ALTER', 'CONTROL', 'TAKE OWNERSHIP')"
        q = (
            "SELECT ISNULL(IS_SRVROLEMEMBER('sysadmin'), 0) + "
            "(SELECT COUNT(*) FROM fn_my_permissions(NULL, 'DATABASE') "
            f" WHERE permission_name IN {writes}) + "
            "(SELECT COUNT(*) FROM sys.tables t JOIN sys.schemas s ON s.schema_id = t.schema_id "
            " CROSS APPLY fn_my_permissions(QUOTENAME(s.name) + '.' + QUOTENAME(t.name), "
            f"'OBJECT') p WHERE t.is_ms_shipped = 0 AND p.permission_name IN {writes})"
        )
        return int(self._query(q)[0][0]) == 0
