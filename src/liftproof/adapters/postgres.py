"""PostgreSQL adapter, with hash pushdown and an application side fallback.

Pushdown computes the canonical hashes inside PostgreSQL so only hashes cross the
network. Tables containing a column that PostgreSQL cannot canonicalise identically
(json and jsonb, whose text forms reorder keys) are hashed application side by
streaming rows through the reference implementation. Both paths are held to byte
identical output by the parity tests.
"""

from __future__ import annotations

import time
from collections.abc import Iterator, Sequence
from typing import Any

import psycopg
from psycopg import sql

from liftproof.adapters.base import (
    Adapter,
    BucketAggregate,
    Column,
    FloatStats,
    HashPlan,
    TableRef,
    TableSchema,
)
from liftproof.canonical import GROUP_SIZE, CanonicalType, RowHasher, column_digest, value64
from liftproof.errors import ConfigError

TYPE_MAP: dict[str, CanonicalType] = {
    "smallint": CanonicalType.INTEGER,
    "integer": CanonicalType.INTEGER,
    "bigint": CanonicalType.INTEGER,
    "numeric": CanonicalType.DECIMAL,
    "real": CanonicalType.FLOAT,
    "double precision": CanonicalType.FLOAT,
    "boolean": CanonicalType.BOOLEAN,
    "text": CanonicalType.TEXT,
    "character varying": CanonicalType.TEXT,
    "name": CanonicalType.TEXT,
    "citext": CanonicalType.TEXT,
    "character": CanonicalType.CHAR,
    "date": CanonicalType.DATE,
    "time without time zone": CanonicalType.TIME,
    "timestamp without time zone": CanonicalType.TIMESTAMP,
    "timestamp with time zone": CanonicalType.TIMESTAMPTZ,
    "bytea": CanonicalType.BINARY,
    "uuid": CanonicalType.UUID,
    "json": CanonicalType.JSON,
    "jsonb": CanonicalType.JSON,
}

PUSHDOWN_TYPES = {t for t in CanonicalType if t.hashed} - {CanonicalType.JSON}

NULL_DIGEST = column_digest(None)
TWO_64 = "18446744073709551616"

SESSION = {
    "TimeZone": "UTC",
    "DateStyle": "ISO, YMD",
    "IntervalStyle": "iso_8601",
    "extra_float_digits": "3",
    "client_encoding": "UTF8",
}


def render_sql(col: sql.Composable, ctype: CanonicalType, precision: int) -> sql.Composable:
    """PostgreSQL expression producing the canonical rendering of one column, or NULL."""
    match ctype:
        case CanonicalType.INTEGER | CanonicalType.UUID:
            return sql.SQL("({})::text").format(col)
        case CanonicalType.DECIMAL:
            return sql.SQL("trim_scale({})::text").format(col)
        case CanonicalType.BOOLEAN:
            return sql.SQL("CASE WHEN {c} IS NULL THEN NULL WHEN {c} THEN '1' ELSE '0' END").format(
                c=col
            )
        case CanonicalType.TEXT:
            return sql.SQL("normalize(({})::text, NFC)").format(col)
        case CanonicalType.CHAR:
            return sql.SQL("normalize(rtrim(({})::text, ' '), NFC)").format(col)
        case CanonicalType.DATE:
            return sql.SQL("to_char({}, 'YYYY-MM-DD')").format(col)
        case CanonicalType.BINARY:
            return sql.SQL("encode({}, 'hex')").format(col)
        case CanonicalType.TIME:
            inner = sql.SQL("('2000-01-01'::date + {})").format(col)
            fmt = "HH24:MI:SS"
        case CanonicalType.TIMESTAMPTZ:
            inner = sql.SQL("({} AT TIME ZONE 'UTC')").format(col)
            fmt = 'YYYY-MM-DD"T"HH24:MI:SS'
        case CanonicalType.TIMESTAMP:
            inner = sql.SQL("({})").format(col)
            fmt = 'YYYY-MM-DD"T"HH24:MI:SS'
        case _:
            raise ValueError(f"no pushdown rendering for {ctype}")
    expr = sql.SQL("to_char({c}, {f})").format(c=inner, f=sql.Literal(fmt))
    if precision > 0:
        expr = sql.SQL("{e} || '.' || substr(to_char({c}, 'US'), 1, {p})").format(
            e=expr, c=inner, p=sql.Literal(min(precision, 6))
        )
    return expr


def digest_sql(rendered: sql.Composable) -> sql.Composable:
    # A NULL rendering makes the concatenation, and so the md5, NULL. Naming the rendering
    # twice rather than three times (CASE WHEN r IS NULL ...) matters: the planner does not
    # share repeated expressions, and the rendering is most of the per row cost.
    return sql.SQL("coalesce(md5(octet_length({r})::text || chr(31) || {r}), {n})").format(
        r=rendered, n=sql.Literal(NULL_DIGEST)
    )


def combine_sql(digests: Sequence[sql.Composable]) -> sql.Composable:
    groups = [
        sql.SQL("md5(concat({}))").format(sql.SQL(", ").join(digests[i : i + GROUP_SIZE]))
        for i in range(0, len(digests), GROUP_SIZE)
    ]
    return sql.SQL("md5(concat({}))").format(sql.SQL(", ").join(groups))


def unsigned64_sql(hex_hash: sql.Composable) -> sql.Composable:
    """First 16 hex characters as an unsigned 64 bit value, as exact numeric.

    bit(64)::bigint is signed, so negative values are lifted by 2**64.
    """
    signed = sql.SQL("(('x' || substr({}, 1, 16))::bit(64)::bigint)").format(hex_hash)
    # One reference to the hash: the subquery is flattened, so each reference to rh or kh
    # recomputes the whole row hash.
    return sql.SQL("mod({s}::numeric + {m}, {m})").format(s=signed, m=sql.SQL(TWO_64))


class PostgresAdapter(Adapter):
    engine = "postgresql"

    def __init__(
        self,
        *,
        host: str,
        port: int = 5432,
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
        params: dict[str, Any] = {
            "host": host,
            "port": port,
            "dbname": database,
            "sslmode": sslmode,
            "connect_timeout": connect_timeout,
            "application_name": "liftproof",
        }
        if user:
            params["user"] = user
        if password:
            params["password"] = password  # passed as a parameter, never in a DSN string
        if sslrootcert:
            params["sslrootcert"] = sslrootcert
        try:
            self.conn = psycopg.connect(**params, autocommit=True)
        except psycopg.OperationalError as exc:
            raise ConfigError(
                f"cannot connect to PostgreSQL at {host}:{port}/{database}: {exc}"
            ) from exc
        self.read_only = read_only
        self.rows_per_second = rows_per_second
        settings = dict(SESSION, statement_timeout=str(statement_timeout_ms))
        if read_only:
            settings["default_transaction_read_only"] = "on"
        with self.conn.cursor() as cur:
            for name, value in settings.items():
                cur.execute(
                    sql.SQL("SELECT set_config({}, {}, false)").format(
                        sql.Literal(name), sql.Literal(value)
                    )
                )
        self._settings = settings
        self._in_snapshot = False

    def close(self) -> None:
        if not self.conn.closed:
            self.conn.close()

    def session_settings(self) -> dict[str, str]:
        return dict(self._settings)

    # snapshot -----------------------------------------------------------------
    def begin_snapshot(self) -> dict[str, Any]:
        self.conn.autocommit = False
        self.conn.isolation_level = psycopg.IsolationLevel.REPEATABLE_READ
        self.conn.read_only = True
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT pg_is_in_recovery(), "
                "CASE WHEN pg_is_in_recovery() THEN pg_last_wal_replay_lsn()::text "
                "ELSE pg_current_wal_lsn()::text END, pg_export_snapshot(), now()"
            )
            in_recovery, lsn, snapshot_id, at = cur.fetchone()
        self._in_snapshot = True
        return {
            "type": "lsn",
            "position": lsn,
            "replica": in_recovery,
            "snapshot_id": snapshot_id,
            "taken_at": at.isoformat(),
        }

    def end_snapshot(self) -> None:
        if self._in_snapshot:
            self.conn.rollback()
            self.conn.autocommit = True
            self._in_snapshot = False

    # catalogue ----------------------------------------------------------------
    def list_tables(self, schemas: Sequence[str]) -> list[TableRef]:
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT table_schema, table_name FROM information_schema.tables "
                "WHERE table_type = 'BASE TABLE' AND table_schema = ANY(%s) "
                "ORDER BY 1, 2",
                (list(schemas),),
            )
            return [TableRef(s, n) for s, n in cur.fetchall()]

    def describe(self, table: TableRef) -> TableSchema:
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT column_name, data_type, udt_name FROM information_schema.columns "
                "WHERE table_schema = %s AND table_name = %s ORDER BY ordinal_position",
                (table.schema, table.name),
            )
            cols = []
            for name, data_type, udt in cur.fetchall():
                native = udt if data_type == "USER-DEFINED" else data_type
                ctype = TYPE_MAP.get(native, CanonicalType.UNSUPPORTED)
                cols.append(Column(name, native, ctype, fixed_width=native == "character"))
            if not cols:
                raise ConfigError(f"table {table} not found")
            cur.execute(
                "SELECT a.attname FROM pg_index i "
                "JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey) "
                "WHERE i.indrelid = %s::regclass AND i.indisprimary",
                (sql.Identifier(table.schema, table.name).as_string(self.conn),),
            )
            pk = [r[0] for r in cur.fetchall()]
        return TableSchema(table, cols, pk)

    def _ident(self, table: TableRef) -> sql.Identifier:
        return sql.Identifier(table.schema, table.name)

    def row_count(self, table: TableRef) -> int:
        with self.conn.cursor() as cur:
            cur.execute(sql.SQL("SELECT count(*) FROM {}").format(self._ident(table)))
            return cur.fetchone()[0]

    # hashing ------------------------------------------------------------------
    def _pushdown(self, plan: HashPlan) -> bool:
        return all(ctype in PUSHDOWN_TYPES for _, ctype in plan.columns)

    def _digests_sql(self, plan: HashPlan) -> list[sql.Composable]:
        return [
            digest_sql(render_sql(sql.Identifier(name), ctype, plan.precision))
            for name, ctype in plan.columns
        ]

    def _key_sql(self, plan: HashPlan) -> list[sql.Composable]:
        types = dict(plan.columns)
        return [render_sql(sql.Identifier(k), types[k], plan.precision) for k in plan.key_columns]

    def _hash_query(self, plan: HashPlan) -> sql.Composable:
        digests = self._digests_sql(plan)
        row = combine_sql(digests)
        key = combine_sql([digests[i] for i in plan.key_positions]) if plan.key_columns else row
        return sql.SQL("SELECT {row} AS rh, {key} AS kh{keys} FROM {t}").format(
            row=row,
            key=key,
            keys=sql.SQL("").join(
                sql.SQL(", {} AS {}").format(e, sql.Identifier(f"k{i}"))
                for i, e in enumerate(self._key_sql(plan))
            ),
            t=self._ident(plan.table),
        )

    def bucket_aggregates(self, plan: HashPlan) -> dict[int, BucketAggregate]:
        if not self._pushdown(plan):
            return self._bucket_aggregates_fallback(plan)
        q = sql.SQL(
            "SELECT mod({kh}, {n})::int AS b, count(*), sum({rh}) FROM ({inner}) h GROUP BY 1"
        ).format(
            kh=unsigned64_sql(sql.SQL("kh")),
            rh=unsigned64_sql(sql.SQL("rh")),
            n=sql.Literal(plan.buckets),
            inner=self._hash_query(plan),
        )
        with self.conn.cursor() as cur:
            cur.execute(q)
            return {b: BucketAggregate(c, int(t)) for b, c, t in cur.fetchall()}

    def _stream(self, plan: HashPlan) -> Iterator[tuple[Any, ...]]:
        cols = sql.SQL(", ").join(sql.Identifier(c) for c, _ in plan.columns)
        q = sql.SQL("SELECT {} FROM {}").format(cols, self._ident(plan.table))
        interval = 1.0 / self.rows_per_second if self.rows_per_second else 0.0
        with self.conn.transaction(), self.conn.cursor(name="liftproof_stream") as cur:
            cur.itersize = 5000
            cur.execute(q)
            for row in cur:
                if interval:
                    time.sleep(interval)
                yield row

    def _bucket_aggregates_fallback(self, plan: HashPlan) -> dict[int, BucketAggregate]:
        hasher = RowHasher(plan.columns, plan.key_positions, plan.precision)
        out: dict[int, BucketAggregate] = {}
        for row in self._stream(plan):
            rh, kh = hasher.hash_row(row)
            b = value64(kh) % plan.buckets
            agg = out.setdefault(b, BucketAggregate(0, 0))
            agg.count += 1
            agg.total += value64(rh)
        return out

    def row_hashes(
        self, plan: HashPlan, buckets: set[int]
    ) -> Iterator[tuple[tuple[Any, ...], str]]:
        if not buckets:
            return
        wanted = set(buckets)
        if not self._pushdown(plan):
            hasher = RowHasher(plan.columns, plan.key_positions, plan.precision)
            for row in self._stream(plan):
                rh, kh = hasher.hash_row(row)
                if value64(kh) % plan.buckets in wanted:
                    rendered = hasher.rendered(row)
                    yield tuple(rendered[i] for i in plan.key_positions), rh
            return
        q = sql.SQL("SELECT * FROM ({inner}) h WHERE mod({kh}, {n})::int = ANY(%s)").format(
            inner=self._hash_query(plan),
            kh=unsigned64_sql(sql.SQL("kh")),
            n=sql.Literal(plan.buckets),
        )
        with self.conn.cursor() as cur:
            cur.execute(q, (sorted(wanted),))
            for row in cur:
                yield tuple(row[2:]), row[0]

    def bucket_rows(
        self, plan: HashPlan, buckets: set[int]
    ) -> Iterator[tuple[int, dict[tuple[Any, ...], str]]]:
        """One pass over the table, ordered by bucket through a server side cursor, so
        only one bucket's keys and hashes are held here at a time."""
        if not self._pushdown(plan):
            yield from super().bucket_rows(plan, buckets)
            return
        wanted = sorted(set(buckets))
        q = sql.SQL(
            "SELECT b, rh, {keys} FROM (SELECT mod({kh}, {n})::int AS b, h.* FROM ({inner}) h) x "
            "WHERE b = ANY(%s) ORDER BY b"
        ).format(
            keys=sql.SQL(", ").join(sql.Identifier(f"k{i}") for i in range(len(plan.key_columns))),
            kh=unsigned64_sql(sql.SQL("kh")),
            n=sql.Literal(plan.buckets),
            inner=self._hash_query(plan),
        )
        pending = iter(wanted)
        current: int | None = None
        rows: dict[tuple[Any, ...], str] = {}
        with self.conn.transaction(), self.conn.cursor(name="liftproof_buckets") as cur:
            cur.itersize = 5000
            cur.execute(q, (wanted,))
            for b, rh, *key in cur:
                if b != current:
                    if current is not None:
                        yield current, rows
                    for empty in pending:  # buckets before this one had no rows
                        if empty == b:
                            break
                        yield empty, {}
                    current, rows = b, {}
                rows[tuple(key)] = rh
        if current is not None:
            yield current, rows
        for empty in pending:
            yield empty, {}

    def fetch_rows(
        self, plan: HashPlan, keys: Sequence[tuple[Any, ...]]
    ) -> dict[tuple[Any, ...], list[Any]]:
        if not keys or not plan.key_columns:
            return {}
        key_exprs = self._key_sql(plan)
        cols = sql.SQL(", ").join(sql.Identifier(c) for c, _ in plan.columns)
        match = sql.SQL("({}) IN ({})").format(
            sql.SQL(", ").join(key_exprs),
            sql.SQL(", ").join(
                sql.SQL("({})").format(sql.SQL(", ").join(sql.Literal(v) for v in k)) for k in keys
            ),
        )
        q = sql.SQL("SELECT {k}, {c} FROM {t} WHERE {m}").format(
            k=sql.SQL(", ").join(key_exprs), c=cols, t=self._ident(plan.table), m=match
        )
        nk = len(plan.key_columns)
        with self.conn.cursor() as cur:
            cur.execute(q)
            return {tuple(r[:nk]): list(r[nk:]) for r in cur.fetchall()}

    def float_stats(self, table: TableRef, column: str) -> FloatStats:
        c = sql.Identifier(column)
        finite = sql.SQL("{c} NOT IN ('NaN', 'Infinity', '-Infinity')").format(c=c)
        q = sql.SQL(
            "SELECT count(*), count({c}), min({c}) FILTER (WHERE {f}), max({c}) FILTER (WHERE {f}),"
            " sum({c}::numeric) FILTER (WHERE {f}),"
            " count(*) FILTER (WHERE {c} = 'NaN'),"
            " count(*) FILTER (WHERE {c} IN ('Infinity', '-Infinity')) FROM {t}"
        ).format(c=c, f=finite, t=self._ident(table))
        with self.conn.cursor() as cur:
            cur.execute(q)
            n, nn, lo, hi, total, nan, inf = cur.fetchone()
        return FloatStats(n, nn, lo, hi, float(total) if total is not None else None, nan, inf)

    # doctor -------------------------------------------------------------------
    def verify_read_only(self) -> bool:
        """True when this session cannot write. Uses a read only transaction and the
        role's privileges, never an actual write against the source."""
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT NOT EXISTS ("
                " SELECT 1 FROM information_schema.table_privileges"
                " WHERE grantee IN (current_user, 'PUBLIC')"
                " AND privilege_type IN ('INSERT','UPDATE','DELETE','TRUNCATE')"
                " AND table_schema NOT IN ('pg_catalog','information_schema'))"
                " AND NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)"
            )
            return bool(cur.fetchone()[0])
