"""Oracle adapter (Oracle Database 19c and later, including Amazon RDS for Oracle).

Connects with python-oracledb in thin mode, so the image needs no Oracle client.

Pushdown computes the canonical hashes inside Oracle with STANDARD_HASH, the same way
the other adapters do. Three Oracle limits decide which rows can be hashed in the
database, and every other row is streamed and hashed application side by the reference
implementation; both halves are summed, so the result is byte identical to a full
fallback (the parity tests hold them to that):

- Oracle has no exact Unicode NFC function (COMPOSE does not decompose first), so a row
  whose text values are not all ASCII goes to the application side;
- a SQL string is at most 4000 bytes, so a row with a text value over 3990 characters
  or a RAW value over 1995 bytes does too;
- TO_CHAR switches to scientific notation for numbers it cannot print in 40 characters,
  so a row holding such a number does too.

Tables with a LOB, JSON or XMLTYPE column are hashed application side; an XMLTYPE value is
read as XMLSERIALIZE writes it, unindented.

Oracle stores the empty string as NULL. A text value that is empty on the other engine
and NULL in Oracle is a real difference and is reported as one; see
docs/canonical-v1.md.

In Oracle a schema is a user, so TableRef.schema is the owner, normally in upper case.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import decimal
import ssl
from collections.abc import Iterator, Sequence
from typing import Any

import oracledb

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
    fetch_batch,
    in_list,
)
from liftproof.canonical import GROUP_SIZE, CanonicalType, RowHasher, column_digest
from liftproof.canonical import value64 as _value64
from liftproof.errors import ConfigError

TYPE_MAP: dict[str, CanonicalType] = {
    "FLOAT": CanonicalType.FLOAT,  # binary precision NUMBER; targets store it as a double
    "BINARY_FLOAT": CanonicalType.FLOAT,
    "BINARY_DOUBLE": CanonicalType.FLOAT,
    "VARCHAR2": CanonicalType.TEXT,
    "NVARCHAR2": CanonicalType.TEXT,
    "VARCHAR": CanonicalType.TEXT,
    "CLOB": CanonicalType.TEXT,
    "NCLOB": CanonicalType.TEXT,
    "CHAR": CanonicalType.CHAR,
    "NCHAR": CanonicalType.CHAR,
    "DATE": CanonicalType.TIMESTAMP,  # an Oracle DATE carries a time of day
    "RAW": CanonicalType.BINARY,
    "BLOB": CanonicalType.BINARY,
    "JSON": CanonicalType.JSON,
    "XMLTYPE": CanonicalType.XML,
    "BOOLEAN": CanonicalType.BOOLEAN,  # 23ai
}

LOB_TYPES = {"CLOB", "NCLOB", "BLOB"}
TEXT_TYPES = {CanonicalType.TEXT, CanonicalType.CHAR}
PUSHDOWN_TYPES = {t for t in CanonicalType if t.hashed} - {
    CanonicalType.JSON,
    CanonicalType.XML,
    CanonicalType.UUID,
    CanonicalType.TIME,  # Oracle has no TIME type
}
MAX_TEXT = 3990  # characters: 4000 byte SQL strings, less the frame's length prefix
MAX_RAW = 1995  # bytes: rendered as two hex characters each
IN_LIST = 500  # Oracle allows 1000 expressions in an IN list

NULL_DIGEST = column_digest(None)

SESSION = {
    "TIME_ZONE": "'+00:00'",
    "NLS_NUMERIC_CHARACTERS": "'.,'",
}


def quote(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def canonical_type(data_type: str, precision: int | None, scale: int | None) -> CanonicalType:
    t = data_type.upper()
    if t == "NUMBER":
        if scale is not None and scale <= 0:
            return CanonicalType.INTEGER  # NUMBER(p), NUMBER(p,0), INTEGER
        return CanonicalType.DECIMAL  # NUMBER(p,s) and unconstrained NUMBER
    if t.startswith("TIMESTAMP"):
        if "TIME ZONE" in t:
            return CanonicalType.TIMESTAMPTZ  # WITH TIME ZONE and WITH LOCAL TIME ZONE
        return CanonicalType.TIMESTAMP
    return TYPE_MAP.get(t, CanonicalType.UNSUPPORTED)


def native_name(data_type: str, length: int | None, precision: int | None, scale: int | None):
    t = data_type.upper()
    if t == "NUMBER":
        if precision is None and scale is None:
            return "NUMBER"
        if precision is None:
            return "INTEGER" if scale == 0 else f"NUMBER(*,{scale})"
        return f"NUMBER({precision},{scale})" if scale else f"NUMBER({precision})"
    if t in ("VARCHAR2", "NVARCHAR2", "CHAR", "NCHAR", "RAW") and length:
        return f"{t}({length})"
    return t


def _utc(native: str, col: str) -> str:
    """A TIMESTAMP expression in UTC for a zone aware column (the session zone is UTC,
    which is what WITH LOCAL TIME ZONE values are shown in)."""
    if "LOCAL TIME ZONE" in native:
        return f"CAST({col} AS TIMESTAMP(9))"
    return f"SYS_EXTRACT_UTC({col})"


def render_sql(col: str, ctype: CanonicalType, precision: int, native: str = "") -> str:
    """Oracle expression producing the canonical rendering of one column, or NULL.

    Oracle turns an empty string into NULL, so the caller decides NULL from the column
    itself and frames a NULL rendering as the empty string (see digest_sql). TEXT and
    CHAR are not NFC normalised here; only ASCII rows reach this expression.
    """
    p = min(precision, 6)
    native = native.upper()
    match ctype:
        case CanonicalType.INTEGER:
            return f"TO_CHAR({col})"
        case CanonicalType.DECIMAL:
            # TO_CHAR prints no trailing zeros, but drops the zero before the point
            return (
                f"CASE WHEN {col} = 0 THEN '0' "
                f"ELSE REGEXP_REPLACE(TO_CHAR({col}), '^(-?)\\.', '\\10.') END"
            )
        case CanonicalType.BOOLEAN:
            return f"CASE WHEN {col} THEN '1' WHEN NOT {col} THEN '0' END"
        case CanonicalType.TEXT:
            return f"TO_CHAR({col})"
        case CanonicalType.CHAR:
            return f"RTRIM(TO_CHAR({col}), ' ')"
        case CanonicalType.DATE:
            return f"TO_CHAR({col}, 'YYYY-MM-DD')"
        case CanonicalType.BINARY:
            return f"LOWER(RAWTOHEX({col}))"
        case CanonicalType.TIMESTAMP | CanonicalType.TIMESTAMPTZ:
            if native == "DATE":
                ts = f"CAST({col} AS TIMESTAMP(0))"
            elif ctype is CanonicalType.TIMESTAMPTZ:
                ts = _utc(native, col)
            else:
                ts = col
            expr = f"TO_CHAR({ts}, 'YYYY-MM-DD\"T\"HH24:MI:SS')"
            if p > 0:
                expr = f"{expr} || '.' || SUBSTR(TO_CHAR({ts}, 'FF9'), 1, {p})"
            return expr
        case _:
            raise ValueError(f"no pushdown rendering for {ctype}")


def _md5(expr: str) -> str:
    return f"LOWER(RAWTOHEX(STANDARD_HASH({expr}, 'MD5')))"


def digest_sql(col: str, rendered: str) -> str:
    """Framed column digest. Rendered values are ASCII, so characters are bytes."""
    return (
        f"CASE WHEN {col} IS NULL THEN '{NULL_DIGEST}' "
        f"ELSE {_md5(f'TO_CHAR(NVL(LENGTH({rendered}), 0)) || CHR(31) || {rendered}')} END"
    )


def combine_sql(digests: Sequence[str]) -> str:
    groups = [
        _md5(" || ".join(digests[i : i + GROUP_SIZE])) for i in range(0, len(digests), GROUP_SIZE)
    ]
    return _md5(" || ".join(groups))


def unsigned64_sql(hex_hash: str) -> str:
    """First 16 hex characters as a NUMBER (exact: NUMBER holds 38 digits)."""
    return f"TO_NUMBER(SUBSTR({hex_hash}, 1, 16), 'xxxxxxxxxxxxxxxx')"


def _pushable_sql(columns: Sequence[tuple[str, CanonicalType]]) -> str | None:
    """Condition true when Oracle can render every value of the row exactly; None when
    every row qualifies."""
    parts = []
    for n, t in columns:
        c = quote(n)
        if t in TEXT_TYPES:
            # ASCIISTR escapes every non-ASCII character (and the backslash), so equality
            # means plain ASCII: already NFC, and one byte per character
            parts.append(f"({c} IS NULL OR (ASCIISTR({c}) = {c} AND LENGTH({c}) <= {MAX_TEXT}))")
        elif t is CanonicalType.DECIMAL:
            parts.append(f"({c} IS NULL OR INSTR(TO_CHAR({c}), 'E') = 0)")
        elif t is CanonicalType.BINARY:
            parts.append(f"({c} IS NULL OR LENGTH(RAWTOHEX({c})) <= {2 * MAX_RAW})")
    return " AND ".join(parts) if parts else None


def _excluding(predicate: str | None) -> str | None:
    """Keep the rows a row ignore rule's predicate does not match; a NULL (unknown)
    result keeps the row too. The predicate comes from the project file (config refuses
    statement separators and comments) and runs in a read only transaction."""
    return f"CASE WHEN ({predicate}) THEN 1 ELSE 0 END = 0" if predicate else None


def _json_value(value: Any) -> Any:
    """oracledb decodes JSON numbers as Decimal; json.loads would give int or float."""
    if isinstance(value, dict):
        return {k: _json_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_value(v) for v in value]
    if isinstance(value, decimal.Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    return value


def prepare(value: Any, ctype: CanonicalType) -> Any:
    """Turn an oracledb value into what the reference renderer expects."""
    if value is None:
        return None
    if ctype is CanonicalType.TIMESTAMPTZ and isinstance(value, dt.datetime):
        return value.replace(tzinfo=dt.UTC)  # selected in UTC (see _select_sql)
    if ctype is CanonicalType.JSON and isinstance(value, (dict, list)):
        return _json_value(value)
    return value


def _output_type_handler(cursor: Any, metadata: Any) -> Any:
    """Exact numbers as Decimal (never float), LOBs as values rather than locators."""
    match metadata.type_code:
        case oracledb.DB_TYPE_NUMBER:
            return cursor.var(decimal.Decimal, arraysize=cursor.arraysize)
        case oracledb.DB_TYPE_CLOB | oracledb.DB_TYPE_NCLOB:
            return cursor.var(oracledb.DB_TYPE_LONG, arraysize=cursor.arraysize)
        case oracledb.DB_TYPE_BLOB:
            return cursor.var(oracledb.DB_TYPE_LONG_RAW, arraysize=cursor.arraysize)
    return None


def _ssl_args(sslmode: str, sslrootcert: str | None) -> dict[str, Any]:
    """Oracle TLS (TCPS) settings. Note that TCPS usually listens on its own port."""
    match sslmode:
        case "disable":
            return {"protocol": "tcp"}
        case "require" | "prefer":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return {"protocol": "tcps", "ssl_context": ctx, "ssl_server_dn_match": False}
        case "verify-ca" | "verify-full":
            ctx = ssl.create_default_context(cafile=sslrootcert)
            full = sslmode == "verify-full"
            ctx.check_hostname = full
            return {"protocol": "tcps", "ssl_context": ctx, "ssl_server_dn_match": full}
    raise ConfigError(f"sslmode {sslmode!r} is not one of disable, require, verify-ca, verify-full")


class OracleAdapter(Adapter):
    engine = "oracle"
    product = "Oracle Database"
    minimum_version = (19,)
    minimum_shown = "Oracle Database 19c"
    hash_probe = "SELECT STANDARD_HASH('liftproof', 'MD5') FROM DUAL"
    supports_row_filters = True
    supports_sampling = True
    supports_workers = True

    def __init__(
        self,
        *,
        host: str,
        port: int = 1521,
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
        params = oracledb.ConnectParams(
            host=host,
            port=port,
            service_name=database,  # the service name, for example ORCLPDB1
            user=user,
            password=password,
            tcp_connect_timeout=connect_timeout,
            program="liftproof",
            **_ssl_args(sslmode, sslrootcert),
        )
        try:
            self.conn = oracledb.connect(params=params)
        except oracledb.Error as exc:
            raise ConfigError(
                f"cannot connect to Oracle at {host}:{port}/{database}: {exc}"
            ) from exc
        self.conn = sqllog.wrap(self.conn, self.engine)
        self.conn.outputtypehandler = _output_type_handler
        if statement_timeout_ms:
            self.conn.call_timeout = int(statement_timeout_ms)
        self.read_only = read_only
        self.pacer = Pacer(rows_per_second, pause_ms)
        with self.conn.cursor() as cur:
            for name, value in SESSION.items():
                cur.execute(f"ALTER SESSION SET {name} = {value}")
            if rows_per_second:  # one core: the cap is per connection
                cur.execute("ALTER SESSION DISABLE PARALLEL QUERY")
        self.require_version(self.conn.version)
        self._settings = {k: v.strip("'") for k, v in SESSION.items()}
        self._settings["call_timeout_ms"] = str(statement_timeout_ms)
        # Queries read the version current when they started and take no row or table
        # lock, so no writer makes one wait: lock_timeout_ms has nothing to set.
        self._settings["lock_timeout"] = "not applicable: Oracle queries take no locks"
        self.lock_timeout_ms = "not applicable"
        if rows_per_second:
            self._settings["parallel_query"] = "disabled"
        self._settings.update(rows_per_second=str(rows_per_second), pause_ms=str(pause_ms))
        # Oracle has no read only session. The adapter only ever reads, a snapshot is a
        # READ ONLY transaction, and doctor checks the login holds no write privilege.
        self._settings["snapshot"] = "SET TRANSACTION READ ONLY"
        self._natives: dict[TableRef, dict[str, str]] = {}
        self._in_snapshot = False
        self._flashback = False

    def close(self) -> None:
        try:
            self.conn.rollback()
            self.conn.close()
        except oracledb.Error:
            pass

    def session_settings(self) -> dict[str, str]:
        return dict(self._settings, version=self.version)

    def _query(self, q: str, args: Any = None) -> list[tuple[Any, ...]]:
        with self.conn.cursor() as cur:
            cur.execute(q, args or [])
            return list(cur.fetchall())

    def excluding(self, predicate: str) -> str:
        return _excluding(predicate) or ""

    def _rows(self, q: str, args: Sequence[Any]) -> list[tuple[Any, ...]]:
        return self._query(q.format(*[f":{i + 1}" for i in range(len(args))]), list(args))

    def current_position(self) -> dict[str, Any] | None:
        (at,) = self._query("SELECT SYS_EXTRACT_UTC(SYSTIMESTAMP) FROM DUAL")[0]
        return {**self._scn(), "taken_at": at.replace(tzinfo=dt.UTC).isoformat()}

    def _scn(self) -> dict[str, Any]:
        """The SCN now; it needs SELECT on V$DATABASE or EXECUTE on DBMS_FLASHBACK, and is
        recorded as unknown without either."""
        for q in (
            "SELECT TO_CHAR(CURRENT_SCN) FROM V$DATABASE",
            "SELECT TO_CHAR(DBMS_FLASHBACK.GET_SYSTEM_CHANGE_NUMBER) FROM DUAL",
        ):
            try:
                return {"type": "scn", "position": self._query(q)[0][0]}
            except oracledb.Error:
                continue
        return {"type": "none", "position": None}

    # snapshot -----------------------------------------------------------------
    def begin_snapshot(self) -> dict[str, Any]:
        """One read only transaction: Oracle answers every query in it as of the moment
        it began (transaction level read consistency)."""
        self.conn.rollback()
        with self.conn.cursor() as cur:
            cur.execute("SET TRANSACTION READ ONLY")
            cur.execute("SELECT SYS_EXTRACT_UTC(SYSTIMESTAMP) FROM DUAL")
            (at,) = cur.fetchone()
        self._in_snapshot = True
        # The SCN is read just after the transaction began, so it can trail the snapshot
        # by the changes committed in between.
        position = self._scn()
        replica = False
        try:
            replica = self._query("SELECT DATABASE_ROLE FROM V$DATABASE")[0][0] != "PRIMARY"
        except oracledb.Error:
            pass
        return {
            **position,
            "exact": False,
            "replica": replica,
            "taken_at": at.replace(tzinfo=dt.UTC).isoformat(),
        }

    def end_snapshot(self) -> None:
        if self._flashback:
            with self.conn.cursor() as cur:
                cur.execute("BEGIN DBMS_FLASHBACK.DISABLE; END;")
            self._flashback = False
        if self._in_snapshot:
            self.conn.rollback()
            self._in_snapshot = False

    def _flashback_to(self, scn: str) -> None:
        """Every query on this session from now on reads the database as of the SCN
        (session flashback). Needs EXECUTE on DBMS_FLASHBACK, and undo retention that
        still holds the SCN, as a long READ ONLY transaction does."""
        with self.conn.cursor() as cur:
            cur.execute("BEGIN DBMS_FLASHBACK.ENABLE_AT_SYSTEM_CHANGE_NUMBER(:1); END;", [int(scn)])
        self._flashback = True
        self._in_snapshot = True

    def shares_snapshot(self, position: dict[str, Any]) -> bool:
        """With the snapshot's SCN, this session and every fork read the database as of
        that one SCN, which also makes the recorded position exact. Without the SCN or
        DBMS_FLASHBACK the READ ONLY transaction stays, and the baseline is taken on one
        connection."""
        if position.get("type") != "scn" or not position.get("position"):
            return False
        self.conn.rollback()  # flashback is enabled outside a transaction
        try:
            self._flashback_to(position["position"])
        except oracledb.Error:
            with self.conn.cursor() as cur:
                cur.execute("SET TRANSACTION READ ONLY")
            return False
        position["exact"] = True
        self._settings["snapshot"] = "DBMS_FLASHBACK at the recorded SCN"
        return True

    def fork(self, snapshot: dict[str, Any] | None = None) -> OracleAdapter:
        other = OracleAdapter(**self._kwargs)
        if snapshot is not None:
            other._flashback_to(snapshot["position"])
        return other

    # catalogue ----------------------------------------------------------------
    def list_tables(self, schemas: Sequence[str]) -> list[TableRef]:
        if not schemas:
            return []
        names = list(dict.fromkeys([*schemas, *(s.upper() for s in schemas)]))
        marks = ", ".join(f":{i + 1}" for i in range(len(names)))
        rows = self._query(
            "SELECT t.OWNER, t.TABLE_NAME FROM ALL_TABLES t "
            f"WHERE t.OWNER IN ({marks}) AND t.NESTED = 'NO' AND t.SECONDARY = 'N' "
            "AND t.TEMPORARY = 'N' AND t.DROPPED = 'NO' AND t.TABLE_NAME NOT LIKE 'MLOG$%' "
            "AND NOT EXISTS (SELECT 1 FROM ALL_MVIEWS m "
            "WHERE m.OWNER = t.OWNER AND m.CONTAINER_NAME = t.TABLE_NAME) "
            "ORDER BY 1, 2",
            names,
        )
        return [TableRef(s, n) for s, n in rows]

    def describe(self, table: TableRef) -> TableSchema:
        rows = self._query(
            "SELECT COLUMN_NAME, DATA_TYPE, CHAR_LENGTH, DATA_LENGTH, DATA_PRECISION, "
            "DATA_SCALE FROM ALL_TAB_COLUMNS WHERE OWNER = :1 AND TABLE_NAME = :2 "
            "ORDER BY COLUMN_ID",
            [table.schema, table.name],
        )
        if not rows:
            raise ConfigError(f"table {table} not found")
        cols = []
        natives = {}
        for name, data_type, char_len, data_len, precision, scale in rows:
            precision = int(precision) if precision is not None else None
            scale = int(scale) if scale is not None else None
            length = int(char_len or 0) or int(data_len or 0) or None
            data_type = str(data_type)
            natives[name] = data_type.upper()
            cols.append(
                Column(
                    name,
                    native_name(data_type, length, precision, scale),
                    canonical_type(data_type, precision, scale),
                    fixed_width=data_type.upper() in ("CHAR", "NCHAR"),
                )
            )
        self._natives[table] = natives
        pk = [
            r[0]
            for r in self._query(
                "SELECT cc.COLUMN_NAME FROM ALL_CONSTRAINTS c JOIN ALL_CONS_COLUMNS cc "
                "ON cc.OWNER = c.OWNER AND cc.CONSTRAINT_NAME = c.CONSTRAINT_NAME "
                "WHERE c.OWNER = :1 AND c.TABLE_NAME = :2 AND c.CONSTRAINT_TYPE = 'P' "
                "ORDER BY cc.POSITION",
                [table.schema, table.name],
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
        return int(self._query(f"SELECT COUNT(*) FROM {self._ident(table)}")[0][0])

    # hashing ------------------------------------------------------------------
    def _pushdown(self, plan: HashPlan) -> bool:
        natives = self._native(plan.table)
        return all(
            ctype in PUSHDOWN_TYPES and natives.get(n, "") not in LOB_TYPES
            for n, ctype in plan.columns
        )

    def _render(self, plan: HashPlan, name: str, ctype: CanonicalType) -> str:
        native = self._native(plan.table).get(name, "")
        return render_sql(quote(name), ctype, plan.precision, native)

    def _key_sql(self, plan: HashPlan) -> list[str]:
        types = dict(plan.columns)
        return [self._render(plan, k, types[k]) for k in plan.key_columns]

    def _hash_query(self, plan: HashPlan, where: str | None) -> str:
        digests = [digest_sql(quote(n), self._render(plan, n, t)) for n, t in plan.columns]
        row = combine_sql(digests)
        key = combine_sql([digests[i] for i in plan.key_positions]) if plan.key_columns else row
        keys = "".join(f", {e} AS k{i}" for i, e in enumerate(self._key_sql(plan)))
        q = f"SELECT {row} AS rh, {key} AS kh{keys} FROM {self._ident(plan.table)}"
        where = all_of(where, _excluding(plan.filter))
        return q + (f" WHERE {where}" if where else "")

    def bucket_aggregates(self, plan: HashPlan) -> dict[int, BucketAggregate]:
        if not self._pushdown(plan):
            return self._bucket_aggregates_fallback(plan)
        pushable = _pushable_sql(plan.columns)
        n = int(plan.buckets)
        sample = "" if plan.sample is None else f" WHERE {in_list('b', plan.sample, IN_LIST)}"
        q = (
            f"SELECT TO_CHAR(b), COUNT(*), TO_CHAR(SUM(v)) FROM ("
            f"SELECT MOD({unsigned64_sql('kh')}, {n}) AS b, {unsigned64_sql('rh')} AS v "
            f"FROM ({self._hash_query(plan, pushable)})){sample} GROUP BY b"
        )
        out = {int(b): BucketAggregate(int(c), int(t)) for b, c, t in self._query(q)}
        if pushable:  # another read of the table (spec 9.15)
            self.pacer.again()
            self._bucket_aggregates_fallback(plan, where=f"NOT ({pushable})", into=out)
        return out

    def _select_sql(self, plan: HashPlan) -> str:
        natives = self._native(plan.table)
        cols = []
        for n, t in plan.columns:
            c = quote(n)
            if t is CanonicalType.TIMESTAMPTZ:
                c = _utc(natives.get(n, ""), c)  # oracledb drops the zone: read it as UTC
            elif natives.get(n) == "XMLTYPE":
                # as text, unindented: binary XML storage pretty prints by default
                c = f"XMLSERIALIZE(CONTENT {c} AS CLOB NO INDENT)"
            cols.append(c)
        return ", ".join(cols)

    def _stream(self, plan: HashPlan, where: str | None = None) -> Iterator[list[Any]]:
        where = all_of(where, _excluding(plan.filter))
        q = f"SELECT {self._select_sql(plan)} FROM {self._ident(plan.table)}" + (
            f" WHERE {where}" if where else ""
        )
        types = [t for _, t in plan.columns]
        with self.conn.cursor() as cur:
            cur.arraysize = fetch_batch(plan, 1000)
            cur.execute(q)
            for row in self.pacer.each(cur):
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
        pushable = _pushable_sql(plan.columns)
        bucket = f"MOD({unsigned64_sql('kh')}, {int(plan.buckets)})"
        q = (
            f"SELECT * FROM ({self._hash_query(plan, pushable)}) "
            f"WHERE {in_list(bucket, sorted(wanted), IN_LIST)}"
        )
        rows = [(tuple(r[2:]), r[0]) for r in self._query(q)]
        if pushable:  # another read of the table (spec 9.15)
            self.pacer.again()
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
        out: dict[tuple[Any, ...], list[Any]] = {}
        for start in range(0, len(keys), IN_LIST):
            chunk = keys[start : start + IN_LIST]
            tuples = ", ".join(
                "(" + ", ".join(f":{i * nk + j + 1}" for j in range(nk)) + ")"
                for i in range(len(chunk))
            )
            q = (
                f"SELECT {', '.join(key_exprs)}, {self._select_sql(plan)} "
                f"FROM {self._ident(plan.table)} WHERE ({', '.join(key_exprs)}) IN ({tuples})"
            )
            args = [v for k in chunk for v in k]
            for r in self._query(q, args):
                out[tuple(r[:nk])] = [prepare(v, t) for v, t in zip(r[nk:], types, strict=True)]
        return out

    def float_stats(self, table: TableRef, column: str, where: str | None = None) -> FloatStats:
        c = quote(column)
        t = self._ident(table) + (f" WHERE {_excluding(where)}" if where else "")
        if self._native(table).get(column, "").startswith("BINARY_"):
            finite = f"{c} IS NOT NAN AND {c} IS NOT INFINITE"
            n, nn, lo, hi, total, nan, inf = self._query(
                f"SELECT COUNT(*), COUNT({c}), MIN(CASE WHEN {finite} THEN {c} END), "
                f"MAX(CASE WHEN {finite} THEN {c} END), "
                f"SUM(CASE WHEN {finite} THEN TO_NUMBER({c}) END), "
                f"COUNT(CASE WHEN {c} IS NAN THEN 1 END), "
                f"COUNT(CASE WHEN {c} IS INFINITE THEN 1 END) FROM {t}"
            )[0]
        else:  # FLOAT is a NUMBER: no NaN, no infinity
            n, nn, lo, hi, total = self._query(
                f"SELECT COUNT(*), COUNT({c}), MIN({c}), MAX({c}), SUM({c}) FROM {t}"
            )[0]
            nan = inf = 0
        return FloatStats(
            int(n),
            int(nn),
            float(lo) if lo is not None else None,
            float(hi) if hi is not None else None,
            float(total) if total is not None else None,
            int(nan),
            int(inf),
        )

    # doctor -------------------------------------------------------------------
    def verify_read_only(self) -> bool:
        """True when the login can change no table. Reads the dictionary only; never
        attempts a write against the source. Covers system privileges and table grants,
        whether direct or through an enabled role, and tables the login owns."""
        writes = "('INSERT', 'UPDATE', 'DELETE', 'ALTER')"
        any_writes = (
            "('INSERT ANY TABLE', 'UPDATE ANY TABLE', 'DELETE ANY TABLE', 'DROP ANY TABLE', "
            "'ALTER ANY TABLE', 'CREATE ANY TABLE', 'SYSDBA', 'SYSOPER')"
        )
        # Oracle's own schemas grant some of their tables to built in roles
        ours = "OWNER NOT IN (SELECT USERNAME FROM ALL_USERS WHERE ORACLE_MAINTAINED = 'Y')"
        q = (
            "SELECT "
            f"(SELECT COUNT(*) FROM SESSION_PRIVS WHERE PRIVILEGE IN {any_writes}) + "
            f"(SELECT COUNT(*) FROM USER_TAB_PRIVS_RECD WHERE PRIVILEGE IN {writes} "
            f" AND {ours}) + "
            f"(SELECT COUNT(*) FROM ROLE_TAB_PRIVS WHERE PRIVILEGE IN {writes} AND {ours} "
            " AND ROLE IN (SELECT ROLE FROM SESSION_ROLES)) + "
            "(SELECT COUNT(*) FROM USER_TABLES) FROM DUAL"
        )
        return int(self._query(q)[0][0]) == 0
