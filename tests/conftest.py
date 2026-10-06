"""Shared fixtures.

PostgreSQL tests need a server. Set LIFTPROOF_TEST_PG_HOST / _PORT / _USER (CI uses a
service container); tests marked postgres are skipped when none is reachable.
"""

from __future__ import annotations

import os
import uuid

import psycopg
import pytest

from liftproof.adapters.postgres import PostgresAdapter

PG = {
    "host": os.environ.get("LIFTPROOF_TEST_PG_HOST", "/tmp"),
    "port": int(os.environ.get("LIFTPROOF_TEST_PG_PORT", "55432")),
    "user": os.environ.get("LIFTPROOF_TEST_PG_USER", "postgres"),
    "password": os.environ.get("LIFTPROOF_TEST_PG_PASSWORD") or None,
}


def _admin():
    return psycopg.connect(
        host=PG["host"], port=PG["port"], user=PG["user"], password=PG["password"],
        dbname="postgres", autocommit=True, connect_timeout=3,
    )


@pytest.fixture(scope="session")
def pg_available():
    try:
        _admin().close()
    except psycopg.OperationalError:
        pytest.skip("no PostgreSQL server for tests")


@pytest.fixture
def make_db(pg_available):
    """Factory creating throwaway databases; returns (dbname, raw connection)."""
    created: list[str] = []
    conns: list[psycopg.Connection] = []

    def factory(prefix: str = "t"):
        name = f"liftproof_{prefix}_{uuid.uuid4().hex[:8]}"
        with _admin() as c:
            c.execute(f'CREATE DATABASE "{name}" ENCODING UTF8 TEMPLATE template0')
        created.append(name)
        conn = psycopg.connect(
            host=PG["host"], port=PG["port"], user=PG["user"], password=PG["password"],
            dbname=name, autocommit=True,
        )
        conns.append(conn)
        return name, conn

    yield factory
    for c in conns:
        c.close()
    with _admin() as c:
        for name in created:
            c.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


@pytest.fixture
def adapter_for():
    opened: list[PostgresAdapter] = []

    def factory(dbname: str, read_only: bool = True) -> PostgresAdapter:
        a = PostgresAdapter(
            host=PG["host"], port=PG["port"], database=dbname, user=PG["user"],
            password=PG["password"], sslmode="disable", read_only=read_only,
        )
        opened.append(a)
        return a

    yield factory
    for a in opened:
        a.close()


# ------------------------------------------------------------------------ MySQL
MY = {
    "host": os.environ.get("LIFTPROOF_TEST_MYSQL_HOST", "127.0.0.1"),
    "port": int(os.environ.get("LIFTPROOF_TEST_MYSQL_PORT", "33306")),
    "user": os.environ.get("LIFTPROOF_TEST_MYSQL_USER", "root"),
    "password": os.environ.get("LIFTPROOF_TEST_MYSQL_PASSWORD", "ci-only-local-service"),
}


def _my_connect(database: str | None = None):
    import pymysql

    return pymysql.connect(
        host=MY["host"], port=MY["port"], user=MY["user"], password=MY["password"],
        database=database, charset="utf8mb4", autocommit=True, connect_timeout=3,
    )


@pytest.fixture(scope="session")
def mysql_available():
    import pymysql

    try:
        _my_connect().close()
    except pymysql.err.MySQLError:
        pytest.skip("no MySQL server for tests")


@pytest.fixture
def make_mysql_db(mysql_available):
    """Factory creating throwaway MySQL databases; returns (dbname, raw cursor).

    The raw session runs with an empty sql_mode so tests can store zero dates.
    """
    created: list[str] = []
    conns = []

    def factory(prefix: str = "t"):
        name = f"liftproof_{prefix}_{uuid.uuid4().hex[:8]}"
        with _my_connect() as c, c.cursor() as cur:
            cur.execute(f"CREATE DATABASE `{name}` CHARACTER SET utf8mb4")
        created.append(name)
        conn = _my_connect(name)
        conns.append(conn)
        cur = conn.cursor()
        cur.execute("SET SESSION sql_mode = ''")
        cur.execute("SET SESSION time_zone = '+00:00'")
        return name, cur

    yield factory
    for c in conns:
        c.close()
    with _my_connect() as c, c.cursor() as cur:
        for name in created:
            cur.execute(f"DROP DATABASE IF EXISTS `{name}`")


@pytest.fixture
def mysql_adapter_for():
    from liftproof.adapters.mysql import MySQLAdapter

    opened: list[MySQLAdapter] = []

    def factory(dbname: str, read_only: bool = True) -> MySQLAdapter:
        a = MySQLAdapter(
            host=MY["host"], port=MY["port"], database=dbname, user=MY["user"],
            password=MY["password"], sslmode="disable", read_only=read_only,
        )
        opened.append(a)
        return a

    yield factory
    for a in opened:
        a.close()


# Oracle ---------------------------------------------------------------------------------
ORA = {
    "host": os.environ.get("LIFTPROOF_TEST_ORACLE_HOST", "127.0.0.1"),
    "port": int(os.environ.get("LIFTPROOF_TEST_ORACLE_PORT", "1521")),
    "service": os.environ.get("LIFTPROOF_TEST_ORACLE_SERVICE", "FREEPDB1"),
    "user": os.environ.get("LIFTPROOF_TEST_ORACLE_USER", "system"),
    "password": os.environ.get("LIFTPROOF_TEST_ORACLE_PASSWORD", "ci-only-local-service"),
}


def _ora_connect(user: str | None = None, password: str | None = None):
    import oracledb

    return oracledb.connect(
        user=user or ORA["user"],
        password=password or ORA["password"],
        host=ORA["host"],
        port=ORA["port"],
        service_name=ORA["service"],
        tcp_connect_timeout=3,
    )


@pytest.fixture(scope="session")
def oracle_available():
    import oracledb

    try:
        _ora_connect().close()
    except oracledb.Error:
        pytest.skip("no Oracle server for tests")


@pytest.fixture
def make_oracle_db(oracle_available):
    """Factory creating throwaway Oracle schemas (users); returns (schema, raw cursor).

    The raw session runs in UTC and autocommits, like the other engines' fixtures.
    """
    created: list[str] = []
    conns = []

    def factory(prefix: str = "t"):
        name = f"LP_{prefix}_{uuid.uuid4().hex[:8]}".upper()
        with _ora_connect() as c, c.cursor() as cur:
            cur.execute(f'CREATE USER "{name}" NO AUTHENTICATION QUOTA UNLIMITED ON USERS')
        created.append(name)
        conn = _ora_connect()
        conn.autocommit = True
        conns.append(conn)
        cur = conn.cursor()
        cur.execute(f'ALTER SESSION SET CURRENT_SCHEMA = "{name}"')
        cur.execute("ALTER SESSION SET TIME_ZONE = '+00:00'")
        return name, cur

    yield factory
    for c in conns:
        c.close()
    with _ora_connect() as c, c.cursor() as cur:
        for name in created:
            cur.execute(f'DROP USER "{name}" CASCADE')


@pytest.fixture
def oracle_adapter_for():
    from liftproof.adapters.oracle import OracleAdapter

    opened: list[OracleAdapter] = []

    def factory(read_only: bool = True, **kw) -> OracleAdapter:
        a = OracleAdapter(
            host=ORA["host"], port=ORA["port"], database=ORA["service"],
            user=kw.pop("user", ORA["user"]), password=kw.pop("password", ORA["password"]),
            sslmode="disable", read_only=read_only, **kw,
        )
        opened.append(a)
        return a

    yield factory
    for a in opened:
        a.close()


# SQL Server -----------------------------------------------------------------------------
MSSQL = {
    "host": os.environ.get("LIFTPROOF_TEST_MSSQL_HOST", "127.0.0.1"),
    "port": int(os.environ.get("LIFTPROOF_TEST_MSSQL_PORT", "1433")),
    "user": os.environ.get("LIFTPROOF_TEST_MSSQL_USER", "sa"),
    "password": os.environ.get("LIFTPROOF_TEST_MSSQL_PASSWORD", "Ci-only-local-service1"),
}


def _ms_connect(database: str = "master", user: str | None = None, password: str | None = None):
    import pytds

    return pytds.connect(
        dsn=MSSQL["host"], port=MSSQL["port"], database=database,
        user=user or MSSQL["user"], password=password or MSSQL["password"],
        login_timeout=3, autocommit=True, disable_connect_retry=True,
    )  # fmt: skip


@pytest.fixture(scope="session")
def sqlserver_available():
    import pytds

    try:
        _ms_connect().close()
    except (pytds.Error, OSError):
        pytest.skip("no SQL Server for tests")


@pytest.fixture
def make_sqlserver_db(sqlserver_available):
    """Factory creating throwaway SQL Server databases (snapshot isolation on, unless
    snapshot=False); returns (database, raw cursor). Tables go in dbo."""
    created: list[str] = []
    conns = []

    def factory(prefix: str = "t", snapshot: bool = True):
        name = f"lp_{prefix}_{uuid.uuid4().hex[:8]}"
        with _ms_connect() as c, c.cursor() as cur:
            cur.execute(f"CREATE DATABASE [{name}]")
            if snapshot:
                cur.execute(f"ALTER DATABASE [{name}] SET ALLOW_SNAPSHOT_ISOLATION ON")
        created.append(name)
        conn = _ms_connect(name)
        conns.append(conn)
        return name, conn.cursor()

    yield factory
    for c in conns:
        c.close()
    with _ms_connect() as c, c.cursor() as cur:
        for name in created:
            cur.execute(f"ALTER DATABASE [{name}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE")
            cur.execute(f"DROP DATABASE [{name}]")


@pytest.fixture
def sqlserver_adapter_for():
    from liftproof.adapters.sqlserver import SQLServerAdapter

    opened: list[SQLServerAdapter] = []

    def factory(database: str, **kw) -> SQLServerAdapter:
        a = SQLServerAdapter(
            host=MSSQL["host"], port=MSSQL["port"], database=database,
            user=kw.pop("user", MSSQL["user"]), password=kw.pop("password", MSSQL["password"]),
            sslmode="disable", **kw,
        )  # fmt: skip
        opened.append(a)
        return a

    yield factory
    for a in opened:
        a.close()
