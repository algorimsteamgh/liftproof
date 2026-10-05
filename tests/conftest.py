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
