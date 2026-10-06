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


# ---------------------------------------------------------------------- browser
@pytest.fixture(scope="session")
def browser_available():
    """Playwright's Chromium, or the binary named by LIFTPROOF_CHROMIUM."""
    try:
        from playwright.sync_api import sync_playwright

        from liftproof.web.browser import launch

        with sync_playwright() as p:
            launch(p).close()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"no browser for tests: {str(exc).splitlines()[0]}")
