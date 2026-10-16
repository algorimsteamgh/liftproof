"""MySQL 8's default login, caching_sha2_password, through the adapter.

A user's first login after FLUSH PRIVILEGES takes the full exchange rather than the cached
fast path: over TLS the password is sent as is, without TLS it is RSA encrypted with the
server's public key. Both must connect.
"""

import uuid

import pytest

from liftproof.adapters.mysql import MySQLAdapter
from tests.conftest import MY, _my_connect

pytestmark = pytest.mark.mysql


@pytest.fixture
def sha2_user(make_mysql_db):
    dbname, _ = make_mysql_db("auth")
    user, password = f"lp_{uuid.uuid4().hex[:8]}", "Auth-ci-only-1"
    with _my_connect() as c, c.cursor() as cur:
        cur.execute(f"CREATE USER '{user}'@'%' IDENTIFIED WITH caching_sha2_password BY "
                    f"'{password}'")  # fmt: skip
        cur.execute(f"GRANT SELECT ON `{dbname}`.* TO '{user}'@'%'")
    yield dbname, user, password
    with _my_connect() as c, c.cursor() as cur:
        cur.execute(f"DROP USER IF EXISTS '{user}'@'%'")


@pytest.mark.parametrize("sslmode", ["disable", "require"])
def test_a_caching_sha2_login_takes_the_full_exchange(sha2_user, sslmode):
    dbname, user, password = sha2_user
    with _my_connect() as c, c.cursor() as cur:
        cur.execute("FLUSH PRIVILEGES")
    for _ in range(2):  # the full exchange, then the cached fast path
        a = MySQLAdapter(host=MY["host"], port=MY["port"], database=dbname, user=user,
                         password=password, sslmode=sslmode)  # fmt: skip
        try:
            with a.conn.cursor() as cur:
                cur.execute("SELECT CURRENT_USER()")
                assert cur.fetchone()[0] == f"{user}@%"
        finally:
            a.close()
