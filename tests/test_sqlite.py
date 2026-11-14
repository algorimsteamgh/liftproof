"""SQLite to PostgreSQL: an application that kept its data in a SQLite file, moved to a
PostgreSQL database (RDS) with real types.

The SQLite copy stores what such applications do: dates as ISO 8601 text and as Unix
milliseconds, booleans as 0 and 1, UUIDs as text, JSON as text, money as REAL and as text.
Loaded into PostgreSQL with proper types, nothing may differ; a value changed in the move
must be reported exactly as between two PostgreSQL databases.
"""

from __future__ import annotations

import datetime as dt
import json
import sqlite3
import uuid
from decimal import Decimal
from pathlib import Path

import pytest
import yaml

from liftproof.adapters.base import TableRef
from liftproof.adapters.sqlite import SQLiteAdapter, prepare
from liftproof.canonical import CanonicalType as T
from liftproof.canonical import RenderError, Verbatim, render
from liftproof.canonical.typemap import DEFAULT_TYPE_MAP, type_keys
from liftproof.config import load_project
from liftproof.errors import ConfigError
from liftproof.findings import FindingWriter, Kind, read_findings
from liftproof.reconcile.baseline import Baseline, take_baseline
from liftproof.reconcile.engine import ReconcileOptions, Reconciler

N = 500
EPOCH = dt.datetime(2026, 3, 1, 9, 30, tzinfo=dt.UTC)

SQLITE_DDL = """
CREATE TABLE users (
  id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE, name TEXT, is_admin INTEGER NOT NULL
  DEFAULT 0, verified BOOLEAN, created_at TEXT DEFAULT CURRENT_TIMESTAMP, last_login INTEGER,
  birthday DATE, public_id TEXT, settings TEXT, balance REAL, credit TEXT
);
CREATE TABLE sessions (
  token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users (id),
  expires_at DATETIME
);
CREATE INDEX sessions_user ON sessions (user_id);
CREATE TABLE _litestream_seq (id INTEGER PRIMARY KEY, seq INTEGER);
"""

PG_DDL = """
CREATE TABLE users (
  id bigint PRIMARY KEY, email text NOT NULL UNIQUE, name text, is_admin boolean NOT NULL
  DEFAULT false, verified boolean, created_at timestamptz, last_login timestamptz,
  birthday date, public_id uuid, settings jsonb, balance double precision, credit numeric(12,2)
);
CREATE TABLE sessions (
  token text PRIMARY KEY, user_id bigint NOT NULL REFERENCES users (id),
  expires_at timestamp
);
CREATE INDEX sessions_user ON sessions (user_id);
"""


def _users():
    for i in range(1, N + 1):
        at = EPOCH + dt.timedelta(minutes=i, milliseconds=i)
        yield {
            "id": i,
            "email": f"user{i}@example.test",
            "name": "José Ñúñez" if i % 7 == 0 else (None if i % 11 == 0 else f"User {i}"),
            "is_admin": i % 50 == 0,
            "verified": None if i % 13 == 0 else i % 2 == 0,
            "created_at": at,
            "last_login": None if i % 9 == 0 else at + dt.timedelta(days=1),
            "birthday": dt.date(1990, 1, 1) + dt.timedelta(days=i * 17),
            "public_id": uuid.UUID(int=i * 7919),
            "settings": {"theme": "dark" if i % 2 else "light", "n": i},
            "balance": i * 0.25,
            "credit": Decimal(i) + Decimal("0.10"),
        }


def _sqlite_row(u):
    # what a JavaScript or Python application writes into SQLite
    created = u["created_at"]
    return (
        u["id"], u["email"], u["name"], 1 if u["is_admin"] else 0,
        None if u["verified"] is None else int(u["verified"]),
        # SQLite's own format for some rows, JavaScript's toISOString for the rest
        created.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] if u["id"] % 2
        else created.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        None if u["last_login"] is None else int(u["last_login"].timestamp() * 1000),
        u["birthday"].isoformat(), str(u["public_id"]).upper() if u["id"] % 3 == 0
        else str(u["public_id"]),
        json.dumps(u["settings"], indent=1 if u["id"] % 2 else None), u["balance"],
        f"{u['credit']:.2f}",
    )  # fmt: skip


@pytest.fixture
def app_db(tmp_path):
    path = tmp_path / "app.db"
    c = sqlite3.connect(path)
    c.executescript(SQLITE_DDL)
    users = list(_users())
    c.executemany(f"INSERT INTO users VALUES ({', '.join('?' * 12)})", map(_sqlite_row, users))
    c.executemany(
        "INSERT INTO sessions VALUES (?, ?, ?)",
        [(f"tok{i}", i, (EPOCH + dt.timedelta(hours=i)).strftime("%Y-%m-%d %H:%M:%S"))
         for i in range(1, 101)],
    )  # fmt: skip
    c.execute("INSERT INTO _litestream_seq VALUES (1, 42)")
    c.commit()
    c.close()
    return path


@pytest.fixture
def moved(app_db, make_db, adapter_for):
    """The same data in PostgreSQL, loaded with real types."""
    pdb, pc = make_db("sqlite")
    pc.execute(PG_DDL)
    with pc.cursor() as cur:
        for u in _users():
            cur.execute(
                f"INSERT INTO users VALUES ({', '.join(['%s'] * 12)})",
                (u["id"], u["email"], u["name"], u["is_admin"], u["verified"],
                 u["created_at"].replace(microsecond=u["created_at"].microsecond // 1000 * 1000),
                 u["last_login"] and u["last_login"].replace(
                     microsecond=u["last_login"].microsecond // 1000 * 1000),
                 u["birthday"], u["public_id"], json.dumps(u["settings"]), u["balance"],
                 u["credit"]),
            )  # fmt: skip
        cur.executemany(
            "INSERT INTO sessions VALUES (%s, %s, %s)",
            [(f"tok{i}", i, (EPOCH + dt.timedelta(hours=i)).replace(tzinfo=None))
             for i in range(1, 101)],
        )  # fmt: skip
    return SQLiteAdapter(path=str(app_db)), adapter_for(pdb), pc


def _run(tmp_path, target, source=None, baseline=None, **opts):
    writer = FindingWriter(tmp_path / "findings", "r-x")
    options = ReconcileOptions(schemas=["main"], schema_map={"main": "public"},
                               rows_per_bucket=100, **opts)  # fmt: skip
    result = Reconciler(target, writer, options, source=source, baseline=baseline).run()
    writer.close()
    return result, list(read_findings(tmp_path / "findings"))


@pytest.mark.postgres
def test_a_sqlite_app_moved_to_postgresql_matches(tmp_path, moved):
    lite, pg, _ = moved
    result, findings = _run(tmp_path, pg, source=lite)
    assert {t.table: t.status for t in result.tables} == {
        "main.sessions": "matched", "main.users": "matched",
    }  # fmt: skip
    users = next(t for t in result.tables if t.table == "main.users")
    assert not users.partial and users.approximate_columns == ["balance"]
    assert not [f for f in findings if f.kind in (Kind.DIFFERENCE, Kind.NOT_CHECKED)], findings
    adopted = {f.object: f.detail["adopted_types"] for f in findings if "adopted_types" in f.detail}
    assert sorted((o["column"], o["native"], o["canonical"]) for o in adopted["main.users"]) == [
        ("created_at", "text", "timestamptz"),
        ("credit", "text", "decimal"),
        ("is_admin", "integer", "boolean"),
        ("last_login", "integer", "timestamptz"),
        ("public_id", "text", "uuid"),
        ("settings", "text", "json"),
    ]
    # Litestream's own table is not application data
    assert "main._litestream_seq" not in {t.table for t in result.tables}


@pytest.mark.postgres
def test_a_value_changed_in_the_move_is_reported(tmp_path, moved):
    lite, pg, pc = moved
    pc.execute("UPDATE users SET created_at = created_at + interval '1 hour' WHERE id = 42")
    pc.execute("UPDATE users SET name = 'Jose Nunez' WHERE id = 77")  # accents lost
    pc.execute("UPDATE users SET is_admin = true WHERE id = 3")
    pc.execute("DELETE FROM sessions WHERE token = 'tok9'")
    result, findings = _run(tmp_path, pg, source=lite)
    users = next(t for t in result.tables if t.table == "main.users")
    sessions = next(t for t in result.tables if t.table == "main.sessions")
    assert (users.status, users.changed_rows) == ("different", 3)
    assert sessions.missing_rows == 1
    changed = {(f.locator, f.column) for f in findings
               if f.kind == Kind.DIFFERENCE and f.summary.startswith("value differs")}  # fmt: skip
    assert changed == {("id = 42", "created_at"), ("id = 77", "name"), ("id = 3", "is_admin")}


@pytest.mark.postgres
def test_baseline_of_the_file_then_validate(tmp_path, app_db, moved):
    """The baseline is taken before the target exists, under SQLite's own types; once the
    target is there the file re-hashes as the target's types, and only that file does."""
    lite, pg, pc = moved
    manifest = tmp_path / "b.json"
    take_baseline(lite, manifest, baseline_id="b1", schemas=["main"], tables=None, ignore=[],
                  business_keys={}, rows_per_bucket=100, precision=6)  # fmt: skip
    b = Baseline.load(manifest)
    assert b.engine == "sqlite" and b.position["type"] == "file"
    assert b.position["position"] == f"sha256:{lite.sha256}" and b.position["exact"] is True
    assert set(b.tables) == {"main.sessions", "main.users"}

    result, _ = _run(tmp_path / "with-file", pg, source=lite, baseline=b)
    assert {t.status for t in result.tables} == {"matched"}
    # without the file, the tables whose types the target settles are not checked
    result, _ = _run(tmp_path / "alone", pg, baseline=b)
    users = next(t for t in result.tables if t.table == "main.users")
    assert users.status == "not_checked" and "live source is needed" in users.reason


def test_the_file_is_read_only_and_named(tmp_path, app_db):
    lite = SQLiteAdapter(path=str(app_db))
    with pytest.raises(sqlite3.OperationalError):
        lite.conn.execute("DELETE FROM users")
    assert lite.verify_read_only() and lite.probe() == "quick_check ok"
    assert lite.list_tables(["main"]) == [TableRef("main", "sessions"), TableRef("main", "users")]
    assert lite.list_tables(["public"]) == []
    schema = lite.describe(TableRef("main", "sessions"))
    assert schema.primary_key == ["token"] and schema.column("token").nullable is False
    [fk] = schema.foreign_keys
    assert (fk.columns, fk.references, fk.referenced_columns) == (
        ("user_id",),
        TableRef("main", "users"),
        ("id",),
    )
    assert [(i.name, i.columns, i.unique) for i in schema.indexes] == [
        ("sessions_user", ("user_id",), False)
    ]
    with pytest.raises(ConfigError, match="not the file named by source.sha256"):
        SQLiteAdapter(path=str(app_db), sha256="0" * 64)
    other = tmp_path / "notes.txt"
    other.write_text("not a database")
    with pytest.raises(ConfigError, match="is not a SQLite database file"):
        SQLiteAdapter(path=str(other))
    with pytest.raises(ConfigError, match="no such file"):
        SQLiteAdapter(path=str(tmp_path / "missing.db"))


def test_a_copy_in_s3_is_downloaded_once(tmp_path, app_db, monkeypatch):
    boto3 = pytest.importorskip("boto3")
    moto = pytest.importorskip("moto")
    monkeypatch.setenv("LIFTPROOF_CACHE", str(tmp_path / "cache"))
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    with moto.mock_aws():
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="lp-bucket")
        s3.upload_file(str(app_db), "lp-bucket", "inputs/app.db")
        a = SQLiteAdapter(path="s3://lp-bucket/inputs/app.db")
        b = SQLiteAdapter(path="s3://lp-bucket/inputs/app.db")
        assert a.local == b.local and a.sha256 == b.sha256
        assert len(list((tmp_path / "cache" / "liftproof-sqlite").glob("*.db"))) == 1
        assert a.row_count(TableRef("main", "users")) == N
        with pytest.raises(ConfigError, match="cannot read it"):
            SQLiteAdapter(path="s3://lp-bucket/inputs/other.db")


@pytest.mark.parametrize(
    ("value", "ctype", "rendered"),
    [
        (1, T.BOOLEAN, "1"), ("false", T.BOOLEAN, "0"), (0, T.BOOLEAN, "0"),
        ("42", T.INTEGER, "42"), (7.0, T.INTEGER, "7"),
        (0.1, T.DECIMAL, "0.1"), ("12.50", T.DECIMAL, "12.5"), (3, T.DECIMAL, "3"),
        ("2026-03-01 09:30:00", T.TIMESTAMPTZ, "2026-03-01T09:30:00.000000"),
        ("2026-03-01T15:00:00+05:30", T.TIMESTAMPTZ, "2026-03-01T09:30:00.000000"),
        ("2026-03-01T09:30:00.123Z", T.TIMESTAMP, "2026-03-01T09:30:00.123000"),
        (1772357400000, T.TIMESTAMPTZ, "2026-03-01T09:30:00.000000"),  # milliseconds
        (1772357400, T.TIMESTAMPTZ, "2026-03-01T09:30:00.000000"),  # seconds
        ("2026-03-01", T.DATE, "2026-03-01"), ("2026-03-01 00:00:00", T.DATE, "2026-03-01"),
        ("2026-03-01 10:00:00", T.DATE, "2026-03-01T10:00:00"),  # differs from every date
        ("09:30", T.TIME, "09:30:00.000000"),
        ("ABCDEF00-0000-0000-0000-000000000001", T.UUID, "abcdef00-0000-0000-0000-000000000001"),
        ('{"b": 1, "a": [1, 2]}', T.JSON, '{"a":[1,2],"b":1}'),
        (b"caf\xc3\xa9", T.TEXT, "café"), (12, T.TEXT, "12"),
        ("ab", T.BINARY, "6162"),
    ],
)  # fmt: skip
def test_stored_values_render_as_their_target_type(value, ctype, rendered):
    assert render(prepare(value, ctype), ctype) == rendered


@pytest.mark.parametrize(
    ("value", "ctype"),
    [("yes please", T.BOOLEAN), (1.5, T.INTEGER), ("12a", T.INTEGER), ("soon", T.TIMESTAMPTZ),
     ("x", T.UUID), ("{", T.JSON), (b"\xff", T.TEXT), ("25:99", T.TIME), (3, T.BINARY)],
)  # fmt: skip
def test_a_value_that_is_not_of_the_type_is_refused(value, ctype):
    with pytest.raises(RenderError):
        prepare(value, ctype)


def test_a_date_with_a_time_of_day_is_verbatim():
    assert prepare("2026-03-01 10:00:00", T.DATE) == Verbatim("2026-03-01T10:00:00")


@pytest.mark.postgres
def test_a_column_that_does_not_parse_is_left_out(tmp_path, app_db, make_db, adapter_for):
    c = sqlite3.connect(app_db)
    c.execute("UPDATE sessions SET expires_at = 'next tuesday' WHERE token = 'tok5'")
    c.commit()
    c.close()
    pdb, pc = make_db("sqlite")
    pc.execute("CREATE TABLE sessions (token text PRIMARY KEY, user_id bigint, expires_at "
               "timestamp)")  # fmt: skip
    with pc.cursor() as cur:
        cur.executemany("INSERT INTO sessions VALUES (%s, %s, %s)",
                        [(f"tok{i}", i, (EPOCH + dt.timedelta(hours=i)).replace(tzinfo=None))
                         for i in range(1, 101)])  # fmt: skip
    result, findings = _run(tmp_path, adapter_for(pdb), source=SQLiteAdapter(path=str(app_db)),
                            tables=["sessions"])  # fmt: skip
    [sessions] = result.tables
    assert sessions.partial and sessions.excluded_columns == ["expires_at"]
    [issue] = [f for f in findings if f.column == "expires_at" and f.kind == Kind.NOT_CHECKED]
    assert "ISO 8601" in issue.summary


def test_the_type_map_types_sqlite_columns_by_affinity():
    assert type_keys("sqlite", "varchar(255)") == ("varchar(255)", "varchar", "affinity text")
    assert type_keys("sqlite", "") == ("", "affinity blob")
    m = DEFAULT_TYPE_MAP
    assert [m.canonical("sqlite", t) for t in
            ("integer", "bigint", "text", "varchar(40)", "", "blob", "real", "double",
             "numeric", "decimal(10,2)", "boolean", "datetime", "date", "json", "uuid")] == [
        T.INTEGER, T.INTEGER, T.TEXT, T.TEXT, T.BINARY, T.BINARY, T.FLOAT, T.FLOAT,
        T.DECIMAL, T.DECIMAL, T.BOOLEAN, T.TIMESTAMP, T.DATE, T.JSON, T.UUID,
    ]  # fmt: skip
    assert m.allows("sqlite", "text", T.TIMESTAMPTZ) and not m.allows("sqlite", "real", T.TEXT)


def test_project_file_takes_a_sqlite_source(tmp_path: Path):
    p = tmp_path / "p.yaml"
    p.write_text(
        "project: app\nsource:\n  engine: sqlite\n  path: s3://bucket/inputs/app.db\n"
        "target:\n  engine: postgresql\n  host: db.example.test\n  database: app\n"
    )
    project = load_project(p)
    assert project.source.is_file and project.source.path == "s3://bucket/inputs/app.db"
    assert project.source.tls_verified and project.source.describe() == (
        "sqlite:s3://bucket/inputs/app.db"
    )
    assert project.database.schemas == ["main"]
    assert project.database.schema_map == {"main": "public"}
    for text, says in [
        ("source:\n  engine: sqlite\n", "source.path is required"),
        ("source:\n  engine: sqlite\n  path: /x.db\n  host: h\n", "host do not apply"),
        ("source:\n  engine: sqlite\n  path: /x.db\n  sha256: abc\n", "64 hexadecimal"),
        ("source:\n  engine: postgresql\n  host: h\n  database: d\n"
         "target:\n  engine: sqlite\n  path: /x.db\n", "can be the source only"),
    ]:  # fmt: skip
        p.write_text("project: app\n" + text)
        with pytest.raises(ConfigError, match=says):
            load_project(p)


# ------------------------------------------------------------------ the CLI
def _cli_project(tmp_path, db_path, pgdb):
    from tests.conftest import PG

    doc = {
        "project": "app",
        "source": {"engine": "sqlite", "path": str(db_path)},
        "target": {"engine": "postgresql", "host": PG["host"], "port": PG["port"],
                   "user": PG["user"], "database": pgdb, "sslmode": "disable",
                   "secret_arn": "arn:aws:secretsmanager:ap-south-1:000000000000:secret:t"},
        "database": {"rows_per_bucket": 100},
    }  # fmt: skip
    path = tmp_path / "app.yaml"
    path.write_text(yaml.safe_dump(doc))
    return path


@pytest.fixture
def cli_secret(monkeypatch):
    from liftproof import cli
    from liftproof.credentials import DbCredentials
    from tests.conftest import PG

    monkeypatch.setattr(cli, "from_secrets_manager",
                        lambda arn: DbCredentials(PG["user"], PG["password"]))  # fmt: skip
    return cli


@pytest.mark.postgres
def test_doctor_baseline_then_validate_from_the_cli(tmp_path, app_db, moved, cli_secret, capsys):
    """The pre-migration baseline of the file, then the comparison with the target: the
    file re-hashes under the target's types; another file is refused as the source."""
    cli = cli_secret
    _, pg, pc = moved
    p = _cli_project(tmp_path, app_db, pg.conn.info.dbname)
    base = ["--project", str(p), "--workdir", str(tmp_path / "work"), "--format", "json"]
    cli.main(["doctor", *base])
    checks = {c["check"]: c for c in json.loads(capsys.readouterr().out)["checks"]}
    # the test server has no TLS; nothing else fails, the file's checks included
    assert [n for n, c in checks.items() if c["result"] != "pass"] == [
        "target TLS verifies the server certificate"
    ]
    assert "quick_check ok" in checks["source database file"]["detail"]
    assert cli.main(["baseline", *base, "--baseline-id", "b1"]) == 0
    capsys.readouterr()
    assert cli.main(["reconcile", *base, "--baseline", "latest", "--run-id", "r1"]) == 0
    assert json.loads(capsys.readouterr().out)["verdict"] == "passed"

    pc.execute("UPDATE users SET email = 'changed@example.test' WHERE id = 5")
    assert cli.main(["reconcile", *base, "--baseline", "latest", "--run-id", "r2"]) == 10
    capsys.readouterr()

    # the file changed after the baseline: it is not used as the source
    c = sqlite3.connect(app_db)
    c.execute("UPDATE users SET name = 'late write' WHERE id = 1")
    c.commit()
    c.close()
    cli.main(["reconcile", *base, "--baseline", "latest", "--run-id", "r3"])
    capsys.readouterr()
    report = json.loads((tmp_path / "work" / "app" / "runs" / "r3" / "report.json").read_text())
    [notice] = [f for f in report["findings"] if "not the one the baseline" in f["summary"]]
    assert notice["detail"]["baseline_file"] != notice["detail"]["source_file"]
