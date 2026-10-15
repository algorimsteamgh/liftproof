"""CLI behaviour a pipeline relies on: exit codes, reports, and credential rules."""

import argparse
import json
import shutil

import pytest
import yaml

from liftproof import cli
from liftproof.canonical import CANONICAL_REVISION
from liftproof.canonical.typemap import DEFAULT_TYPE_MAP
from liftproof.config import LOCK_TIMEOUT_MS, SOURCE_PAUSE_MS, SOURCE_ROWS_PER_SECOND
from liftproof.credentials import DbCredentials
from liftproof.errors import EXIT_CONFIG, EXIT_DIFFERENCES, EXIT_OK, EXIT_RUN_FAILED
from liftproof.store import LocalStore
from tests.conftest import PG

SCHEMA = """
CREATE TABLE orders (id int PRIMARY KEY, status text, total numeric(10,2));
INSERT INTO orders SELECT g, 'DISPATCHED', g + 0.5 FROM generate_series(1, 2000) g;
CREATE TABLE notes (body text);
INSERT INTO notes SELECT 'n' || g FROM generate_series(1, 10) g;
"""


TEST_SECRET_ARN = "arn:aws:secretsmanager:ap-south-1:000000000000:secret:liftproof/test"


@pytest.fixture(autouse=True)
def test_secret(monkeypatch):
    """Serve the test server's login through the Secrets Manager path the CLI really uses."""

    def fake(arn):
        assert arn == TEST_SECRET_ARN
        return DbCredentials(PG["user"], PG["password"])

    monkeypatch.setattr(cli, "from_secrets_manager", fake)


def _project(tmp_path, src, tgt, **database):
    conn = {"engine": "postgresql", "host": PG["host"], "port": PG["port"], "user": PG["user"],
            "sslmode": "disable", "secret_arn": TEST_SECRET_ARN}
    doc = {"project": "acme", "source": dict(conn, database=src),
           "target": dict(conn, database=tgt), "database": {"rows_per_bucket": 500, **database}}
    path = tmp_path / "acme.yaml"
    path.write_text(yaml.safe_dump(doc))
    return path


@pytest.fixture
def dbs(make_db):
    s, sc = make_db("src")
    t, tc = make_db("tgt")
    sc.execute(SCHEMA)
    tc.execute(SCHEMA)
    return s, t, tc


def run(tmp_path, *argv):
    return cli.main([*argv, "--workdir", str(tmp_path / "work"), "--format", "json"])


@pytest.mark.postgres
def test_clean_run_exits_zero_and_writes_both_reports(tmp_path, dbs, capsys):
    s, t, _ = dbs
    p = _project(tmp_path, s, t)
    assert run(tmp_path, "reconcile", "--project", str(p), "--run-id", "r1") == EXIT_OK
    out = json.loads(capsys.readouterr().out)
    assert out["verdict"] == "passed"
    run_dir = tmp_path / "work" / "acme" / "runs" / "r1"
    report = json.loads((run_dir / "report.json").read_text())
    html = (run_dir / "report.html").read_text()
    assert report["coverage"]["tables_coverage_pct"] == 100.0
    assert "Passed" in html and "<script" not in html


@pytest.mark.postgres
def test_differences_exit_ten_and_json_carries_every_html_finding(tmp_path, dbs, capsys):
    s, t, tc = dbs
    tc.execute("DELETE FROM orders WHERE id <= 10")
    p = _project(tmp_path, s, t)
    assert run(tmp_path, "reconcile", "--project", str(p), "--run-id", "r2") == \
        EXIT_DIFFERENCES
    out = json.loads(capsys.readouterr().out)
    assert out["verdict"] == "failed"
    run_dir = tmp_path / "work" / "acme" / "runs" / "r2"
    report = json.loads((run_dir / "report.json").read_text())
    html = (run_dir / "report.html").read_text()
    for f in report["findings"]:
        if f["kind"] in ("difference", "error", "not_checked", "partial"):
            assert f["summary"].split(";")[0][:30] in html
    assert (run_dir / "findings-00001.jsonl").exists()
    # --fail-on never is the one flag that changes an exit code's meaning
    assert run(tmp_path, "reconcile", "--project", str(p), "--fail-on", "never") == EXIT_OK
    # regenerate a report from stored findings
    assert run(tmp_path, "report", "--project", str(p), "--run", "r2") == EXIT_DIFFERENCES


@pytest.mark.postgres
def test_baseline_then_reconcile_against_it(tmp_path, dbs, capsys):
    s, t, _ = dbs
    p = _project(tmp_path, s, t)
    assert run(tmp_path, "baseline", "--project", str(p), "--baseline-id", "b1") == EXIT_OK
    assert run(tmp_path, "reconcile", "--project", str(p), "--baseline", "latest",
               "--no-source") == EXIT_OK


def test_unreachable_database_is_a_configuration_error(tmp_path):
    p = _project(tmp_path, "nope", "nope")
    doc = yaml.safe_load(p.read_text())
    doc["target"]["host"], doc["target"]["port"] = "127.0.0.1", 1
    p.write_text(yaml.safe_dump(doc))
    assert run(tmp_path, "reconcile", "--project", str(p)) == EXIT_CONFIG


def test_credentials_in_project_file_are_refused(tmp_path, capsys):
    p = _project(tmp_path, "a", "b")
    doc = yaml.safe_load(p.read_text())
    doc["source"]["password"] = "hunter22"
    p.write_text(yaml.safe_dump(doc))
    assert run(tmp_path, "reconcile", "--project", str(p)) == EXIT_CONFIG
    assert "Secrets Manager" in capsys.readouterr().err


def test_credentials_in_environment_are_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("PGPASSWORD", "hunter22")
    p = _project(tmp_path, "a", "b")
    assert run(tmp_path, "reconcile", "--project", str(p)) == EXIT_CONFIG


def test_unreadable_instance_settings_are_a_configuration_error(tmp_path, dbs, capsys,
                                                                monkeypatch):
    """Running on without them would quietly drop the deployment's bucket, key and lock."""

    class Unreadable:
        def read_text(self, encoding):
            raise PermissionError(13, "Permission denied")

        def __str__(self):
            return "/etc/mvt/config.yaml"

    monkeypatch.setattr(cli, "INSTANCE_CONFIG", Unreadable())
    s, t, _ = dbs
    assert run(tmp_path, "reconcile", "--project", str(_project(tmp_path, s, t))) == EXIT_CONFIG
    assert "sudo -u mvt" in capsys.readouterr().err


def test_ignore_rule_without_reason_is_refused(tmp_path):
    p = _project(tmp_path, "a", "b", ignore=[{"table": "orders"}])
    assert run(tmp_path, "reconcile", "--project", str(p)) == EXIT_CONFIG


def test_unhandled_exception_maps_to_two_never_one(tmp_path, monkeypatch):
    def boom(_args):
        raise ZeroDivisionError("bug")

    monkeypatch.setattr(cli, "cmd_version", boom)
    assert cli.main(["version"]) == EXIT_RUN_FAILED


def test_version_reports_sdk(capsys):
    assert cli.main(["version", "--format", "json"]) == EXIT_OK
    info = json.loads(capsys.readouterr().out)
    assert info["canonical_version"] == "1.0" and "botocore" in info
    assert info["canonical_revision"] == CANONICAL_REVISION
    assert info["type_map_version"] == "1.0"


def test_init_writes_template(tmp_path):
    assert cli.main(["init", "demo", "--dir", str(tmp_path)]) == EXIT_OK
    assert "secret_arn" in (tmp_path / "demo.yaml").read_text()


@pytest.fixture
def opened(monkeypatch):
    """The databases each command connects to."""
    seen = []
    real = cli.connect

    def spy(conn):
        seen.append(conn.database)
        return real(conn)

    monkeypatch.setattr(cli, "connect", spy)
    return seen


@pytest.mark.postgres
def test_rebaseline_then_regression_against_the_target_alone(tmp_path, dbs, capsys, opened):
    s, t, tc = dbs
    p = _project(tmp_path, s, t)
    # live traffic after cutover: the target no longer matches the frozen source
    tc.execute("UPDATE orders SET status = 'DELIVERED' WHERE id <= 300")
    assert run(tmp_path, "rebaseline", "--project", str(p), "--baseline-id", "t1") == EXIT_OK
    assert json.loads(capsys.readouterr().out)["side"] == "target"
    assert opened == [t]  # the source is never read; it may be decommissioned
    manifest = json.loads((tmp_path / "work/acme/baselines/t1/manifest.json").read_text())
    assert manifest["side"] == "target"

    opened.clear()
    assert run(tmp_path, "reconcile", "--project", str(p), "--baseline", "latest-target",
               "--run-id", "r1") == EXIT_OK  # fmt: skip
    assert opened == [t]
    report = json.loads((tmp_path / "work/acme/runs/r1/report.json").read_text())
    assert report["range"]["reference"] == "target baseline t1"

    # a change since the rebaseline is found, down to the bucket
    tc.execute("UPDATE orders SET total = total + 1 WHERE id = 7")
    assert run(tmp_path, "reconcile", "--project", str(p), "--baseline", "latest-target",
               "--run-id", "r2") == EXIT_DIFFERENCES  # fmt: skip
    summaries = [f["summary"] for f in json.loads(
        (tmp_path / "work/acme/runs/r2/report.json").read_text())["findings"]]  # fmt: skip
    assert any("1 of 4 buckets mismatched" in x for x in summaries)
    assert any("target's past state cannot be re-read" in x for x in summaries)

    # rows added since: the count names the target baseline as the reference
    tc.execute("INSERT INTO notes VALUES ('late')")
    run(tmp_path, "reconcile", "--project", str(p), "--baseline", "latest-target", "--run-id", "r3")
    summaries = [f["summary"] for f in json.loads(
        (tmp_path / "work/acme/runs/r3/report.json").read_text())["findings"]]  # fmt: skip
    assert "row count differs: target baseline 10, target 11 (+1)" in summaries


@pytest.mark.postgres
def test_the_report_records_what_limited_each_database_it_read(tmp_path, dbs, capsys):
    s, t, _ = dbs
    p = _project(tmp_path, s, t)  # no limits in the file: the defaults

    def limits(run_id):
        report = json.loads((tmp_path / f"work/acme/runs/{run_id}/report.json").read_text())
        return report["run"]["source_protection"]

    assert run(tmp_path, "reconcile", "--project", str(p), "--run-id", "r1") == EXIT_OK
    assert limits("r1") == {
        "source": {"rows_per_second": SOURCE_ROWS_PER_SECOND, "pause_ms": SOURCE_PAUSE_MS,
                   "statement_timeout_ms": 0, "lock_timeout_ms": LOCK_TIMEOUT_MS},
        "target": {"rows_per_second": 0, "pause_ms": 0, "statement_timeout_ms": 0,
                   "lock_timeout_ms": LOCK_TIMEOUT_MS},
        "workers": 1,
    }  # fmt: skip
    assert "source protection" in (tmp_path / "work/acme/runs/r1/report.html").read_text()
    assert run(tmp_path, "report", "--project", str(p), "--run", "r1") == EXIT_OK
    assert limits("r1")["source"]["rows_per_second"] == SOURCE_ROWS_PER_SECOND

    # no source entry whenever the source was not read
    assert run(tmp_path, "baseline", "--project", str(p), "--baseline-id", "b1") == EXIT_OK
    assert run(tmp_path, "reconcile", "--project", str(p), "--baseline", "latest",
               "--no-source", "--run-id", "r2") == EXIT_OK  # fmt: skip
    assert run(tmp_path, "rebaseline", "--project", str(p), "--baseline-id", "t1") == EXIT_OK
    assert run(tmp_path, "reconcile", "--project", str(p), "--baseline", "latest-target",
               "--run-id", "r3") == EXIT_OK  # fmt: skip
    doc = yaml.safe_load(p.read_text())
    doc["source"]["host"], doc["source"]["port"] = "127.0.0.1", 1  # unreachable: baseline only
    p.write_text(yaml.safe_dump(doc))
    assert run(tmp_path, "reconcile", "--project", str(p), "--baseline", "latest",
               "--run-id", "r4") == EXIT_OK  # fmt: skip
    for run_id in ("r2", "r3", "r4"):
        assert set(limits(run_id)) == {"target", "workers"}


@pytest.mark.postgres
def test_latest_and_latest_target_are_separate(tmp_path, dbs, capsys):
    s, t, _ = dbs
    p = _project(tmp_path, s, t)
    assert run(tmp_path, "reconcile", "--project", str(p), "--baseline", "latest-target") == \
        EXIT_CONFIG
    assert "liftproof rebaseline" in capsys.readouterr().err
    assert run(tmp_path, "rebaseline", "--project", str(p), "--baseline-id", "t1") == EXIT_OK
    assert run(tmp_path, "reconcile", "--project", str(p), "--baseline", "latest") == EXIT_CONFIG
    assert run(tmp_path, "rebaseline", "--project", str(p), "--baseline-id", "latest") == \
        EXIT_CONFIG
    # a replacement instance (empty work directory) finds the marker through the store
    store_root = tmp_path / "store"
    shutil.copytree(tmp_path / "work/acme", store_root)
    shutil.rmtree(tmp_path / "work")
    args = argparse.Namespace(baseline="latest-target")
    b = cli._load_baseline(args, None, LocalStore(store_root), tmp_path / "work/acme")
    assert (b.baseline_id, b.side) == ("t1", "target")


@pytest.mark.postgres
def test_support_bundle_carries_the_run_without_values(tmp_path, dbs, capsys, monkeypatch):
    import zipfile

    s, t, tc = dbs
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    monkeypatch.setenv("LIFTPROOF_LOG_DIR", str(log_dir))
    tc.execute("UPDATE orders SET status = 'SECRET-VALUE-42' WHERE id = 7")
    p = _project(tmp_path, s, t, show_values=True)
    assert run(tmp_path, "reconcile", "--project", str(p), "--run-id", "r1") == EXIT_DIFFERENCES
    html = (tmp_path / "work/acme/runs/r1/report.html").read_text()
    assert "SECRET-VALUE-42" in html  # the run itself was asked to show values
    capsys.readouterr()

    assert run(tmp_path, "support-bundle", "--project", str(p)) == EXIT_OK
    out = json.loads(capsys.readouterr().out)
    assert out["run_id"] == "r1"  # the latest run by default
    with zipfile.ZipFile(out["bundle"]) as z:
        names = set(z.namelist())
        assert {"MANIFEST.json", "environment.json", "project.json", "run/report.json",
                "run/findings.jsonl", "run/db-results.json", "run.log"} <= names
        assert not [n for n in names if n.endswith(".html")]
        everything = "".join(z.read(n).decode() for n in names)
    assert "SECRET-VALUE-42" not in everything
    assert "id = 7" not in everything  # database locators name key values
    bundle = zipfile.ZipFile(out["bundle"])
    findings = [json.loads(x) for x in bundle.read("run/findings.jsonl").decode().splitlines()]
    changed = [f for f in findings if f["column"] == "status" and f["expected"]]
    assert changed and changed[0]["expected"] == "[redacted]"
    env = json.loads(bundle.read("environment.json"))
    assert env["canonical_version"] and env["packages"]["psycopg"]
    assert env["canonical_revision"] == CANONICAL_REVISION
    assert env["type_map_version"] == "1.0"
    type_map = DEFAULT_TYPE_MAP.record("postgresql")
    assert json.loads(bundle.read("project.json"))["database"]["type_map"] == type_map
    assert json.loads(bundle.read("run/report.json"))["run"]["type_map"] == type_map
    # why a structure check was not made: switched off, or a structure rule with its reason
    every = {"nullability": True, "keys": True, "foreign_keys": True, "indexes": True}
    assert json.loads(bundle.read("project.json"))["database"]["structure"] == every
    assert json.loads(bundle.read("run/report.json"))["range"]["structure"] == every
    assert json.loads(bundle.read("run/db-results.json"))["structure"] == every
    # also in the store, for an operator who has no shell on the instance
    assert (tmp_path / "work/acme/support" / out["bundle"].rsplit("/", 1)[1]).exists()


def test_support_bundle_unknown_run_is_a_configuration_error(tmp_path, capsys):
    p = _project(tmp_path, "s", "t")
    assert run(tmp_path, "support-bundle", "--project", str(p), "--run", "nope") == EXIT_CONFIG


def test_redaction_rules():
    from liftproof.support import REDACTED, redact_finding

    f = redact_finding({
        "comparator": "database", "locator": "id = 7", "expected": "a", "actual": "b",
        "detail": {"key": ["7"], "column": "status", "nested": {"source": {"max": 9.5}},
                   "buckets": [3]},
    })  # fmt: skip
    assert f["locator"] == f["expected"] == f["actual"] == REDACTED
    assert f["detail"] == {"key": REDACTED, "column": "status",
                           "nested": {"source": REDACTED}, "buckets": [3]}  # fmt: skip
    ui = redact_finding({"comparator": "ui", "locator": "#total", "expected": None})
    assert ui["locator"] == "#total" and ui["expected"] is None


def test_mysql_to_postgresql_project_defaults(tmp_path):
    from liftproof.config import load_project

    doc = {
        "project": "shop",
        "source": {"engine": "mysql", "host": "old.example", "database": "shop"},
        "target": {"engine": "postgresql", "host": "new.example", "database": "shop"},
    }
    path = tmp_path / "shop.yaml"
    path.write_text(yaml.safe_dump(doc))
    p = load_project(path)
    assert (p.source.port, p.target.port) == (3306, 5432)
    assert p.database.schemas == ["shop"]
    assert p.database.schema_map == {"shop": "public"}


def test_oracle_home_schema_is_the_login(tmp_path):
    from liftproof.config import load_project

    f = tmp_path / "p.yaml"
    f.write_text(
        "project: p\n"
        "source: {engine: oracle, host: o, database: ORCLPDB1, user: app}\n"
        "target: {engine: postgresql, host: p, database: app}\n"
    )
    p = load_project(f)
    assert p.source.port == 1521
    assert p.database.schemas == ["APP"]
    assert p.database.schema_map == {"APP": "public"}


def test_oracle_without_a_user_needs_schemas(tmp_path):
    from liftproof.config import load_project
    from liftproof.errors import ConfigError

    f = tmp_path / "p.yaml"
    f.write_text(
        "project: p\n"
        "source: {engine: oracle, host: o, database: ORCLPDB1, secret_arn: arn:x}\n"
        "target: {engine: postgresql, host: p, database: app}\n"
    )
    with pytest.raises(ConfigError, match="database.schemas"):
        load_project(f)
    f.write_text(f.read_text() + "database: {schemas: [APP], schema_map: {APP: public}}\n")
    assert load_project(f).database.schema_map == {"APP": "public"}
