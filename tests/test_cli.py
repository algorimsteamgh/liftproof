"""CLI behaviour a pipeline relies on: exit codes, reports, and credential rules."""

import json

import pytest
import yaml

from liftproof import cli
from liftproof.errors import EXIT_CONFIG, EXIT_DIFFERENCES, EXIT_OK, EXIT_RUN_FAILED
from tests.conftest import PG

SCHEMA = """
CREATE TABLE orders (id int PRIMARY KEY, status text, total numeric(10,2));
INSERT INTO orders SELECT g, 'DISPATCHED', g + 0.5 FROM generate_series(1, 2000) g;
CREATE TABLE notes (body text);
INSERT INTO notes SELECT 'n' || g FROM generate_series(1, 10) g;
"""


def _project(tmp_path, src, tgt, **database):
    conn = {"engine": "postgresql", "host": PG["host"], "port": PG["port"], "user": PG["user"],
            "sslmode": "disable"}
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


def test_init_writes_template(tmp_path):
    assert cli.main(["init", "demo", "--dir", str(tmp_path)]) == EXIT_OK
    assert "secret_arn" in (tmp_path / "demo.yaml").read_text()
