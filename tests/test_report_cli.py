"""The report says what was compared and how (spec 12), and the CLI behaves the same
whatever order its flags come in (spec 16 for the logging)."""

from __future__ import annotations

import json

import pytest
import yaml

from liftproof import cli
from liftproof.credentials import DbCredentials
from liftproof.errors import EXIT_DIFFERENCES, EXIT_OK
from tests.conftest import PG

SECRET = "arn:aws:secretsmanager:ap-south-1:000000000000:secret:liftproof/test"
SCHEMA = """
CREATE TABLE orders (id int PRIMARY KEY, placed timestamptz, due date, code text);
INSERT INTO orders SELECT g, timestamptz '2026-01-01 00:00:00+05:30' + g * interval '1 day',
  date '2026-03-01' + g, 'c' || g FROM generate_series(1, 40) g;
CREATE TABLE codes (code text PRIMARY KEY, label text);
INSERT INTO codes SELECT 'k' || g, 'l' || g FROM generate_series(1, 5) g;
"""


@pytest.fixture(autouse=True)
def secret(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "from_secrets_manager",
                        lambda arn: DbCredentials(PG["user"], PG["password"]))  # fmt: skip
    monkeypatch.setattr(cli, "INSTANCE_CONFIG", tmp_path / "no-instance-settings.yaml")


@pytest.fixture
def project(tmp_path, make_db):
    s, sc = make_db("src")
    t, tc = make_db("tgt")
    sc.execute(SCHEMA)
    tc.execute(SCHEMA)
    tc.execute("UPDATE orders SET code = 'changed' WHERE id = 3")
    conn = {"engine": "postgresql", "host": PG["host"], "port": PG["port"], "user": PG["user"],
            "sslmode": "disable", "secret_arn": SECRET}  # fmt: skip
    doc = {"project": "acme", "source": dict(conn, database=s), "target": dict(conn, database=t),
           "database": {"rows_per_bucket": 10}}  # fmt: skip
    path = tmp_path / "acme.yaml"
    path.write_text(yaml.safe_dump(doc))
    return path


def _report(tmp_path, run_id):
    return json.loads((tmp_path / "w" / "acme" / "runs" / run_id / "report.json").read_text())


def test_flags_count_before_the_command_too(tmp_path, project, capsys):
    code = cli.main(["--format", "json", "--workdir", str(tmp_path / "w"), "--fail-on", "never",
                     "reconcile", "--project", str(project), "--run-id", "r1"])  # fmt: skip
    assert code == EXIT_OK  # --fail-on never, given before the command
    assert json.loads(capsys.readouterr().out)["run_id"] == "r1"  # --format json
    assert (tmp_path / "w" / "acme" / "runs" / "r1" / "report.json").exists()
    # after the command still works, and wins when both are given
    assert cli.main(["--format", "json", "version", "--format", "text"]) == EXIT_OK
    assert capsys.readouterr().out.startswith("liftproof: ")


def test_a_log_file_that_cannot_be_opened_costs_the_file_not_the_run(tmp_path, monkeypatch,
                                                                     capsys):  # fmt: skip
    (tmp_path / "logs" / "liftproof.log").mkdir(parents=True)  # cannot be opened as a file
    monkeypatch.setenv("LIFTPROOF_LOG_DIR", str(tmp_path / "logs"))
    assert cli.main(["version"]) == EXIT_OK
    assert "cannot write the log file" in capsys.readouterr().err
    with pytest.raises(SystemExit) as exc:
        cli.main(["version", "--log-level", "chatty"])
    assert exc.value.code == 2  # usage error, not a traceback


def test_debug_logs_each_statement_never_its_values(tmp_path, project, capsys):
    cli.main(["reconcile", "--project", str(project), "--workdir", str(tmp_path / "w"),
              "--log-level", "debug"])  # fmt: skip
    lines = [json.loads(x) for x in capsys.readouterr().err.splitlines() if x.startswith("{")]
    statements = [x["msg"] for x in lines if x["component"] == "sql"]
    assert any(s.startswith("postgresql: SELECT") and "FROM" in s for s in statements)
    assert all(PG["password"] not in s for s in statements if PG["password"])
    assert not any("changed" in s for s in statements)  # the target's row value


def test_the_range_block_names_key_and_date_ranges(tmp_path, project):
    work = ["--workdir", str(tmp_path / "w"), "--format", "json"]
    assert cli.main(["reconcile", "--project", str(project), "--run-id", "r1", *work]) == (
        EXIT_DIFFERENCES
    )
    ranges = _report(tmp_path, "r1")["range"]["data_ranges"]
    orders = ranges["public.orders"]
    assert orders["id"] == {"role": "key", "source": [1, 40], "target": [1, 40]}
    assert orders["placed"]["source"] == ["2026-01-01T18:30:00+00:00", "2026-02-09T18:30:00+00:00"]
    assert orders["due"]["target"] == ["2026-03-02", "2026-04-10"]
    assert "public.codes" not in ranges  # a text key's ends are row values

    # against a baseline, the source side is what the baseline recorded
    assert cli.main(["baseline", "--project", str(project), "--baseline-id", "b1", *work]) == 0
    assert cli.main(["reconcile", "--project", str(project), "--baseline", "latest",
                     "--no-source", "--run-id", "r2", *work]) == EXIT_DIFFERENCES  # fmt: skip
    assert _report(tmp_path, "r2")["range"]["data_ranges"]["public.orders"]["id"]["source"] == [
        1, 40,
    ]  # fmt: skip

    doc = yaml.safe_load(project.read_text())
    doc["database"]["show_values"] = True
    project.write_text(yaml.safe_dump(doc))
    cli.main(["reconcile", "--project", str(project), "--run-id", "r3", *work])
    assert _report(tmp_path, "r3")["range"]["data_ranges"]["public.codes"]["code"]["source"] == [
        "k1", "k5",
    ]  # fmt: skip
    doc["database"]["ranges"] = False
    project.write_text(yaml.safe_dump(doc))
    cli.main(["reconcile", "--project", str(project), "--run-id", "r4", *work])
    assert _report(tmp_path, "r4")["range"]["data_ranges"] == {}


def test_regenerating_a_report_keeps_what_the_run_was(tmp_path, project):
    work = ["--workdir", str(tmp_path / "w"), "--format", "json"]
    cli.main(["baseline", "--project", str(project), "--baseline-id", "b1", *work])
    cli.main(["reconcile", "--project", str(project), "--baseline", "latest", "--run-id", "r1",
              "--scheduled", "nightly", *work])  # fmt: skip
    before = _report(tmp_path, "r1")
    assert cli.main(["report", "--project", str(project), "--run", "r1", *work]) == (
        EXIT_DIFFERENCES
    )
    after = _report(tmp_path, "r1")
    assert after["range"] == before["range"]
    assert after["range"]["reference"] == "source baseline b1"
    for key in ("started_at", "finished_at", "schedule", "invoked_by", "product_version"):
        assert after["run"][key] == before["run"][key], key
    assert after["run"]["regenerated"]["at"] >= before["run"]["finished_at"]
    assert after["findings"] == before["findings"]


def test_the_classification_follows_show_values_for_files(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "x.csv").write_text("id,v\n1,2\n")
    (tmp_path / "b" / "x.csv").write_text("id,v\n1,3\n")
    path = tmp_path / "f.yaml"
    path.write_text(yaml.safe_dump({"project": "acme", "files": [
        {"name": "docs", "source": str(tmp_path / "a"), "target": str(tmp_path / "b")}]}))
    work = ["--workdir", str(tmp_path / "w"), "--format", "json"]
    cli.main(["files", "--project", str(path), "--run-id", "f1", *work])
    assert _report(tmp_path, "f1")["classification"].startswith("hashes")
    cli.main(["files", "--project", str(path), "--run-id", "f2", "--show-values", *work])
    assert _report(tmp_path, "f2")["classification"] == "contains row values"
