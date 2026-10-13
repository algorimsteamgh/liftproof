"""doctor proves the setup before cutover night (spec 13), and every AWS call stays inside
the deployment's rate limit and the instance role (AWSAPI-002, IAM-002)."""

from __future__ import annotations

import json
import socket

import pytest
import yaml

from liftproof import aws, cli
from liftproof.adapters import mysql as mysql_mod
from liftproof.adapters.base import Adapter
from liftproof.adapters.mysql import MySQLAdapter
from liftproof.adapters.oracle import OracleAdapter
from liftproof.adapters.postgres import PostgresAdapter
from liftproof.adapters.sqlserver import SQLServerAdapter
from liftproof.config import load_project
from liftproof.errors import EXIT_CONFIG, EXIT_OK, ConfigError
from liftproof.files.sources import S3Source, open_source
from tests.conftest import PG

BUCKET = "liftproof-doctor-test"


@pytest.fixture
def settings(tmp_path, monkeypatch):
    """The instance settings the deployment template writes."""
    path = tmp_path / "instance.yaml"
    monkeypatch.setattr(cli, "INSTANCE_CONFIG", path)

    def write(**values):
        path.write_text(yaml.safe_dump(values))
        return path

    return write


@pytest.fixture
def files_project(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    path = tmp_path / "docs.yaml"
    files = [{"name": "docs", "source": str(tmp_path / "a"), "target": str(tmp_path / "b")}]
    path.write_text(yaml.safe_dump({"project": "docs", "files": files}))
    return path


def _doctor(project, tmp_path, capsys) -> tuple[int, dict[str, dict[str, str]]]:
    code = cli.main(["doctor", "--project", str(project), "--workdir", str(tmp_path / "w"),
                     "--format", "json"])  # fmt: skip
    checks = json.loads(capsys.readouterr().out)["checks"]
    return code, {c["check"]: c for c in checks}


# ------------------------------------------------------------------ engine versions
class _Fake(Adapter):
    engine = "fake"
    product = "Fake DB"
    minimum_version = (8, 0)
    minimum_shown = "Fake DB 8.0"
    closed = False

    def __init__(self):  # no connection
        pass

    def close(self):
        self.closed = True

    def __getattr__(self, name):  # the abstract methods are never called here
        raise AttributeError(name)


_Fake.__abstractmethods__ = frozenset()


@pytest.mark.parametrize(
    "found, refused",
    [
        ("8.0.36", False),
        ("8.0.mysql_aurora.3.05.2", False),
        ("9.1.0", False),
        ("8", False),  # a bare major is 8.0, not older than it
        ("5.7.44-log", True),
        ("5.7.mysql_aurora.2.11.2", True),
        ("unknown", False),  # nothing to compare: let the connection say so later
    ],
)
def test_the_version_gate_compares_numerically(found, refused):
    a = _Fake()
    if refused:
        with pytest.raises(ConfigError, match=r"Fake DB .* is not supported; .*Fake DB 8\.0"):
            a.require_version(found)
        assert a.closed
    else:
        a.require_version(found)
        assert a.version == found and not a.closed


def test_each_engine_declares_its_minimum():
    assert PostgresAdapter.minimum_version == (13,)  # trim_scale
    assert MySQLAdapter.minimum_version == (8, 0)
    assert OracleAdapter.minimum_version == (19,)
    assert SQLServerAdapter.minimum_version == (13,)  # SQL Server 2016


def test_an_old_server_is_refused_on_connect(pg_available, monkeypatch, adapter_for):
    monkeypatch.setattr(PostgresAdapter, "minimum_version", (99,))
    with pytest.raises(ConfigError, match=r"PostgreSQL \d+\.\d+ is not supported"):
        adapter_for("postgres")
    monkeypatch.undo()
    a = adapter_for("postgres")
    assert a.version.split(".")[0].isdigit() and a.session_settings()


def test_the_doctor_names_the_engine_and_version(pg_available, tmp_path, capsys, monkeypatch,
                                                  settings):  # fmt: skip
    settings()
    conn = {"engine": "postgresql", "host": PG["host"], "port": PG["port"], "user": PG["user"],
            "sslmode": "disable", "database": "postgres"}  # fmt: skip
    if PG["password"]:
        conn["secret_arn"] = "arn:aws:secretsmanager:ap-south-1:000000000000:secret:t"
        from liftproof.credentials import DbCredentials

        monkeypatch.setattr(cli, "from_secrets_manager",
                            lambda arn: DbCredentials(PG["user"], PG["password"]))  # fmt: skip
    project = tmp_path / "p.yaml"
    project.write_text(yaml.safe_dump({"project": "p", "source": conn, "target": conn}))
    _code, checks = _doctor(project, tmp_path, capsys)
    assert ": PostgreSQL " in checks["target database connection"]["detail"]
    monkeypatch.setattr(PostgresAdapter, "minimum_version", (99,))
    code, checks = _doctor(project, tmp_path, capsys)
    assert code == EXIT_CONFIG
    target = checks["target database connection"]
    assert target["result"] == "fail" and "needs PostgreSQL 13 or later" in target["detail"]


class _Cursor:
    def __init__(self, version):
        self.version, self.sent = version, []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, q, args=None):
        self.sent.append(q)

    def fetchone(self):
        return (self.version,)


class _Conn:
    open = True

    def __init__(self, version):
        self.cur = _Cursor(version)

    def cursor(self):
        return self.cur

    def close(self):
        self.open = False


@pytest.mark.parametrize("version", ["10.11.6-MariaDB", "11.4.2-MariaDB-log"])
def test_mariadb_is_refused_by_name_before_any_session_setting(monkeypatch, version):
    conn = _Conn(version)
    monkeypatch.setattr(mysql_mod.pymysql, "connect", lambda **kw: conn)
    with pytest.raises(ConfigError, match="MariaDB .* is not supported"):
        MySQLAdapter(host="db", port=3306, database="d", sslmode="disable")
    assert conn.cur.sent == ["SELECT VERSION()"] and not conn.open


def test_an_old_mysql_is_refused_before_any_session_setting(monkeypatch):
    conn = _Conn("5.7.44-log")
    monkeypatch.setattr(mysql_mod.pymysql, "connect", lambda **kw: conn)
    with pytest.raises(ConfigError, match=r"MySQL 5\.7\.44-log is not supported"):
        MySQLAdapter(host="db", port=3306, database="d", sslmode="disable")
    # max_execution_time does not exist before 5.7.8: the version error comes first
    assert conn.cur.sent == ["SELECT VERSION()"]


# ------------------------------------------------------------------- AWS rate limit
def test_the_rate_limit_comes_from_the_instance_settings(monkeypatch, settings, capsys):
    rates = []
    monkeypatch.setattr(aws, "configure_rate_limit", lambda rate, burst=None: rates.append(rate))
    settings(aws_requests_per_second=5)
    assert cli.main(["version"]) == EXIT_OK
    settings(bucket="b")  # not set: the default
    assert cli.main(["version"]) == EXIT_OK
    assert rates == [5.0, aws.DEFAULT_RATE]
    settings(aws_requests_per_second="fast")
    assert cli.main(["version"]) == EXIT_CONFIG
    assert "aws_requests_per_second" in capsys.readouterr().err


def test_an_s3_file_source_uses_the_shared_rate_limited_client(monkeypatch):
    made = []

    def fake_client(service, region=None, *, endpoint_url=None, credentials=None):
        made.append((service, endpoint_url, credentials))
        return object()

    monkeypatch.setattr(aws, "client", fake_client)
    S3Source("bucket", "in/")  # AWS S3: the instance role, no keys
    monkeypatch.setattr("liftproof.credentials.secret_value", lambda arn, key: f"<{key}>")
    open_source("s3://bucket/in", endpoint_url="https://minio.example:9000",
                secret_arn="arn:aws:secretsmanager:ap-south-1:0:secret:s3")  # fmt: skip
    assert made == [
        ("s3", None, None),
        ("s3", "https://minio.example:9000",
         {"aws_access_key_id": "<access_key_id>",
          "aws_secret_access_key": "<secret_access_key>"}),
    ]  # fmt: skip


def test_keys_for_a_bucket_in_aws_are_refused(tmp_path):
    path = tmp_path / "f.yaml"
    path.write_text(yaml.safe_dump({"project": "p", "files": [{"name": "docs",
        "source": {"location": "s3://bucket/in", "secret_arn": "arn:aws:secretsmanager:x"},
        "target": str(tmp_path)}]}))  # fmt: skip
    with pytest.raises(ConfigError, match="instance role"):
        load_project(path)
    doc = yaml.safe_load(path.read_text())
    doc["files"][0]["source"]["endpoint_url"] = "https://minio.example:9000"
    path.write_text(yaml.safe_dump(doc))
    fs = load_project(path).files[0]
    assert fs.source_secret_arn and fs.source_endpoint_url


# --------------------------------------------------------------------- doctor storage
@pytest.fixture
def s3(monkeypatch):
    moto = pytest.importorskip("moto")
    import boto3

    with moto.mock_aws():
        client = boto3.client("s3", region_name="ap-south-1")
        client.create_bucket(
            Bucket=BUCKET, CreateBucketConfiguration={"LocationConstraint": "ap-south-1"}
        )
        key = boto3.client("kms", region_name="ap-south-1").create_key()["KeyMetadata"]["Arn"]
        monkeypatch.setattr(aws, "client", lambda service, region=None, **kw: client)
        yield client, key


def test_doctor_proves_the_deployment_bucket_and_key(s3, settings, files_project, tmp_path,
                                                     capsys):  # fmt: skip
    client, key = s3
    settings(bucket=BUCKET, kms_key=key)  # the project names no bucket of its own
    code, checks = _doctor(files_project, tmp_path, capsys)
    assert code == EXIT_OK
    storage = checks["S3 bucket writable and readable with KMS encryption"]
    assert storage["result"] == "pass" and "read back" in storage["detail"] and key in (
        storage["detail"]
    )
    (probe,) = [o["Key"] for o in client.list_objects_v2(Bucket=BUCKET)["Contents"]]
    assert probe.endswith("doctor/probe.txt") and f"s3://{BUCKET}/{probe}" in storage["detail"]
    head = client.head_object(Bucket=BUCKET, Key=probe)
    assert head["ServerSideEncryption"] == "aws:kms" and head["SSEKMSKeyId"] == key

    settings(bucket="no-such-bucket", kms_key=key)
    code, checks = _doctor(files_project, tmp_path, capsys)
    storage = checks["S3 bucket writable and readable with KMS encryption"]
    assert code == EXIT_CONFIG and storage["result"] == "fail"
    assert "NoSuchBucket" in storage["detail"] and "kms:Decrypt" in storage["remedy"]


def test_doctor_without_a_bucket_says_where_results_go(settings, files_project, tmp_path,
                                                       capsys):  # fmt: skip
    settings()
    code, checks = _doctor(files_project, tmp_path, capsys)
    assert code == EXIT_OK
    assert str(tmp_path / "w" / "docs") in checks["results storage"]["detail"]
    assert "AWS service endpoints reachable" not in checks  # not on an instance


# ------------------------------------------------------------------- doctor endpoints
def test_doctor_checks_every_endpoint_on_the_instance(settings, files_project, tmp_path,
                                                      capsys, monkeypatch):  # fmt: skip
    settings(region="ap-south-1")
    asked = []

    def reach(service, region, timeout=5.0):
        asked.append((service, region))
        return {"s3": "gateway", "logs": "public address"}.get(service, "vpc endpoint")

    monkeypatch.setattr(aws, "reach", reach)
    code, checks = _doctor(files_project, tmp_path, capsys)
    assert code == EXIT_OK
    assert asked == [(s, "ap-south-1") for s in aws.ENDPOINT_SERVICES]
    endpoints = checks["AWS service endpoints reachable"]
    assert endpoints["result"] == "pass"
    assert endpoints["detail"].endswith("not a VPC endpoint: logs")

    def unreachable(service, region, timeout=5.0):
        if service == "kms":
            raise ConnectionRefusedError(111, "Connection refused")
        if service == "ssm":
            raise socket.gaierror(-2, "Name or service not known")
        return "vpc endpoint"

    monkeypatch.setattr(aws, "reach", unreachable)
    code, checks = _doctor(files_project, tmp_path, capsys)
    endpoints = checks["AWS service endpoints reachable"]
    assert code == EXIT_CONFIG and endpoints["result"] == "fail"
    assert "ssm (Name or service not known)" in endpoints["detail"]
    assert "kms (Connection refused)" in endpoints["detail"]
    assert "private DNS" in endpoints["remedy"]


class _Sock:
    def __init__(self, *a):
        self.connected = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def settimeout(self, t):
        assert t == 5.0

    def connect(self, addr):
        self.connected = addr


@pytest.mark.parametrize(
    "service, address, route",
    [
        ("kms", "10.0.3.17", "vpc endpoint"),
        ("logs", "52.95.86.10", "public address"),
        ("s3", "52.219.62.9", "gateway"),  # a gateway endpoint keeps public addresses
    ],
)
def test_reach_names_the_route(monkeypatch, service, address, route):
    looked_up = []

    def getaddrinfo(host, port, type=0):
        looked_up.append((host, port))
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))]

    monkeypatch.setattr(aws.socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(aws.socket, "socket", _Sock)
    assert aws.reach(service, "ap-south-1") == route
    assert looked_up == [(f"{service}.ap-south-1.amazonaws.com", 443)]


def test_reach_fails_when_nothing_answers(monkeypatch):
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    port = server.getsockname()[1]
    server.close()  # nothing listens there now
    monkeypatch.setattr(aws.socket, "getaddrinfo", lambda host, p, type=0: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))])  # fmt: skip
    with pytest.raises(OSError):
        aws.reach("kms", "ap-south-1", timeout=2.0)

    def no_name(host, p, type=0):
        raise socket.gaierror(-2, "Name or service not known")

    monkeypatch.setattr(aws.socket, "getaddrinfo", no_name)
    with pytest.raises(OSError):
        aws.reach("kms", "ap-south-1")
