"""Database TLS (spec 15): the verifying modes really verify, and the AMI's CA bundle,
which trusts Amazon RDS, is used when a project names no CA of its own."""

from __future__ import annotations

import ssl
from pathlib import Path

import pymysql
import pytest

from liftproof import cli
from liftproof.adapters import mysql
from liftproof.config import Connection
from liftproof.errors import ConfigError

ROOT = Path(__file__).resolve().parents[1]
RDS_BUNDLE = ROOT / "infra/packer/files/rds-global-bundle.pem"


@pytest.mark.parametrize(("mode", "hostname"), [("verify-ca", False), ("verify-full", True)])
def test_mysql_verifies_without_a_ca_file(mode, hostname):
    """With a dict and no "ca", PyMySQL turns verification off; a context keeps it on."""
    ctx = mysql._ssl_args(mode, None)["ssl"]
    assert isinstance(ctx, ssl.SSLContext)
    assert (ctx.verify_mode, ctx.check_hostname) == (ssl.CERT_REQUIRED, hostname)
    # PyMySQL uses the context exactly as given
    conn = pymysql.connections.Connection.__new__(pymysql.connections.Connection)
    assert conn._create_ssl_ctx(ctx) is ctx


def test_mysql_verifies_against_a_named_ca_file():
    ctx = mysql._ssl_args("verify-full", str(RDS_BUNDLE))["ssl"]
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    issuers = {dict(x[0] for x in c["subject"])["organizationName"] for c in ctx.get_ca_certs()}
    assert "Amazon Web Services, Inc." in issuers


def _conn(**kw) -> Connection:
    return Connection(
        **{"engine": "postgresql", "host": "db", "port": 5432, "database": "app", **kw}
    )


def test_the_ami_bundle_is_used_when_no_ca_is_named(tmp_path, monkeypatch):
    bundle = tmp_path / "ca-bundle.pem"
    monkeypatch.setattr(cli, "CA_BUNDLE", bundle)
    assert cli._sslrootcert(_conn()) is None  # no bundle on this host: driver default
    bundle.write_text(RDS_BUNDLE.read_text())
    assert cli._sslrootcert(_conn()) == str(bundle)
    assert cli._sslrootcert(_conn(sslmode="verify-ca")) == str(bundle)
    assert cli._sslrootcert(_conn(sslrootcert="/var/lib/mvt/certs/own.pem")) == (
        "/var/lib/mvt/certs/own.pem"
    )
    # libpq treats a root certificate as "verify" even under require; leave those alone
    assert cli._sslrootcert(_conn(sslmode="require")) is None
    assert cli._sslrootcert(_conn(sslmode="disable")) is None


def test_the_ami_ships_the_rds_bundle():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=str(RDS_BUNDLE))
    certs = ctx.get_ca_certs()
    assert len(certs) > 10
    assert {dict(x[0] for x in c["subject"])["organizationName"] for c in certs} == {
        "Amazon Web Services, Inc."
    }
    provision = (ROOT / "infra/packer/files/provision.sh").read_text(encoding="utf-8")
    assert "/tmp/liftproof-files/rds-global-bundle.pem /opt/mvt/certs/" in provision
    assert str(cli.CA_BUNDLE) == "/opt/mvt/certs/ca-bundle.pem"
    assert "> /opt/mvt/certs/ca-bundle.pem.new" in provision


@pytest.mark.mysql
@pytest.mark.parametrize("mode", ["verify-ca", "verify-full"])
def test_mysql_refuses_a_server_certificate_it_cannot_verify(mysql_available, mode):
    """The test server's certificate is self signed. Before the fix, verify-full with no
    sslrootcert connected anyway: encrypted, but to whoever answered."""
    from tests.conftest import MY

    with pytest.raises(ConfigError, match="CERTIFICATE_VERIFY_FAILED"):
        mysql.MySQLAdapter(host=MY["host"], port=MY["port"], database="mysql",
                           user=MY["user"], password=MY["password"], sslmode=mode)  # fmt: skip


def test_a_ca_kept_in_s3_is_read_with_the_instance_role(tmp_path, monkeypatch):
    """A Cloud SQL server CA (or any private CA) put in the project's bucket, so no one
    needs a shell on the instance."""
    boto3 = pytest.importorskip("boto3")
    moto = pytest.importorskip("moto")
    monkeypatch.setenv("LIFTPROOF_CACHE", str(tmp_path / "cache"))
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    with moto.mock_aws():
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="lp-certs")
        s3.put_object(Bucket="lp-certs", Key="certs/server-ca.pem", Body=RDS_BUNDLE.read_bytes())
        s3.put_object(Bucket="lp-certs", Key="certs/not.pem", Body=b"hello")
        path = Path(cli._sslrootcert(_conn(sslrootcert="s3://lp-certs/certs/server-ca.pem")))
        assert path.read_bytes() == RDS_BUNDLE.read_bytes()
        assert path.stat().st_mode & 0o777 == 0o600
        with pytest.raises(ConfigError, match="not a PEM certificate"):
            cli._sslrootcert(_conn(sslrootcert="s3://lp-certs/certs/not.pem"))
        with pytest.raises(ConfigError, match="cannot read it"):
            cli._sslrootcert(_conn(sslrootcert="s3://lp-certs/certs/missing.pem"))


def test_postgresql_connects_by_address_and_verifies_by_name(monkeypatch, tmp_path):
    """A server across a VPN whose name resolves only in its own network's private DNS
    zone: libpq connects to hostaddr and checks the certificate against host."""
    import yaml

    from liftproof.adapters import postgres
    from liftproof.config import load_project

    seen = {}

    def fake_connect(**params):
        seen.update(params)
        raise postgres.psycopg.OperationalError("stop here")

    monkeypatch.setattr(postgres.psycopg, "connect", fake_connect)
    conn = _conn(hostaddr="10.20.0.4", host="app.private.postgres.database.azure.com")
    with pytest.raises(ConfigError, match=r"database.azure.com \(10.20.0.4\):5432"):
        cli.connect(conn)
    assert (seen["host"], seen["hostaddr"], seen["sslmode"]) == (
        "app.private.postgres.database.azure.com",
        "10.20.0.4",
        "verify-full",
    )

    p = tmp_path / "p.yaml"
    doc = {"project": "p",
           "source": {"engine": "postgresql", "host": "h.example", "database": "d",
                      "hostaddr": "10.20.0.4"},
           "target": {"engine": "postgresql", "host": "t", "database": "d"}}  # fmt: skip
    p.write_text(yaml.safe_dump(doc))
    assert load_project(p).source.hostaddr == "10.20.0.4"
    for engine, value, says in [("postgresql", "db.internal", "IP address"),
                                ("mysql", "10.0.0.1", "for PostgreSQL")]:  # fmt: skip
        doc["source"].update(engine=engine, hostaddr=value)
        p.write_text(yaml.safe_dump(doc))
        with pytest.raises(ConfigError, match=says):
            load_project(p)
