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
    return Connection(engine="postgresql", host="db", port=5432, database="app", **kw)


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
