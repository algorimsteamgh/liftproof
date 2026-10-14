"""SQL Server pushdown against the reference implementation (Technical Spec 19).

The in-database hash (with the rows SQL Server cannot render exactly routed to the
application side) must be byte identical to hashing every row through the reference
implementation.
"""

import datetime as dt
import uuid
from decimal import Decimal

import pytest

from liftproof.adapters.base import HashPlan, TableRef
from liftproof.adapters.sqlserver import (
    SQLServerAdapter,
    _pushable_sql,
    _tls_args,
    canonical_type,
    native_name,
)
from liftproof.canonical import CanonicalType as T
from liftproof.canonical import render
from liftproof.errors import ConfigError

pytestmark = pytest.mark.sqlserver

DDL = """
CREATE TABLE dbo.everything (
  id      bigint PRIMARY KEY,
  tiny    tinyint,
  small   smallint,
  num     decimal(12,4),
  wide    numeric(38,10),
  cash    money,
  petty   smallmoney,
  flag    bit,
  label   varchar(max),
  nlabel  nvarchar(50),
  code    char(6),
  ncode   nchar(4),
  day     date,
  clock   time(7),
  legacy  datetime,
  naive   datetime2(7),
  coarse  smalldatetime,
  aware   datetimeoffset(7),
  blob_   varbinary(max),
  ident   uniqueidentifier,
  weight  float
)"""

INSERT = "INSERT INTO dbo.everything VALUES (" + ", ".join(["%s"] * 21) + ")"
IST = dt.timezone(dt.timedelta(hours=5, minutes=30))

ROWS = [
    (
        1, 7, 300, Decimal("10.5"), Decimal("123.4500000000"), Decimal("12.3456"),
        Decimal("-1.5"), True, "cafe", "plain", "AB", "N", dt.date(2026, 1, 31),
        dt.time(13, 14, 15, 123456), dt.datetime(2026, 1, 31, 13, 14, 15),
        dt.datetime(2026, 9, 25, 11, 2, 41, 123456), dt.datetime(2026, 9, 25, 11, 2),
        dt.datetime(2026, 9, 25, 11, 2, 41, 500000, tzinfo=IST), bytes.fromhex("00ff10"),
        uuid.UUID("4dbc4294-7669-49d2-88f3-f2d4485c2ab6"), 1.5,
    ),
    (
        2, 0, -1, Decimal("-0.5"), Decimal("-0.000001"), Decimal("0"), Decimal("0.01"),
        False, "café", "naïve ☕", "X     ", "    ", dt.date(1999, 12, 31), dt.time(0),
        dt.datetime(2000, 1, 1, 0, 0, 0, 3000), dt.datetime(2000, 1, 1),
        dt.datetime(2000, 1, 1), dt.datetime(2000, 1, 1, 0, 0, 1, tzinfo=dt.UTC), b"",
        uuid.UUID("00000000-0000-0000-0000-000000000000"), 0.0,
    ),
    (3,) + (None,) * 20,
    (
        4, 255, 32767, Decimal("12345678.9"), Decimal("0.0000000001"),
        Decimal("922337203685477.5807"), Decimal("214748.3647"), True,
        "tab\there\\Nsep\r\nend  ", "z", "      ", "ab", dt.date(1, 1, 1),
        dt.time(23, 59, 59, 999999), dt.datetime(2026, 2, 28, 23, 59, 59, 997000),
        dt.datetime(9999, 12, 31, 23, 59, 59, 999999), dt.datetime(2079, 6, 6, 23, 59),
        dt.datetime(2026, 2, 28, 23, 59, 59, tzinfo=dt.timezone(-dt.timedelta(hours=8))),
        bytes(range(256)) * 40, uuid.UUID("ffffffff-ffff-ffff-ffff-ffffffffffff"), -1.0,
    ),
    (  # long plain ASCII: rendered by SQL Server itself
        5, 1, 2, Decimal("0.0001"), Decimal("9999999999999999999999999999.9999999999"),
        Decimal("-922337203685477.5808"), Decimal("0"), False, "y" * 20000, "q", "Z", "z",
        dt.date(2000, 2, 29), dt.time(12, 0, 0, 1), dt.datetime(2000, 2, 29, 12, 0, 0, 7000),
        dt.datetime(2000, 2, 29, 12, 0, 0, 1), dt.datetime(1900, 1, 1),
        dt.datetime(2000, 2, 29, 23, 59, 59, 999999, tzinfo=IST), b"\x00",
        uuid.UUID("12345678-1234-5678-1234-567812345678"), 2.25,
    ),
]  # fmt: skip

COLUMNS = [
    ("aware", T.TIMESTAMPTZ),
    ("blob_", T.BINARY),
    ("cash", T.DECIMAL),
    ("clock", T.TIME),
    ("coarse", T.TIMESTAMP),
    ("code", T.CHAR),
    ("day", T.DATE),
    ("flag", T.BOOLEAN),
    ("id", T.INTEGER),
    ("ident", T.UUID),
    ("label", T.TEXT),
    ("legacy", T.TIMESTAMP),
    ("naive", T.TIMESTAMP),
    ("ncode", T.CHAR),
    ("nlabel", T.TEXT),
    ("num", T.DECIMAL),
    ("petty", T.DECIMAL),
    ("small", T.INTEGER),
    ("tiny", T.INTEGER),
    ("wide", T.DECIMAL),
]


@pytest.fixture
def loaded(make_sqlserver_db, sqlserver_adapter_for):
    db, cur = make_sqlserver_db()
    cur.execute(DDL)
    import pytds

    for row in ROWS:  # bytes bind as text unless marked binary
        cur.execute(INSERT, [pytds.Binary(v) if isinstance(v, bytes) else v for v in row])
    return sqlserver_adapter_for(db)


def table():
    return TableRef("dbo", "everything")


@pytest.mark.parametrize("precision", [0, 3, 6])
@pytest.mark.parametrize("keyed", [True, False])
def test_pushdown_matches_reference(loaded, precision, keyed):
    a = loaded
    plan = HashPlan(table(), COLUMNS, ["id"] if keyed else [], 3, precision)
    assert a._pushdown(plan)
    pushed = a.bucket_aggregates(plan)
    reference = a._bucket_aggregates_fallback(plan)
    assert pushed == reference
    assert sum(b.count for b in pushed.values()) == 5

    rows_push = sorted(a.row_hashes(plan, set(range(3))))
    a._pushdown = lambda p: False
    rows_ref = sorted(a.row_hashes(plan, set(range(3))))
    assert rows_push == rows_ref
    assert len(rows_push) == 5


def test_only_ascii_rows_are_rendered_in_the_database(loaded):
    plan = HashPlan(table(), COLUMNS, ["id"], 1)
    q = f"SELECT id FROM dbo.everything WHERE {_pushable_sql(plan.columns)} ORDER BY 1"
    assert [r[0] for r in loaded._query(q)] == [1, 3, 4, 5]


def test_values_render_canonically(loaded):
    plan = HashPlan(table(), COLUMNS, ["id"], 1)
    rows = loaded.fetch_rows(plan, [("1",), ("2",), ("4",)])
    names = [n for n, _ in COLUMNS]
    one = dict(zip(names, rows[("1",)], strict=True))
    assert render(one["aware"], T.TIMESTAMPTZ) == "2026-09-25T05:32:41.500000"
    assert render(one["cash"], T.DECIMAL) == "12.3456"
    assert render(one["wide"], T.DECIMAL) == "123.45"
    assert render(one["clock"], T.TIME, precision=3) == "13:14:15.123"
    two = dict(zip(names, rows[("2",)], strict=True))
    assert render(two["legacy"], T.TIMESTAMP, precision=3) == "2000-01-01T00:00:00.003"
    assert render(two["code"], T.CHAR) == "X"
    assert render(two["ncode"], T.CHAR) == ""  # all spaces: empty, not NULL
    assert render(two["nlabel"], T.TEXT) == "naïve ☕"
    four = dict(zip(names, rows[("4",)], strict=True))
    assert render(four["legacy"], T.TIMESTAMP, precision=3) == "2026-02-28T23:59:59.997"
    assert render(four["day"], T.DATE) == "0001-01-01"


def test_text_keys_and_decimal_keys(make_sqlserver_db, sqlserver_adapter_for):
    """Rows are fetched by their rendered key, including non-ASCII text and decimals
    (whose rendering SQL holds % signs next to the query parameters)."""
    db, cur = make_sqlserver_db()
    cur.execute("CREATE TABLE dbo.k (code nvarchar(20), amount decimal(9,2), v int, "
                "PRIMARY KEY (code, amount))")  # fmt: skip
    cur.execute("INSERT INTO dbo.k VALUES (N'café', 1.50, 1), (N'plain', 2.00, 2)")
    a = sqlserver_adapter_for(db)
    plan = HashPlan(TableRef("dbo", "k"), [("amount", T.DECIMAL), ("code", T.TEXT),
                    ("v", T.INTEGER)], ["amount", "code"], 2)  # fmt: skip
    hashes = dict(a.row_hashes(plan, {0, 1}))
    assert set(hashes) == {("1.5", "café"), ("2", "plain")}
    got = a.fetch_rows(plan, list(hashes))
    assert {k: v[2] for k, v in got.items()} == {("1.5", "café"): 1, ("2", "plain"): 2}


def test_describe_maps_types(loaded):
    s = loaded.describe(table())
    assert s.primary_key == ["id"]
    got = {c.name: c.canonical for c in s.columns}
    assert got == dict(COLUMNS) | {"weight": T.FLOAT}
    natives = {c.name: c.native_type for c in s.columns}
    assert natives["num"] == "decimal(12,4)" and natives["label"] == "varchar(max)"
    assert natives["nlabel"] == "nvarchar(50)" and natives["naive"] == "datetime2(7)"
    assert natives["code"] == "char(6)" and natives["ncode"] == "nchar(4)"


def test_type_rules():
    assert canonical_type("xml") is T.XML
    assert canonical_type("geography") is T.UNSUPPORTED
    assert canonical_type("sql_variant") is T.UNSUPPORTED
    assert canonical_type("timestamp") is T.BINARY  # rowversion
    assert canonical_type("NVARCHAR") is T.TEXT
    assert native_name("varbinary", -1, 0, 0) == "varbinary(max)"
    assert native_name("time", 5, 16, 7) == "time(7)"


XML_ROWS = [
    (1, "<a b='2' a=\"1\">\n  <x></x>\n  <y>t</y>\n</a>", '<a a="1" b="2"><x></x><y>t</y></a>'),
    (2, "<a/><b/>caf\u00e9", "<a></a><b></b>caf\u00e9"),
    (3, None, None),
    (4, "<?xml version='1.0'?><a><!-- c --><![CDATA[x < y]]></a>", "<a>x &lt; y</a>"),
    (5, '<p:a xmlns:p="urn:p"><p:b xml:space="preserve">  </p:b></p:a>',
     '<p:a xmlns:p="urn:p"><p:b xml:space="preserve">  </p:b></p:a>'),
]  # fmt: skip


def test_xml_hashes_like_its_canonical_text(make_sqlserver_db, sqlserver_adapter_for):
    """SQL Server rewrites xml as it stores it (no declaration, <x/>, whitespace only
    text dropped, a preserved space as a character reference); it still hashes as the
    canonical text does."""
    db, cur = make_sqlserver_db()
    cur.execute("CREATE TABLE docs (id int PRIMARY KEY, doc xml, canon nvarchar(max))")
    for row in XML_ROWS:
        cur.execute("INSERT INTO docs VALUES (%s, %s, %s)", row)
    a = sqlserver_adapter_for(db)
    docs = TableRef("dbo", "docs")
    assert {c.name: c.canonical for c in a.describe(docs).columns} == {
        "id": T.INTEGER, "doc": T.XML, "canon": T.TEXT,
    }  # fmt: skip

    def plan(col, **kw):
        return HashPlan(docs, [(col, T.XML), ("id", T.INTEGER)], ["id"], 3, **kw)

    assert a.bucket_aggregates(plan("doc")) == a.bucket_aggregates(plan("canon"))
    assert sorted(a.row_hashes(plan("doc"), {0, 1, 2})) == sorted(
        a.row_hashes(plan("canon"), {0, 1, 2})
    )
    [stored] = a.fetch_rows(plan("doc"), [("1",)]).values()
    assert stored[0] == '<a b="2" a="1"><x/><y>t</y></a>'  # as SQL Server wrote it


def test_tls_settings():
    assert _tls_args("db.example", "disable", None) == {"dsn": "db.example"}
    full = _tls_args("DB.Example", "verify-full", "/ca.pem")
    assert full == {"dsn": "db.example", "cafile": "/ca.pem", "validate_host": True}
    assert _tls_args("h", "verify-ca", "/ca.pem")["validate_host"] is False
    with pytest.raises(ConfigError, match="verify-ca"):
        _tls_args("h", "require", None)


def test_float_stats(loaded):
    s = loaded.float_stats(table(), "weight")
    assert (s.count, s.non_null, s.nan_count, s.inf_count) == (5, 4, 0, 0)
    assert (s.minimum, s.maximum, s.total) == (-1.0, 2.25, 2.75)


def test_snapshot_isolation(loaded, make_sqlserver_db, sqlserver_adapter_for):
    from tests.conftest import _ms_connect

    snap = loaded.begin_snapshot()
    assert snap["type"] == "dbts" and snap["position"].startswith("0x")
    assert snap["replica"] is False
    # a change committed after the snapshot began is not seen inside it
    before = loaded.row_count(table())
    (db,) = loaded._query("SELECT DB_NAME()")[0]
    with _ms_connect(db) as other, other.cursor() as cur:
        cur.execute("DELETE FROM dbo.everything WHERE id = 3")
    assert loaded.row_count(table()) == before
    loaded.end_snapshot()
    assert loaded.row_count(table()) == before - 1
    assert loaded.session_settings()["snapshot"] == "SNAPSHOT isolation"
    assert loaded.snapshot_available()

    # without ALLOW_SNAPSHOT_ISOLATION the baseline records that it is not consistent
    off, _ = make_sqlserver_db("nosnap", snapshot=False)
    a = sqlserver_adapter_for(off)
    snap = a.begin_snapshot()
    assert snap["type"] == "none" and snap["consistent"] is False
    assert not a.snapshot_available()
    a.end_snapshot()


def test_verify_read_only(make_sqlserver_db, sqlserver_adapter_for):
    from tests.conftest import MSSQL

    db, cur = make_sqlserver_db()
    cur.execute("CREATE TABLE dbo.t (id int PRIMARY KEY)")
    assert not sqlserver_adapter_for(db).verify_read_only()  # sa is sysadmin
    login, pw = f"lp_ro_{uuid.uuid4().hex[:6]}", "Ro-" + uuid.uuid4().hex

    def check() -> bool:
        a = SQLServerAdapter(host=MSSQL["host"], port=MSSQL["port"], database=db, user=login,
                             password=pw, sslmode="disable")  # fmt: skip
        try:
            assert a.list_tables(["dbo"]) == [TableRef("dbo", "t")]
            return a.verify_read_only()
        finally:
            a.close()

    cur.execute(f"CREATE LOGIN [{login}] WITH PASSWORD = '{pw}', CHECK_POLICY = OFF")
    try:
        cur.execute(f"CREATE USER [{login}] FOR LOGIN [{login}]")
        cur.execute(f"ALTER ROLE db_datareader ADD MEMBER [{login}]")
        assert check()
        cur.execute(f"GRANT INSERT ON dbo.t TO [{login}]")
        assert not check()
        cur.execute(f"REVOKE INSERT ON dbo.t FROM [{login}]")
        cur.execute(f"ALTER ROLE db_datawriter ADD MEMBER [{login}]")
        assert not check()
    finally:
        cur.execute(f"DROP USER IF EXISTS [{login}]")
        cur.execute(f"DROP LOGIN [{login}]")


def test_bad_login_is_a_configuration_error(sqlserver_available):
    from tests.conftest import MSSQL

    with pytest.raises(ConfigError, match="cannot connect to SQL Server"):
        SQLServerAdapter(host=MSSQL["host"], port=MSSQL["port"], database="master",
                         user="nobody", password="wrong", sslmode="disable")  # fmt: skip


def test_tls_checks_the_certificate(sqlserver_available, tmp_path):
    """The test server's certificate is self signed, so an unrelated CA rejects it: the
    connection is encrypted and the chain is checked before the login is sent."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    from tests.conftest import MSSQL

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "unrelated test CA")])
    now = dt.datetime.now(dt.UTC)
    ca = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(1)
        .not_valid_before(now).not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )  # fmt: skip
    bundle = tmp_path / "ca.pem"
    bundle.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    with pytest.raises(ConfigError, match="cannot connect to SQL Server"):
        SQLServerAdapter(host=MSSQL["host"], port=MSSQL["port"], database="master",
                         user=MSSQL["user"], password=MSSQL["password"],
                         sslmode="verify-ca", sslrootcert=str(bundle))  # fmt: skip


def test_project_defaults(tmp_path):
    import yaml

    from liftproof.config import load_project

    f = tmp_path / "p.yaml"
    f.write_text(yaml.safe_dump({
        "project": "p",
        "source": {"engine": "sqlserver", "host": "src", "database": "shop"},
        "target": {"engine": "postgresql", "host": "tgt", "database": "shop"},
    }))  # fmt: skip
    p = load_project(f)
    assert p.source.port == 1433
    assert p.database.schemas == ["dbo"] and p.database.schema_map == {"dbo": "public"}
