"""File sets from Azure Blob Storage, and from the files a database table holds.

Azure is served here by a small stand in for the Blob service REST API (List Blobs, Get
Blob, a SAS checked on every request); the table by SQLite and PostgreSQL databases that
hold each file in a column, as an application that stored its uploads in the database did.
"""

from __future__ import annotations

import base64
import json
import sqlite3
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from xml.sax.saxutils import escape

import pytest
import yaml

from liftproof import cli
from liftproof.adapters.sqlite import SQLiteAdapter
from liftproof.config import load_project
from liftproof.errors import ConfigError
from liftproof.files.compare import FileSetConfig, compare_files
from liftproof.files.rows import RowFiles, open_rows
from liftproof.files.sources import AzureBlobSource, LocalSource, is_azure, open_source
from liftproof.findings import Kind

SAS = "sv=2022-11-02&ss=b&srt=co&sp=rl&se=2099-01-01T00:00:00Z&sig=test%2Bsig"


# ------------------------------------------------------------------ Azure Blob Storage
class FakeBlobService(BaseHTTPRequestHandler):
    blobs: dict[str, dict[str, bytes]] = {}  # container -> name -> content
    folders: set[str] = set()  # names that are hierarchical namespace folders
    page = 2  # results per listing page, to exercise NextMarker
    requests: list[str] = []

    def log_message(self, *args):  # quiet
        pass

    def _fail(self, status: int, code: str) -> None:
        body = f"<?xml version='1.0'?><Error><Code>{code}</Code></Error>".encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        url = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(url.query)
        self.requests.append(self.path)
        if q.get("sig") != ["test+sig"] or self.headers.get("x-ms-version") is None:
            return self._fail(403, "AuthenticationFailed")
        container, _, name = url.path.lstrip("/").partition("/")
        if container not in self.blobs:
            return self._fail(404, "ContainerNotFound")
        blobs = self.blobs[container]
        if not name:
            assert q["restype"] == ["container"] and q["comp"] == ["list"]
            prefix = q.get("prefix", [""])[0]
            names = sorted(n for n in [*blobs, *self.folders] if n.startswith(prefix))
            start = int(q.get("marker", ["0"])[0])
            chunk = names[start : start + self.page]
            more = start + self.page < len(names)
            items = "".join(
                f"<Blob><Name>{escape(n)}</Name><Properties><Content-Length>"
                f"{len(blobs.get(n, b''))}</Content-Length></Properties><Metadata>"
                + ("<hdi_isfolder>true</hdi_isfolder>" if n in self.folders else "")
                + "</Metadata></Blob>"
                for n in chunk
            )
            body = (
                "<?xml version='1.0' encoding='utf-8'?><EnumerationResults><Blobs>"
                f"{items}</Blobs><NextMarker>{start + self.page if more else ''}</NextMarker>"
                "</EnumerationResults>"
            ).encode()
        else:
            name = urllib.parse.unquote(name)
            if name not in blobs:
                return self._fail(404, "BlobNotFound")
            body = blobs[name]
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):  # noqa: N802 - Get Blob Properties
        self.do_GET()


@pytest.fixture
def azure():
    FakeBlobService.blobs = {
        "uploads": {
            "photos/a.jpg": b"\xff\xd8 photo a",
            "photos/b b.jpg": b"\xff\xd8 photo b",
            "kyc/doc1.pdf": b"%PDF-1.4 one",
            "kyc/doc2.pdf": b"%PDF-1.4 two",
            "kyc/notes.csv": b"id,v\n1,2\n",
        }
    }
    FakeBlobService.folders = {"kyc", "photos"}
    FakeBlobService.requests = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeBlobService)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def test_azure_listing_pages_and_skips_folders(azure):
    src = AzureBlobSource(f"{azure}/uploads", SAS)
    assert sorted((e.path, e.size) for e in src.entries()) == [
        ("kyc/doc1.pdf", 12), ("kyc/doc2.pdf", 12), ("kyc/notes.csv", 9),
        ("photos/a.jpg", 10), ("photos/b b.jpg", 10),
    ]  # fmt: skip
    assert sum("comp=list" in r for r in FakeBlobService.requests) == 4  # 7 names, 2 a page
    with src.open("photos/b b.jpg") as f:
        assert f.read() == b"\xff\xd8 photo b"
    kyc = AzureBlobSource(f"{azure}/uploads/kyc", "?" + SAS)
    assert sorted(e.path for e in kyc.entries()) == ["doc1.pdf", "doc2.pdf", "notes.csv"]


def test_azure_errors_say_what_to_fix(azure):
    with pytest.raises(ConfigError, match="403 AuthenticationFailed.*Read and List"):
        list(AzureBlobSource(f"{azure}/uploads", SAS.replace("test%2Bsig", "wrong")).entries())
    with pytest.raises(ConfigError, match="404 ContainerNotFound"):
        list(AzureBlobSource(f"{azure}/missing", SAS).entries())
    with pytest.raises(ConfigError, match="not reachable"):
        list(AzureBlobSource("http://127.0.0.1:9/uploads", SAS, timeout=2).entries())
    with pytest.raises(ConfigError, match="starts with https://"):
        AzureBlobSource("http://example.test/uploads", SAS)
    with pytest.raises(ConfigError, match="give its secret_arn"):
        open_source("https://acct.blob.core.windows.net/uploads")
    assert is_azure("https://acct.blob.core.windows.net/uploads/x")
    assert not is_azure("https://example.test/uploads")


def test_azure_to_s3_like_tree_is_compared(azure, tmp_path, monkeypatch):
    tgt = tmp_path / "s3"
    for name, data in FakeBlobService.blobs["uploads"].items():
        (tgt / name).parent.mkdir(parents=True, exist_ok=True)
        (tgt / name).write_bytes(data)
    (tgt / "kyc" / "doc2.pdf").write_bytes(b"%PDF-1.4 TWO")
    (tgt / "photos" / "a.jpg").unlink()
    monkeypatch.setattr("liftproof.credentials.secret_value", lambda arn, key: SAS)
    config = FileSetConfig("uploads", f"{azure}/uploads", str(tgt), source_kind="azure_blob",
                           source_secret_arn="arn:secret")  # fmt: skip
    found = []

    def side(c, which):
        if which == "source":
            return open_source(c.source, secret_arn=c.source_secret_arn, kind=c.source_kind)
        return LocalSource(c.target)

    result = compare_files([config], found.append, side)
    [s] = result.sets
    assert (s.files, s.matched, s.different, s.missing) == (5, 3, 1, 1)


def test_project_file_azure_sides(tmp_path):
    p = tmp_path / "p.yaml"
    doc = {"project": "x", "files": [{"name": "uploads", "target": "s3://b/uploads/", "source": {
        "location": "https://acct.blob.core.windows.net/uploads",
        "secret_arn": "arn:aws:secretsmanager:ap-south-1:1:secret:azure"}}]}  # fmt: skip
    p.write_text(yaml.safe_dump(doc))
    [fs] = load_project(p).files
    assert fs.source_kind == "azure_blob" and fs.source_secret_arn.endswith(":azure")
    doc["files"][0]["source"] = {"location": "http://127.0.0.1:10000/uploads",
                                 "kind": "azure_blob", "secret_arn": "arn:s"}  # fmt: skip
    p.write_text(yaml.safe_dump(doc))
    assert load_project(p).files[0].source_kind == "azure_blob"
    doc["files"][0]["source"] = {"location": "https://acct.blob.core.windows.net/uploads"}
    p.write_text(yaml.safe_dump(doc))
    with pytest.raises(ConfigError, match="SAS token"):
        load_project(p)


# ------------------------------------------------------------------ files in a table
DOCS = [
    (1, "asha.pdf", b"%PDF-1.4 asha"),
    (2, "ben.docx", b"PK\x03\x04 ben"),
    (3, "chen.pdf", b"%PDF-1.4 chen"),
    (4, "dana.txt", "Dana Ñúñez\nengineer\n".encode()),
    (5, "empty.pdf", None),  # a row without a file
]


@pytest.fixture
def docs_db(tmp_path):
    path = tmp_path / "app.db"
    c = sqlite3.connect(path)
    c.execute("CREATE TABLE documents (id INTEGER PRIMARY KEY, file_name TEXT, data BLOB, "
              "data64 TEXT, deleted INTEGER DEFAULT 0)")  # fmt: skip
    c.executemany(
        "INSERT INTO documents (id, file_name, data, data64) VALUES (?, ?, ?, ?)",
        [(i, n, d, base64.b64encode(d).decode() if d else None) for i, n, d in DOCS],
    )
    c.execute("INSERT INTO documents VALUES (6, 'gone.pdf', x'00', 'AA==', 1)")
    c.commit()
    c.close()
    return path


@pytest.fixture
def bucket_tree(tmp_path):
    """The objects a migration wrote: documents/<id>/<file_name>."""
    root = tmp_path / "bucket"
    for i, name, data in DOCS:
        if data is not None:
            (root / str(i)).mkdir(parents=True)
            (root / str(i) / name).write_bytes(data)
    return root


def _rows_source(db, **kw):
    config = RowFiles("source", kw.pop("table", "documents"), kw.pop("content", "data"),
                      kw.pop("path", "{id}/{file_name}"), **kw)  # fmt: skip
    return open_rows(config, lambda database: (SQLiteAdapter(path=str(db)), "main"))


def _compare(source, target):
    found = []
    sets = [FileSetConfig("docs", "source database", str(target))]
    result = compare_files(
        sets, found.append, lambda c, w: source if w == "source" else LocalSource(target)
    )
    return result.sets[0], found


@pytest.mark.parametrize("encoding", ["binary", "base64"])
def test_files_in_a_table_match_their_objects(docs_db, bucket_tree, encoding):
    content = "data" if encoding == "binary" else "data64"
    src = _rows_source(docs_db, content=content, encoding=encoding, where="deleted = 0")
    s, found = _compare(src, bucket_tree)
    assert (s.files, s.matched, s.different, s.missing, s.extra) == (4, 4, 0, 0, 0)
    [note] = [f for f in found if f.kind == Kind.NOTICE]
    assert "1 row(s) of main.documents hold no file" in note.summary
    assert not src._files  # closed after the set: the spooled copies are gone


def test_a_changed_or_missing_file_is_reported(docs_db, bucket_tree):
    (bucket_tree / "3" / "chen.pdf").write_bytes(b"%PDF-1.4 CHEN")
    (bucket_tree / "2" / "ben.docx").unlink()
    (bucket_tree / "9").mkdir()
    (bucket_tree / "9" / "stray.pdf").write_bytes(b"x")
    s, found = _compare(_rows_source(docs_db, where="deleted = 0"), bucket_tree)
    assert (s.matched, s.different, s.missing, s.extra) == (2, 1, 1, 1)
    assert {f.object for f in found if f.kind == Kind.DIFFERENCE} == {
        "docs:3/chen.pdf", "docs:2/ben.docx", "docs:9/stray.pdf"
    }  # fmt: skip


def test_rows_that_give_one_path_or_bad_content_are_not_checked(docs_db, bucket_tree):
    c = sqlite3.connect(docs_db)
    c.execute("UPDATE documents SET data64 = 'not base64!' WHERE id = 3")
    c.commit()
    c.close()
    _, found = _compare(_rows_source(docs_db, content="data64", encoding="base64",
                                     where="deleted = 0"), bucket_tree)  # fmt: skip
    [bad] = [f for f in found if f.kind == Kind.NOT_CHECKED]
    assert bad.object == "docs:3/chen.pdf" and "content is not base64" in bad.summary
    _, found = _compare(_rows_source(docs_db, path="{deleted}"), bucket_tree)
    assert (
        sorted(f.summary for f in found if f.kind == Kind.NOT_CHECKED)
        == ["source file path given by more than one row of the table"] * 3
    )
    with pytest.raises(ConfigError, match="file_nme not a column"):
        list(_rows_source(docs_db, path="{id}/{file_nme}").entries())


@pytest.mark.postgres
def test_files_in_a_postgresql_table(make_db, adapter_for, bucket_tree):
    db, conn = make_db("rows")
    conn.execute("CREATE TABLE documents (id int PRIMARY KEY, file_name text, data bytea)")
    with conn.cursor() as cur:
        cur.executemany("INSERT INTO documents VALUES (%s, %s, %s)", DOCS)
    config = RowFiles("source", "documents", "data", "{id}/{file_name}")
    src = open_rows(config, lambda database: (adapter_for(db), "public"))
    s, _ = _compare(src, bucket_tree)
    assert (s.files, s.matched) == (4, 4)


def test_project_file_database_sides(tmp_path, docs_db, bucket_tree, capsys):
    p = tmp_path / "p.yaml"
    doc = {
        "project": "app",
        "source": {"engine": "sqlite", "path": str(docs_db)},
        "files": [{"name": "docs", "target": str(bucket_tree), "source": {
            "database": "source", "table": "documents", "content": "data",
            "path": "{id}/{file_name}", "where": "deleted = 0"}}],
    }  # fmt: skip
    p.write_text(yaml.safe_dump(doc))
    [fs] = load_project(p).files
    assert fs.source_rows == RowFiles("source", "documents", "data", "{id}/{file_name}",
                                      "deleted = 0")  # fmt: skip
    work = ["--project", str(p), "--workdir", str(tmp_path / "w"), "--format", "json"]
    assert cli.main(["files", *work, "--run-id", "f1"]) == 0
    assert json.loads(capsys.readouterr().out)["counts"]["files"] == 4
    for bad, says in [
        ({"database": "elsewhere"}, "database is source or target"),
        ({"database": "source", "table": "t"}, "give content"),
        ({"database": "source", "content": "c"}, "table, path required"),
        ({"database": "source", "table": "t", "content": "c", "object": "s3://b/{k}",
          "path": "{id}"}, "not both"),
        ({"database": "source", "table": "t", "content": "c", "path": "{id}",
          "object_map": ["a", "b"]}, "apply to object"),
        ({"database": "source", "table": "t", "object": "s3://b/k", "path": "{id}"},
         "object 's3://b/k' is not a template"),
        ({"database": "source", "table": "t", "object": "{u}", "path": "{id}",
          "object_map": ["(", "x"]}, "not a valid regular expression"),
        ({"database": "source", "table": "t", "object": "{u}", "path": "{id}",
          "kind": "azure_blob"}, "SAS token"),
        ({"database": "source", "table": "t", "object": "s3://b/{k}", "path": "{id}",
          "secret_arn": "arn:aws:secretsmanager:x"}, "instance role"),
        ({"database": "source", "table": "t", "content": "c", "path": "fixed"},
         "names no column"),
        ({"database": "source", "table": "t", "content": "c", "path": "{id}",
          "where": "1=1; DROP TABLE t"}, "one SQL condition"),
        ({"database": "source", "table": "t", "content": "c", "path": "{id}",
          "encoding": "hex"}, "encoding is one of"),
    ]:  # fmt: skip
        doc["files"][0]["source"] = bad
        p.write_text(yaml.safe_dump(doc))
        with pytest.raises(ConfigError, match=says):
            load_project(p)


@pytest.mark.mysql
def test_files_in_a_mysql_table(make_mysql_db, mysql_adapter_for, bucket_tree):
    db, cur = make_mysql_db("rows")
    cur.execute("CREATE TABLE documents (id int PRIMARY KEY, file_name varchar(40), data longblob)")
    cur.executemany("INSERT INTO documents VALUES (%s, %s, %s)", DOCS)
    config = RowFiles("source", "documents", "data", "{id}/{file_name}")
    src = open_rows(config, lambda database: (mysql_adapter_for(db), db))
    s, _ = _compare(src, bucket_tree)
    assert (s.files, s.matched) == (4, 4)


@pytest.mark.oracle
def test_files_in_an_oracle_table(make_oracle_db, oracle_adapter_for, bucket_tree):
    schema, cur = make_oracle_db("rows")
    cur.execute("CREATE TABLE documents (id NUMBER(10) PRIMARY KEY, file_name VARCHAR2(40), "
                "data BLOB)")  # fmt: skip
    cur.executemany("INSERT INTO documents VALUES (:1, :2, :3)", DOCS)
    # unquoted Oracle names are stored upper case, and are named so
    config = RowFiles("source", f"{schema}.DOCUMENTS", "DATA", "{ID}/{FILE_NAME}")
    src = open_rows(config, lambda database: (oracle_adapter_for(), schema))
    s, _ = _compare(src, bucket_tree)
    assert (s.files, s.matched) == (4, 4)


@pytest.mark.sqlserver
def test_files_in_a_sqlserver_table(make_sqlserver_db, sqlserver_adapter_for, bucket_tree):
    db, cur = make_sqlserver_db("rows")
    cur.execute("CREATE TABLE documents (id int PRIMARY KEY, file_name nvarchar(40), "
                "data varbinary(max))")  # fmt: skip
    import pytds

    # python-tds binds bytes and None as nvarchar, which varbinary refuses
    cur.executemany("INSERT INTO documents VALUES (%s, %s, %s)",
                    [(i, n, pytds.Binary(d)) for i, n, d in DOCS if d])  # fmt: skip
    cur.execute("INSERT INTO documents VALUES (5, 'empty.pdf', NULL)")
    config = RowFiles("source", "documents", "data", "{id}/{file_name}")
    src = open_rows(config, lambda database: (sqlserver_adapter_for(db), "dbo"))
    s, _ = _compare(src, bucket_tree)
    assert (s.files, s.matched) == (4, 4)


# ------------------------------------------------- files a database row names by location
CV_KEYS = {1: "cvs/7f3a.pdf", 2: "cvs/91bc.docx", 3: "cvs/0d2e.pdf", 4: "cvs/c4d1.txt"}


@pytest.fixture
def named_db(tmp_path):
    """The target side after the move: each row names its file's object, under a key the
    migration chose, not one the source's rows give."""
    path = tmp_path / "target.db"
    c = sqlite3.connect(path)
    c.execute("CREATE TABLE candidates (id INTEGER PRIMARY KEY, cv_key TEXT, cv_url TEXT)")
    c.executemany("INSERT INTO candidates VALUES (?, ?, ?)", [
        (i, k, f"https://cdn.example.com/{k}?Expires=1&Signature=abc&Key-Pair-Id=K")
        for i, k in CV_KEYS.items()
    ])  # fmt: skip
    c.execute("INSERT INTO candidates VALUES (5, NULL, NULL)")
    c.commit()
    c.close()
    return path


def _named(db, obj, **kw):
    config = RowFiles("target", "candidates", None, "{id}", object=obj, **kw)
    return open_rows(config, lambda database: (SQLiteAdapter(path=str(db)), "main"))


def _sides(source, target):
    found = []
    sets = [FileSetConfig("cvs", "source database", "target database")]
    result = compare_files(sets, found.append, lambda c, w: source if w == "source" else target)
    return result.sets[0], found


def _put_objects(put):
    data = {i: d for i, _, d in DOCS}
    for i, key in CV_KEYS.items():
        put(key, data[i])


def test_files_a_row_names_are_compared_with_the_files_a_row_holds(docs_db, named_db,
                                                                    tmp_path):  # fmt: skip
    store = tmp_path / "store"
    _put_objects(lambda k, d: ((store / k).parent.mkdir(parents=True, exist_ok=True),
                               (store / k).write_bytes(d)))  # fmt: skip
    src = _rows_source(docs_db, path="{id}", where="deleted = 0")
    tgt = _named(named_db, f"{store}/{{cv_key}}")
    s, found = _sides(src, tgt)
    assert (s.files, s.matched, s.different, s.missing, s.extra) == (4, 4, 0, 0, 0)
    notes = sorted(f.summary for f in found if f.kind == Kind.NOTICE)
    assert any("1 row(s) of main.candidates name no file (cv_key is NULL" in n for n in notes)
    assert not tgt._objects  # closed after the set

    # a changed object, and a row that names one no longer there
    (store / CV_KEYS[3]).write_bytes(b"%PDF-1.4 CHEN")
    (store / CV_KEYS[2]).unlink()
    s, found = _sides(_rows_source(docs_db, path="{id}", where="deleted = 0"),
                      _named(named_db, f"{store}/{{cv_key}}"))  # fmt: skip
    assert (s.matched, s.different, s.missing) == (2, 1, 1)
    assert {f.object for f in found if f.kind == Kind.DIFFERENCE} == {"cvs:3", "cvs:2"}
    assert any("1 row(s) of main.candidates name an object that does not exist: 2"
               in f.summary for f in found if f.kind == Kind.NOTICE)  # fmt: skip


def test_files_a_row_names_in_s3_by_key_or_by_url(docs_db, named_db, monkeypatch):
    boto3 = pytest.importorskip("boto3")
    moto = pytest.importorskip("moto")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    with moto.mock_aws():
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="lp-cvs")
        _put_objects(lambda k, d: s3.put_object(Bucket="lp-cvs", Key=k, Body=d))
        for obj, kw in [
            ("s3://lp-cvs/{cv_key}", {}),
            # a CDN link with its signature: object_map turns it into the object
            ("{cv_url}", {"object_map": (r"^https://cdn\.example\.com/([^?]*).*$",
                                         r"s3://lp-cvs/\1")}),
            ("https://lp-cvs.s3.us-east-1.amazonaws.com/{cv_key}?X-Amz-Signature=1", {}),
        ]:  # fmt: skip
            src = _rows_source(docs_db, path="{id}", where="deleted = 0")
            s, found = _sides(src, _named(named_db, obj, **kw))
            assert (s.files, s.matched, s.missing) == (4, 4, 0), obj
        s, found = _sides(_rows_source(docs_db, path="{id}", where="deleted = 0"),
                          _named(named_db, "{cv_url}"))  # fmt: skip
        assert {f.object for f in found if f.kind == Kind.NOT_CHECKED} >= {"cvs:1"}
        assert any("turn the URL into one with object_map" in f.summary for f in found)


def test_files_a_row_names_in_azure(docs_db, tmp_path, azure, monkeypatch):
    monkeypatch.setattr("liftproof.credentials.secret_value", lambda arn, key: SAS)
    db = tmp_path / "t.db"
    c = sqlite3.connect(db)
    c.execute("CREATE TABLE candidates (id INTEGER PRIMARY KEY, url TEXT)")
    data = {i: d for i, _, d in DOCS}
    FakeBlobService.blobs["cvs"] = {f"in/{i} cv.bin": d for i, d in data.items() if d}
    c.executemany("INSERT INTO candidates VALUES (?, ?)",
                  [(i, f"{azure}/cvs/in/{i}%20cv.bin") for i in (1, 2, 3, 4)])  # fmt: skip
    c.commit()
    c.close()
    config = RowFiles("target", "candidates", None, "{id}", object="{url}",
                      secret_arn="arn:aws:secretsmanager:x", kind="azure_blob")  # fmt: skip
    tgt = open_rows(config, lambda database: (SQLiteAdapter(path=str(db)), "main"))
    s, _ = _sides(_rows_source(docs_db, path="{id}", where="deleted = 0"), tgt)
    assert (s.files, s.matched, s.missing) == (4, 4, 0)
    assert sum(r.startswith("/cvs/in/") for r in FakeBlobService.requests) == 8  # HEAD + GET


def test_split_location():
    from liftproof.files.sources import split_location

    assert split_location("s3://b/k/a?b#c.pdf") == ("s3://b", "k/a?b#c.pdf")
    assert split_location("gs://b/m/x.jpg") == ("s3://b", "m/x.jpg")
    assert split_location("https://b.s3.ap-south-1.amazonaws.com/cv/1.pdf?X-Amz-Signature=1"
                          ) == ("s3://b", "cv/1.pdf")  # fmt: skip
    assert split_location("https://s3.ap-south-1.amazonaws.com/b/cv/1.pdf") == (
        "s3://b",
        "cv/1.pdf",
    )
    assert split_location("https://storage.googleapis.com/bkt/m/x%20y.jpg?X-Goog-Signature=a"
                          ) == ("s3://bkt", "m/x y.jpg")  # fmt: skip
    assert split_location("https://acct.blob.core.windows.net/up/kyc/1.png?sv=1&sig=x") == (
        "https://acct.blob.core.windows.net/up",
        "kyc/1.png",
    )
    assert split_location("/data/x.pdf") == ("/", "data/x.pdf")
    for bad in ("https://cdn.example.com/x", "x/y", "s3://b", "ftp://h/x"):
        with pytest.raises(ConfigError):
            split_location(bad)


def test_project_file_object_side(tmp_path, docs_db):
    p = tmp_path / "p.yaml"
    p.write_text(yaml.safe_dump({
        "project": "app",
        "source": {"engine": "sqlite", "path": str(docs_db)},
        "target": {"engine": "postgresql", "host": "h", "database": "d"},
        "files": [{"name": "cvs",
                   "source": {"database": "source", "table": "documents", "content": "data",
                              "path": "{id}"},
                   "target": {"database": "target", "table": "candidates", "path": "{id}",
                              "object": "{cv_url}",
                              "object_map": ["^https://cdn/", "s3://lp-cvs/"]}}],
    }))  # fmt: skip
    [fs] = load_project(p).files
    assert fs.target_rows == RowFiles(
        "target",
        "candidates",
        None,
        "{id}",
        object="{cv_url}",
        object_map=("^https://cdn/", "s3://lp-cvs/"),
    )


# ------------------------------------------- S3 compatible stores (Google Cloud Storage)
def test_a_store_outside_aws_is_listed_and_signed_as_they_all_accept():
    from botocore.stub import Stubber

    from liftproof import aws
    from liftproof.files.sources import S3Source

    c = aws.client(
        "s3",
        endpoint_url="https://storage.googleapis.com",
        credentials={"aws_access_key_id": "GOOG1E", "aws_secret_access_key": "x"},
    )
    assert c.meta.region_name == aws.STORE_REGION
    assert c.meta.config.s3["addressing_style"] == "path"
    assert c.meta.config.request_checksum_calculation == "when_required"
    assert c.meta.config.response_checksum_validation == "when_required"
    src = S3Source("media", "m", endpoint_url="https://storage.googleapis.com", client=c)
    with Stubber(c) as stub:
        stub.add_response("list_objects", {"Contents": [{"Key": "m/a.jpg", "Size": 3}],
                                           "IsTruncated": False},
                          {"Bucket": "media", "Prefix": "m/"})  # fmt: skip
        stub.add_client_error(
            "head_object",
            "404",
            http_status_code=404,
            expected_params={"Bucket": "media", "Key": "m/b.jpg"},
        )
        assert [(e.path, e.size) for e in src.entries()] == [("a.jpg", 3)]
        assert src.stat("b.jpg") is None
    assert aws.client("s3", "ap-south-1").meta.region_name == "ap-south-1"  # AWS: as given
