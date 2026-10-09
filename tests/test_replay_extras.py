"""Replay extras: correlation transform chains (base64 and URL encoding between steps)
and replay windows (rows a replay created are left out of later reconciliations)."""

from __future__ import annotations

import base64
import datetime as dt
import json
from types import SimpleNamespace
from urllib.parse import quote

import pytest
import yaml

from liftproof import cli
from liftproof.adapters.base import TableRef
from liftproof.credentials import DbCredentials
from liftproof.errors import EXIT_CONFIG, EXIT_DIFFERENCES, EXIT_OK
from liftproof.findings import FindingWriter, read_findings
from liftproof.reconcile import watermark
from liftproof.reconcile.engine import ReconcileOptions, Reconciler
from liftproof.web import correlate
from liftproof.web.compare import Comparison, WebOptions
from liftproof.web.journey import Correlation, Journey
from liftproof.web.replay import JourneyRun, Replayer
from tests.conftest import PG

b64 = lambda s: base64.b64encode(s.encode()).decode()  # noqa: E731


def _ex(endpoint, *, json_body=None, html=None, request_text="", headers=None):
    return {"endpoint": endpoint, "json": json_body, "headers": headers or {},
            "body": html.encode() if html else None,
            "content_type": "text/html" if html else "application/json",
            "request_text": request_text}  # fmt: skip


# ----------------------------------------------------------- transform chains
def test_value_sent_encoded_is_used_decoded():
    ref = b64("order:48213")
    traffic = [[_ex("POST /api/orders", json_body={"ref": ref})],
               [_ex("GET /orders/{id}", request_text="/orders/order:48213")]]  # fmt: skip
    [c] = correlate.detect(traffic, [[""], [""]])
    assert (c.recorded_value, c.transforms, c.encodings) == ("order:48213", ["base64_decode"], [])
    assert c.confirmed


def test_value_used_encoded_later():
    traffic = [
        [_ex("POST /api/orders", json_body={"id": 48213})],
        [_ex("GET /track/{id}", request_text=f"/track/{b64('48213')}")],
        [_ex("GET /search", request_text="/search?q=" + quote("48213/A", safe=""))],
    ]
    [c] = correlate.detect(traffic, [[""], [""], [""]])
    assert (c.recorded_value, c.transforms, c.encodings) == ("48213", [], ["base64"])
    token = "a/b c+d=8812"
    traffic = [[_ex("GET /form", html=f'<input type="hidden" name="t" value="{token}">')],
               [_ex("POST /form", request_text="t=" + quote(token, safe=""))]]  # fmt: skip
    [c] = correlate.detect(traffic, [[""], [""]])
    assert c.encodings == ["url"] and c.transforms == []


def test_base64_inside_a_url_encoded_parameter():
    sent = quote(b64("ticket=998123"), safe="")  # the padding '=' becomes %3D
    assert "%3D" in sent
    traffic = [[_ex("GET /start", headers={}, json_body={"next": sent})],
               [_ex("GET /claim", request_text="/claim?t=ticket=998123")]]  # fmt: skip
    [c] = correlate.detect(traffic, [[""], [""]])
    assert c.transforms == ["url_decode", "base64_decode"]
    assert c.recorded_value == "ticket=998123"


def test_plain_reuse_wins_and_noise_is_not_decoded():
    # an alphanumeric id is valid base64 but is used as it is
    traffic = [[_ex("POST /a", json_body={"id": "ab12cd34ef56"})],
               [_ex("GET /b", request_text="/b/ab12cd34ef56")]]  # fmt: skip
    [c] = correlate.detect(traffic, [[""], [""]])
    assert c.transforms == [] and c.encodings == []
    assert correlate.decode("base64_decode", "deadbeef00112233") is None  # binary, not text
    assert correlate.decode("url_decode", "plain") is None
    with pytest.raises(ValueError, match="unknown transform"):
        correlate.check_chain(["rot13"], [])


def _captured(endpoint: str, body: dict):
    method, path = endpoint.split(" ", 1)
    ex = SimpleNamespace(method=method, url=path, response_headers={})
    return SimpleNamespace(exchange=ex, json=body, body=json.dumps(body).encode())


def test_replay_substitutes_every_form_and_compare_masks_them():
    c = Correlation("orders.ref", "json_path", "POST /api/orders", "$.ref", "order:48213",
                    transforms=["base64_decode"], encodings=["url", "base64"])  # fmt: skip
    journey = Journey("j", "http://t", correlations=[c])
    run = JourneyRun("j")
    sr = SimpleNamespace(exchanges=[_captured("POST /api/orders", {"ref": b64("order:77001")})])
    Replayer._correlate(None, journey, sr, run)
    assert run.values == {
        "order:48213": "order:77001",
        quote("order:48213", safe=""): quote("order:77001", safe=""),
        b64("order:48213"): b64("order:77001"),
    }
    sub = Replayer._substitute(None, f"/orders/{b64('order:48213')}?q=order%3A48213", run, {})
    assert sub == f"/orders/{b64('order:77001')}?q=order%3A77001"
    cmp = Comparison(journey, run, WebOptions(), lambda f: None, lambda a: None)
    for form in (b64("order:48213"), b64("order:77001"), "order%3A77001", "order:77001"):
        assert cmp.mask(f"x {form} y") == "x {orders.ref} y"


def test_a_journey_with_an_unknown_transform_is_refused(tmp_path, monkeypatch):
    j = Journey("j1", "http://t", correlations=[
        Correlation("x", "json_path", "GET /a", "$.x", "12345", transforms=["rot13"])])
    workdir = tmp_path / "work"
    (workdir / "journeys").mkdir(parents=True)
    j.save(workdir / "journeys" / "j1.json")
    with pytest.raises(cli.ConfigError, match="correlation x: unknown transform"):
        cli._load_journey(cli.LocalStore(tmp_path / "store"), workdir, "j1")


# ------------------------------------------------------------- replay windows
TEST_SECRET_ARN = "arn:aws:secretsmanager:ap-south-1:000000000000:secret:liftproof/test"


def _orders(n: int, start: int = 1) -> list[tuple]:
    base = dt.datetime(2026, 10, 1, 9, 0, 0)
    return [(g, "OPEN", g + 0.5, base + dt.timedelta(minutes=g)) for g in range(start, start + n)]


ENGINES = {
    "postgresql": ("CREATE TABLE orders (id int PRIMARY KEY, status text, total numeric(10,2), "
                   "placed timestamp)", "%s"),
    "mysql": ("CREATE TABLE orders (id int PRIMARY KEY, status varchar(10), "
              "total decimal(10,2), placed datetime(6))", "%s"),
    "oracle": ("CREATE TABLE orders (id NUMBER(10) PRIMARY KEY, status VARCHAR2(10), "
               "total NUMBER(10,2), placed TIMESTAMP)", ":{}"),
    "sqlserver": ("CREATE TABLE orders (id int PRIMARY KEY, status varchar(10), "
                  "total decimal(10,2), placed datetime2(6))", "%s"),
}  # fmt: skip


@pytest.fixture(params=list(ENGINES))
def engine_pair(request):
    """(adapter factory, source name, target name, insert into the target)."""
    name = request.param
    request.applymarker(getattr(pytest.mark, "postgres" if name == "postgresql" else name))
    ddl, mark = ENGINES[name]
    marks = ", ".join(mark.format(i + 1) for i in range(4))
    if name == "postgresql":
        make, adapter = request.getfixturevalue("make_db"), request.getfixturevalue("adapter_for")
    else:
        make = request.getfixturevalue(f"make_{name}_db")
        adapter = request.getfixturevalue(f"{name}_adapter_for")
    made = []
    for prefix in ("src", "tgt"):
        db, cur = make(prefix)
        if name == "postgresql":
            cur = cur.cursor()
        cur.execute(ddl)
        cur.executemany(f"INSERT INTO orders VALUES ({marks})", _orders(500))
        if name == "oracle":
            cur.connection.commit()
        made.append((db, cur))
    (src, _), (tgt, tcur) = made

    def insert(rows):
        tcur.executemany(f"INSERT INTO orders VALUES ({marks})", rows)
        if name == "oracle":
            tcur.connection.commit()

    connect = (lambda db: adapter()) if name == "oracle" else adapter
    schema = {"postgresql": lambda d: "public", "mysql": lambda d: d,
              "oracle": lambda d: d, "sqlserver": lambda d: "dbo"}[name]  # fmt: skip
    return SimpleNamespace(name=name, connect=connect, src=src, tgt=tgt, insert=insert,
                           schema=schema)  # fmt: skip


def _reconcile(tmp_path, e, ignore=(), name="f"):
    s, t = e.schema(e.src), e.schema(e.tgt)
    opts = ReconcileOptions(schemas=[s], schema_map={s: t} if s != t else {},
                            rows_per_bucket=100, ignore=list(ignore))  # fmt: skip
    writer = FindingWriter(tmp_path / name, "r")
    result = Reconciler(e.connect(e.tgt), writer, opts, source=e.connect(e.src)).run()
    writer.close()
    return result.tables[0], list(read_findings(tmp_path / name))


@pytest.mark.parametrize("column", [None, "placed"])
def test_rows_created_inside_the_replay_window_are_left_out(tmp_path, engine_pair, column):
    e = engine_pair
    target = e.connect(e.tgt)
    schema = e.schema(e.tgt)
    columns = {"orders": column} if column else {}
    tables, problems = watermark.resolve(target, [schema], ["orders"], columns)
    assert not problems and list(tables.values()) == [column.upper() if e.name == "oracle"
                                                       and column else column or
                                                       ("ID" if e.name == "oracle" else "id")]
    before = watermark.read(target, tables)
    e.insert(_orders(3, start=501))  # what the replay's journeys placed
    after = watermark.read(target, tables)
    windows = watermark.windows(tables, before, after, "r-replay")
    assert len(windows) == 1 and windows[0].kind == ("timestamp" if column else "number")

    table, _ = _reconcile(tmp_path, e)
    assert table.status == "different" and table.extra_rows == 3
    rules = watermark.rules(windows, target)
    table, findings = _reconcile(tmp_path, e, rules, name="g")
    assert table.status == "matched", [f.summary for f in findings]
    assert any("rows created by replay (r-replay)" in f.summary for f in findings)
    # a row created after the replay is still found
    e.insert(_orders(1, start=600))
    table, _ = _reconcile(tmp_path, e, rules, name="h")
    assert table.status == "different" and table.extra_rows == 1


def test_windows_after_a_target_baseline_only():
    at = "2026-10-08T{}:00:00+00:00"
    w = [watermark.Window("public.orders", "id", "10", "12", "number", "r1", at.format("09")),
         watermark.Window("public.orders", "id", "20", "25", "number", "r2", at.format(11))]
    pg = SimpleNamespace(quote_name=lambda n: f'"{n}"', literal=lambda v: str(v))
    [rule] = watermark.rules(w, pg)
    assert rule.target_where == '("id" > 10 AND "id" <= 12) OR ("id" > 20 AND "id" <= 25)'
    [rule] = watermark.rules(w, pg, since="2026-10-08T10:00:00+00:00")
    assert rule.target_where == '("id" > 20 AND "id" <= 25)' and "(r2)" in rule.reason
    assert watermark.rules(w, pg, since="2026-10-08T12:00:00+00:00") == []


@pytest.mark.postgres
def test_no_growing_key_is_reported(make_db, adapter_for):
    db, cur = make_db("t")
    cur.execute("CREATE TABLE notes (body text); CREATE TABLE tags (id text PRIMARY KEY)")
    tables, problems = watermark.resolve(adapter_for(db), ["public"], ["notes", "tags", "nope"],
                                         {})  # fmt: skip
    assert tables == {} and len(problems) == 3
    assert all("replay_watermarks" in p for p in problems[:2]) and "no such table" in problems[2]


# ------------------------------------------------- the CLI: replay, then reconcile
@pytest.fixture
def secret(monkeypatch):
    monkeypatch.setattr(cli, "from_secrets_manager",
                        lambda arn: DbCredentials(PG["user"], PG["password"]))  # fmt: skip


@pytest.mark.postgres
def test_replay_then_reconcile_leaves_replay_rows_out(tmp_path, make_db, secret, monkeypatch):
    s, sc = make_db("src")
    t, tc = make_db("tgt")
    for c in (sc, tc):
        c.execute("CREATE TABLE orders (id serial PRIMARY KEY, item text);"
                  "INSERT INTO orders (item) SELECT 'i' || g "
                  "FROM generate_series(1, 300) g")  # fmt: skip
    conn = {"engine": "postgresql", "host": PG["host"], "port": PG["port"], "user": PG["user"],
            "sslmode": "disable", "secret_arn": TEST_SECRET_ARN}  # fmt: skip
    project = tmp_path / "acme.yaml"
    project.write_text(yaml.safe_dump({
        "project": "acme", "source": dict(conn, database=s), "target": dict(conn, database=t),
        "database": {"rows_per_bucket": 100},
        "web": {"source_url": "http://src.invalid", "target_url": "http://tgt.invalid"},
    }))  # fmt: skip
    work = tmp_path / "work"
    jdir = work / "acme" / "journeys"
    jdir.mkdir(parents=True)
    Journey("checkout", "http://src.invalid", writes_tables=["orders"]).save(jdir / "checkout.json")

    def fake_replay(journeys, **kw):  # the journeys place two orders on the target
        tc.execute("INSERT INTO orders (item) VALUES ('replayed'), ('replayed')")
        from liftproof.web.run import WebResult

        return WebResult(target_url=kw["target_url"])

    monkeypatch.setattr("liftproof.web.run.run_journeys", fake_replay)
    argv = ["--project", str(project), "--workdir", str(work), "--format", "json"]
    cli.main(["replay", *argv, "--run-id", "rp1"])
    assert cli.main(["reconcile", *argv, "--run-id", "rc1"]) == EXIT_OK
    assert cli.main(["reconcile", *argv, "--include-replay-rows"]) == EXIT_DIFFERENCES
    run_dir = work / "acme" / "runs" / "rc1"
    findings = [json.loads(line) for f in sorted(run_dir.glob("findings-*"))
                for line in f.read_text().splitlines()]  # fmt: skip
    assert any("rows created by replay (rp1)" in f["summary"] for f in findings)


def test_replay_watermarks_must_be_a_mapping(tmp_path):
    conn = {"engine": "postgresql", "host": "a", "database": "a", "secret_arn": TEST_SECRET_ARN}
    p = tmp_path / "p.yaml"
    p.write_text(yaml.safe_dump({"project": "p", "source": conn, "target": conn,
                                 "database": {"replay_watermarks": ["orders"]}}))  # fmt: skip
    argv = ["reconcile", "--project", str(p), "--workdir", str(tmp_path / "w")]
    assert cli.main(argv) == EXIT_CONFIG


def test_table_refs_are_resolved_case_insensitively():
    target = SimpleNamespace(
        list_tables=lambda schemas: [TableRef("APP", "ORDERS")],
        describe=lambda t: SimpleNamespace(
            primary_key=["ID"],
            column=lambda n: SimpleNamespace(name="ID", canonical=correlate_type()),
        ),
    )
    tables, problems = watermark.resolve(target, ["APP"], ["orders"], {})
    assert tables == {TableRef("APP", "ORDERS"): "ID"} and problems == []


def correlate_type():
    from liftproof.canonical import CanonicalType

    return CanonicalType.INTEGER



def test_since_compares_times_not_text():
    # stored times differ in precision and offset: a baseline taken half a second after
    # the r1 window, written in +05:30, still comes after it
    w = [watermark.Window("public.orders", "id", "1", "5", "number", "r1",
                          "2026-10-09T04:00:00+00:00"),
         watermark.Window("public.orders", "id", "5", "9", "number", "r2",
                          "2026-10-09T04:00:01+00:00")]  # fmt: skip
    pg = SimpleNamespace(quote_name=lambda n: f'"{n}"', literal=lambda v: str(v))
    [rule] = watermark.rules(w, pg, since="2026-10-09T09:30:00.500000+05:30")
    assert "(r2)" in rule.reason


def test_a_target_outage_does_not_fail_the_replay(tmp_path, monkeypatch):
    conn = {"engine": "postgresql", "host": "db.invalid", "user": "u", "database": "d"}
    project = tmp_path / "acme.yaml"
    project.write_text(yaml.safe_dump({
        "project": "acme", "source": conn, "target": conn,
        "web": {"source_url": "http://src.invalid", "target_url": "http://tgt.invalid"},
    }))  # fmt: skip
    work = tmp_path / "work"
    jdir = work / "acme" / "journeys"
    jdir.mkdir(parents=True)
    Journey("checkout", "http://src.invalid", writes_tables=["orders"]).save(jdir / "checkout.json")

    def down(c):
        raise OSError("connection refused")

    def fake_replay(journeys, **kw):
        from liftproof.web.run import WebResult

        return WebResult(target_url=kw["target_url"])

    monkeypatch.setattr(cli, "connect", down)
    monkeypatch.setattr("liftproof.web.run.run_journeys", fake_replay)
    argv = ["--project", str(project), "--workdir", str(work), "--format", "json"]
    assert cli.main(["replay", *argv, "--run-id", "rp1"]) == EXIT_OK
    run_dir = work / "acme" / "runs" / "rp1"
    text = "".join(f.read_text() for f in run_dir.glob("findings-*"))
    assert "replay rows cannot be marked: connection refused" in text
