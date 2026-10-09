"""The local web UI: who may use it, what it starts, and what it shows. The UI starts the
CLI as its own process; most tests record the command line instead, and one runs it."""

from __future__ import annotations

import http.client
import json
import os
import stat
import threading
import time
from pathlib import Path
from urllib.parse import urlencode

import pytest
import yaml

from liftproof import cli
from liftproof.errors import ConfigError
from liftproof.ui.server import LOGINS, UI, make_server, new_login
from liftproof.web.journey import Correlation, Journey, SecretBinding, Step

ARN = "arn:aws:secretsmanager:ap-south-1:123456789012:secret:shop/login-AbCdEf"


class Done:
    def __init__(self, code: int = 0):
        self.code = code

    def poll(self):
        return self.code


class Launches:
    """Stands in for subprocess.Popen: keeps the command lines and environments."""

    def __init__(self):
        self.calls: list[tuple[list[str], dict[str, str]]] = []

    def __call__(self, argv, out, env):
        self.calls.append((argv, env))
        out.write(b"started\n")
        return Done(10)


@pytest.fixture
def site(tmp_path):
    projects = tmp_path / "projects"
    projects.mkdir()
    (projects / "acme.yaml").write_text(yaml.safe_dump({
        "project": "acme",
        "files": [{"name": "docs", "source": str(tmp_path / "a"), "target": str(tmp_path / "b")}],
        "web": {"source_url": "http://src.invalid", "target_url": "http://tgt.invalid"},
    }))  # fmt: skip
    (projects / "broken.yaml").write_text("project: [")
    launches = Launches()
    ui = UI(projects, projects, launch=launches)
    server = make_server(ui, port=0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield Client(server.server_address[1], projects), ui, launches
    server.shutdown()
    server.server_close()


class Client:
    def __init__(self, port: int, workdir: Path):
        self.port, self.workdir = port, workdir
        self.cookies: dict[str, str] = {}

    def request(self, method, path, form=None, host=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = {"Host": host or f"127.0.0.1:{self.port}", **(headers or {})}
        if self.cookies:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        body = None
        if form is not None:
            body = urlencode(form)
            h["Content-Type"] = "application/x-www-form-urlencoded"
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        data = r.read().decode("utf-8", "replace")
        for k, v in r.getheaders():
            if k.lower() == "set-cookie":
                name, _, rest = v.partition("=")
                self.cookies[name] = rest.split(";", 1)[0]
        c.close()
        return r, data

    def login(self):
        r, _ = self.request("GET", f"/login?code={new_login(self.workdir)}")
        assert r.status == 303
        return self

    def csrf(self, path="/"):
        _, page = self.request("GET", path)
        marker = 'name="csrf" value="'
        return page.split(marker, 1)[1].split('"', 1)[0]

    def post(self, path, form, **kw):
        return self.request("POST", path, {"csrf": self.csrf(), **form}, **kw)


def test_one_time_login_links(site):
    client, ui, _ = site
    r, page = client.request("GET", "/")
    assert r.status == 401 and "ui-login" in page
    r, _ = client.request("GET", "/login?code=" + "x" * 32)
    assert r.status == 401 and not client.cookies
    code = new_login(ui.workdir)
    [stored] = (ui.workdir / LOGINS).iterdir()
    assert code not in stored.name and stat.S_IMODE(stored.stat().st_mode) == 0o600
    r, _ = client.request("GET", f"/login?code={code}")
    assert r.status == 303 and "HttpOnly" in r.getheader("Set-Cookie")
    r, page = client.request("GET", "/")
    assert r.status == 200 and "/p/acme" in page and "Cannot be read" in page
    assert r.getheader("Content-Security-Policy").startswith("default-src 'none'")
    assert r.getheader("X-Frame-Options") == "DENY"
    other = Client(client.port, ui.workdir)  # the same link a second time
    r, _ = other.request("GET", f"/login?code={code}")
    assert r.status == 401 and not other.cookies
    old = new_login(ui.workdir)  # out of date
    for f in (ui.workdir / LOGINS).iterdir():
        os.utime(f, (time.time() - 3600, time.time() - 3600))
    r, _ = other.request("GET", f"/login?code={old}")
    assert r.status == 401
    other.cookies = {"liftproof_ui": "made-up"}
    r, _ = other.request("GET", "/")
    assert r.status == 401


def test_ui_login_command(tmp_path, capsys):
    assert cli.main(["ui-login", "--workdir", str(tmp_path), "--format", "json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["login_url"].startswith("http://127.0.0.1:8080/login?code=")
    assert (out["valid_minutes"], out["uses"]) == (10, 1)
    ui = UI(tmp_path, tmp_path)
    code = out["login_url"].split("code=")[1]
    assert ui.spend(code) and ui.spend(code) is None


def test_other_host_names_are_refused(site):
    client, _, _ = site
    client.login()
    port = client.port
    for host in (f"evil.example:{port}", "127.0.0.1:1", f"127.0.0.1.nip.io:{port}"):
        r, _ = client.request("GET", "/", host=host)
        assert r.status == 421, host
    r, _ = client.request("GET", "/", host=f"localhost:{client.port}")
    assert r.status == 200


def test_forms_need_their_token_and_this_origin(site):
    client, _, launches = site
    client.login()
    r, _ = client.request("POST", "/p/acme/start", {"command": "files"})
    assert r.status == 403
    r, _ = client.post("/p/acme/start", {"command": "files"},
                       headers={"Origin": "https://evil.example"})  # fmt: skip
    assert r.status == 403 and not launches.calls


def test_a_run_is_the_cli_with_the_options_that_apply(site):
    client, ui, launches = site
    client.login()
    r, _ = client.post("/name", {"name": "Hema D", "back": "/p/acme"})
    assert r.status == 303 and r.getheader("Location") == "/p/acme"
    form = {"command": "reconcile", "baseline": "latest", "tables": "orders,lines",
            "no_source": "1", "journeys": "checkout", "sets": ""}  # fmt: skip
    r, _ = client.post("/p/acme/start", form)
    assert r.status == 303
    argv, env = launches.calls[-1]
    assert argv[3:5] == ["reconcile", "--project"] and argv[5].endswith("acme.yaml")
    assert argv[8:15] == ["--baseline", "latest", "--tables", "orders,lines", "--no-source",
                          "--run-id", argv[14]]  # fmt: skip
    assert "--journeys" not in argv  # reconcile takes no journeys
    assert env["LIFTPROOF_INVOKED_BY"] == "ui:Hema D"
    r, page = client.request("GET", r.getheader("Location"))
    assert r.status == 200 and "differences" in page and "started" in page
    assert f"/p/acme/runs/{argv[14]}/report.html" in page
    _, page = client.request("GET", "/p/acme")
    assert "ui:Hema D" in page
    # baselines take no run id; doctor takes nothing
    client.post("/p/acme/start", {"command": "baseline", "tables": "orders", "resume": "1"})
    assert launches.calls[-1][0][8:] == ["--tables", "orders", "--resume"]
    client.post("/p/acme/start", {"command": "doctor", "tables": "orders"})
    assert launches.calls[-1][0][3] == "doctor" and len(launches.calls[-1][0]) == 8


@pytest.mark.parametrize("form", [
    {"command": "reconcile", "tables": "orders; DROP TABLE x"},
    {"command": "reconcile", "baseline": "a,b"},
    {"command": "reconcile", "tables": "--template=/tmp"},
    {"command": "init"},
])  # fmt: skip
def test_bad_input_starts_nothing(site, form):
    client, _, launches = site
    client.login()
    r, _ = client.post("/p/acme/start", form)
    assert r.status == 400 and not launches.calls


def test_reports_are_served_and_nothing_else(site):
    client, ui, _ = site
    client.login()
    run = ui.workdir / "acme" / "runs" / "r-1"
    run.mkdir(parents=True)
    report = {"run_id": "r-1", "mode": "files", "verdict": "passed",
              "counts": {"differences": 0},
              "run": {"started_at": "2026-10-09T05:00:00+00:00",
                      "invoked_by": "ui:Hema"}}  # fmt: skip
    (run / "report.json").write_text(json.dumps(report))
    (run / "report.html").write_text("<h1>the report</h1>")
    (ui.workdir / "acme" / "secret.txt").write_text("no")
    _, page = client.request("GET", "/p/acme")
    assert "r-1" in page and "passed" in page
    _, index = client.request("GET", "/")
    assert "passed" in index
    r, body = client.request("GET", "/p/acme/runs/r-1/report.html")
    assert r.status == 200 and body == "<h1>the report</h1>"
    r, body = client.request("GET", "/p/acme/runs/r-1/report.json")
    assert r.status == 200 and json.loads(body)["verdict"] == "passed"
    for path in ("/p/acme/runs/../secret.txt/report.html", "/p/acme/runs/r-1/db-results.json",
                 "/p/acme/runs/%2e%2e/report.json", "/p/nope", "/p/broken",
                 "/etc/passwd"):  # fmt: skip
        r, _ = client.request("GET", path)
        assert r.status == 404, path


def test_journeys_bind_secrets_and_confirm_correlations(site):
    client, ui, launches = site
    client.login()
    j = Journey("checkout", "http://src.invalid",
                steps=[Step(1, "goto", url="/login"), Step(2, "fill", value="{{LP_SECRET_1}}")],
                correlations=[Correlation("order_id", "json_path", "POST /api/orders", "$.id",
                                          "12345", ["GET /orders/{id}"], confirmed=False)],
                secrets={"LP_SECRET_1": SecretBinding(field="password")})  # fmt: skip
    j.save(ui.workdir / "acme" / "journeys" / "checkout.json")
    _, page = client.request("GET", "/p/acme")
    assert "/p/acme/journeys/checkout" in page
    r, page = client.request("GET", "/p/acme/journeys/checkout")
    assert r.status == 200 and "not bound" in page and "Confirm" in page
    assert "12345" not in page  # recorded values stay out of the page
    r, _ = client.post("/p/acme/journeys/checkout/bind",
                       {"token": "LP_SECRET_1", "secret_arn": ARN, "key": "password"})  # fmt: skip
    assert r.status == 303
    assert launches.calls[-1][0][3:] == [
        "bind", "--project", launches.calls[-1][0][5], "--workdir", str(ui.workdir),
        "--journey", "checkout", "--token", "LP_SECRET_1", "--secret-arn", ARN, "--key", "password",
    ]  # fmt: skip
    client.post("/p/acme/journeys/checkout/bind", {"confirm": "order_id"})
    assert launches.calls[-1][0][-2:] == ["--confirm", "order_id"]
    n = len(launches.calls)
    r, _ = client.post("/p/acme/journeys/checkout/bind",
                       {"token": "LP_SECRET_1", "secret_arn": "arn:aws:s3:::bucket"})  # fmt: skip
    assert r.status == 400
    r, _ = client.post("/p/acme/journeys/other/bind", {"confirm": "x"})
    assert r.status == 404 and len(launches.calls) == n


def test_binds_to_loopback_only(tmp_path):
    ui = UI(tmp_path, tmp_path)
    with pytest.raises(ConfigError, match="127.0.0.1"):
        make_server(ui, host="0.0.0.0", port=0)  # noqa: S104


def test_a_real_run_from_the_ui(tmp_path, monkeypatch):
    """The UI's own launcher: the CLI runs as a process, the report names who ran it."""
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "x.txt").write_text("one")
    (tmp_path / "b" / "x.txt").write_text("two")
    projects = tmp_path / "projects"
    projects.mkdir()
    docs = {"name": "documents", "source": str(tmp_path / "a"), "target": str(tmp_path / "b")}
    (projects / "docs.yaml").write_text(yaml.safe_dump({"project": "docs", "files": [docs]}))
    ui = UI(projects, projects)
    monkeypatch.delenv("LIFTPROOF_INVOKED_BY", raising=False)
    job = ui.start("docs", "files", {}, "Hema")
    deadline = time.monotonic() + 120
    while job.poll() is None and time.monotonic() < deadline:
        time.sleep(0.2)
    assert job.status == "differences", job.output()
    report = json.loads(Path(projects / "docs" / "runs" / job.run_id / "report.json").read_text())
    assert report["run"]["invoked_by"].startswith("ui:Hema@") and report["mode"] == "files"
    assert ui.runs("docs")[0]["run_id"] == job.run_id
