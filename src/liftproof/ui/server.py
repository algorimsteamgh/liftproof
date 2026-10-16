"""The local web UI (Technical Spec 4, 23): a convenience layer over the CLI for starting
runs, reading reports and finishing journeys (binding secrets, confirming correlations).

The CLI is the product. Everything the UI does, it does by running the CLI as its own
process, exactly as the scheduler and the SSM document do, so nothing here works only in
the UI. Pages read what the runs leave on disk: reports, run history, journey files.

The UI binds to 127.0.0.1 only and is reached through Systems Manager Session Manager
port forwarding. Port forwarding carries no identity, so the UI has its own sign in: a
one time login link from `liftproof ui-login` (also a mode of the SSM run document),
good for ten minutes and for one use, which starts a session cookie. The link only ever
holds a code that is spent or expired by the time anyone reads the command's output.
Requests naming any other host are refused (DNS rebinding), and every form carries a
value derived from the session (cross site requests). Who ran a run is the name people
give the UI, recorded as ui:<name>; it is what they say, not a verified identity.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import logging
import os
import re
import secrets
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import IO, Any
from urllib.parse import parse_qs, quote, unquote, urlsplit

from jinja2 import Environment, PackageLoader, select_autoescape

from liftproof.config import Project, load_project
from liftproof.errors import ConfigError, LiftproofError

log = logging.getLogger(__name__)

COOKIE = "liftproof_ui"
NAME_COOKIE = "liftproof_ui_name"
LOGINS = "ui-logins"  # one file per unspent login code, named by its hash
LOGIN_SECONDS = 600
SESSION_SECONDS = 12 * 3600
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
LIST = re.compile(r"[A-Za-z0-9_$#.-]+(,[A-Za-z0-9_$#.-]+)*")
PERSON = re.compile(r"[\w .@'-]{1,64}")
LOOPBACK = ("127.0.0.1", "localhost", "::1")
SECRET_ARN = re.compile(r"arn:aws[\w-]*:secretsmanager:[\w-]+:\d{12}:secret:[\w/+=.@-]+")

# what each command the UI starts may be given; values the report would print (show
# values) and custom templates stay with the CLI
COMMANDS: dict[str, tuple[str, ...]] = {
    "validate": ("baseline", "tables", "no_source", "include_replay_rows", "journeys", "sets"),
    "reconcile": ("baseline", "tables", "no_source", "include_replay_rows"),
    "files": ("sets",),
    "replay": ("journeys",),
    "smoke": ("journeys",),
    "baseline": ("tables", "resume"),
    "rebaseline": ("tables", "resume"),
    "doctor": (),
}
FLAGS = ("no_source", "include_replay_rows", "resume")
RUNS = ("validate", "reconcile", "files", "replay", "smoke")  # these write a report
EXIT = {0: "clean", 10: "differences", 2: "run failed", 3: "configuration error"}

Launch = Callable[[list[str], IO[bytes], dict[str, str]], Any]


def _popen(argv: list[str], out: IO[bytes], env: dict[str, str]) -> subprocess.Popen:
    return subprocess.Popen(argv, stdout=out, stderr=subprocess.STDOUT, env=env)  # noqa: S603


@dataclass
class Job:
    job_id: str
    project: str
    command: str
    argv: list[str]
    log_path: Path
    started_at: str
    invoked_by: str
    run_id: str | None = None
    proc: Any = None
    code: int | None = None

    def poll(self) -> int | None:
        if self.code is None and self.proc is not None:
            self.code = self.proc.poll()
        return self.code

    @property
    def status(self) -> str:
        code = self.poll()
        if code is None:
            return "running"
        return EXIT.get(code, f"exit code {code}")

    def output(self, limit: int = 200_000) -> str:
        try:
            data = self.log_path.read_bytes()
        except FileNotFoundError:
            return ""
        return data[-limit:].decode("utf-8", "replace")


@dataclass
class UI:
    projects_dir: Path
    workdir: Path
    launch: Launch = _popen
    jobs: dict[str, Job] = field(default_factory=dict)
    sessions: dict[str, float] = field(default_factory=dict)  # session id -> expiry
    lock: threading.Lock = field(default_factory=threading.Lock)
    key: bytes = field(default_factory=lambda: secrets.token_bytes(32))

    def __post_init__(self) -> None:
        self.env = Environment(
            loader=PackageLoader("liftproof.ui", "templates"),
            autoescape=select_autoescape(["html"]),
        )
        self.env.filters["when"] = lambda v: (v or "")[:19].replace("T", " ")

    def csrf(self, session: str) -> str:
        return hmac.new(self.key, session.encode(), hashlib.sha256).hexdigest()

    # signing in -------------------------------------------------------------------
    def spend(self, code: str) -> str | None:
        """A new session for an unspent, unexpired login code; the code is spent."""
        if not re.fullmatch(r"[A-Za-z0-9_-]{20,64}", code):
            return None
        path = self.workdir / LOGINS / hashlib.sha256(code.encode()).hexdigest()
        try:
            age = time.time() - path.stat().st_mtime
            path.unlink()
        except FileNotFoundError:
            return None
        if age > LOGIN_SECONDS:
            return None
        session = secrets.token_urlsafe(32)
        with self.lock:
            now = time.time()
            self.sessions = {k: v for k, v in self.sessions.items() if v > now}
            self.sessions[session] = now + SESSION_SECONDS
        return session

    def session_ok(self, session: str) -> bool:
        with self.lock:
            expiry = self.sessions.get(session)
        return expiry is not None and expiry > time.time()

    # what is on disk ------------------------------------------------------------
    def projects(self) -> dict[str, tuple[Path, Project | None, str | None]]:
        """Project name -> (file, project, why it could not be read)."""
        out: dict[str, tuple[Path, Project | None, str | None]] = {}
        for path in sorted(self.projects_dir.glob("*.yaml")):
            try:
                p = load_project(path)
                out[p.name] = (path, p, None)
            except ConfigError as exc:
                out[path.stem] = (path, None, str(exc))
        return out

    def project(self, name: str) -> tuple[Path, Project]:
        path, p, _ = self.projects().get(name, (None, None, None))
        if p is None or path is None:
            raise LookupError(name)
        return path, p

    def runs(self, name: str) -> list[dict[str, Any]]:
        from liftproof.cli import _store, run_history, sync_reports

        runs_dir = self.workdir / name / "runs"
        try:
            _, p = self.project(name)
            sync_reports(_store(p, self.workdir), runs_dir)
        except (LookupError, LiftproofError) as exc:  # the reports held here still show
            log.warning("run history of %s from this instance only: %s", name, exc)
        return run_history(runs_dir)

    def journey_ids(self, p: Project) -> list[str]:
        from liftproof.cli import _store, journey_index

        listed = list(p.web.journeys or []) if p.web is not None else []
        try:
            recorded = journey_index(_store(p, self.workdir), self.workdir / p.name)
        except LiftproofError as exc:
            log.warning("journeys of %s from this instance only: %s", p.name, exc)
            recorded = [f.stem for f in (self.workdir / p.name / "journeys").glob("*.json")]
        return sorted({*listed, *recorded})

    def journey(self, p: Project, journey_id: str):
        from liftproof.cli import _load_journey, _store

        return _load_journey(_store(p, self.workdir), self.workdir / p.name, journey_id)

    # starting the CLI ------------------------------------------------------------
    def start(self, project: str, command: str, form: dict[str, str], person: str) -> Job:
        path, p = self.project(project)
        if command not in COMMANDS:
            raise ValueError(f"unknown command {command}")
        argv = [sys.executable, "-m", "liftproof.cli", command, "--project", str(path),
                "--workdir", str(self.workdir)]  # fmt: skip
        for key in COMMANDS[command]:
            value = form.get(key, "").strip()
            if not value:
                continue
            flag = "--" + key.replace("_", "-")
            if key in FLAGS:
                argv.append(flag)
            elif not LIST.fullmatch(value) or (key == "baseline" and "," in value):
                raise ValueError(f"{key}: names separated by commas only")
            else:
                argv += [flag, value]
        now = dt.datetime.now(dt.UTC)
        job_id = f"u-{now:%Y%m%d-%H%M%S}-{secrets.token_hex(2)}"
        run_id = job_id if command in RUNS else None
        if run_id:
            argv += ["--run-id", run_id]
        return self._spawn(project, command, argv, person, run_id, job_id, now)

    def bind(self, project: str, journey: str, form: dict[str, str], person: str) -> Job:
        """liftproof bind: a token to a secret (ARN and key), or a correlation confirmed."""
        path, p = self.project(project)
        if journey not in self.journey_ids(p):
            raise LookupError(journey)
        argv = [sys.executable, "-m", "liftproof.cli", "bind", "--project", str(path),
                "--workdir", str(self.workdir), "--journey", journey]  # fmt: skip
        if form.get("confirm"):
            if not NAME.fullmatch(form["confirm"]):
                raise ValueError("correlation: a plain name")
            argv += ["--confirm", form["confirm"]]
        else:
            token, arn, key = (form.get(k, "").strip() for k in ("token", "secret_arn", "key"))
            if not NAME.fullmatch(token) or not SECRET_ARN.fullmatch(arn):
                raise ValueError("a token and a Secrets Manager secret ARN are needed")
            argv += ["--token", token, "--secret-arn", arn, "--key", key or "password"]
        now = dt.datetime.now(dt.UTC)
        job_id = f"u-{now:%Y%m%d-%H%M%S}-{secrets.token_hex(2)}"
        return self._spawn(project, "bind", argv, person, None, job_id, now)

    def _spawn(self, project, command, argv, person, run_id, job_id, now) -> Job:
        jobs_dir = self.workdir / project / "ui-jobs"
        jobs_dir.mkdir(parents=True, exist_ok=True)
        invoked_by = f"ui:{person}" if person else "ui"
        job = Job(job_id, project, command, argv, jobs_dir / f"{job_id}.log",
                  now.isoformat(timespec="seconds"), invoked_by, run_id)  # fmt: skip
        env = {**os.environ, "LIFTPROOF_INVOKED_BY": invoked_by}
        with job.log_path.open("wb") as out:
            job.proc = self.launch(argv, out, env)
        with self.lock:
            self.jobs[job_id] = job
        log.info("ui started %s for %s (%s): %s", command, project, invoked_by, job_id)
        return job

    def project_jobs(self, project: str) -> list[Job]:
        with self.lock:
            jobs = [j for j in self.jobs.values() if j.project == project]
        return sorted(jobs, key=lambda j: j.started_at, reverse=True)

    def render(self, template: str, session: str = "", **kw: Any) -> bytes:
        csrf = self.csrf(session) if session else ""
        return self.env.get_template(template).render(csrf=csrf, **kw).encode()


SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
    "form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "X-Frame-Options": "DENY",
}


class Handler(BaseHTTPRequestHandler):
    ui: UI
    port: int
    server_version = "liftproof-ui"
    sys_version = ""

    def log_message(self, fmt: str, *args: Any) -> None:
        log.info("ui %s %s", self.address_string(), fmt % args)

    # plumbing ---------------------------------------------------------------------
    def _send(self, status: int, body: bytes, ctype: str = "text/html; charset=utf-8",
              headers: dict[str, str] | None = None) -> None:  # fmt: skip
        self.send_response(status)
        for k, v in {**SECURITY_HEADERS, "Content-Type": ctype, **(headers or {})}.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, to: str, cookies: Sequence[str] = ()) -> None:
        self.send_response(HTTPStatus.SEE_OTHER)
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        self.send_header("Location", to)
        for c in cookies:
            self.send_header("Set-Cookie", c)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _error(self, status: int, message: str) -> None:
        body = self.ui.render("error.html", self._session(), status=int(status), message=message)
        self._send(status, body)

    def _cookies(self) -> dict[str, str]:
        c = SimpleCookie()
        try:
            c.load(self.headers.get("Cookie", ""))
        except Exception:  # noqa: BLE001 - a malformed cookie is no cookie
            return {}
        return {k: m.value for k, m in c.items()}

    def _host_ok(self) -> bool:
        """The request names this UI as the tunnel reaches it, not some other host name
        that resolves here (DNS rebinding)."""
        try:
            url = urlsplit("//" + (self.headers.get("Host") or "").strip())
            return url.hostname in LOOPBACK and url.port == self.port
        except ValueError:
            return False

    def _session(self) -> str:
        got = self._cookies().get(COOKIE, "")
        return got if got and self.ui.session_ok(got) else ""

    def _page(self, template: str, **kw: Any) -> None:
        self._send(200, self.ui.render(template, self._session(), **kw))

    def _person(self) -> str:
        name = unquote(self._cookies().get(NAME_COOKIE, ""))
        return name if PERSON.fullmatch(name) else ""

    def _form(self) -> dict[str, str]:
        length = int(self.headers.get("Content-Length") or 0)
        if length > 64_000:
            raise ValueError("form too large")
        raw = self.rfile.read(length).decode("utf-8", "replace")
        return {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}

    def _gate(self) -> bool:
        if not self._host_ok():
            self._send(HTTPStatus.MISDIRECTED_REQUEST, b"use http://127.0.0.1 through the tunnel",
                       "text/plain; charset=utf-8")  # fmt: skip
            return False
        return True

    # GET --------------------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        if not self._gate():
            return
        url = urlsplit(self.path)
        if url.path == "/login":
            session = self.ui.spend(parse_qs(url.query).get("code", [""])[0])
            if session is None:
                return self._error(
                    HTTPStatus.UNAUTHORIZED,
                    "That login link is spent or out of date. Get another with liftproof "
                    "ui-login (or the ui-login mode of the run document).",
                )
            cookie = f"{COOKIE}={session}; Path=/; HttpOnly; SameSite=Strict"
            return self._redirect("/", [cookie])
        if not self._session():
            return self._error(
                HTTPStatus.UNAUTHORIZED,
                "Sign in with a login link from liftproof ui-login (or the ui-login mode of "
                "the run document).",
            )
        parts = [p for p in url.path.split("/") if p]
        try:
            self._route_get(parts)
        except LookupError:
            self._error(HTTPStatus.NOT_FOUND, "Nothing here.")

    def _route_get(self, parts: list[str]) -> None:
        ui = self.ui
        if not parts:
            projects = []
            for name, (path, p, problem) in ui.projects().items():
                last = ui.runs(name)[:1] if p is not None else []
                projects.append({"name": name, "file": path.name, "problem": problem,
                                 "last": last[0] if last else None})  # fmt: skip
            return self._page("index.html", projects=projects, person=self._person())
        if parts[0] != "p" or len(parts) < 2 or not NAME.fullmatch(parts[1]):
            raise LookupError(self.path)
        name = parts[1]
        path, p = ui.project(name)
        rest = parts[2:]
        if not rest:
            from liftproof.schedule import next_runs

            journeys = ui.journey_ids(p) if p.web is not None else []
            return self._page(
                "project.html", p=p, file=path.name, runs=ui.runs(name)[:50],
                jobs=ui.project_jobs(name)[:20], journeys=journeys, commands=COMMANDS,
                schedules=next_runs(p.schedules, dt.datetime.now(dt.UTC)),
                person=self._person(),
            )  # fmt: skip
        if rest[0] == "jobs" and len(rest) == 2:
            job = ui.jobs.get(rest[1])
            if job is None or job.project != name:
                raise LookupError(rest[1])
            return self._page("job.html", p=p, job=job, output=job.output())
        if rest[0] == "runs" and len(rest) == 3 and NAME.fullmatch(rest[1]):
            run_dir = ui.workdir / name / "runs" / rest[1]
            kinds = {"report.html": "text/html; charset=utf-8",
                     "report.json": "application/json"}  # fmt: skip
            if rest[2] not in kinds or not (run_dir / rest[2]).is_file():
                raise LookupError(rest[2])
            return self._send(200, (run_dir / rest[2]).read_bytes(), kinds[rest[2]])
        if rest[0] == "journeys" and len(rest) == 2 and NAME.fullmatch(rest[1]):
            if p.web is None or rest[1] not in ui.journey_ids(p):
                raise LookupError(rest[1])
            try:
                journey, problem = ui.journey(p, rest[1]), None
            except ConfigError as exc:
                journey, problem = None, str(exc)
            return self._page("journey.html", p=p, journey_id=rest[1], j=journey,
                              problem=problem, person=self._person())  # fmt: skip
        raise LookupError(self.path)

    # POST -------------------------------------------------------------------------
    def do_POST(self) -> None:  # noqa: N802
        if not self._gate():
            return
        session = self._session()
        if not session:
            return self._error(HTTPStatus.UNAUTHORIZED, "Sign in with a login link first.")
        origin = self.headers.get("Origin")
        if origin and urlsplit(origin).hostname not in LOOPBACK:
            return self._error(HTTPStatus.FORBIDDEN, "Cross site request refused.")
        try:
            form = self._form()
        except ValueError as exc:
            return self._error(HTTPStatus.BAD_REQUEST, str(exc))
        if not hmac.compare_digest(form.get("csrf", ""), self.ui.csrf(session)):
            return self._error(HTTPStatus.FORBIDDEN, "This form has expired; reload the page.")
        parts = [p for p in urlsplit(self.path).path.split("/") if p]
        try:
            self._route_post(parts, form)
        except LookupError:
            self._error(HTTPStatus.NOT_FOUND, "Nothing here.")
        except ValueError as exc:
            self._error(HTTPStatus.BAD_REQUEST, str(exc))

    def _route_post(self, parts: list[str], form: dict[str, str]) -> None:
        if parts == ["name"]:
            person = form.get("name", "").strip()
            if person and not PERSON.fullmatch(person):
                raise ValueError("a name of letters, digits, spaces and . @ ' -")
            cookie = f"{NAME_COOKIE}={quote(person)}; Path=/; SameSite=Strict"
            return self._redirect(form.get("back") if form.get("back", "").startswith("/p/")
                                  else "/", [cookie])  # fmt: skip
        if len(parts) < 3 or parts[0] != "p" or not NAME.fullmatch(parts[1]):
            raise LookupError(self.path)
        name = parts[1]
        if parts[2:] == ["start"]:
            job = self.ui.start(name, form.get("command", ""), form, self._person())
            return self._redirect(f"/p/{name}/jobs/{job.job_id}")
        if len(parts) == 5 and parts[2] == "journeys" and parts[4] == "bind":
            job = self.ui.bind(name, parts[3], form, self._person())
            return self._redirect(f"/p/{name}/jobs/{job.job_id}")
        raise LookupError(self.path)


def new_login(workdir: Path) -> str:
    """A one time login code for the UI, good for LOGIN_SECONDS. Only its hash is kept."""
    code = secrets.token_urlsafe(24)
    logins = workdir / LOGINS
    logins.mkdir(parents=True, exist_ok=True, mode=0o700)
    for old in logins.iterdir():  # spent nothing, but out of date
        if time.time() - old.stat().st_mtime > LOGIN_SECONDS:
            old.unlink(missing_ok=True)
    path = logins / hashlib.sha256(code.encode()).hexdigest()
    os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
    return code


def make_server(ui: UI, host: str = "127.0.0.1", port: int = 8470) -> ThreadingHTTPServer:
    if host not in LOOPBACK:
        raise ConfigError("the UI binds to 127.0.0.1 only; reach it through SSM port forwarding")
    server = ThreadingHTTPServer((host, port), Handler)
    handler = type("BoundHandler", (Handler,), {"ui": ui, "port": server.server_address[1]})
    server.RequestHandlerClass = handler
    return server
