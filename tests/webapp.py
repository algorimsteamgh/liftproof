"""A small order application, served twice: once as the source and once as the target.

The target variant can be changed deliberately (Technical Spec 18: replay tests against
a sample application deliberately changed between source and target). Generated ids,
CSRF tokens and timestamps differ between the two on every run, as they would in life.
"""

from __future__ import annotations

import datetime as dt
import json
import secrets
import threading
import time
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

PASSWORD = "s3cret-pass"  # noqa: S105 - the sample application's test login

LOGIN = """<!doctype html><html><head><title>Shop</title>
<meta name="csrf-token" content="{csrf}"></head><body><main>
<h1>Sign in</h1>
<form method="post" action="/login">
<input type="hidden" name="csrf" value="{csrf}">
<label for="u">Username</label> <input id="u" name="username">
<label for="p">Password</label> <input id="p" name="password" type="password">
<button type="submit">Sign in</button>
</form></main></body></html>"""

ORDERS = """<!doctype html><html><head><title>Shop</title></head><body><main>
<h1>Orders</h1>
<p data-liftproof-volatile>Served by node {node}</p>
<form id="new">
<label for="item">Item</label> <input id="item" name="item">
<button type="submit" {testid}>{button}</button>
</form>
<script>
document.getElementById('new').addEventListener('submit', async (e) => {{
  e.preventDefault();
  const r = await fetch('/api/orders', {{method: 'POST', headers: {{'Content-Type':
    'application/json'}}, body: JSON.stringify({{item: document.getElementById('item').value}})}});
  const o = await r.json();
  location.href = '/orders/' + o.id;
}});
</script></main></body></html>"""

ORDER = """<!doctype html><html><head><title>Shop</title></head><body><main>
<h1>Order <span id="oid"></span></h1>{greeting}<dl id="d"></dl>
<a href="/orders">Back to orders</a>
<button type="button" onclick="history.back()">Previous page</button>
<button type="button" onclick="location.reload()">Refresh</button>
<a href="#d">Details</a>
<button type="button" onclick="history.pushState(null, '', '?tab=more')">More</button>
<p data-liftproof-volatile>Served by node {node}</p>
<script>
fetch('/api/orders/{oid}').then(r => r.json()).then(o => {{
  document.getElementById('oid').textContent = o.id;
  document.getElementById('d').innerHTML = '<dt>Item</dt><dd>' + o.item + '</dd>' +
    '<dt>Status</dt><dd>' + o.status + '</dd><dt>Total</dt><dd>' + o.total + '</dd>' +
    '<dt>Placed</dt><dd>' + o.placed_at + '</dd>';
}});
</script></main></body></html>"""

HELP = """<!doctype html><html><head><title>Shop</title></head><body><main>
<h1>Help</h1>
<aside data-liftproof-volatile>Served by node {node}. <a href="/login">Sign in</a></aside>
</main></body></html>"""

# a page whose frame moves on by itself once loaded: a history entry for the frame alone
FRAMED = """<!doctype html><html><head><title>Shop</title></head><body><main>
<h1>Framed</h1><iframe title="news" src="/frame/a"></iframe></main></body></html>"""

FRAME = """<!doctype html><html><body><p>Frame {name}</p>
<script>{script}</script></body></html>"""
NEXT_FRAME = "addEventListener('load', () => setTimeout(() => location.assign('/frame/b'), 50));"

INBOX = """<!doctype html><html><head><title>Shop</title></head><body><main>
<h1>Inbox</h1>
<script>fetch('/api/updates');</script></main></body></html>"""


class ShopApp:
    """variant: same | changed. changed renames a status, adds an API field, drops the
    order button's test id (so replay falls back to a weaker locator) and returns 500 for
    a missing order instead of 404. latency_ms delays every response, as a real
    application across a network does (the performance suite uses it).

    posts counts the POSTs that reach it, by path. post_status and post_delay_ms (by path)
    change the answer to a write it has already stored: its status, and how long it takes.
    GET /dropped closes the connection without an answer, GET /export answers with a
    download and GET /empty with 204. GET /framed holds a frame that moves on by itself.
    GET /inbox long polls /api/updates, which is held open until the app closes; polls
    counts those requests.

    Every page after sign in names the node that served it, marked volatile, and so does
    GET /help, around its link to sign in. greeting (plain, or marked volatile) welcomes
    the user on the order page by a name that differs on every visit. pages counts the
    pages served, by path."""

    def __init__(
        self,
        variant: str = "same",
        latency_ms: int = 0,
        *,
        post_status: dict[str, int] | None = None,
        post_delay_ms: dict[str, int] | None = None,
        greeting: str | None = None,
    ) -> None:
        self.variant = variant
        self.latency_ms = latency_ms
        self.post_status = post_status or {}
        self.post_delay_ms = post_delay_ms or {}
        self.greeting = greeting
        self.posts: Counter[str] = Counter()
        self.pages: Counter[str] = Counter()
        self.polls = 0
        self._closing = threading.Event()
        self.orders: dict[str, dict] = {}
        self.sessions: set[str] = set()
        self.csrf: set[str] = set()
        # signed-in sessions with a request in flight, and the most there were at once
        self.busy: dict[str, int] = {}
        self.peak_sessions = 0
        self._lock = threading.Lock()
        app = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):  # quiet
                pass

            def _send(self, status, body, ctype="text/html", headers=None):
                sid = next((c.strip()[4:] for c in self.headers.get("Cookie", "").split(";")
                            if c.strip().startswith("sid=")), None)  # fmt: skip
                if sid:
                    with app._lock:
                        app.busy[sid] = app.busy.get(sid, 0) + 1
                        app.peak_sessions = max(app.peak_sessions, len(app.busy))
                try:
                    self._respond(status, body, ctype, headers)
                finally:
                    if sid:
                        with app._lock:
                            app.busy[sid] -= 1
                            if not app.busy[sid]:
                                del app.busy[sid]

            def _respond(self, status, body, ctype, headers):
                if app.latency_ms:
                    time.sleep(app.latency_ms / 1000)
                if self.command == "POST" and self.path in app.post_delay_ms:
                    time.sleep(app.post_delay_ms[self.path] / 1000)
                data = body.encode() if isinstance(body, str) else body
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)

            def _authed(self):
                cookie = self.headers.get("Cookie", "")
                return any(c.strip() == f"sid={s}" for s in app.sessions for c in cookie.split(";"))

            def do_GET(self):
                path = self.path.split("?")[0]
                with app._lock:
                    app.pages[path] += 1
                if path == "/dropped":
                    return  # the connection closes with nothing sent
                if path == "/inbox":
                    return self._send(200, INBOX)
                if path == "/export":
                    return self._send(200, "a,b\n", "text/csv",
                                      {"Content-Disposition": 'attachment; filename="o.csv"'})
                if path == "/empty":
                    return self._send(204, "")
                if path == "/framed":
                    return self._send(200, FRAMED)
                if path.startswith("/frame/"):
                    name = path.rsplit("/", 1)[1]
                    return self._send(200, FRAME.format(
                        name=name, script=NEXT_FRAME if name == "a" else ""))
                if path == "/help":
                    return self._send(200, HELP.format(node=secrets.token_hex(4)))
                if path == "/api/updates":
                    with app._lock:
                        app.polls += 1
                    app._closing.wait()  # no news, ever
                    return
                if path in ("/", "/login"):
                    token = secrets.token_hex(16)
                    app.csrf.add(token)
                    return self._send(200, LOGIN.format(csrf=token))
                if not self._authed():
                    return self._send(302, "", headers={"Location": "/login"})
                if path == "/orders":
                    same = app.variant == "same"
                    return self._send(200, ORDERS.format(
                        testid='data-testid="place-order"' if same else "",
                        button="Place order", node=secrets.token_hex(4)))
                if path.startswith("/orders/"):
                    return self._send(200, ORDER.format(
                        oid=path.rsplit("/", 1)[1], node=secrets.token_hex(4),
                        greeting=app._greeting()))
                if path.startswith("/api/orders/"):
                    o = app.orders.get(path.rsplit("/", 1)[1])
                    if o is None:
                        return self._send(500 if app.variant == "changed" else 404, "{}",
                                          "application/json")
                    return self._send(200, o, "application/json")
                return self._send(404, "not found")

            def do_POST(self):
                with app._lock:
                    app.posts[self.path] += 1
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length).decode()
                if self.path == "/login":
                    form = {k: v[0] for k, v in parse_qs(raw).items()}
                    if form.get("csrf") not in app.csrf or form.get("password") != PASSWORD:
                        return self._send(401, "<main><h1>Sign in failed</h1></main>")
                    sid = secrets.token_hex(16)
                    app.sessions.add(sid)
                    return self._send(302, "", headers={"Location": "/orders",
                                                        "Set-Cookie": f"sid={sid}; Path=/"})
                if self.path == "/api/orders" and self._authed():
                    item = json.loads(raw or "{}").get("item", "")
                    oid = str(secrets.randbelow(900000) + 100000)
                    placed = dt.datetime.now(dt.UTC).isoformat(timespec="milliseconds")
                    if app.variant == "changed":
                        body = (f'{{"id": {oid}, "item": "{item}", "status": "PENDING", '
                                f'"total": 10.5, "currency": "EUR", "placed_at": "{placed}"}}')
                    else:
                        body = (f'{{"id": {oid}, "item": "{item}", "status": "OPEN", '
                                f'"total": 10.50, "placed_at": "{placed}"}}')
                    app.orders[oid] = body
                    return self._send(app.post_status.get(self.path, 201), body,
                                      "application/json")
                return self._send(403, "{}", "application/json")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def _greeting(self) -> str:
        if self.greeting is None:
            return ""
        marked = " data-liftproof-volatile" if self.greeting == "marked" else ""
        return f'<p class="greeting"{marked}>Welcome back, visitor {secrets.token_hex(3)}</p>'

    def __enter__(self) -> ShopApp:
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._closing.set()
        self.server.shutdown()
        self.server.server_close()
