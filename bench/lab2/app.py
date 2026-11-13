"""Second vulnerable lab app, written independently of testapp/vuln_app.py.

Why a second app: the main self-test and the scanner evolved together, so a
green result there can mean "the scanner learned this app's markup" rather than
"the scanner works". This app uses a different routing style, a different page
skeleton, different parameter names and a different set of contexts, and its
ground truth lives beside the code (``LABELS``) instead of in a manifest served
to the scanner.

Every endpoint is one of:

* vulnerable - the request value reaches a sink without encoding; the expected
  reflection context is declared.
* safe       - the value is encoded, stripped, or never reaches markup; the
  scanner must not report it.
* json       - the value is echoed in a JSON document; a browser never parses
  it as HTML, so it is not XSS and must not be reported.

``LABELS`` is only a claim until it is checked: ``bench/verify_lab.py`` probes
every endpoint with a benign marker and asserts that the declared behaviour is
what the handler really does.
"""
from __future__ import annotations

import html
import json
import re
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---------------------------------------------------------------------------
# Ground truth. ``probe`` is a benign value used by verify_lab.py: for a
# vulnerable endpoint the raw marker must appear in the response inside the
# declared context; for a safe/json endpoint it must not appear as live markup.
# ---------------------------------------------------------------------------
LABELS: list[dict] = [
    {"path": "/quotes", "param": "text", "method": "GET", "vulnerable": True,
     "context": "html_text"},
    {"path": "/avatar", "param": "name", "method": "GET", "vulnerable": True,
     "context": "attr_double"},
    {"path": "/nick", "param": "name", "method": "GET", "vulnerable": True,
     "context": "attr_single"},
    {"path": "/qty", "param": "n", "method": "GET", "vulnerable": True,
     "context": "attr_unquoted"},
    {"path": "/greet", "param": "who", "method": "GET", "vulnerable": True,
     "context": "js_string_single"},
    {"path": "/note", "param": "body", "method": "GET", "vulnerable": True,
     "context": "textarea"},
    {"path": "/headline", "param": "title", "method": "GET", "vulnerable": True,
     "context": "title"},
    {"path": "/debug", "param": "msg", "method": "GET", "vulnerable": True,
     "context": "comment"},
    {"path": "/subscribe", "param": "email", "method": "POST", "vulnerable": True,
     "context": "html_text"},
    {"path": "/escape", "param": "text", "method": "GET", "vulnerable": False},
    {"path": "/strip", "param": "text", "method": "GET", "vulnerable": False},
    {"path": "/count", "param": "n", "method": "GET", "vulnerable": False},
    {"path": "/api/echo", "param": "text", "method": "GET", "vulnerable": False},
]

LINKS = [
    "/quotes?text=hello", "/avatar?name=guest", "/nick?name=guest",
    "/qty?n=1", "/greet?who=guest", "/note?body=hello", "/headline?title=hello",
    "/debug?msg=hello", "/escape?text=hello", "/strip?text=hello",
    "/count?n=7", "/api/echo?text=hello",
]

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Benchmark lab</title></head>
<body>
<h1>Benchmark lab</h1>
<p>Deliberately vulnerable. Every link below takes one parameter.</p>
<ul>{links}</ul>
<form method="post" action="/subscribe">
  <label>E-mail <input name="email" type="text" value=""></label>
  <button type="submit">subscribe</button>
</form>
</body></html>"""


def _links_html() -> str:
    return "\n".join(f'<li><a href="{href}">{href}</a></li>' for href in LINKS)


def _q(query: dict[str, list[str]], name: str) -> str:
    values = query.get(name)
    return values[0] if values else ""


def _one(value: str) -> str:
    return re.sub(r"<[^>]*>", "", value)


# ---------------------------------------------------------------------------
# Handlers: (query) -> (status, content_type, body)
# ---------------------------------------------------------------------------
def page_quotes(query):
    text = _q(query, "text")
    return 200, "text/html; charset=utf-8", (
        "<!doctype html><html><head><title>Quotes</title></head><body>"
        f"<article><p>{text}</p></article></body></html>")


def page_avatar(query):
    name = _q(query, "name")
    return 200, "text/html; charset=utf-8", (
        "<!doctype html><html><body><form action=\"/avatar\">"
        f"<input type=\"text\" name=\"name\" value=\"{name}\">"
        "<button>save</button></form></body></html>")


def page_nick(query):
    name = _q(query, "name")
    return 200, "text/html; charset=utf-8", (
        "<!doctype html><html><body><form action=\"/nick\">"
        f"<input type='text' name='name' value='{name}'>"
        "</form></body></html>")


def page_qty(query):
    n = _q(query, "n")
    return 200, "text/html; charset=utf-8", (
        "<!doctype html><html><body>"
        f"<input name=\"n\" value={n} class=\"qty\"></body></html>")


def page_greet(query):
    who = _q(query, "who")
    return 200, "text/html; charset=utf-8", (
        "<!doctype html><html><head><title>Greeting</title></head><body>"
        f"<script>var who = '{who}'; document.getElementById('out') && "
        "(document.getElementById('out').textContent = who);</script>"
        "<div id=\"out\"></div></body></html>")


def page_note(query):
    body = _q(query, "body")
    return 200, "text/html; charset=utf-8", (
        "<!doctype html><html><body><form action=\"/note\">"
        f"<textarea name=\"body\" rows=\"3\">{body}</textarea>"
        "</form></body></html>")


def page_headline(query):
    title = _q(query, "title")
    return 200, "text/html; charset=utf-8", (
        f"<!doctype html><html><head><title>{title}</title></head>"
        "<body><h1>Headline</h1></body></html>")


def page_debug(query):
    msg = _q(query, "msg")
    return 200, "text/html; charset=utf-8", (
        "<!doctype html><html><body>"
        f"<!-- debug: {msg} --><p>debug page</p></body></html>")


def page_escape(query):
    text = html.escape(_q(query, "text"), quote=True)
    return 200, "text/html; charset=utf-8", (
        f"<!doctype html><html><body><p>{text}</p></body></html>")


def page_strip(query):
    text = _one(_q(query, "text"))
    return 200, "text/html; charset=utf-8", (
        f"<!doctype html><html><body><p>{text}</p></body></html>")


def page_count(query):
    try:
        n = int(_q(query, "n"))
    except ValueError:
        n = 0
    return 200, "text/html; charset=utf-8", (
        f"<!doctype html><html><body><p>count is {n}</p></body></html>")


def api_echo(query):
    text = _q(query, "text")
    payload = json.dumps({"echo": text, "length": len(text)})
    return 200, "application/json", payload


def subscribe(fields):
    email = (fields.get("email") or [""])[0]
    return 200, "text/html; charset=utf-8", (
        "<!doctype html><html><body>"
        f"<div class=\"ok\">Thanks, <span class=\"email\">{email}</span>.</div>"
        "</body></html>")


GET_ROUTES = {
    "/": lambda query: (200, "text/html; charset=utf-8", PAGE.format(links=_links_html())),
    "/quotes": page_quotes,
    "/avatar": page_avatar,
    "/nick": page_nick,
    "/qty": page_qty,
    "/greet": page_greet,
    "/note": page_note,
    "/headline": page_headline,
    "/debug": page_debug,
    "/escape": page_escape,
    "/strip": page_strip,
    "/count": page_count,
    "/api/echo": api_echo,
}

POST_ROUTES = {"/subscribe": subscribe}


class Handler(BaseHTTPRequestHandler):
    server_version = "LabTwo/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # keep the bench output readable
        pass

    def _send(self, status: int, ctype: str, body: str):
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        handler = GET_ROUTES.get(parsed.path.rstrip("/") or "/")
        if handler is None:
            self._send(404, "text/html; charset=utf-8", "<h1>not found</h1>")
            return
        self._send(*handler(urllib.parse.parse_qs(parsed.query, keep_blank_values=True)))

    do_HEAD = do_GET

    def do_POST(self):
        parsed = urllib.parse.urlsplit(self.path)
        handler = POST_ROUTES.get(parsed.path.rstrip("/") or "/")
        if handler is None:
            self._send(404, "text/html; charset=utf-8", "<h1>not found</h1>")
            return
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        fields = urllib.parse.parse_qs(raw, keep_blank_values=True)
        self._send(*handler(fields))


def make_server(port: int = 0) -> ThreadingHTTPServer:
    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def serve_in_thread(port: int = 0):
    server = make_server(port)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread
