"""Deliberately vulnerable lab application used to validate xssmap.

Every endpoint has a known expected verdict, exposed at /manifest.json, so the
scanner can be scored automatically (true positives AND false positives).

Run:  python testapp/vuln_app.py --port 8888
"""
from __future__ import annotations

import argparse
import html
import json
import re
import secrets
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CSRF_TOKEN = "csrftok123"
GUESTBOOK: list[str] = []
INBOX: list[str] = []
JSON_GUESTBOOK: list[str] = []
ACCOUNT_NOTES: list[tuple[str, str]] = []
SESSIONS: dict[str, dict] = {}
LOGIN_STATE: dict[str, str] = {}
USERS = {"alice": "s3cret"}
STORE_LOCK = threading.Lock()

LAYOUT = """<!doctype html>
<html><head><meta charset="utf-8"><title>{title}</title>
<link rel="stylesheet" href="/static/app.css">
</head><body>
<nav><a href="/">home</a> | <a href="/search?q=hello">search</a> |
<a href="/attr?name=bob">profile</a> | <a href="/js?name=guest">greeting</a> |
<a href="/textarea?msg=hi">notes</a> | <a href="/form">contact</a> |
<a href="/account">account</a> | <a href="/guestbook-json">json guestbook</a></nav>
<main>{body}</main>
<footer><!-- build 2026.11.13 --></footer>
<script>
var page = "{page}";
fetch("/api/search?q=widgets").then(function(r){{return r.json()}}).then(function(d){{console.log(d)}});
</script>
</body></html>"""


def page(title: str, body: str, page_name: str = "index") -> bytes:
    return LAYOUT.format(title=title, body=body, page=page_name).encode()


class Handler(BaseHTTPRequestHandler):
    server_version = "labapp/1.0"
    protocol_version = "HTTP/1.1"
    verbose = False

    # -- helpers -----------------------------------------------------
    def log_message(self, fmt, *args):
        if self.verbose:
            print("  [app] " + (fmt % args))

    def _send(self, body: bytes, status: int = 200, ctype: str = "text/html; charset=utf-8",
              extra: dict | None = None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _qs(self) -> dict[str, str]:
        parsed = urllib.parse.urlsplit(self.path)
        pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        return dict(pairs)

    def _path(self) -> str:
        return urllib.parse.urlsplit(self.path).path

    # -- routing -----------------------------------------------------
    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def do_HEAD(self):
        self.route("GET")

    def route(self, method: str):
        path = self._path()
        q = self._qs()
        try:
            handler = ROUTES.get(path)
            if handler is None:
                if path == "/robots.txt":
                    return self._send(b"User-agent: *\nAllow: /\nSitemap: /sitemap.xml\n", ctype="text/plain")
                if path == "/sitemap.xml":
                    return self._send(SITEMAP, ctype="application/xml")
                if path == "/manifest.json":
                    return self._send(json.dumps({"expectations": EXPECT,
                                                  "auth_expectations": AUTH_EXPECT}).encode(),
                                      ctype="application/json")
                if path == "/static/app.css":
                    return self._send(b"body{font-family:sans-serif}", ctype="text/css")
                return self._send(page("Not found", "<h1>404</h1>", "404"), status=404)
            return handler(self, q, method)
        except BrokenPipeError:
            pass
        except Exception as exc:  # pragma: no cover - lab only
            self._send(f"<h1>500</h1><pre>{html.escape(str(exc))}</pre>".encode(), status=500)

    # -- endpoints ---------------------------------------------------
    def index(self, q, method):
        body = """
<h1>Lab shop</h1>
<p>Search the catalogue:</p>
<form action="/search" method="GET">
  <input name="q" value="shoes"> <input type="submit" value="Search">
</form>
<ul>
 <li><a href="/attr?name=alice">profile</a></li>
 <li><a href="/attr-single?name=alice">single quoted</a></li>
 <li><a href="/attr-unquoted?q=bob">unquoted attr</a></li>
 <li><a href="/js?name=guest">js context</a></li>
 <li><a href="/js-single?name=guest">js single</a></li>
 <li><a href="/textarea?msg=hello">textarea</a></li>
 <li><a href="/comment?x=debug">comment</a></li>
 <li><a href="/title?q=shop">title</a></li>
 <li><a href="/encoded?q=test">encoded</a></li>
 <li><a href="/stripped?q=test">stripped</a></li>
 <li><a href="/safe?q=test">json-safe</a></li>
 <li><a href="/json?q=test">json api</a></li>
 <li><a href="/misconfig?q=test">misconfigured api</a></li>
 <li><a href="/csp?q=test">csp protected</a></li>
 <li><a href="/redirect?next=/search">redirect</a></li>
 <li><a href="/form">contact form</a></li>
 <li><a href="/form-post">post form</a></li>
 <li><a href="/dom?q=hello">dom sink</a></li>
 <li><a href="/dom-hash">hash sink</a></li>
 <li><a href="/dom-state?q=hello">saved search</a></li>
 <li><a href="/dom-hydrate?q=hello">hydrated results</a></li>
 <li><a href="/filter?q=hello">filtered</a></li>
 <li><a href="/csp-report-only?q=hello">csp report-only</a></li>
 <li><a href="/charset?q=hello">gbk search</a></li>
 <li><a href="/charset-safe?q=hello">utf-8 search</a></li>
 <li><a href="/guestbook">guestbook</a></li>
 <li><a href="/feedback">feedback</a></li>
 <li><a href="/admin/inbox">admin inbox</a></li>
</ul>"""
        return self._send(page("Lab shop", body, "home"))

    def search(self, q, method):
        term = q.get("q", "")
        body = f'<h1>Results</h1><p>You searched for: {term}</p><div>no results</div>'
        return self._send(page("Search", body, "search"))

    def attr(self, q, method):
        name = q.get("name", "")
        body = f'<h1>Profile</h1><form><input type="text" name="name" value="{name}"><button>save</button></form>'
        return self._send(page("Profile", body, "profile"))

    def attr_single(self, q, method):
        name = q.get("name", "")
        body = f"<h1>Profile</h1><input type='text' value='{name}'>"
        return self._send(page("Profile", body, "profile"))

    def attr_unquoted(self, q, method):
        val = q.get("q", "")
        body = f"<h1>Search</h1><input type=text value={val}>"
        return self._send(page("Search", body, "search"))

    def js(self, q, method):
        name = q.get("name", "")
        body = f'<h1>Hello</h1><script>var name = "{name}"; document.write("<p>hi</p>");</script>'
        return self._send(page("Hello", body, "hello"))

    def js_single(self, q, method):
        name = q.get("name", "")
        body = f"<h1>Hello</h1><script>var name = '{name}';</script>"
        return self._send(page("Hello", body, "hello"))

    def textarea(self, q, method):
        msg = q.get("msg", "")
        body = f"<h1>Notes</h1><textarea rows=4>{msg}</textarea>"
        return self._send(page("Notes", body, "notes"))

    def comment(self, q, method):
        x = q.get("x", "")
        body = f"<h1>Debug</h1><!-- trace: {x} --><p>ok</p>"
        return self._send(page("Debug", body, "debug"))

    def title_page(self, q, method):
        val = q.get("q", "")
        raw = f"""<!doctype html><html><head><title>{val}</title></head>
<body><h1>t</h1><script>var t = "x";</script></body></html>"""
        return self._send(raw.encode())

    def encoded(self, q, method):
        val = html.escape(q.get("q", ""), quote=True)
        body = f"<h1>Safe?</h1><p>{val}</p>"
        return self._send(page("Encoded", body, "encoded"))

    def stripped(self, q, method):
        val = re.sub(r"""[<>"'`()]""", "", q.get("q", ""))
        body = f"<h1>Safe</h1><p>{val}</p>"
        return self._send(page("Stripped", body, "stripped"))

    def safe_json(self, q, method):
        val = json.dumps(q.get("q", "")).replace("<", "\\u003c").replace(">", "\\u003e")
        raw = f"""<!doctype html><html><head><title>safe</title></head><body>
<script type="application/json" id="data">{{"q": {val}}}</script>
<div id="out"></div>
<script>var d = JSON.parse(document.getElementById('data').textContent);</script>
</body></html>"""
        return self._send(raw.encode())

    def json_api(self, q, method):
        val = q.get("q", "")
        return self._send(json.dumps({"query": val, "results": []}).encode(),
                          ctype="application/json", extra={"X-Content-Type-Options": "nosniff"})

    def misconfig(self, q, method):
        val = q.get("q", "")
        return self._send(json.dumps({"html": f"<b>{val}</b>"}).encode(),
                          ctype="text/html; charset=utf-8")

    def csp(self, q, method):
        val = q.get("q", "")
        body = f"<h1>Protected</h1><p>{val}</p>"
        return self._send(page("CSP", body, "csp"),
                          extra={"Content-Security-Policy": "default-src 'self'; script-src 'self'"})

    def header_reflect(self, q, method):
        ref = self.headers.get("Referer", "")
        ref2 = self.headers.get("X-Forwarded-Host", "")
        body = f"<h1>Referrer</h1><p>{ref}</p><p>{ref2}</p>"
        return self._send(page("Ref", body, "ref"))

    def redirect(self, q, method):
        target = q.get("next", "/")
        self.send_response(302)
        self.send_header("Location", target)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def form(self, q, method):
        body = """<h1>Contact</h1>
<form action="/search" method="GET">
 <input name="q" placeholder="message">
 <select name="lang"><option>en</option><option>de</option></select>
 <textarea name="body">hi</textarea>
 <input type="submit" value="send">
</form>"""
        return self._send(page("Contact", body, "contact"))

    def form_post(self, q, method):
        if method == "POST":
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length).decode("utf-8", "replace")
            data = dict(urllib.parse.parse_qsl(raw, keep_blank_values=True))
            if data.get("csrf") != CSRF_TOKEN:
                return self._send(b"<h1>403</h1><p>bad csrf token</p>", status=403)
            comment = data.get("comment", "")
            body = f"<h1>Thanks</h1><p>Your comment: {comment}</p>"
            return self._send(page("Thanks", body, "thanks"))
        body = f"""<h1>Leave a comment</h1>
<form action="/form-post" method="POST">
 <input type="hidden" name="csrf" value="{CSRF_TOKEN}">
 <input name="comment" value="">
 <input type="hidden" name="redirect" value="/thanks">
 <button type="submit">post</button>
</form>"""
        return self._send(page("Comment", body, "comment"))

    # -- v2 fixtures -------------------------------------------------
    def dom(self, q, method):
        """Client-side sink: the server never echoes the value."""
        body = """<h1>DOM search</h1>
<p>Results are rendered by JavaScript from the query string.</p>
<div id="out">loading</div>
<script>
var q = new URLSearchParams(location.search).get('q') || '';
document.getElementById('out').innerHTML = q;
</script>"""
        return self._send(page("DOM search", body, "dom"))

    def dom_hash(self, q, method):
        """Fragment-driven sink: nothing is ever sent to the server."""
        body = """<h1>Hash router</h1>
<div id="out">start</div>
<script>
function render(){
  var params = new URLSearchParams(location.hash.slice(1));
  var term = params.get('q') || '';
  document.getElementById('out').innerHTML = term;
}
window.addEventListener('hashchange', render);
render();
</script>"""
        return self._send(page("Hash router", body, "hash"))

    def dom_state(self, q, method):
        """Write half of a two-step flow: the value is parked in localStorage.

        The sink lives on /dom-state-read. A taint pass over one script cannot see
        the flow at all: the write and the read are different resources and the
        value never appears in the markup.
        """
        body = """<h1>Saved search</h1>
<p>Recent searches are kept in this browser and shown on the history page.</p>
<div id="out">nothing saved</div>
<p><a href="/dom-state-read">search history</a></p>
<script>
var term = new URLSearchParams(location.search).get('q') || '';
if (term) { localStorage.setItem('saved-search', term); }
document.getElementById('out').textContent = term ? 'saved' : 'nothing saved';
</script>"""
        return self._send(page("Saved search", body, "dom-state"))

    def dom_state_read(self, q, method):
        """Read half: whatever is in storage is written back as HTML."""
        body = """<h1>Search history</h1>
<div id="out">empty</div>
<script>
var saved = localStorage.getItem('saved-search') || '';
if (saved) { document.getElementById('out').innerHTML = saved; }
</script>"""
        return self._send(page("Search history", body, "dom-state-read"))

    def dom_hydrate(self, q, method):
        """SSR hydration: server JSON-encodes, client renders the value as HTML.

        The server escapes ``<`` for the script context, so nothing dangerous is
        reflected. The client then hands the decoded string to innerHTML, which is
        the actual flaw -- and only a browser can prove it.
        """
        state = json.dumps({"query": q.get("q", ""), "results": 0}).replace("<", "\\u003c")
        body = f"""<h1>Hydrated results</h1>
<div id="out">loading</div>
<script id="__INITIAL_STATE__" type="application/json">{state}</script>
<script>
var boot = JSON.parse(document.getElementById('__INITIAL_STATE__').textContent);
document.getElementById('out').innerHTML = boot.query || '';
</script>"""
        return self._send(page("Hydrated results", body, "dom-hydrate"))

    def filtered(self, q, method):
        """Naive keyword blacklist: lowercase handler names are stripped."""
        val = q.get("q", "")
        for bad in ("onerror", "onload", "script", "javascript:"):
            val = val.replace(bad, "")
        body = (f"<h1>Filtered search</h1><p>You searched for: {val}</p>"
                "<p class='note'>some keywords are removed by a blacklist</p>")
        return self._send(page("Filtered", body, "filtered"))

    def guestbook(self, q, method):
        """Persistent, unescaped guestbook: classic stored XSS."""
        if method == "POST":
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length).decode("utf-8", "replace")
            data = dict(urllib.parse.parse_qsl(raw, keep_blank_values=True))
            with STORE_LOCK:
                GUESTBOOK.append(data.get("comment", ""))
            self.send_response(303)
            self.send_header("Location", "/guestbook")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        with STORE_LOCK:
            entries = list(GUESTBOOK)
        rendered = "".join(f"<li class='entry'>{e}</li>" for e in entries) or \
            "<li class='entry'>no entries yet</li>"
        body = f"""<h1>Guestbook</h1>
<form action="/guestbook" method="POST">
 <input name="comment" value="" placeholder="leave a note">
 <button type="submit">sign</button>
</form>
<ul id="entries">{rendered}</ul>"""
        return self._send(page("Guestbook", body, "guestbook"))

    def feedback(self, q, method):
        """Writes into an admin-only queue: the storing page never shows it."""
        if method == "POST":
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length).decode("utf-8", "replace")
            data = dict(urllib.parse.parse_qsl(raw, keep_blank_values=True))
            with STORE_LOCK:
                INBOX.append(data.get("message", ""))
            body = "<h1>Feedback received</h1><p>An administrator will review it.</p>"
            return self._send(page("Feedback", body, "feedback-thanks"))
        body = """<h1>Feedback</h1>
<form action="/feedback" method="POST">
 <textarea name="message">tell us</textarea>
 <button type="submit">send</button>
</form>
<p><a href="/admin/inbox">admin inbox</a></p>"""
        return self._send(page("Feedback", body, "feedback"))

    def admin_inbox(self, q, method):
        """Admin-only view of the feedback queue: renders entries unescaped."""
        with STORE_LOCK:
            entries = list(INBOX)
        rendered = "".join(f"<div class='msg'>{e}</div>" for e in entries) or \
            "<div class='msg'>empty</div>"
        body = f"<h1>Admin inbox</h1><p>messages from the feedback form</p>{rendered}"
        return self._send(page("Admin inbox", body, "admin"))

    def csp_report_only(self, q, method):
        """Report-only policy: recorded, never enforced."""
        val = q.get("q", "")
        body = f"<h1>Report only</h1><p>{val}</p>"
        return self._send(page("Report only", body, "report"), extra={
            "Content-Security-Policy-Report-Only":
                "default-src 'self'; script-src 'self'; report-uri /csp-report"})

    # -- authenticated area -----------------------------------------
    def _read_form(self) -> dict[str, str]:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace")
        if (self.headers.get("Content-Type") or "").startswith("application/json"):
            try:
                data = json.loads(raw or "{}")
            except ValueError:
                return {}
            return data if isinstance(data, dict) else {}
        return dict(urllib.parse.parse_qsl(raw, keep_blank_values=True))

    def _cookie(self, name: str) -> str:
        raw = self.headers.get("Cookie") or ""
        for part in raw.split(";"):
            key, _, value = part.strip().partition("=")
            if key == name:
                return value
        return ""

    def _session(self):
        sid = self._cookie("sid")
        return sid, SESSIONS.get(sid)

    def _redirect(self, location: str, extra: dict | None = None):
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()

    def login(self, q, method):
        """Session login with a rotating anti-CSRF token (tests token refresh)."""
        if method == "POST":
            form = self._read_form()
            if form.get("csrf") != LOGIN_STATE.get("token"):
                body = LOGIN_FORM.format(token=LOGIN_STATE.get("token", ""),
                                         error="<p class='err'>invalid CSRF token</p>")
                return self._send(page("Sign in", body, "login"), status=400)
            user = form.get("username", "")
            if USERS.get(user) != form.get("password", ""):
                body = LOGIN_FORM.format(token=LOGIN_STATE.get("token", ""),
                                         error="<p class='err'>invalid username or password</p>")
                return self._send(page("Sign in", body, "login"))
            sid = secrets.token_hex(8)
            with STORE_LOCK:
                SESSIONS[sid] = {"user": user, "token": secrets.token_hex(8)}
            return self._redirect("/account",
                                  {"Set-Cookie": f"sid={sid}; Path=/; HttpOnly; SameSite=Lax"})
        token = secrets.token_hex(8)
        LOGIN_STATE["token"] = token
        body = LOGIN_FORM.format(token=token, error="")
        return self._send(page("Sign in", body, "login"))

    def logout(self, q, method):
        sid, _session = self._session()
        with STORE_LOCK:
            SESSIONS.pop(sid, None)
        return self._redirect("/login",
                              {"Set-Cookie": "sid=deleted; Path=/; Max-Age=0"})

    def account(self, q, method):
        """Authenticated, CSRF-protected note form that renders notes unescaped."""
        _sid, session = self._session()
        if not session:
            return self._redirect("/login?next=/account")
        if method == "POST":
            form = self._read_form()
            if form.get("csrf") != session["token"]:
                return self._send(page("Account", "<h1>Account</h1>"
                                       "<p class='err'>stale CSRF token</p>", "account"),
                                  status=403)
            with STORE_LOCK:
                ACCOUNT_NOTES.append((session["user"], form.get("comment", "")))
                session["token"] = secrets.token_hex(8)
            return self._redirect("/account")
        with STORE_LOCK:
            session["token"] = secrets.token_hex(8)   # rotates on every page view
            token = session["token"]
            notes = [n for owner, n in ACCOUNT_NOTES if owner == session["user"]]
        rendered = "".join(f"<li class='entry'>{n}</li>" for n in notes) or \
            "<li class='entry'>no notes yet</li>"
        body = ACCOUNT_PAGE.format(user=html.escape(session["user"]), token=token,
                                   notes=rendered)
        return self._send(page("Account", body, "account"))

    def api_guestbook(self, q, method):
        """JSON write endpoint behind the xhr guestbook."""
        if method != "POST":
            return self._send(b'{"ok": false, "error": "POST only"}', status=405,
                              ctype="application/json")
        data = self._read_form()
        text = str(data.get("comment") or data.get("message") or "")
        with STORE_LOCK:
            JSON_GUESTBOOK.append(text)
            count = len(JSON_GUESTBOOK)
        return self._send(json.dumps({"ok": True, "stored": count}).encode(),
                          ctype="application/json")

    def guestbook_json(self, q, method):
        with STORE_LOCK:
            entries = list(JSON_GUESTBOOK)
        rendered = "".join(f"<li class='entry'>{e}</li>" for e in entries) or \
            "<li class='entry'>no entries yet</li>"
        body = ("<h1>JSON guestbook</h1><p>written through /api/guestbook</p>"
                f"<ul id='entries'>{rendered}</ul>")
        return self._send(page("JSON guestbook", body, "guestbook-json"))

    # -- mutation-XSS sinks ------------------------------------------
    def mxss(self, q, method):
        data = json.dumps(q.get("q", "")).replace("</", "<\\/")
        return self._send(page("Comment preview", MXSS_PAGE % data, "mxss"))

    def mxss_safe(self, q, method):
        # Correct implementation: escape at the boundary, so both parses see text.
        data = json.dumps(html.escape(q.get("q", ""), quote=True)).replace("</", "<\\/")
        return self._send(page("Comment preview", MXSS_PAGE % data, "mxss-safe"))

    # -- multibyte charset -------------------------------------------
    def _raw_param(self, name: str) -> bytes:
        """Read a query parameter as the bytes the client actually sent.

        ``parse_qs`` decodes UTF-8; a GBK payload has to survive as bytes for
        the escaping bug to be reproduced at all.
        """
        query = urllib.parse.urlsplit(self.path).query
        for part in query.split("&"):
            key, _, value = part.partition("=")
            if urllib.parse.unquote_plus(key) == name:
                return urllib.parse.unquote_to_bytes(value.replace("+", " "))
        return b""

    def _charset_page(self, charset: str, escape: bool):
        raw = self._raw_param("q")
        if escape:
            # addslashes() semantics: the backslash itself first, then the
            # characters it protects. < and > are neutralised as well, so the
            # only way out of the string literal is the escaping bug itself and
            # not a plain </script> close-out.
            raw = (raw.replace(b"\\", b"\\\\")
                      .replace(b"'", b"\\'")
                      .replace(b'"', b'\\"')
                      .replace(b"<", b"\\x3c")
                      .replace(b">", b"\\x3e"))
        value = raw.decode(charset, "replace")
        body = CHARSET_PAGE.format(charset=charset, value=value)
        self._send(body.encode(charset, "replace"),
                   ctype=f"text/html; charset={charset}")

    def charset_gbk(self, q, method):
        # The classic bug: escaping is byte-wise, the connection decodes GBK, so
        # 0xBF 0x5C is one character and the quote after it is bare.
        self._charset_page("gbk", escape=True)

    def charset_safe(self, q, method):
        # Same escaping, but the document really is UTF-8: 0xBF is not a lead
        # byte there, so the backslash stays a backslash.
        self._charset_page("utf-8", escape=True)

    def api_search(self, q, method):
        val = q.get("q", "")
        return self._send(json.dumps({"query": val, "results": ["a", "b"]}).encode(),
                          ctype="application/json")


# A realistic client-side sink: the value is parsed by innerHTML, walked by a
# naive "sanitiser" that strips on* attributes and <script>, serialised back to a
# string, and assigned to innerHTML again. Ordinary payloads die in the walk.
# A mutation payload hides its handler inside text the first parser never turns
# into an element, so the walk never sees it and the second parse activates it.
CHARSET_PAGE = """<!doctype html>
<html><head><meta charset="{charset}"><title>Search</title></head>
<body><h1>Search</h1><script>var q = '{value}';</script></body></html>"""

MXSS_PAGE = """<h1>Comment preview</h1>
<p>Your comment passes through the site sanitiser before it is rendered.</p>
<div id="out"></div>
<script id="mxss-data" type="application/json">%s</script>
<script>
var raw = JSON.parse(document.getElementById('mxss-data').textContent);
var stage = document.createElement('div');
stage.innerHTML = raw;
var els = stage.querySelectorAll('*');
for (var i = 0; i < els.length; i++) {
  var el = els[i];
  if (el.tagName === 'SCRIPT' || el.tagName === 'IFRAME') { el.remove(); continue; }
  for (var a = el.attributes.length - 1; a >= 0; a--) {
    var name = el.attributes[a].name.toLowerCase();
    if (name.indexOf('on') === 0 || name === 'srcdoc') {
      el.removeAttribute(el.attributes[a].name);
    }
  }
}
var clean = stage.innerHTML;
document.getElementById('out').innerHTML = clean;
</script>"""


LOGIN_FORM = """<h1>Sign in</h1>
{error}
<form action="/login" method="POST">
 <input type="hidden" name="csrf" value="{token}">
 <label>username <input name="username" value=""></label>
 <label>password <input type="password" name="password" value=""></label>
 <button type="submit">sign in</button>
</form>"""

ACCOUNT_PAGE = """<h1>Account of {user}</h1>
<form action="/account" method="POST">
 <input type="hidden" name="csrf" value="{token}">
 <input name="comment" value="" placeholder="private note">
 <button type="submit">save note</button>
</form>
<h2>Your notes</h2>
<ul id="notes">{notes}</ul>"""


ROUTES = {
    "/": Handler.index,
    "/search": Handler.search,
    "/attr": Handler.attr,
    "/attr-single": Handler.attr_single,
    "/attr-unquoted": Handler.attr_unquoted,
    "/js": Handler.js,
    "/js-single": Handler.js_single,
    "/textarea": Handler.textarea,
    "/comment": Handler.comment,
    "/title": Handler.title_page,
    "/encoded": Handler.encoded,
    "/stripped": Handler.stripped,
    "/safe": Handler.safe_json,
    "/json": Handler.json_api,
    "/misconfig": Handler.misconfig,
    "/csp": Handler.csp,
    "/header": Handler.header_reflect,
    "/redirect": Handler.redirect,
    "/form": Handler.form,
    "/form-post": Handler.form_post,
    "/dom": Handler.dom,
    "/dom-hash": Handler.dom_hash,
    "/dom-state": Handler.dom_state,
    "/dom-state-read": Handler.dom_state_read,
    "/dom-hydrate": Handler.dom_hydrate,
    "/filter": Handler.filtered,
    "/csp-report-only": Handler.csp_report_only,
    "/guestbook": Handler.guestbook,
    "/feedback": Handler.feedback,
    "/admin/inbox": Handler.admin_inbox,
    "/mxss": Handler.mxss,
    "/mxss-safe": Handler.mxss_safe,
    "/charset": Handler.charset_gbk,
    "/charset-safe": Handler.charset_safe,
    "/api/search": Handler.api_search,
    "/login": Handler.login,
    "/logout": Handler.logout,
    "/account": Handler.account,
    "/api/guestbook": Handler.api_guestbook,
    "/guestbook-json": Handler.guestbook_json,
}

SITEMAP = b"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
 <url><loc>/search?q=sitemap</loc></url>
 <url><loc>/attr?name=sitemap</loc></url>
</urlset>"""

EXPECT = [
    {"path": "/search", "param": "q", "vulnerable": True, "context": "html_text"},
    {"path": "/attr", "param": "name", "vulnerable": True, "context": "attr_double"},
    {"path": "/attr-single", "param": "name", "vulnerable": True, "context": "attr_single"},
    {"path": "/attr-unquoted", "param": "q", "vulnerable": True, "context": "attr_unquoted"},
    {"path": "/js", "param": "name", "vulnerable": True, "context": "js_string_double"},
    {"path": "/js-single", "param": "name", "vulnerable": True, "context": "js_string_single"},
    {"path": "/textarea", "param": "msg", "vulnerable": True, "context": "textarea"},
    {"path": "/comment", "param": "x", "vulnerable": True, "context": "comment"},
    {"path": "/title", "param": "q", "vulnerable": True, "context": "title"},
    {"path": "/misconfig", "param": "q", "vulnerable": True, "context": "html_text"},
    {"path": "/csp", "param": "q", "vulnerable": True, "context": "html_text", "csp": True},
    {"path": "/csp-report-only", "param": "q", "vulnerable": True, "context": "html_text"},
    {"path": "/filter", "param": "q", "vulnerable": True, "context": "html_text", "filtered": True},
    {"path": "/dom", "param": "q", "vulnerable": True, "context": "dom_xss", "dom": True},
    {"path": "/dom-hash", "param": "q", "vulnerable": True, "context": "dom_xss", "dom": True,
     "delivery": "hash"},
    {"path": "/dom-state-read", "param": "q", "vulnerable": True, "context": "dom_xss",
     "dom": True, "delivery": "storage"},
    {"path": "/dom-hydrate", "param": "q", "vulnerable": True, "context": "dom_xss",
     "dom": True, "delivery": "hydrate"},
    {"path": "/guestbook", "param": "comment", "vulnerable": True,
     "context": "stored_xss", "stored": True},
    {"path": "/feedback", "param": "message", "vulnerable": True,
     "context": "stored_xss", "stored": True, "blind": True},
    {"path": "/charset", "param": "q", "vulnerable": True, "context": "charset"},
    {"path": "/charset-safe", "param": "q", "vulnerable": False,
     "reason": "utf-8 decoding keeps the escape"},
    {"path": "/encoded", "param": "q", "vulnerable": False, "reason": "html_escape"},
    {"path": "/stripped", "param": "q", "vulnerable": False, "reason": "character stripping"},
    {"path": "/safe", "param": "q", "vulnerable": False, "reason": "json script escaping"},
    {"path": "/json", "param": "q", "vulnerable": False, "reason": "json content-type + nosniff"},
]


AUTH_EXPECT = [
    {"path": "/account", "param": "comment", "vulnerable": True,
     "context": "stored_xss", "stored": True, "auth": True,
     "login": "/login", "user": "alice", "password": "s3cret"},
    {"path": "/guestbook-json", "param": "comment", "vulnerable": True,
     "context": "stored_xss", "stored": True, "json": "/api/guestbook"},
]


def make_server(port: int = 8888, host: str = "127.0.0.1", verbose: bool = False):
    Handler.verbose = verbose
    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.daemon_threads = True
    return httpd


def serve_in_thread(port: int = 0, host: str = "127.0.0.1"):
    httpd = make_server(port, host)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, httpd.server_address[1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8888)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    httpd = make_server(args.port, args.host, args.verbose)
    print(f"lab app listening on http://{args.host}:{args.port}  (manifest: /manifest.json)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
