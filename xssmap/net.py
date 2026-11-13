"""HTTP transport for xssmap.

Stdlib only. Provides:
  * connection pooling with automatic retries
  * proxy support (http + socks5, socks needs PySocks if installed)
  * redirect tracking (each hop recorded, can be enabled as injection surface)
  * adaptive throttling (slows down on 429/503, backs off exponentially)
  * raw request capture for evidence
"""
from __future__ import annotations

import base64
import gzip
import http.client
import random
import socket
import ssl
import threading
import time
import urllib.parse
import zlib
from dataclasses import dataclass, field

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 xssmap/1.0"
)

# Headers that must never be inherited when following a cross-host redirect.
SENSITIVE_HEADERS = {"authorization", "cookie", "proxy-authorization"}


class NetError(Exception):
    """Transport-level failure after all retries."""


@dataclass
class Response:
    url: str
    method: str
    status: int
    headers: list[tuple[str, str]]
    body: bytes
    elapsed: float
    request_headers: list[tuple[str, str]] = field(default_factory=list)
    request_body: bytes = b""
    history: list[Hop] = field(default_factory=list)
    error: str | None = None
    # Binary bodies (images, fonts, archives, media) are read up to a cap and
    # the connection is dropped: nothing downstream parses them.
    truncated: bool = False

    # -- convenience -------------------------------------------------
    @property
    def text(self) -> str:
        ctype = self.header("content-type") or ""
        charset = "utf-8"
        for part in ctype.split(";"):
            part = part.strip()
            if part.lower().startswith("charset="):
                charset = part.split("=", 1)[1].strip("\"' ")
        if not charset or charset.lower() in ("none", "unknown"):
            charset = "utf-8"
        try:
            return self.body.decode(charset, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")

    def header(self, name: str) -> str | None:
        name = name.lower()
        for k, v in self.headers:
            if k.lower() == name:
                return v
        return None

    @property
    def content_type(self) -> str:
        return (self.header("content-type") or "").split(";")[0].strip().lower()

    @property
    def is_html(self) -> bool:
        ct = self.content_type
        if ct in ("text/html", "application/xhtml+xml"):
            return True
        if not ct or ct == "text/plain":
            head = self.body[:1024].lstrip().lower()
            return head.startswith(b"<!doctype") or b"<html" in head or b"<body" in head
        return False

    @property
    def is_javascript(self) -> bool:
        ct = self.content_type
        return ct in (
            "application/javascript",
            "text/javascript",
            "application/x-javascript",
            "application/ecmascript",
        )

    @property
    def is_json(self) -> bool:
        ct = self.content_type
        return ct.endswith("json") or ct.endswith("+json") or ct == "application/javascript-ld+json"

    def header_dict(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for k, v in self.headers:
            if k.lower() in out:
                out[k.lower()] += ", " + v
            else:
                out[k.lower()] = v
        return out


@dataclass
class Hop:
    """One request/response pair inside a redirect chain."""
    url: str
    method: str
    status: int
    location: str | None
    body: bytes
    headers: list[tuple[str, str]]


@dataclass
class Request:
    method: str = "GET"
    url: str = ""
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes | None = None

    def header(self, name: str) -> str | None:
        name = name.lower()
        for k, v in self.headers:
            if k.lower() == name:
                return v
        return None

    def set_header(self, name: str, value: str) -> None:
        low = name.lower()
        for i, (k, _) in enumerate(self.headers):
            if k.lower() == low:
                self.headers[i] = (k, value)
                return
        self.headers.append((name, value))

    def remove_header(self, name: str) -> None:
        low = name.lower()
        self.headers = [(k, v) for k, v in self.headers if k.lower() != low]

    def copy(self, **changes) -> Request:
        req = Request(
            method=changes.get("method", self.method),
            url=changes.get("url", self.url),
            headers=list(changes.get("headers", self.headers)),
            body=changes.get("body", self.body),
        )
        return req


MAX_RETRY_AFTER = 120.0  # never honour a server hold longer than two minutes

# Cap on non-textual bodies. Enough to sniff a mislabelled HTML page, small
# enough that a 40 MB video does not become part of the crawl.
MAX_BINARY_BODY = 262_144

# Content types whose bodies are parsed by some later stage (context analysis,
# DOM taint, endpoint mining) and therefore must be read in full.
TEXTUAL_TYPES = frozenset({
    "application/xhtml+xml", "application/xml", "application/json",
    "application/ld+json", "application/javascript", "application/ecmascript",
    "application/x-javascript", "application/x-www-form-urlencoded",
    "application/manifest+json", "application/rss+xml", "application/atom+xml",
    "image/svg+xml",
})


def _is_textual(headers) -> bool:
    """True when a response body may contain markup or code worth reading."""
    ctype = ""
    for k, v in headers or []:
        if str(k).lower() == "content-type":
            ctype = str(v).split(";")[0].strip().lower()
            break
    if not ctype:
        return True          # no type: sniff it, the body is usually HTML
    if ctype.startswith("text/"):
        return True
    return ctype in TEXTUAL_TYPES or ctype.endswith(("+xml", "+json"))

# Statuses that mean "you are sending too much": these justify slowing every
# worker down. A 500 is an application error - a scanner trips them constantly on
# malformed parameters - so it must not be read as backpressure, and neither must
# a one-off 503 from a flapping worker. Pacing only grows after a short streak.
LOAD_SIGNALS = (429, 503)
UPSTREAM_ERRORS = (502, 504)
SLOW_AFTER = 2
MAX_ADAPTIVE_DELAY = 3.0


def parse_retry_after(value: str | None) -> float | None:
    """Seconds requested by a Retry-After header (delta or HTTP-date).

    Returns None when the header is absent or unparsable, and clamps absurd
    values so a hostile or misconfigured target cannot stall the scan.
    """
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    import datetime as _dt
    try:
        seconds = float(text)
    except ValueError:
        seconds = None
    if seconds is None:
        try:
            from email.utils import parsedate_to_datetime
            when = parsedate_to_datetime(text)
        except (TypeError, ValueError, IndexError):
            return None
        if when is None:
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=_dt.timezone.utc)
        seconds = (when - _dt.datetime.now(_dt.timezone.utc)).total_seconds()
    if seconds is None or seconds < 0:
        return None
    return min(float(seconds), MAX_RETRY_AFTER)


def _header_value(headers, name: str) -> str | None:
    low = name.lower()
    for key, value in headers or []:
        if str(key).lower() == low:
            return str(value)
    return None


class Throttle:
    """Adaptive request pacing shared between all workers."""

    def __init__(self, delay: float = 0.0, max_workers: int = 1):
        self.base_delay = max(0.0, delay)
        self.delay = self.base_delay
        self.lock = threading.Lock()
        self.next_slot = 0.0
        self.blocked_until = 0.0
        self.holds = 0
        self.consecutive_errors = 0
        self.total = 0
        self.deadline: float | None = None
        self.requests_per_host: dict[str, list[float]] = {}

    def set_deadline(self, deadline: float | None) -> None:
        """Stop pacing requests the moment the scan budget is spent."""
        self.deadline = deadline

    def wait(self, host: str = "") -> None:
        with self.lock:
            now = time.monotonic()
            slot = max(now, self.next_slot, self.blocked_until)
            self.next_slot = slot + self.delay
            self.total += 1
            stamps = self.requests_per_host.setdefault(host, [])
            stamps.append(now)
            if len(stamps) > 300:
                del stamps[:100]
        delta = slot - time.monotonic()
        if self.deadline is not None:
            delta = min(delta, max(0.0, self.deadline - time.monotonic()))
        if delta > 0:
            time.sleep(delta)

    def on_status(self, status: int) -> None:
        with self.lock:
            if status in LOAD_SIGNALS:
                self.consecutive_errors += 1
                if self.consecutive_errors >= SLOW_AFTER:
                    self.delay = min(max(self.delay * 2.0, 0.35), MAX_ADAPTIVE_DELAY)
            elif status in UPSTREAM_ERRORS:
                # A gateway that cannot reach its backend is a hint, not a verdict.
                self.delay = min(max(self.delay, 0.15), 1.5)
            elif status >= 500:
                # Application errors (500, 501, 505): neutral. Slowing down here
                # punished a target for rejecting one payload and stalled the
                # rest of the crawl behind a delay it never asked for.
                return
            else:
                self.consecutive_errors = max(0, self.consecutive_errors - 1)
                if self.delay > self.base_delay:
                    # Recover quickly: a scan that took one 429 should not keep
                    # paying for it for the next fifty requests.
                    self.delay = max(self.base_delay, self.delay * 0.6)

    def on_response(self, status: int, headers) -> float | None:
        """Record a response and return the server-requested hold in seconds.

        A Retry-After on 429/503 is authoritative: every worker waits for it
        before the next slot. Other statuses only feed the adaptive delay.
        """
        self.on_status(status)
        if status not in (429, 503):
            return None
        seconds = parse_retry_after(_header_value(headers, "Retry-After"))
        if seconds is None:
            return None
        with self.lock:
            self.blocked_until = max(self.blocked_until, time.monotonic() + seconds)
            self.delay = min(max(self.delay, 0.5), 8.0)
            self.holds += 1
        return seconds

    def rate(self, host: str, window: float = 10.0) -> float:
        with self.lock:
            stamps = self.requests_per_host.get(host, [])
            now = time.monotonic()
            recent = [s for s in stamps if now - s <= window]
            return len(recent) / window


class RawCapture:
    """Renders a request/response pair as an HTTP/1.1 transcript for evidence."""

    @staticmethod
    def clean_header(name: str, value: str) -> str:
        """Hide credentials so a shared report never leaks a live session."""
        return "<redacted>" if str(name).lower() in SENSITIVE_HEADERS else value

    @staticmethod
    def render(resp: Response, max_body: int = 12000) -> str:
        lines = []
        parsed = urllib.parse.urlsplit(resp.url)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        lines.append(f"{resp.method} {path} HTTP/1.1")
        lines.append(f"Host: {parsed.netloc}")
        for k, v in resp.request_headers:
            lines.append(f"{k}: {RawCapture.clean_header(k, v)}")
        if resp.request_body:
            lines.append("")
            lines.append(resp.request_body.decode("utf-8", "replace")[:2000])
        lines.append("")
        lines.append(f"HTTP/1.1 {resp.status}")
        for k, v in resp.headers:
            lines.append(f"{k}: {RawCapture.clean_header(k, v)}")
        body = resp.body.decode("utf-8", "replace")
        if len(body) > max_body:
            body = body[:max_body] + f"\n... [truncated, {len(resp.body)} bytes total]"
        lines.append("")
        lines.append(body)
        return "\n".join(lines)

    @staticmethod
    def render_request(method: str, url: str, headers: list[tuple[str, str]], body: bytes | None) -> str:
        parsed = urllib.parse.urlsplit(url)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        out = [f"{method} {path} HTTP/1.1", f"Host: {parsed.netloc}"]
        for k, v in headers:
            out.append(f"{k}: {RawCapture.clean_header(k, v)}")
        if body:
            out.append("")
            out.append(body.decode("utf-8", "replace"))
        return "\n".join(out)


class HTTP:
    """Thread-safe HTTP client with pooling, retries and redirect control."""

    def __init__(
        self,
        timeout: float = 15.0,
        retries: int = 2,
        proxy: str | None = None,
        verify: bool = True,
        extra_headers: dict[str, str] | None = None,
        user_agent: str = DEFAULT_UA,
        max_redirects: int = 5,
        throttle: Throttle | None = None,
        debug: bool = False,
        jar=None,
    ):
        self.timeout = timeout
        # Absolute monotonic deadline (--max-minutes). A request must never wait
        # longer than the budget that is left, or the scan overruns its own
        # limit by one full timeout per in-flight request.
        self.deadline: float | None = None
        self.retries = max(0, retries)
        self.proxy = proxy
        self.verify = verify
        self.ua = user_agent
        self.max_redirects = max_redirects
        self.throttle = throttle or Throttle()
        self.debug = debug
        self.extra_headers = dict(extra_headers or {})
        self.jar = jar          # xssmap.session.CookieJar (optional)
        self._local = threading.local()
        self._ssl = ssl.create_default_context()
        if not verify:
            self._ssl.check_hostname = False
            self._ssl.verify_mode = ssl.CERT_NONE
        self._proxy_parts = self._parse_proxy(proxy)
        self.stats = {"requests": 0, "errors": 0, "bytes": 0, "rate_limits": 0}

    def set_deadline(self, deadline: float | None) -> None:
        """Bound each later request by the remaining budget, not just the loop."""
        self.deadline = deadline
        setter = getattr(self.throttle, "set_deadline", None)
        if setter is not None:
            setter(deadline)

    def _timeout(self) -> float:
        """Per-request socket timeout clipped to the remaining scan budget."""
        if self.deadline is None:
            return self.timeout
        remaining = self.deadline - time.monotonic()
        # Below the floor, fail fast instead of blocking a worker; the scan loop
        # sees the timeout as an ordinary request error and stops on its own
        # deadline check.
        return max(0.25, min(self.timeout, remaining))

    # -- proxy -------------------------------------------------------
    @staticmethod
    def _parse_proxy(proxy: str | None) -> urllib.parse.SplitResult | None:
        if not proxy:
            return None
        if "://" not in proxy:
            proxy = "http://" + proxy
        parts = urllib.parse.urlsplit(proxy)
        if parts.scheme not in ("http", "https", "socks5", "socks5h", "socks4"):
            raise ValueError(f"unsupported proxy scheme: {parts.scheme}")
        return parts

    def _proxy_auth_header(self) -> str | None:
        p = self._proxy_parts
        if p and p.username:
            creds = f"{urllib.parse.unquote(p.username)}:{urllib.parse.unquote(p.password or '')}"
            return "Basic " + base64.b64encode(creds.encode()).decode()
        return None

    # -- connection --------------------------------------------------
    def _pool(self) -> list:
        if not hasattr(self._local, "pool"):
            self._local.pool = []
        return self._local.pool

    def _get_conn(self, scheme: str, host: str, port: int, use_tunnel: bool):
        key = f"{scheme}://{host}:{port}:{int(use_tunnel)}"
        pool = self._pool()
        # Search the whole pool instead of popping: a request for another host
        # used to throw away every warm connection queued ahead of it, so a
        # crawl that touched a CDN lost its keep-alive sockets and re-handshook.
        for index in range(len(pool) - 1, -1, -1):
            k, conn, last_used = pool[index]
            if k != key:
                continue
            del pool[index]
            if time.time() - last_used > 45:
                try:
                    conn.close()
                except Exception:
                    pass
                continue
            return conn, key
        if self._proxy_parts and self._proxy_parts.scheme.startswith("socks"):
            conn = self._make_socks(host, port, scheme)
            return conn, key
        if self._proxy_parts and scheme == "http" and not use_tunnel:
            ph = self._proxy_parts.hostname or ""
            pp = self._proxy_parts.port or 8080
            conn = http.client.HTTPConnection(ph, pp, timeout=self._timeout())
            return conn, key
        if self._proxy_parts:
            ph = self._proxy_parts.hostname or ""
            pp = self._proxy_parts.port or 8080
            if scheme == "https":
                conn = http.client.HTTPSConnection(ph, pp, timeout=self._timeout(),
                                                   context=self._ssl)
                conn.set_tunnel(host, port, headers=self._tunnel_headers())
            else:
                conn = http.client.HTTPConnection(ph, pp, timeout=self._timeout())
                conn.set_tunnel(host, port, headers=self._tunnel_headers())
            return conn, key
        if scheme == "https":
            return http.client.HTTPSConnection(host, port, timeout=self._timeout(),
                                               context=self._ssl), key
        return http.client.HTTPConnection(host, port, timeout=self._timeout()), key

    def _tunnel_headers(self) -> dict[str, str] | None:
        auth = self._proxy_auth_header()
        if not auth:
            return None
        return {"Proxy-Authorization": auth}

    def _make_socks(self, host: str, port: int, scheme: str):
        try:
            import socks  # PySocks
        except ImportError as exc:
            raise NetError("SOCKS proxy needs PySocks: pip install pysocks") from exc
        p = self._proxy_parts
        if p is None:
            raise NetError("SOCKS proxy requested without a proxy URL")
        sock = socks.socksocket()
        sock.set_proxy(
            socks.SOCKS5 if p.scheme != "socks4" else socks.SOCKS4,
            p.hostname,
            p.port or 1080,
            username=urllib.parse.unquote(p.username) if p.username else None,
            password=urllib.parse.unquote(p.password or "") if p.password else None,
        )
        sock.settimeout(self._timeout())
        sock.connect((host, port))
        conn: http.client.HTTPConnection
        if scheme == "https":
            conn = http.client.HTTPSConnection(host, port, timeout=self._timeout(),
                                               context=self._ssl)
            conn.sock = self._ssl.wrap_socket(sock, server_hostname=host)
            return conn
        conn = http.client.HTTPConnection(host, port, timeout=self._timeout())
        conn.sock = sock
        return conn

    def _release(self, conn, key: str) -> None:
        pool = self._pool()
        if len(pool) < 24:
            pool.append((key, conn, time.time()))
        else:
            try:
                conn.close()
            except Exception:
                pass

    # -- decode ------------------------------------------------------
    @staticmethod
    def _decode_body(resp: http.client.HTTPResponse, raw: bytes) -> bytes:
        enc = (resp.getheader("content-encoding") or "").lower()
        try:
            if "gzip" in enc:
                return gzip.decompress(raw)
            if "deflate" in enc:
                try:
                    return zlib.decompress(raw)
                except zlib.error:
                    return zlib.decompress(raw, -zlib.MAX_WBITS)
        except Exception:
            return raw
        return raw

    # -- main send ---------------------------------------------------
    def _send_once(self, req: Request, allow_redirects: bool) -> Response:
        hops: list[Hop] = []
        current = req
        for _ in range(0, self.max_redirects + 1 if allow_redirects else 1):
            resp = self._send_raw(current)
            hops.append(Hop(
                url=current.url, method=current.method, status=resp.status,
                location=resp.header("location"), body=resp.body, headers=resp.headers,
            ))
            if not allow_redirects or resp.status not in (301, 302, 303, 307, 308):
                resp.history = hops[:-1]
                return resp
            loc = resp.header("location")
            if not loc:
                resp.history = hops[:-1]
                return resp
            new_url = urllib.parse.urljoin(current.url, loc)
            old_host = urllib.parse.urlsplit(current.url).netloc.lower()
            new_host = urllib.parse.urlsplit(new_url).netloc.lower()
            new_headers = list(current.headers)
            if new_host != old_host:
                new_headers = [(k, v) for k, v in new_headers if k.lower() not in SENSITIVE_HEADERS]
            new_method = current.method
            new_body = current.body
            if resp.status == 303 or (resp.status in (301, 302) and current.method.upper() == "POST"):
                new_method = "GET"
                new_body = None
                new_headers = [(k, v) for k, v in new_headers if k.lower() not in ("content-type", "content-length")]
            current = Request(method=new_method, url=new_url, headers=new_headers, body=new_body)
        resp.history = hops[:-1]
        return resp

    def _send_raw(self, req: Request) -> Response:
        parsed = urllib.parse.urlsplit(req.url)
        if parsed.scheme not in ("http", "https"):
            raise NetError(f"unsupported scheme in {req.url}")
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        use_tunnel = bool(self._proxy_parts) and parsed.scheme == "https"
        if self._proxy_parts and parsed.scheme == "http" and not self._proxy_parts.scheme.startswith("socks"):
            path = req.url  # absolute-form for forward proxies

        headers = list(req.headers)
        names = {k.lower() for k, _ in headers}
        if "user-agent" not in names:
            headers.append(("User-Agent", self.ua))
        if "accept" not in names:
            headers.append(("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"))
        if "accept-encoding" not in names:
            headers.append(("Accept-Encoding", "gzip, deflate"))
        if "connection" not in names:
            headers.append(("Connection", "keep-alive"))
        for k, v in self.extra_headers.items():
            if k.lower() not in names:
                headers.append((k, v))
        if self.jar is not None and "cookie" not in names:
            jar_cookie = self.jar.header_for(req.url)
            if jar_cookie:
                headers.append(("Cookie", jar_cookie))
                names.add("cookie")
        if req.body is not None and "content-length" not in {k.lower() for k, _ in headers}:
            headers.append(("Content-Length", str(len(req.body))))

        host_key = parsed.netloc
        self.throttle.wait(host_key)
        started = time.monotonic()
        last_err: Exception | None = None
        for attempt in range(self.retries + 1):
            conn = None
            try:
                conn, key = self._get_conn(parsed.scheme, host, port, use_tunnel)
                conn.request(req.method, path, body=req.body, headers=dict(headers))
                raw_resp = conn.getresponse()
                raw_resp_headers = raw_resp.getheaders()
                truncated = False
                if _is_textual(raw_resp_headers):
                    raw = raw_resp.read()
                else:
                    # A crawler that downloads every PDF, font and video in full
                    # spends its whole budget on bytes no stage ever reads.
                    raw = raw_resp.read(MAX_BINARY_BODY)
                    # http.client closes the response only once it drained the
                    # body; anything still open has bytes left on the socket.
                    truncated = not raw_resp.isclosed()
                data = self._decode_body(raw_resp, raw)
                elapsed = time.monotonic() - started
                if truncated:
                    # The rest of the body is still on the wire: the socket
                    # cannot go back to the pool.
                    try:
                        conn.close()
                    except Exception:
                        pass
                else:
                    self._release(conn, key)
                self.stats["requests"] += 1
                self.stats["bytes"] += len(raw)
                hold = self.throttle.on_response(raw_resp.status, raw_resp_headers)
                if self.jar is not None:
                    self.jar.update_from_response(req.url, raw_resp_headers)
                resp = Response(
                    url=req.url, method=req.method, status=raw_resp.status,
                    headers=raw_resp_headers, body=data, elapsed=elapsed,
                    request_headers=headers, request_body=req.body or b"",
                    truncated=truncated,
                )
                if self.debug:
                    print(f"    [{resp.status}] {req.method} {req.url[:140]} ({len(data)}b {elapsed*1000:.0f}ms)")
                if hold is not None:
                    self.stats["rate_limits"] += 1
                    if self.debug:
                        print(f"    [hold] server asked for {hold:.1f}s before the next request")
                    # Only replay requests that cannot change server state.
                    if req.method in ("GET", "HEAD") and attempt < self.retries:
                        self.throttle.wait(host_key)
                        continue
                return resp
            except (socket.timeout, TimeoutError) as exc:
                last_err = exc
                if conn:
                    try:
                        conn.close()
                    except Exception:
                        pass
                self.stats["errors"] += 1
                # A slow page is not backpressure: the per-request retry below
                # already backs off, and slowing every other worker would only
                # make the whole scan wait for one unresponsive host.
            except (ConnectionError, http.client.HTTPException, OSError, ssl.SSLError) as exc:
                last_err = exc
                if conn:
                    try:
                        conn.close()
                    except Exception:
                        pass
                self.stats["errors"] += 1
            if attempt < self.retries:
                if self.deadline is not None and time.monotonic() >= self.deadline:
                    break
                time.sleep(min(4.0, 0.4 * (2 ** attempt)) + random.uniform(0, 0.2))
        raise NetError(f"{req.method} {req.url} failed: {last_err}")

    # -- public API --------------------------------------------------
    def send(self, req: Request, allow_redirects: bool = False) -> Response:
        return self._send_once(req, allow_redirects)

    def get(self, url: str, headers: list[tuple[str, str]] | None = None, allow_redirects: bool = True) -> Response:
        return self._send_once(Request("GET", url, headers or []), allow_redirects)

    def post(self, url: str, data: bytes, headers: list[tuple[str, str]] | None = None,
             allow_redirects: bool = False) -> Response:
        return self._send_once(Request("POST", url, headers or [], data), allow_redirects)
