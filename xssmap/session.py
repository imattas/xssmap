"""Authenticated scanning primitives: a cookie jar, a login flow and CSRF tokens.

The scanner historically only understood a static ``Cookie:`` header.  Real
targets hand out cookies, expire them, and rotate anti-CSRF tokens per form.
This module keeps that state so a scan can stay logged in:

* :class:`CookieJar` - RFC 6265 style storage (domain / path / secure /
  expiry matching) filled from ``Set-Cookie`` response headers.
* :class:`Session` - performs a form login (picking the username and password
  fields, carrying hidden CSRF tokens) and judges whether it worked.
* :func:`csrf_tokens` - extracts anti-CSRF fields from a page so a form can be
  re-submitted after the token rotated.

Cookie *values* are secrets: nothing here logs them.  Use
:meth:`CookieJar.names` / :meth:`CookieJar.describe` for reports.
"""
from __future__ import annotations

import dataclasses
import email.utils
import os
import re
import threading
import time
import urllib.parse

# Field names that usually carry a per-session anti-CSRF token.
TOKEN_RE = re.compile(r"(csrf|xsrf|token|nonce|authenticity|_wpnonce|requestverification)",
                      re.I)
# Cookie names that usually mean "you are now logged in".
SESSION_COOKIE_RE = re.compile(
    r"(sess|sid$|^sid|auth|token|jwt|login|remember|laravel|phpsessid|jsessionid|"
    r"connect\.sid|asp\.net)", re.I)
FAILURE_RE = re.compile(
    r"(invalid (username|password|credentials|login)|incorrect (username|password)|"
    r"wrong (username|password)|login failed|authentication failed|"
    r"could not (log|sign) you in|try again|bad credentials)", re.I)


def _host(url: str) -> str:
    try:
        return (urllib.parse.urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _default_path(url: str) -> str:
    path = urllib.parse.urlsplit(url).path or "/"
    if not path.startswith("/"):
        path = "/" + path
    if path.count("/") <= 1:
        return "/"
    return path[: path.rfind("/")] or "/"


def _path_match(request_path: str, cookie_path: str) -> bool:
    if request_path == cookie_path:
        return True
    if not request_path.startswith(cookie_path):
        return False
    return cookie_path.endswith("/") or request_path[len(cookie_path):][:1] == "/"


@dataclasses.dataclass
class Cookie:
    name: str
    value: str
    domain: str = ""
    path: str = "/"
    secure: bool = False
    expires: float = 0.0          # epoch seconds; 0.0 means a session cookie
    host_only: bool = True
    scheme: str = "http"           # scheme the cookie was received over

    def expired(self, now: float | None = None) -> bool:
        return bool(self.expires) and (self.expires or 0) <= (now or time.time())

    def matches(self, url: str) -> bool:
        if self.expired():
            return False
        host = _host(url)
        if not host:
            return False
        if self.host_only:
            if host != self.domain:
                return False
        elif host != self.domain and not host.endswith("." + self.domain):
            return False
        parts = urllib.parse.urlsplit(url)
        if self.secure and parts.scheme != "https":
            return False
        return _path_match(parts.path or "/", self.path)

    def redacted(self) -> str:
        return f"{self.name}=<redacted>"


def parse_set_cookie(url: str, raw: str) -> Cookie | None:
    """Parse one ``Set-Cookie`` value into a :class:`Cookie`."""
    if not raw or "=" not in raw.split(";", 1)[0]:
        return None
    pieces = [p.strip() for p in raw.split(";")]
    name, _, value = pieces[0].partition("=")
    name, value = name.strip(), value.strip()
    if not name:
        return None
    scheme = urllib.parse.urlsplit(url).scheme or "http"
    cookie = Cookie(name=name, value=value, domain=_host(url), path=_default_path(url),
                    scheme=scheme)
    for attr in pieces[1:]:
        key, _, val = attr.partition("=")
        key, val = key.strip().lower(), val.strip()
        if key == "domain" and val:
            cookie.domain = val.lstrip(".").lower()
            cookie.host_only = False
        elif key == "path" and val.startswith("/"):
            cookie.path = val
        elif key == "secure":
            cookie.secure = True
        elif key == "max-age":
            try:
                seconds = int(val)
            except ValueError:
                continue
            # Max-Age=0 (or negative) deletes the cookie.
            cookie.expires = time.time() + seconds if seconds > 0 else 1.0
        elif key == "expires" and not cookie.expires:
            try:
                when = email.utils.parsedate_to_datetime(val)
            except (TypeError, ValueError):
                continue
            if when is not None:
                cookie.expires = when.timestamp()
    return cookie


class CookieJar:
    """Thread-safe cookie store keyed by (domain, path, name)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cookies: dict[tuple[str, str, str], Cookie] = {}

    # -- writing -----------------------------------------------------
    def store(self, cookie: Cookie) -> None:
        key = (cookie.domain, cookie.path, cookie.name)
        with self._lock:
            if cookie.expired():
                self._cookies.pop(key, None)
            else:
                self._cookies[key] = cookie

    def update_from_response(self, url: str, headers) -> list[str]:
        """Remember every ``Set-Cookie`` in *headers*; return the cookie names."""
        names: list[str] = []
        for name, value in headers or []:
            if str(name).lower() != "set-cookie":
                continue
            cookie = parse_set_cookie(url, str(value))
            if cookie is None:
                continue
            self.store(cookie)
            names.append(cookie.name)
        return names

    def add_raw(self, url: str, raw: str) -> list[str]:
        """Seed the jar from a literal ``a=1; b=2`` cookie header."""
        names = []
        for part in (raw or "").split(";"):
            if "=" not in part:
                continue
            name, _, value = part.partition("=")
            name, value = name.strip(), value.strip()
            if not name:
                continue
            self.store(Cookie(name=name, value=value, domain=_host(url),
                              path="/", host_only=True,
                              scheme=urllib.parse.urlsplit(url).scheme or "http"))
            names.append(name)
        return names

    # -- reading -----------------------------------------------------
    def header_for(self, url: str) -> str:
        with self._lock:
            live = [c for c in self._cookies.values() if c.matches(url)]
        live.sort(key=lambda c: len(c.path), reverse=True)
        return "; ".join(f"{c.name}={c.value}" for c in live)

    def names(self, url: str = "") -> list[str]:
        with self._lock:
            live = [c for c in self._cookies.values()
                    if not url or c.matches(url)]
        return sorted({c.name for c in live})

    def cdp_cookies(self) -> list[dict]:
        """Cookies as ``Network.setCookie`` parameters (for browser verification)."""
        out = []
        with self._lock:
            cookies = [c for c in self._cookies.values() if not c.expired()]
        for c in cookies:
            scheme = "https" if (c.secure or c.scheme == "https") else "http"
            out.append({"name": c.name, "value": c.value, "path": c.path,
                        "url": f"{scheme}://{c.domain}{c.path}"})
        return out

    def describe(self, url: str = "") -> str:
        names = self.names(url)
        return f"{len(names)} cookie(s): {', '.join(names)}" if names else "no cookies"

    def __len__(self) -> int:
        with self._lock:
            return len([c for c in self._cookies.values() if not c.expired()])

    def __contains__(self, name: str) -> bool:
        return name in self.names()

    # -- persistence -------------------------------------------------
    def load_netscape(self, path: str) -> int:
        loaded = 0
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.rstrip("\n")
                if not line or line.startswith("#") or line.startswith("HttpOnly"):
                    continue
                fields = line.split("\t")
                if len(fields) < 7:
                    continue
                domain, _flag, cpath, secure, expiry, name, value = fields[:7]
                try:
                    expires = float(expiry)
                except ValueError:
                    expires = 0.0
                self.store(Cookie(name=name, value=value, domain=domain.lstrip(".").lower(),
                                  path=cpath or "/", secure=secure.upper() == "TRUE",
                                  expires=expires, host_only=not domain.startswith(".")))
                loaded += 1
        return loaded

    def save_netscape(self, path: str) -> str:
        """Write the jar for reuse.  The file holds live session secrets."""
        lines = ["# Netscape HTTP Cookie File", "# Written by xssmap - SENSITIVE, keep private."]
        with self._lock:
            cookies = [c for c in self._cookies.values() if not c.expired()]
        for c in sorted(cookies, key=lambda c: (c.domain, c.path, c.name)):
            lines.append("\t".join([
                ("." + c.domain) if not c.host_only else c.domain,
                "FALSE" if c.host_only else "TRUE",
                c.path, "TRUE" if c.secure else "FALSE",
                str(int(c.expires)), c.name, c.value,
            ]))
        # The file holds live session cookies, so create it owner-only from the
        # start instead of writing it world-readable and fixing it afterwards.
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        try:
            os.chmod(path, 0o600)  # keep an existing file's mode honest too
        except OSError:
            pass
        return path


# -- page helpers ----------------------------------------------------
def csrf_tokens(text: str) -> dict[str, str]:
    """Hidden anti-CSRF fields (and ``<meta name=csrf-token>``) on a page."""
    from .htmlparse import parse_page

    tokens: dict[str, str] = {}
    try:
        page = parse_page("", text or "")
    except Exception:
        page = None
    if page is not None:
        for form in page.forms:
            for name, value, ptype in form.params:
                if name and value and (ptype or "").lower() == "hidden" and TOKEN_RE.search(name):
                    tokens.setdefault(name, value)
    for match in re.finditer(
            r"""<meta[^>]+name=["']([^"']*csrf[^"']*)["'][^>]*content=["']([^"']+)""",
            text or "", re.I):
        tokens.setdefault(match.group(1), match.group(2))
    return tokens


@dataclasses.dataclass
class LoginResult:
    ok: bool
    confident: bool
    reason: str
    url: str = ""
    status: int = 0
    cookie_names: list = dataclasses.field(default_factory=list)
    notes: list = dataclasses.field(default_factory=list)

    def describe(self) -> str:
        state = "logged in" if self.ok else "login not confirmed"
        extra = f" ({', '.join(self.cookie_names)})" if self.cookie_names else ""
        return f"{state}: {self.reason}{extra}"


class Session:
    """Cookie-aware login helper bound to one :class:`xssmap.net.HTTP` client."""

    def __init__(self, http, log=None) -> None:
        self.http = http
        self.log = log
        if getattr(http, "jar", None) is None:
            http.jar = CookieJar()
        self.jar: CookieJar = http.jar
        # Kept in memory only, so a long scan can re-establish an expired
        # session before --verify replays a finding. Never written to a report.
        self.credentials: dict | None = None
        self.relogins = 0

    # -- login -------------------------------------------------------
    def login(self, url: str, username: str, password: str,
              user_field: str = "", pass_field: str = "",
              extra: dict[str, str] | None = None) -> LoginResult:
        from .htmlparse import parse_page

        try:
            before = self.http.get(url, allow_redirects=True)
        except Exception as exc:
            return LoginResult(False, True, f"could not load the login page: {str(exc)[:120]}")
        if before.status >= 400:
            return LoginResult(False, True, f"login page returned HTTP {before.status}",
                               before.url, before.status)

        page = parse_page(before.url, before.text or "")
        form = _pick_login_form(page.forms)
        fields = {p[0]: p for p in (form.params if form else [])}
        ufield = user_field or _guess_user_field(fields)
        pfield = pass_field or _guess_pass_field(fields)
        if not form or not ufield or not pfield:
            return LoginResult(False, True,
                               "no login form with a username and password field was found "
                               "(use --login-user-field/--login-pass-field)",
                               before.url, before.status)

        action = form.action or before.url
        if not action.lower().startswith(("http://", "https://")):
            action = urllib.parse.urljoin(before.url, action)
        pairs: list[tuple[str, str]] = []
        for name, value, ptype in form.params:
            if not name or (ptype or "").lower() in ("submit", "button", "image", "reset", "file"):
                continue
            if name == ufield:
                value = username
            elif name == pfield:
                value = password
            pairs.append((name, value))
        known = {n for n, _ in pairs}
        for name, value in (extra or {}).items():
            if name in known:
                pairs = [(n, value if n == name else v) for n, v in pairs]
            else:
                pairs.append((name, value))

        body = urllib.parse.urlencode(pairs).encode()
        method = (form.method or "POST").upper()
        try:
            if method == "GET":
                parts = urllib.parse.urlsplit(action)
                query = (parts.query + "&" if parts.query else "") + body.decode()
                after = self.http.get(urllib.parse.urlunsplit(
                    (parts.scheme, parts.netloc, parts.path, query, "")),
                    allow_redirects=True)
            else:
                after = self.http.post(action, body,
                                       [("Content-Type", "application/x-www-form-urlencoded"),
                                        ("Referer", before.url)],
                                       allow_redirects=True)
        except Exception as exc:
            return LoginResult(False, True, f"submitting the login form failed: {str(exc)[:120]}",
                               action, 0, self.jar.names())

        names = self.jar.names(after.url or action)
        result = self._judge(before, after, names)
        if result.ok:
            self.credentials = {"url": url, "username": username,
                                "password": password, "user_field": ufield,
                                "pass_field": pfield, "extra": dict(extra or {})}
        return result

    def relogin(self) -> LoginResult | None:
        """Submit the stored login again; ``None`` when nothing was stored.

        Called when a replayed request comes back unauthenticated, which is the
        normal outcome of a session cookie expiring during a long scan. It is a
        single retry by design: a login that keeps failing is reported, not
        hammered.
        """
        if not self.credentials:
            return None
        self.relogins += 1
        return self.login(**self.credentials)

    def _judge(self, before, after, cookie_names: list[str]) -> LoginResult:
        from .htmlparse import parse_page

        text = (after.text if getattr(after, "is_html", False) else "") or ""
        notes = [f"POST returned HTTP {after.status}, final URL {after.url}"]
        if after.status in (401, 403):
            return LoginResult(False, True, f"credentials rejected (HTTP {after.status})",
                               after.url, after.status, cookie_names, notes)
        if FAILURE_RE.search(text):
            return LoginResult(False, True, "the response contains a login failure message",
                               after.url, after.status, cookie_names, notes)
        page = parse_page(after.url, text)
        password_left = any(is_login_form(f) for f in page.forms)
        session_cookie = [n for n in cookie_names if SESSION_COOKIE_RE.search(n)]
        if session_cookie and not password_left:
            notes.append("session cookie was issued by the login response")
            return LoginResult(True, True, "session cookie issued; the login form is gone",
                               after.url, after.status, cookie_names, notes)
        if after.url and before.url and after.url.split("#")[0] != before.url.split("#")[0] \
                and not password_left:
            notes.append("the flow redirected away from the login form")
            return LoginResult(True, True, "redirected away from the login form",
                               after.url, after.status, cookie_names, notes)
        if password_left:
            return LoginResult(False, True,
                               "the login form is still present after submitting",
                               after.url, after.status, cookie_names, notes)
        return LoginResult(False, False,
                           "no session cookie, redirect or error to confirm the login",
                           after.url, after.status, cookie_names, notes)

    # -- token refresh ----------------------------------------------
    def refresh_tokens(self, page_url: str) -> dict[str, str]:
        try:
            resp = self.http.get(page_url, allow_redirects=True)
        except Exception:
            return {}
        if not getattr(resp, "is_html", False):
            return {}
        return csrf_tokens(resp.text or "")


def is_login_form(form) -> bool:
    """A form that looks like a sign-in box (password + an identity field)."""
    has_password = any((t or "").lower() == "password" for _n, _v, t in form.params)
    has_identity = any(re.search(r"(user|email|login|account|name)", n or "", re.I)
                       for n, _v, _t in form.params)
    return has_password and has_identity


def _pick_login_form(forms):
    with_password = [f for f in forms
                     if any((t or "").lower() == "password" for _n, _v, t in f.params)]
    if not with_password:
        return None
    for form in with_password:
        if re.search(r"log[-_]?in|sign[-_]?in|auth", form.action or "", re.I):
            return form
    return with_password[0]


def _guess_user_field(fields: dict) -> str:
    for name, (_name, _value, ptype) in fields.items():
        if (ptype or "").lower() in ("email", "text") and re.search(
                r"(user|email|login|account|name)", name, re.I):
            return name
    return next((n for n in fields if re.search(r"(user|email|login|account)", n, re.I)), "")


def _guess_pass_field(fields: dict) -> str:
    for name, (_name, _value, ptype) in fields.items():
        if (ptype or "").lower() == "password":
            return name
    return next((n for n in fields if re.search(r"pass", n, re.I)), "")
