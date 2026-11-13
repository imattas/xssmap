"""Headless browser execution verifier.

A reflected payload that survives verbatim is strong evidence, but only a real
engine proves execution -- and a real engine is also what proves that a Content
Security Policy *stopped* it. We look for a local Chrome/Chromium/Edge, drive it
over the DevTools protocol (stdlib WebSocket, no dependencies) and ask the live
DOM whether the injected script managed to create its artifact element.

Asking the DOM instead of grepping the serialized HTML matters: the handler
source itself contains the marker string, so a substring match would "confirm"
payloads that never ran.

For POST injections a tiny auto-submitting form is written to disk and opened,
so the browser performs a genuine cross-document POST to the target.
"""
from __future__ import annotations

import base64
import json
import os
import platform
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from typing import Any

from .verify import Verification

CANDIDATES_WIN = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
    r"C:\Program Files\Chromium\Application\chrome.exe",
]

CANDIDATES_NIX = [
    "/usr/bin/google-chrome", "/usr/bin/google-chrome-stable", "/usr/bin/chromium",
    "/usr/bin/chromium-browser", "/snap/bin/chromium", "/usr/bin/microsoft-edge",
    "/usr/bin/brave-browser", "/usr/bin/vivaldi",
]

CANDIDATES_MAC = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
]


def find_browser() -> str | None:
    system = platform.system()
    if system == "Windows":
        paths = CANDIDATES_WIN
    elif system == "Darwin":
        paths = CANDIDATES_MAC
    else:
        paths = CANDIDATES_NIX
    for p in paths:
        if p and os.path.isfile(p):
            return p
    for name in ("chrome", "chromium", "google-chrome", "msedge", "brave-browser"):
        found = shutil.which(name)
        if found:
            return found
    return None


class DevToolsError(RuntimeError):
    pass


class WebSocket:
    """Bare-bones RFC 6455 client: text frames out, text messages in."""

    def __init__(self, url: str, timeout: float = 15.0):
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("ws", "wss"):
            raise DevToolsError(f"unsupported websocket url: {url}")
        host, port = parts.hostname, parts.port or (443 if parts.scheme == "wss" else 80)
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        request = (
            f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(request.encode())
        raw = b""
        while b"\r\n\r\n" not in raw:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise DevToolsError("devtools closed during handshake")
            raw += chunk
        head, _, self._buf = raw.partition(b"\r\n\r\n")
        status = head.split(b"\r\n", 1)[0]
        if b" 101 " not in status + b" ":
            raise DevToolsError(f"devtools handshake failed: {status[:80]!r}")

    # -- framing -------------------------------------------------------
    def _read(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self.sock.recv(max(4096, n - len(self._buf)))
            if not chunk:
                raise DevToolsError("devtools connection closed")
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        mask = os.urandom(4)
        header = bytearray([0x80 | opcode])
        n = len(payload)
        if n < 126:
            header.append(0x80 | n)
        elif n < 65536:
            header.append(0x80 | 126)
            header += struct.pack(">H", n)
        else:
            header.append(0x80 | 127)
            header += struct.pack(">Q", n)
        header += mask
        masked = bytes(b ^ mask[i & 3] for i, b in enumerate(payload))
        self.sock.sendall(bytes(header) + masked)

    def send(self, text: str) -> None:
        self._send_frame(0x1, text.encode("utf-8"))

    def recv(self) -> str:
        chunks: list[bytes] = []
        while True:
            try:
                b1, b2 = self._read(2)
            except socket.timeout as exc:
                raise DevToolsError("devtools read timed out") from exc
            fin, opcode = b1 & 0x80, b1 & 0x0F
            masked, length = b2 & 0x80, b2 & 0x7F
            if length == 126:
                length = struct.unpack(">H", self._read(2))[0]
            elif length == 127:
                length = struct.unpack(">Q", self._read(8))[0]
            mask = self._read(4) if masked else None
            payload = self._read(length)
            if mask:
                payload = bytes(b ^ mask[i & 3] for i, b in enumerate(payload))
            if opcode == 0x9:  # ping
                self._send_frame(0xA, payload)
                continue
            if opcode == 0x8:
                raise DevToolsError("devtools closed the session")
            chunks.append(payload)
            if fin:
                return b"".join(chunks).decode("utf-8", "replace")

    def close(self) -> None:
        try:
            self._send_frame(0x8, b"")
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass


class CDP:
    """One request at a time; events are collected but never awaited."""

    def __init__(self, ws: WebSocket):
        self.ws = ws
        self._id = 0
        self.events: list[dict] = []

    def call(self, method: str, params: dict | None = None, timeout: float = 20.0) -> dict:
        self._id += 1
        mid = self._id
        self.ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
        deadline = time.time() + timeout
        while True:
            if time.time() > deadline:
                raise DevToolsError(f"devtools timeout on {method}")
            message = json.loads(self.ws.recv())
            if message.get("id") == mid:
                if "error" in message:
                    raise DevToolsError(str(message["error"].get("message", message["error"])))
                return message.get("result") or {}
            if "method" in message:
                self.events.append(message)


class BrowserVerifier:
    def __init__(self, enabled: bool = True, timeout: float = 25.0, log=None,
                 headless: str = "new", proxy: str | None = None):
        self.log = log
        self.timeout = timeout
        self.headless = headless
        self.proxy = proxy
        self.path = find_browser() if enabled else None
        self.available = bool(enabled and self.path)
        self.runs = 0
        self.hits = 0
        self.launches = 0            # browser process starts, expected to stay at 1
        self.seconds = 0.0           # wall time spent inside verification
        self.last_error = ""
        self.last_result: dict = {}
        self.cookies: list[dict] = []   # [{'name','value','url'}] applied over CDP
        self._profile: str | None = None
        self._proc: subprocess.Popen | None = None
        self._cdp: CDP | None = None
        self._port: int | None = None
        self._observers_on = False
        self._lock = threading.RLock()

    def describe(self) -> str:
        """One line for the report header.

        ``launches`` is reported on purpose: the verifier keeps one browser
        process and one DevTools session alive for the whole scan, so a run with
        many checks and a single launch is the evidence that page loads were
        reused instead of paying a browser start per payload.
        """
        if not self.available:
            return "browser verification: disabled (no Chromium/Chrome/Edge found)"
        note = f"browser verification: {os.path.basename(self.path or '')}"
        if self.runs:
            note += (f" ({self.runs} check(s), {self.launches} launch(es), "
                     f"{1000.0 * self.seconds / self.runs:.0f} ms/check)")
        return note

    # -- lifecycle -----------------------------------------------------
    def _profile_dir(self) -> str:
        if self._profile is None:
            self._profile = tempfile.mkdtemp(prefix="xssmap-profile-")
        return self._profile

    def _launch(self) -> None:
        if self._cdp is not None and self._port and self._alive(self._port):
            return
        self._shutdown_browser()
        profile = self._profile_dir()
        port = _free_port()
        proxy_args = (["--proxy-server=" + self.proxy] if self.proxy
                      else ["--no-proxy-server"])
        args = [
            self.path or "",
            f"--headless={self.headless}" if self.headless in ("new", "old") else "--headless",
            "--no-sandbox",
            *proxy_args,
            f"--remote-debugging-port={port}",
            f"--user-data-dir={profile}",
            "--disable-gpu",
            "--disable-dev-shm-usage",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-extensions",
            "--disable-background-networking",
            "--disable-sync",
            "--disable-popup-blocking",
            "--mute-audio",
            "--window-size=1280,900",
            "about:blank",
        ]
        kwargs: dict = {
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
        }
        if platform.system() == "Windows":
            kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
        else:
            kwargs["start_new_session"] = True
        self._proc = subprocess.Popen(args, **kwargs)

        # The Windows launcher often exits at once while the real browser keeps
        # running detached, so liveness is judged by the DevTools endpoint only.
        if not self._wait_for_devtools(port, 20.0):
            raise DevToolsError(self.last_error or "browser did not expose a DevTools port")
        self._port = port
        ws_url = self._page_socket(port)
        cdp = CDP(WebSocket(ws_url, timeout=20.0))
        self._cdp = cdp
        for domain in ("Page.enable", "Runtime.enable"):
            try:
                cdp.call(domain, timeout=10.0)
            except DevToolsError:
                pass
        self.launches += 1

    def _alive(self, port: int) -> bool:
        try:
            with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/json/version", timeout=1.5) as resp:
                return getattr(resp, "status", 0) == 200
        except Exception:
            return False

    def _wait_for_devtools(self, port: int, timeout: float) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._alive(port):
                return True
            time.sleep(0.15)
        return False

    def _page_socket(self, port: int) -> str:
        base = f"http://127.0.0.1:{port}"
        for _ in range(40):
            try:
                with urllib.request.urlopen(base + "/json/list", timeout=2) as resp:
                    targets = json.loads(resp.read().decode("utf-8", "replace"))
                for t in targets:
                    if t.get("type") == "page" and t.get("webSocketDebuggerUrl"):
                        return t["webSocketDebuggerUrl"]
            except Exception:
                pass
            time.sleep(0.25)
        # no page target yet: ask for one explicitly
        try:
            req = urllib.request.Request(base + "/json/new?about:blank", method="PUT")
            with urllib.request.urlopen(req, timeout=3) as resp:
                target = json.loads(resp.read().decode("utf-8", "replace"))
            if target.get("webSocketDebuggerUrl"):
                return target["webSocketDebuggerUrl"]
        except Exception:
            pass
        raise DevToolsError("browser exposed no page target")

    def _shutdown_browser(self) -> None:
        # graceful: ask the browser to exit through its own DevTools endpoint
        if self._port:
            try:
                with urllib.request.urlopen(
                        f"http://127.0.0.1:{self._port}/json/version", timeout=1.5) as resp:
                    info = json.loads(resp.read().decode("utf-8", "replace"))
                browser_ws = info.get("webSocketDebuggerUrl")
                if browser_ws:
                    CDP(WebSocket(browser_ws, timeout=4.0)).call("Browser.close", timeout=3.0)
            except Exception:
                pass
        if self._cdp is not None:
            try:
                self._cdp.ws.close()
            except Exception:
                pass
        self._cdp = None
        self._observers_on = False
        if self._proc is not None and self._proc.poll() is None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=3)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
        self._proc = None
        if self._profile:
            _kill_by_profile(self._profile)
        self._port = None

    # -- navigation ----------------------------------------------------
    def _evaluate(self, expression: str, timeout: float = 15.0) -> str:
        cdp = self._cdp
        if cdp is None:
            return ""
        result = cdp.call("Runtime.evaluate", {
            "expression": expression, "returnByValue": True, "awaitPromise": False,
        }, timeout=timeout)
        return str((result.get("result") or {}).get("value") or "")

    def _evaluate_raw(self, expression: str, timeout: float = 15.0):
        """Evaluate and return the value with its type intact (dicts stay dicts)."""
        cdp = self._cdp
        if cdp is None:
            return None
        result = cdp.call("Runtime.evaluate", {
            "expression": expression, "returnByValue": True, "awaitPromise": False,
        }, timeout=timeout)
        if result.get("exceptionDetails"):
            return None
        return (result.get("result") or {}).get("value")

    def _load(self, url: str) -> None:
        cdp = self._cdp
        if cdp is None:
            return
        result = cdp.call("Page.navigate", {"url": url}, timeout=20.0)
        self.last_result = {"requested": url, "error": result.get("errorText") or ""}
        deadline = time.time() + 8.0
        while time.time() < deadline:
            try:
                if self._evaluate("document.readyState", timeout=5.0) == "complete":
                    break
            except DevToolsError:
                pass
            time.sleep(0.1)
        time.sleep(0.15)  # let load handlers (and inline onload) settle

    def _dom_check(self, target_id: str) -> str:
        expr = ("(function(){var e=document.getElementById(" + json.dumps(target_id) +
                ");return e?(e.tagName+':'+e.id):''})()")
        return self._evaluate(expr)

    def _enable_observers(self) -> None:
        """Turn on the event domains we need to explain a non-execution.

        Without these, "the handler never fired" and "CSP refused the handler"
        look identical from the outside. Enabling them costs one round trip per
        browser launch and buys a defensible reason for every negative.
        """
        if self._cdp is None or self._observers_on:
            return
        for domain in ("Runtime.enable", "Log.enable", "Network.enable"):
            try:
                self._cdp.call(domain, timeout=10.0)
            except DevToolsError:
                pass  # not fatal: we just lose a diagnostic channel
        self._observers_on = True
        self._apply_cookies()

    def set_cookies(self, cookies) -> None:
        """Carry an authenticated session into the verifier (secrets stay in memory)."""
        self.cookies = [dict(c) for c in (cookies or []) if c.get("name")]

    def _apply_cookies(self) -> None:
        if self._cdp is None or not self.cookies:
            return
        for cookie in self.cookies:
            try:
                self._cdp.call("Network.setCookie", {
                    "name": cookie["name"], "value": cookie["value"],
                    "url": cookie["url"], "path": cookie.get("path", "/"),
                }, timeout=10.0)
            except (DevToolsError, KeyError):
                continue  # a rejected cookie must not break verification

    def _event_mark(self) -> int:
        return len(self._cdp.events) if self._cdp is not None else 0

    def _events_since(self, mark: int) -> dict:
        """Distil events after ``mark`` into the handful of facts we care about."""
        out: dict[str, Any] = {"csp": [], "errors": [], "failed": [], "scripts": 0}
        if self._cdp is None:
            return out
        for event in self._cdp.events[mark:]:
            method = event.get("method", "")
            params = event.get("params") or {}
            if method == "Log.entryAdded":
                entry = params.get("entry") or {}
                text = (entry.get("text") or "")[:300]
                low = text.lower()
                if "content security policy" in low or entry.get("source") == "security":
                    out["csp"].append(text)
                elif entry.get("level") == "error":
                    out["errors"].append(text)
            elif method == "Runtime.exceptionThrown":
                details = params.get("exceptionDetails") or {}
                text = (details.get("text") or "") + " " + str(
                    (details.get("exception") or {}).get("description", ""))
                if "content security policy" in text.lower():
                    out["csp"].append(text[:300])
                else:
                    out["errors"].append(text.strip()[:300])
            elif method == "Network.loadingFailed":
                reason = params.get("blockedReason") or params.get("errorText") or ""
                if reason:
                    out["failed"].append(str(reason)[:120])
                    if "csp" in str(reason).lower():
                        out["csp"].append(f"request blocked: {reason}")
            elif method == "Network.requestWillBeSent":
                kind = params.get("type")
                if kind == "Script":
                    out["scripts"] += 1
        # Drop the consumed window: a long scan would otherwise accumulate every
        # event of every navigation for the whole run. Each caller takes a fresh
        # mark immediately before loading, so trimming here is safe.
        self._cdp.events[:] = self._cdp.events[mark:][-500:]
        return out

    # -- public API ----------------------------------------------------
    def evaluate(self, expression: str, timeout: float = 15.0) -> str:
        with self._lock:
            self._launch()
            return self._evaluate(expression, timeout=timeout)

    def navigate(self, url: str, settle: float = 0.2) -> dict:
        """Load a URL in the current tab and report what actually happened."""
        with self._lock:
            self._launch()
            self._apply_cookies()
            try:
                before = self._evaluate("document.URL")
            except DevToolsError:
                before = ""
            self.last_result = {"url": url, "loaded": False}
            cdp = self._cdp
            if cdp is None:
                self.last_result = {"url": url, "loaded": False,
                                    "error": "browser connection is not open"}
                return self.last_result
            try:
                result = cdp.call("Page.navigate", {"url": url}, timeout=25.0)
            except DevToolsError as exc:
                self.last_result = {"url": url, "loaded": False, "error": str(exc)[:200]}
                return self.last_result
            error_text = result.get("errorText")
            # Page.navigate returns before the new document commits. Poll until the
            # URL actually changes; otherwise readyState still describes the old page
            # and every check races the load.
            same_doc = before.split("#", 1)[0] == url.split("#", 1)[0]
            deadline = time.time() + (3.0 if same_doc else 10.0)
            final_url = before
            ready = ""
            while time.time() < deadline:
                try:
                    final_url = self._evaluate("document.URL")
                    ready = self._evaluate("document.readyState")
                except DevToolsError:
                    time.sleep(0.1)
                    continue
                if ready in ("interactive", "complete") and (same_doc or final_url != before):
                    break
                time.sleep(0.1)
            time.sleep(settle)
            ready = self._evaluate("document.readyState") or ready
            loaded = bool(final_url) and ready in ("interactive", "complete")
            self.last_result = {
                "url": final_url, "requested": url,
                "loaded": loaded, "error": error_text or "",
                "title": self._evaluate("document.title"),
            }
            return self.last_result

    def _wait_ready(self, timeout: float = 8.0) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                if self._evaluate("document.readyState", timeout=5.0) in ("interactive", "complete"):
                    return
            except DevToolsError:
                pass
            time.sleep(0.1)

    def screenshot(self, path: str) -> bool:
        """Capture the viewport as PNG evidence."""
        with self._lock:
            if self._cdp is None:
                return False
            try:
                data = self._cdp.call("Page.captureScreenshot", {"format": "png"}, timeout=15.0)
                raw = base64.b64decode(data.get("data", ""))
                if not raw:
                    return False
                os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
                with open(path, "wb") as fh:
                    fh.write(raw)
                return True
            except Exception:
                return False

    def _page_live(self) -> dict:
        """Is there a committed, parsed document in the tab right now?"""
        try:
            probe = self._evaluate(
                "(function(){return JSON.stringify({u:document.URL,"
                "r:document.readyState,b:!!document.body,"
                "n:(document.body?document.body.childElementCount:0)})})()")
        except DevToolsError as exc:
            return {"live": False, "error": str(exc)[:160]}
        try:
            data = json.loads(probe) if probe else {}
        except ValueError:
            return {"live": False, "error": "unreadable page probe"}
        data["live"] = bool(data.get("u")) and data.get("r") in ("interactive", "complete")
        return data

    def verify_execution(self, req, target_id: str,
                         screenshot_path: str | None = None) -> Verification:
        """Load the injected request and return a tri-state verdict.

        The distinction that matters: a page that loaded and did nothing is
        ``not_observed`` (a real negative), while anything that stopped us from
        getting a valid look is ``not_tested`` (an absence of evidence). Only
        the first may be used to argue that a payload does not work.
        """
        if not self.available:
            return Verification.not_tested("no Chromium/Chrome/Edge on this host")
        with self._lock:
            self.runs += 1
            started = time.monotonic()
            wrapper = None
            self.last_result = {"loaded": False}
            try:
                target = req.url
                if req.method.upper() == "POST":
                    wrapper = self._post_wrapper(req)
                    if wrapper is None:
                        return Verification.not_tested(
                            "could not build a POST wrapper page for the browser")
                    target = "file:///" + wrapper.replace("\\", "/")
                self._launch()
                self._enable_observers()
                mark = self._event_mark()
                self._load(target)
                live = self._page_live()
                events = self._events_since(mark)
                self.last_result = {
                    "loaded": bool(live.get("live")),
                    "url": live.get("u", ""),
                    "requested": req.url,
                    "csp": events["csp"],
                    "console_errors": events["errors"],
                    "failed_requests": events["failed"],
                    "scripts": events["scripts"],
                }
                if not live.get("live"):
                    reason = (live.get("error") or "no committed document")
                    nav = (self.last_result or {}).get("error") or ""
                    if nav:
                        reason = f"{reason}; navigation error: {nav}"
                    return Verification.not_tested(f"page never committed: {reason}"[:240])

                found = self._dom_check(target_id)
                if screenshot_path:
                    self.screenshot(screenshot_path)
                if found:
                    self.hits += 1
                    return Verification.confirmed(
                        f"DOM contains injected node <{found}> after execution",
                        artifact=found, url=live.get("u", ""))

                detail = {"url": live.get("u", ""), "scripts": events["scripts"],
                          "csp": events["csp"], "console_errors": events["errors"]}
                if events["csp"]:
                    return Verification.not_observed(
                        "Content-Security-Policy refused execution: "
                        + events["csp"][0][:160], **detail)
                if events["errors"]:
                    return Verification.not_observed(
                        "handler did not run; console reported: "
                        + events["errors"][0][:160], **detail)
                return Verification.not_observed(
                    "page rendered; the payload handler produced no effect", **detail)
            except DevToolsError as exc:
                self.last_error = str(exc)[:200]
                self.last_result = {"loaded": False, "error": self.last_error}
                self._shutdown_browser()
                return Verification.not_tested(f"devtools failure, browser recycled: {exc}"[:240])
            except Exception as exc:
                self.last_error = f"{type(exc).__name__}: {exc}"[:200]
                self.last_result = {"loaded": False, "error": self.last_error}
                self._shutdown_browser()
                return Verification.from_exception(exc, "verifier error")
            finally:
                self.seconds += time.monotonic() - started
                if wrapper and os.path.exists(wrapper):
                    try:
                        os.remove(wrapper)
                    except OSError:
                        pass

    def prove(self, req, probe_js: str, target_id: str = "",
              trigger_js: str = "") -> dict:
        """Load a request and report what the injected script actually reached.

        :meth:`verify_execution` answers "did this payload run" with one DOM
        artifact. This answers the next question: once it runs, what can it
        read and do? The probe is the injected script's own report (cookies it
        can see, same-origin fetches it can make, whether it still owns the
        document), so an exploit claim rests on the page's behaviour rather
        than on the scanner's expectation of it.
        """
        out: dict = {"loaded": False, "probe": None, "artifact": "",
                     "csp": [], "errors": [], "failed": [], "url": "", "error": ""}
        if not self.available:
            out["error"] = "no Chromium/Chrome/Edge on this host"
            return out
        with self._lock:
            wrapper = None
            try:
                target = req.url
                if req.method.upper() == "POST":
                    wrapper = self._post_wrapper(req)
                    if wrapper is None:
                        body = (req.body or b"").lstrip()
                        if body.startswith((b"{", b"[")):
                            out["error"] = ("JSON request bodies have no form equivalent, so "
                                            "this POST cannot be replayed from a wrapper page")
                        else:
                            out["error"] = "could not build a POST wrapper page for the browser"
                        return out
                    target = "file:///" + wrapper.replace("\\", "/")
                self._launch()
                self._enable_observers()
                mark = self._event_mark()
                self._load(target)
                live = self._page_live()
                events = self._events_since(mark)
                out.update({"loaded": bool(live.get("live")),
                            "url": live.get("u", ""),
                            "csp": events["csp"], "errors": events["errors"],
                            "failed": events["failed"], "scripts": events["scripts"]})
                self.last_result = dict(out)
                if not out["loaded"]:
                    out["error"] = live.get("error") or "no committed document"
                    return out
                if trigger_js:
                    try:
                        self._evaluate(trigger_js, timeout=5.0)
                    except DevToolsError:
                        pass
                    time.sleep(0.2)  # let the dispatched handlers run
                if target_id:
                    out["artifact"] = self._dom_check(target_id)
                if probe_js:
                    out["probe"] = self._evaluate_raw(probe_js)
                return out
            except DevToolsError as exc:
                self.last_error = str(exc)[:200]
                self._shutdown_browser()
                out["error"] = f"devtools failure, browser recycled: {exc}"[:240]
                return out
            except Exception as exc:
                self.last_error = f"{type(exc).__name__}: {exc}"[:200]
                self._shutdown_browser()
                out["error"] = self.last_error
                return out
            finally:
                if wrapper and os.path.exists(wrapper):
                    try:
                        os.remove(wrapper)
                    except OSError:
                        pass

    def roundtrip(self, markup: str, target_id: str) -> dict:
        """Serialize *markup* the way a sanitiser would, then re-parse it live.

        Mutation XSS lives in the gap between the parser that produced a
        document and the parser that later consumes it. This mirrors that gap:
        parse -> serialise -> parse in a fresh document that actually executes,
        and report whether the second parse produced a live node.
        """
        if not self.available:
            return {"ok": False, "error": "browser unavailable"}
        script = _ROUNDTRIP_JS % (json.dumps(markup), json.dumps(target_id))
        with self._lock:
            self._launch()
            if self._cdp is None:
                return {"ok": False, "error": "browser not running"}
            try:
                result = self._cdp.call("Runtime.evaluate", {
                    "expression": script, "returnByValue": True, "awaitPromise": True,
                }, timeout=20.0)
                raw = str((result.get("result") or {}).get("value") or "")
            except DevToolsError as exc:
                self._shutdown_browser()
                return {"ok": False, "error": str(exc)[:200]}
            try:
                data = json.loads(raw) if raw else {}
            except ValueError:
                return {"ok": False, "error": "unreadable round-trip result"}
            data["ok"] = True
            data["activated"] = bool(data.get("hit"))
            data["control_activated"] = bool(data.get("control_hit"))
            return data

    def _post_wrapper(self, req) -> str | None:
        try:
            body = (req.body or b"").decode("utf-8", "replace")
            pairs = urllib.parse.parse_qsl(body, keep_blank_values=True)
            if not pairs:
                return None
            inputs = "\n".join(
                f'<input type="hidden" name="{_attr(k)}" value="{_attr(v)}">' for k, v in pairs
            )
            html = (
                "<!doctype html><html><body>"
                f'<form id="f" method="POST" action="{_attr(req.url)}">{inputs}</form>'
                "<script>document.getElementById('f').submit();</script>"
                "</body></html>"
            )
            fd, path = tempfile.mkstemp(prefix="xssmap-post-", suffix=".html")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(html)
            return path
        except Exception:
            return None

    def cleanup(self) -> None:
        with self._lock:
            self._shutdown_browser()
            if self._profile and os.path.isdir(self._profile):
                shutil.rmtree(self._profile, ignore_errors=True)
            self._profile = None


def _free_port() -> int:
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def _kill_by_profile(profile: str) -> None:
    """Stop browser processes still holding *profile* (they can outlive the launcher)."""
    names = ("msedge.exe", "chrome.exe", "brave.exe", "chromium.exe")
    if platform.system() == "Windows":
        quoted = profile.replace("'", "''")
        filter_names = " or ".join(f"Name='{n}'" for n in names)
        script = (
            f"Get-CimInstance Win32_Process -Filter \"{filter_names}\" | "
            f"Where-Object {{ $_.CommandLine -like '*{quoted}*' }} | "
            "ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"
        )
        try:
            subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=25,
                creationflags=0x08000000,
            )
        except Exception:
            pass
    else:
        try:
            subprocess.run(
                ["pkill", "-f", profile], stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10,
            )
        except Exception:
            pass


def _attr(value: str) -> str:
    return (value.replace("&", "&amp;").replace('"', "&quot;")
            .replace("<", "&lt;").replace(">", "&gt;"))


# Parse -> serialise -> re-parse, with a paired control so the comparison is
# meaningful. Both stages load a same-origin srcdoc iframe that really executes:
#   control  = a fresh document parsed from the raw markup
#   test     = a fresh document parsed from serialize(parse(raw markup))
# A vector is mutation XSS only when the control stays inert and the test
# executes. Without the control, an ordinary payload that the serialiser merely
# re-quotes (src=x -> src="x") would be mislabelled as a mutation.
# The stage parse happens in a detached div, so nothing runs there; any stray
# artifact that a detached parse somehow created is cleaned up afterwards.
# Two %s slots, filled with json.dumps(): braces are never interpreted.
_ROUNDTRIP_JS = """(async function(){
  var payload = %s, target = %s;
  var stage = document.createElement('div');
  stage.innerHTML = payload;
  var serialized = stage.innerHTML;
  function loadInto(html) {
    return new Promise(function(resolve){
      var frame = document.createElement('iframe');
      frame.setAttribute('aria-hidden','true');
      frame.style.cssText = 'width:0;height:0;border:0;position:absolute;left:-9999px';
      (document.body || document.documentElement).appendChild(frame);
      var settled = false;
      function finish(how) {
        if (settled) { return; }
        settled = true;
        setTimeout(function(){
          var hit = '', err = '';
          try {
            var doc = frame.contentDocument;
            var el = doc && doc.getElementById(target);
            if (el) { hit = el.tagName + ':' + el.id; }
          } catch (e) { err = e.name; }
          frame.remove();
          resolve({hit: hit, error: err, how: how});
        }, 200);
      }
      frame.addEventListener('load', function(){ finish('load'); }, {once:true});
      setTimeout(function(){ finish('timeout'); }, 2000);
      frame.srcdoc = '<!doctype html><html><body>' + html + '</body></html>';
    });
  }
  var control = await loadInto(payload);
  var test = await loadInto(serialized);
  var stray = document.getElementById(target);
  if (stray && stray.parentNode) { stray.parentNode.removeChild(stray); }
  stage.remove();
  return JSON.stringify({serialized: serialized,
                         control_hit: control.hit, control_how: control.how,
                         hit: test.hit, how: test.how, error: test.error});
})()"""
