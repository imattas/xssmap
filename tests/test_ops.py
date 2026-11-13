"""Unit tests for the operational layer: Retry-After, resume state, viewers."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from xssmap import report as rp  # noqa: E402
from xssmap import state as stateio  # noqa: E402
from xssmap.callback import CallbackListener  # noqa: E402
from xssmap.htmlparse import Form  # noqa: E402
from xssmap.net import Throttle, parse_retry_after  # noqa: E402
from xssmap.scanner import Finding, QueryPoint, Scanner  # noqa: E402
from xssmap.stored import StoredScanner  # noqa: E402


class RetryAfterTests(unittest.TestCase):
    def test_delta_seconds(self):
        self.assertEqual(parse_retry_after("5"), 5.0)
        self.assertEqual(parse_retry_after(" 0 "), 0.0)
        self.assertEqual(parse_retry_after("2.5"), 2.5)

    def test_clamped(self):
        self.assertEqual(parse_retry_after("99999"), 120.0)

    def test_rejects_negative_and_garbage(self):
        for value in ("-4", "", "   ", "soon", None, "Wed, 32 Nov 2026 99:99:99 GMT"):
            self.assertIsNone(parse_retry_after(value), value)

    def test_http_date(self):
        import datetime as dt
        from email.utils import format_datetime
        when = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=30)
        parsed = parse_retry_after(format_datetime(when))
        self.assertIsNotNone(parsed)
        self.assertGreater(parsed, 25.0)
        self.assertLessEqual(parsed, 30.0)


class ThrottleTests(unittest.TestCase):
    def test_hold_from_429(self):
        throttle = Throttle()
        hold = throttle.on_response(429, [("Retry-After", "0.25")])
        self.assertEqual(hold, 0.25)
        self.assertEqual(throttle.holds, 1)
        started = time.monotonic()
        throttle.wait("example.test")
        self.assertGreaterEqual(time.monotonic() - started, 0.2)

    def test_header_is_case_insensitive(self):
        throttle = Throttle()
        self.assertEqual(throttle.on_response(503, [("retry-after", "1")]), 1.0)

    def test_ignored_on_success(self):
        throttle = Throttle()
        self.assertIsNone(throttle.on_response(200, [("Retry-After", "5")]))
        self.assertEqual(throttle.blocked_until, 0.0)

    def test_ignored_without_header(self):
        throttle = Throttle()
        self.assertIsNone(throttle.on_response(429, []))
        self.assertEqual(throttle.holds, 0)


class ResumeStateTests(unittest.TestCase):
    def _finding(self) -> Finding:
        return Finding(
            url="https://t.example/search?q=1", method="GET", param="q",
            location="query", payload="<svg/onload=alert(1)>", context="html_text",
            status=200, confidence="high", verified_browser=True,
            browser_checked=True, verify_state="confirmed", verify_reason="handler ran",
            csp_blocked=False, csp="default-src 'self'", interaction=False,
            evidence="--- request ---\nGET /search?q=1", notes=["browser confirmed"],
            content_type="text/html", nosniff=True, reflections=2, encoding="none",
        )

    def test_round_trip(self):
        finding = self._finding()
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "state.json")
            stateio.save_state(path, ["https://t.example"], {"q:a", "f:b"}, [finding], [])
            loaded = stateio.load_state(path)
            self.assertNotIn("error", loaded)
            self.assertEqual(set(loaded["done"]), {"q:a", "f:b"})
            self.assertEqual(len(loaded["findings"]), 1)
            back = loaded["findings"][0]
            self.assertEqual(back.url, finding.url)
            self.assertEqual(back.payload, finding.payload)
            self.assertEqual(back.verify_state, "confirmed")
            self.assertTrue(back.verified_browser)
            self.assertEqual(rp.severity_of(back), rp.severity_of(finding))

    def test_missing_file_is_empty(self):
        loaded = stateio.load_state(os.path.join(tempfile.gettempdir(), "xssmap-none.json"))
        self.assertEqual(loaded["done"], [])
        self.assertNotIn("error", loaded)

    def test_corrupt_file_reports_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "state.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("{not json")
            loaded = stateio.load_state(path)
            self.assertEqual(loaded["done"], [])
            self.assertIn("error", loaded)

    def test_unknown_version_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "state.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"version": 99, "done": ["x"]}, fh)
            loaded = stateio.load_state(path)
            self.assertIn("error", loaded)
            self.assertEqual(loaded["done"], [])

    def test_skipped_point_is_not_marked_complete(self):
        point = QueryPoint("https://t.example/?q=1", 0, [])
        scanner = Scanner(http=None)
        key = scanner._point_key(point)
        scanner = Scanner(http=None, skip_points={key})
        self.assertEqual(scanner.scan_point(point), [])
        self.assertEqual(scanner.resumed_points, 1)
        self.assertEqual(scanner.completed_points, set())


class CallbackTests(unittest.TestCase):
    def test_public_url_overrides_the_bind_address_in_payloads(self):
        listener = CallbackListener(host="127.0.0.1", port=0,
                                    public_url="https://cb.example/hook/")
        self.assertEqual(listener.url, "https://cb.example/hook")
        self.assertEqual(listener.public_url, "https://cb.example/hook")
        # The served beacon stays relative so it also works through a tunnel.
        self.assertIn("'/hit?m='+m", listener.beacon("m1"))

    def test_default_url_is_the_bound_loopback_address(self):
        listener = CallbackListener(host="127.0.0.1", port=4321)
        self.assertEqual(listener.url, "http://127.0.0.1:4321")

    def test_hit_is_recorded_and_attributed_to_its_marker(self):
        import urllib.request
        listener = CallbackListener(host="127.0.0.1", port=0).start()
        try:
            url = listener.url + "/hit?m=m1&u=http%3A%2F%2Fvictim.tld%2Fpage"
            with urllib.request.urlopen(url, timeout=5) as resp:
                self.assertEqual(resp.status, 200)
            found = listener.wait_for("m1", timeout=2.0)
            self.assertIsNotNone(found)
            self.assertEqual(found["victim_url"], "http://victim.tld/page")
            self.assertEqual(listener.seen("other"), [])
        finally:
            listener.stop()


class _Resp:
    def __init__(self, url: str, text: str = "", status: int = 200):
        self.url = url
        self.text = text
        self.status = status
        self.is_html = True


class _FakeHTTP:
    def __init__(self):
        self.gets: list[str] = []
        self.posts: list[str] = []

    def get(self, url: str, allow_redirects: bool = True):
        self.gets.append(url)
        return _Resp(url, "<html><body>nothing here</body></html>")

    def post(self, url: str, data: bytes, headers=None, allow_redirects: bool = False):
        self.posts.append(url)
        return _Resp(url, "ok")


class ViewerUrlTests(unittest.TestCase):
    def test_viewer_url_is_fetched_first(self):
        http = _FakeHTTP()
        form = Form(action="https://t.example/guestbook", method="POST",
                    enctype="application/x-www-form-urlencoded",
                    params=[("comment", "", "text")],
                    origin_url="https://t.example/guestbook")
        scanner = StoredScanner(http, viewer_urls=["https://t.example/admin/inbox"],
                                max_pages=1)
        scanner.scan("https://t.example/", [form], ["https://t.example/guestbook"])
        self.assertEqual(http.gets[0], "https://t.example/admin/inbox")
        self.assertEqual(len(http.gets), 1, "max_pages should keep the viewer only")


if __name__ == "__main__":
    unittest.main(verbosity=2)
