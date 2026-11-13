"""Crawl scheduling and transport cost.

Three behaviours are pinned here, all of them things that made a crawl slower
than the work it was doing:

  * the crawl queue is fed continuously, so ``max_depth`` counts hops from the
    seed and ``max_pages`` is a hard stop;
  * a 500 from the target is not read as backpressure (only 429/503 are, and
    only after a short streak);
  * binary bodies are read up to a cap and their connection is dropped instead
    of being returned to the pool half-drained.
"""
from __future__ import annotations

import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssmap.crawler import Crawler, Scope
from xssmap.net import HTTP, MAX_BINARY_BODY, Throttle

SEED = "http://app.test/"


class QuietLog:
    def info(self, *_a, **_k):
        pass

    def debug(self, *_a, **_k):
        pass

    def warn(self, *_a, **_k):
        pass

    def ok(self, *_a, **_k):
        pass

    def action(self, *_a, **_k):
        pass


class PageResp:
    """Enough of :class:`xssmap.net.Response` for the crawler to parse."""

    def __init__(self, url, status=200, text="", content_type="text/html"):
        self.url = url
        self.status = status
        self.text = text
        self.body = text.encode()
        self.content_type = content_type
        self.history: list = []

    @property
    def is_html(self):
        return self.content_type.startswith("text/html")

    @property
    def is_javascript(self):
        return "javascript" in self.content_type


class RouterHTTP:
    def __init__(self, pages):
        self.pages = pages
        self.urls: list[str] = []

    def get(self, url, headers=None, **_kwargs):
        self.urls.append(url)
        if url.endswith("/robots.txt") or url.endswith("/sitemap.xml"):
            return PageResp(url, 404, "not found", "text/plain")
        text = self.pages.get(url)
        if text is None:
            return PageResp(url, 404, "not found", "text/html")
        ctype = "application/javascript" if url.endswith(".js") else "text/html"
        return PageResp(url, 200, text, ctype)


def crawl(pages, depth, max_pages=50):
    http = RouterHTTP(pages)
    crawler = Crawler(http, Scope(SEED), QuietLog(), max_depth=depth,
                      max_pages=max_pages, crawl_js=True)
    return crawler.run([SEED]), http


class DepthTests(unittest.TestCase):
    PAGES = {
        SEED: '<a href="/a">a</a><a href="/b">b</a>',
        "http://app.test/a": '<a href="/a1">a1</a>',
        "http://app.test/b": '<a href="/b1">b1</a>',
        "http://app.test/a1": '<a href="/a2">a2</a>',
        "http://app.test/b1": "leaf",
        "http://app.test/a2": "leaf",
    }

    def test_depth_counts_hops_from_seed(self):
        _result, http = crawl(self.PAGES, depth=1)
        fetched = {u for u in http.urls if not u.endswith(("/robots.txt", "/sitemap.xml"))}
        self.assertEqual(fetched, {SEED, "http://app.test/a", "http://app.test/b"})
        self.assertNotIn("http://app.test/a1", fetched)

    def test_seed_is_depth_zero(self):
        result, _http = crawl(self.PAGES, depth=1)
        self.assertEqual(result.pages[SEED].depth, 0)
        self.assertEqual(result.pages["http://app.test/a"].depth, 1)

    def test_page_budget_stops_the_crawl(self):
        _result, http = crawl(self.PAGES, depth=5, max_pages=2)
        fetched = [u for u in http.urls if not u.endswith(("/robots.txt", "/sitemap.xml"))]
        self.assertEqual(len(fetched), 2)

    def test_boundary_pages_are_fetched_but_not_expanded(self):
        result, _http = crawl(self.PAGES, depth=2)
        # The seed is hop 0, so depth 2 reaches /a1 at hop 2 and stops there.
        self.assertEqual(result.pages["http://app.test/a1"].depth, 2)
        self.assertNotIn("http://app.test/a2", result.pages)


class ThrottleTests(unittest.TestCase):
    def test_application_error_is_not_backpressure(self):
        throttle = Throttle(delay=0.0)
        for _ in range(6):
            throttle.on_status(500)
        self.assertEqual(throttle.delay, 0.0)

    def test_single_load_signal_does_not_slow_the_scan(self):
        throttle = Throttle(delay=0.0)
        throttle.on_status(503)
        self.assertEqual(throttle.delay, 0.0)

    def test_repeated_load_signals_slow_then_recover(self):
        throttle = Throttle(delay=0.0)
        throttle.on_status(429)
        throttle.on_status(429)
        slowed = throttle.delay
        self.assertGreater(slowed, 0.0)
        for _ in range(6):
            throttle.on_status(200)
        self.assertLess(throttle.delay, slowed)
        self.assertGreaterEqual(throttle.delay, throttle.base_delay)

    def test_adaptive_delay_is_capped(self):
        throttle = Throttle(delay=0.0)
        for _ in range(20):
            throttle.on_status(503)
        self.assertLessEqual(throttle.delay, 3.0)


class _BodyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    disable_nagle_algorithm = True

    def log_message(self, *_a):
        pass

    def do_GET(self):
        if self.path == "/big.bin":
            body = b"\x00" * (MAX_BINARY_BODY + 500_000)
            ctype = "application/octet-stream"
        elif self.path == "/small.bin":
            body = b"\x00" * 2048
            ctype = "application/octet-stream"
        else:
            body = b"<html><body>hello</body></html>"
            ctype = "text/html"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        # A client that abandons a capped binary body leaves the server thread
        # writing into a closed socket; that is the behaviour under test.
        pass


class BodyCapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = _QuietServer(("127.0.0.1", 0), _BodyHandler)
        cls.server.daemon_threads = True
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_binary_body_is_capped_and_flagged(self):
        http = HTTP(timeout=10, retries=0, throttle=Throttle())
        resp = http.get(self.base + "/big.bin")
        self.assertTrue(resp.truncated)
        self.assertEqual(len(resp.body), MAX_BINARY_BODY)

    def test_truncated_connection_is_not_pooled(self):
        http = HTTP(timeout=10, retries=0, throttle=Throttle())
        http.get(self.base + "/big.bin")
        self.assertEqual(len(http._pool()), 0)

    def test_full_binary_body_is_pooled(self):
        # Under the cap nothing is truncated, so the socket stays reusable.
        http = HTTP(timeout=10, retries=0, throttle=Throttle())
        resp = http.get(self.base + "/small.bin")
        self.assertFalse(resp.truncated)
        pool = http._pool()
        self.assertEqual(len(pool), 1)
        for _key, conn, _used in pool:
            conn.close()

    def test_text_body_is_read_in_full_and_pooled(self):
        http = HTTP(timeout=10, retries=0, throttle=Throttle())
        resp = http.get(self.base + "/page.html")
        self.assertFalse(resp.truncated)
        self.assertIn(b"hello", resp.body)
        pool = http._pool()
        self.assertEqual(len(pool), 1)
        for _key, conn, _used in pool:
            conn.close()


if __name__ == "__main__":
    unittest.main()
