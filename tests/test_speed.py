"""Tests for the request-count and worker-count rules behind scan speed.

Two things make a 4,000-URL scan slow, and both are counted here rather than
timed (timing tests are flaky in CI):

  * discovery ran at ``--threads`` (5) workers, so a 4,096-page crawl was 800
    sequential round trips. Discovery now has its own, wider default.
  * every parameter of a URL paid for its own baseline request even though the
    unmodified request is byte-identical. The baseline is shared now, and only
    its status is kept, so nothing large is cached.

Run:  python -m unittest tests.test_speed -v
"""
from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from xssmap import cli, scanner  # noqa: E402
from xssmap.net import Response  # noqa: E402

FLAT = "<html><body><p>nothing is echoed here</p></body></html>"


class _CountingHTTP:
    """Answers with a body that never contains the probe; counts every request."""

    def __init__(self):
        self.requests = []

    def send(self, req, allow_redirects: bool = False):
        self.requests.append(req)
        return Response(url=req.url, method=req.method, status=200,
                        headers=[("content-type", "text/html; charset=utf-8")],
                        body=FLAT.encode("utf-8"), elapsed=0.0)


def _points(url: str) -> list:
    return scanner.points_from_url(url, [])


class BaselineSharingTest(unittest.TestCase):
    def _run(self, points, concurrency=1):
        http = _CountingHTTP()
        scan = scanner.Scanner(http=http, browser=None)
        findings = scan.scan_points(points, concurrency=concurrency)
        return http, findings

    def test_second_parameter_reuses_the_first_baseline(self):
        # ?a=1&b=2 -> two points; their baseline request is the same URL, so the
        # second point must not pay for it again.
        http, findings = self._run(_points("https://t.example/search?a=1&b=2"))
        self.assertEqual(findings, [])
        self.assertEqual(len(http.requests), 5,
                         "two points x 3 requests minus one shared baseline")

    def test_parallel_workers_do_not_fetch_the_same_baseline_twice(self):
        # Both points start before either baseline answered; the second worker
        # must wait for the first one's answer instead of re-fetching the page.
        http, findings = self._run(_points("https://t.example/search?a=1&b=2"),
                                   concurrency=2)
        self.assertEqual(findings, [])
        self.assertEqual(len(http.requests), 5)

    def test_one_parameter_still_costs_its_own_baseline(self):
        http, _ = self._run(_points("https://t.example/search?a=1"))
        self.assertEqual(len(http.requests), 3)

    def test_different_urls_do_not_share_a_baseline(self):
        # Same parameter names, different path: the baseline is a different
        # request, so both points must send one.
        http, _ = self._run(_points("https://t.example/a?q=1") + _points("https://t.example/b?q=1"))
        self.assertEqual(len(http.requests), 6)

    def test_cache_only_holds_statuses(self):
        http = _CountingHTTP()
        scan = scanner.Scanner(http=http, browser=None)
        scan.scan_points(_points("https://t.example/search?a=1&b=2"), concurrency=1)
        self.assertTrue(all(isinstance(v, int) for v in scan._baseline_status_cache.values()),
                        "response bodies must not be kept alive by the cache")


class CrawlWorkerTest(unittest.TestCase):
    def _args(self, argv):
        parser = cli.build_parser()
        args = parser.parse_args(argv)
        cli.finalize_args(args)
        return args

    def test_discovery_runs_wider_than_payload_testing_by_default(self):
        args = self._args(["-u", "https://t.example/"])
        self.assertEqual(args.threads, 10)
        self.assertEqual(args.crawl_threads, 16)

    def test_explicit_crawl_threads_wins(self):
        args = self._args(["-u", "https://t.example/", "--crawl-threads", "4"])
        self.assertEqual(args.crawl_threads, 4)

    def test_payload_threads_raise_the_discovery_floor(self):
        # Asking for 40 payload workers must not leave discovery at 16.
        args = self._args(["-u", "https://t.example/", "--threads", "40"])
        self.assertEqual(args.crawl_threads, 40)

    def test_autonomous_keeps_the_wider_discovery_default(self):
        args = self._args(["--domain", "example.com", "--autonomous"])
        self.assertGreaterEqual(args.crawl_threads, 16)


if __name__ == "__main__":
    unittest.main()
