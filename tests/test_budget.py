"""Unit tests for --max-minutes: the budget must bind *inside* a phase.

A between-phases check only notices a phase that has already finished, which is
exactly the overrun it is supposed to prevent: one large crawl produces
thousands of points, and the scan phase then runs past the promised deadline
without ever looking at the clock again. These tests pin the per-point
behaviour that makes the budget honest, and pin the resume contract that goes
with it: a point skipped for budget reasons must not be recorded as completed,
otherwise --state would silently drop it from the next run.
"""
from __future__ import annotations

import os
import sys
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from xssmap.domscan import DomScanner  # noqa: E402
from xssmap.htmlparse import Form  # noqa: E402
from xssmap.scanner import Scanner  # noqa: E402
from xssmap.stored import StoredScanner  # noqa: E402


class Point:
    """Minimal injection point: enough for keying, logging and progress."""

    def __init__(self, name: str):
        self.name = name

    def label(self) -> str:
        return self.name


def a_form() -> Form:
    return Form(action="http://lab.invalid/post", method="POST",
                enctype="application/x-www-form-urlencoded",
                params=[("comment", "", "text")],
                origin_url="http://lab.invalid/")


class FakeLog:
    def __init__(self):
        self.warnings = []

    def warn(self, message):
        self.warnings.append(message)

    def info(self, message):
        pass

    def debug(self, message):
        pass

    def progress(self, *args):
        pass

    def found(self, finding):
        pass


class ReflectedBudgetTests(unittest.TestCase):
    def test_no_deadline_changes_nothing(self):
        scanner = Scanner(http=object())
        seen = []
        scanner.scan_point = lambda point: seen.append(point) or []
        scanner.scan_points(["a", "b", "c"], concurrency=1)
        self.assertEqual(seen, ["a", "b", "c"])
        self.assertFalse(scanner.budget_exhausted)
        self.assertFalse(scanner.budget_stop)

    def test_expired_deadline_sends_no_request(self):
        scanner = Scanner(http=object(), deadline=time.monotonic() - 1.0)
        scanned = []
        scanner._scan = lambda point: scanned.append(point) or []
        self.assertEqual(scanner.scan_point("p1"), [])
        self.assertEqual(scanned, [])
        self.assertTrue(scanner.budget_exhausted)

    def test_skipped_point_is_not_recorded_as_progress(self):
        scanner = Scanner(http=object(), deadline=time.monotonic() - 1.0)
        scanner.scan_points(["a", "b"], concurrency=1)
        self.assertEqual(scanner.completed_points, set())
        self.assertEqual(scanner.stats["points"], 0)

    def test_budget_stops_a_running_phase(self):
        scanner = Scanner(http=object(), deadline=time.monotonic() + 0.15)
        seen = []

        def slow_point(point):
            seen.append(point)
            time.sleep(0.1)
            return []

        scanner.scan_point = slow_point
        points = [f"p{i}" for i in range(12)]
        started = time.monotonic()
        scanner.scan_points(points, concurrency=1)
        elapsed = time.monotonic() - started
        self.assertTrue(scanner.budget_exhausted)
        self.assertTrue(scanner.budget_stop)
        self.assertGreaterEqual(len(seen), 1)
        self.assertLess(len(seen), len(points))
        # the queued tail must be dropped, not merely marked: a stalled point
        # would otherwise keep the process alive past the deadline
        self.assertNotIn("p11", seen)
        self.assertLess(elapsed, 1.0)

    def test_warning_reports_points_actually_tested(self):
        # Counting futures that are "not done yet" was wrong: a free worker
        # drains the gate-skipped queue in microseconds, so the number bore no
        # relation to the work lost. The message must report the tested count.
        log = FakeLog()
        scanner = Scanner(http=object(), log=log, deadline=time.monotonic() + 0.15)
        scanner._scan = lambda point: (time.sleep(0.1), [])[1]
        scanner.scan_points([Point(f"p{i}") for i in range(8)], concurrency=1)
        self.assertEqual(len(log.warnings), 1)
        self.assertIn(f"{scanner.stats['points']} point(s) tested", log.warnings[0])
        self.assertNotIn("left untested", log.warnings[0])

    def test_budget_stop_with_threads_drops_the_queue(self):
        scanner = Scanner(http=object(), deadline=time.monotonic() + 0.15)
        seen = []

        def slow_point(point):
            seen.append(point)
            time.sleep(0.08)
            return []

        scanner.scan_point = slow_point
        scanner.scan_points([f"p{i}" for i in range(40)], concurrency=4)
        self.assertTrue(scanner.budget_stop)
        self.assertLess(len(seen), 40)


class StoredBudgetTests(unittest.TestCase):
    def test_expired_deadline_flags_exhaustion(self):
        scanner = StoredScanner(http=object(), deadline=time.monotonic() - 1.0)
        self.assertTrue(scanner._over_budget())
        self.assertTrue(scanner.budget_exhausted)

    def test_no_deadline_never_flags(self):
        scanner = StoredScanner(http=object())
        self.assertFalse(scanner._over_budget())
        self.assertFalse(scanner.budget_exhausted)

    def test_expired_deadline_plants_nothing(self):
        scanner = StoredScanner(http=object(), deadline=time.monotonic() - 1.0)
        outcome = scanner.scan("http://lab.invalid/", [a_form()], [])
        self.assertEqual(outcome["findings"], [])
        self.assertEqual(outcome["stats"]["markers"], 0)
        self.assertEqual(outcome["stats"]["submitted"], 0)
        self.assertTrue(scanner.budget_exhausted)


class DomBudgetTests(unittest.TestCase):
    def test_expired_deadline_flags_exhaustion(self):
        scanner = DomScanner(browser=None, deadline=time.time() - 1.0)
        self.assertTrue(scanner._out_of_budget())
        self.assertTrue(scanner.budget_exhausted)

    def test_no_deadline_never_flags(self):
        scanner = DomScanner(browser=None)
        self.assertFalse(scanner._out_of_budget())
        self.assertFalse(scanner.budget_exhausted)

    def test_expired_deadline_drives_no_browser_flow(self):
        # A browser that raises would prove the gate ran before any navigation.
        class ExplodingBrowser:
            available = True

            def navigate(self, url):
                raise AssertionError("navigated past the budget")

        scanner = DomScanner(browser=ExplodingBrowser(), deadline=time.time() - 1.0)
        resource = ("http://lab.invalid/app.js",
                    "document.body.innerHTML = location.search;",
                    ["http://lab.invalid/"])
        outcome = scanner.scan("http://lab.invalid/", [resource])
        self.assertEqual(outcome["findings"], [])
        self.assertTrue(scanner.budget_exhausted)


if __name__ == "__main__":
    unittest.main()


class TransportDeadlineTests(unittest.TestCase):
    """Loops check the clock, but a single request can still block for
    ``--timeout`` seconds after the budget is gone. The transport has to clip
    itself, and the throttle must not pace a scan that is already over."""

    def test_without_a_deadline_the_configured_timeout_is_used(self):
        from xssmap.net import HTTP
        http = HTTP(timeout=9.0)
        self.assertEqual(http._timeout(), 9.0)

    def test_timeout_is_clipped_to_the_remaining_budget(self):
        from xssmap.net import HTTP
        http = HTTP(timeout=30.0)
        http.set_deadline(time.monotonic() + 2.0)
        self.assertLessEqual(http._timeout(), 2.0)
        self.assertGreater(http._timeout(), 1.0)

    def test_spent_budget_fails_fast_instead_of_hanging(self):
        from xssmap.net import HTTP
        http = HTTP(timeout=30.0)
        http.set_deadline(time.monotonic() - 5.0)
        self.assertLessEqual(http._timeout(), 0.25)

    def test_deadline_is_shared_with_the_throttle(self):
        from xssmap.net import HTTP, Throttle
        throttle = Throttle(delay=0.0)
        http = HTTP(timeout=5.0, throttle=throttle)
        deadline = time.monotonic() + 1.0
        http.set_deadline(deadline)
        self.assertEqual(throttle.deadline, deadline)

    def test_throttle_does_not_sleep_past_the_deadline(self):
        from xssmap.net import Throttle
        throttle = Throttle(delay=0.0)
        throttle.blocked_until = time.monotonic() + 30.0  # a long Retry-After
        throttle.set_deadline(time.monotonic() + 0.2)
        started = time.monotonic()
        throttle.wait("t.invalid")
        self.assertLess(time.monotonic() - started, 1.0)
