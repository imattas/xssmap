"""Tests for the promises the scanner makes about its own uncertainty.

Three groups:

* a verdict is never invented -- an internal error is NOT_TESTED, an interrupt
  keeps what was already proven, and a callback beacon only reads cookies when
  the operator asked for it;
* template hygiene -- ``str.format`` on a JavaScript template turns every
  literal brace into a format field, which is a bug this codebase has hit;
* package hygiene -- no bare ``except:`` and every module imports cleanly.

Run:  python -m unittest tests.test_honesty -v
"""
from __future__ import annotations

import ast
import importlib
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from xssmap import scanner  # noqa: E402
from xssmap.callback import BEACON_JS, COOKIE_EXPR, CallbackListener  # noqa: E402
from xssmap.verify import CONFIRMED, NOT_OBSERVED, NOT_TESTED, Verification  # noqa: E402

PKG = os.path.join(ROOT, "xssmap")


def modules():
    for name in sorted(os.listdir(PKG)):
        if name.endswith(".py"):
            path = os.path.join(PKG, name)
            with open(path, encoding="utf-8") as fh:
                yield path, ast.parse(fh.read(), filename=path)


class TestVerdicts(unittest.TestCase):
    def test_internal_error_is_not_a_negative(self):
        verdict = Verification.from_exception(RuntimeError("devtools died"), "probe")
        self.assertEqual(verdict.state, NOT_TESTED)
        self.assertFalse(verdict.was_tested)
        self.assertFalse(verdict.is_confirmed)
        self.assertIn("devtools died", verdict.reason)

    def test_states_are_distinct(self):
        self.assertNotEqual(NOT_TESTED, NOT_OBSERVED)
        self.assertTrue(Verification.not_observed("loaded, nothing fired").was_tested)
        self.assertFalse(Verification.not_tested("no browser").was_tested)

    def test_merge_prefers_the_stronger_evidence(self):
        confirmed = Verification.confirmed("node found")
        self.assertIs(confirmed.merge(Verification.not_tested("x")).state, CONFIRMED)
        self.assertIs(Verification.not_tested("x").merge(confirmed).state, CONFIRMED)
        observed = Verification.not_observed("loaded, no effect")
        self.assertIs(observed.merge(Verification.not_tested("timeout")).state, NOT_OBSERVED)

    def test_merge_never_upgrades_unknown_to_negative(self):
        merged = Verification.not_tested("a").merge(Verification.not_tested("b"))
        self.assertEqual(merged.state, NOT_TESTED)
        self.assertIn("a", merged.reason)
        self.assertIn("b", merged.reason)


class TestInterrupt(unittest.TestCase):
    """Ctrl-C must not discard findings that are already proven."""

    def test_interrupt_keeps_completed_findings_and_flags_the_run(self):
        s = scanner.Scanner(http=object())
        seen = []

        def fake_scan_point(point):
            seen.append(point)
            if len(seen) > 1:
                raise KeyboardInterrupt()
            return [make_finding("first")]

        s.scan_point = fake_scan_point
        out = s.scan_points(["p1", "p2", "p3"], concurrency=1)
        self.assertTrue(s.interrupted)
        self.assertEqual([f.url for f in out], ["first"])

    def test_normal_run_is_not_flagged(self):
        s = scanner.Scanner(http=object())
        s.scan_point = lambda point: []
        self.assertEqual(s.scan_points(["p1"], concurrency=1), [])
        self.assertFalse(s.interrupted)


def make_finding(url: str) -> scanner.Finding:
    return scanner.Finding(url=url, method="GET", param="q", location="query",
                           payload="<x>", context="html_text", status=200)


class TestCallbackCookies(unittest.TestCase):
    def test_cookies_are_off_by_default(self):
        listener = CallbackListener()
        js = listener.beacon("abc123")
        self.assertNotIn("document.cookie", js)
        self.assertIn("abc123", js)

    def test_cookies_are_sent_only_when_enabled(self):
        listener = CallbackListener(capture_cookies=True)
        js = listener.beacon("abc123")
        self.assertIn(COOKIE_EXPR, js)
        self.assertIn("abc123", js)

    def test_beacon_keeps_its_shape(self):
        for enabled in (False, True):
            js = CallbackListener(capture_cookies=enabled).beacon("m1")
            self.assertIn("/hit?m=", js)
            self.assertIn("location.href", js)
            # braces are literal JavaScript, so the template must not be formatted
            self.assertIn("(function(){", js)
            self.assertIn(BEACON_JS.split("%s")[0][:20], js)


class TestTemplateHygiene(unittest.TestCase):
    """`str.format` on a JavaScript snippet is a bug, not a style choice.

    A JS constant is full of literal braces (function bodies, object literals),
    and format() raises ValueError on the first one that is not a field. The
    error is easy to swallow in a bare except, which is exactly how the DOM
    artifact probe stopped running. Templates that *are* meant to be formatted
    (report.HTML_TEMPLATE) carry doubled braces and are not matched here.
    """

    NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")
    TEMPLATE_HINT = ("_JS", "_SNIPPET")

    def test_no_format_on_module_templates(self):
        offenders = []
        for path, tree in modules():
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                if not isinstance(func, ast.Attribute) or func.attr != "format":
                    continue
                target = func.value
                if not isinstance(target, ast.Name) or not self.NAME.match(target.id):
                    continue
                if any(hint in target.id for hint in self.TEMPLATE_HINT):
                    offenders.append(f"{os.path.basename(path)}:{node.lineno} {target.id}.format()")
        self.assertEqual(offenders, [],
                         "str.format() on a JavaScript snippet: literal braces raise "
                         "ValueError and the error is easy to swallow")

    def test_html_template_is_a_real_format_template(self):
        # The one formatted template keeps its literal braces doubled.
        from xssmap import report
        self.assertIn("{{ --bg:", report.HTML_TEMPLATE)

    def test_every_module_imports(self):
        for name in sorted(os.listdir(PKG)):
            if not name.endswith(".py") or name.startswith("__main__"):
                continue
            module = "xssmap." + name[:-3]
            with self.subTest(module=module):
                importlib.import_module(module)


class TestNoBareExcept(unittest.TestCase):
    def test_no_bare_except_handlers(self):
        offenders = []
        for path, tree in modules():
            for node in ast.walk(tree):
                if isinstance(node, ast.ExceptHandler) and node.type is None:
                    offenders.append(f"{os.path.basename(path)}:{node.lineno}")
        self.assertEqual(offenders, [],
                         "bare 'except:' also swallows KeyboardInterrupt and SystemExit")


if __name__ == "__main__":
    unittest.main(verbosity=2)
