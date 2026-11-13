"""Unit tests for the per-parameter fuzz matrix.

The fuzzer's job is to describe what a parameter does to the response, not to
claim a vulnerability. The tests pin down the three distinctions that matter:
raw reflection, HTML-encoded reflection, and server-side evaluation; plus the
baseline comparison that keeps boilerplate punctuation from being reported as
an injected reflection.

Run:  python tests/test_fuzz.py
"""
from __future__ import annotations

import html
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from stubhttp import FakeHTTP, Resp, query_dict

from xssmap import fuzz

URL = "http://t.example/search?q=1"
BASE = "<html><body><h1>search</h1><p>results</p></body></html>"


def _value(url: str) -> str:
    return query_dict(url).get("q", "")


def echo(url: str) -> Resp:
    """Reflects the value into a text node, byte for byte."""
    return Resp(url, 200, BASE.replace("</body>", f"<p>value: {_value(url)}</p></body>"))


def encoder(url: str) -> Resp:
    """Reflects the value through html.escape(), like a template engine."""
    return Resp(url, 200, BASE.replace(
        "</body>", "<p>value: " + html.escape(_value(url)) + "</p></body>"))


def boilerplate(url: str) -> Resp:
    """A static page that already contains every punctuation probe literal."""
    return Resp(url, 200,
                "<html lang='en'><body title=\"page\"><!-- nav -->"
                "<p>static</p></body></html>")


def evaluator(url: str) -> Resp:
    """Evaluates {{7*7}} and ${7*7} server-side and prints only the result."""
    body = BASE
    if "7*7" in _value(url):
        body = body.replace("</body>", "<p>result: 49</p></body>")
    return Resp(url, 200, body)


def echo_debug(url: str) -> Resp:
    """Only ``debug`` is read and echoed; used for the discovery path."""
    query = query_dict(url)
    if "debug" in query:
        return Resp(url, 200, BASE.replace(
            "</body>", f"<p>value: {query['debug']}</p></body>"))
    return Resp(url, 200, BASE)


class TestFuzzParam(unittest.TestCase):
    def _report(self, router, budget: int = 32):
        http = FakeHTTP(router)
        return fuzz.fuzz_param(http, URL, 0, "q", budget=budget), http

    def test_raw_reflection_is_classified(self):
        report, _http = self._report(echo)
        self.assertIn("single-quote", report.raw)
        self.assertIn("tag", report.raw)
        self.assertNotIn("single-quote", report.encoded)
        self.assertTrue(report.context)
        # One baseline plus one request per probe.
        self.assertEqual(report.requests, 1 + len(fuzz.PROBES))
        self.assertEqual(len(report.results), len(fuzz.PROBES))

    def test_encoded_reflection_is_not_reported_as_raw(self):
        report, _http = self._report(encoder)
        by_probe = {r.probe: r.state for r in report.results}
        for probe in ("single-quote", "double-quote", "angle-open", "tag"):
            with self.subTest(probe=probe):
                self.assertEqual(by_probe[probe], "encoded")
        self.assertNotIn("single-quote", report.raw)
        # Parentheses are not escaped by html.escape(), so they really do
        # survive verbatim and must be reported as raw.
        self.assertIn("parens", report.raw)

    def test_boilerplate_punctuation_is_not_a_reflection(self):
        report, _http = self._report(boilerplate)
        self.assertEqual(report.raw, [])
        self.assertEqual(report.encoded, [])
        self.assertEqual(report.evaluated, [])
        self.assertEqual(len(report.results), len(fuzz.PROBES))

    def test_template_evaluation_is_detected(self):
        report, _http = self._report(evaluator)
        self.assertEqual(sorted(report.evaluated), ["ssti-dollar", "ssti-moustache"])
        self.assertIn("server-side template evaluation detected", report.notes)

    def test_probe_budget_is_respected(self):
        report, http = self._report(echo, budget=3)
        self.assertEqual(len(report.results), 3)
        self.assertEqual(report.requests, 4, "baseline plus three probes")
        self.assertEqual(len(http.urls), 4)

    def test_as_dict_shape(self):
        report, _http = self._report(echo)
        data = report.as_dict()
        for key in ("name", "url", "context", "raw", "encoded", "evaluated",
                    "notes", "requests", "probes"):
            self.assertIn(key, data)
        self.assertEqual(data["name"], "q")
        self.assertIn("probe", data["probes"][0])


class TestRun(unittest.TestCase):
    def test_every_parameter_is_fuzzed(self):
        http = FakeHTTP(echo)
        result = fuzz.run(http, [URL])
        self.assertEqual([p["name"] for p in result["params"]], ["q"])
        self.assertTrue(result["params"][0]["raw"])
        self.assertFalse(result["truncated"])
        self.assertEqual(result["requests"], result["params"][0]["requests"])

    def test_url_without_params_is_skipped_with_a_hint(self):
        result = fuzz.run(FakeHTTP(echo), ["http://t.example/search"])
        self.assertEqual(result["params"], [])
        self.assertIn("discover-params", result["skipped"][0]["reason"])

    def test_discovery_finds_and_fuzzes_a_hidden_parameter(self):
        http = FakeHTTP(echo_debug)
        result = fuzz.run(http, ["http://t.example/search"], discover=True)
        self.assertIn("discovery", result)
        self.assertEqual(result["params"][0]["name"], "debug")
        self.assertTrue(result["params"][0]["raw"])
        self.assertIn("debug=1", result["urls"][0])

    def test_budget_truncates_the_run(self):
        result = fuzz.run(FakeHTTP(echo), [URL], max_requests=5)
        self.assertTrue(result["truncated"])
        self.assertEqual(len(result["params"]), 1)
        self.assertEqual(result["requests"], 5)

    def test_summary_counts(self):
        result = fuzz.run(FakeHTTP(echo), [URL])
        data = fuzz.summary(result)
        self.assertEqual(set(data), {"parameters_fuzzed", "with_raw_reflection",
                                     "encoded_only", "template_evaluation",
                                     "requests", "truncated"})
        self.assertEqual(data["parameters_fuzzed"], 1)
        self.assertEqual(data["with_raw_reflection"], 1)
        self.assertFalse(data["truncated"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
