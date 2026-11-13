"""Unit tests for hidden-parameter discovery.

The discovery strategy is two cheap passes: one batched request carrying a unique
marker per candidate name (echoes prove the parameter is read) and one bounded
single-parameter pass for names that change the response without echoing.

Run:  python tests/test_params.py
"""
from __future__ import annotations

import html
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from stubhttp import FakeHTTP, Resp, query_dict

from xssmap import params

URL = "http://t.example/search?q=1"
BASE_BODY = "<html><body><h1>search</h1><p>results</p></body></html>"


def echo_debug(url: str) -> Resp:
    """Only ``debug`` is read, and its value is echoed into the page."""
    query = query_dict(url)
    if "debug" in query:
        return Resp(url, 200, BASE_BODY.replace("</body>", f"<pre>{query['debug']}</pre></body>"))
    return Resp(url, 200, BASE_BODY)


def shape_debug(url: str) -> Resp:
    """Only ``debug`` is read, and it changes the body without echoing anything."""
    query = query_dict(url)
    body = BASE_BODY
    if "debug" in query:
        body = body.replace("</body>", "<div class=debug>" + "x" * 300 + "</div></body>")
    return Resp(url, 200, body)


def plain(url: str) -> Resp:
    return Resp(url, 200, BASE_BODY)


class TestDiscovery(unittest.TestCase):
    def test_reflected_parameter_is_reported_with_reflection_signal(self):
        found = params.discover(FakeHTTP(echo_debug), URL)
        self.assertEqual(found.names(), ["debug"])
        item = found.found[0]
        self.assertTrue(item.reflected)
        self.assertEqual(item.signal, "reflection")
        self.assertEqual(item.status, 200)
        self.assertTrue(item.evidence)

    def test_parameter_that_only_changes_shape_is_confirmed_separately(self):
        http = FakeHTTP(shape_debug)
        found = params.discover(http, URL)
        self.assertEqual(found.names(), ["debug"])
        item = found.found[0]
        self.assertFalse(item.reflected)
        self.assertEqual(item.signal, "shape")
        self.assertGreater(abs(item.delta), 48)
        # One single-parameter confirmation request has to have been made.
        self.assertTrue(any("debug=1" in u for u in http.urls))

    def test_quiet_target_reports_nothing(self):
        http = FakeHTTP(plain)
        found = params.discover(http, URL)
        self.assertEqual(found.found, [])
        # 120 of the 183 built-in candidates fit the default budget.
        self.assertEqual(found.tested, min(len(params.CANDIDATES), 120))
        # two baselines + four batches + twelve confirmations, never more
        self.assertLessEqual(found.requests, 2 + 4 + 12)
        self.assertGreaterEqual(found.requests, 2 + 4)

    def test_existing_parameters_are_not_re_discovered(self):
        url = URL + "&debug=1"
        found = params.discover(FakeHTTP(echo_debug), url)
        self.assertNotIn("debug", found.names())

    def test_wordlist_is_tested_before_the_builtin_candidates(self):
        http = FakeHTTP(echo_debug)
        found = params.discover(http, URL, wordlist=["tenant", "debug", "tenant"])
        # The budget is 120 names; a user wordlist has to sit inside it, not
        # behind the 183 built-ins where truncation would silently drop it.
        self.assertEqual(found.tested, 120)
        batches = [u for u in http.urls if "xsq" in u]
        self.assertTrue(any("tenant=xsq0zq" in u for u in batches), batches[:1])
        self.assertTrue(any("debug=xsq1zq" in u for u in batches), batches[:1])
        # Deduplicated against the built-in list, not tested twice.
        self.assertEqual(len([u for u in batches if "tenant=" in u]), 1)
        self.assertIn("debug", found.names())

    def test_alphanumeric_markers_survive_output_encoding(self):
        # Markers are alphanumeric, so HTML/URL-encoding the response cannot
        # hide them. The old "URL-encoded" heuristic was unreachable (quote()
        # is the identity for alphanumeric text) and has been removed.
        def encoded(url: str) -> Resp:
            query = query_dict(url)
            value = query.get("debug")
            if value is None:
                return Resp(url, 200, BASE_BODY)
            return Resp(url, 200, BASE_BODY.replace(
                "</body>", html.escape(value) + "</body>"))

        found = params.discover(FakeHTTP(encoded), URL)
        self.assertIn("debug", found.names())
        self.assertIn("verbatim", found.found[0].evidence)

    def test_validation_mention_is_reported_as_error_signal(self):
        def picky(url: str) -> Resp:
            query = query_dict(url)
            if "debug" in query:
                return Resp(url, 200, BASE_BODY.replace(
                    "</body>", "<p>invalid value for parameter debug</p></body>"))
            return Resp(url, 200, BASE_BODY)

        found = params.discover(FakeHTTP(picky), URL)
        self.assertIn("debug", found.names())
        item = next(d for d in found.found if d.name == "debug")
        self.assertEqual(item.signal, "error")
        self.assertFalse(item.reflected)

    def test_unreachable_target_is_reported_not_raised(self):
        def boom(url):
            raise OSError("connection refused")

        found = params.discover(FakeHTTP(boom), URL)
        self.assertEqual(found.found, [])
        self.assertIn("baseline request failed", found.note)

    def test_single_request_per_batch(self):
        http = FakeHTTP(plain)
        params.discover(http, URL)
        batches = [u for u in http.urls if u.count("xsq") > 1]
        self.assertEqual(len(batches), 4, "120 candidates in batches of 30")

    def test_as_dict_shape(self):
        found = params.discover(FakeHTTP(echo_debug), URL)
        data = found.as_dict()
        for key in ("url", "tested", "requests", "baseline_status",
                    "baseline_length", "note", "params"):
            self.assertIn(key, data)
        self.assertEqual(data["url"], URL)
        self.assertIn("name", data["params"][0])


class TestWithParams(unittest.TestCase):
    def test_existing_query_is_preserved_and_names_are_added(self):
        url = params.with_params("http://t.example/p?q=1", ["debug", "preview"])
        query = query_dict(url)
        self.assertEqual(query["q"], "1")
        self.assertIn("debug", query)
        self.assertIn("preview", query)

    def test_empty_name_list_is_a_no_op(self):
        self.assertEqual(params.with_params(URL, []), URL)


class BodyHTTP:
    """POST-capable fake: hands the decoded body to a router."""

    def __init__(self, router):
        self.router = router
        self.bodies: list[bytes] = []
        self.stats = {"requests": 0, "errors": 0, "bytes": 0, "rate_limits": 0}

    def post(self, url, body, headers=None, **kwargs):
        self.bodies.append(body)
        self.stats["requests"] += 1
        return self.router(url, json.loads(body.decode("utf-8")))

    def get(self, url, headers=None, **kwargs):
        return self.router(url, {})


class TestBodyDiscovery(unittest.TestCase):
    def test_property_read_only_from_the_body_is_found(self):
        def router(url, data):
            if "template" in data:
                return Resp(url, 200, BASE_BODY.replace(
                    "</body>", f"<p>{data['template']}</p></body>"))
            return Resp(url, 200, BASE_BODY)

        http = BodyHTTP(router)
        found = params.discover_body(http, URL, '{"q": "1"}', "json",
                                     max_params=40, batch_size=40)
        self.assertEqual(found.names(), ["template"])
        self.assertTrue(found.found[0].reflected)
        # two baselines, one batch, and confirmations bounded in requests
        self.assertLessEqual(found.requests, 2 + 1 + 12)

    def test_shape_change_that_does_not_reproduce_is_rejected(self):
        state = {"n": 0}

        def router(url, data):
            if "debug" in data:
                state["n"] += 1
                if state["n"] == 1:      # only the first probe is bigger
                    return Resp(url, 200, BASE_BODY.replace(
                        "</body>", "x" * 400 + "</body>"))
            return Resp(url, 200, BASE_BODY)

        http = BodyHTTP(router)
        found = params.discover_body(http, URL, "{}", "json", max_params=6,
                                     batch_size=6, max_followups=4)
        # A one-off size change is what a nonce looks like: the two-shot
        # confirmation exists to keep it out of the report.
        self.assertNotIn("debug", found.names())

    def test_body_with_adds_exactly_one_member(self):
        body = params.body_with('{"a": 1}', "json", "b", "xsq")
        self.assertEqual(json.loads(body), {"a": 1, "b": "xsq"})

    def test_names_from_js_reads_parameter_names(self):
        names = params.names_from_js([
            ("http://t.example/app.js",
             "fetch('/api?report_id=' + id); params.debug = 1; "
             "searchParams.get('preview');", []),
        ])
        self.assertIn("report_id", names)
        self.assertIn("debug", names)
        self.assertIn("preview", names)
        self.assertEqual(params.names_from_js([]), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
