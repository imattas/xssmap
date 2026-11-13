"""Unit tests for the character-level filter brute forcer.

The brute forcer never touches HTTP itself: it takes a ``send(value)`` callable,
which is exactly what makes it testable without a network or a mock server.

Run:  python tests/test_brute.py
"""
from __future__ import annotations

import html
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from stubhttp import Resp

from xssmap import brute

MARKER = "bm5"


def reflector(url="http://t.example/?q=1"):
    """Echoes the value back verbatim, like a page with no filter at all."""
    def send(value: str) -> Resp:
        return Resp(url, 200, f"<html><body><p>value: {value}</p></body></html>")
    return send


def encoder(url="http://t.example/?q=1"):
    """HTML-encodes every special character, like a template engine does."""
    def send(value: str) -> Resp:
        return Resp(url, 200, "<html><body><p>value: "
                    + html.escape(value, quote=True) + "</p></body></html>")
    return send


def stripper(url="http://t.example/?q=1"):
    """Deletes the five characters a naive sanitiser blocks."""
    def send(value: str) -> Resp:
        cleaned = "".join(ch for ch in value if ch not in "<>\"'`")
        return Resp(url, 200, f"<html><body><p>value: {cleaned}</p></body></html>")
    return send


class TestCharMap(unittest.TestCase):
    def test_everything_raw_costs_one_request_per_character(self):
        budget = 1 + len(brute.PROBE_CHARS)
        chars = brute.map_chars(reflector(), MARKER, max_requests=budget)
        self.assertTrue(chars.marker_ok)
        self.assertEqual(chars.requests, budget)
        self.assertEqual(chars.stripped, [])
        for ch in brute.PROBE_CHARS:
            with self.subTest(ch=ch):
                self.assertTrue(chars.raw(ch), f"{ch!r} should survive raw")

    def test_encoded_characters_are_not_reported_as_raw(self):
        chars = brute.map_chars(encoder(), MARKER)
        for ch in ('<', '>', '"', "'", '&'):
            with self.subTest(ch=ch):
                self.assertTrue(chars.encoded(ch), f"{ch!r} should be encoded")
                self.assertFalse(chars.raw(ch))
        self.assertTrue(chars.raw("("), "parentheses are not escaped by html.escape")

    def test_stripped_characters_are_detected(self):
        chars = brute.map_chars(stripper(), MARKER)
        for ch in ('<', '>', '"', "'", '`'):
            with self.subTest(ch=ch):
                self.assertEqual(chars.state(ch), "stripped")
        self.assertEqual(sorted(chars.stripped), sorted(['<', '>', '"', "'", '`']))

    def test_point_that_does_not_reflect_exits_after_one_request(self):
        send = lambda value: Resp("http://t.example/", 200, "<html>static</html>")
        chars = brute.map_chars(send, MARKER)
        self.assertEqual(chars.requests, 1)
        self.assertFalse(chars.marker_ok)
        self.assertFalse(chars.known)
        self.assertEqual(chars.chars, {})

    def test_request_budget_is_respected(self):
        chars = brute.map_chars(reflector(), MARKER, max_requests=5)
        self.assertEqual(chars.requests, 5)
        self.assertEqual(len(chars.chars), 4)

    def test_transport_errors_do_not_abort_the_map(self):
        calls = {"n": 0}

        def flaky(value: str) -> Resp:
            calls["n"] += 1
            if calls["n"] in (2, 3):
                raise OSError("reset by peer")
            return Resp("http://t.example/", 200, f"<p>{value}</p>")

        chars = brute.map_chars(flaky, MARKER, chars="<>\"")
        self.assertTrue(chars.marker_ok)
        # A failed probe leaves the character unknown: it is neither evidence of
        # survival nor of filtering, and must not be counted as a request.
        self.assertEqual(chars.state("<"), "unknown")
        self.assertEqual(chars.state(">"), "unknown")
        self.assertEqual(chars.state('"'), "raw")
        self.assertEqual(chars.requests, 2)

    def test_describe_mentions_survivors_and_stripped_characters(self):
        text = brute.map_chars(stripper(), MARKER).describe()
        self.assertIn("probe(s)", text)
        self.assertIn("stripped", text)

    def test_as_dict_is_json_ready(self):
        data = brute.map_chars(stripper(), MARKER).as_dict()
        self.assertEqual(set(data), {"chars", "requests", "marker_reflected"})
        self.assertTrue(data["marker_reflected"])


class TestKeywords(unittest.TestCase):
    def test_keyword_survival_is_per_word(self):
        def send(value: str) -> Resp:
            # The target blocks the literal lowercase "onerror" only.
            return Resp("http://t.example/", 200,
                        "<p>" + value.replace("onerror", "[blocked]") + "</p>")

        words = brute.map_keywords(send, MARKER, words=("alert", "onerror", "svg"))
        self.assertTrue(words["alert"])
        # Blocking one spelling is not blocking the keyword: HTML attribute names
        # are case-insensitive, so a surviving casing is a working bypass.
        self.assertTrue(words["onerror"])
        self.assertTrue(words["svg"])
        forms = brute.keyword_forms(send, MARKER, words=("onerror",))
        self.assertTrue(forms["onerror"])
        self.assertNotEqual(forms["onerror"], "onerror")
        self.assertEqual(forms["onerror"].lower(), "onerror")

    def test_keyword_blocked_in_every_casing_is_reported_blocked(self):
        def send(value: str) -> Resp:
            lowered = value.lower()
            for word in ("onerror", "script", "svg"):
                lowered = lowered.replace(word, "[blocked]")
            return Resp("http://t.example/", 200, "<p>" + lowered + "</p>")

        forms = brute.keyword_forms(send, MARKER, words=("onerror", "svg"),
                                    max_requests=8)
        self.assertEqual(forms["onerror"], "")
        self.assertEqual(forms["svg"], "")

    def test_keyword_probe_budget(self):
        words = brute.map_keywords(reflector(), MARKER, words=("alert", "svg", "img"),
                                   max_requests=2)
        self.assertEqual(len(words), 2)


class TestSequences(unittest.TestCase):
    def test_blocked_sequence_is_seen_even_when_its_characters_survive(self):
        # "<" and "script" both survive on their own, but the token is blocked;
        # single-character mapping cannot see that and would pick a dead vector.
        def send(value: str) -> Resp:
            return Resp("http://t.example/", 200,
                        "<p>" + value.replace("<script", "[blocked]") + "</p>")

        pairs = brute.map_pairs(send, MARKER, pairs=("<script", "<svg"))
        self.assertFalse(pairs["<script"])
        self.assertTrue(pairs["<svg"])

    def test_pair_probe_budget(self):
        pairs = brute.map_pairs(reflector(), MARKER, pairs=("<svg", "onload=", "<>" ),
                                max_requests=2)
        self.assertEqual(len(pairs), 2)

    def test_truncation_length_is_measured(self):
        def send(value: str) -> Resp:
            return Resp("http://t.example/", 200, "<p>" + value[:120] + "</p>")

        cut = brute.detect_truncation(send, MARKER, max_requests=12)
        self.assertTrue(110 <= cut <= 120, cut)

    def test_no_truncation_on_a_target_that_keeps_everything(self):
        self.assertEqual(brute.detect_truncation(reflector(), MARKER), 0)


class TestSynthesis(unittest.TestCase):
    def setUp(self):
        self.chars = brute.map_chars(reflector(), MARKER)

    def test_every_synthesised_vector_renders_a_concrete_marker(self):
        vectors = brute.synthesise(self.chars)
        self.assertTrue(vectors)
        for vector in vectors:
            with self.subTest(vector=vector.name):
                rendered = vector.render(MARKER)
                self.assertIn(MARKER, rendered)
                self.assertNotIn("{JS}", rendered)
                self.assertNotIn("{M}", rendered)
                self.assertTrue(vector.name)
        self.assertEqual(len({v.name for v in vectors}), len(vectors),
                         "vector names must be unique")

    def test_quotes_follow_what_the_filter_keeps(self):
        # The double quote is stripped but the single quote survives, so every
        # vector must still render a call without a double quote in it.
        chars = brute.map_chars(reflector(), MARKER)
        chars.chars['"'] = "stripped"
        vectors = brute.synthesise(chars)
        self.assertTrue(vectors)
        for vector in vectors:
            rendered = vector.render(MARKER)
            self.assertNotIn('"', rendered, vector.name)
            self.assertIn(MARKER, rendered, vector.name)

    def test_contexts_that_cannot_execute_produce_nothing(self):
        for context in ("json_body", "header", "plain_text"):
            with self.subTest(context=context):
                self.assertNotIn(context, brute.EXECUTABLE_CONTEXTS)

    def test_unquoted_attribute_is_executable(self):
        # A space starts a new attribute inside an unquoted value, so this
        # context is exploitable and must not be skipped by the brute forcer.
        self.assertIn("attr_unquoted", brute.EXECUTABLE_CONTEXTS)

    def test_summary_is_flat_and_complete(self):
        data = brute.summary(self.chars)
        forms = brute.summary(self.chars, words={"alert": True},
                              context="html_text", forms={"alert": "alert"},
                              blocked={"<script": False}, truncation=114)
        self.assertEqual(set(forms), {"chars", "requests", "marker_reflected",
                                      "keywords", "keyword_forms", "blocked_sequences",
                                      "truncation", "stripped", "synthesised"})
        self.assertEqual(forms["truncation"], 114)
        self.assertEqual(forms["blocked_sequences"], ["<script"])
        self.assertEqual(forms["keyword_forms"], {"alert": "alert"})
        self.assertIsInstance(data["chars"], dict)
        self.assertIsInstance(data["synthesised"], list)
        self.assertTrue(data["synthesised"])

    def test_no_synthesis_without_a_marker(self):
        chars = brute.CharMap(chars={}, requests=1, marker_ok=False)
        self.assertEqual(brute.synthesise(chars), [])
        self.assertEqual(brute.summary(chars)["synthesised"], [])

    def test_every_callable_blocked_produces_no_vector(self):
        # Falling back to ``alert`` when all four were probed and blocked used
        # to emit a payload containing the one word the filter removes.
        words = {name: False for name in brute.FUNCTIONS}
        forms = {name: "" for name in brute.FUNCTIONS}
        self.assertEqual(brute.synthesise(self.chars, words, forms=forms), [])

    def test_every_handler_blocked_keeps_the_script_block(self):
        # No event handler survives, but ``<script>`` needs none: the vectors
        # that remain must not smuggle a blocked handler back in.
        words = {name: False for name in brute.EVENTS}
        forms = {name: "" for name in brute.EVENTS}
        vectors = brute.synthesise(self.chars, words, forms=forms)
        self.assertTrue(vectors, "a script block is still possible")
        rendered = [vector.render(MARKER) for vector in vectors]
        self.assertTrue(any("<script>" in item for item in rendered),
                        "the handler-free script block must be among the vectors")
        for item in rendered:
            self.assertNotIn("onload", item)
            self.assertNotIn("onerror", item)


if __name__ == "__main__":
    unittest.main(verbosity=2)
