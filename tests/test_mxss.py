"""mXSS stage tests: vector table hygiene, the survival gate, round-trip verdicts."""
from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from xssmap import mxss  # noqa: E402


class VectorTableTests(unittest.TestCase):
    def test_table_is_not_empty_and_names_are_unique(self):
        self.assertGreaterEqual(len(mxss.VECTORS), 6)
        names = [name for name, _ in mxss.VECTORS]
        self.assertEqual(len(names), len(set(names)))

    def test_every_vector_has_a_handler_slot(self):
        for name, markup in mxss.VECTORS:
            self.assertIn("__JS__", markup, name)
            self.assertNotIn("alert(1)", markup,
                             f"{name} should use the __JS__ placeholder")

    def test_vectors_render_the_requested_js(self):
        for name, markup in mxss.vectors("HelloWorld()"):
            self.assertNotIn("__JS__", markup, name)
            self.assertIn("HelloWorld()", markup, name)

    def test_limit_truncates(self):
        self.assertEqual(len(mxss.vectors("x()", limit=2)), 2)


class SurvivalGateTests(unittest.TestCase):
    MARKUP = "<form><math><mtext></form><form><mglyph><style></math>"

    def test_raw_markup_survives(self):
        self.assertTrue(mxss.markup_survives(f"<div>{self.MARKUP}</div>", self.MARKUP))

    def test_escaped_markup_does_not(self):
        escaped = self.MARKUP.replace("<", "&lt;").replace(">", "&gt;")
        self.assertFalse(mxss.markup_survives(f"<div>{escaped}</div>", self.MARKUP))

    def test_single_common_tag_is_not_enough(self):
        self.assertFalse(mxss.markup_survives("<html><style>.a{}</style></html>",
                                              "<img src=x onerror=1>"))

    def test_data_block_is_decoded_first(self):
        import json
        blob = json.dumps({"html": self.MARKUP})
        page = f"<script type='application/json'>{blob}</script>"
        self.assertTrue(mxss.markup_survives(page, self.MARKUP))

    def test_cosmetic_whitespace_is_ignored(self):
        self.assertFalse(mxss.looks_mutated("<a  href='x'>", "< a href='x' >"))
        self.assertTrue(mxss.looks_mutated("<img src=x>", '<img src="x">'))


class _Browser:
    def __init__(self, result):
        self.result = result

    def roundtrip(self, markup, target_id):
        return self.result


class ProbeVerdictTests(unittest.TestCase):
    def test_transport_failure_is_not_a_negative_verdict(self):
        out = mxss.probe(_Browser({"ok": False, "error": "browser unavailable"}), "<b>", "x")
        self.assertFalse(out["mxss"])
        self.assertEqual(out["error"], "browser unavailable")

    def test_control_that_already_runs_is_ordinary_xss(self):
        out = mxss.probe(_Browser({"ok": True, "serialized": "<b>", "activated": True,
                                   "control_activated": True, "hit": "b1"}), "<b>", "x")
        self.assertFalse(out["mxss"])
        self.assertIn("ordinary XSS", out["proof"])

    def test_inert_control_that_runs_after_round_trip_is_mxss(self):
        out = mxss.probe(_Browser({"ok": True, "serialized": "<b><img>", "activated": True,
                                   "control_activated": False, "hit": "b2"}), "<b>", "x")
        self.assertTrue(out["mxss"])
        self.assertTrue(out["mutated"])
        self.assertIn("inert as delivered", out["proof"])

    def test_unchanged_round_trip_is_reported_as_such(self):
        out = mxss.probe(_Browser({"ok": True, "serialized": "<b>", "activated": False,
                                   "control_activated": False}), "<b>", "x")
        self.assertFalse(out["mxss"])
        self.assertIn("unchanged", out["proof"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
