"""Scoring tests for the benchmark runner.

The scorer is the part of a benchmark that can lie: if it silently ignores a
finding, or credits a finding to the wrong endpoint, the printed precision looks
great and means nothing. These cases pin the arithmetic and the attribution
rules down with synthetic reports, so a regression shows up without running the
lab.
"""
from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from bench.lab2.app import LABELS  # noqa: E402
from bench.run_bench import score  # noqa: E402


def report(*findings):
    return {"findings": list(findings)}


def finding(url, param, context="html_text", verify_state="not_tested",
            confidence="high"):
    return {"url": url, "parameter": param, "context": context,
            "verify_state": verify_state, "confidence": confidence}


class LabelHygieneTests(unittest.TestCase):
    def test_keys_are_unique(self):
        keys = [(lab["path"], lab["param"], lab.get("method", "GET")) for lab in LABELS]
        self.assertEqual(len(keys), len(set(keys)))

    def test_vulnerable_labels_declare_a_known_context(self):
        known = {"html_text", "attr_double", "attr_single", "attr_unquoted",
                 "js_string_single", "textarea", "title", "comment"}
        for lab in LABELS:
            if lab["vulnerable"]:
                self.assertIn(lab.get("context"), known, lab["path"])

    def test_there_are_controls(self):
        self.assertGreaterEqual(sum(1 for lab in LABELS if not lab["vulnerable"]), 3)


class ScoringTests(unittest.TestCase):
    BASE = "http://127.0.0.1:9"

    def test_all_vulnerable_and_no_control_reported_is_perfect(self):
        findings = [finding(self.BASE + lab["path"], lab["param"], lab["context"])
                    for lab in LABELS if lab["vulnerable"]]
        result = score(report(*findings), LABELS)
        self.assertEqual((result["tp"], result["fn"], result["fp"], result["tn"]),
                         (9, 0, 0, 4))
        self.assertEqual(result["precision"], 1.0)
        self.assertEqual(result["recall"], 1.0)

    def test_a_missed_endpoint_lowers_recall(self):
        findings = [finding(self.BASE + lab["path"], lab["param"], lab["context"])
                    for lab in LABELS if lab["vulnerable"] and lab["path"] != "/debug"]
        result = score(report(*findings), LABELS)
        self.assertEqual(result["fn"], 1)
        self.assertLess(result["recall"], 1.0)
        row = next(r for r in result["rows"] if r["path"] == "/debug")
        self.assertEqual(row["result"], "FN")

    def test_a_reported_control_is_a_false_positive(self):
        findings = [finding(self.BASE + "/escape", "text")]
        result = score(report(*findings), LABELS)
        self.assertEqual(result["fp"], 1)
        self.assertEqual(result["precision"], 0.0)

    def test_finding_outside_the_corpus_is_reported_but_not_scored(self):
        result = score(report(finding(self.BASE + "/somewhere", "q")), LABELS)
        self.assertEqual(result["unexpected_findings"][0]["url"],
                         self.BASE + "/somewhere")
        self.assertEqual((result["tp"], result["fp"]), (0, 0))
        self.assertEqual(result["recall"], 0.0)

    def test_query_string_does_not_affect_attribution(self):
        result = score(report(finding(self.BASE + "/quotes?text=%3Csvg%3E", "text")),
                       LABELS)
        self.assertEqual(result["tp"], 1)

    def test_context_mismatch_is_flagged(self):
        result = score(report(finding(self.BASE + "/quotes", "text",
                                      context="attr_double")), LABELS)
        self.assertEqual(result["tp"], 1)
        self.assertFalse(result["rows"][0]["context_ok"])

    def test_browser_mode_requires_a_confirmed_verdict(self):
        unconfirmed = finding(self.BASE + "/quotes", "text", verify_state="not_tested")
        result = score(report(unconfirmed), LABELS, require_confirmed=True)
        self.assertEqual(result["tp"], 0)
        self.assertEqual([r["result"] for r in result["rows"] if r["path"] == "/quotes"],
                         ["FN"])
        confirmed = finding(self.BASE + "/quotes", "text", verify_state="confirmed")
        result = score(report(confirmed), LABELS, require_confirmed=True)
        self.assertEqual(result["tp"], 1)

    def test_stored_finding_is_attributed_by_parameter(self):
        labels = [{"path": "/wall", "param": "comment", "vulnerable": True,
                   "stored": True, "context": "html_text"}]
        result = score(report(finding(self.BASE + "/admin", "comment",
                                      context="stored_xss")), labels)
        self.assertEqual(result["tp"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
