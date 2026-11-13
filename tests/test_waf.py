"""Unit tests for WAF fingerprinting and vendor-aware evasion.

Run:  python tests/test_waf.py
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from stubhttp import FakeHTTP, Resp, query_text

from xssmap import waf

CF_BLOCK = (
    "<!doctype html><html><head><title>Attention Required! | Cloudflare</title>"
    "</head><body><div class=\"cf-error-details\">Ray ID: 8f2c1</div></body></html>"
)


def hostile(url: str) -> bool:
    """The three probe shapes the detector sends."""
    query = query_text(url)
    return "<" in query or "'" in query or "passwd" in query


def cloudflare_router(url: str) -> Resp:
    if hostile(url):
        return Resp(url, 403, CF_BLOCK,
                    [("CF-RAY", "8f2c1"), ("Server", "cloudflare")])
    return Resp(url, 200, "<html><body>hello</body></html>",
                [("Server", "cloudflare"), ("CF-Cache-Status", "DYNAMIC")])


class TestDetection(unittest.TestCase):
    def test_cloudflare_block_page_is_identified(self):
        det = waf.detect(FakeHTTP(cloudflare_router), "http://t.example/search?q=1")
        self.assertTrue(det.checked)
        self.assertTrue(det.detected)
        self.assertEqual(det.vendor, "cloudflare")
        self.assertEqual(det.name, "Cloudflare")
        self.assertTrue(det.blocking)
        self.assertIn(det.confidence, ("medium", "high"))
        self.assertEqual(det.baseline_status, 200)
        self.assertTrue(any("Ray ID" in e or "cf-error" in e or "CF-RAY" in e
                            for e in det.evidence))
        self.assertIn("Cloudflare", det.describe())

    def test_detection_costs_one_request_per_probe(self):
        http = FakeHTTP(cloudflare_router)
        waf.detect(http, "http://t.example/search?q=1")
        self.assertEqual(http.stats["requests"], 1 + len(waf.PROBES))

    def test_clean_target_is_not_flagged(self):
        http = FakeHTTP(lambda url: Resp(url, 200, "<html>ok</html>"))
        det = waf.detect(http, "http://t.example/?q=1")
        self.assertTrue(det.checked)
        self.assertFalse(det.detected)
        self.assertFalse(det.blocking)
        self.assertFalse(det.evasive)
        self.assertEqual(det.confidence, "none")
        self.assertEqual(det.describe(), "WAF: none detected")
        self.assertEqual(waf.evasion_budget(det.confidence, det.blocking), 0)

    def test_block_without_a_signature_is_reported_as_unidentified(self):
        http = FakeHTTP(lambda url: (
            Resp(url, 403, "<html>Forbidden</html>") if hostile(url)
            else Resp(url, 200, "<html>ok</html>")))
        det = waf.detect(http, "http://t.example/?q=1")
        self.assertTrue(det.detected)
        self.assertEqual(det.vendor, "")
        self.assertEqual(det.name, "unidentified filter")
        self.assertEqual(det.confidence, "low")
        self.assertTrue(det.blocking)

    def test_same_status_for_every_probe_is_not_a_block(self):
        http = FakeHTTP(lambda url: Resp(url, 403, "<html>login required</html>"))
        det = waf.detect(http, "http://t.example/?q=1")
        self.assertFalse(det.blocking)
        self.assertEqual(det.baseline_status, 403)

    def test_unreachable_target_reports_checked_with_evidence(self):
        def boom(url):
            raise OSError("connection refused")

        det = waf.detect(FakeHTTP(boom), "http://t.example/?q=1")
        self.assertTrue(det.checked)
        self.assertFalse(det.detected)
        self.assertTrue(det.evidence)

    def test_budget_grows_with_confidence(self):
        self.assertLess(waf.evasion_budget("low", False),
                        waf.evasion_budget("high", False))
        self.assertLess(waf.evasion_budget("low", False),
                        waf.evasion_budget("low", True))
        self.assertLess(waf.evasion_budget("high", False),
                        waf.evasion_budget("high", True))

    def test_known_vendors_all_declare_strategies(self):
        for vendor in waf.VENDORS:
            with self.subTest(vendor=vendor.key):
                self.assertTrue(vendor.strategies, "no evasion strategies declared")
                det = waf.WAFDetection(vendor=vendor.key, name=vendor.name,
                                       confidence="high", blocking=True, checked=True)
                self.assertEqual(det.strategies(), vendor.strategies)
                self.assertTrue(det.evasive)

    def test_as_dict_is_report_ready(self):
        det = waf.detect(FakeHTTP(cloudflare_router), "http://t.example/?q=1")
        data = det.as_dict()
        for key in ("checked", "vendor", "name", "confidence", "blocking",
                    "evidence", "baseline_status", "probes", "strategies"):
            self.assertIn(key, data)
        self.assertTrue(data["strategies"])
        self.assertEqual(len(data["probes"]), len(waf.PROBES))


class TestEvasion(unittest.TestCase):
    PAYLOAD = '<svg onload=alert("mm1")>'

    def test_markup_variants_change_the_payload_and_never_repeat_it(self):
        variants = waf.markup_variants(self.PAYLOAD, "html_text",
                                       ("case", "space-slash", "comment-pad"))
        self.assertTrue(variants)
        for strategy, candidate in variants:
            with self.subTest(strategy=strategy):
                self.assertNotEqual(candidate, self.PAYLOAD)
                self.assertNotIn(candidate, [v for _s, v in variants if v == candidate][1:])

    def test_markup_only_strategies_are_skipped_inside_js_strings(self):
        variants = waf.markup_variants(self.PAYLOAD, "js_string_double",
                                       ("case", "space-slash", "js-entity"))
        self.assertNotIn("space-slash", [s for s, _ in variants])
        self.assertNotIn("case", [s for s, _ in variants])

    def test_js_variants_are_valid_js_around_the_marker(self):
        marker = "mmZ9"
        variants = waf.js_variants(marker)
        self.assertTrue(variants)
        names = [name for name, _js in variants]
        self.assertEqual(len(names), len(set(names)))
        for name, body in variants:
            with self.subTest(strategy=name):
                self.assertTrue(body.strip())
                if name == "waf-b64":
                    self.assertNotIn(marker, body)   # marker is encoded on purpose
                else:
                    self.assertIn(marker, body)

    def test_double_percent_encoding_is_not_offered_as_a_strategy(self):
        # The transport already percent-encodes every value once, so a second
        # round of encoding cannot be a bypass; it only wastes requests.
        variants = waf.markup_variants(self.PAYLOAD, "html_text",
                                       ("percent", "double-percent", "case"))
        self.assertNotIn("percent", [s for s, _ in variants])
        self.assertNotIn("double-percent", [s for s, _ in variants])


class TestAdaptiveOrdering(unittest.TestCase):
    """The target is a better source than the vendor table: a strategy that
    already got through is tried first, a filtered one last."""

    def test_proven_strategy_moves_to_the_front(self):
        memory = waf.AdaptiveEvasion()
        order = ("case", "js-split", "js-entity", "tab-space")
        memory.record("js-entity", True)
        self.assertEqual(memory.rank(order)[0], "js-entity")

    def test_filtered_strategies_are_demoted_below_untried_ones(self):
        memory = waf.AdaptiveEvasion()
        order = ("case", "js-split", "js-entity")
        memory.record("case", False)
        memory.record("case", False)
        ranked = memory.rank(order)
        self.assertEqual(ranked[-1], "case")
        self.assertEqual(ranked[0], "js-split")

    def test_repeated_successes_beat_a_single_one(self):
        memory = waf.AdaptiveEvasion()
        memory.record("case", True)
        memory.record("js-split", True)
        memory.record("js-split", True)
        self.assertEqual(memory.rank(("case", "js-split"))[0], "js-split")

    def test_order_never_reaches_outside_the_vendor_strategies(self):
        memory = waf.AdaptiveEvasion()
        memory.record("unicode", True)
        variants = waf.markup_variants("<img src=x onerror=alert(1)>", "html_text",
                                       ("case",), limit=4, order=("unicode", "case"))
        self.assertEqual([s for s, _ in variants], ["case"])

    def test_learned_order_changes_which_variant_is_tried_first(self):
        payload = "<img src=x onerror=alert(1)>"
        plain = waf.markup_variants(payload, "html_text",
                                   ("case", "comment-pad"), limit=1)
        memory = waf.AdaptiveEvasion()
        memory.record("comment-pad", True)
        learned = waf.markup_variants(payload, "html_text",
                                     ("case", "comment-pad"), limit=1,
                                     order=memory.rank(("case", "comment-pad")))
        self.assertEqual([s for s, _ in plain], ["case"])
        self.assertEqual([s for s, _ in learned], ["comment-pad"])

    def test_describe_is_empty_until_something_is_learned(self):
        memory = waf.AdaptiveEvasion()
        self.assertEqual(memory.describe(), "")
        memory.record("case", True)
        memory.record("js-split", False)
        text = memory.describe()
        self.assertIn("worked: case x1", text)
        self.assertIn("filtered: js-split x1", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
