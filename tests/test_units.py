"""Table-driven unit tests: CVSS 3.1, reproduction material, context classification."""
from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from xssmap import payloads, repro  # noqa: E402
from xssmap.htmlparse import parse_page  # noqa: E402
from xssmap.scanner import Finding  # noqa: E402


def finding(**kwargs) -> Finding:
    base = dict(url="https://t.example/comment?x=1", method="GET", param="x",
                location="query", payload="<svg/onload=alert(1)>", context="html_text",
                status=200, confidence="high", content_type="text/html")
    base.update(kwargs)
    return Finding(**base)


CAPTURE = (
    "--- request ---\n"
    "POST /comment?x=1 HTTP/1.1\n"
    "Host: t.example\n"
    "Content-Type: application/x-www-form-urlencoded\n"
    "Cookie: sid=topsecret\n"
    "X-Test: 1\n"
    "\n"
    "comment=%3Csvg%3E\n"
    "\n"
    "--- response ---\n"
    "HTTP 200  content-type: text/html  length: 42\n"
    "\n"
    "--- reflection context: html_text (payload template: svg-onload) ---\n"
    "<p><svg onload=alert(1)></p>"
)


class CvssTests(unittest.TestCase):
    TABLE = [
        # AV, AC, PR, UI, S, C, I, A -> official base score
        (("N", "L", "N", "N", "U", "H", "H", "H"), 9.8),
        (("N", "L", "N", "R", "U", "H", "H", "H"), 8.8),
        (("N", "L", "N", "N", "C", "H", "H", "H"), 10.0),
        (("N", "L", "N", "N", "U", "N", "L", "N"), 5.3),
        (("L", "H", "H", "R", "U", "N", "N", "N"), 0.0),
    ]

    def test_reference_scores(self):
        for (av, ac, pr, ui, scope, c, i, a), expected in self.TABLE:
            metrics = {"AV": av, "AC": ac, "PR": pr, "UI": ui, "S": scope,
                       "C": c, "I": i, "A": a}
            score, _label = repro.score(metrics)
            self.assertAlmostEqual(score, expected, places=1,
                                   msg=f"{repro.vector(metrics)} -> {score}")

    def test_label_thresholds(self):
        self.assertEqual(repro.score({"AV": "N", "AC": "L", "PR": "N", "UI": "N",
                                      "S": "U", "C": "H", "I": "H", "A": "H"})[1], "critical")
        self.assertEqual(repro.score({"AV": "L", "AC": "H", "PR": "H", "UI": "R",
                                      "S": "U", "C": "N", "I": "N", "A": "N"})[1], "none")

    def test_vector_order(self):
        self.assertEqual(
            repro.vector({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                          "C": "N", "I": "L", "A": "N"}),
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N")

    def test_unverified_reflection_has_no_confidentiality_impact(self):
        cvss = repro.cvss_for(finding())
        self.assertEqual(cvss["metrics"]["C"], "N")
        self.assertEqual(cvss["metrics"]["UI"], "N")

    def test_verified_execution_and_interaction(self):
        cvss = repro.cvss_for(finding(verified_browser=True, browser_checked=True,
                                      verify_state="confirmed", interaction=True))
        self.assertEqual(cvss["metrics"]["C"], "L")
        self.assertEqual(cvss["metrics"]["UI"], "R")


class CurlTests(unittest.TestCase):
    def test_captured_request_becomes_a_runnable_command(self):
        cmd = repro.curl_for(finding(method="POST", evidence=CAPTURE))
        self.assertIn("curl -sS -i -X POST 'https://t.example/comment?x=1'", cmd)
        self.assertIn("-H 'Content-Type: application/x-www-form-urlencoded'", cmd)
        self.assertIn("-H 'X-Test: 1'", cmd)
        self.assertIn("--data-binary comment=%3Csvg%3E", cmd)
        self.assertNotIn("topsecret", cmd)
        self.assertNotIn("https://t.example/t.example", cmd)

    def test_fallback_for_a_post_without_capture(self):
        cmd = repro.curl_for(finding(method="POST", context="stored_xss",
                                     url="https://t.example/comment"))
        self.assertIn("-X POST https://t.example/comment", cmd)
        self.assertIn("--data ", cmd)
        self.assertIn("x=", cmd)


class PairTests(unittest.TestCase):
    def test_pair_redacts_the_session_cookie(self):
        text = repro.pair_text(finding(method="POST", evidence=CAPTURE))
        self.assertIn("POST /comment?x=1 HTTP/1.1", text)
        self.assertIn("Cookie: <redacted>", text)
        self.assertNotIn("topsecret", text)
        self.assertIn("HTTP 200", text)
        self.assertIn("reflection", text.lower())

    def test_pair_without_capture_says_so(self):
        text = repro.pair_text(finding())
        self.assertIn("no raw request was captured", text)
        self.assertIn("HTTP 200", text)


class SeverityConditionTests(unittest.TestCase):
    def test_csp_and_untested_are_called_out(self):
        conditions = " ".join(repro.severity_conditions(
            finding(csp_blocked=True, verify_state="not_tested")))
        self.assertIn("CSP", conditions)
        self.assertIn("never observed", conditions)

    def test_verified_mentions_privilege_context(self):
        conditions = " ".join(repro.severity_conditions(
            finding(verified_browser=True, verify_state="confirmed")))
        self.assertIn("administrative", conditions)

    def test_low_confidence_asks_for_a_retest(self):
        conditions = " ".join(repro.severity_conditions(finding(confidence="low")))
        self.assertIn("re-test", conditions)


class PayloadTableTests(unittest.TestCase):
    def test_every_payload_renders_both_placeholders(self):
        for payload in payloads.build_payload_set("alert(1)"):
            rendered = payload.render("marker123", "alert(1)")
            self.assertNotIn("{M}", rendered, payload.name)
            self.assertNotIn("{JS}", rendered, payload.name)

    def test_each_named_context_has_at_least_one_payload(self):
        table = {
            "html_text": payloads.html_text_payloads(),
            "attr_double": payloads.attr_payloads("attr_double"),
            "attr_single": payloads.attr_payloads("attr_single"),
            "attr_unquoted": payloads.attr_payloads("attr_unquoted"),
            "js_string_single": payloads.js_payloads("js_string_single"),
            "comment": payloads.comment_payloads(),
            "textarea": payloads.rawtext_payloads("textarea"),
            "tag_space": payloads.tag_space_payloads(),
        }
        for context, items in table.items():
            self.assertTrue(items, context)
            for payload in items:
                self.assertTrue(payload.template, payload.name)


class ContextClassificationTests(unittest.TestCase):
    TABLE = [
        ("<p>MARK</p>", "html_text"),
        ('<input value="MARK">', "attr_double"),
        ("<input value='MARK'>", "attr_single"),
        ("<script>var a='MARK';</script>", "js_string_single"),
        ("<script>var a=\"MARK\";</script>", "js_string_double"),
        ("<textarea>MARK</textarea>", "textarea"),
        ("<!-- MARK -->", "comment"),
    ]

    def test_classification_table(self):
        for body, expected in self.TABLE:
            page = parse_page("https://t.example/", body)
            reflections = payloads.classify_reflections(page, "MARK", limit=4)
            self.assertTrue(reflections, body)
            self.assertEqual(reflections[0].context, expected, body)

    def test_script_json_block_is_not_executable(self):
        page = parse_page("https://t.example/",
                          '<script type="application/json">{"a": "MARK"}</script>')
        reflections = payloads.classify_reflections(page, "MARK", limit=4)
        contexts = {r.context for r in reflections}
        self.assertNotIn("js_string_double", contexts)


if __name__ == "__main__":
    unittest.main(verbosity=2)
