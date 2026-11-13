"""Unit tests for the CSP parser.

The cases are the ones where a substring check gives the wrong answer: keyword
interactions (a nonce silently disables 'unsafe-inline'), fallback chains,
report-only delivery, multiple policies, and host/port/path matching.

Run:  python -m unittest tests.test_csp -v
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssmap import csp

HANDLER = "<img src=x onerror=alert(1)>"
INLINE = "<script>alert(1)</script>"
EXTERNAL = '<script src="https://cdn.example.com/lib.js"></script>'


def feasibility(policy_text: str, markup: str, url: str = "https://app.example.com/page",
                report_only: bool = False) -> csp.Feasibility:
    return csp.Policy.parse(policy_text, report_only=report_only).feasibility(markup, url)


class TestTechniqueDetection(unittest.TestCase):
    def test_classification(self):
        cases = [
            (HANDLER, "inline_event_handler"),
            (INLINE, "inline_script"),
            (EXTERNAL, "external_script"),
            ('<a href="javascript:alert(1)">x</a>', "javascript_url"),
            ('<iframe srcdoc="<script>alert(1)</script>"></iframe>', "srcdoc"),
            ("plain text", "markup"),
        ]
        for markup, expected in cases:
            with self.subTest(markup=markup):
                self.assertEqual(csp.technique_of(markup), expected)


class TestInlinePermissions(unittest.TestCase):
    def test_no_policy_restriction_is_not_assessed(self):
        verdict = feasibility("img-src 'self'", HANDLER)
        self.assertIsNone(verdict.allowed)

    def test_unsafe_inline_allows_handler(self):
        verdict = feasibility("script-src 'self' 'unsafe-inline'", HANDLER)
        self.assertTrue(verdict.allowed)

    def test_self_only_blocks_handler(self):
        verdict = feasibility("script-src 'self'", HANDLER)
        self.assertFalse(verdict.allowed)

    def test_nonce_disables_unsafe_inline(self):
        verdict = feasibility("script-src 'nonce-abc123' 'unsafe-inline'", INLINE)
        self.assertFalse(verdict.allowed)
        self.assertIn("ignores", verdict.reason)

    def test_hash_disables_unsafe_inline(self):
        verdict = feasibility(
            "script-src 'sha256-AAA' 'unsafe-inline'", INLINE)
        self.assertFalse(verdict.allowed)

    def test_strict_dynamic_disables_unsafe_inline(self):
        verdict = feasibility("script-src 'strict-dynamic' 'unsafe-inline'", INLINE)
        self.assertFalse(verdict.allowed)

    def test_default_src_fallback(self):
        self.assertTrue(feasibility("default-src 'unsafe-inline'", HANDLER).allowed)
        self.assertFalse(feasibility("default-src 'self'", HANDLER).allowed)

    def test_script_src_attr_overrides_for_handlers_only(self):
        policy = "script-src 'unsafe-inline'; script-src-attr 'none'"
        self.assertFalse(feasibility(policy, HANDLER).allowed)
        self.assertTrue(feasibility(policy, INLINE).allowed)

    def test_none_combined_with_self_ignores_none(self):
        verdict = feasibility("script-src 'none' 'self'", INLINE)
        self.assertFalse(verdict.allowed)  # 'none' ignored, 'self' still no inline

    def test_empty_script_src_blocks_inline(self):
        self.assertFalse(feasibility("script-src", INLINE).allowed)

    def test_javascript_url_needs_unsafe_inline(self):
        markup = '<a href="javascript:alert(1)">x</a>'
        self.assertTrue(feasibility("script-src 'unsafe-inline'", markup).allowed)
        self.assertFalse(feasibility("script-src 'self'", markup).allowed)

    def test_srcdoc_inherits_inline_permission(self):
        markup = '<iframe srcdoc="<script>alert(1)</script>"></iframe>'
        self.assertFalse(feasibility("script-src 'self'", markup).allowed)
        self.assertTrue(feasibility("script-src 'unsafe-inline'", markup).allowed)


class TestExternalScripts(unittest.TestCase):
    def test_exact_host_allowed(self):
        verdict = feasibility("script-src https://cdn.example.com", EXTERNAL)
        self.assertTrue(verdict.allowed)

    def test_wildcard_matches_subdomain(self):
        verdict = feasibility("script-src *.example.com", EXTERNAL)
        self.assertTrue(verdict.allowed)

    def test_wildcard_does_not_match_bare_domain(self):
        verdict = feasibility("script-src *.example.com",
                              '<script src="https://example.com/lib.js"></script>')
        self.assertFalse(verdict.allowed)

    def test_wrong_host_blocked(self):
        verdict = feasibility("script-src https://cdn.other.com", EXTERNAL)
        self.assertFalse(verdict.allowed)

    def test_path_prefix_allowed(self):
        markup = '<script src="https://cdn.example.com/lib/app.js"></script>'
        verdict = feasibility("script-src https://cdn.example.com/lib/", markup)
        self.assertTrue(verdict.allowed)

    def test_directory_prefix_does_not_match_file(self):
        verdict = feasibility("script-src https://cdn.example.com/lib/", EXTERNAL)
        self.assertFalse(verdict.allowed)

    def test_path_prefix_requires_segment_boundary(self):
        verdict = feasibility("script-src https://cdn.example.com/lib",
                              '<script src="https://cdn.example.com/library.js"></script>')
        self.assertFalse(verdict.allowed)

    def test_non_default_port_must_match(self):
        markup = '<script src="https://cdn.example.com:8443/lib.js"></script>'
        self.assertFalse(feasibility("script-src https://cdn.example.com", markup).allowed)
        self.assertTrue(feasibility("script-src https://cdn.example.com:8443", markup).allowed)

    def test_strict_dynamic_blocks_markup_injection(self):
        verdict = feasibility("script-src 'strict-dynamic' 'nonce-abc'",
                              EXTERNAL)
        self.assertFalse(verdict.allowed)
        self.assertIn("strict-dynamic", verdict.reason)

    def test_self_matches_same_origin(self):
        markup = '<script src="/static/app.js"></script>'
        verdict = feasibility("script-src 'self'", markup,
                              url="https://app.example.com/page")
        self.assertTrue(verdict.allowed)

    def test_self_rejects_other_origin(self):
        verdict = feasibility("script-src 'self'", EXTERNAL,
                              url="https://app.example.com/page")
        self.assertFalse(verdict.allowed)

    def test_scheme_source_allows_any_host(self):
        verdict = feasibility("script-src https:", EXTERNAL)
        self.assertTrue(verdict.allowed)

    def test_protocol_relative_url_uses_page_scheme(self):
        markup = '<script src="//cdn.example.com/lib.js"></script>'
        verdict = feasibility("script-src https://cdn.example.com", markup,
                              url="https://app.example.com/page")
        self.assertTrue(verdict.allowed)


class TestHeaderCollection(unittest.TestCase):
    def test_report_only_does_not_block(self):
        headers = [("Content-Security-Policy-Report-Only", "script-src 'self'")]
        assessment = csp.Assessment.from_headers(headers)
        self.assertTrue(assessment.present)
        self.assertEqual(assessment.enforced, [])
        self.assertIsNone(assessment.feasibility(HANDLER).allowed)

    def test_enforced_policy_is_used(self):
        headers = [("Content-Security-Policy", "script-src 'self'")]
        assessment = csp.Assessment.from_headers(headers)
        self.assertFalse(assessment.feasibility(HANDLER).allowed)

    def test_all_enforced_policies_must_allow(self):
        headers = [
            ("Content-Security-Policy", "script-src 'unsafe-inline'"),
            ("Content-Security-Policy", "script-src 'self'"),
        ]
        assessment = csp.Assessment.from_headers(headers)
        self.assertFalse(assessment.feasibility(HANDLER).allowed)

    def test_comma_separated_policies_are_split(self):
        headers = [("Content-Security-Policy",
                    "script-src 'unsafe-inline', script-src 'self'")]
        assessment = csp.Assessment.from_headers(headers)
        self.assertEqual(len(assessment.enforced), 2)
        self.assertFalse(assessment.feasibility(HANDLER).allowed)

    def test_header_name_is_case_insensitive(self):
        headers = [("content-security-policy", "script-src 'self'")]
        self.assertFalse(csp.Assessment.from_headers(headers)
                         .feasibility(HANDLER).allowed)

    def test_no_csp_header(self):
        assessment = csp.Assessment.from_headers([("Content-Type", "text/html")])
        self.assertFalse(assessment.present)
        self.assertEqual(assessment.describe(HANDLER), "")


class TestPolicyDetails(unittest.TestCase):
    def test_summary_lists_enforced_directives(self):
        summary = csp.Policy.parse("default-src 'self'; script-src 'self' cdn.example.com").summary()
        self.assertIn("enforced", summary)
        self.assertIn("script-src 'self' cdn.example.com", summary)

    def test_report_only_summary_is_labelled(self):
        summary = csp.Policy.parse("script-src 'self'", report_only=True).summary()
        self.assertIn("report-only", summary)

    def test_deficiencies_flag_unsafe_inline(self):
        gaps = csp.Policy.parse("script-src 'unsafe-inline'").deficiencies()
        self.assertTrue(any("unsafe-inline" in gap for gap in gaps))

    def test_deficiencies_flag_missing_base_uri(self):
        gaps = csp.Policy.parse("default-src 'self'").deficiencies()
        self.assertTrue(any("base-uri" in gap for gap in gaps))

    def test_deficiencies_flag_third_party_trust(self):
        gaps = csp.Policy.parse("script-src 'self' https://cdn.example.com").deficiencies()
        self.assertTrue(any("JSONP" in gap for gap in gaps))

    def test_deficiencies_flag_wildcards(self):
        gaps = csp.Policy.parse("default-src *").deficiencies()
        self.assertTrue(any("'*'" in gap for gap in gaps))

    def test_deficiencies_flag_report_only(self):
        gaps = csp.Policy.parse("script-src 'none'", report_only=True).deficiencies()
        self.assertTrue(any("blocks nothing" in gap for gap in gaps))

    def test_duplicate_directive_first_wins(self):
        policy = csp.Policy.parse("script-src 'self'; script-src 'unsafe-inline'")
        self.assertEqual(policy.directives["script-src"], ("'self'",))

    def test_invalid_directive_name_ignored(self):
        policy = csp.Policy.parse("script_src 'unsafe-inline'")
        self.assertEqual(policy.directives, {})

    def test_unsafe_eval(self):
        self.assertTrue(csp.Policy.parse("script-src 'unsafe-eval'").allows_eval())
        self.assertFalse(csp.Policy.parse("script-src 'self'").allows_eval())


class StrictDynamicTests(unittest.TestCase):
    """'strict-dynamic' blocks markup scripts, but not a trusted-script gadget.

    The header cannot answer "is there a gadget", so the note must say what was
    found and leave the verdict open instead of claiming either outcome.
    """

    POLICY = ("Content-Security-Policy",
              "script-src 'nonce-abc' 'strict-dynamic' https://cdn.example.com")

    def assessment(self):
        return csp.Assessment.from_headers([self.POLICY])

    def test_strict_dynamic_is_recognised(self):
        self.assertTrue(self.assessment().strict_dynamic())
        plain = csp.Assessment.from_headers([("Content-Security-Policy", "script-src 'self'")])
        self.assertFalse(plain.strict_dynamic())

    def test_inline_is_blocked_and_the_gadget_note_explains_why_it_still_matters(self):
        html = "<div id=x></div><script>var s = document.createElement('script');</script>"
        note = csp.describe_with_gadgets(self.assessment(), INLINE,
                                        "https://app.example.com/page", html)
        self.assertIn("does not include 'unsafe-inline'", note)
        self.assertIn("strict-dynamic", note)
        self.assertIn("createElement('script')", note)
        self.assertIn("manual gadget check", note)
        # a gadget is a lead, never a claim that the page is exploitable
        self.assertNotIn("confirmed", note.lower())

    def test_page_without_a_gadget_is_reported_as_not_established(self):
        note = csp.describe_with_gadgets(self.assessment(), INLINE,
                                         "https://app.example.com/page",
                                         "<script>var a = 1;</script>")
        self.assertIn("no script-creating gadget", note)
        self.assertIn("not established", note)

    def test_json_blocks_are_not_scanned_for_gadgets(self):
        html = ('<script type="application/json">'
                '{"tpl": "document.createElement(\'script\')"}</script>')
        self.assertEqual(csp.strict_dynamic_gadgets(html), [])

    def test_gadget_excerpt_is_bounded(self):
        html = "<script>document.write('<script src=x>' + 'a' * 500)</script>"
        found = csp.strict_dynamic_gadgets(html)
        self.assertTrue(found)
        self.assertLessEqual(len(found[0][2]), 120)

    def test_plain_policy_gets_no_gadget_addendum(self):
        assessment = csp.Assessment.from_headers(
            [("Content-Security-Policy", "script-src 'self'")])
        note = csp.describe_with_gadgets(assessment, INLINE, "https://app.example.com/page",
                                         "<script>document.createElement('script')</script>")
        self.assertNotIn("strict-dynamic", note)


class JsonpTests(unittest.TestCase):
    def test_allowlisted_jsonp_endpoint_is_reported(self):
        assessment = csp.Assessment.from_headers(
            [("Content-Security-Policy", "script-src 'self' https://cdn.example.com")])
        html = ('<script src="https://cdn.example.com/api/jsonp?callback=cb"></script>')
        found = csp.allowlisted_jsonp(assessment, html, "https://app.example.com/page")
        self.assertEqual(found, ["https://cdn.example.com/api/jsonp?callback=cb"])

    def test_non_allowlisted_jsonp_endpoint_is_not_reported(self):
        assessment = csp.Assessment.from_headers(
            [("Content-Security-Policy", "script-src 'self'")])
        html = '<script src="https://evil.tld/jsonp?callback=cb"></script>'
        self.assertEqual(csp.allowlisted_jsonp(assessment, html,
                                               "https://app.example.com/page"), [])

    def test_strict_dynamic_makes_the_host_allowlist_irrelevant(self):
        assessment = csp.Assessment.from_headers(
            [("Content-Security-Policy",
              "script-src 'nonce-abc' 'strict-dynamic' https://cdn.example.com")])
        html = '<script src="https://cdn.example.com/jsonp?callback=cb"></script>'
        self.assertEqual(csp.allowlisted_jsonp(assessment, html,
                                               "https://app.example.com/page"), [])

    def test_ordinary_script_urls_are_ignored(self):
        assessment = csp.Assessment.from_headers(
            [("Content-Security-Policy", "script-src https://cdn.example.com")])
        html = '<script src="https://cdn.example.com/lib.js"></script>'
        self.assertEqual(csp.allowlisted_jsonp(assessment, html,
                                               "https://app.example.com/page"), [])

    def test_no_policy_means_nothing_to_bypass(self):
        assessment = csp.Assessment.from_headers([])
        html = '<script src="https://cdn.example.com/jsonp?callback=cb"></script>'
        self.assertEqual(csp.allowlisted_jsonp(assessment, html,
                                               "https://app.example.com/page"), [])


if __name__ == "__main__":
    unittest.main()
