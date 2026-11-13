"""Tests for lead reporting: a reflecting point is never reported as clean.

A point that reflects the marker but swallows every payload is not "nothing
here" -- it is a sink a human may be able to get past. The scanner keeps those
as low-confidence leads (separate from confirmed findings) so the report can say
what the sink does instead of implying safety.

The harder half is the sink that never returns the probe intact: it strips
digits, truncates, or recases.  That used to be indistinguishable from "not
reflected" and disappeared from the report entirely.

Run:  python -m unittest tests.test_leads -v
"""
from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from xssmap import efficiency, filters, scanner  # noqa: E402
from xssmap.htmlparse import query_pairs  # noqa: E402
from xssmap.net import Response  # noqa: E402

TEXT_TEMPLATE = "<html><body><p>results: {value}</p></body></html>"


def _html_response(req, template: str, transform=None, content_type="text/html; charset=utf-8"):
    """Echo the injected value into a text node, like a search page does."""
    value = dict(query_pairs(req.url)).get("q", "")
    if transform is not None:
        value = transform(value)
    body = template.format(value=value).encode("utf-8")
    return Response(url=req.url, method=req.method, status=200,
                    headers=[("content-type", content_type)],
                    body=body, elapsed=0.0)


class _StubHTTP:
    def __init__(self, template: str, transform=None, content_type="text/html; charset=utf-8"):
        self.template = template
        self.transform = transform
        self.content_type = content_type
        self.requests = []

    def send(self, req, allow_redirects: bool = False):
        self.requests.append(req)
        return _html_response(req, self.template, self.transform, self.content_type)


def _scan(template: str = TEXT_TEMPLATE, profile=None, transform=None, **kwargs):
    content_type = kwargs.pop("content_type", "text/html; charset=utf-8")
    try_context = kwargs.pop("_try_context", None)
    http = _StubHTTP(template, transform, content_type)
    point = scanner.QueryPoint("https://t.example/search?q=1", 0, [])
    scan = scanner.Scanner(http=http, browser=None, **kwargs)
    if profile is not None:
        scan._profile_point = lambda *a, **k: profile   # measured filter, stubbed
    if try_context is not None:
        scan._try_context = try_context
    return scan, scan._scan(point)


class LeadFallbackTest(unittest.TestCase):
    def test_filtered_reflection_is_recorded_as_a_lead(self):
        profile = filters.FilterProfile(allowed=set("abc"), stripped={"<", ">", '"'},
                                        blocked_keywords={"alert"}, known=True)
        scan, findings = _scan(profile=profile,
                               _try_context=lambda *a, **k: None)
        self.assertEqual(findings, [], "a swallowed payload must not become a finding")
        self.assertEqual(len(scan.leads), 1, "the reflection must still be reported")
        lead = scan.leads[0]
        self.assertEqual(lead.context, "html_text", "the real context is more useful than 'filtered'")
        self.assertEqual(lead.confidence, "low")
        self.assertEqual(lead.param, "q")
        self.assertEqual(lead.filter_profile.get("lead_kind"), "unproven")
        self.assertIn("no tested payload produced execution", " ".join(lead.notes))
        self.assertIn("reflected verbatim", lead.evidence)

    def test_clean_reflection_without_execution_is_still_a_lead(self):
        # Everything survives, so the payloads were not filtered -- but nothing
        # ran either. That is a sink worth a human look, not a clean bill.
        profile = filters.FilterProfile(allowed=set("<>\"'abc"), known=True)
        scan, findings = _scan(profile=profile, _try_context=lambda *a, **k: None)
        self.assertEqual(findings, [])
        self.assertEqual(len(scan.leads), 1)
        self.assertEqual(scan.leads[0].confidence, "low")
        self.assertIn("untested rather than disproved", " ".join(scan.leads[0].notes))

    def test_marker_must_actually_be_in_the_body(self):
        # A profile that says "filtered" is not enough evidence on its own.
        profile = filters.FilterProfile(allowed=set("abc"), stripped={"<"}, known=True)
        scan, findings = _scan("<html><body><p>no echo here</p></body></html>", profile,
                               _try_context=lambda *a, **k: None)
        self.assertEqual(findings, [])
        self.assertEqual(scan.leads, [])

    def test_truncated_reflection_is_recovered_as_a_lead(self):
        # The sink keeps four characters, so neither the marker nor a payload
        # can survive: the point must still be reported, with the reason.
        scan, findings = _scan(transform=lambda v: v[:4])
        self.assertEqual(findings, [])
        self.assertEqual(len(scan.leads), 1, "a truncated echo is not 'unreflected'")
        lead = scan.leads[0]
        self.assertEqual(lead.filter_profile.get("lead_kind"), "partial-reflection")
        self.assertIn("mangles", " ".join(lead.notes))
        self.assertIn("only the first 4 characters survive", lead.evidence)

    def test_non_html_reflection_is_a_lead(self):
        scan, findings = _scan('{{"q": "{value}"}}', content_type="application/json")
        self.assertEqual(findings, [])
        self.assertEqual(len(scan.leads), 1)
        self.assertEqual(scan.leads[0].filter_profile.get("lead_kind"), "non-html")
        self.assertIn("not an HTML execution context", " ".join(scan.leads[0].notes))


class SettleProbeTest(unittest.TestCase):
    def test_marker_missing_one_character_still_triggers_the_short_probe(self):
        # The worst case for the old gate: a 10-character marker with exactly one
        # digit leaves 9 characters behind, which scores 90%+ and is labelled
        # "escaped" -- i.e. reflected.  Treating that as an intact value skipped
        # the letters-only rescue probe entirely, so the sink swallowed every
        # payload and the point vanished.  One lost character is still a mangled
        # value, and the marker has to be re-issued in a spelling that cannot lose
        # any.  Deterministic: no random marker is involved.
        def strip_digits(value: str) -> str:
            return "".join(c for c in value if not c.isdigit())

        http = _StubHTTP(TEXT_TEMPLATE, strip_digits)
        point = scanner.QueryPoint("https://t.example/search?q=1", 0, [])
        scan = scanner.Scanner(http=http, browser=None, level=2)
        marker = "xsabc1def"  # exactly one digit, like ~9% of random hex markers
        resp = http.send(point.build(marker + "zqx"))

        mangled = efficiency.measure(resp.text, marker + "zqx")
        self.assertTrue(mangled.reflected, "a 90% match must not read as unreflected")
        self.assertFalse(mangled.verbatim, "but it is not intact either")
        self.assertNotEqual(mangled.kind, "case")

        chosen, _alt_resp, match = scan._settle_probe(point, marker, resp)
        self.assertNotEqual(chosen, marker, "the mangled spelling must be replaced")
        self.assertNotIn("1", chosen)
        self.assertTrue(match.verbatim, match.describe())
        self.assertEqual(len(http.requests), 2, "exactly one rescue request")


class MangledProbeTest(unittest.TestCase):
    def test_sink_that_strips_digits_still_yields_a_finding(self):
        # A hex marker loses its digits; the point is fully exploitable, so the
        # short letters-only probe has to rescue it instead of reporting silence.
        scan, findings = _scan(transform=lambda v: "".join(c for c in v if not c.isdigit()),
                               level=2, risk=1)
        self.assertEqual(len(findings), 1, "digit-stripping sink is still injectable")
        self.assertTrue(findings[0].payload.startswith("<svg onload="))
        self.assertEqual(scan.leads, [])

    def test_bruteforce_confirms_what_the_payload_ladder_misses(self):
        # Case-sensitive block on the literal "alert": every fixed payload the
        # ladder knows is lowercase, so all of them are mangled. The brute
        # forcer probes casings and rebuilds the call as aLERT(...).
        def strip_alert(value: str) -> str:
            return value.replace("alert", "")

        _scan_obj, findings = _scan(transform=strip_alert, level=2, risk=1,
                                    bruteforce=True, brute_budget=60)
        self.assertEqual(len(findings), 1, "a casing bypass must still be confirmed")
        finding = findings[0]
        # The mutator may randomise further (aLeRt), but the literal the filter
        # strips must be gone and the call must have survived.
        self.assertNotIn("alert", finding.payload, "the blocked literal must not appear")
        self.assertIn("alert", finding.payload.lower())
        self.assertEqual(finding.context, "html_text")
        self.assertTrue(any("brute" in n.lower() or "synthes" in n.lower()
                            for n in finding.notes), finding.notes)


if __name__ == "__main__":
    unittest.main()
