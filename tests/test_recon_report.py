"""Tests for the reconnaissance sections of the Markdown/HTML/SARIF reports.

The new stages (WAF, libraries, discovery, fuzzing, brute force) produce no
findings, so their only durable output is the report. These tests make sure
they actually reach it, stay escaped, and do not leak structured data into the
flat metadata table.

Run:  python tests/test_recon_report.py
"""
from __future__ import annotations

import datetime as dt
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssmap import report as rp
from xssmap import sarif

META = {
    "targets": ["http://t.example/"],
    "waf": [{
        "target": "http://t.example", "checked": True, "vendor": "cloudflare",
        "name": "Cloudflare", "confidence": "high", "blocking": True,
        "evidence": ["server header: cloudflare", "blocked probe returned 403"],
        "strategies": ["case", "js-entity"],
    }],
    "js_libraries": [{
        "name": "jQuery", "version": "1.12.4", "severity": "medium",
        "cves": ["CVE-2020-11022", "CVE-2020-11023"],
        "source": "http://t.example/jquery-1.12.4.min.js",
        "evidence": "body: /*! jQuery v1.12.4 */",
        "detail": "htmlPrefilter allows XSS", "fixed_in": "3.5.0",
        "vulnerable": True,
    }],
    "discovered_parameters": [{
        "url": "http://t.example/search?q=1", "tested": 120, "requests": 18,
        "params": [{"name": "debug", "signal": "reflection", "reflected": True,
                    "evidence": "value reflected verbatim", "status": 200, "delta": 0}],
    }],
    "fuzzing": {"parameters_fuzzed": 1, "with_raw_reflection": 1,
                "encoded_only": 0, "template_evaluation": 1,
                "requests": 17, "truncated": True},
    "fuzzed_parameters": [{
        "name": "q", "url": "http://t.example/search?q=1", "context": "html_text",
        "raw": ["single-quote", "tag"], "encoded": [],
        "evaluated": ["ssti-moustache"], "notes": [], "requests": 17, "probes": [],
    }],
    "leads": [{
        "url": "http://t.example/search?q=1", "param": "q", "context": "attr_double",
        "location": "GET", "confidence": "low",
        "notes": ["every payload was blocked by the WAF",
                  "reflected verbatim in a quoted attribute"],
    }],
    "brute_force": [{
        "point": "GET q", "context": "html_text", "vector": "svg-onload",
        "payload": "<svg onload=alert(1)><script>alert(2)</script>",
        "chars": {"<": "raw", ">": "raw", " ": "raw", '"': "stripped"},
        "requests": 25, "marker_reflected": True, "keywords": {},
        "stripped": ['"'], "synthesised": ["svg-onload"],
    }],
}


class TestMarkdown(unittest.TestCase):
    def test_every_stage_gets_a_section(self):
        text = "\n".join(rp.recon_markdown(META))
        for heading in ("## Reconnaissance", "### Web application firewall",
                        "### Client-side libraries", "### Discovered parameters",
                        "### Parameter fuzzing", "### Filter brute force"):
            with self.subTest(heading=heading):
                self.assertIn(heading, text)
        self.assertIn("CVE-2020-11022", text)
        self.assertIn("Cloudflare", text)
        self.assertIn("`debug`", text)
        self.assertIn("ssti-moustache", text)
        self.assertIn('stripped: "', text)
        self.assertIn("remaining parameters were not probed", text)

    def test_empty_meta_produces_nothing(self):
        self.assertEqual(rp.recon_markdown({}), [])
        self.assertEqual(rp.recon_html({}), "")

    def test_pipes_are_escaped_in_tables(self):
        meta = {"js_libraries": [{"name": "a|b", "version": "1.0", "severity": "low",
                                  "cves": [], "source": "http://t/x.js"}]}
        self.assertIn(r"a\|b", "\n".join(rp.recon_markdown(meta)))

    def test_leads_are_listed_but_not_as_findings(self):
        text = "\n".join(rp.leads_markdown(META))
        self.assertIn("## Leads (unconfirmed)", text)
        self.assertIn("not findings", text)
        self.assertIn("`q`", text)
        self.assertIn("attr_double", text)
        self.assertIn("blocked by the WAF", text)
        self.assertIn("reflected verbatim in a quoted attribute", text)

    def test_lead_kind_is_explained_in_the_context_column(self):
        text = "\n".join(rp.leads_markdown({"leads": [
            {"param": "q", "context": "html_text", "kind": "partial-reflection",
             "notes": ["reflected with 50% efficiency (partial): only the first 5 "
                       "characters survive"]}]}))
        self.assertIn("html_text - mangled reflection", text)
        self.assertIn("only the first 5 characters survive", text)

    def test_ordinary_lead_gets_no_extra_context_label(self):
        # "unproven" is the normal case, so the table stays quiet about it.
        text = "\n".join(rp.leads_markdown({"leads": [
            {"param": "q", "context": "attr_double", "kind": "unproven",
             "notes": ["reflected verbatim x1"]}]}))
        self.assertIn("| attr_double |", text)
        self.assertNotIn("attr_double -", text)

    def test_non_html_lead_is_labelled(self):
        text = "\n".join(rp.leads_markdown({"leads": [
            {"param": "q", "context": "unclassified", "kind": "non-html",
             "notes": ["the sink returns application/json"]}]}))
        self.assertIn("unclassified - non-HTML sink", text)

    def test_no_leads_means_no_section(self):
        self.assertEqual(rp.leads_markdown({}), [])
        self.assertEqual(rp.leads_markdown({"leads": []}), [])
        self.assertEqual(rp.leads_html({"leads": []}), "")

    def test_lead_notes_are_escaped_in_html(self):
        out = rp.leads_html({"leads": [{"param": "q", "url": "http://t/?q=1",
                                          "context": "html_text", "notes": [
                                              "<script>alert(1)</script> blocked"]}]})
        self.assertIn("Leads (unconfirmed)", out)
        self.assertIn("&lt;script&gt;", out)
        self.assertNotIn("<script>alert(1)</script>", out)

    def test_capped_lead_list_says_so(self):
        text = "\n".join(rp.leads_markdown({"leads": [{"param": "q"}],
                                            "leads_truncated": True}))
        self.assertIn("capped", text)

    def test_unchecked_waf_is_labelled(self):
        text = "\n".join(rp.recon_markdown(
            {"waf": [{"target": "http://t.example", "checked": False}]}))
        self.assertIn("not checked", text)


class TestHtml(unittest.TestCase):
    def test_sections_and_escaping(self):
        out = rp.recon_html(META)
        self.assertIn("<h2>Reconnaissance</h2>", out)
        self.assertIn("<h3>Web application firewall</h3>", out)
        self.assertIn("CVE-2020-11022", out)
        self.assertIn("<code>debug</code>", out)
        self.assertNotIn("<script>alert(2)</script>", out)
        self.assertIn("&lt;script&gt;alert(2)&lt;/script&gt;", out)

    def test_write_html_keeps_structured_data_out_of_the_meta_table(self):
        started = dt.datetime(2026, 11, 13, 10, 0, 0)
        meta = rp.build_meta(["http://t.example/"], started,
                             started + dt.timedelta(seconds=12), {"points": 3})
        meta.update({k: v for k, v in META.items() if k != "targets"})
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "report.html")
            rp.write_html(path, [], meta)
            with open(path, encoding="utf-8") as handle:
                text = handle.read()
        self.assertIn("Reconnaissance", text)
        self.assertIn("Client-side libraries", text)
        self.assertNotIn("<td>js_libraries</td>", text)
        self.assertNotIn("<td>brute_force</td>", text)

    def test_write_markdown_reaches_a_clean_report(self):
        started = dt.datetime(2026, 11, 13, 10, 0, 0)
        meta = rp.build_meta(["http://t.example/"], started,
                             started + dt.timedelta(seconds=12), {"points": 3})
        meta.update({k: v for k, v in META.items() if k != "targets"})
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "report.md")
            rp.write_markdown(path, [], meta)
            with open(path, encoding="utf-8") as handle:
                text = handle.read()
        self.assertIn("No cross-site scripting was confirmed.", text)
        self.assertIn("## Reconnaissance", text)
        self.assertIn("## Leads (unconfirmed)", text)
        self.assertNotIn("| leads |", text)


class TestSarif(unittest.TestCase):
    def test_reconnaissance_is_carried_in_run_properties(self):
        data = sarif.build_sarif([], META)
        recon = data["runs"][0]["properties"]["reconnaissance"]
        self.assertEqual(recon["waf"][0]["name"], "Cloudflare")
        self.assertEqual(recon["libraries"][0]["name"], "jQuery")
        self.assertIn("discoveredParameters", recon)
        self.assertIn("fuzzing", recon)
        self.assertIn("bruteForce", recon)
        json.dumps(data)  # must stay serialisable

    def test_plain_meta_has_no_reconnaissance_key(self):
        data = sarif.build_sarif([], {"targets": ["http://t.example/"]})
        self.assertNotIn("reconnaissance", data["runs"][0]["properties"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
