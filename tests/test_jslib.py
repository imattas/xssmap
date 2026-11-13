"""Unit tests for JavaScript library fingerprinting and CVE hints.

Two properties are load-bearing and therefore tested hardest: a version is only
reported when it was read from the resource itself, and "outdated" is only
turned into a CVE when the observed version is genuinely below the published
fixed version.

Run:  python tests/test_jslib.py
"""
from __future__ import annotations

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from stubhttp import Resp

from xssmap import jslib


class TestScan(unittest.TestCase):
    def test_old_jquery_is_flagged_with_its_cves(self):
        libs = jslib.scan([("http://t.example/jquery-1.12.4.min.js",
                            "/*! jQuery v1.12.4 | (c) jQuery Foundation */", [])])
        self.assertEqual(len(libs), 1)
        lib = libs[0]
        self.assertEqual((lib.name, lib.version), ("jQuery", "1.12.4"))
        self.assertTrue(lib.vulnerable)
        # 1.12.4 is below every fix in the table, so every matching advisory is
        # reported: the htmlPrefilter pair, the selector XSS (fixed 1.9.0 is
        # *below* this version, so that one must not appear) and cross-domain
        # ajax (fixed 3.0.0).
        self.assertEqual(lib.cves, ["CVE-2015-9251", "CVE-2020-11022", "CVE-2020-11023"])
        self.assertEqual(lib.fixed_in, "3.5.0")
        self.assertEqual(lib.severity, "medium")
        self.assertIn("jQuery", lib.evidence)

    def test_bootstrap_reports_the_cve_that_actually_covers_the_version(self):
        # CVE-2019-8331 covers 3.0.0-<3.4.1 and 4.0.0-<4.3.1 only. A single
        # "fixed in 4.3.1" number used to flag every 2.x release, which is a
        # false positive, and to miss 4.0.0-4.2.x, which is a false negative.
        expected = {
            "2.3.2": False, "3.3.7": True, "3.4.0": True,
            "4.0.0": True, "4.2.1": True, "4.3.1": False, "5.3.0": False,
        }
        for version, affected in expected.items():
            with self.subTest(version=version):
                libs = jslib.scan([(f"http://t.example/bootstrap-{version}.min.js",
                                    "", [])])
                self.assertEqual(len(libs), 1)
                self.assertEqual(("CVE-2019-8331" in libs[0].cves), affected,
                                 libs[0].cves)

    def test_bootstrap_337_keeps_its_own_advisory(self):
        # 3.3.7 is genuinely affected by the prototype-pollution advisory fixed
        # in 3.4.0, so "not affected by CVE-2019-8331" must not mean "clean".
        libs = jslib.scan([("http://t.example/bootstrap-3.3.7.min.js", "", [])])
        self.assertTrue(libs[0].vulnerable)
        self.assertIn("CVE-2019-5428", libs[0].cves)

    def test_current_jquery_has_no_cve_hint(self):
        libs = jslib.scan([("http://t.example/jquery-3.7.1.min.js",
                            "/*! jQuery v3.7.1 */", [])])
        self.assertEqual(len(libs), 1)
        self.assertEqual(libs[0].version, "3.7.1")
        self.assertFalse(libs[0].vulnerable)
        self.assertEqual(libs[0].cves, [])
        self.assertEqual(libs[0].severity, "info")

    def test_old_dompurify_is_flagged(self):
        libs = jslib.scan([("http://t.example/purify.js",
                            'DOMPurify.version = "2.0.11";', [])])
        self.assertEqual(libs[0].name, "DOMPurify")
        self.assertEqual(libs[0].cves, ["CVE-2020-26870"])

    def test_version_can_come_from_the_filename(self):
        libs = jslib.scan([("http://t.example/js/jquery-ui-1.12.1.min.js", "", [])])
        self.assertEqual((libs[0].name, libs[0].version), ("jQuery UI", "1.12.1"))
        self.assertEqual(libs[0].cves, ["CVE-2022-31160"])
        self.assertIn("filename:", libs[0].evidence)

    def test_unknown_library_produces_nothing(self):
        self.assertEqual(
            jslib.scan([("http://t.example/app.js", "console.log(1);", [])]), [])

    def test_same_library_and_version_is_reported_once(self):
        libs = jslib.scan([
            ("http://t.example/jquery-1.12.4.min.js", "jQuery v1.12.4", []),
            ("http://t.example/js/jquery-1.12.4.min.js", "jQuery v1.12.4", []),
        ])
        self.assertEqual(len(libs), 1)

    def test_malformed_resources_are_ignored(self):
        self.assertEqual(jslib.scan([None, ("only-a-url",), 42]), [])

    def test_results_are_sorted_by_severity(self):
        libs = jslib.scan([
            ("http://t.example/jquery-3.7.1.min.js", "jQuery v3.7.1", []),
            ("http://t.example/handlebars.js", 'Handlebars.VERSION = "4.5.0";', []),
        ])
        self.assertEqual([lib.name for lib in libs], ["Handlebars", "jQuery"])
        self.assertEqual(libs[0].severity, "critical")

    def test_as_dict_carries_the_evidence(self):
        lib = jslib.scan([("http://t.example/jquery-1.12.4.min.js",
                           "/*! jQuery v1.12.4 */", [])])[0]
        data = lib.as_dict()
        for key in ("name", "version", "source", "evidence", "cves",
                    "severity", "detail", "fixed_in", "vulnerable"):
            self.assertIn(key, data)
        self.assertTrue(data["vulnerable"])
        self.assertIn("v1.12.4", data["evidence"])


class TestVersionCompare(unittest.TestCase):
    def test_numeric_not_lexical(self):
        self.assertTrue(jslib._below("3.9.1", "3.10.0"))
        self.assertFalse(jslib._below("3.10.0", "3.9.1"))
        self.assertFalse(jslib._below("3.5.0", "3.5.0"))

    def test_padding_and_suffixes(self):
        self.assertTrue(jslib._below("1.12", "1.12.1"))
        self.assertTrue(jslib._below("1.12.4-beta", "3.5.0"))
        self.assertFalse(jslib._below("", "1.0.0"))


class _Log:
    def __init__(self):
        self.warnings: list[str] = []
        self.debugs: list[str] = []

    def warn(self, message: str) -> None:
        self.warnings.append(message)

    def debug(self, message: str) -> None:
        self.debugs.append(message)


class TestReport(unittest.TestCase):
    def test_vulnerable_libraries_warn_and_all_are_returned(self):
        libs = jslib.scan([
            ("http://t.example/jquery-1.12.4.min.js", "jQuery v1.12.4", []),
            ("http://t.example/jquery-3.7.1.min.js", "jQuery v3.7.1", []),
        ])
        log = _Log()
        rows = jslib.report(libs, log)
        self.assertEqual(len(rows), 2)
        self.assertEqual(len(log.warnings), 1)
        self.assertIn("CVE-2020-11022", log.warnings[0])
        self.assertEqual(len(log.debugs), 1)

    def test_report_without_a_logger(self):
        libs = jslib.scan([("http://t.example/jquery-1.12.4.min.js", "jQuery v1.12.4", [])])
        self.assertEqual(len(jslib.report(libs)), 1)

    def test_summary_shape(self):
        libs = jslib.scan([
            ("http://t.example/jquery-1.12.4.min.js", "jQuery v1.12.4", []),
            ("http://t.example/jquery-3.7.1.min.js", "jQuery v3.7.1", []),
        ])
        data = jslib.summary(libs)
        self.assertEqual(set(data), {"detected", "outdated", "libraries"})
        self.assertEqual(data["detected"], 2)
        self.assertEqual(data["outdated"], 1)
        self.assertEqual(len(data["libraries"]), 2)


class _OSVHTTP:
    """Fake advisory client: records each query, answers with fixed vulns."""

    def __init__(self, vulns, status=200):
        self.vulns = vulns
        self.status = status
        self.queries: list[dict] = []

    def post(self, url, body, headers=None, **kwargs):
        self.queries.append(json.loads(body.decode("utf-8")))
        return Resp(url, self.status, json.dumps({"vulns": self.vulns}))


class TestOsv(unittest.TestCase):
    def _lib(self, version="3.7.1"):
        return jslib.scan([(f"http://t.example/jquery-{version}.min.js",
                            f"jQuery v{version}", [])])

    def test_aliases_are_merged_into_the_local_verdict(self):
        libs = self._lib()
        http = _OSVHTTP([{"id": "GHSA-1", "aliases": ["CVE-2024-0001"]}])
        changed = jslib.enrich_osv(libs, http)
        self.assertEqual(changed, 1)
        self.assertEqual(libs[0].cves, ["CVE-2024-0001"])
        self.assertTrue(libs[0].vulnerable)
        self.assertEqual(libs[0].severity, "medium")
        self.assertIn("osv", libs[0].evidence)
        self.assertEqual(http.queries[0]["package"],
                         {"name": "jquery", "ecosystem": "npm"})

    def test_service_failure_does_not_change_the_verdict(self):
        libs = self._lib()
        changed = jslib.enrich_osv(libs, _OSVHTTP([], status=503))
        self.assertEqual(changed, 0)
        self.assertEqual(libs[0].cves, [])
        self.assertFalse(libs[0].vulnerable)

    def test_malformed_response_is_ignored(self):
        libs = self._lib()
        http = _OSVHTTP([], status=200)
        http.post = lambda *a, **k: Resp("https://api.osv.dev/", 200, "not json")
        self.assertEqual(jslib.enrich_osv(libs, http), 0)

    def test_library_without_a_known_version_is_not_queried(self):
        # OSV answers a versionless query with every advisory for the package,
        # which would read as "this build is vulnerable to all of them".
        libs = [jslib.Library(name="Lodash", version="", source="", evidence="",
                              cves=[], severity="info")]
        http = _OSVHTTP([{"id": "GHSA-1", "aliases": ["CVE-2024-0001"]}])
        self.assertEqual(jslib.enrich_osv(libs, http), 0)
        self.assertEqual(http.queries, [])
        self.assertFalse(libs[0].vulnerable)

    def test_long_advisory_list_is_summarised_in_the_line(self):
        cves = [f"CVE-2026-{i:04d}" for i in range(12)]
        lib = jslib.Library(name="DOMPurify", version="2.0.0", source="",
                            evidence="", cves=cves, severity="medium")
        line = lib.line()
        self.assertIn("CVE-2026-0000", line)
        self.assertIn("(+4 more)", line)
        self.assertNotIn("CVE-2026-0011", line, "the tail is counted, not printed")
        self.assertEqual(len(lib.as_dict()["cves"]), 12, "JSON keeps every advisory")

    def test_lookups_are_capped(self):
        libs = jslib.scan([
            ("http://t.example/jquery-3.7.1.min.js", "jQuery v3.7.1", []),
            ("http://t.example/lodash-4.17.21.min.js", "", []),
            ("http://t.example/moment-2.29.4.min.js", "", []),
        ])
        http = _OSVHTTP([])
        jslib.enrich_osv(libs, http, max_lookups=2)
        self.assertEqual(len(http.queries), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
