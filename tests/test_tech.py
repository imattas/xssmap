"""Server-stack fingerprinting: header parsing, version rules and report shape."""
import unittest

from xssmap import tech


def names(techs):
    return [t.name for t in techs]


def by_name(techs, name):
    return next(t for t in techs if t.name == name)


class HeaderParsingTests(unittest.TestCase):
    def test_nginx_version_is_read_from_server(self):
        found = tech.detect([("Server", "nginx/1.24.0")])
        self.assertEqual(names(found), ["nginx"])
        self.assertEqual(found[0].version, "1.24.0")
        self.assertEqual(found[0].source, "Server")

    def test_header_lookup_is_case_insensitive(self):
        found = tech.detect([("server", "Apache/2.4.51 (Debian)")])
        self.assertEqual(found[0].name, "Apache httpd")
        self.assertEqual(found[0].version, "2.4.51")

    def test_products_without_a_version_are_still_named(self):
        found = tech.detect([("Server", "cloudflare")])
        self.assertEqual(found[0].name, "Cloudflare")
        self.assertEqual(found[0].version, "")

    def test_several_products_in_one_header(self):
        found = tech.detect([("Server", "nginx/1.18.0 (Ubuntu) OpenSSL/1.1.1f")])
        self.assertEqual(names(found), ["nginx"])

    def test_powered_by_and_aspnet_version(self):
        found = tech.detect([("X-Powered-By", "PHP/8.1.2"),
                             ("X-AspNet-Version", "4.0.30319")])
        self.assertEqual(set(names(found)), {"PHP", "ASP.NET"})
        self.assertEqual(by_name(found, "ASP.NET").version, "4.0.30319")

    def test_meta_generator_identifies_the_cms(self):
        found = tech.detect([], generator="WordPress 6.2")
        self.assertEqual(found[0].name, "WordPress")
        self.assertEqual(found[0].version, "6.2")
        self.assertEqual(found[0].source, "meta generator")

    def test_cookie_names_identify_the_runtime(self):
        found = tech.detect([("Set-Cookie", "PHPSESSID=abc123; path=/; HttpOnly")])
        self.assertEqual(found[0].name, "PHP")
        self.assertEqual(found[0].version, "")
        self.assertTrue(found[0].source.startswith("cookie "))

    def test_cookie_does_not_repeat_a_versioned_product(self):
        found = tech.detect([("X-Powered-By", "PHP/7.4.33"),
                             ("Set-Cookie", "PHPSESSID=abc; path=/")])
        self.assertEqual(names(found), ["PHP"])
        self.assertEqual(found[0].version, "7.4.33")

    def test_duplicate_evidence_is_collapsed(self):
        found = tech.detect([("Server", "nginx/1.24.0"), ("Server", "nginx/1.24.0")])
        self.assertEqual(len(found), 1)

    def test_empty_headers_yield_nothing(self):
        self.assertEqual(tech.detect([]), [])
        self.assertEqual(tech.detect([], generator=""), [])


class VersionRuleTests(unittest.TestCase):
    def test_apache_2449_is_flagged_critical(self):
        row = tech.detect([("Server", "Apache/2.4.49")])[0]
        self.assertEqual(row.status, "vulnerable")
        self.assertEqual(row.severity, "critical")
        self.assertIn("CVE-2021-41773", row.cves)

    def test_apache_2450_is_flagged_with_its_own_cve(self):
        row = tech.detect([("Server", "Apache/2.4.50")])[0]
        self.assertIn("CVE-2021-42013", row.cves)

    def test_patched_apache_is_not_flagged(self):
        row = tech.detect([("Server", "Apache/2.4.51")])[0]
        self.assertEqual(row.status, "detected")
        self.assertEqual(row.cves, [])

    def test_old_nginx_matches_the_resolver_cve(self):
        row = tech.detect([("Server", "nginx/1.18.0")])[0]
        self.assertEqual(row.status, "vulnerable")
        self.assertEqual(row.severity, "high")
        self.assertIn("CVE-2021-23017", row.cves)

    def test_nginx_1201_is_the_fix_and_is_clean(self):
        row = tech.detect([("Server", "nginx/1.20.1")])[0]
        self.assertEqual(row.status, "detected")

    def test_version_compare_is_numeric_not_lexicographic(self):
        # 1.20.10 > 1.20.9 > 1.20.1, so none of these are "older than 1.20.1".
        for version in ("1.20.9", "1.20.10", "1.21.0"):
            row = tech.detect([("Server", f"nginx/{version}")])[0]
            self.assertEqual(row.status, "detected", version)

    def test_php_below_82_is_out_of_support_without_a_cve_claim(self):
        row = tech.detect([("X-Powered-By", "PHP/7.4.33")])[0]
        self.assertEqual(row.status, "outdated")
        self.assertEqual(row.cves, [])
        self.assertTrue(row.detail)

    def test_supported_php_is_clean(self):
        row = tech.detect([("X-Powered-By", "PHP/8.3.1")])[0]
        self.assertEqual(row.status, "detected")

    def test_iis_10_is_not_flagged(self):
        row = tech.detect([("Server", "Microsoft-IIS/10.0")])[0]
        self.assertEqual(row.status, "detected")

    def test_iis_85_is_flagged_but_prefix_does_not_swallow_10(self):
        self.assertEqual(tech.detect([("Server", "Microsoft-IIS/8.5")])[0].status,
                         "outdated")
        self.assertEqual(tech.detect([("Server", "Microsoft-IIS/10.0")])[0].status,
                         "detected")

    def test_cms_versions_are_reported_without_eol_claims(self):
        row = tech.detect([], generator="Drupal 9")[0]
        self.assertEqual(row.status, "detected")
        self.assertEqual(row.cves, [])


class ReportShapeTests(unittest.TestCase):
    def test_rows_carry_every_report_field(self):
        rows = tech.rows(tech.detect([("Server", "Apache/2.4.49")]))
        self.assertEqual(set(rows[0]), {"name", "version", "source", "status",
                                        "severity", "cves", "detail"})
        self.assertIsInstance(rows[0]["cves"], list)

    def test_summary_counts_by_status(self):
        found = (tech.detect([("Server", "Apache/2.4.49")])
                 + tech.detect([("X-Powered-By", "PHP/7.4")])
                 + tech.detect([("Server", "Microsoft-IIS/10.0")]))
        self.assertEqual(tech.summary(found)["vulnerable"], 1)
        self.assertEqual(tech.summary(found)["outdated"], 1)
        self.assertEqual(tech.summary(found)["detected"], 1)

    def test_line_names_the_version_and_evidence(self):
        row = tech.detect([("Server", "nginx/1.18.0")])[0]
        self.assertIn("nginx 1.18.0", row.line())
        self.assertIn("Server", row.line())
        self.assertIn("1.20.1", row.line())


if __name__ == "__main__":
    unittest.main()
