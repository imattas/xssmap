"""Tests for subdomain discovery, domain input and the autonomous preset.

Every test here is offline: DNS and HTTP are injected fakes, so the suite keeps
passing on a machine with no network and never touches a third party.
"""
import json
import os
import tempfile
import unittest

from xssmap import subdomains as subs
from xssmap.cli import (
    apply_autonomous,
    build_parser,
    domain_host,
    explicit_dests,
    finalize_args,
    read_wordlist,
)
from xssmap.crawler import Crawler, Scope


class QuietLog:
    def __init__(self):
        self.lines = []

    def _record(self, level, message):
        self.lines.append((level, message))

    def info(self, message):
        self._record("info", message)

    def warn(self, message):
        self._record("warn", message)

    def debug(self, message):
        self._record("debug", message)

    def action(self, message):
        self._record("action", message)

    def ok(self, message):
        self._record("ok", message)


def resolver_for(live):
    """Fake resolver: names in `live` resolve, everything else is NXDOMAIN."""
    def resolve(host):
        if host in live:
            return live[host]
        raise OSError("nxdomain")
    return resolve


class NormalizeDomainTests(unittest.TestCase):
    def test_accepts_the_forms_people_type(self):
        cases = {
            "example.com": "example.com",
            "Example.COM": "example.com",
            "https://example.com/": "example.com",
            "https://example.com": "example.com",
            "example.com:8443": "example.com",
            "example.com.": "example.com",
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(subs.normalize_domain(value), expected)

    def test_rejects_paths_and_queries(self):
        for value in ("example.com/app", "example.com/?q=1", ""):
            with self.subTest(value=value), self.assertRaises(subs.DiscoveryError):
                subs.normalize_domain(value)


class ScopeMatchTests(unittest.TestCase):
    def test_is_under_does_not_match_lookalike_suffixes(self):
        self.assertTrue(subs.is_under("a.example.com", "example.com"))
        self.assertTrue(subs.is_under("example.com", "example.com"))
        self.assertFalse(subs.is_under("notexample.com", "example.com"))
        self.assertFalse(subs.is_under("example.com.evil.tld", "example.com"))

    def test_subdomain_base_strips_only_www(self):
        self.assertEqual(subs.subdomain_base("https://www.example.com/x"), "example.com")
        self.assertEqual(subs.subdomain_base("https://shop.example.com"), "shop.example.com")
        self.assertEqual(subs.subdomain_base("https://example.com"), "example.com")

    def test_multi_label_suffix_widens_to_the_registrable_domain(self):
        # A shop on example.co.uk belongs to the same registrable domain, unlike
        # shop.example.com where .com says nothing about ownership.
        self.assertEqual(subs.subdomain_base("https://shop.example.co.uk"),
                         "example.co.uk")
        # Two labels below the suffix is a host of its own; only the direct
        # child of a registrable domain is widened by `auto`.
        self.assertEqual(subs.subdomain_base("https://a.b.example.co.uk"),
                         "a.b.example.co.uk")
        self.assertEqual(subs.subdomain_base("https://a.b.example.co.uk", "registrable"),
                         "example.co.uk")
        self.assertEqual(subs.subdomain_base("shop.example.co.uk", "registrable"),
                         "example.co.uk")
        self.assertEqual(subs.subdomain_base("shop.example.co.uk", "host"),
                         "shop.example.co.uk")

    def test_unknown_mode_is_rejected(self):
        with self.assertRaises(ValueError):
            subs.subdomain_base("https://example.com", "everything")


class PublicSuffixTests(unittest.TestCase):
    def test_known_suffixes_beat_the_last_label(self):
        self.assertEqual(subs.public_suffix("a.b.example.co.uk"), "co.uk")
        self.assertEqual(subs.public_suffix("shop.example.com"), "com")
        self.assertEqual(subs.public_suffix("example.github.io"), "github.io")

    def test_registrable_domain_is_suffix_plus_one_label(self):
        self.assertEqual(subs.registrable_domain("shop.example.co.uk"), "example.co.uk")
        self.assertEqual(subs.registrable_domain("example.com"), "example.com")
        self.assertEqual(subs.registrable_domain("a.b.example.github.io"),
                         "example.github.io")

    def test_wildcard_and_exception_rules(self):
        table = {"*.ck", "!www.ck", "*.kawasaki.jp", "!city.kawasaki.jp"}
        self.assertEqual(subs.public_suffix("a.b.ck", table), "b.ck")
        self.assertEqual(subs.public_suffix("www.ck", table), "ck")
        self.assertEqual(subs.public_suffix("city.kawasaki.jp", table),
                         "kawasaki.jp")

    def test_suffix_file_loader_reads_rules_and_skips_comments(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "public_suffix_list.dat")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("// comment\n\nco.uk\n*.ck\n!www.ck\n")
            table = subs.load_suffix_file(path)
        self.assertEqual(table, {"co.uk", "*.ck", "!www.ck"})

    def test_loaded_table_changes_the_base_domain(self):
        # Treating example.com as a suffix makes shop.example.com registrable.
        table = {"example.com"}
        self.assertEqual(subs.registrable_domain("shop.example.com", table),
                         "shop.example.com")
        self.assertEqual(subs.subdomain_base("a.shop.example.com", "auto", table),
                         "shop.example.com")


class CertificateTransparencyTests(unittest.TestCase):
    def test_parse_keeps_in_scope_names_only(self):
        payload = json.dumps([
            {"name_value": "api.example.com\n*.dev.example.com"},
            {"common_name": "WWW.Example.com"},
            {"name_value": "example.com"},
            {"name_value": "notexample.com"},
            {"name_value": "*.example.com.evil.tld"},
            {"common_name": "*.example.com"},
        ])
        self.assertEqual(
            subs.parse_ct_json(payload, "example.com"),
            ["api.example.com", "dev.example.com", "www.example.com"])

    def test_malformed_payload_is_not_fatal(self):
        self.assertEqual(subs.parse_ct_json("<html>502</html>", "example.com"), [])
        self.assertEqual(subs.parse_ct_json('{"a": 1}', "example.com"), [])


class DiscoveryTests(unittest.TestCase):
    def test_ip_target_is_skipped_cleanly(self):
        log = QuietLog()
        result = subs.discover("127.0.0.1", fetch=lambda url: "[]",
                               resolve_func=resolver_for({}), log=log)
        self.assertEqual(result.hosts, [])
        self.assertIn("registrable", result.skipped)
        self.assertIn("skipped", result.describe())
        # a user who asked for --subdomains must be told why nothing happened
        self.assertTrue(any(level == "warn" for level, _ in log.lines))

    def test_ct_and_dns_results_are_merged_and_dead_hosts_dropped(self):
        ct = json.dumps([
            {"name_value": "api.example.com"},
            {"name_value": "dead.example.com"},
            {"name_value": "www.example.com"},
        ])
        live = {
            "api.example.com": ["192.0.2.10"],
            "www.example.com": ["192.0.2.11"],
        }
        log = QuietLog()
        result = subs.discover("example.com", fetch=lambda url: ct,
                               resolve_func=resolver_for(live), log=log, brute=False)
        self.assertEqual(result.hosts, ["api.example.com", "www.example.com"])
        self.assertEqual(result.by_source["ct"], 3)
        self.assertTrue(any("did not resolve" in e for e in result.errors))
        self.assertIn("2 host(s)", result.describe())
        self.assertTrue(log.lines)

    def test_wildcard_dns_skips_brute_force(self):
        def resolve(host):
            return ["192.0.2.99"]  # every name "resolves"

        calls = []

        def counting_resolve(host):
            calls.append(host)
            return resolve(host)

        result = subs.discover("example.com", fetch=None,
                               resolve_func=counting_resolve, brute=True,
                               wordlist=["api", "dev"], max_hosts=5)
        self.assertTrue(result.wildcard)
        self.assertNotIn("dns", result.by_source)
        # detection stops at the first resolving probe and never touches the wordlist
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0].endswith(".example.com"))
        self.assertTrue(any("wildcard" in e for e in result.errors))

    def test_host_cap_is_enforced_and_reported(self):
        ct = json.dumps([{"name_value": f"h{i}.example.com"} for i in range(10)])
        live = {f"h{i}.example.com": ["192.0.2.1"] for i in range(10)}
        result = subs.discover("example.com", fetch=lambda url: ct,
                               resolve_func=resolver_for(live), brute=False, max_hosts=3)
        self.assertEqual(len(result.hosts), 3)
        self.assertTrue(any("host cap" in e for e in result.errors))

    def test_fetch_failure_is_recorded_not_raised(self):
        def boom(url):
            raise RuntimeError("crt.sh returned HTTP 502")

        result = subs.discover("example.com", fetch=boom,
                               resolve_func=resolver_for({}), brute=False)
        self.assertEqual(result.hosts, [])
        self.assertTrue(any("crt.sh" in e for e in result.errors))


class MultiProviderTests(unittest.TestCase):
    """One certificate source failing must not empty the result."""

    LIVE = {"api.example.com": ["192.0.2.10"], "www.example.com": ["192.0.2.11"]}

    def test_certspotter_names_are_parsed_and_scoped(self):
        payload = json.dumps([
            {"dns_names": ["api.example.com", "*.example.com", "evil.tld"]},
            {"dns_names": ["notexample.com", "www.example.com"]},
        ])
        self.assertEqual(subs.parse_certspotter_json(payload, "example.com"),
                         ["api.example.com", "www.example.com"])
        self.assertEqual(subs.parse_certspotter_json("nope", "example.com"), [])

    def test_hackertarget_csv_is_parsed_and_errors_are_empty(self):
        payload = "api.example.com,192.0.2.10\nwww.example.com,192.0.2.11\n"
        self.assertEqual(subs.parse_hackertarget_text(payload, "example.com"),
                         ["api.example.com", "www.example.com"])
        self.assertEqual(subs.parse_hackertarget_text("API count exceeded",
                                                      "example.com"), [])

    def test_second_provider_runs_when_the_first_fails(self):
        called = []
        payload = json.dumps([{"dns_names": ["api.example.com", "www.example.com"]}])

        def fetch(url):
            called.append(url)
            if "crt.sh" in url:
                raise RuntimeError("crt.sh returned HTTP 502")
            return payload

        result = subs.discover("example.com", fetch=fetch,
                               resolve_func=resolver_for(self.LIVE), brute=False)
        self.assertEqual(result.hosts, ["api.example.com", "www.example.com"])
        # The failed source is skipped, not fatal; the next ones are still asked
        # because the host cap has not been met yet.
        self.assertEqual(result.providers, {"certspotter": 2, "hackertarget": 0})
        self.assertEqual(len(called), 3)
        self.assertTrue(any("crt.sh" in e for e in result.errors))

    def test_third_provider_runs_when_the_first_two_fail(self):
        def fetch(url):
            if "crt.sh" in url:
                raise RuntimeError("crt.sh returned HTTP 502")
            if "certspotter" in url:
                raise RuntimeError("api.certspotter.com returned HTTP 429")
            return "api.example.com,192.0.2.10\n"

        result = subs.discover("example.com", fetch=fetch,
                               resolve_func=resolver_for(self.LIVE), brute=False)
        self.assertEqual(result.hosts, ["api.example.com"])
        self.assertEqual(result.providers, {"hackertarget": 1})
        self.assertEqual(len(result.errors), 2)

    def test_providers_stop_once_the_host_cap_is_met(self):
        called = []
        payload = json.dumps([{"name_value": f"h{i}.example.com"} for i in range(5)])

        def fetch(url):
            called.append(url)
            return payload

        live = {f"h{i}.example.com": ["192.0.2.1"] for i in range(5)}
        result = subs.discover("example.com", fetch=fetch,
                               resolve_func=resolver_for(live), brute=False,
                               max_hosts=2)
        self.assertEqual(len(called), 1)  # cap already satisfied by crt.sh
        self.assertEqual(result.providers, {"crt.sh": 5})

    def test_explicit_provider_list_is_honoured(self):
        seen = []

        def fetch(url):
            seen.append(url)
            return json.dumps([{"name_value": "api.example.com"}])

        subs.discover("example.com", fetch=fetch,
                      resolve_func=resolver_for(self.LIVE), brute=False,
                      providers=("hackertarget",))
        self.assertEqual(len(seen), 1)
        self.assertIn("hackertarget", seen[0])


class AutonomousPresetTests(unittest.TestCase):
    def setUp(self):
        self.parser = build_parser()

    def test_preset_turns_on_the_sweep(self):
        argv = ["--domain", "example.com"]
        args = self.parser.parse_args(argv)
        apply_autonomous(args, explicit_dests(self.parser, argv))
        self.assertEqual(args.max_pages, 400)
        self.assertEqual(args.crawl_depth, 3)
        self.assertEqual(args.max_minutes, 30.0)
        self.assertTrue(args.subdomains)
        self.assertTrue(args.stored)
        self.assertTrue(args.forms)
        self.assertTrue(args.screenshots)

    def test_explicit_values_win(self):
        argv = ["--domain", "example.com", "--max-pages", "50", "--depth", "1"]
        args = self.parser.parse_args(argv)
        apply_autonomous(args, explicit_dests(self.parser, argv))
        self.assertEqual(args.max_pages, 50)
        self.assertEqual(args.crawl_depth, 1)

    def test_explicit_off_switches_survive(self):
        argv = ["--domain", "example.com", "--no-stored", "--no-browser"]
        args = self.parser.parse_args(argv)
        apply_autonomous(args, explicit_dests(self.parser, argv))
        self.assertFalse(args.stored)
        self.assertIsNone(args.browser)
        finalize_args(args)
        self.assertFalse(args.stored)

    def test_finalize_collapses_crawl_flags(self):
        args = self.parser.parse_args(["--domain", "example.com"])
        finalize_args(args)
        self.assertTrue(args.crawl)
        args = self.parser.parse_args(["--domain", "example.com", "--no-crawl"])
        finalize_args(args)
        self.assertFalse(args.crawl)

    def test_explicit_detection_reads_aliases_and_values(self):
        explicit = explicit_dests(self.parser, ["--depth", "4", "--max-pages=10", "-u", "x"])
        self.assertEqual(explicit, {"crawl_depth", "max_pages", "url"})


class DomainArgumentTests(unittest.TestCase):
    def test_host_and_port(self):
        self.assertEqual(domain_host("example.com"), ("example.com", None))
        self.assertEqual(domain_host("https://example.com:8443/"), ("example.com", 8443))

    def test_path_is_rejected_with_advice(self):
        with self.assertRaises(subs.DiscoveryError) as ctx:
            domain_host("example.com/app")
        self.assertIn("-u", str(ctx.exception))


class WordlistTests(unittest.TestCase):
    def test_reads_labels_and_skips_noise(self):
        fd, path = tempfile.mkstemp(suffix=".txt")
        os.close(fd)
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("# comment\n\napi\nAPI\nbad_host!\n  dev  \n")
            self.assertEqual(read_wordlist(path), ["api", "dev"])
        finally:
            os.unlink(path)


class FakeResponse:
    def __init__(self, url, status=200, text="", content_type="text/html"):
        self.url = url
        self.status = status
        self.text = text
        self.body = text.encode()
        self.content_type = content_type
        self.history = []

    @property
    def is_html(self):
        return "html" in self.content_type

    @property
    def is_javascript(self):
        return "javascript" in self.content_type


class FakeHTTP:
    def __init__(self, pages):
        self.pages = pages
        self.requests = []

    def get(self, url, headers=None, **kwargs):
        self.requests.append(url)
        if url.endswith("robots.txt") or url.endswith("sitemap.xml"):
            return FakeResponse(url, 404, "", "text/plain")
        body = self.pages.get(url, "<html><body>empty</body></html>")
        return FakeResponse(url, 200, body)


class MultiHostCrawlTests(unittest.TestCase):
    def _crawl(self, scope_mode):
        pages = {
            "http://example.com/": '<html><body><a href="/search?q=1">s</a></body></html>',
            "http://api.example.com/": '<html><body><a href="/search?q=2">s</a></body></html>',
        }
        http = FakeHTTP(pages)
        crawler = Crawler(http, Scope("http://example.com", scope_mode), QuietLog(),
                          max_depth=1, max_pages=20, crawl_js=False)
        return crawler.run(["http://example.com", "http://api.example.com"])

    def test_subdomain_scope_crawls_every_seed(self):
        result = self._crawl("subdomain")
        self.assertIn("http://example.com/", result.pages)
        self.assertIn("http://api.example.com/", result.pages)
        self.assertIn("http://api.example.com/search?q=2", result.param_urls)

    def test_host_scope_drops_the_extra_seed(self):
        result = self._crawl("host")
        self.assertIn("http://example.com/", result.pages)
        # the foreign seed is dropped before any request is made, so nothing is
        # counted as a scope skip and no traffic reaches the other host
        self.assertNotIn("http://api.example.com/", result.pages)
        self.assertEqual(result.skipped_scope, 0)


if __name__ == "__main__":
    unittest.main()
