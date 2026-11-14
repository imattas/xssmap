"""Discovery completeness: sitemap index trees, compressed sitemaps, caps.

A crawl that only follows links pays one round trip per page and can never see
a page nobody links to. Sitemaps invert that: one request names thousands of
URLs, so a site with 4,000 parameterised pages costs a handful of requests
instead of 4,000. These tests pin the reader's behaviour, including the limits
that keep a hostile target from turning discovery into an endless fetch loop.

Run:  python -m unittest tests.test_discovery -v
"""
from __future__ import annotations

import gzip
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssmap import cli
from xssmap.crawler import Crawler, Scope

BASE = "http://app.test/"

URLSET = ('<?xml version="1.0" encoding="UTF-8"?>'
          '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{}</urlset>')
INDEX = ('<?xml version="1.0" encoding="UTF-8"?>'
         '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{}</sitemapindex>')


def urlset(*locs: str) -> str:
    return URLSET.format("".join(f"<url><loc>{loc}</loc></url>" for loc in locs))


def index(*locs: str) -> str:
    return INDEX.format("".join(f"<sitemap><loc>{loc}</loc></sitemap>" for loc in locs))


class QuietLog:
    def info(self, *_a, **_k):
        pass

    def debug(self, *_a, **_k):
        pass

    def warn(self, *_a, **_k):
        pass

    def ok(self, *_a, **_k):
        pass

    def action(self, *_a, **_k):
        pass


class Resp:
    """Enough of :class:`xssmap.net.Response` for the crawler's sitemap path."""

    def __init__(self, url, status=200, body=b"", content_type="application/xml"):
        self.url = url
        self.status = status
        self.body = body.encode("utf-8") if isinstance(body, str) else body
        self.text = self.body.decode("utf-8", "replace")
        self.content_type = content_type
        self.headers: list = []
        self.history: list = []

    @property
    def is_html(self) -> bool:
        return self.content_type.startswith("text/html")

    @property
    def is_javascript(self) -> bool:
        return "javascript" in self.content_type


class SitemapHTTP:
    """URL -> (body, content-type); anything else is a 404."""

    def __init__(self, routes):
        self.routes = routes
        self.urls: list[str] = []

    def get(self, url, headers=None, **_kwargs):
        self.urls.append(url)
        if url in self.routes:
            body, ctype = self.routes[url]
            return Resp(url, 200, body, ctype)
        return Resp(url, 404, "not found", "text/plain")

    def requested(self, url: str) -> int:
        return self.urls.count(url)


def crawl(routes, depth: int = 0):
    http = SitemapHTTP(routes)
    crawler = Crawler(http, Scope(BASE), QuietLog(), max_depth=depth, max_pages=5,
                      crawl_js=False, crawl_forms=False)
    return crawler.run([BASE]), http


HOME = ("<html><body><p>home</p></body></html>", "text/html")
ROBOTS = (f"Sitemap: {BASE}sitemap_index.xml\n", "text/plain")


class SitemapTreeTest(unittest.TestCase):
    def test_children_of_a_sitemap_index_are_followed(self):
        # The regression: index children used to be skipped as "sitemap*.xml",
        # so a site that publishes an index contributed zero URLs.
        routes = {
            BASE: HOME,
            BASE + "robots.txt": ROBOTS,
            BASE + "sitemap_index.xml": (index(BASE + "a.xml", BASE + "b.xml"), "application/xml"),
            BASE + "a.xml": (urlset(BASE + "p?x=1", BASE + "p?x=2"), "application/xml"),
            BASE + "b.xml": (urlset(BASE + "q?y=1"), "application/xml"),
        }
        result, http = crawl(routes)
        self.assertEqual(set(result.param_urls),
                         {BASE + "p?x=1", BASE + "p?x=2", BASE + "q?y=1"})
        self.assertEqual(http.requested(BASE + "a.xml"), 1)
        self.assertEqual(http.requested(BASE + "b.xml"), 1)

    def test_robots_can_list_several_sitemaps(self):
        routes = {
            BASE: HOME,
            BASE + "robots.txt": (f"Sitemap: {BASE}one.xml\nSitemap: {BASE}two.xml\n", "text/plain"),
            BASE + "one.xml": (urlset(BASE + "one?x=1"), "application/xml"),
            BASE + "two.xml": (urlset(BASE + "two?y=1"), "application/xml"),
        }
        result, _http = crawl(routes)
        self.assertEqual(set(result.param_urls), {BASE + "one?x=1", BASE + "two?y=1"})

    def test_nested_index_is_followed_two_levels_deep(self):
        routes = {
            BASE: HOME,
            BASE + "robots.txt": ROBOTS,
            BASE + "sitemap_index.xml": (index(BASE + "middle.xml"), "application/xml"),
            BASE + "middle.xml": (index(BASE + "leaf.xml"), "application/xml"),
            BASE + "leaf.xml": (urlset(BASE + "deep?z=1"), "application/xml"),
        }
        result, _http = crawl(routes)
        self.assertEqual(result.param_urls, [BASE + "deep?z=1"])

    def test_depth_cap_stops_a_fourth_level(self):
        routes = {
            BASE: HOME,
            BASE + "robots.txt": ROBOTS,
            BASE + "sitemap_index.xml": (index(BASE + "one.xml"), "application/xml"),
            BASE + "one.xml": (index(BASE + "two.xml"), "application/xml"),
            BASE + "two.xml": (index(BASE + "three.xml"), "application/xml"),
            BASE + "three.xml": (urlset(BASE + "never?z=1"), "application/xml"),
        }
        result, http = crawl(routes)
        self.assertEqual(http.requested(BASE + "three.xml"), 0)
        self.assertEqual(result.param_urls, [])

    def test_sitemap_file_cap_is_global(self):
        children = [BASE + f"child{i}.xml" for i in range(6)]
        routes = {
            BASE: HOME,
            BASE + "robots.txt": (f"Sitemap: {BASE}root.xml\n", "text/plain"),
            BASE + "root.xml": (index(*children), "application/xml"),
        }
        routes.update({c: (urlset(c + "?k=1"), "application/xml") for c in children})
        # root.xml holds one of the three slots, so two children may follow.
        with mock.patch("xssmap.crawler.MAX_SITEMAP_FILES", 3):
            _result, http = crawl(routes)
        fetched = sum(http.requested(c) for c in children)
        self.assertEqual(fetched, 2, "only the cap may be fetched, never the whole index")


class SitemapFormatTest(unittest.TestCase):
    def test_gzip_sitemap_is_decoded(self):
        # Search engines accept sitemap.xml.gz; the locs are gzip, not XML text.
        payload = gzip.compress(urlset(BASE + "gz?k=1").encode("utf-8"))
        routes = {BASE: HOME, BASE + "sitemap.xml": (payload, "application/gzip")}
        result, _http = crawl(routes)
        self.assertEqual(result.param_urls, [BASE + "gz?k=1"])

    def test_entities_in_loc_urls_are_decoded(self):
        routes = {
            BASE: HOME,
            BASE + "sitemap.xml": (urlset(BASE + "search?q=a&amp;b=1"), "application/xml"),
        }
        result, _http = crawl(routes)
        self.assertEqual(result.param_urls, [BASE + "search?q=a&b=1"])

    def test_one_huge_sitemap_cannot_register_everything(self):
        locs = [BASE + f"page?p{i}=1" for i in range(10)]
        routes = {BASE: HOME, BASE + "sitemap.xml": (urlset(*locs), "application/xml")}
        with mock.patch("xssmap.crawler.MAX_SITEMAP_URLS", 3):
            result, _http = crawl(routes)
        self.assertEqual(len(result.param_urls), 3)

    def test_html_error_page_is_not_parsed_as_a_sitemap(self):
        routes = {BASE: HOME,
                  BASE + "sitemap.xml": ("<html><body>not here</body></html>", "text/html")}
        result, _http = crawl(routes)
        self.assertEqual(result.param_urls, [])


class FastPresetTest(unittest.TestCase):
    """--fast is a preset, so an explicit flag must always win over it."""

    def _resolve(self, argv):
        parser = cli.build_parser()
        args = parser.parse_args(argv)
        cli.finalize_args(args)
        if "--fast" in argv:
            cli.apply_preset(args, cli.explicit_dests(parser, argv), cli.FAST_DEFAULTS)
        return args

    def test_fast_caps_the_cheap_knobs(self):
        args = self._resolve(["-u", BASE, "--fast"])
        self.assertEqual(args.crawl_depth, 1)
        self.assertEqual(args.max_pages, 60)
        self.assertEqual(args.max_points, 300)
        self.assertTrue(args.no_js)
        self.assertFalse(args.browser)

    def test_explicit_flags_survive_the_preset(self):
        args = self._resolve(["-u", BASE, "--fast", "--depth", "3", "--max-pages", "500"])
        self.assertEqual(args.crawl_depth, 3)
        self.assertEqual(args.max_pages, 500)

    def test_no_fast_leaves_the_defaults_alone(self):
        args = self._resolve(["-u", BASE])
        self.assertEqual(args.crawl_depth, 2)
        self.assertEqual(args.max_pages, 150)


if __name__ == "__main__":
    unittest.main()
