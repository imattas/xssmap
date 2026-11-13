"""Inline-script collection.

A page routinely splits one flow across several <script> blocks, and a state blob
sits in a non-executable block of its own. The crawler must hand the DOM engine
every executable block of a page, otherwise the flow is never analysed at all.
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssmap.crawler import Crawler, Scope, is_js_script_type
from xssmap.domscan import DomScanner


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
        if url.endswith(("robots.txt", "sitemap.xml")):
            return FakeResponse(url, 404, "", "text/plain")
        return FakeResponse(url, 200, self.pages.get(url, "<html><body>empty</body></html>"))


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


WRITE_PAGE = "http://app.test/save?q=hello"
READ_PAGE = "http://app.test/history"
HYDRATE_PAGE = "http://app.test/results?q=hello"

WRITE_HTML = """<html><body><a href="/history">history</a>
<script>var term = new URLSearchParams(location.search).get('q') || '';</script>
<script>if (term) { localStorage.setItem('saved-search', term); }</script>
</body></html>"""

READ_HTML = """<html><body><div id="out"></div>
<script>var saved = localStorage.getItem('saved-search') || '';</script>
<script>if (saved) { document.getElementById('out').innerHTML = saved; }</script>
</body></html>"""

HYDRATE_HTML = """<html><body><div id="out"></div>
<script id="__INITIAL_STATE__" type="application/json">{"query": "x"}</script>
<script>var boot = JSON.parse(document.getElementById('__INITIAL_STATE__').textContent);</script>
<script>document.getElementById('out').innerHTML = boot.query || '';</script>
</body></html>"""


def _crawl(pages, seed="http://app.test/save?q=hello", max_pages=20):
    crawler = Crawler(FakeHTTP(pages), Scope("http://app.test"), QuietLog(),
                      max_depth=2, max_pages=max_pages, crawl_js=True)
    return crawler.run([seed])


class ScriptTypeTests(unittest.TestCase):
    def test_data_blocks_are_not_scripts(self):
        for value in ("application/json", "application/ld+json", "  TEXT/TEMPLATE "):
            self.assertFalse(is_js_script_type(value), value)

    def test_code_blocks_are_scripts(self):
        for value in ("", "module", "text/javascript", "application/javascript"):
            self.assertTrue(is_js_script_type(value), value)


class InlineCollectionTests(unittest.TestCase):
    def test_every_inline_block_of_a_page_is_kept(self):
        result = _crawl({WRITE_PAGE: WRITE_HTML})
        body = result.js_files[WRITE_PAGE + "#inline"].body
        self.assertIn("location.search", body)          # first block
        self.assertIn("localStorage.setItem", body)     # second block

    def test_data_block_does_not_shadow_the_reader_script(self):
        result = _crawl({HYDRATE_PAGE: HYDRATE_HTML}, seed=HYDRATE_PAGE)
        body = result.js_files[HYDRATE_PAGE + "#inline"].body
        self.assertIn("JSON.parse", body)
        self.assertIn("innerHTML", body)
        self.assertNotIn('{"query"', body)

    def test_store_flow_survives_the_crawl(self):
        """Write page and read page are joined from what the crawler collected."""
        pages = {WRITE_PAGE: WRITE_HTML, READ_PAGE: READ_HTML}
        result = _crawl(pages)
        self.assertIn(READ_PAGE, result.pages)
        resources = [(info.url, info.body, info.pages)
                     for info in result.js_files.values()]
        cands = [c for c in DomScanner(browser=None).collect(resources) if c.store]
        self.assertEqual(len(cands), 1, [c.summary() for c in cands])
        cand = cands[0]
        self.assertEqual(cand.store, "localStorage")
        self.assertEqual(cand.store_key, "saved-search")
        self.assertEqual(cand.write_page, WRITE_PAGE)
        self.assertEqual(cand.page, READ_PAGE)
        self.assertEqual(cand.parameter, "q")
        self.assertTrue(cand.two_step)

    def test_hydration_flow_survives_the_crawl(self):
        result = _crawl({HYDRATE_PAGE: HYDRATE_HTML}, seed=HYDRATE_PAGE)
        resources = [(info.url, info.body, info.pages)
                     for info in result.js_files.values()]
        cands = [c for c in DomScanner(browser=None).collect(resources)
                 if c.source == "__INITIAL_STATE__"]
        self.assertEqual(len(cands), 1, [c.summary() for c in cands])
        self.assertEqual(cands[0].delivery, "query")
        self.assertEqual(cands[0].sink, "innerHTML")


if __name__ == "__main__":
    unittest.main()
