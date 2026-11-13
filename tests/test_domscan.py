"""Unit tests for DOM flow analysis: which part of the URL a flow reads.

The delivery decides how the browser is driven during confirmation. Get it wrong
and the payload is injected into a URL component the page never reads, so a real
DOM XSS is recorded as an unproven lead. A wrapper such as ``URLSearchParams``
hides the real origin, which is exactly how ``location.hash`` flows were being
mislabelled as query flows.
"""
from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from xssmap.domscan import _delivery_for, analyze_js  # noqa: E402

HASH_ROUTER = """
function render(){
  var params = new URLSearchParams(location.hash.slice(1));
  var term = params.get('q') || '';
  document.getElementById('out').innerHTML = term;
}
window.addEventListener('hashchange', render);
render();
"""

QUERY_ROUTER = """
var q = new URLSearchParams(location.search).get('q');
document.getElementById('out').innerHTML = q;
"""


class DeliveryTests(unittest.TestCase):
    def test_wrapper_does_not_hide_the_fragment(self):
        cands = analyze_js("inline", HASH_ROUTER)
        self.assertTrue(cands, "the hash flow should be collected")
        self.assertEqual(cands[0].delivery, "hash")

    def test_query_wrapper_stays_query(self):
        cands = analyze_js("inline", QUERY_ROUTER)
        self.assertTrue(cands)
        self.assertEqual(cands[0].delivery, "query")

    def test_direct_location_members(self):
        self.assertEqual(_delivery_for("location.hash", "x.innerHTML = location.hash"), "hash")
        self.assertEqual(_delivery_for("location.search", "x.innerHTML = location.search"), "query")

    def test_bracket_access_is_understood(self):
        self.assertEqual(_delivery_for("URLSearchParams", "p = new URLSearchParams(location['hash'])"),
                         "hash")

    def test_table_default_survives_without_a_location_reference(self):
        self.assertEqual(_delivery_for("window.name", "x.innerHTML = window.name"), "window.name")


class SinkTests(unittest.TestCase):
    def test_framework_sinks_are_recognised(self):
        js = ("const {q} = useSearchParams();"
              "return <div dangerouslySetInnerHTML={{__html: q}} />;")
        cands = analyze_js("bundle.js", js)
        self.assertTrue(any(c.sink == "dangerouslySetInnerHTML" for c in cands),
                        [c.sink for c in cands])

    def test_hardened_flow_keeps_its_hardening(self):
        js = ("var q = location.search;"
              "document.getElementById('o').innerHTML = DOMPurify.sanitize(q);")
        cands = analyze_js("inline", js)
        self.assertTrue(cands)
        self.assertTrue(cands[0].hardening, "DOMPurify flow must be marked as hardened")


if __name__ == "__main__":
    unittest.main()
