"""Unit tests for the multibyte charset bypass model.

Run:  python tests/test_charset.py
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssmap import charset
from xssmap.scanner import byte_repr, charset_js, hex_window

GBK = charset.family_for("gbk")
BIG5 = charset.family_for("big5")
SJIS = charset.family_for("shift_jis")
UTF8 = charset.Family("UTF-8", "utf-8", b"\xbf", (), "not a multibyte family")

JS = "document.body.appendChild(document.createElement(`b`)).id=`xmmabcx`"


def lab_escape(raw: bytes) -> bytes:
    """The escaping the lab app (and any addslashes-style code) performs."""
    return (raw.replace(b"\\", b"\\\\")
               .replace(b"'", b"\\'")
               .replace(b'"', b'\\"'))


class TestFamilies(unittest.TestCase):
    def test_lead_byte_consumes_the_escape(self):
        for family in (GBK, BIG5, SJIS):
            with self.subTest(family=family.name):
                self.assertTrue(charset.pair_is_one_character(family, family.lead))

    def test_same_bytes_are_not_one_character_in_utf8(self):
        self.assertFalse(charset.pair_is_one_character(UTF8, UTF8.lead))

    def test_trail_byte_must_be_a_backslash(self):
        self.assertFalse(charset.pair_is_one_character(GBK, GBK.lead, b";"))

    def test_lead_byte_is_a_multibyte_lead_in_its_own_encoding(self):
        for family in charset.FAMILIES:
            with self.subTest(family=family.name):
                raw = family.lead + b"\x40"
                self.assertEqual(len(raw.decode(family.codec)), 1)

    def test_aliases(self):
        cases = {
            "gbk": "GBK", "GB2312": "GBK", "gb18030": "GBK", "cp936": "GBK",
            "euc-cn": "GBK", "x-gbk": "GBK",
            "big5": "Big5", "BIG5-HKSCS": "Big5", "cp950": "Big5",
            "shift_jis": "Shift_JIS", "sjis": "Shift_JIS", "windows-31j": "Shift_JIS",
            "cp932": "Shift_JIS", "x-sjis": "Shift_JIS",
        }
        for alias, name in cases.items():
            with self.subTest(alias=alias):
                family = charset.family_for(alias)
                self.assertIsNotNone(family)
                self.assertEqual(family.name, name)

    def test_single_byte_charsets_are_not_a_family(self):
        for label in ("utf-8", "utf8", "iso-8859-1", "us-ascii", "", None, "  "):
            with self.subTest(label=label):
                self.assertIsNone(charset.family_for(label))

    def test_quoted_and_spaced_labels(self):
        self.assertEqual(charset.family_for(' "GBK" ').name, "GBK")


class TestDetect(unittest.TestCase):
    def test_header_wins(self):
        family = charset.detect("text/html; charset=gbk")
        self.assertEqual(family.name, "GBK")

    def test_header_without_charset_falls_back_to_meta(self):
        body = b'<!doctype html><html><head><meta charset="big5"></head></html>'
        self.assertEqual(charset.detect("text/html", body).name, "Big5")

    def test_meta_with_single_quotes_and_spacing(self):
        body = b"<meta http-equiv='Content-Type' content=\"text/html; charset = Shift_JIS\">"
        self.assertEqual(charset.detect(None, body).name, "Shift_JIS")

    def test_utf8_page_is_not_a_family(self):
        body = b'<html><head><meta charset="utf-8"></head></html>'
        self.assertIsNone(charset.detect("text/html; charset=utf-8", body))

    def test_meta_beyond_the_sniff_window_is_ignored(self):
        body = b"<!--" + b"x" * 5000 + b'--><meta charset="gbk">'
        self.assertIsNone(charset.detect("text/html", body))

    def test_no_declaration(self):
        self.assertIsNone(charset.detect("text/html", b"<html></html>"))
        self.assertIsNone(charset.detect(None, b""))


class TestProbe(unittest.TestCase):
    def test_probe_shape(self):
        payload = charset.probe_bytes(GBK, JS)
        self.assertTrue(payload.startswith(GBK.lead))
        self.assertIn(GBK.lead + b"';", payload)
        self.assertTrue(payload.endswith(b"//"))
        self.assertIn(JS.encode("ascii"), payload)

    def test_probe_keeps_both_quote_kinds_out_of_the_js(self):
        for family in charset.FAMILIES:
            payload = charset.probe_bytes(family, charset_js("abc123"))
            tail = payload[len(family.lead) + 2:]
            self.assertNotIn(b"'", tail)
            self.assertNotIn(b'"', tail)

    def test_bypass_detected_after_escaping(self):
        body = b"<script>var q = '" + lab_escape(charset.probe_bytes(GBK, JS)) + b"';</script>"
        self.assertTrue(charset.bypass_in_body(body, GBK, b"document."))

    def test_double_escaping_defeats_the_bypass(self):
        twice = lab_escape(lab_escape(charset.probe_bytes(GBK, JS)))
        body = b"<script>var q = '" + twice + b"';</script>"
        self.assertFalse(charset.bypass_in_body(body, GBK, b"document."))

    def test_utf8_decoding_is_not_a_bypass(self):
        body = b"<script>var q = '" + lab_escape(charset.probe_bytes(GBK, JS)) + b"';</script>"
        # The bytes look identical, but 0xbf 0x5c is not one character in utf-8.
        self.assertFalse(charset.bypass_in_body(body, UTF8, b"document."))

    def test_quote_stripping_defeats_the_bypass(self):
        body = b"<script>var q = '" + charset.probe_bytes(GBK, JS).replace(b"'", b"") + b"';</script>"
        self.assertFalse(charset.bypass_in_body(body, GBK, b"document."))

    def test_code_must_follow_the_bare_quote(self):
        stripped = charset.probe_bytes(GBK, "").replace(JS.encode(), b"")
        body = b"<script>var q = '" + lab_escape(stripped) + b"';</script>"
        self.assertFalse(charset.bypass_in_body(body, GBK, b"document."))

    def test_empty_body(self):
        self.assertFalse(charset.bypass_in_body(b"", GBK))

    def test_escape_observed(self):
        self.assertTrue(charset.escape_observed(b"q = 'a\\'b'"))
        self.assertTrue(charset.escape_observed(b'q = \\"x\\"', b'"'))
        self.assertFalse(charset.escape_observed(b"q = 'plain'"))
        self.assertFalse(charset.escape_observed(b""))


class TestRendering(unittest.TestCase):
    def test_byte_repr_is_unambiguous(self):
        self.assertEqual(byte_repr(GBK.lead + b"';"), "\\xbf';")
        self.assertEqual(byte_repr(b"a\\b"), "a\\x5cb")

    def test_charset_js_uses_no_escapable_quotes(self):
        js = charset_js("abc")
        self.assertNotIn("'", js)
        self.assertNotIn('"', js)
        self.assertIn("xmmabcx", js)
        self.assertIn("document.body", js)

    def test_hex_window_shows_the_needle(self):
        body = b"x" * 40 + GBK.lead + b"\\';document.body" + b"y" * 40
        window = hex_window(body, GBK.lead + b"\\';")
        self.assertIn("offset", window)
        self.assertIn("bf 5c 27", window)
        self.assertIn("(pattern not found", hex_window(body, b"\xfe"))

    def test_describe(self):
        self.assertIn("GBK", charset.describe(GBK))
        self.assertIn("0xBF", charset.describe(GBK))


if __name__ == "__main__":
    unittest.main(verbosity=2)
