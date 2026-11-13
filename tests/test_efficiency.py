"""Tests for reflection efficiency scoring (the XSStrike ``fuzz.partial_ratio`` idea).

The scanner has to tell three situations apart:

* the probe came back exactly as sent          -> verbatim, payloads are viable
* the probe came back changed but traceable    -> escaped/case/partial, a filter
  is rewriting the value and only synthesis has a chance
* the probe is simply not in the body          -> absent, nothing to report

Getting the middle case wrong is what used to make a hostile sink look clean.

Run:  python -m unittest tests.test_efficiency -v
"""
from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from xssmap.efficiency import (  # noqa: E402
    ESCAPED,
    VERBATIM,
    Match,
    longest_run,
    measure,
    summarize,
)

PROBE = "xsab12cdef"


class VerbatimTest(unittest.TestCase):
    def test_exact_echo_scores_100(self):
        match = measure(f"<p>{PROBE}</p>", PROBE)
        self.assertEqual(match.kind, "verbatim")
        self.assertTrue(match.verbatim)
        self.assertEqual(match.score, VERBATIM)
        self.assertEqual(match.offset, 3)
        self.assertEqual(match.window, PROBE)
        self.assertTrue(match.executable_score)

    def test_occurrences_are_counted_for_repeated_echoes(self):
        match = measure(f"<p>{PROBE}</p><p>{PROBE}</p>", PROBE)
        self.assertEqual(match.kind, "verbatim")
        self.assertEqual(match.occurrences, 2)


class MangledEchoTest(unittest.TestCase):
    def test_uppercased_echo_is_detected(self):
        # Markers are lowercase, so this only works if the comparison ignores
        # the body's case: an uppercasing sink is still a sink.
        match = measure("<p>XSAB12CDEF</p>", PROBE)
        self.assertEqual(match.kind, "case", "an uppercased echo must not read as absent")
        self.assertEqual(match.score, 99)
        self.assertEqual(match.offset, 3)
        self.assertTrue(match.reflected)
        self.assertFalse(match.executable_score, "recased output needs a rebuilt payload")
        self.assertIn("case", match.note)

    def test_backslash_escaped_quote_scores_90_and_stays_usable(self):
        probe = "ab'cdefghi"
        match = measure("<p>ab\\'cdefghi</p>", probe)
        self.assertEqual(match.kind, "escaped")
        self.assertGreaterEqual(match.score, ESCAPED)
        self.assertTrue(match.executable_score, "an escaped quote is still a break-out primitive")
        self.assertNotIn("absent", match.kind)

    def test_single_rewritten_character_is_escaped(self):
        # Last character replaced: nine of ten survive, which the scale calls
        # escaped rather than a clean echo.
        match = measure("<p>xsab12cdeX</p>", PROBE)
        self.assertEqual(match.kind, "escaped")
        self.assertGreaterEqual(match.score, ESCAPED)
        self.assertLess(match.score, VERBATIM)

    def test_truncated_echo_reports_the_surviving_head(self):
        match = measure("<p>xsabc</p>", "xsabcdefgh")
        self.assertEqual(match.kind, "partial")
        self.assertEqual(match.score, 50)
        self.assertEqual(match.window, "xsabc")
        self.assertIn("only the first 5 characters survive", match.note)
        self.assertFalse(match.executable_score)

    def test_rewritten_value_without_a_shared_run_is_absent(self):
        # A page that merely contains two letters of the probe must not be
        # promoted to "reflected": that is how a scanner invents findings.
        self.assertEqual(measure("<p>xs</p>", PROBE).kind, "absent")
        self.assertEqual(measure("<p>zzzz</p>", PROBE).kind, "absent")


class AbsentTest(unittest.TestCase):
    def test_missing_probe_is_absent(self):
        match = measure("<p>no echo here</p>", PROBE)
        self.assertEqual(match.kind, "absent")
        self.assertFalse(match.reflected)
        self.assertEqual(match.offset, -1)
        self.assertEqual(match.describe(), "no reflection of the probe")

    def test_empty_inputs_are_absent(self):
        self.assertEqual(measure("", PROBE).kind, "absent")
        self.assertEqual(measure("<p>x</p>", "").kind, "absent")


class MatchFormatTest(unittest.TestCase):
    def test_describe_verbatim_mentions_the_occurrences(self):
        self.assertEqual(measure(f"{PROBE}{PROBE}", PROBE).describe(),
                         "reflected verbatim x2")

    def test_describe_partial_mentions_score_and_note(self):
        text = measure("<p>xsabc</p>", "xsabcdefgh").describe()
        self.assertIn("50% efficiency", text)
        self.assertIn("partial", text)
        self.assertIn("only the first 5 characters survive", text)

    def test_as_dict_is_serialisable_and_bounded(self):
        payload = measure("<p>" + PROBE + "A" * 200 + "</p>", PROBE).as_dict()
        self.assertEqual(payload["kind"], "verbatim")
        self.assertEqual(payload["offset"], 3)
        self.assertEqual(payload["score"], 100)
        self.assertEqual(payload["occurrences"], 1)
        self.assertLessEqual(len(payload["window"]), 80)

    def test_default_match_is_absent(self):
        match = Match()
        self.assertEqual(match.kind, "absent")
        self.assertEqual(match.score, 0)


class SummarizeTest(unittest.TestCase):
    def test_line_lists_blocked_characters_and_weak_ones(self):
        matches = {
            "<": Match(kind="verbatim", score=100, occurrences=1),
            "1": Match(kind="case", score=99, occurrences=1),
            "(": Match(),
        }
        lines = summarize(matches)
        self.assertEqual(len(lines), 2)
        self.assertIn("characters not reflected: (", lines[0])
        self.assertIn("1=99", lines[1])

    def test_verbatim_only_has_nothing_to_report(self):
        self.assertEqual(summarize({"<": Match(kind="verbatim", score=100)}), [])

    def test_empty_input_has_nothing_to_report(self):
        self.assertEqual(summarize({}), [])


class LongestRunTest(unittest.TestCase):
    def test_common_substring_length(self):
        self.assertEqual(longest_run("abcdef", "zzcdefzz"), 4)
        self.assertEqual(longest_run("abcdef", "xyz"), 0)
        self.assertEqual(longest_run("", "abc"), 0)


if __name__ == "__main__":
    unittest.main()
