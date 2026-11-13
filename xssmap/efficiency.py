"""How much of a probe actually survives a sink, on XSStrike's scale.

XSStrike never asks the binary question "did my string come back?".  It sends
``st4r7s`` + probe + ``3nd`` and scores the returned window against what it
sent (``core/checker.py``), then gates whole payload families on that number
(``core/generator.py``: verbatim, ``>83`` for a mangled-but-present char, ``90``
for a quote the sink escaped with a backslash).

The distinction matters here for a second, more practical reason.  A parameter
that reflects nothing *verbatim* and a parameter that does not reflect at all
look identical to a scanner that only does substring search, so the old code
gave up silently on the first case -- which is precisely the case a filter
brute forcer exists for.  Scoring the window recovers the sink position even
when the probe came back mangled, and the score says whether building a
payload from the surviving characters is worth the requests.
"""
from __future__ import annotations

import difflib
import re

#: A window identical to the probe.
VERBATIM = 100
#: A quote the sink backslash-escaped; XSStrike scores this 90 on purpose,
#: because ``\'`` is still a usable break-out for the multibyte and JS cases.
ESCAPED = 90
#: Below this the window is not the probe: treat the value as not reflected.
PARTIAL_MIN = 70
#: A fuzzy window has to share at least this many consecutive characters with
#: the probe.  Without it, a page that happens to contain "xs" scores highly
#: against a marker it never received.
MIN_RUN = 5

#: Anchors tried when the probe is mangled.  Six characters is long enough to
#: be specific and short enough to survive the truncation most sinks apply.
_ANCHOR_LEN = 6
_MAX_HITS = 6


def _ratio(a: str, b: str) -> int:
    """Similarity of two short strings as 0-100 (difflib, no dependencies)."""
    if not a or not b:
        return 0
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    if sm.real_quick_ratio() * 100 < PARTIAL_MIN:
        return int(sm.real_quick_ratio() * 100)
    if sm.quick_ratio() * 100 < PARTIAL_MIN:
        return int(sm.quick_ratio() * 100)
    return round(sm.ratio() * 100)


def longest_run(a: str, b: str) -> int:
    """Length of the longest common substring (bounded: both are ~10 chars)."""
    if not a or not b:
        return 0
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    match = sm.find_longest_match(0, len(a), 0, len(b))
    return match.size


class Match:
    """One reflection measurement: where it landed and how intact it is."""

    __slots__ = ("kind", "note", "occurrences", "offset", "score", "window")

    def __init__(self, offset: int = -1, window: str = "", score: int = 0,
                 kind: str = "absent", occurrences: int = 0, note: str = "") -> None:
        self.offset = offset
        self.window = window
        self.score = score
        self.kind = kind
        self.occurrences = occurrences
        self.note = note

    @property
    def reflected(self) -> bool:
        return self.kind != "absent"

    @property
    def verbatim(self) -> bool:
        return self.kind == "verbatim"

    @property
    def executable_score(self) -> bool:
        """Is the window intact enough that a crafted payload could survive?

        A verbatim or backslash-escaped window means the sink is not rewriting
        characters.  A partial window (or one the sink recased) means it is, and
        only the character-level synthesiser has a chance there -- the cached
        payload ladder would just burn requests on strings the sink will mangle.
        """
        return self.kind in ("verbatim", "escaped")

    def describe(self) -> str:
        if not self.reflected:
            return "no reflection of the probe"
        if self.verbatim:
            return f"reflected verbatim x{self.occurrences}"
        head = f"reflected with {self.score}% efficiency ({self.kind})"
        if self.note:
            head += f": {self.note}"
        return head

    def as_dict(self) -> dict:
        return {"offset": self.offset, "score": self.score, "kind": self.kind,
                "occurrences": self.occurrences, "window": self.window[:80],
                "note": self.note}


def measure(body: str, probe: str) -> Match:
    """Score how *probe* appears in *body*.

    Exact hits are cheap and win immediately.  Otherwise the probe's own
    leading and trailing anchors are searched for, and the window that follows
    each hit is compared against the probe, which is how a mangled reflection
    is recognised as a reflection at all.
    """
    if not body or not probe:
        return Match()
    hits = body.count(probe)
    if hits:
        return Match(offset=body.find(probe), window=probe, score=VERBATIM,
                     kind="verbatim", occurrences=hits)

    # A sink that recases its output is still a sink.  Detecting it here costs
    # no request and keeps the point out of the "not reflected" bucket, which
    # is where it used to disappear.  The probe itself is lowercase (markers are
    # hex), so the comparison has to ignore the body's case -- and it has to run
    # through ``re`` so the offset stays valid when case folding changes length.
    caseless = re.compile(re.escape(probe), re.IGNORECASE)
    hit = caseless.search(body)
    if hit is not None:
        return Match(offset=hit.start(), window=body[hit.start():hit.end()], score=99,
                     kind="case",
                     occurrences=sum(1 for _ in caseless.finditer(body)),
                     note="the sink changes the case of the value")

    anchors = []
    for anchor in (probe[:_ANCHOR_LEN], probe[-_ANCHOR_LEN:], probe[2:2 + _ANCHOR_LEN]):
        if len(anchor) >= 4 and anchor not in anchors:
            anchors.append(anchor)

    best = Match()
    for anchor in anchors:
        start = 0
        seen = 0
        while seen < _MAX_HITS:
            idx = body.find(anchor, start)
            if idx == -1:
                break
            start = idx + 1
            seen += 1
            window = body[idx:idx + len(probe) + 4]
            score = _ratio(probe, window[:len(probe)])
            # A window that starts at a trailing anchor also has to be scored
            # as the tail of the probe, not its head.
            tail = body[max(0, idx - (len(probe) - len(anchor))):idx + len(anchor)]
            score = max(score, _ratio(probe, tail))
            if score < PARTIAL_MIN or score <= best.score:
                continue
            if longest_run(probe, window) < MIN_RUN and longest_run(probe, tail) < MIN_RUN:
                continue
            kind = "escaped" if score >= ESCAPED else "partial"
            note = ""
            if len(window.strip()) < len(probe):
                note = "value looks truncated"
            elif score < VERBATIM:
                note = "characters were rewritten or removed"
            best = Match(offset=idx, window=window[:len(probe) + 4], score=score,
                         kind=kind, occurrences=body.count(anchor), note=note)

    if best.reflected:
        return best
    # Truncation that cuts before any anchor: the head of the probe is present
    # but too short to score.  Worth reporting as a lead, never as a finding.
    head = probe[:max(4, len(probe) // 2)]
    if len(head) >= 4 and head in body:
        return Match(offset=body.find(head), window=head, score=50, kind="partial",
                     occurrences=body.count(head),
                     note=f"only the first {len(head)} characters survive")
    return Match()


def summarize(matches: dict[str, Match]) -> list[str]:
    """Report lines for per-character efficiency, blocked ones included."""
    if not matches:
        return []
    blocked = [ch for ch, m in matches.items() if not m.reflected]
    weak = [f"{ch}={m.score}" for ch, m in matches.items()
            if m.reflected and not m.verbatim]
    lines = []
    if blocked:
        lines.append("characters not reflected: " + " ".join(sorted(blocked)))
    if weak:
        lines.append("characters reflected with reduced efficiency: " + ", ".join(weak))
    return lines
