"""Tri-state execution verification.

The rule this module exists to enforce: **"I could not test it" must never be
reported as "it did not work".** A scanner that collapses those two into a
single boolean produces confident false negatives, and the failure is invisible
because a negative result looks exactly like a clean one.

Every verification therefore lands in exactly one of three states:

``confirmed``
    A real engine executed the payload. We have direct evidence: a DOM node the
    payload's own handler created, or an out-of-band callback from the browser.

``not_observed``
    The engine loaded the page, ran the payload's document, and the effect did
    not appear. This is a real negative *for this payload in this browser*.

``not_tested``
    We never got a valid observation. No browser, a DevTools failure, a
    navigation that never committed, a payload that was not reflected. This is
    an absence of evidence and must be surfaced as such, never as reassurance.

Internal errors always map to ``not_tested``. That is deliberate: a bug in the
verifier must degrade into "unknown", because "unknown" is honest and
"not vulnerable" is a claim we have not earned.
"""
from __future__ import annotations

from dataclasses import dataclass, field

CONFIRMED = "confirmed"
NOT_OBSERVED = "not_observed"
NOT_TESTED = "not_tested"

STATES = (CONFIRMED, NOT_OBSERVED, NOT_TESTED)


@dataclass
class Verification:
    """The outcome of one attempt to prove execution."""

    state: str = NOT_TESTED
    reason: str = ""
    detail: dict = field(default_factory=dict)

    # -- constructors --------------------------------------------------
    @classmethod
    def confirmed(cls, reason: str = "", **detail) -> Verification:
        return cls(CONFIRMED, reason, detail)

    @classmethod
    def not_observed(cls, reason: str = "", **detail) -> Verification:
        return cls(NOT_OBSERVED, reason, detail)

    @classmethod
    def not_tested(cls, reason: str = "", **detail) -> Verification:
        return cls(NOT_TESTED, reason, detail)

    @classmethod
    def from_exception(cls, exc: BaseException, context: str = "") -> Verification:
        """Any internal failure is *unknown*, never a negative."""
        where = f"{context}: " if context else ""
        return cls(NOT_TESTED, f"{where}{type(exc).__name__}: {exc}"[:240])

    # -- queries -------------------------------------------------------
    @property
    def is_confirmed(self) -> bool:
        return self.state == CONFIRMED

    @property
    def was_tested(self) -> bool:
        return self.state != NOT_TESTED

    def merge(self, other: Verification) -> Verification:
        """Prefer the strongest evidence; keep the weaker-only-if-untested case."""
        if self.is_confirmed:
            return self
        if other.is_confirmed:
            return other
        if self.was_tested and not other.was_tested:
            return self
        if other.was_tested and not self.was_tested:
            return other
        if self.reason and other.reason:
            return Verification(other.state, f"{self.reason}; {other.reason}")
        return self if self.reason else other

    def describe(self) -> str:
        label = {
            CONFIRMED: "confirmed: payload executed",
            NOT_OBSERVED: "not observed: page ran, payload produced no effect",
            NOT_TESTED: "NOT TESTED: no valid observation of this payload",
        }[self.state]
        return f"{label} ({self.reason})" if self.reason else label

    def as_dict(self) -> dict:
        return {"state": self.state, "reason": self.reason}


class VerifyError(RuntimeError):
    """Raised when the verifier cannot produce a trustworthy observation.

    Distinct from ``DevToolsError``: this is "the machinery broke", which maps
    to ``not_tested``, not to a negative result.
    """


def summarize(states: list[str]) -> dict:
    """Count states for the run summary, so untested work is visible."""
    out = {state: 0 for state in STATES}
    for state in states:
        out[state if state in out else NOT_TESTED] += 1
    return out
