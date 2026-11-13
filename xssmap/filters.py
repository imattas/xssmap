"""Input-filter fingerprinting and payload mutation.

Two problems this module solves:

1. *Wasted requests.* A scanner that fires 40 markup payloads at a parameter whose
   ``<`` is stripped is just noise. One probe reveals which characters and which
   keywords survive, so only feasible payloads are sent.

2. *Filters that are almost right.* Real applications strip or encode one character,
   lowercase one keyword, or block the literal string ``onload``. A small set of
   principled mutations (attribute case, alternative separators, entity encoding,
   nested tags, null bytes, double encoding) gets past those without hand-written
   per-site payloads.

Everything here is derived from the response, not assumed: an unknown profile
degrades to "send everything".
"""
from __future__ import annotations

import html
import random
import re
import urllib.parse
from dataclasses import dataclass, field

# Characters whose survival decides which markup is possible.
SPECIAL_CHARS = '<>"\'`/\\=;:(){}[]&%#+@!$*,.-_|~^ \t\n'

# Keywords that must survive literally for the payload structure to work.
STRUCT_KEYWORDS = (
    "script", "svg", "img", "iframe", "details", "video", "body", "input", "select",
    "marquee", "template", "math", "mtext", "mglyph", "animate", "source", "style",
    "onload", "onerror", "onfocus", "onmouseover", "ontoggle", "onbegin", "onpageshow",
    "onstart", "oninput", "javascript", "srcdoc", "autofocus", "href", "src",
)

# Identifiers that only the JS expression needs (alternatives exist).
JS_KEYWORDS = ("alert", "prompt", "confirm", "eval", "document", "window", "fetch", "top", "self")

# Characters that appear in entity-encoded output.
_ENTITY_FORMS = {
    c: (html.escape(c, quote=True), f"&#{ord(c)};", f"&#x{ord(c):x};")
    for c in '<>"\'`&/='
}


@dataclass
class FilterProfile:
    """What survives one request parameter, measured rather than guessed."""

    allowed: set[str] = field(default_factory=set)
    encoded: dict[str, str] = field(default_factory=dict)   # char -> observed form
    stripped: set[str] = field(default_factory=set)
    allowed_keywords: set[str] = field(default_factory=set)
    blocked_keywords: set[str] = field(default_factory=set)
    known: bool = False
    sample: str = ""

    # -- queries -----------------------------------------------------
    def allows(self, chars) -> bool:
        if not self.known:
            return True
        return all(c in self.allowed for c in chars)

    def keywords_ok(self, words) -> bool:
        if not self.known:
            return True
        return all(w.lower() in self.allowed_keywords for w in words)

    def feasible(self, payload: str) -> bool:
        """Structural feasibility: needed characters and tag/attribute keywords."""
        if not self.known or not payload:
            return True
        chars = {c for c in payload if c in SPECIAL_CHARS_SET}
        if not self.allows(chars):
            return False
        lowered = payload.lower()
        needed = [k for k in STRUCT_KEYWORDS if k in lowered]
        return self.keywords_ok(needed)

    # -- reporting ---------------------------------------------------
    def summary(self) -> str:
        if not self.known:
            return "filter: unknown (no reflection of probe)"
        bits = []
        if not self.stripped and not self.encoded:
            bits.append("no character filtering")
        if self.encoded:
            groups: dict[str, list[str]] = {}
            for c, form in self.encoded.items():
                groups.setdefault(_form_kind(form), []).append(c)
            for kind, chars in groups.items():
                bits.append(f"{kind}: {''.join(sorted(chars))}")
        if self.stripped:
            bits.append(f"stripped: {''.join(sorted(self.stripped))}")
        if self.blocked_keywords:
            bits.append(f"blocked keywords: {', '.join(sorted(self.blocked_keywords))}")
        return "filter: " + ("; ".join(bits) if bits else "none detected")

    def as_dict(self) -> dict:
        return {
            "known": self.known,
            "allowed": "".join(sorted(self.allowed)),
            "encoded": self.encoded,
            "stripped": "".join(sorted(self.stripped)),
            "blocked_keywords": sorted(self.blocked_keywords),
        }


SPECIAL_CHARS_SET = set(SPECIAL_CHARS)


def _form_kind(form: str) -> str:
    if form.startswith("&") and form.endswith(";"):
        return "html-encoded"
    if form.startswith("%"):
        return "url-encoded"
    if form.startswith("\\"):
        return "backslash-escaped"
    return "transformed"


def build_profile(send, marker: str, log=None) -> FilterProfile:
    """Measure character and keyword survival with two requests.

    ``send(value) -> Response`` injects *value* at the same parameter.
    """
    profile = FilterProfile()
    try:
        char_probe = marker + "~" + "".join(SPECIAL_CHARS) + "~" + marker
        resp = send(char_probe)
        body = resp.text
        first, last = body.find(marker), body.rfind(marker)
        if first == -1 or last <= first:
            return profile
        segment = body[first + len(marker):last]
        profile.sample = segment[:200]
        profile.known = True
        for ch in SPECIAL_CHARS:
            if ch in segment:
                profile.allowed.add(ch)
                continue
            forms = _ENTITY_FORMS.get(ch, ())
            hit = next((f for f in forms if f in segment), "")
            if not hit:
                quoted = urllib.parse.quote(ch, safe="")
                if quoted != ch and quoted in segment:
                    hit = quoted
            if hit:
                profile.encoded[ch] = hit
            else:
                profile.stripped.add(ch)
    except Exception as exc:
        if log:
            log.debug(f"    filter probe failed: {exc}")
        return profile

    try:
        kw_probe = marker + "|" + "|".join(STRUCT_KEYWORDS + JS_KEYWORDS) + "|" + marker
        resp = send(kw_probe)
        body = resp.text
        first, last = body.find(marker), body.rfind(marker)
        if first != -1 and last > first:
            segment = body[first + len(marker):last].lower()
            for word in STRUCT_KEYWORDS + JS_KEYWORDS:
                if word in segment:
                    profile.allowed_keywords.add(word)
                else:
                    profile.blocked_keywords.add(word)
    except Exception:
        pass
    return profile


# ---------------------------------------------------------------------------
# Mutation engine
# ---------------------------------------------------------------------------

_TAG_RE = re.compile(r"</?[a-zA-Z][\w:-]*")
_ATTR_RE = re.compile(r"(?<![\w-])[a-zA-Z][\w-]*(?=\s*=)")


def _swap_case(text: str, mode: str = "random") -> str:
    out = []
    for ch in text:
        if mode == "upper":
            out.append(ch.upper())
        elif mode == "lower":
            out.append(ch.lower())
        else:
            out.append(ch.upper() if random.random() < 0.5 else ch.lower())
    return "".join(out)


def _case(payload: str) -> str | None:
    """Randomise the case of tag and attribute names (`<sVg oNlOaD=`)."""
    mutated = _TAG_RE.sub(lambda m: _swap_case(m.group(0)), payload)
    mutated = _ATTR_RE.sub(lambda m: _swap_case(m.group(0)), mutated)
    return mutated if mutated != payload else None


def _space_slash(payload: str) -> str | None:
    """Swap the separator between tag name and first attribute."""
    if re.search(r"<[a-zA-Z][\w:-]*\s+[a-zA-Z]", payload):
        return re.sub(r"(<[a-zA-Z][\w:-]*)\s+", r"\1/", payload, count=1)
    if re.search(r"<[a-zA-Z][\w:-]*/[a-zA-Z]", payload):
        return re.sub(r"(<[a-zA-Z][\w:-]*)/", r"\1 ", payload, count=1)
    return None


def _tab_space(payload: str) -> str | None:
    """Use a tab where filters expect a space inside markup."""
    mutated = re.sub(r"(<[a-zA-Z][\w:-]*)\s+", r"\1\t", payload, count=1)
    return mutated if mutated != payload else None


def _newline_space(payload: str) -> str | None:
    mutated = re.sub(r"(<[a-zA-Z][\w:-]*)\s+", r"\1\n", payload, count=1)
    return mutated if mutated != payload else None


def _js_entity(payload: str) -> str | None:
    """Entity-encode the JS call punctuation (works in HTML attributes and text)."""
    mutated = payload.replace("(", "&#40;").replace(")", "&#41;")
    return mutated if mutated != payload else None


def _nested_tag(payload: str) -> str | None:
    """Tag-splitting for filters that remove a tag once: `<scr<script>ipt>`."""
    m = re.search(r"<(script|svg|img|iframe)([\s>/])", payload, re.I)
    if not m:
        return None
    name = m.group(1)
    inner = f"<{name[0]}{name}{name[1:]}" if len(name) > 1 else f"<{name}"
    mutated = payload[:m.start()] + "<" + name[0] + inner + name[1:] + m.group(2) + payload[m.end():]
    return mutated if mutated != payload else None


def _unclosed(payload: str) -> str | None:
    """Drop the final `>`; some filters only neutralise well-formed tags."""
    stripped = payload.rstrip()
    if stripped.endswith(">"):
        return stripped[:-1]
    return None


def _null_byte(payload: str) -> str | None:
    """Insert a NUL inside the tag name for filters that stop comparing at NUL."""
    m = re.search(r"<([a-zA-Z]{2,})", payload)
    if not m:
        return None
    name = m.group(1)
    return payload[:m.start(1)] + name[0] + "\x00" + name[1:] + payload[m.end(1):]


def _double_encode(payload: str) -> str | None:
    """Percent-encode markup so a decode-once filter still yields markup."""
    if "<" not in payload and '"' not in payload:
        return None
    return re.sub(r"[<>\"']", lambda m: urllib.parse.quote(m.group(0)), payload)


def _comment_pad(payload: str) -> str | None:
    """Prefix with a comment to survive filters that consume the first tag."""
    if payload.startswith("<!"):
        return None
    return "<!--x-->" + payload


def _event_swap(payload: str) -> str | None:
    """Swap a blocked event handler for a different auto-firing one."""
    swaps = [
        ("onload", "onerror"), ("onerror", "onload"), ("onload", "ontoggle"),
        ("ontoggle", "onload"), ("onfocus", "onpointerover"),
    ]
    for old, new in swaps:
        if old in payload.lower():
            mutated = re.sub(old, new, payload, count=1, flags=re.I)
            return mutated if mutated != payload else None
    return None


MUTATORS = [
    ("case", _case),
    ("space-slash", _space_slash),
    ("tab-space", _tab_space),
    ("newline-space", _newline_space),
    ("js-entity", _js_entity),
    ("nested-tag", _nested_tag),
    ("unclosed", _unclosed),
    ("null-byte", _null_byte),
    ("double-encode", _double_encode),
    ("comment-pad", _comment_pad),
    ("event-swap", _event_swap),
]


def mutate(payload: str, limit: int = 12, seed: int | None = None) -> list[tuple[str, str]]:
    """Return deduplicated (mutator_name, mutated_payload) variants."""
    if limit <= 0 or not payload:
        return []
    rng_state = random.getstate()
    if seed is not None:
        random.seed(seed)
    out: list[tuple[str, str]] = []
    seen = {payload}
    try:
        for name, fn in MUTATORS:
            if len(out) >= limit:
                break
            try:
                mutated = fn(payload)
            except Exception:
                continue
            if not mutated or mutated in seen:
                continue
            seen.add(mutated)
            out.append((name, mutated))
    finally:
        if seed is not None:
            random.setstate(rng_state)
    return out


def missing_chars(payload: str, profile: FilterProfile) -> str:
    """Which required characters the filter destroys (for reporting)."""
    if not profile.known:
        return ""
    return "".join(sorted({c for c in payload if c in SPECIAL_CHARS_SET and c not in profile.allowed}))
