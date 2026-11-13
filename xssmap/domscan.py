"""DOM-based XSS: static taint flow plus runtime proof.

Server-side reflection scanning cannot see DOM XSS. The dangerous flow lives
entirely in JavaScript: a *source* (``location.search``, ``location.hash``,
``document.referrer``, ``window.name``, storage) reaches a *sink*
(``innerHTML``, ``document.write``, ``eval``, ``location.href`` ...).

What this module does:

1. Parses every JS resource the crawler found (inline blocks and bundles).
2. Builds a light taint graph: variables assigned from a source, then variables
   assigned from those variables (fixpoint, so ``a = location.hash; b = a`` counts).
3. Records each sink that consumes a tainted value, including the parameter name
   when the code reads one (``URLSearchParams(location.search).get('q')``).
4. Notices hardening in the flow (DOMPurify, ``createPolicy``, an escape call)
   so a sanitised flow is reported as a lead rather than as a vulnerability.
5. Verifies the surviving flows in a real browser by driving the page with a
   payload that creates a DOM artifact, and only claims DOM XSS if the artifact
   appears.

Static flow is labelled *inferred* in the report; only the browser step proves it.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field

from . import domstate

# -- sources ---------------------------------------------------------------
SOURCES = {
    "location.search": "query",
    "document.location.search": "query",
    "location.hash": "hash",
    "document.location.hash": "hash",
    "location.href": "url",
    "document.location.href": "url",
    "document.URL": "url",
    "document.documentURI": "url",
    "document.referrer": "referrer",
    "window.name": "window.name",
    "document.cookie": "cookie",
    "localStorage": "storage",
    "sessionStorage": "storage",
    "document.baseURI": "url",
    # Framework router hooks: they expose the same URL state under a name the
    # plain location.* patterns cannot see.
    "useSearchParams": "query",
    "useLocation": "url",
    "useParams": "url",
    "useRoute": "query",
    "$route.query": "query",
    "route.query": "query",
    "URLSearchParams": "query",
    "location.pathname": "url",
}
# Server-rendered state the client re-reads after hydration. The payload does not
# have to be reflected into markup: it only has to land in the blob, and the
# bundle hands it to a sink on the client.
SOURCES.update({name: "query" for name in domstate.HYDRATION_SOURCES})

SOURCE_RX = re.compile(
    r"(?P<src>"
    + "|".join(re.escape(s) for s in sorted(SOURCES, key=len, reverse=True))
    + r")(?![\w$])"
)

# Sources that are a *shape*, not a name: server-rendered JSON handed to the page
# through a data- attribute (`el.dataset.state`, `getAttribute('data-boot')`).
STRUCTURAL_SOURCE_RX = re.compile(
    r"(?P<src>\.dataset(?:\.(?P<one>[A-Za-z_$][\w$]{0,40})"
    r"|\[\s*['\"](?P<two>[^'\"]{1,40})['\"]\s*\])"
    r"|getAttribute\s*\(\s*['\"](?P<attr>data-[^'\"]{1,60})['\"]\s*\))"
)
STRUCTURAL_DELIVERY = "query"

# -- sinks -----------------------------------------------------------------
SINKS = [
    ("innerHTML", re.compile(r"\.innerHTML\s*\+?=")),
    ("outerHTML", re.compile(r"\.outerHTML\s*\+?=")),
    ("insertAdjacentHTML", re.compile(r"\.insertAdjacentHTML\s*\(")),
    ("document.write", re.compile(r"document\.write(?:ln)?\s*\(")),
    ("eval", re.compile(r"(?<![\w$.])eval\s*\(")),
    ("Function", re.compile(r"new\s+Function\s*\(")),
    ("setTimeout-string", re.compile(r"setTimeout\s*\(\s*[^,)]*[a-zA-Z_$][\w$]*\s*[,)]")),
    ("location.assign", re.compile(r"location\.assign\s*\(")),
    ("location.href=", re.compile(r"location\.href\s*=")),
    ("window.open", re.compile(r"window\.open\s*\(")),
    ("jquery-html", re.compile(r"\.html\s*\(")),
    ("jquery-append", re.compile(r"\.(?:append|prepend|after|before|replaceWith|wrap)\s*\(")),
    ("srcdoc", re.compile(r"\.srcdoc\s*=")),
    ("script-src", re.compile(r"createElement\s*\(\s*['\"]script['\"]")),
    # Framework template escape hatches: React, Vue and Angular each have an
    # explicit "this string is HTML" API, and bundles keep their names.
    ("dangerouslySetInnerHTML", re.compile(r"dangerouslySetInnerHTML\s*[:=]")),
    ("v-html", re.compile(r"v-html\s*=")),
    ("bypassSecurityTrustHtml", re.compile(r"\.bypassSecurityTrustHtml\s*\(")),
    ("createContextualFragment", re.compile(r"createContextualFragment\s*\(")),
    ("jquery-parseHTML", re.compile(r"\.parseHTML\s*\(")),
]

HARDENING_RX = re.compile(
    r"(?P<kind>DOMPurify|createPolicy|TrustedTypes|trustedTypes|encodeURIComponent|"
    r"escapeHtml|sanitize\w*|textContent|innerText|createTextNode)",
    re.I,
)

GET_PARAM_RX = re.compile(r"""\.get\s*\(\s*['"]([^'"]{1,60})['"]\s*\)""")
PARAM_RX = re.compile(r"""(?:getParameterByName|getParam|param|query)\s*\(\s*['"]([^'"]{1,60})['"]""")
ASSIGN_RX = re.compile(
    r"(?:^|[;{}\n,(])\s*(?:var|let|const)?\s*([A-Za-z_$][\w$]{0,40})\s*=\s*([^;\n]{0,400})"
)
# $route.query.q / route.query['q'] (Vue Router) and other property reads.
QUERY_PROP_RX = re.compile(r"query\.([A-Za-z_$][\w$]{0,60})")
QUERY_INDEX_RX = re.compile(r"query\[\s*['\"]([^'\"]{1,60})['\"]\s*\]")
# Destructuring router hooks: const [sp] = useSearchParams(), {search} = useLocation()
HOOK_BIND_RX = re.compile(
    r"(?:const|let|var)\s*[\[{]\s*([A-Za-z_$][\w$]{0,40})[^\]}]*[\]}]\s*=\s*"
    r"(useSearchParams|useLocation|useParams|useRoute)\s*\("
)
# Shapes the `var x = expr` pass cannot see: a value parked on an object
# property, appended to an array that is rendered later, or pushed into a React
# hook's state setter. All three are the same flow with a different carrier.
PROP_ASSIGN_RX = re.compile(
    r"([A-Za-z_$][\w$]{0,40})\.([A-Za-z_$][\w$]{0,40})\s*=(?!=)\s*([^;\n]{0,300})"
)
PUSH_RX = re.compile(r"([A-Za-z_$][\w$]{0,40})\.(?:push|unshift)\s*\(\s*([^;\n]{0,200})")
HOOK_STATE_RX = re.compile(
    r"(?:const|let|var)\s*\[\s*([A-Za-z_$][\w$]{0,40})\s*,\s*"
    r"([A-Za-z_$][\w$]{0,40})\s*\]\s*=\s*useState"
)
SETTER_CALL_RX = re.compile(r"([A-Za-z_$][\w$]{0,40})\s*\(\s*([^;\n]{0,240})")
# Carriers that are themselves globals or sinks: treating them as taint stores
# only adds noise, and the sink match already sees the source in the statement.
NON_STORE_OBJECTS = {"window", "document", "location", "console", "JSON", "Math",
                     "Object", "Array", "Number", "String", "Date", "this", "self"}
SINK_PROPERTIES = {"innerHTML", "outerHTML", "srcdoc", "href", "src", "action"}
STATEMENT_SPLIT = re.compile(r"[;\n]")


@dataclass
class DomCandidate:
    resource: str
    sink: str
    source: str
    parameter: str
    delivery: str            # query | hash | url | referrer | window.name | cookie | storage
    taint_chain: list[str] = field(default_factory=list)
    sink_snippet: str = ""
    flow_snippet: str = ""
    hardening: str = ""
    line: int = 0
    page: str = ""               # page that loads the code (verification host)
    confidence: str = "medium"   # medium until the browser proves it
    # Cross-resource flows: the value was parked in a store and read later.
    store: str = ""              # localStorage | sessionStorage | state | dispatch
    store_key: str = ""
    write_page: str = ""         # page that performs the store write
    write_line: int = 0
    two_step: bool = False       # verification must drive the write step first
    param_guesses: list[str] = field(default_factory=list)

    def key(self) -> str:
        return f"{self.resource}|{self.sink}|{self.parameter}|{self.delivery}"

    def summary(self) -> str:
        chain = " -> ".join(self.taint_chain) if self.taint_chain else self.source
        if self.store:
            hop = f"{self.store}.{self.store_key}"
            if not chain.endswith(hop):
                chain = f"{chain} -> {hop}"
        return f"{chain} reaches {self.sink}()"


def _line_of(body: str, offset: int) -> int:
    return body.count("\n", 0, offset) + 1


def _statement_at(body: str, offset: int, radius: int = 260) -> str:
    """Grab a readable statement window around an offset (works on minified code).

    Some callers hand over the start of a match whose pattern begins with a
    delimiter (``ASSIGN_RX`` matches ``{var x =``), so an offset sitting *on* a
    ``;``/newline would otherwise return the previous statement -- which silently
    attached the wrong origin (``location.hash`` became ``query``) to a flow.
    """
    while offset < len(body) and body[offset] in ";\n":
        offset += 1
    starts = [m.end() for m in STATEMENT_SPLIT.finditer(body, 0, offset)]
    start = starts[-1] if starts else max(0, offset - radius)
    end_match = STATEMENT_SPLIT.search(body, offset)
    end = end_match.start() if end_match else min(len(body), offset + radius)
    snippet = body[start:end].strip()
    return snippet[:400]


# Wrappers expose URL state but hide which part of the URL it came from.
WRAPPER_SOURCES = {"URLSearchParams", "useSearchParams", "useRoute",
                   "useLocation", "useParams"}


def _struct_name(match: re.Match[str]) -> str:
    groups = match.groupdict()
    name = groups.get("src") or ""
    if "dataset" in name:
        return "dataset"
    if groups.get("attr") or name.startswith("getAttribute"):
        return "data-attribute"
    return name


def find_source(text: str) -> str:
    """Name of the request-derived source in *text*, or ''.

    The literal table covers named APIs; ``STRUCTURAL_SOURCE_RX`` covers the
    shape-only cases (``.dataset.state``), where the element name is the store.
    Among several hits the concrete origin wins over the wrapper around it:
    ``new URLSearchParams(location.search)`` reports ``location.search``, which is
    what telling query from fragment delivery depends on.
    """
    hits = [(m.start(), m.group("src")) for m in SOURCE_RX.finditer(text)]
    struct = STRUCTURAL_SOURCE_RX.search(text)
    if struct:
        hits.append((struct.start(), _struct_name(struct)))
    if not hits:
        return ""
    direct = [hit for hit in hits if hit[1] not in WRAPPER_SOURCES]
    hits = direct or hits
    hits.sort(key=lambda hit: hit[0])
    return hits[0][1]


def _rhs_source(rhs: str, taint: dict) -> tuple[str, str] | None:
    """(source, delivery) for a right-hand side, following already-tainted names."""
    source = find_source(rhs)
    if source:
        return source, _delivery_for(source, rhs)
    for other, (other_source, delivery, _line) in taint.items():
        if re.search(r"(?<![\w$.])" + re.escape(other) + r"(?![\w$])", rhs):
            return other_source, delivery
    return None


def _build_taint(body: str) -> dict[str, tuple[str, str, int]]:
    """variable -> (source, delivery, line), propagated through assignments."""
    taint: dict[str, tuple[str, str, int]] = {}

    # 0. destructured router hooks do not use the `x = expr` shape, so bind
    #    them before the generic assignment pass.
    for m in HOOK_BIND_RX.finditer(body):
        var, hook = m.group(1), m.group(2)
        source = "$route.query" if hook == "useRoute" else hook
        taint.setdefault(var, (source, SOURCES.get(source, "query"),
                               _line_of(body, m.start())))

    # 0b. carriers other than a plain variable: `holder.value = <src>`,
    #     `items.push(<src>)`, and a React hook's `setDraft(<src>)` (the value
    #     is read back as `draft`, so the state variable is what gets tainted).
    hooks = {setter: state for state, setter in HOOK_STATE_RX.findall(body)}

    # 1. propagate taint through assignments (three passes handle short chains)
    for _ in range(3):
        for m in PROP_ASSIGN_RX.finditer(body):
            obj, prop, rhs = m.group(1), m.group(2), m.group(3)
            carrier = f"{obj}.{prop}"
            if obj in NON_STORE_OBJECTS or prop in SINK_PROPERTIES or carrier in taint:
                continue
            found = _rhs_source(rhs, taint)
            if found:
                taint[carrier] = (found[0], found[1], _line_of(body, m.start()))
        for m in PUSH_RX.finditer(body):
            array, rhs = m.group(1), m.group(2)
            if array in taint:
                continue
            found = _rhs_source(rhs, taint)
            if found:
                taint[array] = (found[0], found[1], _line_of(body, m.start()))
        for m in SETTER_CALL_RX.finditer(body):
            setter, rhs = m.group(1), m.group(2)
            state = hooks.get(setter)
            if not state or state in taint:
                continue
            found = _rhs_source(rhs, taint)
            if found:
                taint[state] = (found[0], found[1], _line_of(body, m.start()))
        for m in ASSIGN_RX.finditer(body):
            var, rhs = m.group(1), m.group(2)
            if var in taint:
                continue
            source = find_source(rhs)
            if source:
                # Delivery is decided at the assignment, where the real origin is
                # visible: `new URLSearchParams(location.hash.slice(1))` reads the
                # fragment even though the wrapper alone says "query".
                origin = _statement_at(body, m.start(1)) or rhs
                taint[var] = (source, _delivery_for(source, origin),
                              _line_of(body, m.start()))
                continue
            for other, (other_source, delivery, _line) in list(taint.items()):
                if re.search(r"(?<![\w$.])" + re.escape(other) + r"(?![\w$])", rhs):
                    taint[var] = (other_source, delivery, _line_of(body, m.start()))
                    break
    return taint


def analyze_js(resource: str, body: str, max_candidates: int = 40,
               taint: dict | None = None) -> list[DomCandidate]:
    """Return source→sink flows found in one JavaScript resource."""
    if not body:
        return []
    if taint is None:
        taint = _build_taint(body)
    candidates: list[DomCandidate] = []
    seen: set[str] = set()

    # 2. find sinks whose statement consumes tainted data or a source directly
    for sink_name, sink_rx in SINKS:
        for m in sink_rx.finditer(body):
            if len(candidates) >= max_candidates:
                break
            stmt = _statement_at(body, m.start())
            if not stmt:
                continue
            direct = find_source(stmt)
            tainted_vars = [v for v in taint
                            if re.search(r"(?<![\w$.])" + re.escape(v) + r"(?![\w$])", stmt)]
            if not direct and not tainted_vars:
                continue
            if direct:
                source = direct
                delivery = _delivery_for(source, stmt)
                chain = [source]
            else:
                # prefer the variable closest to the sink call
                tainted_vars.sort(key=lambda v: stmt.rfind(v), reverse=True)
                var = tainted_vars[0]
                source, delivery, _line = taint[var]
                delivery = _delivery_for(source, stmt, delivery)
                chain = [source, var] + [v for v in tainted_vars[1:3]]
            param = _param_for(body, m.start(), stmt)
            if source in domstate.HYDRATION_SOURCES or source in ("dataset", "data-attribute"):
                # Server-rendered state: the parameter is the server's choice, not
                # something the bundle names, so verification has to guess it.
                param = ""
            hardening = ""
            hm = HARDENING_RX.search(stmt)
            if hm:
                hardening = hm.group("kind")
            harden_par = _hardening_before(body, m.start(), source)
            key = f"{sink_name}|{param}|{delivery}|{source}"
            if key in seen:
                continue
            seen.add(key)
            candidates.append(DomCandidate(
                resource=resource,
                sink=sink_name,
                source=source,
                parameter=param,
                delivery=delivery,
                taint_chain=chain,
                sink_snippet=stmt,
                flow_snippet=_flow_snippet(body, source, taint, sink_name),
                hardening=hardening or harden_par,
                line=_line_of(body, m.start()),
            ))
    return candidates


def _delivery_for(source: str, stmt: str, default: str | None = None) -> str:
    """Which part of the URL the flow actually reads.

    A wrapper hides the real origin: ``new URLSearchParams(location.hash.slice(1))``
    reads the fragment, not the query string, and ``URLSearchParams`` alone is
    mapped to ``query``. Left that way the browser is driven with ``?q=payload``
    on a page that only ever reads ``#q=payload``, the payload never reaches the
    sink, and a real DOM XSS is reported as an unproven lead. An explicit
    ``location.<member>`` in the same statement therefore outranks the table.
    """
    base = default or SOURCES.get(source, "url")
    if "location" in stmt:
        if re.search(r"location(?:\.|\[['\"])hash", stmt):
            return "hash"
        if re.search(r"location(?:\.|\[['\"])search", stmt):
            return "query"
    return base


def _param_for(body: str, sink_offset: int, stmt: str) -> str:
    for rx in (GET_PARAM_RX, PARAM_RX, QUERY_INDEX_RX, QUERY_PROP_RX):
        m = rx.search(stmt)
        if m:
            return m.group(1)
    # the parameter is often read a few statements earlier
    window_start = max(0, sink_offset - 900)
    for m in GET_PARAM_RX.finditer(body, window_start, sink_offset):
        return m.group(1)
    return "q"


def _hardening_before(body: str, sink_offset: int, source: str) -> str:
    window_start = max(0, sink_offset - 1200)
    window = body[window_start:sink_offset]
    if re.search(r"createPolicy\s*\(", window) or "trustedTypes" in window:
        return "Trusted Types policy"
    if re.search(r"DOMPurify\.sanitize|\.sanitize\s*\(", window):
        return "sanitizer"
    if re.search(r"[.\s]textContent\s*=", window) and "innerHTML" not in window[-200:]:
        return "textContent (safe sink)"
    return ""


def _flow_snippet(body: str, source: str, taint: dict, sink: str) -> str:
    """Show the assignment that introduced the source, for the report."""
    m = SOURCE_RX.search(body)
    if not m:
        return ""
    line = _line_of(body, m.start())
    stmt = _statement_at(body, m.start(), radius=200)
    return f"line {line}: {stmt[:300]}"


def is_hardened(candidate: DomCandidate) -> bool:
    """A flow through an escaping/sanitising API is not automatically exploitable."""
    if not candidate.hardening:
        return False
    if candidate.hardening in ("textContent", "innerText", "createTextNode"):
        return True
    # encodeURIComponent on a URL sink is still exploitable in some cases, so it
    # only hardens when the sink is not markup-based
    return candidate.hardening.lower() in (
        "dompurify", "sanitizer", "trusted types policy", "escapehtml",
    )


# ---------------------------------------------------------------------------
# Delivery
# ---------------------------------------------------------------------------

def build_test_url(base: str, candidate: DomCandidate, payload: str,
                   param: str | None = None) -> str | None:
    """Place the payload where the candidate's source actually reads from."""
    parts = urllib.parse.urlsplit(base)
    encoded = urllib.parse.quote(payload, safe="")
    param = param or candidate.parameter or "q"
    if candidate.delivery in ("query", "url"):
        pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        pairs = [(k, v) for k, v in pairs if k != param]
        pairs.append((param, payload))
        query = urllib.parse.urlencode(pairs, quote_via=urllib.parse.quote)
        return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))
    if candidate.delivery == "hash":
        fragment = f"{param}={encoded}"
        return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, fragment))
    if candidate.delivery == "window.name":
        return None  # needs a scripted setter; handled by the browser driver
    if candidate.delivery in ("referrer", "cookie", "storage"):
        return None  # requires request-level injection, handled elsewhere
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path,
                                    parts.query, f"{param}={encoded}"))


def build_window_name_payload(payload: str) -> str:
    return payload


DOM_JS_TEMPLATE = (
    "document.body.appendChild(document.createElement('b')).id='{}'"
)


def dom_payloads(marker: str) -> list[tuple[str, str]]:
    """Markup vectors that execute the moment the node is inserted.

    Ordering is empirical, not cosmetic. Chromium (Edge 13x) does **not** fire
    ``onload`` for an inline ``<svg>`` created through ``innerHTML``, so the
    classic ``<svg/onload=...>`` vector silently produces a dead node: the
    markup is in the DOM but nothing runs. ``<img onerror>`` does fire, and it
    fires even for a one-pixel ``src=x`` request that 404s, which is why it is
    first. The bare (unquoted) variant survives filters that strip quotes, and
    ``<details ontoggle>`` covers pages where images are blocked outright.
    """
    js = dom_js_artifact(marker)
    return [
        ("img-onerror", f'<img src=x onerror="{js}">'),
        ("img-onerror-bare", f"<img src=x onerror={js}>"),
        ("details-ontoggle", f'<details open ontoggle="{js}">'),
        ("svg-onload", f'<svg onload="{js}">'),
    ]


def dom_payload(marker: str) -> str:
    """Primary markup vector (kept for callers that need a single string)."""
    return dom_payloads(marker)[0][1]


def dom_js_artifact(marker: str) -> str:
    """Space-free JS that leaves an element only execution can create."""
    return f"document.body.appendChild(document.createElement('b')).id='{dom_target_id(marker)}'"


def dom_target_id(marker: str) -> str:
    return f"xdm{marker}x"


MARKUP_SINKS = {
    "innerhtml", "outerhtml", "insertadjacenthtml", "document.write",
    "jquery-html", "jquery-append", "srcdoc", "dangerouslysetinnerhtml",
    "v-html", "bypasssecuritytrusthtml", "createcontextualfragment",
    "jquery-parshtml", "jquery-parsehtml",
}

JS_SINKS = {
    "eval", "function", "settimeout-string",
}

URL_SINKS = {
    "location.assign", "location.href=", "window.open",
}

# sinks a markup or javascript: payload cannot exercise (they need a served script)
UNVERIFIABLE_SINKS = {"script-src"}


def sink_kind(sink: str) -> str:
    s = (sink or "").lower()
    if s in MARKUP_SINKS:
        return "markup"
    if s in JS_SINKS:
        return "js"
    if s in URL_SINKS:
        return "url"
    return "markup"


def payloads_for(kind: str, marker: str) -> list[tuple[str, str]]:
    """Ranked (vector, payload) pairs for one sink class."""
    js = dom_js_artifact(marker)
    if kind == "js":
        return [("js-direct", js), ("js-string-break", f"';{js};//")]
    if kind == "url":
        return [("javascript-url", "javascript:" + js),
                ("javascript-url-mixed", "JaVaScRiPt:" + js)]
    return dom_payloads(marker)


def payload_for(kind: str, marker: str) -> str:
    return payloads_for(kind, marker)[0][1]


# NOTE: keep %s, never str.format -- the IIFE braces would be read as fields
# and .format() raises ValueError *before* the script is ever evaluated.
DOM_ARTIFACT_JS = (
    "(function(){var e=document.getElementById(%s);"
    "return e?(e.tagName+':'+e.id):''})()"
)


# ---------------------------------------------------------------------------
# Runtime verification
# ---------------------------------------------------------------------------

class DomScanner:
    """Turn static flows into proven findings, or into explicitly-labelled leads."""

    def __init__(self, browser=None, log=None, max_flows: int = 25,
                 screenshot_dir: str | None = None, deadline: float | None = None,
                 max_store_flows: int = 12):
        self.browser = browser
        self.log = log
        self.max_flows = max_flows
        self.max_store_flows = max_store_flows
        self.screenshot_dir = screenshot_dir
        # Wall-clock deadline shared with the other phases. The DOM phase drives a
        # real browser per flow, so it is the easiest place to blow a budget.
        self.deadline = deadline
        self.budget_exhausted = False
        self.flows: list[DomCandidate] = []
        self.findings: list = []
        self.leads: list = []
        self.runtime: list[dict] = []

    def _out_of_budget(self) -> bool:
        if self.deadline is None:
            return False
        if time.time() < self.deadline:
            return False
        if not self.budget_exhausted:
            self.budget_exhausted = True
            self._log("time budget reached during DOM analysis; reporting flows "
                      "proven so far")
        return True

    # -- collection ----------------------------------------------------
    def collect(self, resources) -> list[DomCandidate]:
        """*resources* is a list of (url, body, pages_that_load_it)."""
        seen: set[str] = set()
        out: list[DomCandidate] = []
        hosts: dict[str, str] = {}
        writes: list[domstate.StoreWrite] = []
        reads: list[domstate.StoreRead] = []
        reducers: dict[str, str] = {}
        by_resource_reads: dict[str, list[domstate.StoreRead]] = {}

        for resource, body, pages in resources:
            if not body:
                continue
            host = ""
            for p in pages or []:
                if p and not p.endswith("#inline") and p != resource:
                    host = p
                    break
            if not host and "#inline" in resource:
                host = resource.split("#inline", 1)[0]
            hosts[resource] = host
            taint = _build_taint(body)

            # 1. flows that live inside this resource
            for cand in analyze_js(resource, body, taint=taint):
                if cand.key() in seen:
                    continue
                seen.add(cand.key())
                cand.page = host
                out.append(cand)

            # 2. store traffic: writes and reads are joined across resources
            body_writes, body_reads = domstate.scan_state(resource, body, taint, SINKS)
            writes.extend(body_writes)
            reads.extend(body_reads)
            reducers.update(domstate.reducer_map(body))
            if body_reads:
                by_resource_reads[resource] = body_reads

        # A dispatch carries an action type; the reducer maps it to a field. Only
        # after every resource has been read can the two halves be joined.
        writes = domstate.expand_dispatch(writes, reducers)

        # A storage read is only a *lead* today because the value looks like it
        # arrives out of band. When the same key is written from a URL source,
        # the browser can be driven through both steps -- so recover the key and
        # promote the flow to verifiable instead of leaving it unexplained.
        for cand in out:
            if cand.delivery != "storage" or cand.store:
                continue
            for var in cand.taint_chain[1:]:
                read = domstate.read_for_var(reads, var, cand.resource)
                if read is None:
                    continue
                write = domstate.write_for(read.kind, read.key, writes)
                if write is None:
                    continue
                self._attach_store(cand, write, read, hosts)
                seen.add(cand.key())
                break

        for flow in domstate.join_state(writes, reads, limit=self.max_store_flows):
            flow_cand = self._store_candidate(flow, hosts)
            if flow_cand is None or flow_cand.key() in seen:
                continue
            seen.add(flow_cand.key())
            out.append(flow_cand)

        self.flows = out
        return out

    @staticmethod
    def _same_origin(a: str, b: str) -> bool:
        """Storage is origin-scoped: a cross-origin join can never be exercised."""
        if not a or not b:
            return True
        try:
            return urllib.parse.urlsplit(a).netloc == urllib.parse.urlsplit(b).netloc
        except ValueError:
            return False

    def _attach_store(self, cand: DomCandidate, write: domstate.StoreWrite,
                      read: domstate.StoreRead, hosts: dict[str, str]) -> None:
        cand.store = read.kind
        cand.store_key = read.key
        cand.write_page = hosts.get(write.resource, "") or cand.page
        cand.write_line = write.line
        cand.source = write.source
        cand.delivery = write.delivery
        cand.parameter = read.parameter or write.parameter or cand.parameter
        cand.taint_chain = [write.source, f"{write.kind}.{write.key}"]
        cand.two_step = (write.kind in ("localStorage", "sessionStorage")
                         or cand.write_page != cand.page)
        if not self._same_origin(cand.write_page, cand.page):
            cand.store = ""
            cand.two_step = False

    def _store_candidate(self, flow: domstate.StoreFlow,
                         hosts: dict[str, str]) -> DomCandidate | None:
        read, write = flow.read, flow.write
        page = hosts.get(read.resource, "")
        write_page = hosts.get(write.resource, "") or page
        if not write.delivery:
            return None
        cand = DomCandidate(
            resource=read.resource,
            sink=read.sink,
            source=write.source,
            parameter=read.parameter or write.parameter or "",
            delivery=write.delivery,
            taint_chain=[write.source, f"{write.kind}.{write.key}"],
            sink_snippet=read.statement,
            flow_snippet=f"line {write.line}: {write.snippet}",
            line=read.line,
            page=page,
            store=read.kind,
            store_key=read.key,
            write_page=write_page,
            write_line=write.line,
        )
        # A second document is involved whenever the two halves live on different
        # pages, not only for web storage: the replay has to walk both steps.
        cand.two_step = (write.kind in ("localStorage", "sessionStorage")
                         or write_page != page)
        if not self._same_origin(write_page, page):
            return None
        return cand

    # -- verification --------------------------------------------------
    def scan(self, base_url: str, resources) -> dict:
        cands = self.collect(resources)
        if not cands:
            return {"flows": [], "findings": [], "leads": [], "runtime": []}
        self._log(f"DOM analysis: {len(cands)} source-to-sink flow(s) in "
                  f"{len(resources)} script resource(s)")
        checkable = [c for c in cands if self._can_verify(c)]
        rest = [c for c in cands if not self._can_verify(c)]
        for cand in rest[: self.max_flows]:
            if cand.store and not cand.two_step:
                reason = (f"{cand.store}.{cand.store_key} is written from another origin, "
                          "so the browser cannot be driven through both steps")
            elif cand.store:
                reason = (f"{cand.store}.{cand.store_key} lives in page memory, so a "
                          "second navigation cannot carry it; review the write and "
                          "the read together")
            elif cand.delivery == "storage":
                reason = ("value is read from storage but no URL-fed write was found, "
                          "so the flow cannot be replayed from the request")
            else:
                reason = "requires request-level injection or a served script"
            self.leads.append(self._lead(cand, base_url, reason))
        for cand in checkable[: self.max_flows]:
            if is_hardened(cand):
                self.leads.append(self._lead(cand, base_url,
                                             f"flow passes through {cand.hardening}"))
                continue
            if self._out_of_budget():
                break
            finding = self._verify(base_url, cand)
            if finding is None:
                continue
            if finding.verified_browser:
                self.findings.append(finding)
                self._log(f"DOM XSS confirmed: {cand.parameter} -> {cand.sink}() on "
                          f"{cand.page or base_url}")
            else:
                self.leads.append(finding)
        return {"flows": self.flows, "findings": self.findings,
                "leads": self.leads, "runtime": self.runtime}

    def _can_verify(self, cand: DomCandidate) -> bool:
        if not self.browser or not getattr(self.browser, "available", False):
            return False
        if cand.sink.lower() in UNVERIFIABLE_SINKS:
            return False
        if cand.two_step:
            # Browser storage survives a second navigation, so a joined write can
            # be replayed even though the value never travels in one request. An
            # in-memory store (setState, reducer, event bus) is reset by the new
            # document, so only a single-page flow can actually be driven.
            if cand.store and cand.store not in ("localStorage", "sessionStorage"):
                return False
            return cand.delivery in ("query", "url", "hash") and bool(cand.write_page)
        return cand.delivery in ("query", "url", "hash", "window.name")

    def _param_candidates(self, page_url: str, cand: DomCandidate) -> list[str]:
        """Parameters worth trying when the flow does not name one.

        A hydration blob or a data- attribute is populated by *some* parameter the
        server chose; the page's own query names are the best evidence we have,
        and the list is capped because every guess costs a navigation.
        """
        if cand.parameter:
            return [cand.parameter]
        names: list[str] = []
        try:
            names.extend(k for k, _ in urllib.parse.parse_qsl(
                urllib.parse.urlsplit(page_url).query, keep_blank_values=True) if k)
        except ValueError:
            pass
        for guess in ("q", "search", "query", "id", "page", "s", "term", "name", "state"):
            if guess not in names:
                names.append(guess)
        return names[:3] or ["q"]

    def _verify(self, base_url: str, cand: DomCandidate):
        marker = uuid.uuid4().hex[:10]
        kind = sink_kind(cand.sink)
        page_url = cand.page or base_url
        target = dom_target_id(marker)
        observation: dict = {"flow": cand.summary(), "resource": cand.resource,
                             "page": page_url, "payload": "", "kind": kind,
                             "delivery": cand.delivery, "marker": marker,
                             "attempts": []}

        confirmed = False
        detail: dict = {"loaded": False}
        params = self._param_candidates(page_url, cand)
        vectors = payloads_for(kind, marker)
        if len(params) > 1:
            # the parameter has to be guessed, and every guess costs a navigation:
            # spend them on names rather than on extra vectors
            vectors = vectors[:1]
        for label, payload in vectors:
            for param in params:
                if self._out_of_budget():
                    break
                if cand.delivery == "window.name":
                    ok, detail = self._drive_window_name(page_url, payload, target)
                elif cand.delivery == "hash":
                    ok, detail = self._drive_hash(page_url, cand, payload, target, param=param)
                elif cand.two_step:
                    ok, detail = self._drive_store(cand, payload, param, target)
                else:
                    url = build_test_url(page_url, cand, payload, param=param) or page_url
                    ok, detail = self._drive_url(url, target)
                    observation.setdefault("url", url)
                observation["attempts"].append({"vector": label, "parameter": param,
                                                "confirmed": ok,
                                                "artifact": detail.get("artifact", "")})
                if not detail.get("loaded"):
                    return None  # the page never loaded; nothing to say about this flow
                if ok:
                    confirmed = True
                    observation["vector"] = label
                    observation["parameter"] = param
                    observation["payload"] = payload
                    observation["url"] = (detail.get("url") or observation.get("url")
                                          or page_url)
                    break
            if confirmed:
                break
        if not observation["payload"]:
            observation["payload"] = payloads_for(kind, marker)[0][1]
        payload = observation["payload"]

        observation.update(detail)
        if confirmed and self.screenshot_dir:
            shot = os.path.join(self.screenshot_dir, f"dom-xss-{marker}.png")
            try:
                if self.browser.screenshot(shot):
                    observation["screenshot"] = shot
            except Exception:
                pass
        self.runtime.append(observation)
        if not detail.get("loaded"):
            return None

        evidence = self._evidence(cand, observation)
        notes = [f"DOM flow: {cand.summary()}",
                 "static taint flow is inferred; runtime check is the proof"]
        if confirmed:
            notes.append("injected node observed in the live DOM after execution")
        elif detail.get("marker_in_dom"):
            notes.append("payload reached the DOM but its handler did not run "
                         "(Content-Security-Policy or a sanitizer)")
        else:
            notes.append("payload did not reach the DOM through the analysed flow")

        from .scanner import Finding
        return Finding(
            url=observation.get("url") or page_url,
            method="GET", param=observation.get("parameter") or cand.parameter or "q",
            location="DOM", payload=payload, context="dom_xss", status=0,
            confidence="high" if confirmed else "low",
            verified_browser=confirmed, browser_checked=True,
            verify_state="confirmed" if confirmed else "not_observed",
            verify_reason=("injected node observed in the live DOM after execution" if confirmed
                           else ("payload reached the DOM but the handler did not run"
                                 if detail.get("marker_in_dom")
                                 else "the analysed flow did not place the payload in the DOM")),
            evidence=evidence, notes=notes, title="DOM-based XSS",
        )

    def _drive_url(self, url: str, target: str) -> tuple[bool, dict]:
        info = self.browser.navigate(url)
        detail = {"loaded": bool(info.get("loaded")), "error": info.get("error", ""),
                  "url": info.get("url") or url}
        if not detail["loaded"]:
            return False, detail
        self._settle()
        artifact = self._artifact(target)
        detail["artifact"] = artifact
        detail["marker_in_dom"] = self._marker_seen(target)
        return bool(artifact), detail

    def _drive_hash(self, page_url: str, cand: DomCandidate,
                    payload: str, target: str,
                    param: str | None = None) -> tuple[bool, dict]:
        """Set the fragment from script so no character is re-encoded, then reload.

        Both ``#param=payload`` and ``#payload`` are attempted because the two
        common readers (URLSearchParams vs. slice(1)) expect different shapes.
        """
        param = param or cand.parameter or "q"
        # ``#q=payload`` first: modern routers read the fragment with
        # URLSearchParams. The bare shape covers slice(1)-style routers.
        variants = [f"{param}={payload}", payload]
        detail: dict = {"loaded": False}
        for fragment in variants:
            info = self.browser.navigate(page_url)
            if not info.get("loaded"):
                return False, {"loaded": False, "error": info.get("error", "")}
            try:
                token = self.browser.evaluate("String(performance.timeOrigin)")
                self.browser.evaluate("location.hash = " + json.dumps("#" + fragment))
                self.browser.evaluate("location.reload()")
                self._wait_new_document(token)
            except Exception as exc:  # browser went away mid-flow
                return False, {"loaded": True, "error": str(exc)[:160]}
            self._settle()
            artifact = self._artifact(target)
            if artifact:
                return True, {"loaded": True, "url": page_url, "artifact": artifact,
                              "marker_in_dom": True, "fragment_shape": fragment[:40]}
            detail = {"loaded": True, "url": page_url,
                      "artifact": "", "marker_in_dom": self._marker_seen(target),
                      "fragment_shape": fragment[:40]}
        return False, detail

    def _drive_store(self, cand: DomCandidate, payload: str, param: str,
                     target: str) -> tuple[bool, dict]:
        """Walk the flow the way the application does: write the value, then read it.

        A store flow has two steps on purpose -- the page that *stores* the request
        data and the page that *renders* it can be different documents. The write
        step is verified before the read step so a payload that was never stored
        is reported as "not exercised" rather than as "not vulnerable".
        """
        write_page = cand.write_page or cand.page
        read_page = cand.page or write_page
        if not write_page or not read_page:
            return False, {"loaded": False, "error": "store flow without page URLs"}
        url = build_test_url(write_page, cand, payload, param=param) or write_page
        info = self.browser.navigate(url)
        if not info.get("loaded"):
            return False, {"loaded": False, "error": info.get("error", ""), "url": url}
        self._settle()
        stored = self._store_value(cand.store, cand.store_key, target)
        if read_page.rstrip("/") != write_page.rstrip("/"):
            info = self.browser.navigate(read_page)
            if not info.get("loaded"):
                return False, {"loaded": False, "error": info.get("error", ""),
                               "url": read_page, "store_value_seen": stored}
        self._settle()
        artifact = self._artifact(target)
        return bool(artifact), {"loaded": True, "url": read_page, "artifact": artifact,
                                "marker_in_dom": self._marker_seen(target),
                                "write_url": url, "store_value_seen": stored}

    def _store_value(self, store: str, key: str, target: str) -> bool | None:
        """Did the write step actually park the payload? ``None`` = cannot tell.

        Web storage is readable from the driver, so a false here means the flow was
        never exercised and the runtime result must not be read as a negative.
        A framework store (``state``/``dispatch``) is in-memory and opaque: there
        is no honest way to inspect it from outside, so it reports ``None``.
        """
        if store not in ("localStorage", "sessionStorage"):
            return None
        script = (
            f"(function(){{try{{var v=window[{json.dumps(store)}].getItem("
            f"{json.dumps(key)});return v?v.indexOf({json.dumps(target)})>=0:false}}"
            f"catch(e){{return false}}}})()"
        )
        try:
            value = self.browser.evaluate(script)
        except Exception:
            return None
        return bool(value) if isinstance(value, bool) else None

    def _drive_window_name(self, page_url: str, payload: str,
                           target: str) -> tuple[bool, dict]:
        info = self.browser.navigate("about:blank")
        if not info.get("loaded"):
            return False, {"loaded": False, "error": "could not open about:blank"}
        self.browser.evaluate("window.name = " + json.dumps(payload))
        info = self.browser.navigate(page_url)
        if not info.get("loaded"):
            return False, {"loaded": False, "error": info.get("error", "")}
        self._settle()
        artifact = self._artifact(target)
        return bool(artifact), {"loaded": True, "url": page_url, "artifact": artifact,
                                "marker_in_dom": self._marker_seen(target)}

    def _wait_new_document(self, old_token: str, timeout: float = 6.0) -> None:
        """Block until a *new* document exists (timeOrigin changes on reload)."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                token = self.browser.evaluate("String(performance.timeOrigin)")
                ready = self.browser.evaluate("document.readyState")
            except Exception:
                return
            if token and token != old_token and ready in ("interactive", "complete"):
                return
            time.sleep(0.1)

    def _settle(self, timeout: float = 3.0) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                if self.browser.evaluate("document.readyState") in ("interactive", "complete"):
                    return
            except Exception:
                return
            time.sleep(0.1)

    def _artifact(self, target: str, timeout: float = 2.5) -> str:
        """Poll briefly: error/load handlers run after the insertion returns."""
        deadline = time.time() + timeout
        while True:
            try:
                found = self.browser.evaluate(DOM_ARTIFACT_JS % json.dumps(target)) or ""
            except Exception:
                return ""
            if found or time.time() >= deadline:
                return found
            time.sleep(0.1)

    def _marker_seen(self, target: str) -> bool:
        try:
            value = self.browser.evaluate(
                "document.documentElement.outerHTML.indexOf(" + json.dumps(target) + ")>=0")
            if isinstance(value, bool):
                return value
            return str(value).strip().lower() in ("true", "1")
        except Exception:
            return False

    # -- reporting -----------------------------------------------------
    def _evidence(self, cand: DomCandidate, obs: dict) -> str:
        lines = [
            f"DOM flow (static, inferred): {cand.summary()}",
            f"  script: {cand.resource}",
            f"  source line {cand.line}: {cand.sink_snippet}",
            f"  delivery: {cand.delivery}, parameter: "
            f"{obs.get('parameter') or cand.parameter or 'guessed at verification'}",
        ]
        if cand.store:
            lines.append(f"  store: {cand.store}.{cand.store_key} written at "
                         f"{cand.write_page or 'the same page'} line {cand.write_line}")
        if cand.flow_snippet:
            lines.append(f"  origin: {cand.flow_snippet}")
        if obs.get("artifact"):
            steps = (f"wrote the payload at {obs.get('write_url')} then loaded "
                     if obs.get("write_url") else "navigated to ")
            lines.append(f"Runtime proof: {steps}{obs.get('url')} and observed "
                         f"the injected node <{obs['artifact']}> in the live DOM")
            if obs.get("screenshot"):
                lines.append(f"  screenshot: {obs['screenshot']}")
        elif obs.get("marker_in_dom"):
            lines.append(f"Runtime check: payload reached the DOM at {obs.get('url')} "
                         "but no injected node appeared (blocked)")
        elif obs.get("store_value_seen") is False:
            lines.append(f"Runtime check: the write step at {obs.get('write_url')} did not "
                         "store the payload, so the read step was never exercised")
        else:
            lines.append(f"Runtime check: the analysed flow did not place the payload "
                         f"in the DOM at {obs.get('url')}")
        return "\n".join(lines)

    def _lead(self, cand: DomCandidate, base_url: str, reason: str):
        from .scanner import Finding
        return Finding(
            url=cand.page or base_url, method="GET", param=cand.parameter or "q",
            location="DOM", payload="", context="dom_xss", status=0,
            confidence="low", verified_browser=False, browser_checked=False,
            verify_state="not_tested", verify_reason=reason,
            evidence=self._evidence(cand, {}),
            notes=[f"DOM flow: {cand.summary()}", f"not verified: {reason}"],
            title="DOM-based XSS (candidate)",
        )

    def _log(self, message: str) -> None:
        if self.log is not None:
            try:
                self.log.info(message)
            except Exception:
                pass
