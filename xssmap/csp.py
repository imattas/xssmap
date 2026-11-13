"""Content-Security-Policy: read the policy the way a browser reads it.

Substring matching ("the response mentions Content-Security-Policy") cannot
answer the only question a scanner has: *would this payload have run if the
application had not filtered it?* The answer lives in the policy's directives,
their fallback chains, and the keywords that silently disable other keywords --
``'unsafe-inline'`` is ignored as soon as a nonce or hash appears,
``'strict-dynamic'`` discards host allowlists and ``'self'``, and ``'none'`` is
only meaningful on its own.

This module parses the header into directives and answers three questions:

* is inline script / an event handler / a ``javascript:`` URL permitted?
* would a ``<script src=...>`` on this URL be permitted?
* what does the policy leave open even if it does block the payload
  (missing ``base-uri``/``object-src``, wildcard or ``http:`` allowlists,
  report-only delivery)?

The answers are *static*: they describe what the policy declares, not what the
engine did. The browser remains the only source of an execution verdict; a
policy that forbids a technique explains a negative result, it never creates a
positive one.
"""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field

# Fetch directives fall back to default-src; these do not (or fall back to a
# different chain first). Getting this wrong turns "not assessed" into a false
# claim, so the chains are explicit.
_FALLBACKS: dict[str, tuple[str, ...]] = {
    "script-src-elem": ("script-src", "default-src"),
    "script-src-attr": ("script-src", "default-src"),
    "style-src-elem": ("style-src", "default-src"),
    "style-src-attr": ("style-src", "default-src"),
    "worker-src": ("child-src", "script-src", "default-src"),
    "frame-src": ("child-src", "default-src"),
    "connect-src": ("default-src",),
    "img-src": ("default-src",),
    "font-src": ("default-src",),
    "media-src": ("default-src",),
    "object-src": ("default-src",),
    "manifest-src": ("default-src",),
    "prefetch-src": ("default-src",),
    "base-uri": (),
    "form-action": (),
    "frame-ancestors": (),
    "sandbox": (),
    "report-uri": (),
    "report-to": (),
}

_NAME_RE = re.compile(r"^[a-z][a-z0-9-]*\Z")
_SCHEME_SRC_RE = re.compile(r"^([a-z][a-z0-9+.-]*):\Z", re.I)
_HOST_SRC_RE = re.compile(
    r"^(?:([a-z][a-z0-9+.-]*)://)?(\*|\*\.[^/:]+|\[[^\]]+\]|[^/:]+)(?::(\d+|\*))?(/.*)?\Z",
    re.I,
)
_POLICY_SPLIT_RE = re.compile(r",(?=\s*[a-z][a-z0-9-]*\s)", re.I)

_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}

# Payload techniques, most specific first. The order matters: `<script src=...>`
# also contains `<script`, and an event handler may sit inside a `<script>` body.
_TECHNIQUE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("external_script", re.compile(r"<script\b[^>]*\bsrc\s*=", re.I)),
    ("srcdoc", re.compile(r"\bsrcdoc\b", re.I)),
    ("inline_script", re.compile(r"<script\b", re.I)),
    ("javascript_url", re.compile(r"javascript\s*:", re.I)),
    ("inline_event_handler", re.compile(r"<[a-z][^>]*?\son[a-z]+\s*=", re.I | re.S)),
)

TECHNIQUE_LABELS = {
    "external_script": "an external script element",
    "inline_script": "an inline script element",
    "inline_event_handler": "an inline event handler",
    "javascript_url": "a javascript: URL",
    "srcdoc": "an iframe srcdoc document",
    "markup": "markup only (no script technique)",
}


def technique_of(markup: str) -> str:
    """Classify what a payload needs the policy to permit."""
    text = markup or ""
    for name, pattern in _TECHNIQUE_PATTERNS:
        if pattern.search(text):
            return name
    return "markup"


@dataclass(frozen=True)
class Feasibility:
    """Static answer to "would the policy let this technique run?"."""

    technique: str
    allowed: bool | None      # None = the policy says nothing about it
    reason: str

    def line(self) -> str:
        label = TECHNIQUE_LABELS.get(self.technique, self.technique)
        if self.allowed is None:
            return f"{label}: not forbidden by the policy ({self.reason})"
        verdict = "would be permitted" if self.allowed else "would be blocked"
        return f"{label} {verdict}: {self.reason}"


@dataclass(frozen=True)
class Policy:
    raw: str
    directives: dict[str, tuple[str, ...]] = field(default_factory=dict)
    report_only: bool = False

    # -- construction ----------------------------------------------------
    @classmethod
    def parse(cls, raw: str, report_only: bool = False) -> Policy:
        directives: dict[str, tuple[str, ...]] = {}
        for part in (raw or "").split(";"):
            tokens = part.split()
            if not tokens:
                continue
            name = tokens[0].lower()
            # Browsers ignore a directive whose name is not a valid token.
            if not _NAME_RE.match(name):
                continue
            # A repeated directive is ignored: the first instance wins.
            if name in directives:
                continue
            values: list[str] = []
            for token in tokens[1:]:
                if token not in values:
                    values.append(token)
            directives[name] = tuple(values)
        return cls(raw=(raw or "").strip(), directives=directives,
                   report_only=report_only)

    # -- directive resolution -------------------------------------------
    def effective(self, name: str) -> tuple[str, tuple[str, ...]] | None:
        """Resolve *name* through its fallback chain.

        Returns ``(directive_name, sources)`` for the directive a browser would
        actually use, or ``None`` when no policy covers it. ``'none'`` on its
        own means the empty set; combined with other sources it is ignored.
        """
        chain = (name,) + _FALLBACKS.get(name, ("default-src",))
        for candidate in chain:
            if candidate not in self.directives:
                continue
            sources = tuple(s for s in self.directives[candidate]
                            if s.lower() != "'none'")
            return candidate, sources
        return None

    def present(self) -> bool:
        return bool(self.directives)

    def policy_for_scripts(self, kind: str = "elem") -> tuple[str, tuple[str, ...]] | None:
        name = "script-src-attr" if kind == "attr" else "script-src-elem"
        return self.effective(name)

    # -- keyword analysis ------------------------------------------------
    @staticmethod
    def _keywords(sources: tuple[str, ...]) -> dict[str, bool]:
        low = [s.lower() for s in sources]
        return {
            "unsafe_inline": "'unsafe-inline'" in low,
            "unsafe_eval": "'unsafe-eval'" in low or "'wasm-unsafe-eval'" in low,
            "strict_dynamic": "'strict-dynamic'" in low,
            "nonce": any(s.startswith("'nonce-") for s in low),
            "hash": any(s.startswith(("'sha256-", "'sha384-", "'sha512-")) for s in low),
            "self": "'self'" in low,
            "wildcard": "*" in low,
        }

    def inline_allowed(self, kind: str = "elem") -> Feasibility:
        """May inline script (``elem``) or an event handler (``attr``) run?"""
        technique = "inline_event_handler" if kind == "attr" else "inline_script"
        resolved = self.policy_for_scripts(kind)
        if resolved is None:
            return Feasibility(technique, None,
                               "no script-src/script-src-elem/default-src directive applies")
        name, sources = resolved
        kw = self._keywords(sources)
        disablers = []
        if kw["nonce"]:
            disablers.append("a nonce-source")
        if kw["hash"]:
            disablers.append("a hash-source")
        if kw["strict_dynamic"]:
            disablers.append("'strict-dynamic'")
        if kw["unsafe_inline"] and not disablers:
            return Feasibility(technique, True, f"{name} lists 'unsafe-inline'")
        if kw["unsafe_inline"]:
            return Feasibility(
                technique, False,
                f"{name} lists 'unsafe-inline' but the browser ignores it when the "
                f"policy also contains {', '.join(disablers)}")
        listed = " ".join(sources) or "(empty)"
        return Feasibility(technique, False,
                           f"{name} is {listed} and does not include 'unsafe-inline'")

    def allows_eval(self) -> bool | None:
        resolved = self.policy_for_scripts("elem")
        if resolved is None:
            return None
        return self._keywords(resolved[1])["unsafe_eval"]

    def strict_dynamic(self) -> bool:
        """Does this policy trust a script tree instead of a script allowlist?"""
        resolved = self.policy_for_scripts("elem")
        if resolved is None:
            return False
        return self._keywords(resolved[1])["strict_dynamic"]

    # -- URL matching ----------------------------------------------------
    def allows_url(self, url: str, kind: str = "elem",
                   self_origin: str = "") -> Feasibility:
        """Would a script loaded from *url* be permitted?"""
        technique = "external_script"
        resolved = self.policy_for_scripts(kind)
        if resolved is None:
            return Feasibility(technique, None,
                               "no script-src/script-src-elem/default-src directive applies")
        name, sources = resolved
        kw = self._keywords(sources)
        if kw["strict_dynamic"] and not kw["nonce"] and not kw["hash"]:
            # Without a nonce/hash in the document, strict-dynamic permits only
            # scripts created by already-trusted script: a markup injection
            # cannot bootstrap itself.
            return Feasibility(
                technique, False,
                f"{name} uses 'strict-dynamic' without a nonce or hash, so a "
                f"markup-injected external script cannot load")
        target = _absolute(url, self_origin)
        if not target:
            return Feasibility(technique, None, "payload has no resolvable script URL")
        for source in sources:
            if source_matches(source, target, self_origin):
                return Feasibility(technique, True,
                                   f"{name} allows {source} for {_host_of(target)}")
        listed = " ".join(sources) or "(empty)"
        return Feasibility(technique, False,
                           f"{name} is {listed} and none matches {_host_of(target)}")

    # -- assessment ------------------------------------------------------
    def feasibility(self, markup: str, page_url: str = "") -> Feasibility:
        """Static feasibility of *markup* under this policy."""
        technique = technique_of(markup)
        if technique == "inline_event_handler":
            return self.inline_allowed("attr")
        if technique == "inline_script":
            return self.inline_allowed("elem")
        if technique == "javascript_url":
            inline = self.inline_allowed("elem")
            if inline.allowed is None:
                return Feasibility("javascript_url", None, inline.reason)
            return Feasibility(
                "javascript_url", inline.allowed,
                ("'unsafe-inline' is required for javascript: URLs; " + inline.reason))
        if technique == "external_script":
            match = re.search(r"<script\b[^>]*\bsrc\s*=\s*(['\"]?)([^'\"\s>]+)", markup, re.I)
            if not match:
                return Feasibility(technique, None, "could not parse the script src")
            return self.allows_url(match.group(2), "elem", page_url)
        if technique == "srcdoc":
            # A srcdoc document inherits the embedding page's policy, so script
            # inside it is judged by the same script-src.
            inner = self.inline_allowed("elem")
            return Feasibility(
                "srcdoc", inner.allowed,
                "a srcdoc frame inherits this policy; " + inner.reason)
        return Feasibility("markup", None, "no script technique in the payload")

    def deficiencies(self) -> list[str]:
        """What the policy leaves open, independent of any payload."""
        out: list[str] = []
        script = self.policy_for_scripts("elem")
        if script is None:
            out.append("no script-src or default-src directive: script is unrestricted")
        else:
            name, sources = script
            kw = self._keywords(sources)
            if kw["unsafe_inline"] and not (kw["nonce"] or kw["hash"] or kw["strict_dynamic"]):
                out.append(f"{name} allows 'unsafe-inline': the policy does not "
                           f"mitigate reflected XSS")
            if kw["unsafe_eval"]:
                out.append(f"{name} allows 'unsafe-eval'")
            if kw["wildcard"]:
                out.append(f"{name} allows '*' (any host)")
            if self._keywords(sources)["hash"] and kw["unsafe_inline"]:
                out.append(f"{name} mixes hashes with 'unsafe-inline'; only the hashes apply")
            lowered = [s.lower() for s in sources]
            if any(s == "http:" or s.startswith("http://") for s in lowered):
                out.append(f"{name} allows plaintext http: sources")
            if "data:" in lowered:
                out.append(f"{name} allows data: URLs")
            if kw["strict_dynamic"] and not (kw["nonce"] or kw["hash"]):
                out.append(f"{name} uses 'strict-dynamic' without a nonce or hash; "
                           f"browsers that support it ignore the host allowlist")
            hosts = [s for s in sources
                     if s and not s.startswith("'") and s not in ("*",)]
            hosts = [s for s in hosts if not _SCHEME_SRC_RE.match(s)]
            if hosts and not kw["strict_dynamic"]:
                listed = ", ".join(hosts[:4]) + (" ..." if len(hosts) > 4 else "")
                out.append(f"{name} trusts {listed}: a host that serves JSONP or a "
                           f"script gadget can be used to bypass the policy")
        if "base-uri" not in self.directives:
            out.append("no base-uri directive: an injected <base href> can retarget "
                       "relative script URLs")
        if "object-src" not in self.directives and "default-src" not in self.directives:
            out.append("no object-src or default-src: plugin content is unrestricted")
        if "form-action" not in self.directives:
            out.append("no form-action directive: injected forms can post off-origin")
        if self.report_only:
            out.append("delivered as Content-Security-Policy-Report-Only: it reports "
                       "violations but blocks nothing")
        return out

    def summary(self) -> str:
        parts = []
        for name in ("default-src", "script-src", "script-src-elem", "script-src-attr",
                     "object-src", "base-uri"):
            if name in self.directives:
                values = " ".join(self.directives[name]) or "(empty)"
                parts.append(f"{name} {values}")
        if not parts:
            return "empty policy"
        prefix = "report-only" if self.report_only else "enforced"
        return f"{prefix}: " + "; ".join(parts)


# ---------------------------------------------------------------------------
# Header collection
# ---------------------------------------------------------------------------

@dataclass
class Assessment:
    """Every policy a response declares, split by enforcement mode."""

    enforced: list[Policy] = field(default_factory=list)
    report_only: list[Policy] = field(default_factory=list)

    @classmethod
    def from_headers(cls, headers: list[tuple[str, str]] | None) -> Assessment:
        assessment = cls()
        for name, value in headers or []:
            lowered = name.lower().strip()
            if lowered not in ("content-security-policy",
                               "content-security-policy-report-only"):
                continue
            report_only = lowered.endswith("report-only")
            for chunk in _split_policies(value):
                policy = Policy.parse(chunk, report_only=report_only)
                if not policy.present():
                    continue
                (assessment.report_only if report_only
                 else assessment.enforced).append(policy)
        return assessment

    @property
    def present(self) -> bool:
        return bool(self.enforced or self.report_only)

    def feasibility(self, markup: str, page_url: str = "") -> Feasibility:
        """Combine every enforced policy: all of them must permit the technique."""
        technique = technique_of(markup)
        if not self.enforced:
            return Feasibility(technique, None,
                               "report-only headers do not block; no enforced policy")
        allowed = True
        reasons: list[str] = []
        assessed = False
        for policy in self.enforced:
            verdict = policy.feasibility(markup, page_url)
            if verdict.allowed is None:
                reasons.append(verdict.reason)
                continue
            assessed = True
            if not verdict.allowed:
                return Feasibility(technique, False, verdict.reason)
            reasons.append(verdict.reason)
        if not assessed:
            return Feasibility(technique, None, "; ".join(reasons) or "not restricted")
        return Feasibility(technique, allowed, "; ".join(reasons))

    def deficiencies(self) -> list[str]:
        out: list[str] = []
        for policy in self.enforced:
            out.extend(policy.deficiencies())
        for _ in self.report_only:
            out.append("a report-only policy has no effect on execution")
        seen: set[str] = set()
        unique = []
        for item in out:
            if item not in seen:
                seen.add(item)
                unique.append(item)
        return unique

    def summary(self) -> str:
        if not self.present:
            return "no Content-Security-Policy header"
        parts = [p.summary() for p in self.enforced]
        parts += [p.summary() for p in self.report_only]
        return " | ".join(parts)

    def describe(self, markup: str, page_url: str = "", limit: int = 3) -> str:
        """Compact multi-line description for a finding's notes."""
        if not self.present:
            return ""
        lines = [self.summary(), self.feasibility(markup, page_url).line()]
        for item in self.deficiencies()[:limit]:
            lines.append(f"policy gap: {item}")
        return "\n".join(lines)

    def strict_dynamic(self) -> bool:
        """True when an enforced policy switches the host allowlist off.

        Any policy that carries 'strict-dynamic' blocks a markup-inserted
        script, so one is enough to make the gadget question relevant.
        """
        return any(p.strict_dynamic() for p in self.enforced)


def describe_with_gadgets(assessment: Assessment, markup: str, page_url: str = "",
                          page_html: str = "", limit: int = 3) -> str:
    """``describe()`` plus what ``'strict-dynamic'`` leaves open on this page.

    ``'strict-dynamic'`` is not a blanket XSS fix: it trusts any script created
    by script that is already trusted. A page that ships a gadget consuming
    attacker-controlled data into ``createElement('script')``/``innerHTML``
    therefore still executes, and no header can tell us whether such a gadget
    exists. The note states what was found and leaves the verdict to a human.
    """
    text = assessment.describe(markup, page_url, limit=limit)
    if not assessment.strict_dynamic():
        return text
    gadgets = strict_dynamic_gadgets(page_html)
    lines = [text] if text else []
    if gadgets:
        found = ", ".join(f"{label} x{count}" for label, count, _ in gadgets)
        lines.append(
            f"strict-dynamic: HTML injection alone cannot load a script, but this "
            f"page's own code contains {len(gadgets)} script-creating gadget(s) "
            f"({found}); if one consumes attacker-controlled data the policy does "
            f"not stop the resulting execution - needs a manual gadget check")
        first = gadgets[0][2]
        if first:
            lines.append(f"strict-dynamic gadget excerpt: {first}")
    else:
        lines.append(
            "strict-dynamic: only nonce/hash scripts can run and no script-creating "
            "gadget was found in this page's code, so a DOM-only execution path "
            "is not established by this page alone")
    jsonp = allowlisted_jsonp(assessment, page_html, page_url)
    if jsonp:
        lines.append("allowlisted JSONP endpoint(s) - the callback must be checked by "
                     "hand, an unescaped one executes from an allowed origin: "
                     + ", ".join(jsonp[:5]))
    return "\n".join(lines)


# Script-creating patterns that turn data into code *inside* an already trusted
# script. Ordered by how often they appear in real bypasses.
_GADGET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("createElement('script')", re.compile(r"createElement\s*\(\s*['\"]script['\"]", re.I)),
    ("innerHTML with <script>", re.compile(r"innerHTML\s*=\s*[^;\n]{0,200}?<script", re.I)),
    ("jQuery/HTML sink with <script>", re.compile(r"\$\(\s*[^)\n]{0,160}?<script", re.I)),
    ("document.write with <script>", re.compile(r"document\.write(?:ln)?\s*\(\s*[^)\n]{0,200}?<script", re.I)),
    ("insertAdjacentHTML with <script>",
     re.compile(r"insertAdjacentHTML\s*\([^)\n]{0,200}?<script", re.I)),
)

_SCRIPT_BLOCK_RE = re.compile(r"<script\b([^>]*)>(.*?)</script\s*>", re.I | re.S)
_CALLBACK_PARAM_RE = re.compile(
    r"[?&](?:callback|cb|jsonp|jsonpCallback|json_callback|_callback)=([^&#\s'\"<>]+)", re.I)

# Bounds: a hostile or enormous page must not turn a note into a CPU sink.
_MAX_HTML = 2_000_000
_MAX_SCRIPTS = 200
_MAX_EXCERPT = 120


def inline_scripts(page_html: str) -> list[str]:
    """Bodies of inline ``<script>`` blocks, bounded in count and length."""
    if not page_html:
        return []
    out: list[str] = []
    for match in _SCRIPT_BLOCK_RE.finditer(page_html[:_MAX_HTML]):
        attrs, body = match.group(1), match.group(2)
        if re.search(r"\bsrc\s*=", attrs, re.I):
            continue
        if re.search(r"\btype\s*=\s*['\"]?(?:application/(?:ld\+)?json|text/template)", attrs, re.I):
            continue
        if body.strip():
            out.append(body)
        if len(out) >= _MAX_SCRIPTS:
            break
    return out


def strict_dynamic_gadgets(page_html: str) -> list[tuple[str, int, str]]:
    """Count script-creating gadgets in the page's inline code.

    Returns ``(label, occurrences, excerpt)``; the excerpt is whitespace-
    collapsed and truncated so it can sit in a finding note. A match is a
    lead -- the gadget still has to receive attacker-controlled data.
    """
    found: list[tuple[str, int, str]] = []
    scripts = inline_scripts(page_html)
    for label, pattern in _GADGET_PATTERNS:
        count = 0
        excerpt = ""
        for script in scripts:
            for match in pattern.finditer(script):
                count += 1
                if not excerpt:
                    snippet = " ".join(match.group(0).split())
                    excerpt = snippet[:_MAX_EXCERPT]
                break
        if count:
            found.append((label, count, excerpt))
    return found


def allowlisted_jsonp(assessment: Assessment, page_html: str, page_url: str = "") -> list[str]:
    """Script URLs on a host the policy trusts that take a callback parameter.

    The classic JSONP bypass: ``<script src=allowed-host/jsonp?callback=...>``
    passes a host allowlist without any nonce. Under ``'strict-dynamic'`` the
    allowlist is ignored for markup-inserted scripts, so this returns nothing:
    claiming a bypass there would be wrong.
    """
    if not assessment.enforced or not page_html or assessment.strict_dynamic():
        return []
    limit = 0
    for policy in assessment.enforced:
        resolved = policy.policy_for_scripts("elem")
        if resolved is not None:
            limit = max(limit, len(resolved[1]))
    if not limit:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for match in re.finditer(r"<script\b[^>]*\bsrc\s*=\s*(['\"]?)([^'\"\s>]+)",
                             page_html[:_MAX_HTML], re.I):
        url = match.group(2)
        if not _CALLBACK_PARAM_RE.search(url):
            continue
        absolute = _absolute(url, page_url) or url
        if absolute in seen:
            continue
        verdict = assessment.feasibility(f'<script src="{absolute}"></script>', page_url)
        if verdict.allowed:
            seen.add(absolute)
            out.append(absolute)
            if len(out) >= 20:
                break
    return out


def _split_policies(value: str) -> list[str]:
    """Split one header value into policies.

    A comma between policies is only a separator when what follows looks like a
    directive name; commas inside a source expression or report URI are not.
    """
    return [chunk.strip() for chunk in _POLICY_SPLIT_RE.split(value or "") if chunk.strip()]


# ---------------------------------------------------------------------------
# Source expression matching
# ---------------------------------------------------------------------------

def _host_of(url: str) -> str:
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return url
    host = parts.hostname or ""
    return f"{parts.scheme}://{host}:{parts.port}" if parts.port else f"{parts.scheme}://{host}"


def _absolute(url: str, base: str) -> str:
    if url.startswith("//"):
        scheme = urllib.parse.urlsplit(base).scheme or "https"
        return f"{scheme}:{url}"
    if re.match(r"^[a-z][a-z0-9+.-]*:", url, re.I):
        return url
    if base:
        return urllib.parse.urljoin(base, url)
    return ""


def source_matches(source: str, url: str, self_origin: str = "") -> bool:
    """Does one CSP source expression allow *url*?

    Implements the parts that decide a script load: ``'self'``, ``*``, scheme
    sources, host sources with optional wildcard/port/path. It deliberately
    ignores nonces and hashes (they cannot be satisfied by injected markup).
    """
    src = (source or "").strip()
    low = src.lower()
    if not src or low in ("'none'", "'unsafe-inline'", "'unsafe-eval'", "'wasm-unsafe-eval'",
                          "'strict-dynamic'", "'report-sample'", "'unsafe-hashes'"):
        return False
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    if not parts.scheme:
        return False
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    port = parts.port or _DEFAULT_PORTS.get(scheme, 0)

    if low == "'self'":
        if not self_origin:
            return False
        try:
            base = urllib.parse.urlsplit(self_origin)
        except ValueError:
            return False
        base_port = base.port or _DEFAULT_PORTS.get(base.scheme.lower(), 0)
        return (base.scheme.lower() == scheme and (base.hostname or "").lower() == host
                and base_port == port)

    if low == "*":
        return scheme in ("http", "https", "ws", "wss", "ftp")

    scheme_match = _SCHEME_SRC_RE.match(src)
    if scheme_match:
        return scheme_match.group(1).lower() == scheme

    match = _HOST_SRC_RE.match(src)
    if not match:
        return False
    src_scheme, src_host, src_port, src_path = match.groups()
    if src_scheme:
        if src_scheme.lower() != scheme:
            return False
    elif scheme not in ("http", "https", "ws", "wss"):
        # A scheme-less host source matches only network schemes, and permits
        # the http -> https upgrade.
        return False
    if not _host_matches(src_host, host):
        return False
    if src_port and src_port != "*":
        if int(src_port) != port:
            return False
    elif not src_port and port != _DEFAULT_PORTS.get(scheme, 0):
        # No port in the source means the scheme's default port only.
        return False
    if src_path:
        path = parts.path or "/"
        if src_path.endswith("/"):
            if not path.startswith(src_path):
                return False
        elif path != src_path and not path.startswith(src_path + "/"):
            return False
    return True


def _host_matches(pattern: str, host: str) -> bool:
    pattern = (pattern or "").lower()
    if pattern == "*":
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]           # ".example.com"
        # Per CSP, *.example.com matches subdomains but not example.com itself.
        return host.endswith(suffix) and host != suffix.lstrip(".")
    return pattern == host
