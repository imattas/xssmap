"""Server-side technology fingerprinting.

The client-library pass (``xssmap.jslib``) answers "is this page running an
outdated jQuery". This module answers the other half: which web server,
language runtime and CMS the responses advertise, and whether that exact
version is known to be vulnerable or out of support.

Everything here is derived from what the target itself sends - ``Server``,
``X-Powered-By``, ``X-AspNet-Version``, ``<meta name=generator>`` and session
cookie names. Nothing is guessed from behaviour, so a row is only ever as
strong as the header it cites, and the evidence column says which one.

Version policy rules are deliberately conservative. A rule is only listed when
the affected range and the fix are public and stable, because a scanner that
cries "outdated" on a patched server is worse than one that stays quiet.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

#: ``Server:`` products worth naming. The regex captures the version that
#: follows the slash; products without one are still reported by name.
SERVER_PATTERNS = (
    (re.compile(r"\bnginx/([0-9][0-9.]*)", re.I), "nginx"),
    (re.compile(r"\bopenresty/([0-9][0-9.]*)", re.I), "openresty"),
    (re.compile(r"\bApache/([0-9][0-9.]*)", re.I), "Apache httpd"),
    (re.compile(r"\bMicrosoft-IIS/([0-9][0-9.]*)", re.I), "Microsoft IIS"),
    (re.compile(r"\bLiteSpeed\b", re.I), "LiteSpeed"),
    (re.compile(r"\bCaddy\b", re.I), "Caddy"),
    (re.compile(r"\bcloudflare\b", re.I), "Cloudflare"),
    (re.compile(r"\bAmazonS3\b", re.I), "Amazon S3"),
    (re.compile(r"\bGitHub\.com\b", re.I), "GitHub Pages"),
)

POWERED_BY_PATTERNS = (
    (re.compile(r"\bPHP/([0-9][0-9.]*)", re.I), "PHP"),
    (re.compile(r"\bASP\.NET\b", re.I), "ASP.NET"),
    (re.compile(r"\bExpress\b", re.I), "Express"),
    (re.compile(r"\bNext\.js\b", re.I), "Next.js"),
    (re.compile(r"\bServlet/([0-9][0-9.]*)", re.I), "Java Servlet"),
    (re.compile(r"\bPhusion Passenger\b", re.I), "Phusion Passenger"),
)

GENERATOR_PATTERNS = (
    (re.compile(r"WordPress\s*([0-9][0-9.]*)", re.I), "WordPress"),
    (re.compile(r"Drupal\s*([0-9][0-9.]*)", re.I), "Drupal"),
    (re.compile(r"Joomla!?\s*([0-9][0-9.]*)", re.I), "Joomla"),
    (re.compile(r"TYPO3\s*([0-9][0-9.]*)", re.I), "TYPO3"),
    (re.compile(r"Ghost\s*([0-9][0-9.]*)", re.I), "Ghost"),
)

#: Session cookie names that identify a runtime even when every other header is
#: stripped. No version is implied, so these rows carry ``version=""``.
COOKIE_TECH = {
    "phpsessid": "PHP",
    "jsessionid": "Java",
    "asp.net_sessionid": "ASP.NET",
    "aspsessionid": "Classic ASP",
    "laravel_session": "Laravel",
    "ci_session": "CodeIgniter",
    "django_session": "Django",
    "rack.session": "Ruby Rack",
    "connect.sid": "Express",
}


@dataclass
class Tech:
    name: str
    version: str
    source: str
    status: str = "detected"      # detected | outdated | vulnerable
    detail: str = ""
    cves: list[str] = field(default_factory=list)
    severity: str = "info"

    def line(self) -> str:
        ver = f" {self.version}" if self.version else ""
        tail = f" - {self.detail}" if self.detail else ""
        return f"{self.name}{ver} ({self.source}){tail}"


def _ver_tuple(value: str) -> tuple[int, ...]:
    """Numeric parts of a version, so 1.20.10 sorts above 1.20.9."""
    parts: list[int] = []
    for chunk in (value or "").split("."):
        digits = re.match(r"\d+", chunk)
        if not digits:
            break
        parts.append(int(digits.group()))
    return tuple(parts)


def _cmp(left: str, right: str) -> int:
    """Compare two dotted versions, padding the shorter one with zeros."""
    a, b = _ver_tuple(left), _ver_tuple(right)
    width = max(len(a), len(b))
    a += (0,) * (width - len(a))
    b += (0,) * (width - len(b))
    return (a > b) - (a < b)


@dataclass(frozen=True)
class Rule:
    """A version range with a published consequence."""

    name: str
    op: str
    bound: str
    detail: str
    cves: tuple[str, ...] = ()
    severity: str = "medium"

    def matches(self, version: str) -> bool:
        if not version:
            return False
        if self.op == "eq":
            return _cmp(version, self.bound) == 0
        if self.op == "lt":
            return _cmp(version, self.bound) < 0
        if self.op == "le":
            return _cmp(version, self.bound) <= 0
        if self.op == "prefix":
            return version == self.bound or version.startswith(self.bound + ".")
        return False


#: Only well-known, still-cited issues. Each one is public, has a fixed release
#: and is cheap to verify against the cited advisory.
RULES = (
    Rule("Apache httpd", "eq", "2.4.49",
         "path traversal and remote code execution when mod_cgi is enabled",
         ("CVE-2021-41773",), "critical"),
    Rule("Apache httpd", "eq", "2.4.50",
         "incomplete fix for CVE-2021-41773, still exploitable",
         ("CVE-2021-42013",), "critical"),
    Rule("nginx", "lt", "1.20.1",
         "resolver off-by-one heap write (fixed in 1.20.1 / 1.21.0)",
         ("CVE-2021-23017",), "high"),
    Rule("PHP", "lt", "8.2",
         "branch is out of security support (8.1 reached end of life 2025-12-31)",
         (), "high"),
    Rule("Microsoft IIS", "prefix", "6.0",
         "ships only with Windows Server 2003, which is out of support", (), "medium"),
    Rule("Microsoft IIS", "prefix", "7.0",
         "ships only with Windows Server 2008, which is out of support", (), "medium"),
    Rule("Microsoft IIS", "prefix", "7.5",
         "ships only with Windows Server 2008 R2, which is out of support", (), "medium"),
    Rule("Microsoft IIS", "prefix", "8.0",
         "ships only with Windows Server 2012, which is out of support", (), "medium"),
    Rule("Microsoft IIS", "prefix", "8.5",
         "ships only with Windows Server 2012 R2, which is out of support", (), "medium"),
)


def _apply_rules(tech: Tech) -> Tech:
    for rule in RULES:
        if rule.name.lower() != tech.name.lower() or not rule.matches(tech.version):
            continue
        tech.status = "vulnerable" if rule.cves else "outdated"
        tech.detail = rule.detail
        tech.cves = list(rule.cves)
        tech.severity = rule.severity
        return tech
    return tech


def _header_values(headers, name: str) -> list[str]:
    wanted = name.lower()
    return [str(v) for k, v in (headers or []) if str(k).lower() == wanted]


def _cookie_names(headers) -> list[str]:
    names: list[str] = []
    for raw in _header_values(headers, "set-cookie"):
        first = raw.split(";", 1)[0]
        if "=" in first:
            names.append(first.split("=", 1)[0].strip().lower())
    return names


def detect(headers, generator: str = "") -> list[Tech]:
    """Identify server-side technologies from response headers.

    ``generator`` is the content of ``<meta name="generator">`` when the scanner
    has the page body; it is what identifies most CMS installs.
    """
    found: list[Tech] = []
    seen: set[tuple[str, str]] = set()

    def add(name: str, version: str, source: str) -> None:
        key = (name.lower(), version)
        if key in seen:
            return
        if not version and any(t.name.lower() == name.lower() and t.version
                               for t in found):
            # A versioned row already names this product; a versionless one
            # (usually a cookie) would only repeat it with less information.
            return
        seen.add(key)
        found.append(_apply_rules(Tech(name=name, version=version, source=source)))

    for value in _header_values(headers, "server"):
        for pattern, name in SERVER_PATTERNS:
            match = pattern.search(value)
            if match:
                add(name, match.group(1) if match.groups() else "", "Server")

    for value in _header_values(headers, "x-powered-by"):
        for pattern, name in POWERED_BY_PATTERNS:
            match = pattern.search(value)
            if match:
                add(name, match.group(1) if match.groups() else "", "X-Powered-By")

    for value in _header_values(headers, "x-aspnet-version"):
        add("ASP.NET", value.strip(), "X-AspNet-Version")

    for value in _header_values(headers, "x-generator"):
        for pattern, name in GENERATOR_PATTERNS:
            match = pattern.search(value)
            if match:
                add(name, match.group(1), "X-Generator")

    if generator:
        for pattern, name in GENERATOR_PATTERNS:
            match = pattern.search(generator)
            if match:
                add(name, match.group(1), "meta generator")

    for cookie in _cookie_names(headers):
        product = COOKIE_TECH.get(cookie)
        if product:
            add(product, "", f"cookie {cookie}")

    return found


def rows(techs: list[Tech]) -> list[dict]:
    """Serialise for the report meta (JSON, Markdown and HTML all read this)."""
    return [
        {
            "name": t.name,
            "version": t.version,
            "source": t.source,
            "status": t.status,
            "severity": t.severity,
            "cves": list(t.cves),
            "detail": t.detail,
        }
        for t in techs
    ]


def summary(techs: list[Tech]) -> dict:
    """Counts per status, so ``detected`` means "found and nothing wrong"."""
    return {
        "detected": sum(1 for t in techs if t.status == "detected"),
        "outdated": sum(1 for t in techs if t.status == "outdated"),
        "vulnerable": sum(1 for t in techs if t.status == "vulnerable"),
    }
