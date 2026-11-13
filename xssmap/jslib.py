"""Client-side library fingerprinting with known-vulnerability hints.

A scan produces a list of JavaScript resources anyway; reading their banners for
a name and version costs nothing extra. The value is in the mapping: jQuery
before 3.5.0 still has the ``htmlPrefilter`` XSS, old DOMPurify has mutation
bypasses, old Handlebars is remote code execution. Those are leads a payload
ladder will never find on its own, because the vulnerable code is the
application's own dependency, not the reflected parameter.

Three rules keep this honest:

* a version is only reported when it was read from the resource itself (banner,
  ``VERSION`` assignment, or the filename), with the evidence quoted;
* an advisory is only applied inside its published version *range*
  (``introduced <= version < fixed``). A single "fixed in" number cannot say
  "3.x below 3.4.1, and 4.x below 4.3.1", and using one that way flags every
  2.x and 5.x release as vulnerable - a false positive a reviewer will catch;
* "outdated" is not "vulnerable". The output names the CVE and the fixed
  version, and the report distinguishes what was observed from what was applied.

:func:`enrich_osv` can add advisories from the OSV database at run time, so the
table below does not have to be the only source of truth.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Signature:
    name: str
    body_rx: tuple[str, ...] = ()
    file_rx: str = ""
    note: str = ""


@dataclass(frozen=True)
class Vuln:
    """An affected version range: ``introduced <= version < fixed``.

    ``introduced`` is empty for "every release before the fix", which is the
    common case for a library's first advisory. ``fixed`` is required: a range
    with no fixed version cannot be evaluated and is ignored rather than
    guessed at.
    """

    detail: str
    fixed: str
    cves: tuple[str, ...] = ()
    severity: str = "medium"
    introduced: str = ""

    def affects(self, version: str) -> bool:
        if not self.fixed or not _below(version, self.fixed):
            return False
        # An advisory that names the version it was introduced in must not be
        # applied backwards (it covers 3.0.0-3.4.0, not everything below 3.4.1).
        return not (self.introduced and _below(version, self.introduced))


SIGNATURES: tuple[Signature, ...] = (
    Signature("jQuery",
              body_rx=(r"(?i)jQuery\s*(?:JavaScript Library\s*)?v?(\d+\.\d+(?:\.\d+)?)",
                       r"jQuery\.fn\.jquery\s*=\s*[\"']([\d.]+)[\"']"),
              file_rx=r"(?i)jquery[.-](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js"),
    Signature("jQuery UI",
              body_rx=(r"(?i)jQuery UI[^\n]{0,40}?v?(\d+\.\d+\.\d+)",),
              file_rx=r"(?i)jquery-ui[.-](\d+\.\d+\.\d+)"),
    Signature("Bootstrap",
              body_rx=(r"(?i)Bootstrap\s*v?(\d+\.\d+\.\d+)",),
              file_rx=r"(?i)bootstrap(?:\.bundle)?(?:\.min)?[.-](\d+\.\d+\.\d+)"),
    Signature("AngularJS",
              body_rx=(r"(?i)@license AngularJS v(\d+\.\d+\.\d+)",
                       r"(?i)angular\.version\s*=\s*\{[^}]*full:\s*[\"']([\d.]+)"),
              file_rx=r"(?i)angular(?:\.min)?[.-](\d+\.\d+\.\d+)"),
    Signature("Lodash",
              body_rx=(r"(?i)lodash[^\n]{0,80}?VERSION\s*=\s*[\"']([\d.]+)[\"']",
                       r"(?i)VERSION\s*=\s*[\"']([\d.]+)[\"'][^\n]{0,80}?lodash"),
              file_rx=r"(?i)lodash(?:\.min)?[.-](\d+\.\d+\.\d+)"),
    Signature("Moment.js",
              body_rx=(r"(?i)moment\.js[^\n]{0,80}?version\s*[:=]\s*[\"']([\d.]+)",
                       r"(?i)hooks\.version\s*=\s*[\"']([\d.]+)[\"']"),
              file_rx=r"(?i)moment(?:\.min)?[.-](\d+\.\d+\.\d+)"),
    Signature("DOMPurify",
              body_rx=(r"(?i)DOMPurify\.version\s*=\s*[\"']([\d.]+)[\"']",
                       r"(?i)purify(?:\.min)?\.js[^\n]{0,80}?([\d]+\.[\d]+\.[\d]+)"),
              file_rx=r"(?i)(?:dompurify|purify)(?:\.min)?[.-](\d+\.\d+\.\d+)"),
    Signature("Handlebars",
              body_rx=(r"(?i)Handlebars\.VERSION\s*=\s*[\"']([\d.]+)[\"']",),
              file_rx=r"(?i)handlebars(?:\.min)?[.-](\d+\.\d+\.\d+)"),
    Signature("Underscore.js",
              body_rx=(r"(?i)_\.VERSION\s*=\s*[\"']([\d.]+)[\"']",),
              file_rx=r"(?i)underscore(?:\.min)?[.-](\d+\.\d+\.\d+)"),
    Signature("Axios",
              body_rx=(r"(?i)axios[^\n]{0,80}?VERSION\s*=\s*[\"']([\d.]+)[\"']",
                       r"(?i)VERSION\s*=\s*[\"']([\d.]+)[\"'][^\n]{0,80}?axios"),
              file_rx=r"(?i)axios(?:\.min)?[.-](\d+\.\d+\.\d+)"),
    Signature("React",
              body_rx=(r"(?i)ReactVersion\s*=\s*[\"']([\d.]+)[\"']",),
              file_rx=r"(?i)react(?:\.production(?:\.min)?)?[.-](\d+\.\d+\.\d+)"),
    Signature("Vue.js",
              body_rx=(r"(?i)vue(?:\.runtime)?[^\n]{0,40}?version\s*[:=]\s*[\"']([\d.]+)",
                       r"(?i)Vue\.version\s*=\s*[\"']([\d.]+)[\"']"),
              file_rx=r"(?i)vue(?:\.runtime)?(?:\.min)?[.-](\d+\.\d+\.\d+)"),
    Signature("marked",
              body_rx=(r"(?i)marked[^\n]{0,60}?version[^\n]{0,20}?([\d]+\.[\d]+\.[\d]+)",),
              file_rx=r"(?i)marked(?:\.min)?[.-](\d+\.\d+\.\d+)"),
)

# Ranges, not "fixed-in" numbers. Every entry states the first affected release
# when the advisory does not cover the library's whole history.
VULNS: dict[str, tuple[Vuln, ...]] = {
    "jQuery": (
        Vuln("htmlPrefilter allows XSS through crafted HTML passed to .html()/.append()",
             "3.5.0", ("CVE-2020-11022", "CVE-2020-11023"), "medium"),
        Vuln("Selector-based XSS when $(location.hash) style lookups are used",
             "1.9.0", ("CVE-2012-6708",), "medium"),
        Vuln("Cross-domain ajax requests can be used to read responses",
             "3.0.0", ("CVE-2015-9251",), "low"),
    ),
    "jQuery UI": (
        Vuln("XSS in the checkboxradio widget's refresh method",
             "1.13.2", ("CVE-2022-31160",), "medium", introduced="1.13.0"),
        Vuln("XSS in the dialog title option",
             "1.13.2", ("CVE-2022-31160",), "medium"),
    ),
    "Bootstrap": (
        Vuln("Tooltip/popover data-template XSS",
             "3.4.1", ("CVE-2019-8331",), "medium", introduced="3.0.0"),
        Vuln("Tooltip/popover data-template XSS (4.x line)",
             "4.3.1", ("CVE-2019-8331",), "medium", introduced="4.0.0"),
        Vuln("Prototype pollution in util.extend",
             "3.4.0", ("CVE-2019-5428",), "medium", introduced="3.0.0"),
    ),
    "AngularJS": (
        Vuln("angular.element XSS via crafted attributes",
             "1.8.0", ("CVE-2020-7676",), "medium", introduced="1.0.0"),
        Vuln("Template sandbox escape in 1.5 era releases",
             "1.6.0", ("CVE-2016-4055",), "high", introduced="1.5.0"),
    ),
    "Lodash": (
        Vuln("Command injection in template compilation",
             "4.17.21", ("CVE-2021-23337",), "high"),
        Vuln("Prototype pollution via zipObjectDeep/merge",
             "4.17.20", ("CVE-2020-8203",), "high"),
    ),
    "Moment.js": (
        Vuln("ReDoS in duration parsing",
             "2.29.4", ("CVE-2022-31129",), "high"),
        Vuln("Path traversal in locale loading",
             "2.29.2", ("CVE-2022-24785",), "high"),
    ),
    "DOMPurify": (
        Vuln("Mutation XSS through namespace confusion",
             "2.0.17", ("CVE-2020-26870",), "medium", introduced="2.0.0"),
        Vuln("Mutation XSS through improperly nested content",
             "3.0.11", ("CVE-2024-45801",), "high", introduced="3.0.0"),
    ),
    "Handlebars": (
        Vuln("Remote code execution when compiling untrusted templates",
             "4.7.7", ("CVE-2021-23369",), "critical", introduced="4.0.0"),
    ),
    "Underscore.js": (
        Vuln("Code injection through the template function",
             "1.12.1", ("CVE-2021-23358",), "high"),
    ),
    "Axios": (
        Vuln("ReDoS in the URL parser",
             "0.21.2", ("CVE-2021-3749",), "high", introduced="0.0.0"),
        Vuln("XSRF token leaked to third-party hosts",
             "1.6.0", ("CVE-2023-45857",), "medium", introduced="1.0.0"),
    ),
    "React": (
        Vuln("XSS in server-side rendering of attributes",
             "16.4.2", ("CVE-2018-6341",), "medium", introduced="16.0.0"),
    ),
    "marked": (
        Vuln("ReDoS in the markdown parser",
             "4.0.10", ("CVE-2022-21680", "CVE-2022-21681"), "high",
             introduced="4.0.0"),
    ),
}

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

#: A single OSV record can list dozens of CVEs (DOMPurify 2.0.0 has 24).  The
#: report keeps them all in JSON but prints the worst few, because a wall of
#: identifiers stops being readable long before it stops being accurate.
MAX_LINE_CVES = 8

# npm package names for libraries whose package name differs from the display
# name, used when asking OSV.
NPM_NAMES = {
    "jQuery": "jquery",
    "jQuery UI": "jquery-ui",
    "Bootstrap": "bootstrap",
    "AngularJS": "angular",
    "Lodash": "lodash",
    "Moment.js": "moment",
    "DOMPurify": "dompurify",
    "Handlebars": "handlebars",
    "Underscore.js": "underscore",
    "Axios": "axios",
    "React": "react",
    "Vue.js": "vue",
    "marked": "marked",
}


@dataclass
class Library:
    name: str
    version: str
    source: str
    evidence: str
    cves: list[str]
    severity: str
    detail: str = ""
    fixed_in: str = ""
    # Human-readable affected ranges (e.g. ">=3.0.0 <3.4.1"), filled by advisories().
    ranges: list[str] = field(default_factory=list)

    @property
    def vulnerable(self) -> bool:
        return bool(self.cves)

    def line(self) -> str:
        if self.cves:
            where = f" at {self.source}" if self.source else ""
            shown = ", ".join(self.cves[:MAX_LINE_CVES])
            if len(self.cves) > MAX_LINE_CVES:
                shown += f" (+{len(self.cves) - MAX_LINE_CVES} more)"
            return (f"{self.name} {self.version}{where} - "
                    f"{shown} (fixed in {self.fixed_in}): {self.detail}")
        return f"{self.name} {self.version}{' at ' + self.source if self.source else ''}"

    def as_dict(self) -> dict:
        return {"name": self.name, "version": self.version, "source": self.source,
                "evidence": self.evidence, "cves": list(self.cves),
                "severity": self.severity, "detail": self.detail,
                "fixed_in": self.fixed_in, "vulnerable": self.vulnerable,
                "affected_ranges": list(self.ranges)}


def _vt(version: str) -> tuple[int, ...]:
    parts = []
    for piece in re.split(r"[.\-+]", version or ""):
        if piece.isdigit():
            parts.append(int(piece))
        else:
            break
    return tuple(parts)


def _below(version: str, fixed: str) -> bool:
    """True when ``version`` is older than ``fixed``; false when unparseable."""
    a, b = _vt(version), _vt(fixed)
    if not a or not b:
        return False
    width = max(len(a), len(b))
    return a + (0,) * (width - len(a)) < b + (0,) * (width - len(b))


def _match(sig: Signature, url: str, body: str) -> tuple[str, str] | None:
    for pattern in sig.body_rx:
        try:
            found = re.search(pattern, body)
        except re.error:
            continue
        if found:
            version = found.group(1)
            snippet = body[max(0, found.start() - 20):found.end() + 20].replace("\n", " ")
            return version, f"body: {snippet.strip()[:90]}"
    if sig.file_rx:
        try:
            found = re.search(sig.file_rx, url)
        except re.error:
            found = None
        if found:
            label = "inline script in page" if url.endswith("#inline") else \
                url.rsplit("/", 1)[-1][:90]
            return found.group(1), f"filename: {label}"
    return None


def advisories(name: str, version: str) -> tuple[list[str], str, str, str, list[str]]:
    """Advisories affecting exactly this version.

    Returns ``(cves, severity, detail, fixed_in, range_labels)``. Multiple ranges
    can match one version (different issues); all of their CVEs are reported and
    the highest severity wins, because reporting only the first match hides the
    more serious advisory.
    """
    cves: list[str] = []
    severity = "info"
    details: list[str] = []
    fixes: list[str] = []
    labels: list[str] = []
    for vuln in VULNS.get(name, ()):
        if not vuln.affects(version):
            continue
        cves.extend(vuln.cves)
        if SEVERITY_RANK.get(vuln.severity, 0) > SEVERITY_RANK.get(severity, 0):
            severity = vuln.severity
        details.append(vuln.detail)
        fixes.append(vuln.fixed)
        lo = vuln.introduced or "0"
        labels.append(f">={lo} <{vuln.fixed}")
    # The upgrade target is the *highest* fix among the matched advisories:
    # "upgrade to 3.5.0" clears both the 3.0.0 and the 3.5.0 issues, whereas a
    # list of every fix reads like several separate upgrade paths.
    fixed_in = max(fixes, key=_vt) if fixes else ""
    return (sorted(set(cves)), severity, "; ".join(dict.fromkeys(details)),
            fixed_in, labels)


def scan(js_resources) -> list[Library]:
    """Fingerprint ``(url, body, pages)`` resources and attach CVE hints."""
    out: dict[tuple[str, str], Library] = {}
    for item in js_resources or []:
        try:
            url, body, _pages = item
        except (TypeError, ValueError):
            continue
        body = body or ""
        for sig in SIGNATURES:
            found = _match(sig, url, body)
            if not found:
                continue
            version, evidence = found
            key = (sig.name, version)
            if key in out:
                continue
            cves, severity, detail, fixed_in, labels = advisories(sig.name, version)
            out[key] = Library(sig.name, version, url, evidence, cves, severity,
                               detail, fixed_in, labels)
    return sorted(out.values(), key=lambda lib: (
        -SEVERITY_RANK.get(lib.severity, 0), lib.name.lower(), _vt(lib.version)))


def report(libs: list[Library], log=None) -> list[dict]:
    """Log one line per library and return the report-ready list."""
    for lib in libs:
        if log is None:
            continue
        if lib.vulnerable:
            log.warn("  outdated client library: " + lib.line())
        else:
            log.debug("  client library: " + lib.line())
    return [lib.as_dict() for lib in libs]


def summary(libs: list[Library]) -> dict:
    return {
        "detected": len(libs),
        "outdated": sum(1 for lib in libs if lib.vulnerable),
        "libraries": [lib.as_dict() for lib in libs],
    }


# ---------------------------------------------------------------------------
# Optional live advisories
# ---------------------------------------------------------------------------

OSV_ENDPOINT = "https://api.osv.dev/v1/query"


def _osv_query(http, package: str, version: str) -> list[dict]:
    payload = json.dumps({
        "package": {"name": package, "ecosystem": "npm"},
        "version": version,
    }).encode("utf-8")
    resp = http.post(OSV_ENDPOINT, payload,
                     headers=[("Content-Type", "application/json")])
    if getattr(resp, "status", 0) != 200:
        return []
    try:
        data = json.loads(getattr(resp, "text", "") or "{}")
    except (ValueError, TypeError):
        return []
    vulns = data.get("vulns") or []
    return vulns if isinstance(vulns, list) else []


def enrich_osv(libs: list[Library], http, log=None, max_lookups: int = 12) -> int:
    """Merge advisories from OSV into the local results.

    The local table is a curated shortcut; OSV is authoritative and current.
    Lookups are capped and every failure is swallowed: an unavailable advisory
    service must not fail a scan or silently change a verdict. Returns the
    number of libraries that gained at least one advisory.
    """
    changed = 0
    looked_up = 0
    for lib in libs:
        if looked_up >= max_lookups:
            break
        package = NPM_NAMES.get(lib.name)
        if not package or not _vt(lib.version):
            # An unknown version would make OSV reply with *every* advisory for
            # the package, which reads as "this build is vulnerable to all of
            # them".  Better to say nothing than to invent that.
            continue
        looked_up += 1
        try:
            vulns = _osv_query(http, package, lib.version)
        except Exception as exc:
            if log is not None:
                log.debug(f"    osv lookup failed for {lib.name}: {str(exc)[:80]}")
            continue
        found: list[str] = []
        for entry in vulns:
            for alias in entry.get("aliases") or []:
                if isinstance(alias, str) and alias.startswith("CVE-"):
                    found.append(alias)
            ident = entry.get("id")
            if isinstance(ident, str) and ident.startswith("CVE-"):
                found.append(ident)
        new = sorted(set(found) - set(lib.cves))
        if not new:
            continue
        lib.cves = sorted(set(lib.cves) | set(found))
        if not lib.detail:
            lib.detail = "reported by OSV for this version"
        if not lib.fixed_in:
            lib.fixed_in = "see advisory"
        if SEVERITY_RANK.get(lib.severity, 0) < SEVERITY_RANK["medium"]:
            lib.severity = "medium"
        note = ", ".join(new[:6]) + (f" (+{len(new) - 6} more)" if len(new) > 6 else "")
        lib.evidence = (lib.evidence + "; osv: " + note)[:400]
        changed += 1
        if log is not None:
            log.info(f"  OSV added {', '.join(new)} for {lib.name} {lib.version}")
    return changed
