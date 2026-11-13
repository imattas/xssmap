"""Reporting: console, JSON, Markdown and a self-contained HTML report."""
from __future__ import annotations

import html
import json
import os
import re

from . import __version__ as _pkg_version
from . import repro

# One source of truth: pyproject.toml reads xssmap.__version__ at build time and
# every report, banner and User-Agent string uses the same value.
VERSION = _pkg_version

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
GREY = "\033[90m"

# Short aliases used by the logo. They resolve to the same codes as the named
# colours above, so a palette change happens in one place.
Y = YELLOW            # bright yellow
DG = GREY             # dark gray
RY = "\033[43m"       # yellow background
RR = "\033[41m"       # red background
N = RESET             # none

ANSI_RX = re.compile(r"\x1b\[[0-9;]*m")

# The logo is the sqlmap-style block layout, redrawn for xssmap. Placeholders are
# filled by render_banner(); the art itself contains no other braces, which is
# why str.format is safe here.
BANNER_ART = (
    "            {Y}___{N}\n"
    "           {Y}__H__{N}\n"
    " {Y}_ _ ___ ___[{RR}\"{N}{Y}]_____ ___ ___{N}\n"
    "{Y}|_'_|_ -|_ -[{RR}\"{N}{Y}]     | .'| . |{N}\n"
    "{Y}|_,_|___|___[{RR}\"{N}{Y}]_|_|_|__,|  _|{N}\n"
    "             {Y}V{ver}|_|{N}"
)


def strip_ansi(text: str) -> str:
    return ANSI_RX.sub("", text)


def render_banner(version: str = VERSION, summary: str = "", color: bool = True) -> str:
    """Logo plus one status line, in the style of the sqlmap splash.

    The version sits where sqlmap puts it (after the ``V``) and the padding keeps
    the right-hand ``|_|`` column fixed, so a longer version does not shift the
    artwork.
    """
    pad = " " * max(1, 10 - len(version))
    art = BANNER_ART.format(Y=Y, N=N, RR=RR, ver=version + pad)
    if summary:
        art += "\n" + DG + "  " + summary + N
    return art if color else strip_ansi(art)


VERIFY_LABEL = {
    "confirmed": "confirmed",
    "not_observed": "not observed",
    "not_tested": "NOT TESTED",
}


def verify_label(f) -> str:
    """Human label for the tri-state browser verdict ('' when never attempted)."""
    return VERIFY_LABEL.get(getattr(f, "verify_state", "") or "", "not attempted")


def exploit_state(f) -> str:
    """proven / unproven / not_tested / '' (stage never ran)."""
    return str((getattr(f, "exploit", None) or {}).get("status") or "")


def severity_of(f) -> str:
    if exploit_state(f) == "proven":
        # Script execution was not merely reflected: it ran and reached data.
        return "high"
    if f.confidence == "low":
        return "low"
    if getattr(f, "csp_blocked", False):
        return "medium"  # reflection is real, execution is stopped today by policy
    if f.verified_browser:
        return "high"
    if f.interaction:
        return "medium"
    return "high" if f.confidence == "high" else "medium"


def severity_colour(sev: str) -> str:
    return {"high": RED, "medium": YELLOW, "low": CYAN}.get(sev, GREY)


def dedupe(findings: list) -> list:
    """Collapse identical root causes (same URL+param+context)."""
    seen, out = set(), []
    for f in sorted(findings, key=lambda x: (severity_of(x) != "high", x.url, x.param)):
        key = (f.method, f.url.split("#")[0], f.param, f.context, f.location)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


# ---------------------------------------------------------------------------
# Console
# ---------------------------------------------------------------------------

class Console:
    def __init__(self, quiet: bool = False, color: bool = True, verbose: bool = False):
        self.quiet = quiet
        self.color = color
        self.verbose = verbose
        self._bar_open = False

    def _clear_bar(self):
        """Erase a half-drawn progress line so real output starts on a clean row."""
        if self._bar_open and not self.quiet:
            print("\r" + " " * 96 + "\r", end="", flush=True)
        self._bar_open = False

    def _c(self, code: str, text: str) -> str:
        return f"{code}{text}{RESET}" if self.color else text

    def splash(self, version: str = VERSION, summary: str = ""):
        """Program logo and target summary, printed once at start-up."""
        if self.quiet:
            return
        self._clear_bar()
        print()
        print(render_banner(version, summary, color=self.color))
        print()

    def banner(self, text: str):
        if self.quiet:
            return
        self._clear_bar()
        print()
        print(self._c(BOLD + MAGENTA, text))
        print(self._c(GREY, "-" * min(72, max(30, len(text)))))

    def info(self, text: str):
        if not self.quiet:
            print(self._c(GREY, "  " + text), flush=True)

    def action(self, text: str):
        if not self.quiet:
            print(self._c(CYAN, "[*] ") + text, flush=True)

    def debug(self, text: str):
        if self.verbose and not self.quiet:
            print(self._c(GREY, "    " + text), flush=True)

    def warn(self, text: str):
        print(self._c(YELLOW, "[!] ") + text, flush=True)

    def error(self, text: str):
        print(self._c(RED, "[-] ") + text, flush=True)

    def ok(self, text: str):
        print(self._c(GREEN, "[+] ") + text, flush=True)

    def found(self, f):
        sev = severity_of(f)
        col = severity_colour(sev)
        if f.verified_browser:
            tag = "CONFIRMED"
        elif getattr(f, "verify_state", "") == "not_tested":
            tag = "UNVERIFIED"
        else:
            tag = "REFLECTED" if f.confidence != "low" else "REVIEW"
        self._clear_bar()
        print()
        print(self._c(col + BOLD, f"  [{sev.upper()}] XSS ({tag}) ") + self._c(BOLD, f"{f.method} {f.param}"))
        print(f"      {f.url[:160]}")
        verdict = verify_label(f)
        print(self._c(GREY, f"      context: {f.context}   confidence: {f.confidence}"
                            + (f"   browser: {verdict}" if getattr(f, "verify_state", "") else "")))
        if getattr(f, "verify_state", "") == "not_tested" and getattr(f, "verify_reason", ""):
            print(self._c(YELLOW, f"      no execution verdict: {f.verify_reason[:150]}"))
        print(f"      payload: {f.payload[:150]}")
        exploit = getattr(f, "exploit", None) or {}
        if exploit.get("status") == "proven":
            print(self._c(GREEN, f"      exploit PROVEN ({exploit.get('technique', 'payload')}): "
                                 f"{str(exploit.get('impact', ''))[:220]}"))
        elif exploit.get("status") in ("unproven", "not_tested"):
            print(self._c(YELLOW, f"      exploit {exploit['status']}: "
                                     f"{str(exploit.get('reason', ''))[:180]}"))

    def progress(self, done: int, total: int, label: str):
        if self.quiet:
            return
        bar_len = 24
        frac = done / total if total else 1
        filled = int(bar_len * frac)
        bar = "#" * filled + "-" * (bar_len - filled)
        print(f"\r  {self._c(GREY, '[' + bar + ']')} {done}/{total}  {label[:46]:<46}",
              end="", flush=True)
        self._bar_open = done < total
        if done >= total:
            print()


# ---------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------

def finding_to_dict(f) -> dict:
    return {
        "url": f.url,
        "method": f.method,
        "parameter": f.param,
        "location": f.location,
        "payload": f.payload,
        "context": f.context,
        "severity": severity_of(f),
        "confidence": f.confidence,
        "browser_verified": f.verified_browser,
        "browser_checked": getattr(f, "browser_checked", False),
        "verify_state": getattr(f, "verify_state", ""),
        "verify_reason": getattr(f, "verify_reason", ""),
        "csp_blocked": getattr(f, "csp_blocked", False),
        "csp": getattr(f, "csp", ""),
        "requires_interaction": f.interaction,
        "http_status": f.status,
        "content_type": f.content_type,
        "nosniff": f.nosniff,
        "reflection_count": f.reflections,
        "filter_profile": f.encoding,
        "notes": f.notes,
        "template": getattr(f, "template", "") or "",
        "payload_name": getattr(f, "payload_name", "") or "",
        "exploit": getattr(f, "exploit", None) or {},
        "evidence": f.evidence,
        "cvss": repro.cvss_for(f),
        "reproduction": repro.curl_for(f),
        "severity_change_conditions": repro.severity_conditions(f),
    }


def build_meta(targets, started, finished, stats, crawl_stats=None, browser_note="", command="") -> dict:
    return {
        "tool": f"xssmap {VERSION}",
        "targets": targets,
        "started": started.isoformat(timespec="seconds"),
        "finished": finished.isoformat(timespec="seconds"),
        "duration_s": round((finished - started).total_seconds(), 1),
        "statistics": stats,
        "crawl": crawl_stats or {},
        "browser_verification": browser_note,
        "command": command,
    }


def write_json(path: str, findings: list, meta: dict) -> str:
    data = dict(meta)
    data["findings"] = [finding_to_dict(f) for f in findings]
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    return path


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

def write_markdown(path: str, findings: list, meta: dict) -> str:
    lines = []
    lines.append("# xssmap scan report\n")
    lines.append(f"- **Target(s):** {', '.join(meta.get('targets') or [])}")
    lines.append(f"- **Started:** {meta.get('started')}")
    lines.append(f"- **Finished:** {meta.get('finished')}")
    lines.append(f"- **Duration:** {meta.get('duration_s')}s")
    stats = meta.get("statistics") or {}
    lines.append(f"- **Injection points tested:** {stats.get('points', 0)}")
    lines.append(f"- **Reflected points:** {stats.get('reflected_points', 0)}")
    lines.append(f"- **Findings:** {len(findings)}")
    if _lead_rows(meta):
        lines.append(f"- **Unconfirmed leads:** {len(_lead_rows(meta))}")
    lines.append(f"- **Browser verification:** {meta.get('browser_verification')}")
    verification = meta.get("verification") or {}
    if verification:
        lines.append(f"- **Exploit stage:** {verification.get('proven', 0)} proven, "
                     f"{verification.get('unproven', 0)} unproven, "
                     f"{verification.get('not_tested', 0)} not tested")
    lines.append("")
    if meta.get("interrupted"):
        lines.append("> **This scan was interrupted.** The report contains only the tests "
                     "that completed before the stop; anything not listed was not assessed.")
        lines.append("")

    if not findings:
        lines.append("No cross-site scripting was confirmed.\n")
    else:
        lines.append("## Summary\n")
        lines.append("| # | Severity | Method | Parameter | Context | Browser | URL |")
        lines.append("|---|----------|--------|-----------|---------|---------|-----|")
        for i, f in enumerate(findings, 1):
            lines.append(
                f"| {i} | {severity_of(f)} | {f.method} | `{f.param}` | {f.context} | "
                f"{verify_label(f)} | {_md(f.url)} |")
        lines.append("")

        for i, f in enumerate(findings, 1):
            lines.append(f"## {i}. {severity_of(f).upper()} — {f.method} parameter `{f.param}`\n")
            lines.append(f"- **URL:** {_md(f.url)}")
            lines.append(f"- **Injection point:** {f.location} / `{f.param}`")
            lines.append(f"- **Reflection context:** `{f.context}`")
            lines.append(f"- **Confidence:** {f.confidence}"
                         + (" (confirmed in browser)" if f.verified_browser else " (static analysis)"))
            if getattr(f, "verify_state", ""):
                lines.append(f"- **Browser verdict:** {verify_label(f)}"
                             + (f" — {f.verify_reason}" if getattr(f, "verify_reason", "") else ""))
            if f.interaction:
                lines.append("- **User interaction:** required")
            cvss = repro.cvss_for(f)
            lines.append(f"- **CVSS 3.1:** {cvss['score']} ({cvss['severity']})"
                         f"  ·  `{cvss['vector']}`")
            lines.append(f"- **HTTP status:** {f.status}  ·  content-type: `{f.content_type}`")
            if f.encoding:
                lines.append(f"- **Filter behaviour:** {f.encoding}")
            if getattr(f, "csp", ""):
                lines.append("- **Content-Security-Policy**")
                for csp_line in f.csp.splitlines():
                    lines.append(f"  - {csp_line}")
            for n in f.notes:
                lines.append(f"- {n}")
            for condition in repro.severity_conditions(f):
                lines.append(f"- **Severity change:** {condition}")
            lines.append("")
            lines.append("**Payload**\n")
            lines.append("```")
            lines.append(f.payload)
            lines.append("```\n")
            lines.append("**Reproduction**\n")
            lines.append("```bash")
            lines.append(repro.curl_for(f))
            lines.append("```\n")
            exploit = getattr(f, "exploit", None) or {}
            if exploit:
                lines.append("**Exploit (proof of impact)**\n")
                lines.append(f"- **Status:** {exploit.get('status', 'not_tested')}"
                             + (f" ({exploit['technique']})" if exploit.get("technique") else ""))
                if exploit.get("reason"):
                    lines.append(f"- **Reason:** {exploit['reason']}")
                if exploit.get("impact"):
                    lines.append(f"- **Impact:** {exploit['impact']}")
                caps = exploit.get("capabilities") or {}
                observed = []
                if caps.get("cookie_bytes"):
                    observed.append(f"cookies readable: {caps['cookie_bytes']} bytes"
                                    + (f" ({', '.join(caps.get('cookie_names') or [])})"
                                       if caps.get("cookie_names") else ""))
                if caps.get("csrf_token_readable"):
                    observed.append(f"anti-CSRF token readable: "
                                    f"{caps.get('csrf_token_length', 0)} chars")
                if caps.get("same_origin_status"):
                    observed.append(f"same-origin GET: HTTP {caps['same_origin_status']}, "
                                    f"{caps.get('same_origin_bytes', 0)} bytes")
                if observed:
                    lines.append("- **Observed:** " + "; ".join(observed))
                if exploit.get("payload"):
                    lines.append("\n```")
                    lines.append(exploit["payload"][:2000])
                    lines.append("```")
                if exploit.get("evidence"):
                    lines.append("\n```http")
                    lines.append(str(exploit["evidence"])[:4000])
                    lines.append("```")
                lines.append("")
            lines.append("**Evidence**\n")
            lines.append("```http")
            lines.append(f.evidence[:6000])
            lines.append("```\n")
    lines.extend(leads_markdown(meta))
    lines.extend(recon_markdown(meta))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return path


def _md(text: str) -> str:
    return text.replace("|", "\\|")


# ---------------------------------------------------------------------------
# Reconnaissance sections (WAF, libraries, parameter discovery, fuzzing,
# brute force). These stages do not produce findings, but their observations are
# what makes a clean result meaningful, so they get their own report section.
# ---------------------------------------------------------------------------

RECON_SUMMARY_KEYS = ("waf", "js_libraries", "server_stack",
                      "discovered_parameters", "fuzzed_parameters", "brute_force",
                      "leads")


def _waf_rows(meta: dict) -> list[dict]:
    return [row for row in (meta.get("waf") or []) if isinstance(row, dict)]


def _lead_rows(meta: dict) -> list[dict]:
    return [row for row in (meta.get("leads") or []) if isinstance(row, dict)]


#: Why a reflecting point stayed a lead, in the report's words.  ``unproven``
#: is the ordinary case (nothing executed), so it earns no extra label.
_LEAD_KINDS = {
    "unproven": "",
    "non-html": "non-HTML sink",
    "partial-reflection": "mangled reflection",
}


def _lead_context(row: dict) -> str:
    """Reflection context plus why the point is only a lead."""
    context = str(row.get("context") or "unknown")
    label = _LEAD_KINDS.get(str(row.get("kind") or ""))
    return f"{context} - {label}" if label else context


def _lead_reason(row: dict, limit: int = 2) -> str:
    """One-line observation for a lead: its own notes, most specific first."""
    notes = [str(n).strip() for n in (row.get("notes") or []) if str(n).strip()]
    if not notes:
        return "reflected, but no tested vector survived"
    text = "; ".join(notes[:limit])
    return text if len(text) <= 220 else text[:217].rstrip() + "..."


def leads_markdown(meta: dict) -> list[str]:
    """Markdown lines for unconfirmed leads ([] when there are none)."""
    leads = _lead_rows(meta)
    if not leads:
        return []
    out = ["## Leads (unconfirmed)\n"]
    out.append("These injection points reflect input, but no payload survived to execution. "
               "They are not findings: a filter, sink or WAF stopped every vector that was "
               "tried, so the point is unproven rather than clean. Review the observation "
               "column before dismissing them.\n")
    out.append("| # | Parameter | Context | URL | Confidence | Observation |")
    out.append("|---|---|---|---|---|---|")
    for i, lead in enumerate(leads, 1):
        out.append(f"| {i} | `{_md(str(lead.get('param', '')))}` | "
                   f"{_md(_lead_context(lead))} | "
                   f"{_md(str(lead.get('url', '')))} | "
                   f"{_md(str(lead.get('confidence') or 'low'))} | "
                   f"{_md(_lead_reason(lead))} |")
    out.append("")
    if meta.get("leads_truncated"):
        out.append("> The lead list is capped; additional reflecting points were recorded "
                   "in the JSON report only.\n")
    return out


def recon_markdown(meta: dict) -> list[str]:
    """Markdown lines for the reconnaissance stages ([] when none ran)."""
    waf_rows = _waf_rows(meta)
    libs = [lib for lib in (meta.get("js_libraries") or []) if isinstance(lib, dict)]
    stack = [t for t in (meta.get("server_stack") or []) if isinstance(t, dict)]
    discoveries = [d for d in (meta.get("discovered_parameters") or [])
                   if isinstance(d, dict)]
    fuzzed = [p for p in (meta.get("fuzzed_parameters") or []) if isinstance(p, dict)]
    brute = [b for b in (meta.get("brute_force") or []) if isinstance(b, dict)]
    if not any((waf_rows, libs, stack, discoveries, fuzzed, brute)):
        return []

    out = ["## Reconnaissance\n"]
    if waf_rows:
        out.append("### Web application firewall\n")
        out.append("| Target | Vendor | Confidence | Blocking | Evasion strategies |")
        out.append("|---|---|---|---|---|")
        for row in waf_rows:
            target = _md(str(row.get("target", "")))
            if not row.get("checked"):
                out.append(f"| {target} | not checked | - | - | - |")
                continue
            vendor = _md(str(row.get("name") or row.get("vendor") or "not identified"))
            strategies = _md(", ".join(row.get("strategies") or []) or "-")
            out.append(f"| {target} | {vendor} | {row.get('confidence') or 'none'} | "
                       f"{'yes' if row.get('blocking') else 'no'} | {strategies} |")
        out.append("")
        for row in waf_rows:
            for item in (row.get("evidence") or [])[:4]:
                out.append(f"- {item}")
        out.append("")

    if libs:
        out.append("### Client-side libraries\n")
        out.append("| Library | Version | Severity | CVEs | Source |")
        out.append("|---|---|---|---|---|")
        for lib in libs:
            cves = _md(", ".join(lib.get("cves") or []) or "-")
            out.append(f"| {_md(str(lib.get('name')))} | {_md(str(lib.get('version')))} | "
                       f"{_md(str(lib.get('severity')))} | {cves} | "
                       f"{_md(str(lib.get('source', '')))} |")
        out.append("")
        for lib in libs:
            if not lib.get("vulnerable"):
                continue
            out.append(f"- **{lib.get('name')} {lib.get('version')}** — {lib.get('detail')} "
                       f"(fixed in {lib.get('fixed_in')}); evidence: `{lib.get('evidence')}`")
        out.append("")

    if stack:
        out.append("### Server stack\n")
        out.append("| Component | Version | Status | CVEs | Evidence |")
        out.append("|---|---|---|---|---|")
        for row in stack:
            cves = _md(", ".join(row.get("cves") or []) or "-")
            out.append(f"| {_md(str(row.get('name')))} | "
                       f"{_md(str(row.get('version') or '-'))} | "
                       f"{_md(str(row.get('status') or 'detected'))} | {cves} | "
                       f"{_md(str(row.get('source') or ''))} |")
        out.append("")
        for row in stack:
            if row.get("status") == "detected" or not row.get("detail"):
                continue
            version = f" {row.get('version')}" if row.get("version") else ""
            out.append(f"- **{row.get('name')}{version}** — {row.get('detail')}")
        out.append("")

    if discoveries:
        out.append("### Discovered parameters\n")
        for item in discoveries:
            found = [p for p in (item.get("params") or []) if isinstance(p, dict)]
            label = ", ".join(
                f"`{p.get('name')}` ({p.get('signal') or 'reflection'})"
                for p in found) or "none"
            out.append(f"- `{item.get('url')}` — {item.get('tested', 0)} name(s) tested in "
                       f"{item.get('requests', 0)} request(s): {label}")
            if item.get("note"):
                out.append(f"  - {item['note']}")
        out.append("")

    if fuzzed:
        out.append("### Parameter fuzzing\n")
        out.append("| Parameter | Context | Raw | Encoded | Evaluated | URL |")
        out.append("|---|---|---|---|---|---|")
        for param in fuzzed:
            out.append(
                f"| `{_md(str(param.get('name')))}` | {_md(str(param.get('context') or '-'))} | "
                f"{_md(', '.join(param.get('raw') or [])) or '-'} | "
                f"{_md(', '.join(param.get('encoded') or [])) or '-'} | "
                f"{_md(', '.join(param.get('evaluated') or [])) or '-'} | "
                f"{_md(str(param.get('url', '')))} |")
        out.append("")
        if (meta.get("fuzzing") or {}).get("truncated"):
            out.append("> Fuzzing stopped at the request budget; the remaining "
                       "parameters were not probed.\n")

    if brute:
        out.append("### Filter brute force\n")
        for item in brute:
            kept = " ".join(sorted(ch for ch, state in (item.get("chars") or {}).items()
                                     if state == "raw")) or "none"
            stripped = " ".join(item.get("stripped") or []) or "none"
            out.append(f"- **{item.get('point')}** (`{item.get('context')}`) — vector "
                       f"`{item.get('vector')}`: {_md(str(item.get('payload') or ''))}")
            out.append(f"  - characters kept: {kept}; stripped: {stripped}; "
                       f"{item.get('requests', 0)} probe(s)")
        out.append("")
    return out


def _recon_table(headers, rows) -> str:
    head = "".join(f"<th>{html.escape(str(h))}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>"
                   for row in rows)
    return f'<table class="kv"><tr>{head}</tr>{body}</table>'


def leads_html(meta: dict) -> str:
    """HTML block for unconfirmed leads ('' when there are none)."""
    leads = _lead_rows(meta)
    if not leads:
        return ""
    rows = []
    for lead in leads:
        rows.append([
            f"<code>{html.escape(str(lead.get('param', '')))}</code>",
            html.escape(_lead_context(lead)),
            f"<code>{html.escape(str(lead.get('url', '')))}</code>",
            html.escape(str(lead.get('confidence') or "low")),
            html.escape(_lead_reason(lead)),
        ])
    note = ("These injection points reflect input, but no payload survived to execution. "
            "They are not findings: a filter, sink or WAF stopped every vector that was "
            "tried, so the point is unproven rather than clean.")
    suffix = ""
    if meta.get("leads_truncated"):
        suffix = ('<p class="note">The lead list is capped; additional reflecting points '
                  'were recorded in the JSON report only.</p>')
    return ("<h2>Leads (unconfirmed)</h2>"
            f'<p class="note">{html.escape(note)}</p>'
            + _recon_table(["Parameter", "Context", "URL", "Confidence", "Observation"],
                           rows)
            + suffix)


def recon_html(meta: dict) -> str:
    """HTML block for the reconnaissance stages ('' when none ran)."""
    esc = lambda value: html.escape(str(value))
    waf_rows = _waf_rows(meta)
    libs = [lib for lib in (meta.get("js_libraries") or []) if isinstance(lib, dict)]
    stack = [t for t in (meta.get("server_stack") or []) if isinstance(t, dict)]
    discoveries = [d for d in (meta.get("discovered_parameters") or [])
                   if isinstance(d, dict)]
    fuzzed = [p for p in (meta.get("fuzzed_parameters") or []) if isinstance(p, dict)]
    brute = [b for b in (meta.get("brute_force") or []) if isinstance(b, dict)]
    if not any((waf_rows, libs, stack, discoveries, fuzzed, brute)):
        return ""

    parts = ["<h2>Reconnaissance</h2>"]
    if waf_rows:
        rows = []
        for row in waf_rows:
            target = f"<code>{esc(row.get('target', ''))}</code>"
            if not row.get("checked"):
                rows.append([target, "not checked", "-", "-", "-"])
                continue
            rows.append([
                target,
                esc(row.get("name") or row.get("vendor") or "not identified"),
                esc(row.get("confidence") or "none"),
                "yes" if row.get("blocking") else "no",
                esc(", ".join(row.get("strategies") or []) or "-"),
            ])
        parts.append("<h3>Web application firewall</h3>")
        parts.append(_recon_table(
            ["Target", "Vendor", "Confidence", "Blocking", "Evasion strategies"], rows))
        evidence = [item for row in waf_rows for item in (row.get("evidence") or [])[:4]]
        if evidence:
            parts.append("<ul>" + "".join(f"<li>{esc(item)}</li>" for item in evidence)
                         + "</ul>")

    if libs:
        rows = [[esc(lib.get("name")), esc(lib.get("version")), esc(lib.get("severity")),
                 esc(", ".join(lib.get("cves") or []) or "-"),
                 f"<code>{esc(lib.get('source', ''))}</code>"] for lib in libs]
        parts.append("<h3>Client-side libraries</h3>")
        parts.append(_recon_table(
            ["Library", "Version", "Severity", "CVEs", "Source"], rows))
        vulnerable = [lib for lib in libs if lib.get("vulnerable")]
        if vulnerable:
            parts.append("<ul>" + "".join(
                f"<li><strong>{esc(lib.get('name'))} {esc(lib.get('version'))}</strong> — "
                f"{esc(lib.get('detail'))} (fixed in {esc(lib.get('fixed_in'))})</li>"
                for lib in vulnerable) + "</ul>")

    if stack:
        rows = [[esc(row.get("name")), esc(row.get("version") or "-"),
                 esc(row.get("status") or "detected"),
                 esc(", ".join(row.get("cves") or []) or "-"),
                 f"<code>{esc(row.get('source', ''))}</code>"] for row in stack]
        parts.append("<h3>Server stack</h3>")
        parts.append(_recon_table(
            ["Component", "Version", "Status", "CVEs", "Evidence"], rows))
        flagged = [row for row in stack
                   if row.get("status") != "detected" and row.get("detail")]
        if flagged:
            parts.append("<ul>" + "".join(
                f"<li><strong>{esc(row.get('name'))} {esc(row.get('version'))}</strong> — "
                f"{esc(row.get('detail'))}</li>" for row in flagged) + "</ul>")

    if discoveries:
        items = []
        for item in discoveries:
            found = [p for p in (item.get("params") or []) if isinstance(p, dict)]
            label = ", ".join(
                f"<code>{esc(p.get('name'))}</code> ({esc(p.get('signal') or 'reflection')})"
                for p in found) or "none"
            note = f" — {esc(item['note'])}" if item.get("note") else ""
            items.append(
                f"<li><code>{esc(item.get('url', ''))}</code> — "
                f"{esc(item.get('tested', 0))} name(s) tested in "
                f"{esc(item.get('requests', 0))} request(s): {label}{note}</li>")
        parts.append("<h3>Discovered parameters</h3><ul>" + "".join(items) + "</ul>")

    if fuzzed:
        rows = [[f"<code>{esc(param.get('name'))}</code>",
                 esc(param.get("context") or "-"),
                 esc(", ".join(param.get("raw") or []) or "-"),
                 esc(", ".join(param.get("encoded") or []) or "-"),
                 esc(", ".join(param.get("evaluated") or []) or "-"),
                 f"<code>{esc(param.get('url', ''))}</code>"]
                for param in fuzzed]
        parts.append("<h3>Parameter fuzzing</h3>")
        parts.append(_recon_table(
            ["Parameter", "Context", "Raw", "Encoded", "Evaluated", "URL"], rows))
        if (meta.get("fuzzing") or {}).get("truncated"):
            parts.append('<p class="note">Fuzzing stopped at the request budget; the '
                         'remaining parameters were not probed.</p>')

    if brute:
        items = []
        for item in brute:
            kept = " ".join(sorted(ch for ch, state in (item.get("chars") or {}).items()
                                     if state == "raw")) or "none"
            stripped = " ".join(item.get("stripped") or []) or "none"
            items.append(
                f"<li><strong>{esc(item.get('point'))}</strong> "
                f"(<code>{esc(item.get('context'))}</code>) — vector "
                f"<code>{esc(item.get('vector'))}</code>: "
                f"<code>{esc(item.get('payload') or '')}</code>"
                f"<br><span class=\"note\">characters kept: {esc(kept)}; "
                f"stripped: {esc(stripped)}; {esc(item.get('requests', 0))} probe(s)</span></li>")
        parts.append("<h3>Filter brute force</h3><ul>" + "".join(items) + "</ul>")

    return "".join(parts)


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

HTML_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>xssmap report - {targets}</title>
<style>
:root {{ --bg:#0d1117; --panel:#161b22; --line:#30363d; --txt:#e6edf3; --muted:#8b949e;
         --high:#f85149; --med:#d29922; --low:#58a6ff; --ok:#3fb950; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--txt);
        font:14px/1.55 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }}
header {{ padding:28px 32px; border-bottom:1px solid var(--line); background:#010409; }}
h1 {{ margin:0 0 6px; font-size:22px; letter-spacing:.2px; }}
h2 {{ font-size:16px; margin:28px 0 10px; }}
.sub {{ color:var(--muted); font-size:13px; }}
.wrap {{ padding:24px 32px 60px; max-width:1150px; }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:12px; margin:18px 0 8px; }}
.card {{ background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:14px 16px; }}
.card .n {{ font-size:22px; font-weight:600; }}
.card .l {{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.6px; }}
.finding {{ background:var(--panel); border:1px solid var(--line); border-left:4px solid var(--med);
            border-radius:8px; padding:16px 18px; margin:16px 0; }}
.finding.high {{ border-left-color:var(--high); }}
.finding.low {{ border-left-color:var(--low); }}
.badge {{ display:inline-block; font-size:11px; font-weight:700; letter-spacing:.6px;
          padding:3px 8px; border-radius:999px; text-transform:uppercase; }}
.badge.high {{ background:rgba(248,81,73,.16); color:var(--high); }}
.badge.medium {{ background:rgba(210,153,34,.16); color:var(--med); }}
.badge.low {{ background:rgba(88,166,255,.16); color:var(--low); }}
.badge.ok {{ background:rgba(63,185,80,.16); color:var(--ok); }}
table.kv {{ width:100%; border-collapse:collapse; margin:10px 0 4px; }}
table.kv td {{ padding:4px 8px 4px 0; vertical-align:top; border-bottom:1px solid #21262d; }}
table.kv td:first-child {{ color:var(--muted); width:170px; white-space:nowrap; }}
code, pre {{ font-family:ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace; }}
code {{ background:#0b1017; padding:1px 5px; border-radius:4px; border:1px solid #21262d; }}
pre {{ background:#010409; border:1px solid var(--line); border-radius:6px; padding:12px;
       overflow:auto; max-height:420px; font-size:12.5px; white-space:pre-wrap; word-break:break-word; }}
.note {{ color:var(--muted); }}
footer {{ color:var(--muted); padding:20px 32px; border-top:1px solid var(--line); font-size:12px; }}
</style></head><body>
<header>
  <h1>xssmap &mdash; cross-site scripting report</h1>
  <div class="sub">Targets: {targets} &nbsp;·&nbsp; {started} &rarr; {finished} &nbsp;·&nbsp; {duration}s
  &nbsp;·&nbsp; xssmap {version}</div>
</header>
<div class="wrap">
  <div class="grid">
    <div class="card"><div class="n">{n_high}</div><div class="l">High</div></div>
    <div class="card"><div class="n">{n_med}</div><div class="l">Medium</div></div>
    <div class="card"><div class="n">{n_low}</div><div class="l">Low / review</div></div>
    <div class="card"><div class="n">{n_verified}</div><div class="l">Browser-confirmed</div></div>
    <div class="card"><div class="n">{n_proven}</div><div class="l">Exploit-proven</div></div>
    <div class="card"><div class="n">{n_points}</div><div class="l">Points tested</div></div>
    <div class="card"><div class="n">{n_reflected}</div><div class="l">Reflected</div></div>
  </div>
  <h2>Findings</h2>
  {findings_html}
  {leads_html}
  {recon_html}
  <h2>Scan metadata</h2>
  <table class="kv">{meta_rows}</table>
</div>
<footer>Generated by xssmap {version}. Only test systems you are authorised to test.</footer>
</body></html>"""


def write_html(path: str, findings: list, meta: dict) -> str:
    counts = {"high": 0, "medium": 0, "low": 0}
    verified = proven = 0
    for f in findings:
        counts[severity_of(f)] += 1
        if f.verified_browser:
            verified += 1
        if exploit_state(f) == "proven":
            proven += 1

    if not findings:
        body = ('<div class="card"><span class="badge ok">clean</span> '
                '<p class="note">No reflected cross-site scripting was confirmed on the tested '
                'injection points.</p></div>')
    else:
        cards = []
        for i, f in enumerate(findings, 1):
            sev = severity_of(f)
            badge = (f'<span class="badge {sev}">{sev}</span>')
            if f.verified_browser:
                state = '<span class="badge ok">browser-confirmed</span>'
            elif getattr(f, "verify_state", "") == "not_tested":
                state = '<span class="badge medium">not tested in browser</span>'
            else:
                state = '<span class="badge low">reflected / static</span>'
            notes = "".join(f"<li>{html.escape(n)}</li>" for n in f.notes)
            conditions = "".join(f"<li>{html.escape(c)}</li>"
                                  for c in repro.severity_conditions(f))
            cvss = repro.cvss_for(f)
            exploit = getattr(f, "exploit", None) or {}
            exploit_html = ""
            if exploit:
                bits = [f"<strong>{html.escape(str(exploit.get('status', 'not_tested')))}</strong>"]
                if exploit.get("technique"):
                    bits.append(html.escape(str(exploit["technique"])))
                if exploit.get("reason"):
                    bits.append(html.escape(str(exploit["reason"])))
                if exploit.get("impact"):
                    bits.append(html.escape(str(exploit["impact"])))
                caps = exploit.get("capabilities") or {}
                if caps.get("cookie_bytes"):
                    bits.append(f"cookies {caps['cookie_bytes']} bytes"
                                + (f" ({html.escape(', '.join(caps.get('cookie_names') or []))})"
                                   if caps.get("cookie_names") else ""))
                if caps.get("csrf_token_readable"):
                    bits.append(f"anti-CSRF token readable ({caps.get('csrf_token_length', 0)} chars)")
                if caps.get("same_origin_status"):
                    bits.append(f"same-origin HTTP {caps['same_origin_status']} "
                                f"{caps.get('same_origin_bytes', 0)} bytes")
                detail = " · ".join(bits)
                payload_block = (f"<pre>{html.escape(str(exploit['payload'])[:2000])}</pre>"
                                 if exploit.get("payload") else "")
                exploit_html = (f'<tr><td>Exploit proof</td><td>{detail}{payload_block}</td></tr>')
            cards.append(f"""
<div class="finding {sev}">
  <div>{badge} {state} <strong>#{i} &nbsp;{html.escape(f.method)} parameter
      <code>{html.escape(f.param)}</code></strong></div>
  <table class="kv">
    <tr><td>URL</td><td><code>{html.escape(f.url)}</code></td></tr>
    <tr><td>Injection point</td><td>{html.escape(f.location)}</td></tr>
    <tr><td>Reflection context</td><td><code>{html.escape(f.context)}</code></td></tr>
    <tr><td>HTTP status / type</td><td>{f.status} &nbsp; <code>{html.escape(f.content_type)}</code></td></tr>
    <tr><td>Confidence</td><td>{html.escape(f.confidence)}{" · browser-verified" if f.verified_browser else ""}</td></tr>
    <tr><td>CVSS 3.1</td><td>{cvss['score']} ({cvss['severity']}) &nbsp; <code>{html.escape(cvss['vector'])}</code></td></tr>
    <tr><td>Browser verdict</td><td>{html.escape(verify_label(f))}{(" — " + html.escape(f.verify_reason)) if getattr(f, 'verify_reason', '') else ''}</td></tr>
    <tr><td>Filter behaviour</td><td>{html.escape(f.encoding or "n/a")}</td></tr>
    {f'<tr><td>Content-Security-Policy</td><td><pre>{html.escape(f.csp)}</pre></td></tr>' if getattr(f, 'csp', '') else ''}
    <tr><td>Payload</td><td><code>{html.escape(f.payload)}</code></td></tr>
    {exploit_html}
    {f'<tr><td>Notes</td><td><ul>{notes}</ul></td></tr>' if notes else ''}
    {f'<tr><td>Severity change</td><td><ul>{conditions}</ul></td></tr>' if conditions else ''}
    <tr><td>Reproduce</td><td><pre>{html.escape(repro.curl_for(f))}</pre></td></tr>
  </table>
  <details><summary>Captured request / response</summary>
  <pre>{html.escape(f.evidence)}</pre></details>
</div>""")
        body = "\n".join(cards)

    meta_rows = "".join(
        f"<tr><td>{html.escape(str(k))}</td><td>{html.escape(str(v))}</td></tr>"
        for k, v in meta.items()
        if k not in ("statistics", "crawl") + RECON_SUMMARY_KEYS)

    stats = meta.get("statistics") or {}
    if meta.get("interrupted"):
        body = ('<div class="card" style="border-color:#f85149">'
                '<strong>This scan was interrupted.</strong> Only the tests that completed '
                'before the stop are listed; anything absent was not assessed.</div>\n') + body
    out = HTML_TEMPLATE.format(
        targets=html.escape(", ".join(meta.get("targets") or [])),
        started=html.escape(str(meta.get("started"))),
        finished=html.escape(str(meta.get("finished"))),
        duration=meta.get("duration_s"),
        version=VERSION,
        n_high=counts["high"], n_med=counts["medium"], n_low=counts["low"],
        n_verified=verified,
        n_proven=proven,
        n_points=stats.get("points", 0),
        n_reflected=stats.get("reflected_points", 0),
        findings_html=body,
        leads_html=leads_html(meta),
        recon_html=recon_html(meta),
        meta_rows=meta_rows,
    )
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(out)
    return path
