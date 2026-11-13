"""Fuzz mode: a per-parameter probe matrix, without a full scan.

Sometimes you do not want a scan. You want to point the tool at one URL and be
told, parameter by parameter, which characters survive, where they land, and
whether anything is being evaluated server-side. That is what this mode does:
it sends a fixed, small probe corpus per parameter and reports a matrix. It
never claims a vulnerability — it tells you where to look and hands the
interesting parameters back to the scanner.

Two probe kinds:

``reflect``  the probe is prefixed with a unique marker so its reflection can
             be located unambiguously and classified by context.
``evaluate`` the probe is sent verbatim and the response is searched for the
             evaluated result (``{{7*7}}`` → ``49``), which catches template
             injection that reflection alone would miss.
"""
from __future__ import annotations

import html
import urllib.parse
from dataclasses import dataclass, field

from .htmlparse import parse_page, set_query_param
from .payloads import classify_reflections

PROBES = (
    ("single-quote", "'", "reflect"),
    ("double-quote", '"', "reflect"),
    ("angle-open", "<", "reflect"),
    ("angle-close", ">", "reflect"),
    ("comment-open", "<!--", "reflect"),
    ("script-close", "</script>", "reflect"),
    ("backtick", "`", "reflect"),
    ("backslash", "\\", "reflect"),
    ("parens", "()", "reflect"),
    ("tag", "<svg onload=alert(1)>", "reflect"),
    ("entity", "&lt;", "reflect"),
    ("js-url", "javascript:alert(1)", "reflect"),
    ("sqli-quote", "' OR 1=1-- ", "reflect"),
    ("ssti-dollar", "${7*7}", "evaluate"),
    ("ssti-moustache", "{{7*7}}", "evaluate"),
)


@dataclass
class ProbeResult:
    probe: str
    state: str                  # raw / encoded / stripped / evaluated / inert
    context: str = ""
    note: str = ""

    def as_dict(self) -> dict:
        return {"probe": self.probe, "state": self.state,
                "context": self.context, "note": self.note}


@dataclass
class ParamReport:
    name: str
    url: str
    results: list[ProbeResult] = field(default_factory=list)
    context: str = ""
    notes: list[str] = field(default_factory=list)
    requests: int = 0

    @property
    def raw(self) -> list[str]:
        return [r.probe for r in self.results if r.state == "raw"]

    @property
    def encoded(self) -> list[str]:
        return [r.probe for r in self.results if r.state == "encoded"]

    @property
    def evaluated(self) -> list[str]:
        return [r.probe for r in self.results if r.state == "evaluated"]

    def as_dict(self) -> dict:
        return {"name": self.name, "url": self.url, "context": self.context,
                "raw": self.raw, "encoded": self.encoded,
                "evaluated": self.evaluated, "notes": list(self.notes),
                "requests": self.requests,
                "probes": [r.as_dict() for r in self.results]}


def _with_param(url: str, index: int, value: str) -> str:
    return set_query_param(url, index, value)


def _context_of(text: str, url: str, value: str) -> str:
    try:
        page = parse_page(url, text)
        found = classify_reflections(page, value, limit=1)
        return found[0].context if found else ""
    except Exception:
        return ""


def fuzz_param(http, url: str, index: int, name: str,
               headers: list[tuple[str, str]] | None = None,
               budget: int = 32, log=None) -> ParamReport:
    """Probe one parameter and classify each result."""
    report = ParamReport(name=name, url=url)
    headers = list(headers or [])
    # A baseline with an inert value: punctuation-only probes ('<', '"', '<!--')
    # occur in every page, so a hit only means something when the same literal
    # was absent before the probe. Without this the fuzzer reports "raw" for
    # boilerplate it never injected.
    baseline_text = ""
    try:
        base_resp = http.get(_with_param(url, index, "xsfbase0"), headers=headers)
        baseline_text = getattr(base_resp, "text", "") or ""
        report.requests += 1
    except Exception:
        baseline_text = ""
    spent = 0
    for probe_name, literal, kind in PROBES:
        if spent >= budget:
            break
        value = literal if kind == "evaluate" else f"xsf{spent}{literal}"
        try:
            resp = http.get(_with_param(url, index, value), headers=headers)
        except Exception:
            continue
        spent += 1
        report.requests += 1
        text = getattr(resp, "text", "") or ""
        if kind == "evaluate":
            if "49" in text and ("7*7" not in text):
                report.results.append(ProbeResult(
                    probe_name, "evaluated",
                    note=f"expression evaluated server-side ({literal} became 49)"))
            else:
                report.results.append(ProbeResult(probe_name, "inert"))
            continue
        escaped_forms = {html.escape(literal), html.escape(literal, quote=True)}
        if value in text:
            context = _context_of(text, resp.url or url, value)
            report.results.append(ProbeResult(probe_name, "raw", context))
            if not report.context and context:
                report.context = context
        elif any(form in text and form not in baseline_text for form in escaped_forms):
            report.results.append(ProbeResult(probe_name, "encoded",
                                              note="reflected HTML-encoded"))
        elif literal in text and literal not in baseline_text:
            report.results.append(ProbeResult(probe_name, "raw",
                                              note="survived without its marker"))
        else:
            report.results.append(ProbeResult(probe_name, "stripped"))
    if report.raw:
        report.notes.append("characters survive raw: " + " ".join(report.raw))
    if report.encoded and not report.raw:
        report.notes.append("reflection is being HTML-encoded")
    if report.evaluated:
        report.notes.append("server-side template evaluation detected")
    if log:
        state = "raw" if report.raw else ("encoded" if report.encoded else "stripped")
        extra = f", context {report.context}" if report.context else ""
        log.info(f"  {name}: {state}{extra}"
                 + (", template evaluation" if report.evaluated else ""))
    return report


def run(http, urls: list[str], headers: list[tuple[str, str]] | None = None,
        log=None, params: list[str] | None = None, max_params: int = 8,
        max_requests: int = 240, discover: bool = False,
        wordlist: list[str] | None = None) -> dict:
    """Fuzz every parameter of every URL, within a request budget."""
    out: dict = {"urls": [], "requests": 0, "params": [], "truncated": False}
    remaining = max(0, max_requests)
    for url in urls:
        pairs = urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query,
                                       keep_blank_values=True)
        names = list(params or [])
        if not names:
            names = [k for k, _ in pairs]
        if not names and discover:
            from . import params as paramdisc
            found = paramdisc.discover(http, url, headers, log=log,
                                       wordlist=wordlist, max_params=80)
            names = found.names()
            remaining -= found.requests
            out["requests"] += found.requests
            out.setdefault("discovery", []).append(found.as_dict())
        if not names:
            out["urls"].append(url)
            out.setdefault("skipped", []).append(
                {"url": url, "reason": "no parameters; try --discover-params"})
            continue
        # Every probed name must exist in the URL: set_query_param() leaves the
        # URL untouched for an index that is not there, which would turn the
        # whole probe matrix into repeated requests for the same unchanged page.
        present = {name for name, _v in pairs}
        missing = [n for n in names if n not in present]
        target_url = url
        if missing:
            from . import params as paramdisc
            target_url = paramdisc.with_params(url, missing)
            pairs = urllib.parse.parse_qsl(
                urllib.parse.urlsplit(target_url).query, keep_blank_values=True)
        out["urls"].append(target_url)
        index_of = {name: i for i, (name, _v) in enumerate(pairs)}
        for name in names[:max_params]:
            index = index_of.get(name)
            if index is None:
                continue
            if remaining <= 0:
                out["truncated"] = True
                break
            # fuzz_param() always spends one request on its baseline before
            # probing, so the probe budget is what is left after that.
            budget = max(0, min(32, remaining - 1))
            report = fuzz_param(http, target_url, index, name, headers,
                                budget=budget, log=log)
            spent = report.requests or sum(1 for _ in report.results)
            remaining -= spent
            out["requests"] += spent
            out["params"].append(report.as_dict())
        if remaining <= 0:
            out["truncated"] = True
            break
    return out


def summary(result: dict) -> dict:
    """Counts for the report header."""
    params = result.get("params") or []
    return {
        "parameters_fuzzed": len(params),
        "with_raw_reflection": sum(1 for p in params if p.get("raw")),
        "encoded_only": sum(1 for p in params if p.get("encoded") and not p.get("raw")),
        "template_evaluation": sum(1 for p in params if p.get("evaluated")),
        "requests": result.get("requests", 0),
        "truncated": bool(result.get("truncated")),
    }
