"""Machine-readable output and per-finding evidence files.

Two things a scanner is judged on after the fact: can a CI system consume the
result (SARIF), and can a human re-check a finding without re-running the whole
scan (evidence files). Both are written from the same ``Finding`` objects the
console report uses, so the three outputs can never disagree.
"""
from __future__ import annotations

import json
import os
import re
import urllib.parse
from typing import Any

from . import report as rp
from . import repro

SARIF_VERSION = "2.1.0"
SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

CONTEXT_RULE = {
    "html_text": ("xss-html-text", "HTML body context"),
    "attr_double": ("xss-attr-double", "Double-quoted attribute context"),
    "attr_single": ("xss-attr-single", "Single-quoted attribute context"),
    "attr_unquoted": ("xss-attr-unquoted", "Unquoted attribute context"),
    "js_string_double": ("xss-js-string", "JavaScript string context"),
    "js_string_single": ("xss-js-string", "JavaScript string context"),
    "js_code": ("xss-js-code", "JavaScript code context"),
    "textarea": ("xss-rcdata", "RCDATA (textarea/title) context"),
    "title": ("xss-rcdata", "RCDATA (textarea/title) context"),
    "comment": ("xss-comment", "HTML comment context"),
    "dom_xss": ("xss-dom", "DOM source-to-sink flow"),
    "mxss": ("xss-mxss", "Mutation XSS via sanitiser round trip"),
    "charset": ("xss-charset", "Multibyte charset escaping bypass"),
    "stored_xss": ("xss-stored", "Stored/blind XSS"),
    "header": ("xss-header", "Header reflection"),
    "cookie": ("xss-cookie", "Cookie reflection"),
}


def _rule(context: str) -> tuple[str, str]:
    return CONTEXT_RULE.get(context, ("xss-reflected", "Reflected cross-site scripting"))


def _level(f) -> str:
    sev = rp.severity_of(f)
    if sev == "high":
        return "error"
    if sev == "medium":
        return "warning"
    return "note"


def build_sarif(findings, meta: dict | None = None) -> dict:
    meta = meta or {}
    rules: dict[str, dict] = {}
    results = []
    for f in findings:
        rule_id, name = _rule(f.context)
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": name.replace(" ", ""),
            "shortDescription": {"text": name},
            "fullDescription": {"text": (
                "User-controlled input reaches an executable position "
                f"({f.context}) without correct encoding.")},
            "help": {"text": (
                "Encode output for the exact context (HTML, attribute, JS, URL) and "
                "apply a Content-Security-Policy as defence in depth.")},
            "properties": {"tags": ["security", "xss", f.context]},
        })
        parts = urllib.parse.urlsplit(f.url)
        uri = urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
        region = {}
        if parts.query:
            region = {"startLine": 1, "snippet": {"text": parts.query[:400]}}
        verdict = getattr(f, "verify_state", "") or "not-attempted"
        exploit = getattr(f, "exploit", None) or {}
        message = (f"{f.context} XSS in parameter '{f.param}'"
                   + (" (browser-verified)" if f.verified_browser
                      else f" (browser verdict: {verdict})")
                   + (f" [exploit proven: {exploit.get('technique', 'payload')}]"
                      if exploit.get("status") == "proven" else ""))
        results.append({
            "ruleId": rule_id,
            "level": _level(f),
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    **({"region": region} if region else {}),
                },
                **({"logicalLocations": [{"fullyQualifiedName": f.param}]}),
            }],
            "properties": {
                "parameter": f.param,
                "method": f.method,
                "payload": f.payload,
                "context": f.context,
                "confidence": f.confidence,
                "location": f.location,
                "browserVerified": bool(f.verified_browser),
                "browserVerifyState": verdict,
                "browserVerifyReason": getattr(f, "verify_reason", "") or "",
                "exploit": {
                    "status": exploit.get("status", "not_tested"),
                    "technique": exploit.get("technique", ""),
                    "impact": exploit.get("impact", ""),
                    "reason": exploit.get("reason", ""),
                    "capabilities": exploit.get("capabilities") or {},
                } if exploit else {},
                "filterProfile": f.filter_profile or {},
                "mutation": f.mutation or "",
                "cvss": repro.cvss_for(f),
                "reproduction": repro.curl_for(f),
            },
        })
    run: dict[str, Any] = {
        "tool": {"driver": {
            "name": "xssmap",
            "version": rp.VERSION,
            "semanticVersion": rp.VERSION,
            "rules": list(rules.values()),
        }},
        "results": results,
    }
    if meta:
        run["properties"] = {"targets": meta.get("targets", []),
                             "durationSeconds": meta.get("duration_s"),
                             "statistics": meta.get("statistics", {})}
        reconnaissance = {}
        if meta.get("waf"):
            reconnaissance["waf"] = meta["waf"]
        if meta.get("js_libraries"):
            reconnaissance["libraries"] = meta["js_libraries"]
        if meta.get("discovered_parameters"):
            reconnaissance["discoveredParameters"] = meta["discovered_parameters"]
        if meta.get("fuzzing"):
            reconnaissance["fuzzing"] = meta["fuzzing"]
        if meta.get("brute_force"):
            reconnaissance["bruteForce"] = meta["brute_force"]
        if reconnaissance:
            run["properties"]["reconnaissance"] = reconnaissance
    return {"$schema": SCHEMA, "version": SARIF_VERSION, "runs": [run]}


def write_sarif(path: str, findings, meta: dict | None = None) -> str:
    data = build_sarif(findings, meta)
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")
    return path


def _slug(text: str, limit: int = 40) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9]+", "-", text or "").strip("-").lower()
    return (cleaned or "finding")[:limit]


def write_evidence(findings, directory: str) -> list[str]:
    """One file per finding: enough detail to reproduce it by hand."""
    os.makedirs(directory, exist_ok=True)
    written = []
    for index, f in enumerate(findings, 1):
        name = f"{index:03d}-{_slug(f.context)}-{_slug(f.param)}.txt"
        path = os.path.join(directory, name)
        lines = [
            f"xssmap {rp.VERSION} - finding evidence",
            "=" * 60,
            f"title:      {f.title or f.context}",
            f"severity:   {rp.severity_of(f)}",
            f"confidence: {f.confidence}",
            f"context:    {f.context}",
            f"location:   {f.location}",
            f"method:     {f.method}",
            f"url:        {f.url}",
            f"parameter:  {f.param}",
            f"payload:    {f.payload}",
            f"http:       {f.status}",
            f"verified:   browser={bool(f.verified_browser)} checked={bool(f.browser_checked)}",
            f"verify:     {getattr(f, 'verify_state', '') or 'not attempted'}"
            + (f" ({f.verify_reason})" if getattr(f, "verify_reason", "") else ""),
            f"csp_blocked: {bool(f.csp_blocked)}",
            f"interaction: {bool(f.interaction)}",
        ]
        exploit = getattr(f, "exploit", None) or {}
        if exploit:
            lines.append(f"exploit:    {exploit.get('status', 'not_tested')} "
                         f"({exploit.get('technique') or 'n/a'})")
            if exploit.get("reason"):
                lines.append(f"exploit why: {exploit['reason']}")
            if exploit.get("impact"):
                lines.append(f"impact:     {exploit['impact']}")
            if exploit.get("payload"):
                lines.append(f"weaponised: {exploit['payload']}")
            caps = exploit.get("capabilities") or {}
            if caps:
                lines.append(f"capabilities: {json.dumps(caps, sort_keys=True)}")
        cvss = repro.cvss_for(f)
        lines.append(f"cvss:       {cvss['score']} ({cvss['severity']}) {cvss['vector']}")
        conditions = repro.severity_conditions(f)
        if conditions:
            lines.append("severity would change if:")
            lines.extend(f"  - {c}" for c in conditions)
        if f.filter_profile:
            lines.append(f"filter:     {json.dumps(f.filter_profile, sort_keys=True)}")
        if getattr(f, "csp", ""):
            lines.append("csp:")
            lines.extend(f"  {csp_line}" for csp_line in f.csp.splitlines())
        if f.mutation:
            lines.append(f"mutation:   {f.mutation}")
        if f.notes:
            lines.append("")
            lines.append("notes:")
            lines.extend(f"  - {n}" for n in f.notes)
        lines.append("")
        lines.append("observed evidence:")
        lines.append(f.evidence or "  (none recorded)")
        lines.append("")
        lines.append("reproduce:")
        lines.append("  " + repro.curl_for(f).replace("\n", "\n  "))
        lines.append("")
        lines.append("request / response pair:")
        lines.append(f"  {os.path.basename(path).rsplit('.', 1)[0]}.http")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
        written.append(path)
        pair_path = os.path.join(directory, f"{index:03d}-{_slug(f.context)}-{_slug(f.param)}.http")
        with open(pair_path, "w", encoding="utf-8") as handle:
            handle.write(repro.pair_text(f))
        written.append(pair_path)
    return written


def capture_screenshots(browser, findings, directory: str, limit: int = 15) -> list[str]:
    """Screenshot every verified finding that does not have one yet."""
    if not browser or not getattr(browser, "available", False):
        return []
    os.makedirs(directory, exist_ok=True)
    shots: list[str] = []
    for index, f in enumerate(findings, 1):
        if len(shots) >= limit:
            break
        if not f.verified_browser or "screenshot:" in (f.evidence or ""):
            continue
        path = os.path.join(directory, f"{index:03d}-{_slug(f.context)}.png")
        try:
            info = browser.navigate(f.url)
            if not info.get("loaded"):
                continue
            if browser.screenshot(path):
                f.evidence = (f.evidence or "") + f"\n  screenshot: {path}"
                shots.append(path)
        except Exception:
            continue
    return shots
