"""Reproduction material for a finding: CVSS 3.1, a curl command, a raw pair.

The report is only useful if somebody else can re-check the finding. Everything
here is derived from data the scanner actually observed:

  * CVSS 3.1 base metrics are chosen from the demonstrated evidence, not from the
    vulnerability class (an unverified reflection does not get confidentiality
    impact; a verified page-execution finding does).
  * The curl command is rebuilt from the captured raw request when one exists,
    so headers and form fields are the real ones.
  * The request/response pair is the captured exchange, with the variable parts
    (session cookie) removed rather than invented.
"""
from __future__ import annotations

import math
import re
import shlex
import urllib.parse

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

# Cookie names that imply an authenticated session rather than a preference.
SESSION_COOKIE_RX = re.compile(
    r"(?:^|[_\-.])(?:sess(?:ion)?|sid|auth|token|jwt|login|remember|user)(?:$|[_\-.])",
    re.I,
)

# Headers that are noise or secrets in a reproduction command.
DROP_HEADERS = {"host", "content-length", "connection", "accept-encoding",
                "cookie", "user-agent", "proxy-authorization"}


def roundup(value: float) -> float:
    """CVSS 3.1 Appendix A: round up to one decimal place."""
    return math.ceil(round(value, 6) * 10) / 10.0


def score(metrics: dict) -> tuple[float, str]:
    iss = 1 - (1 - CIA[metrics["C"]]) * (1 - CIA[metrics["I"]]) * (1 - CIA[metrics["A"]])
    scope = metrics["S"]
    if scope == "U":
        impact = 6.42 * iss
        pr = PR_UNCHANGED[metrics["PR"]]
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        pr = PR_CHANGED[metrics["PR"]]
    exploitability = 8.22 * AV[metrics["AV"]] * AC[metrics["AC"]] * pr * UI[metrics["UI"]]
    if impact <= 0:
        raw = 0.0
    elif scope == "U":
        raw = min(impact + exploitability, 10.0)
    else:
        raw = min(1.08 * (impact + exploitability), 10.0)
    base = roundup(raw)
    if base == 0:
        label = "none"
    elif base < 4.0:
        label = "low"
    elif base < 7.0:
        label = "medium"
    elif base < 9.0:
        label = "high"
    else:
        label = "critical"
    return base, label


def vector(metrics: dict) -> str:
    order = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    return "CVSS:3.1/" + "/".join(f"{key}:{metrics[key]}" for key in order)


def cvss_for(finding) -> dict:
    """Base metrics justified by what was observed for this finding."""
    confirmed = bool(getattr(finding, "verified_browser", False)) \
        or getattr(finding, "verify_state", "") == "confirmed"
    exploit = getattr(finding, "exploit", None) or {}
    proven = exploit.get("status") == "proven"
    caps = exploit.get("capabilities") or {}
    if proven:
        confirmed = True
    c = "N"
    if proven:
        names = [str(n) for n in (caps.get("cookie_names") or [])]
        session_like = any(SESSION_COOKIE_RX.search(n) for n in names)
        readable = int(caps.get("same_origin_status") or 0)
        authenticated_read = 200 <= readable < 300
        # High only when a session-style cookie or a token plus a readable
        # authenticated response was actually observed: that is account access.
        # Otherwise execution alone still reads the page it runs on (low).
        if session_like or (caps.get("csrf_token_readable") and authenticated_read):
            c = "H"
        else:
            c = "L"
    elif confirmed:
        c = "L"
    metrics = {
        "AV": "N",                                   # HTTP, remote
        "AC": "L",                                   # a single request reproduces it
        "PR": "N",                                   # no credentials are required
        "UI": "R" if getattr(finding, "interaction", False) else "N",
        "S": "U",                                    # same origin as the vulnerable page
        # Reading page data is only demonstrated once script actually ran.
        "C": c,
        "I": "L",                                    # markup/script injection was observed
        "A": "N",
    }
    base, label = score(metrics)
    return {"score": base, "severity": label, "vector": vector(metrics), "metrics": metrics}


def _captured_request(finding):
    """Parse the raw request block the scanner stored as evidence, if present."""
    evidence = getattr(finding, "evidence", "") or ""
    if "--- request ---" not in evidence:
        return None
    block = evidence.split("--- request ---", 1)[1]
    block = block.split("--- response ---", 1)[0].strip("\n")
    lines = block.splitlines()
    if not lines:
        return None
    parts = lines[0].split()
    if len(parts) < 3 or not parts[2].startswith("HTTP/"):
        return None
    method, path = parts[0], parts[1]
    headers: list[tuple[str, str]] = []
    body = ""
    rest = lines[1:]
    for index, line in enumerate(rest):
        if not line.strip():
            body = "\n".join(rest[index + 1:])
            break
        if ":" in line:
            name, value = line.split(":", 1)
            headers.append((name.strip(), value.strip()))
    return method, path, headers, body


def _absolute(finding, path: str, headers) -> str:
    host = next((v for k, v in headers if k.lower() == "host"), "")
    if not host:
        host = urllib.parse.urlsplit(finding.url).netloc
    scheme = urllib.parse.urlsplit(finding.url).scheme or "http"
    return f"{scheme}://{host}{path}"


def curl_for(finding) -> str:
    """A runnable curl command built from the captured request."""
    captured = _captured_request(finding)
    if captured:
        method, path, headers, body = captured
        url = _absolute(finding, path, headers)
        args = [f"curl -sS -i -X {method} {shlex.quote(url)}"]
        for name, value in headers:
            if name.lower() in DROP_HEADERS:
                continue
            args.append(f"  -H {shlex.quote(name + ': ' + value)}")
        if body:
            args.append(f"  --data-binary {shlex.quote(body)}")
        if any(k.lower() == "cookie" for k, _v in headers):
            args.append("  # add -b 'session=...' when the endpoint needs the session "
                        "that produced this response")
        return " \\\n".join(args)
    url = shlex.quote(finding.url)
    if (finding.method or "GET").upper() == "GET":
        return f"curl -sS -i {url}"
    data = shlex.quote(f"{finding.param}={finding.payload}")
    return f"curl -sS -i -X {finding.method} {url} --data {data}"


def response_block(finding) -> str:
    evidence = getattr(finding, "evidence", "") or ""
    if "--- response ---" in evidence:
        block = evidence.split("--- response ---", 1)[1]
        reflection = ""
        if "--- reflection context" in block:
            head, _, tail = block.partition("--- reflection context")
            block = head
            reflection = "--- reflection context" + tail.split("--- payload", 1)[0]
        else:
            block = block.split("--- payload", 1)[0]
        block = block.strip("\n")
        if reflection:
            block = (block + "\n\n" + reflection.strip("\n")).strip("\n")
        if block:
            return block
    status = getattr(finding, "status", 0) or 0
    return (f"HTTP {status}\ncontent-type: {getattr(finding, 'content_type', '') or 'unknown'}\n"
            "(response body was not captured for this finding)")


def pair_text(finding) -> str:
    """Plain-text request/response pair for the evidence directory."""
    captured = _captured_request(finding)
    if captured:
        method, path, headers, body = captured
        request = [f"{method} {path} HTTP/1.1"]
        for name, value in headers:
            if name.lower() in ("cookie", "authorization"):
                request.append(f"{name}: <redacted>")
            else:
                request.append(f"{name}: {value}")
        if body:
            request.extend(["", body])
        request_text = "\n".join(request)
    else:
        request_text = f"{finding.method} {finding.url}\n(no raw request was captured)"
    return ("# request\n" + request_text +
            "\n\n# response\n" + response_block(finding) + "\n")


def severity_conditions(finding) -> list[str]:
    """What evidence would raise or lower the rating."""
    out: list[str] = []
    state = getattr(finding, "verify_state", "")
    if getattr(finding, "csp_blocked", False):
        out.append("Execution is currently blocked by the page's CSP; this becomes high "
                   "impact if the policy is relaxed or bypassed.")
    if state == "not_tested" or (not getattr(finding, "browser_checked", False)
                                 and not getattr(finding, "verified_browser", False)):
        out.append("Execution was never observed; raise the rating once a browser (or an "
                   "out-of-band hit) confirms the payload runs.")
    elif state == "not_observed" and not getattr(finding, "verified_browser", False):
        out.append("The marker was reflected but no handler ran; lower the rating if the "
                   "sink is inert (for example a CSP nonce or a text-only sink).")
    exploit = getattr(finding, "exploit", None) or {}
    if exploit.get("status") == "proven":
        caps = exploit.get("capabilities") or {}
        if caps.get("cookie_bytes") or caps.get("csrf_token_readable"):
            out.append("The exploit stage proved script execution and read cookie/token "
                       "material; lower the rating if those values are non-sensitive or "
                       "the cookies are HttpOnly in the affected deployment.")
        else:
            out.append("Script execution was proven but no cookie, token or same-origin "
                       "read was observed; raise the rating if the origin holds an "
                       "authenticated session reachable from this page.")
    elif exploit.get("status") == "unproven":
        out.append("The weaponised replay did not execute; raise the rating if a browser "
                   "that supports the vector (or a less strict policy) is used.")
    elif exploit.get("status") == "not_tested":
        out.append("The exploit stage could not replay this finding ("
                   + (exploit.get("reason") or "no browser") +
                   "); impact is unmeasured rather than absent.")
    if getattr(finding, "interaction", False):
        out.append("Exploitation needs a user gesture; lower the rating if no realistic "
                   "gesture exists on the page.")
    if getattr(finding, "verified_browser", False):
        out.append("Raise the rating if the same sink is reachable from an authenticated "
                   "or administrative page; lower it if only trusted users can reach it.")
    if getattr(finding, "confidence", "") == "low":
        out.append("Confidence is low because the reflection was not stable across re-sends; "
                   "re-test before rating it.")
    return out
