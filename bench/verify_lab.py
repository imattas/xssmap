"""Check bench/lab2's declared ground truth against what it really returns.

A benchmark is only as good as its labels. This module probes every endpoint
with a benign marker and asserts the claim made by ``LABELS``:

* vulnerable: the marker is echoed unencoded, at the declared syntactic
  position, and quote/tag characters survive as characters (not entities);
* safe: the marker is encoded, stripped or coerced, and never appears as live
  markup;
* json: the body is served as JSON and the marker lives inside a JSON string.

The checks use plain string assertions on purpose. Classifying the response with
the scanner's own parser would make the verifier agree with the scanner by
construction and hide parser bugs.

Run directly for a report:  python bench/verify_lab.py
"""
from __future__ import annotations

import json
import os
import sys
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from bench.lab2.app import LABELS, serve_in_thread  # noqa: E402

PROBE = "BMK7q2"
HOSTILE = "BMK7\"q2<x>"   # quote + tag characters that must not be encoded

# How the marker must appear for each declared context.
EXPECT_TEMPLATE = {
    "html_text": ">{probe}<",
    "attr_double": 'value="{probe}"',
    "attr_single": "value='{probe}'",
    "attr_unquoted": "value={probe} ",
    "js_string_single": "'{probe}'",
    "textarea": ">{probe}</textarea>",
    "title": "<title>{probe}</title>",
    "comment": "<!-- debug: {probe} -->",
}


def _fetch(base: str, path: str, param: str, method: str, value: str):
    quoted = urllib.parse.quote_plus(value)
    if method == "POST":
        data = urllib.parse.urlencode({param: value}).encode()
        request = urllib.request.Request(base + path, data=data, method="POST")
    else:
        request = urllib.request.Request(f"{base}{path}?{param}={quoted}")
    with urllib.request.urlopen(request, timeout=10) as response:
        return (response.status, response.headers.get("Content-Type", ""),
                response.read().decode("utf-8", "replace"))


def check(base: str) -> list[str]:
    """Return a list of human-readable problems; empty means the lab is honest."""
    problems: list[str] = []
    for label in LABELS:
        path, param = label["path"], label["param"]
        method = label.get("method", "GET")
        try:
            status, ctype, body = _fetch(base, path, param, method, PROBE)
        except Exception as exc:
            problems.append(f"{path}: request failed: {exc}")
            continue
        if status != 200:
            problems.append(f"{path}: status {status}")
            continue

        if not label["vulnerable"]:
            _status, _ctype, hostile_body = _fetch(base, path, param, method, HOSTILE)
            if path == "/api/echo":
                if "json" not in ctype.lower():
                    problems.append(f"{path}: expected a JSON content type, got {ctype!r}")
                # JSON itself escapes the quote, so the body is decoded before
                # comparing; the escaping is the serialiser's, not XSS defence,
                # which is exactly why the content type is the control.
                try:
                    echoed = json.loads(hostile_body).get("echo")
                except ValueError:
                    problems.append(f"{path}: body is not valid JSON")
                    continue
                if echoed != HOSTILE:
                    problems.append(f"{path}: JSON echo was {echoed!r}")
                continue
            if path == "/escape":
                if "&lt;x&gt;" not in hostile_body:
                    problems.append(f"{path}: marker was not HTML-encoded")
                if HOSTILE in hostile_body:
                    problems.append(f"{path}: hostile probe survived unencoded")
                continue
            if path == "/strip":
                if "<x>" in hostile_body:
                    problems.append(f"{path}: tag survived the stripper")
                if HOSTILE in hostile_body:
                    problems.append(f"{path}: hostile probe survived the stripper")
                continue
            if HOSTILE in hostile_body:
                problems.append(f"{path}: hostile probe was echoed, label says safe")
            if "count is" not in hostile_body:
                problems.append(f"{path}: expected the numeric rendering, got none")
            continue

        context = label.get("context", "")
        template = EXPECT_TEMPLATE.get(context)
        if template is None:
            problems.append(f"{path}: unknown context {context!r}")
            continue
        if template.format(probe=PROBE) not in body:
            problems.append(
                f"{path}: expected {template.format(probe=PROBE)!r} for {context}")

        # The vulnerability claim is "no encoding", so hostile characters must
        # arrive as themselves. The probe is chosen to stay inside the same
        # syntactic slot (it does not close the tag), so the raw substring is a
        # fair test for all contexts except attr_unquoted, where a space would
        # end the value.
        if context != "attr_unquoted":
            _status, _ctype, hostile_body = _fetch(base, path, param, method, HOSTILE)
            if HOSTILE not in hostile_body:
                problems.append(
                    f"{path}: hostile probe was encoded or rewritten, so the endpoint "
                    f"is not actually injectable ({context})")
    return problems


def main() -> int:
    server, _thread = serve_in_thread(0)
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        problems = check(base)
    finally:
        server.shutdown()
        server.server_close()
    if problems:
        for problem in problems:
            print(f"FAIL  {problem}")
        print(f"\n{len(problems)} label problem(s); the benchmark would be measuring a lie")
        return 1
    print(f"OK    {len(LABELS)} labels match observed behaviour at {base}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
