"""Resumable scan state: completed injection points and findings already proven.

A long engagement can stop (Ctrl-C, budget, shift end) and continue later
without paying for every request twice. The file is plain JSON so it can be
inspected, diffed or shipped next to a report.

What resume does and does not cover:

  * injection points that finished scanning are recorded and skipped next run
  * findings/leads already proven are merged back into the next report
  * crawling still happens (cheap, and it refreshes forms/tokens)
  * stored, DOM and mXSS work is re-derived from whatever the crawl finds
"""
from __future__ import annotations

import datetime as dt
import json
import os
import tempfile

from . import report as rp
from .scanner import Finding

STATE_VERSION = 1
MAX_KEPT = 5000  # bound the file even on very large engagements


def empty_state() -> dict:
    return {"version": STATE_VERSION, "done": [], "findings": [], "leads": []}


def load_state(path: str) -> dict:
    """Read a state file. Never raises: an unreadable file becomes empty state."""
    data = empty_state()
    if not path:
        return data
    try:
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
    except FileNotFoundError:
        return data
    except (OSError, ValueError) as exc:
        data["error"] = f"{path}: {exc}"
        return data
    if not isinstance(raw, dict) or int(raw.get("version") or 0) > STATE_VERSION:
        data["error"] = f"{path}: unsupported state format"
        return data

    done = raw.get("done")
    if isinstance(done, list):
        data["done"] = [str(key) for key in done if isinstance(key, (str, int))]
    for key in ("findings", "leads"):
        items = raw.get(key)
        if not isinstance(items, list):
            continue
        for item in items[:MAX_KEPT]:
            finding = finding_from_dict(item)
            if finding is not None:
                data[key].append(finding)
    return data


def finding_from_dict(data) -> Finding | None:
    """Rebuild a Finding from the report JSON shape (inverse of finding_to_dict)."""
    if not isinstance(data, dict) or not data.get("url"):
        return None
    notes = data.get("notes") or []
    if isinstance(notes, str):
        notes = [notes]
    exploit = data.get("exploit")
    exploit = dict(exploit) if isinstance(exploit, dict) else {}
    return Finding(
        url=str(data.get("url") or ""),
        method=str(data.get("method") or "GET"),
        param=str(data.get("parameter") or ""),
        location=str(data.get("location") or ""),
        payload=str(data.get("payload") or ""),
        context=str(data.get("context") or ""),
        status=_as_int(data.get("http_status")),
        confidence=str(data.get("confidence") or "medium"),
        verified_browser=bool(data.get("browser_verified")),
        browser_checked=bool(data.get("browser_checked")),
        csp_blocked=bool(data.get("csp_blocked")),
        csp=str(data.get("csp") or ""),
        interaction=bool(data.get("requires_interaction")),
        evidence=str(data.get("evidence") or ""),
        notes=[str(n) for n in notes if str(n).strip()],
        content_type=str(data.get("content_type") or ""),
        nosniff=bool(data.get("nosniff")),
        reflections=_as_int(data.get("reflection_count")),
        encoding=str(data.get("filter_profile") or ""),
        verify_state=str(data.get("verify_state") or ""),
        verify_reason=str(data.get("verify_reason") or ""),
        template=str(data.get("template") or ""),
        payload_name=str(data.get("payload_name") or ""),
        # Exploit proof survives a resume, so a later report does not lose the
        # measured impact (the original request object cannot be serialised and
        # is rebuilt from url/method when possible).
        exploit=exploit,
    )


def save_state(path: str, targets, done, findings, leads) -> None:
    """Write the state file atomically (a crash cannot truncate it)."""
    payload = {
        "version": STATE_VERSION,
        "tool": f"xssmap {rp.VERSION}",
        "saved": dt.datetime.now().isoformat(timespec="seconds"),
        "targets": list(targets or []),
        "done": sorted({str(key) for key in done or ()}),
        "findings": [rp.finding_to_dict(f) for f in list(findings or [])[:MAX_KEPT]],
        "leads": [rp.finding_to_dict(f) for f in list(leads or [])[:MAX_KEPT]],
    }
    directory = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(prefix=".xssmap-state-", suffix=".json", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=1, sort_keys=False)
            fh.write("\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _as_int(value) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0
