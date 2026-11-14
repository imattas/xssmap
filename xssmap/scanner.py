"""XSS detection engine.

Per injection point the engine:
  1. sends a baseline request and a unique alphanumeric marker
  2. classifies every reflection context (HTML text / attribute + quote style /
     JS string / JS code / comment / RCDATA / CSS / tag space)
  3. emits payloads aimed at that exact context, filtered by --level/--risk
  4. requires a *verbatim* reflection with the break-out character intact
  5. re-sends to rule out flaky/one-off responses
  6. optionally confirms execution in a real headless browser
"""
from __future__ import annotations

import html
import json
import re
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from . import brute, charset, csp, efficiency, mxss, waf
from .filters import FilterProfile, build_profile, mutate
from .htmlparse import (
    Form,
    build_query,
    parse_page,
    query_pairs,
    set_query_param,
)
from .net import HTTP, NetError, RawCapture, Request, Response
from .payloads import (
    Payload,
    Reflection,
    classify_reflections,
    generic_payloads,
    new_marker,
    new_marker_letters,
    payloads_for_context,
    polyglot_payload,
    reflection_at,
)
from .verify import Verification

MAX_PARAM_LEN = 2000
MUTATIONS_PER_PAYLOAD = 3
MXSS_BUDGET = 24  # browser loads per scan; each is a full page load
MXSS_VECTORS_PER_POINT = 6  # the six highest-yield vectors, in table order
CHARSET_BUDGET = 8  # injection points probed for a multibyte escape bypass


def _csp_note(policy: csp.Assessment, markup: str, resp: Response) -> str:
    """Policy summary + feasibility, plus what strict-dynamic leaves open."""
    if not policy.present:
        return ""
    return csp.describe_with_gadgets(policy, markup, resp.url, resp.text or "")


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    url: str
    method: str
    param: str
    location: str
    payload: str
    context: str
    status: int
    confidence: str = "high"
    verified_browser: bool = False
    browser_checked: bool = False
    csp_blocked: bool = False
    # Rendered policy summary plus a static feasibility verdict for this payload.
    csp: str = ""
    interaction: bool = False
    evidence: str = ""
    notes: list[str] = field(default_factory=list)
    content_type: str = ""
    nosniff: bool = False
    reflections: int = 0
    encoding: str = ""
    title: str = ""
    mutation: str = ""
    record_tag: str = ""
    filter_profile: dict = field(default_factory=dict)
    # Tri-state browser verdict. Empty string means the browser was never asked.
    verify_state: str = ""
    verify_reason: str = ""
    # Payload template that produced `payload` (keeps the {JS}/{M} slots, so a
    # later stage can re-render the same working vector with a different script
    # instead of guessing at the context again).
    template: str = ""
    payload_name: str = ""
    # The exact request that triggered the finding, so the exploit stage can
    # replay it with a weaponised payload (same method, headers, cookies, body).
    request: object | None = None
    # What the exploit stage proved the injected script can do. Empty until
    # --verify runs; never filled from an assumption.
    exploit: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Injection points
# ---------------------------------------------------------------------------

class InjectionPoint:
    kind = "generic"

    def label(self) -> str:
        raise NotImplementedError

    def original(self) -> str:
        raise NotImplementedError

    def build(self, value: str) -> Request:
        raise NotImplementedError

    def describe(self) -> str:
        return self.label()


class QueryPoint(InjectionPoint):
    kind = "query"

    def __init__(self, url: str, index: int, headers: list[tuple[str, str]]):
        self.url = url
        self.index = index
        self.headers = headers
        pairs = query_pairs(url)
        self.name = pairs[index][0] if index < len(pairs) else "?"

    def original(self) -> str:
        pairs = query_pairs(self.url)
        return pairs[self.index][1] if self.index < len(pairs) else ""

    def build(self, value: str) -> Request:
        return Request("GET", set_query_param(self.url, self.index, value), list(self.headers))

    def label(self) -> str:
        return f"GET param '{self.name}'"


class FormPoint(InjectionPoint):
    kind = "form"

    def __init__(self, form: Form, field_name: str, headers: list[tuple[str, str]],
                 csrf_fetcher=None):
        self.form = form
        self.name = field_name
        self.headers = headers
        self.csrf_fetcher = csrf_fetcher

    def original(self) -> str:
        for n, v, _ in self.form.params:
            if n == self.name:
                return v
        return ""

    def _params(self) -> list[tuple[str, str]]:
        pairs = []
        for n, v, t in self.form.params:
            if n and t not in ("submit", "button", "file", "image", "reset"):
                pairs.append((n, v))
        if self.csrf_fetcher:
            try:
                fresh = self.csrf_fetcher()
                merged = dict(pairs)
                merged.update(fresh)
                pairs = list(merged.items())
            except Exception:
                pass
        return pairs

    def build(self, value: str) -> Request:
        pairs = [(n, value if n == self.name else v) for n, v in self._params()]
        method = self.form.method
        if method == "GET":
            parts = urllib.parse.urlsplit(self.form.action)
            glue = "&" if parts.query else ""
            url = urllib.parse.urlunsplit((
                parts.scheme, parts.netloc, parts.path, parts.query + glue + build_query(pairs), ""))
            return Request("GET", url, list(self.headers))
        body = build_query(pairs).encode()
        headers = list(self.headers) + [("Content-Type", "application/x-www-form-urlencoded")]
        return Request("POST", self.form.action, headers, body)

    def label(self) -> str:
        return f"{self.form.method} form field '{self.name}'"


class JsonPoint(InjectionPoint):
    kind = "json"

    def __init__(self, url: str, path: list, body: bytes, headers: list[tuple[str, str]],
                 method: str = "POST"):
        self.url = url
        self.path = path
        self.body = body
        self.headers = headers
        self.method = method

    def _get(self, obj, default=None):
        cur = obj
        for k in self.path:
            try:
                cur = cur[k] if not isinstance(cur, list) else cur[int(k)]
            except Exception:
                return default
        return cur

    def original(self) -> str:
        try:
            return str(self._get(json.loads(self.body))) if self.body else ""
        except Exception:
            return ""

    def _set(self, obj, value):
        cur = obj
        for k in self.path[:-1]:
            cur = cur[k] if not isinstance(cur, list) else cur[int(k)]
        last = self.path[-1]
        if isinstance(cur, list):
            cur[int(last)] = value
        else:
            cur[last] = value
        return obj

    def build(self, value: str) -> Request:
        data = json.loads(self.body)
        data = self._set(data, value)
        headers = list(self.headers) + [("Content-Type", "application/json")]
        return Request(self.method, self.url, headers, json.dumps(data).encode())

    def label(self) -> str:
        return f"JSON field '{'.'.join(map(str, self.path))}'"


class HeaderPoint(InjectionPoint):
    kind = "header"

    def __init__(self, url: str, header: str, base_headers: list[tuple[str, str]], method: str = "GET"):
        self.url = url
        self.header = header
        self.base_headers = base_headers
        self.method = method

    def original(self) -> str:
        for k, v in self.base_headers:
            if k.lower() == self.header.lower():
                return v
        return ""

    def build(self, value: str) -> Request:
        headers = [(k, v) for k, v in self.base_headers if k.lower() != self.header.lower()]
        headers.append((self.header, value))
        return Request(self.method, self.url, headers)

    def label(self) -> str:
        return f"{self.header} header"


class CookiePoint(InjectionPoint):
    kind = "cookie"

    def __init__(self, url: str, cookie_name: str, headers: list[tuple[str, str]]):
        self.url = url
        self.cookie_name = cookie_name
        self.headers = headers

    def _cookies(self) -> list[tuple[str, str]]:
        for k, v in self.headers:
            if k.lower() == "cookie":
                out = []
                for part in v.split(";"):
                    part = part.strip()
                    if "=" in part:
                        n, val = part.split("=", 1)
                        out.append((n.strip(), val.strip()))
                return out
        return []

    def original(self) -> str:
        for n, v in self._cookies():
            if n == self.cookie_name:
                return v
        return ""

    def build(self, value: str) -> Request:
        cookies = [(n, value if n == self.cookie_name else v) for n, v in self._cookies()]
        jar = "; ".join(f"{n}={v}" for n, v in cookies)
        headers = [(k, v) for k, v in self.headers if k.lower() != "cookie"]
        headers.append(("Cookie", jar))
        return Request("GET", self.url, headers)

    def label(self) -> str:
        return f"cookie '{self.cookie_name}'"


# ---------------------------------------------------------------------------
# JS call variants
# ---------------------------------------------------------------------------

def js_variants(marker: str) -> list[tuple[str, str]]:
    return [
        ("alert", f"alert('{marker}')"),
        ("prompt", f"prompt('{marker}')"),
        ("confirm", f"confirm('{marker}')"),
        ("window-alert", f"window['al'+'ert']('{marker}')"),
        ("alert-nested", f"(alert)('{marker}')"),
    ]


def dom_js(marker: str) -> str:
    """JS that leaves a DOM artifact so a headless browser can prove execution.

    Deliberately avoids < > and spaces so it survives unquoted attribute
    contexts and inside-script contexts alike.
    """
    return ("document.body.appendChild(document.createElement('b')).id='"
            + dom_marker_id(marker) + "'")


def dom_marker_id(marker: str) -> str:
    return f"xmm{marker}x"


def charset_js(marker: str) -> str:
    """JS artifact for the multibyte probe, using backticks only.

    The target under test backslash-escapes both quote kinds, so the injected
    statement must not contain ``'`` or ``"`` at all: after the breakout those
    characters would be re-escaped and turn the statement into a syntax error.
    Template literals are not touched by ``addslashes``-style escaping.
    """
    return ("document.body.appendChild(document.createElement(`b`)).id=`"
            + dom_marker_id(marker) + "`")


def byte_repr(data: bytes) -> str:
    """Print bytes so a human can see exactly which bytes were sent."""
    return "".join(chr(b) if 32 <= b < 127 and b != 0x5C else f"\\x{b:02x}" for b in data)


def hex_window(body: bytes, needle: bytes, before: int = 24, after: int = 48) -> str:
    """Hexdump of the served bytes around a byte pattern."""
    index = body.find(needle)
    if index < 0:
        return "(pattern not found in response bytes)"
    start = max(0, index - before)
    chunk = body[start:index + len(needle) + after]
    hexed = " ".join(f"{b:02x}" for b in chunk)
    raw = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
    return f"offset {start}: {hexed}\n          {raw}"


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class Scanner:
    def __init__(self, http: HTTP, level: int = 2, risk: int = 2, browser=None,
                 log=None, headers: list[tuple[str, str]] | None = None,
                 params_override: str | None = None, delay_between: float = 0.0,
                 cookie_header: str | None = None, profile_enabled: bool = True,
                 mutation_budget: int = MUTATIONS_PER_PAYLOAD,
                 skip_points: set[str] | None = None,
                 deadline: float | None = None,
                 waf_detection=None, evasion: bool = True,
                 bruteforce: bool = False, brute_budget: int = 40,
                 waf_budget: int = 240):
        self.http = http
        self.level = level
        self.risk = risk
        self.browser = browser
        self.log = log
        self.headers = list(headers or [])
        self.params_override = params_override
        self.findings: list[Finding] = []
        self.leads: list[Finding] = []
        self._profiles: dict[str, FilterProfile] = {}
        self.lock = threading.Lock()
        self.delay_between = delay_between
        self.tested = 0
        self.points_total = 0
        self._seen_findings: set[str] = set()
        self._tested_points: set[str] = set()
        # Points recorded by an earlier run through --state. They are not tested
        # again; completed_points only grows for work that actually finished, so
        # an interrupted run never claims more progress than it earned.
        self.skip_points: set[str] = set(skip_points or ())
        self.completed_points: set[str] = set()
        self.resumed_points = 0
        self._baseline_status_cache: dict[str, int] = {}
        # One in-flight baseline per request: two parameters of the same URL are
        # queued next to each other, so without this the workers both miss the
        # cache and both fetch the same page.
        self._baseline_inflight: dict[str, threading.Event] = {}
        self.profile_enabled = profile_enabled
        self.mutation_budget = max(0, mutation_budget)
        self.interrupted = False
        # Monotonic deadline shared with the caller's --max-minutes budget.
        # Enforced per point, not only between phases, so a single large phase
        # cannot quietly overrun the wall-clock budget it promised.
        self.deadline = deadline
        self.budget_exhausted = False
        self.budget_stop = False
        # WAF evasion: only candidate *generation* changes, never the proof
        # standard. A variant that does not reflect verbatim is dropped like any
        # other payload, so an evasion failure cannot become a finding.
        self.waf = waf_detection
        self.evasion = evasion
        # What this target itself taught us about its filter: proven strategies
        # are tried first, filtered ones last. Reordering only; the budget and
        # the evidence bar are untouched.
        self.evasion_memory = waf.AdaptiveEvasion()
        # A *global* ceiling only, so one hostile point cannot spend the budget
        # the rest of the page needs. Each reflection gets its own share from
        # waf.evasion_budget() and the total is capped here (--evasion-budget).
        self._evasion_left = max(0, waf_budget)
        # Character-level brute force, spent only on reflecting points where
        # every crafted payload failed.
        self.bruteforce = bruteforce
        self._brute_left = max(0, brute_budget)
        self.brute_reports: list[dict] = []
        self.stats = {"points": 0, "requests": 0, "reflected_points": 0, "verified": 0,
                      "mxss_probes": 0, "charset_probes": 0, "waf_variants": 0,
                      "brute_probes": 0}

    # -- payload selection -------------------------------------------
    def _payloads_for(self, refl: Reflection) -> list[Payload]:
        base = payloads_for_context(refl)
        if refl.context in ("js_string_double", "js_string_single", "js_template"):
            # a script close-out always works regardless of string state
            base = base + [p for p in generic_payloads() if p.name == "polyglot"]
        out: list[Payload] = []
        for p in base:
            if p.danger == "high" and self.risk < 3:
                continue
            if p.danger == "medium" and self.risk < 2:
                continue
            if self.level < 2 and p.context in ("js_code", "js_string_double", "js_string_single", "js_template", "comment"):
                continue
            if self.level < 3 and p.name in ("ultim-polyglot",):
                continue
            out.append(p)
        return out

    # -- main entry --------------------------------------------------
    def _over_budget(self) -> bool:
        if self.deadline is None or time.monotonic() < self.deadline:
            return False
        with self.lock:
            self.budget_exhausted = True
        return True

    def scan_points(self, points: list[InjectionPoint], concurrency: int = 4) -> list[Finding]:
        self.points_total = len(points)
        if not points:
            return []
        done = 0
        pool = ThreadPoolExecutor(max_workers=max(1, concurrency))
        futures: dict = {}
        try:
            futures = {pool.submit(self.scan_point, p): p for p in points}
            for fut in as_completed(futures):
                point = futures[fut]
                done += 1
                try:
                    found = fut.result()
                except Exception as exc:
                    if self.log:
                        self.log.debug(f"  error on {point.label()}: {exc}")
                    continue
                if found:
                    with self.lock:
                        self.findings.extend(found)
                    if self.log:
                        for f in found:
                            self.log.found(f)
                if self.log:
                    self.log.progress(done, len(points), point.label())
                if self._over_budget():
                    for not_started in [f for f in futures if not f.done()]:
                        not_started.cancel()
                    self.budget_stop = True
                    break
        except KeyboardInterrupt:
            # Ctrl-C must not throw away everything already proven: stop handing
            # out work, keep the findings that completed, and let the caller
            # write a partial report. In-flight workers are cancelled, not awaited.
            self.interrupted = True
            for pending in futures:
                pending.cancel()
            if self.log:
                self.log.warn("interrupted: keeping the findings that already completed")
        finally:
            if self.interrupted:
                # Ctrl-C: do not block on workers that are mid-request.
                pool.shutdown(wait=False, cancel_futures=True)
            elif self.budget_stop:
                # Budget: drop queued work, but let the points already in flight
                # finish so their findings are not lost. Overshoot is bounded by
                # a single point, not by a whole phase.
                pool.shutdown(wait=True, cancel_futures=True)
            else:
                pool.shutdown(wait=True)
            if self.budget_stop and self.log:
                # Counted after shutdown: a free worker drains the gate-skipped
                # queue in microseconds, so "futures not done yet" was never a
                # truthful measure of what the budget actually cost.
                msg = f"time budget reached mid-scan; {self.stats['points']} point(s) tested"
                if self.resumed_points:
                    msg += f", {self.resumed_points} skipped as already done"
                self.log.warn(msg)
        return self.findings

    def scan_point(self, point: InjectionPoint) -> list[Finding]:
        # Past the deadline: do not start new work and do not claim progress.
        # The point stays out of completed_points, so --state still re-tests it.
        if self._over_budget():
            return []
        key = self._point_key(point)
        with self.lock:
            if key in self._tested_points:
                return []
            self._tested_points.add(key)
            if key in self.skip_points:
                self.resumed_points += 1
                return []

        found: list[Finding] = []
        finished = False
        try:
            found = self._scan(point)
            finished = True
        except NetError as exc:
            if self.log:
                self.log.debug(f"  network error {point.label()}: {exc}")
        except Exception as exc:
            if self.log:
                self.log.debug(f"  scan error {point.label()}: {exc}")
        with self.lock:
            self.stats["points"] += 1
            if finished:
                self.completed_points.add(key)
        return found

    def _baseline_status(self, req: Request) -> int | None:
        """Status of a baseline request, cached per method+URL+body.

        A URL with three parameters produces three points whose baseline request
        is byte-identical, and the engine only reads ``.status`` from it. Bodies
        are never cached, so this costs a dictionary of integers rather than a
        copy of every page.
        """
        key = f"{req.method} {req.url}\x00{req.body!r}"
        event: threading.Event
        with self.lock:
            cached = self._baseline_status_cache.get(key)
            if cached is not None:
                return cached
            existing = self._baseline_inflight.get(key)
            owner = existing is None
            if existing is None:
                event = threading.Event()
                self._baseline_inflight[key] = event
            else:
                event = existing
        if not owner:
            # Another worker is fetching exactly this baseline; its answer is ours.
            event.wait(getattr(self.http, "timeout", 15.0) + 5.0)
            with self.lock:
                return self._baseline_status_cache.get(key)
        try:
            status: int | None = self._send(req).status
        except NetError:
            status = None
        with self.lock:
            if status is not None:
                if len(self._baseline_status_cache) >= 4096:
                    self._baseline_status_cache.clear()
                self._baseline_status_cache[key] = status
            self._baseline_inflight.pop(key, None)
        event.set()
        return status

    def _point_key(self, p: InjectionPoint) -> str:
        if isinstance(p, QueryPoint):
            return f"q:{p.url.split('#')[0]}:{p.index}"
        if isinstance(p, FormPoint):
            return f"f:{p.form.action}:{p.name}"
        if isinstance(p, JsonPoint):
            return f"j:{p.url}:{'.'.join(map(str, p.path))}"
        if isinstance(p, HeaderPoint):
            return f"h:{p.url}:{p.header}"
        if isinstance(p, CookiePoint):
            return f"c:{p.url}:{p.cookie_name}"
        return str(id(p))

    # -- detection ---------------------------------------------------
    def _send(self, req: Request, allow_redirects: bool = False) -> Response:
        with self.lock:
            self.stats["requests"] += 1
        return self.http.send(req, allow_redirects=allow_redirects)

    def _scan(self, point: InjectionPoint) -> list[Finding]:
        if self.delay_between:
            import time
            time.sleep(self.delay_between)
        original = point.original()
        if self.params_override is not None:
            value_original = self.params_override
        else:
            value_original = original

        # 1. baseline with the original value (some apps 500 on empty params).
        # Only the status is ever consulted, so it is shared between points that
        # build the identical request -- the second parameter of a URL does not
        # need its own copy of the same round trip.
        baseline_status = self._baseline_status(point.build(value_original))

        marker = new_marker()
        marker_value = f"{marker}zqx"
        resp = self._send(point.build(marker_value))
        # A 500 here where the unmodified URL answered fine means our value broke
        # the request. The old code answered that by re-sending the identical
        # probe, which can only reproduce the 500 and costs a round trip; the
        # error body is analysed below instead, because some applications echo
        # the value inside their error page.
        if (self.log and baseline_status is not None and resp.status >= 500
                and baseline_status < 500):
            self.log.debug(f"    {point.label()} answers {resp.status} with our value "
                           f"({baseline_status} unmodified); error body kept")

        marker, resp, match = self._settle_probe(point, marker, resp)
        text = resp.text
        if not resp.is_html:
            if match.reflected:
                # JSON/XML/JS echoes are not HTML execution contexts, but they
                # are sinks: stored and DOM XSS read from exactly these bodies.
                if self.log:
                    self.log.debug(
                        f"    reflection in non-HTML body ({resp.content_type or 'no content-type'}) "
                        f"for {point.label()} - recorded as a lead")
                self._lead(point, marker, resp, match, kind="non-html")
            return []
        page = parse_page(resp.url, text)
        reflections = classify_reflections(page, marker) if match.verbatim else []
        recovered: Reflection | None = None
        if not reflections:
            if not match.reflected:
                return []
            # The value is reflected, but mangled: there is no marker to search
            # for, so classify the position the efficiency match points at
            # instead of reporting the point as unreflected.
            recovered = reflection_at(page, match.offset)
        with self.lock:
            self.stats["reflected_points"] += 1

        primary: Reflection | None = reflections[0] if reflections else recovered
        if self.log:
            if reflections:
                contexts = ", ".join(sorted({r.context for r in reflections}))
                self.log.debug(f"    reflected in {point.label()} -> {contexts}")
            else:
                where = primary.context if primary is not None else "unclassified"
                self.log.debug(f"    reflected in {point.label()} -> {where} "
                               f"(inferred from position; {match.describe()})")

        encoding = self._encoding_profile(text, marker)
        profile = self._profile_point(
            point, marker, context=primary.context if primary is not None else "")
        findings: list[Finding] = []
        tried_contexts: set[str] = set()
        # A mangled probe means a crafted payload will be mangled too, so the
        # payload ladder is pointless there: only the character-level
        # synthesiser can build something the sink will pass through.
        ladder: list[Reflection] = list(reflections)
        if not ladder and match.executable_score and recovered is not None:
            ladder = [recovered]

        for refl in ladder:
            if refl.context in tried_contexts:
                continue
            tried_contexts.add(refl.context)
            result = self._try_context(point, refl, marker, encoding, resp, profile)
            if result:
                findings.append(result)
                with self.lock:
                    dedupe = f"{urllib.parse.urlsplit(result.url).netloc}{urllib.parse.urlsplit(result.url).path}|" \
                             f"{result.param}|{refl.context}"
                    if dedupe in self._seen_findings:
                        findings.pop()
                    else:
                        self._seen_findings.add(dedupe)
        # Cheap and browser-free, so it runs before the browser stages: a hit
        # here is a complete finding on its own (byte-level proof).
        if match.verbatim and not any(f.verified_browser for f in findings):
            charset_hit = self._charset_stage(point, resp, marker)
            if charset_hit:
                findings.append(charset_hit)
        # Nothing crafted worked, but the point reflects: measure the filter one
        # character at a time and rebuild a payload from what survives. This is
        # the only stage that can still land a payload on a sink that rewrites
        # its output, because it builds from the characters that survive.
        if (self.bruteforce and self.level >= 2 and not findings
                and self._brute_left >= 6 and primary is not None):
            brute_hit = self._bruteforce_stage(point, primary, marker, resp,
                                               inferred=not bool(reflections))
            if brute_hit:
                findings.append(brute_hit)
        if (self.level >= 2 and self.browser and getattr(self.browser, "available", False)
                and not any(f.verified_browser for f in findings)):
            mutated = self._mxss_stage(point, marker)
            if mutated:
                findings.append(mutated)
        if not findings:
            # The point reflects, so "nothing here" would be a wrong answer: the
            # payloads were stripped, encoded, cut, or never reached the sink.
            # Record what was observed so a human can judge whether a targeted
            # bypass is worth pursuing.
            self._lead(point, marker, resp, match, profile=profile, refl=primary,
                       kind=("unproven" if match.verbatim else "partial-reflection"))
        return findings

    def _charset_stage(self, point: InjectionPoint, resp: Response,
                       marker: str) -> Finding | None:
        """Test a backslash-escaping sink on a multibyte page encoding.

        Two requests decide it, neither needing a browser:

        1. the escape probe sends ``<marker>'`` and looks for ``<marker>\\'``
           in the raw body. No backslash escaping means there is nothing for a
           multibyte trick to defeat, and the stage stops here;
        2. the bypass probe sends ``lead ' ; <js> //`` as *bytes* (percent
           encoded, never decoded and re-encoded by the scanner) and looks for
           ``lead 0x5C 0x27 ;`` in the served bytes. In a multibyte encoding
           ``lead 0x5C`` is one character, so the quote after it is bare and
           the statement that follows is source code.

        The byte-level demonstration is evidence by itself (medium). A live
        browser verdict is what raises it to high, and its absence is reported
        as ``not_tested`` rather than as a negative.
        """
        if self.level < 2:
            return None
        family = charset.detect(resp.header("content-type"), resp.body)
        if family is None:
            return None
        with self.lock:
            if self.stats.get("charset_probes", 0) >= CHARSET_BUDGET:
                return None
            self.stats["charset_probes"] = self.stats.get("charset_probes", 0) + 1

        try:
            escape_probe = self._send(point.build(marker + "'"))
        except NetError:
            return None
        if marker.encode("ascii") + b"\\'" not in escape_probe.body:
            if self.log:
                self.log.debug(
                    f"    {marker} charset {family.name}: quote is not backslash-escaped "
                    f"at {point.label()}, multibyte bypass does not apply")
            return None

        js = charset_js(marker)
        target_id = dom_marker_id(marker)
        payload = charset.probe_bytes(family, js)
        placeholder = f"xssmapraw{marker}"
        request = self._raw_bytes_request(point.build(placeholder), placeholder, payload)
        try:
            byte_resp = self._send(request)
        except NetError:
            return None
        js_head = b"document."
        if not charset.bypass_in_body(byte_resp.body, family, js_head):
            if self.log:
                self.log.debug(
                    f"    {marker} charset {family.name}: bytes did not survive "
                    f"at {point.label()} (no bare quote after the lead byte)")
            return None

        verdict = self._charset_verify(request, target_id)
        finding = self._charset_finding(point, byte_resp, request, payload, family, verdict,
                                         marker, escape_probe)
        with self.lock:
            parts = urllib.parse.urlsplit(byte_resp.url)
            dedupe = f"{parts.netloc}{parts.path}|{finding.param}|charset"
            if dedupe in self._seen_findings:
                return None
            self._seen_findings.add(dedupe)
            if verdict.is_confirmed:
                self.stats["verified"] += 1
        return finding

    @staticmethod
    def _raw_bytes_request(request: Request, placeholder: str, payload: bytes) -> Request:
        """Replace an ASCII placeholder with raw percent-encoded payload bytes.

        Every point builder URL-encodes the value it is given, so the bytes are
        smuggled through as a token that survives encoding untouched and are
        then swapped in place. Doing the encoding here (rather than decoding a
        response and re-encoding it) is what lets a GBK-only byte sequence reach
        the server intact.
        """
        encoded = urllib.parse.quote_from_bytes(payload, safe="")
        out = request.copy()
        out.url = out.url.replace(placeholder, encoded)
        if out.body:
            out.body = out.body.replace(placeholder.encode("ascii"), encoded.encode("ascii"))
            if out.header("content-length") is not None:
                out.set_header("Content-Length", str(len(out.body)))
        return out

    def _charset_verify(self, request: Request, target_id: str) -> Verification:
        if not (self.browser and getattr(self.browser, "available", False)):
            return Verification.not_tested("browser verification not enabled")
        try:
            return self.browser.verify_execution(request, target_id)
        except Exception as exc:
            return Verification.from_exception(exc, "charset payload load")

    def _charset_finding(self, point: InjectionPoint, resp: Response, request: Request,
                         payload: bytes, family: charset.Family, verdict: Verification,
                         marker: str, escape_probe: Response) -> Finding:
        decoded = (family.lead + b"\\").decode(family.codec, "replace")
        marker_needle = family.lead + b"\\';"
        escape_needle = marker.encode("ascii") + b"\\'"
        display = byte_repr(payload)
        policy = csp.Assessment.from_headers(resp.headers)
        lines = [
            f"--- request ({point.kind} injection, raw multibyte bytes) ---",
            RawCapture.render_request(request.method, request.url, request.headers, request.body),
            "",
            "--- escape probe (is the quote escaped at all?) ---",
            f"sent value:  {marker}'",
            f"served as:   {marker}\\'  (byte-wise backslash escaping observed)",
            hex_window(escape_probe.body, escape_needle),
            "",
            f"--- response ---\nHTTP {resp.status}  content-type: {resp.header('content-type')}  "
            f"length: {len(resp.body)}",
            "",
            f"--- payload bytes ({family.name}) ---",
            display,
            f"lead {family.lead.hex()} + 0x5c decodes as {decoded!r} in {family.codec}: "
            f"one character, so the 0x27 that follows is not escaped",
            "",
            "--- served bytes around the breakout ---",
            hex_window(resp.body, marker_needle),
            "",
            f"browser verdict: {verdict.state} - {verdict.reason}",
        ]
        notes = [
            f"page encoding: {charset.describe(family)}",
            "the application backslash-escapes quotes byte-wise, which cannot work in a "
            f"multibyte encoding: 0x{family.lead.hex()} 0x5c is a single {family.codec} "
            "character, so the quote after it terminates the JavaScript string",
            "the payload was sent as raw percent-encoded bytes; the breakout is visible in "
            "the response bytes themselves",
        ]
        if verdict.is_confirmed:
            notes.append("execution confirmed in a real browser: the injected DOM node was observed")
        elif verdict.was_tested:
            notes.append("loaded in a browser but no execution was observed; the byte-level "
                         "breakout is real, the reason it did not run is reported above")
        else:
            notes.append("NOT TESTED in a browser: the byte-level breakout is proven, execution "
                         "of the injected statement is not")
        confidence = "high" if verdict.is_confirmed else "medium"
        finding = Finding(
            url=resp.url, method=resp.method,
            param=point.name if hasattr(point, "name") else point.label(),
            location=point.kind, payload=display, context="charset",
            request=request,
            status=resp.status, confidence=confidence,
            verified_browser=verdict.is_confirmed,
            browser_checked=verdict.was_tested,
            verify_state=verdict.state if verdict.was_tested else "not_tested",
            verify_reason=verdict.reason,
            evidence="\n".join(lines), notes=notes,
            title=f"Multibyte charset escaping bypass ({family.name})",
            content_type=resp.content_type,
            nosniff=(resp.header("x-content-type-options") or "").lower() == "nosniff",
            encoding=f"{family.codec} (declared by the page)",
        )
        if policy.present:
            finding.csp = _csp_note(policy, display, resp)
            feasibility = policy.feasibility(display, resp.url)
            if not verdict.is_confirmed and feasibility.allowed is False:
                finding.csp_blocked = True
                finding.confidence = "medium"
                finding.notes.append(
                    f"the page's Content-Security-Policy does not permit this technique: "
                    f"{feasibility.reason}")
        return finding

    def _bruteforce_stage(self, point: InjectionPoint, refl: Reflection, marker: str,
                          baseline_resp: Response, inferred: bool = False) -> Finding | None:
        """Build a payload from the characters the filter actually allows.

        Only reached when every crafted payload failed on a point that clearly
        reflects. Each probe is one marker-wrapped character, so a value that is
        rejected as a whole cannot hide which character caused it; the surviving
        set then drives synthesis for this reflection's context. Both the budget
        and the number of vectors are bounded by the caller's flags.
        """
        if refl.context not in brute.EXECUTABLE_CONTEXTS:
            return None
        with self.lock:
            budget = self._brute_left
        if budget < 8:
            return None

        def send(value):
            return self._send(point.build(value))

        # Probing must never eat the whole budget: discovering the filter and
        # then having nothing left to try against it is the one outcome this
        # stage exists to avoid.
        reserve = 3
        spent = 0

        def alloc(want: int) -> int:
            return max(0, min(want, budget - spent - reserve))

        chars = brute.map_chars(send, marker, max_requests=max(1, alloc(20)), log=self.log)
        spent += chars.requests
        forms: dict[str, str] = {}
        allowed = alloc(14)
        if chars.known and allowed >= 2:
            # Case matters: a filter that blocks "onerror" usually allows
            # "OnErRoR", and the HTML parser does not care. Probing only the
            # lowercase spelling would report a usable keyword as blocked.
            forms = brute.keyword_forms(send, marker, max_requests=allowed, log=self.log)
            spent += allowed
        blocked: dict[str, bool] = {}
        allowed = alloc(4)
        if chars.known and allowed >= 2:
            blocked = brute.map_pairs(send, marker, max_requests=allowed, log=self.log)
            spent += allowed
        truncation = 0
        allowed = alloc(4)
        if chars.known and allowed >= 2:
            truncation = brute.detect_truncation(send, marker, max_requests=allowed,
                                                 log=self.log)
            spent += allowed
        with self.lock:
            self._brute_left = max(0, self._brute_left - spent)
            self.stats["brute_probes"] += spent
        if not chars.known:
            return None

        words = {word: bool(form) for word, form in forms.items()}
        banned = tuple(seq for seq, ok in blocked.items() if not ok)
        profile = brute.summary(chars, words, context=refl.context, forms=forms,
                               blocked=blocked, truncation=truncation)
        synthetics = brute.synthesise(chars, words, marker=marker,
                                      context=refl.context, forms=forms, banned=banned)
        if not synthetics:
            return None
        if self.log:
            cut_note = f", truncated near {truncation}" if truncation else ""
            self.log.debug(f"    brute force: {chars.describe()}{cut_note} -> "
                           f"{len(synthetics)} synthesised vector(s) [{refl.context}]")

        verify_js = dom_js(marker)
        if refl.context == "attr_single":
            # The artifact script is single-quoted; inside a single-quoted
            # attribute that quote would close the handler early.
            verify_js = verify_js.replace("'", '"')

        for syn in synthetics[:6]:
            with self.lock:
                if self._brute_left <= 0:
                    break
                self._brute_left -= 1
            payload_str = syn.render(marker)
            if not payload_str or len(payload_str) > MAX_PARAM_LEN:
                continue
            try:
                resp = self._send(point.build(payload_str))
            except NetError:
                continue
            if resp.status in (401, 403, 404, 405, 429, 501) and resp.status != baseline_resp.status:
                continue
            payload = Payload(name=f"brute:{syn.name}", template=syn.template,
                              context=refl.context, danger="high")
            if not self._reflects_executably(resp, payload_str, refl, payload):
                continue
            try:
                resp2 = self._send(point.build(payload_str))
            except NetError:
                continue
            if payload_str not in resp2.text:
                continue  # one-off reflection: not a stable sink

            extra = [payload_str]
            if verify_js != dom_js(marker):
                extra.append(syn.render(marker, verify_js))
            verdict = self._browser_verify_ex(point, refl, marker, payload, payload_str,
                                              extra=extra)
            verified = verdict.is_confirmed
            browser_checked = verdict.was_tested
            notes = [f"payload synthesised from surviving characters ({syn.name})",
                     "filter map: " + chars.describe()]
            unusable = [w for w, ok in words.items() if not ok]
            if unusable:
                notes.append("keywords blocked in every casing: " + ", ".join(unusable))
            recased = [f"{w}->{form}" for w, form in forms.items()
                       if form and form != w]
            if recased:
                notes.append("keyword casing required: " + ", ".join(recased))
            if banned:
                notes.append("blocked sequences avoided: " + ", ".join(banned))
            if truncation:
                notes.append(f"the target truncates values near {truncation} characters")
            confidence = "high"
            if inferred:
                notes.append("the reflection context was inferred from the injected value's "
                             "position because the sink mangled the probe")
            if verified:
                notes.append("execution confirmed in a real browser: injected DOM node observed")
            elif browser_checked:
                confidence = "medium"
                notes.append("browser did not observe execution for the synthesised vector")
            elif inferred:
                # Position-derived context plus no execution proof is not high.
                confidence = "medium"
                notes.append("NOT TESTED in a browser: the vector survives the sink and the "
                             "context is inferred, so execution is unproven")
            else:
                notes.append("NOT TESTED in a browser: the reflection is confirmed, execution is not")
            finding = Finding(
                url=resp.url, method=resp.method,
                param=point.name if hasattr(point, "name") else point.label(),
                location=point.kind, payload=payload_str, context=refl.context,
                request=point.build(payload_str), template=syn.template,
                payload_name=f"brute:{syn.name}", status=resp.status,
                confidence=confidence, verified_browser=verified,
                browser_checked=browser_checked, interaction=False,
                evidence=self._build_evidence(point, payload_str, resp, refl, payload, True),
                mutation="brute-force", notes=notes,
                verify_state=verdict.state if browser_checked else "",
                verify_reason=verdict.reason if browser_checked else "",
                content_type=resp.content_type,
                nosniff=(resp.header("x-content-type-options") or "").lower() == "nosniff",
                reflections=resp.text.count(payload_str),
                filter_profile=profile,
            )
            policy = csp.Assessment.from_headers(resp.headers)
            if policy.present:
                finding.csp = _csp_note(policy, payload_str, resp)
                if policy.feasibility(payload_str, resp.url).allowed is False:
                    finding.csp_blocked = True
                    finding.confidence = "medium" if finding.confidence == "high" else finding.confidence
                    finding.notes.append("the page's Content-Security-Policy does not permit "
                                         "this payload's technique")
            if not resp.is_html and finding.confidence == "high":
                finding.confidence = "low"
            with self.lock:
                self.brute_reports.append({"point": point.label(), "context": refl.context,
                                           "vector": syn.name, "payload": payload_str,
                                           **profile})
            return finding
        return None

    def _mxss_stage(self, point: InjectionPoint, marker: str) -> Finding | None:
        """Hunt for mutation XSS when a reflection exists but does not execute.

        This runs only after the ordinary payload ladder failed *in a live
        browser*, which makes the negative meaningful: the page renders the
        injection point, a real engine ran it, and the straightforward handlers
        did not fire. The remaining explanation a reflection-only scanner cannot
        see is a sanitiser round trip.

        The proof always comes from the application, never from the model: the
        vector is sent, the *served page* is loaded in the browser, and only an
        artifact node in that page counts as confirmed. The round-trip model is
        then run as a diagnostic to explain the result (and to justify a lead
        when the served page did not execute it).

        Cost is bounded: at most ``MXSS_BUDGET`` browser loads per scan, and a
        vector must keep its handler source in the response first, so a filtered
        point costs one HTTP request and no browser time.
        """
        with self.lock:
            if self.stats.get("mxss_probes", 0) >= MXSS_BUDGET:
                return None
        js = dom_js(marker)
        target_id = dom_marker_id(marker)
        for name, markup in mxss.vectors(js, limit=MXSS_VECTORS_PER_POINT):
            if len(markup) > MAX_PARAM_LEN:
                continue
            request = point.build(markup)
            try:
                resp = self._send(request)
            except NetError:
                continue
            # A sanitiser rewrites the markup, so byte equality is the wrong test.
            # Two cheap gates before spending a browser load: the handler source
            # must be present (it carries the marker), and at least one raw tag
            # must have survived. An escaping endpoint fails both and costs one
            # HTTP request with no browser time.
            if target_id not in resp.text or not mxss.markup_survives(resp.text, markup):
                continue
            with self.lock:
                if self.stats.get("mxss_probes", 0) >= MXSS_BUDGET:
                    break
                self.stats["mxss_probes"] = self.stats.get("mxss_probes", 0) + 1
            verdict = self.browser.verify_execution(request, target_id)
            if not verdict.is_confirmed:
                # A mutation-capable payload that the application does not
                # execute is not evidence about the application: its own
                # round-trip code was never observed doing the mutation. Keep it
                # in the log for the operator, never in the findings list.
                if self.log:
                    self.log.debug(
                        f"    mXSS vector {name} not executed at {point.label()}: "
                        f"{verdict.state} - {verdict.reason}")
                continue
            with self.lock:
                self.stats["verified"] += 1
            model = mxss.probe(self.browser, markup, target_id)
            if model.get("error") and self.log:
                self.log.debug(f"    mXSS model failed at {point.label()}: {model['error']}")
            return self._mxss_finding(point, resp, markup, name, verdict, model)
        return None

    def _mxss_finding(self, point: InjectionPoint, resp: Response, markup: str,
                      vector: str, verdict: Verification, model: dict) -> Finding:
        """Build the mXSS finding. Callers only reach this after a live confirmation."""
        request = point.build(markup)
        serialized = str(model.get("serialized") or "")[:800]
        lines = [
            f"--- request ({point.kind} injection) ---",
            RawCapture.render_request(request.method, request.url,
                                      request.headers, request.body),
            "",
            f"--- response ---\nHTTP {resp.status}  content-type: {resp.content_type}  "
            f"length: {len(resp.body)}",
            f"handler source present in response: {resp.text.count(markup)}x verbatim, "
            f"marker present: {resp.text.count(model.get('artifact') or '')}x",
            "",
            f"--- mutation vector: {vector} ---",
            f"delivered markup:\n{markup}",
            f"after parse/serialise ({model.get('how') or 'load'}):\n{serialized}",
            f"control (single parse of raw markup): "
            f"{model.get('control_artifact') or 'inert'}",
            f"test (single parse of serialised markup): {model.get('artifact') or 'inert'}",
            f"round-trip model: {model.get('proof') or 'n/a'}",
            f"live page verdict: {verdict.state} - {verdict.reason}",
        ]
        if model.get("mxss"):
            notes = [
                f"mutation vector: {vector}",
                "the served page executed the handler; the round-trip model shows the "
                "markup is inert on a single parse and only becomes executable after "
                "parse/serialise/re-parse",
                "control document (raw markup) stayed inert, so mutation is what made "
                "this payload dangerous",
            ]
        else:
            notes = [
                f"mutation vector: {vector}",
                "the served page executed the handler",
                "the round-trip model classifies this markup as ordinary XSS (it also "
                "executes on a single parse), so mutation is not required here",
            ]
        policy = csp.Assessment.from_headers(resp.headers)
        return Finding(
            url=resp.url, method=resp.method,
            param=point.name if hasattr(point, "name") else point.label(),
            location=point.kind, payload=markup, context="mxss", request=request,
            csp=_csp_note(policy, markup, resp),
            status=resp.status, confidence="high",
            verified_browser=True, browser_checked=verdict.was_tested,
            verify_state=verdict.state if verdict.was_tested else "not_tested",
            verify_reason=verdict.reason,
            evidence="\n".join(lines), notes=notes,
            title=("Mutation XSS (mXSS)" if model.get("mxss")
                   else "XSS via sanitiser round-trip payload"),
            content_type=resp.content_type,
            nosniff=(resp.header("x-content-type-options") or "").lower() == "nosniff",
            reflections=resp.text.count(markup),
        )

    def _settle_probe(self, point: InjectionPoint, marker: str,
                      resp: Response) -> tuple[str, Response, efficiency.Match]:
        """Find a probe spelling the sink actually returns.

        A sink that strips digits or truncates makes a correct probe look like no
        reflection at all -- or, worse, like a nearly-intact one: losing one
        character out of ten still scores 90%+ ("escaped"), so the point cannot
        be told apart from a filter that merely mangles metacharacters.  "Not
        reflected" and "reflected with a character missing" are both answers a
        scanner must not get wrong.  One extra request with a short, letters-only
        probe settles it; whatever it returns is then the marker for this point.
        """
        match = efficiency.measure(resp.text, marker + "zqx")
        # Only an intact value (verbatim, or merely recased) lets the payload
        # ladder speak for itself.  A high partial score is not proof of
        # survival: the sink may be eating characters, so the marker has to be
        # re-issued in a spelling that cannot lose any.
        if match.kind in ("verbatim", "case") or self.level < 2:
            return marker, resp, match

        alt = new_marker_letters()
        try:
            alt_resp = self._send(point.build(alt))
        except NetError:
            return marker, resp, match
        alt_match = efficiency.measure(alt_resp.text, alt)
        if not alt_match.reflected:
            return marker, resp, match
        if self.log:
            self.log.debug(f"    {point.label()}: {marker} was not returned intact, short probe "
                           f"{alt} was ({alt_match.describe()})")
        return alt, alt_resp, alt_match

    def _lead(self, point, marker: str, resp: Response, match: efficiency.Match,
              profile: FilterProfile | None = None,
              refl: Reflection | None = None, kind: str = "unproven") -> None:
        """Record a reflecting point that no stage could turn into a finding.

        This is the difference between "nothing here" and "something here, but a
        filter or sink stops it". A lead is never a vulnerability claim: it says
        the parameter reaches a sink and what the sink did to the value, so a
        human can decide whether a targeted bypass is worth the effort.
        """
        profile = profile or self._current_profile(point)
        context = refl.context if refl is not None else "unclassified"
        details = [match.describe()]
        # The observation comes first: "what the sink did to the value" is the
        # part a human needs before deciding whether the lead is worth chasing.
        notes = [match.describe(),
                 "parameter reflects input but no tested payload produced execution"]
        if kind == "non-html":
            notes.append(f"the sink returns {resp.content_type or 'a non-HTML body'}, "
                         "which is not an HTML execution context")
        elif kind == "partial-reflection":
            notes.append("the sink mangles the value: even the probe did not come back "
                         "intact, so a crafted payload would not either")
        else:
            if self.browser and getattr(self.browser, "available", False):
                notes.append("the value survived intact, so the sink rather than a filter "
                             "is what stopped execution; the browser did not observe it")
            else:
                notes.append("the value survived intact; browser verification was not "
                             "enabled, so execution is untested rather than disproved")
        if profile is not None and profile.known:
            details.append(profile.summary())
            if profile.stripped or profile.encoded or profile.blocked_keywords:
                notes.append("a filter, encoder or keyword block rewrote the value")
            dead = sorted({c for c in "<>\"'" if c not in profile.allowed})
            if dead:
                notes.append("cannot form markup with the surviving characters "
                             f"(missing {''.join(dead)}); a manual bypass may exist")
        if refl is not None and refl.snippet:
            details.append(f"reflection window: {refl.snippet}")

        req = point.build(marker)
        evidence = "\n".join([
            "--- request ---",
            RawCapture.render_request(req.method, req.url, req.headers, req.body),
            "",
            "--- response ---",
            f"HTTP {resp.status}  content-type: {resp.content_type}  length: {len(resp.body)}",
            "",
            f"--- observation ({kind}) ---",
            *details,
        ])
        fed: dict = profile.as_dict() if profile is not None and profile.known else {}
        fed["efficiency"] = match.as_dict()
        fed["lead_kind"] = kind
        finding = Finding(
            url=resp.url, method=resp.method,
            param=point.name if hasattr(point, "name") else point.label(),
            location=point.kind, payload=marker, context=context,
            status=resp.status, confidence="low", interaction=False,
            evidence=evidence, notes=notes, content_type=resp.content_type,
            title=(refl.tag if refl is not None else ""),
            filter_profile=fed,
        )
        self.leads.append(finding)
        if self.log:
            self.log.debug(f"    lead ({kind}) at {point.label()}: {match.describe()}")

    def _encoding_profile(self, body: str, injected: str) -> str:
        if injected not in body:
            h = html.escape(injected, quote=True)
            if h in body:
                return "html-encoded"
            if urllib.parse.quote(injected, safe="") in body:
                return "url-encoded"
            return "encoded/unknown"
        raw = body.count(injected)
        # which special characters made it through untouched?
        probe = "<>\"'`"
        survived = [c for c in probe if c in injected]
        return f"raw x{raw}" + (f" (chars {survived})" if survived else "")

    def _profile_family(self, point: InjectionPoint, context: str) -> str:
        """Key that makes equal endpoints share one measured filter profile.

        Two URLs that differ only in a parameter *value* land on the same handler
        and filter identically, so making the second one pay for the same two
        probes is pure waste. The reflection context is part of the key because
        escaping comes from the sink, not from the parameter.
        """
        if isinstance(point, QueryPoint):
            parts = urllib.parse.urlsplit(point.url)
            return f"qf:{parts.netloc}{parts.path}|{point.name}|{context}"
        if isinstance(point, FormPoint):
            return f"ff:{point.form.action}|{point.name}|{context}"
        return ""

    def _profile_point(self, point: InjectionPoint, marker: str,
                       context: str = "") -> FilterProfile:
        """Measure what survives this parameter, cached per point and per endpoint.

        The cache was per exact URL, which still charged every value variant of
        one parameter (``?id=1``, ``?id=2``) two requests each. Sibling variants
        now inherit the measurement; deferred payloads are still sent, so a
        shared profile can only reorder the ladder, never drop a payload.
        """
        if not self.profile_enabled:
            return FilterProfile()
        key = self._point_key(point)
        family = self._profile_family(point, context)
        with self.lock:
            cached = self._profiles.get(key)
            if cached is None and family:
                cached = self._profiles.get(family)
        if cached is not None:
            if family:
                with self.lock:
                    self._profiles.setdefault(key, cached)
            return cached
        profile = build_profile(lambda value: self._send(point.build(value)), marker, self.log)
        with self.lock:
            self._profiles[key] = profile
            if family:
                self._profiles.setdefault(family, profile)
        if self.log and profile.known:
            self.log.debug(f"    {profile.summary()} [{point.label()}]")
        return profile

    def _candidates(self, payloads, js_calls, marker: str, point, refl: Reflection,
                    profile: FilterProfile | None = None):
        """Order payloads by feasibility, then append mutations for filtered spots.

        Ordering matters more than raw payload count: the first payload that both
        survives the filter and breaks out is the finding. Unknown profile means
        everything is feasible, so behaviour is unchanged on clean targets.
        """
        profile = profile or self._current_profile(point)
        out = []
        deferred = []
        for payload in payloads:
            for js_name, js in js_calls:
                try:
                    payload_str = payload.render(marker, js)
                except Exception:
                    continue
                item = (payload, payload_str, js_name, "")
                if profile.feasible(payload_str):
                    out.append(item)
                else:
                    deferred.append(item)
        if self.level >= 2 and self.mutation_budget:
            for payload, payload_str, js_name, _m in (out + deferred)[:6]:
                if profile.feasible(payload_str):
                    continue  # nothing is filtered, mutation would be noise
                for name, mutated in mutate(payload_str, limit=self.mutation_budget, seed=len(marker)):
                    if profile.feasible(mutated) or not profile.known:
                        out.append((payload, mutated, js_name, name))
        self._waf_extras(out, refl)
        out.extend(deferred)
        return out

    def _current_profile(self, point):
        key = self._point_key(point)
        with self.lock:
            return self._profiles.get(key)

    # -- WAF evasion -------------------------------------------------
    def _waf_evasion(self) -> bool:
        return bool(self.evasion and self.waf is not None
                    and getattr(self.waf, "evasive", False))

    def _waf_call_variants(self, marker: str) -> list[tuple[str, str]]:
        """Obfuscated alert() bodies, only when a WAF is actually in the way."""
        if not self._waf_evasion():
            return []
        return waf.js_variants(marker)[:2]

    def _waf_extras(self, out: list, refl: Reflection) -> None:
        """Append per-vendor payload mutations built from the *rendered* payload.

        Mutating after rendering matters: the strategy has to obfuscate the
        string that will actually be sent (tags, attribute quoting and all), not
        a template whose slots are still empty. Nothing here relaxes the
        evidence bar -- a variant still has to reflect verbatim.
        """
        if not self._waf_evasion():
            return
        vendor = getattr(self.waf, "vendor", None)
        strategies = tuple(getattr(vendor, "strategies", ()) or ()) or waf.STRATEGY_ORDER
        budget = waf.evasion_budget(getattr(self.waf, "confidence", "low"),
                                    bool(getattr(self.waf, "blocking", False)))
        with self.lock:
            budget = min(budget, self._evasion_left)
        if budget <= 0:
            return
        seen = {item[1] for item in out}
        added = 0
        order = self.evasion_memory.rank(strategies)
        for payload, payload_str, js_name, _m in list(out)[:5]:
            if added >= budget:
                break
            for strategy, variant in waf.markup_variants(
                    payload_str, refl.context, strategies, limit=budget - added,
                    order=order):
                if variant in seen:
                    continue
                seen.add(variant)
                out.append((payload, variant, f"{js_name}+{strategy}", f"waf:{strategy}"))
                added += 1
        if added:
            with self.lock:
                self._evasion_left -= added
                self.stats["waf_variants"] += added
            if self.log:
                self.log.debug(f"    waf evasion: {added} extra variant(s) queued [{refl.context}]")

    def _try_context(self, point: InjectionPoint, refl: Reflection, marker: str,
                     encoding: str, baseline_resp: Response,
                     profile: FilterProfile | None = None) -> Finding | None:
        payloads = self._payloads_for(refl)
        js_calls = js_variants(marker)[: 1 if self.risk <= 2 else 3]
        js_calls += self._waf_call_variants(marker)
        candidates = self._candidates(payloads, js_calls, marker, point, refl, profile)

        for payload, payload_str, js_name, mutator in candidates:
            for _attempt in (0,):
                if len(payload_str) > MAX_PARAM_LEN:
                    continue
                try:
                    resp = self._send(point.build(payload_str))
                except NetError:
                    continue
                if resp.status in (404, 405, 501) and baseline_resp.status not in (404, 405, 501):
                    if mutator.startswith("waf:"):
                        self.evasion_memory.record(mutator[4:], False)
                    continue
                if not self._reflects_executably(resp, payload_str, refl, payload):
                    if mutator.startswith("waf:"):
                        self.evasion_memory.record(mutator[4:], False)
                    continue
                if mutator.startswith("waf:"):
                    # The variant survived the filter and reflected verbatim:
                    # this is the target telling us which shape it lets through.
                    self.evasion_memory.record(mutator[4:], True)
                # re-send for stability; a real reflection is deterministic
                try:
                    resp2 = self._send(point.build(payload_str))
                except NetError:
                    resp2 = None
                stable = resp2 is not None and payload_str in resp2.text
                if not stable and resp2 is not None:
                    continue

                verdict = self._browser_verify_ex(
                    point, refl, marker, payload, payload_str)
                verified = verdict.is_confirmed
                browser_checked = verdict.was_tested
                verify_note = verdict.reason if verdict.was_tested and not verified else ""

                confidence = "high"
                notes = [f"payload variant: {js_name}"]
                if mutator:
                    notes.append(f"filter bypass via mutation: {mutator}")
                if payload.interaction:
                    confidence = "medium"
                    notes.append("requires one user interaction (click/hover) to fire")
                if refl.context in ("json_body", "plain_text", "header"):
                    confidence = "low"
                    notes.append(f"reflection context is {refl.context}, not an HTML execution context")
                if verified:
                    confidence = "high"
                    notes.append("execution confirmed in a real browser: injected DOM node observed")

                title_match = re.search(r"(?is)<title[^>]*>(.*?)</title>", resp.text)
                title_text = title_match.group(1).strip()[:90] if title_match else ""
                finding = Finding(
                    url=resp.url,
                    method=resp.method,
                    param=point.name if hasattr(point, "name") else point.label(),
                    location=point.kind,
                    payload=payload_str,
                    context=refl.context,
                    request=point.build(payload_str),
                    template=payload.template,
                    payload_name=payload.name,
                    status=resp.status,
                    confidence=confidence,
                    verified_browser=verified,
                    browser_checked=browser_checked,
                    interaction=payload.interaction,
                    evidence=self._build_evidence(point, payload_str, resp, refl, payload, stable),
                    mutation=mutator or "",
                    notes=notes + ([verify_note] if verify_note else []),
                    verify_state=verdict.state if browser_checked else "",
                    verify_reason=verdict.reason if browser_checked else "",
                    content_type=resp.content_type,
                    nosniff=(resp.header("x-content-type-options") or "").lower() == "nosniff",
                    reflections=resp.text.count(payload_str),
                    encoding=encoding,
                    title=title_text,
                    filter_profile=profile.as_dict() if profile else {},
                )
                policy = csp.Assessment.from_headers(resp.headers)
                feasibility = policy.feasibility(payload_str, resp.url)
                if policy.present:
                    finding.csp = _csp_note(policy, payload_str, resp)
                # Execution was actually attempted: let the engine's verdict decide the claim.
                if browser_checked and not verified:
                    violation = "content-security-policy" in verdict.reason.lower()
                    if violation or feasibility.allowed is False:
                        finding.csp_blocked = True
                        finding.confidence = "medium"
                        if violation:
                            finding.notes.append(
                                "execution blocked by the page's Content-Security-Policy "
                                "(the browser reported a policy violation)")
                        else:
                            finding.notes.append(
                                "the page's Content-Security-Policy does not permit this "
                                f"payload's technique: {feasibility.reason}")
                    elif finding.confidence == "high":
                        finding.confidence = "medium"
                        finding.notes.append(
                            "browser did not observe execution; the reflection is confirmed but "
                            "code execution is unproven (filtering, MIME, or CSP may be responsible)")
                elif not browser_checked:
                    finding.notes.append(
                        "NOT TESTED in a browser: no execution verdict was obtained for this "
                        "payload, so the finding rests on the reflection alone")
                if not resp.is_html and finding.confidence == "high":
                    finding.confidence = "low"
                    finding.notes.append(f"response is {resp.content_type or 'unknown'}, not text/html")
                return finding
        return None

    def _reflects_executably(self, resp: Response, payload_str: str, refl: Reflection,
                             payload: Payload) -> bool:
        body = resp.text
        if payload_str not in body:
            return False
        idx = body.find(payload_str)
        # must not be wrapped in an escape we can see right before it
        if refl.context in ("json_body", "plain_text", "header"):
            return True
        # break-out characters must be present raw (they are, by definition, in
        # payload_str, but a filter could re-encode them inside the response)
        need = self._needed_chars(refl.context, payload)
        window = body[idx:idx + len(payload_str)]
        if not all(ch in window for ch in need):
            return False
        # a quote preceded by an odd run of backslashes is escaped, not a break-out
        if refl.context in ("js_string_double", "js_string_single", "js_template"):
            backslashes = 0
            j = idx - 1
            while j >= 0 and body[j] == "\\":
                backslashes += 1
                j -= 1
            if backslashes % 2 == 1:
                return False
        return True

    @staticmethod
    def _needed_chars(context: str, payload: Payload) -> str:
        if context == "html_text":
            return "<"
        if context == "attr_double":
            return '"'
        if context == "attr_single":
            return "'"
        if context == "attr_unquoted":
            return " "
        if context == "js_string_double":
            return '"'
        if context == "js_string_single":
            return "'"
        if context == "js_template":
            return "`"
        if context in ("comment",):
            return ">"
        if context in ("textarea", "title", "style", "xmp", "noscript",
                       "noembed", "noframes", "template"):
            return "<"
        if context in ("tag_space", "script_data"):
            return " " if context == "tag_space" else "<"
        return ""

    # -- browser verification ----------------------------------------
    def _browser_verify_ex(self, point: InjectionPoint, refl: Reflection, marker: str,
                           payload: Payload, payload_str: str,
                           extra: list[str] | None = None) -> Verification:
        """Prove execution in a real browser; report how sure we are.

        The return value distinguishes the three cases that a boolean hides:
        the payload ran, the payload did not run in a page we actually loaded,
        and we never got a valid look. Only the middle case may be used to
        downgrade a finding, and only the first may be used to raise it.
        """
        if not (self.browser and self.browser.available):
            return Verification.not_tested("browser verification not enabled")
        js = dom_js(marker)
        target_id = dom_marker_id(marker)
        # ``extra`` holds already-rendered payloads (a synthesised brute-force
        # vector whose quotes were chosen for its context) that the generic
        # payload renderer would rebuild incorrectly.
        attempts: list[str] = [a for a in (extra or []) if a]
        try:
            attempts.append(payload.render(marker, js))
        except (KeyError, IndexError, ValueError) as exc:
            return Verification.from_exception(exc, "payload rendering")
        for candidate in [p for p in payloads_for_context(refl) if not p.interaction][:4]:
            try:
                attempts.append(candidate.render(marker, js))
            except (KeyError, IndexError, ValueError):
                continue
        try:
            attempts.append(polyglot_payload().render(marker, js))
        except (KeyError, IndexError, ValueError):
            pass

        verdict = Verification.not_tested("no payload variant was reflected verbatim")
        for attempt in dict.fromkeys(a for a in attempts if a):
            try:
                req = point.build(attempt)
                resp = self._send(req)
            except NetError as exc:
                verdict = verdict.merge(Verification.not_tested(f"re-send failed: {exc}"[:160]))
                continue
            if attempt not in resp.text:
                continue
            try:
                result = self.browser.verify_execution(req, target_id)
            except Exception as exc:
                result = Verification.from_exception(exc, "verifier")
            if result.is_confirmed:
                with self.lock:
                    self.stats["verified"] += 1
                return result
            verdict = verdict.merge(result)
        return verdict

    # -- evidence ----------------------------------------------------
    def _build_evidence(self, point: InjectionPoint, payload_str: str, resp: Response,
                        refl: Reflection, payload: Payload, stable: bool) -> str:
        req = point.build(payload_str)
        lines = [
            "--- request ---",
            RawCapture.render_request(req.method, req.url, req.headers, req.body),
            "",
            "--- response ---",
            f"HTTP {resp.status}  content-type: {resp.content_type}  length: {len(resp.body)}",
            "",
            f"--- reflection context: {refl.context} (payload template: {payload.name}) ---",
            refl.snippet,
            "",
            f"payload appears {resp.text.count(payload_str)}x verbatim; stable re-send: {stable}",
        ]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Point generation from crawl results
# ---------------------------------------------------------------------------

def points_from_url(url: str, headers: list[tuple[str, str]], params_override: str | None = None,
                    only_params: list[str] | None = None) -> list[InjectionPoint]:
    pairs = query_pairs(url)
    out: list[InjectionPoint] = []
    for i, (name, _v) in enumerate(pairs):
        if only_params and name not in only_params:
            continue
        if name.startswith("__") or name in ("submit", "Submit"):
            continue
        out.append(QueryPoint(url, i, headers))
    return out


def points_from_form(form: Form, headers: list[tuple[str, str]], csrf_fetcher=None,
                     only_params: list[str] | None = None) -> list[InjectionPoint]:
    out: list[InjectionPoint] = []
    seen = set()
    for name, _v, typ in form.params:
        if not name or typ in ("submit", "button", "file", "image", "reset", "checkbox", "radio"):
            continue
        if only_params and name not in only_params:
            continue
        if name in seen:
            continue
        seen.add(name)
        out.append(FormPoint(form, name, headers, csrf_fetcher))
    return out


def points_from_json(url: str, body: bytes, headers: list[tuple[str, str]],
                     only_params: list[str] | None = None, method: str = "POST") -> list[InjectionPoint]:
    try:
        data = json.loads(body)
    except Exception:
        return []
    out: list[InjectionPoint] = []

    def walk(obj, path):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    walk(v, path + [k])
                else:
                    if only_params and k not in only_params:
                        continue
                    out.append(JsonPoint(url, path + [k], body, headers, method))
        elif isinstance(obj, list):
            for i, v in enumerate(obj[:3]):
                if isinstance(v, (dict, list)):
                    walk(v, path + [i])
                else:
                    out.append(JsonPoint(url, path + [i], body, headers, method))

    walk(data, [])
    return out
