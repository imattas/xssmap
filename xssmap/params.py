"""Parameter discovery: find the inputs the application reads but never links.

A crawl only sees parameters that appear in URLs and forms. Plenty of handlers
also read names nobody advertises — ``debug``, ``preview``, ``template``,
``callback``, ``redirect`` — and those are frequently the least defended.

The cheap trick that makes this affordable: send *all* candidate names in one
request, each with a unique alphanumeric marker as its value. Any marker that
comes back proves its parameter is read and echoed, at a cost of one request
per batch instead of one per name. A bounded second pass looks for parameters
that change the response without echoing (status or body-size delta), which
catches the ones that alter behaviour silently.
"""
from __future__ import annotations

import json
import urllib.parse
from dataclasses import dataclass, field

# Ordered roughly by how often a hidden parameter is worth testing. The list is
# deliberately about *behaviour* names rather than payload names: `debug=1` is
# interesting because it may switch on a verbose page, not because of the word.
CANDIDATES = (
    "debug", "test", "testing", "admin", "preview", "draft", "staging", "dev",
    "id", "page", "p", "pageid", "post", "post_id", "article", "item", "product",
    "product_id", "sku", "category", "cat", "section", "tab", "view", "template",
    "theme", "layout", "format", "type", "mode", "action", "do", "op", "cmd",
    "q", "s", "search", "query", "keyword", "keywords", "term", "filter", "sort",
    "order", "orderby", "limit", "offset", "start", "end", "from", "to", "page_size",
    "lang", "language", "locale", "country", "region", "currency", "timezone",
    "redirect", "redirect_uri", "redirect_url", "return", "return_to", "next",
    "url", "uri", "link", "target", "goto", "dest", "destination", "continue",
    "callback", "jsonp", "cb", "ref", "referer", "referrer", "source", "src",
    "utm_source", "utm_medium", "utm_campaign", "affiliate", "partner", "promo",
    "coupon", "code", "voucher", "discount", "price", "amount", "qty", "quantity",
    "user", "username", "userid", "user_id", "account", "profile", "email", "name",
    "message", "comment", "content", "body", "text", "title", "subject", "note",
    "file", "filename", "path", "dir", "folder", "include", "require", "load",
    "page_url", "host", "domain", "site", "base", "root", "config", "setting",
    "option", "options", "flag", "feature", "experiment", "variant", "ab", "beta",
    "token", "auth", "key", "apikey", "api_key", "secret", "password", "pass",
    "pwd", "otp", "verify", "confirm", "reset", "step", "state", "status",
    "session", "sid", "sessionid", "csrf", "csrf_token", "_token", "_method",
    "json", "xml", "ajax", "api", "version", "v", "build", "mobile", "desktop",
    "embed", "iframe", "frame", "popup", "modal", "overlay", "print", "download",
    "export", "raw", "output", "width", "height", "size", "color", "lang_code",
)


@dataclass
class Discovered:
    name: str
    reflected: bool = False
    signal: str = "reflection"      # reflection / shape / error
    evidence: str = ""
    status: int = 0
    delta: int = 0

    def as_dict(self) -> dict:
        return {"name": self.name, "reflected": self.reflected,
                "signal": self.signal, "evidence": self.evidence,
                "status": self.status, "delta": self.delta}


@dataclass
class Discovery:
    url: str = ""
    found: list[Discovered] = field(default_factory=list)
    tested: int = 0
    requests: int = 0
    baseline_status: int = 0
    baseline_length: int = 0
    note: str = ""

    def names(self) -> list[str]:
        return [d.name for d in self.found]

    def as_dict(self) -> dict:
        return {"url": self.url, "tested": self.tested, "requests": self.requests,
                "baseline_status": self.baseline_status,
                "baseline_length": self.baseline_length,
                "note": self.note,
                "params": [d.as_dict() for d in self.found]}


def _with_params(url: str, pairs: list[tuple[str, str]]) -> str:
    parts = urllib.parse.urlsplit(url)
    existing = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    merged = existing + pairs
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path,
         urllib.parse.urlencode(merged, doseq=True), ""))


def with_params(url: str, names: list[str]) -> str:
    """``url`` with each discovered name given a harmless value."""
    return _with_params(url, [(name, "1") for name in names])


def names_from_js(js_resources) -> list[str]:
    """Parameter names the application's own JavaScript uses.

    A client bundle is a list of the parameter names the backend actually reads,
    written by the developers. It outperforms a static wordlist on any target
    whose front end was renamed or localised, and it costs no requests: the
    crawler has already downloaded the files.
    """
    import re
    found: list[str] = []
    patterns = (
        re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_]{1,40})="),          # URL literals
        re.compile(r"\.(?:get|set|append|has)\(\s*['\"]([A-Za-z_][A-Za-z0-9_]{1,40})['\"]"),
        re.compile(r"['\"]([A-Za-z_][A-Za-z0-9_]{1,40})['\"]\s*:\s*(?:\$|req|query|params)"),
        re.compile(r"\bparams\.([A-Za-z_][A-Za-z0-9_]{1,40})\b"),
        re.compile(r"\bsearchParams\.get\(\s*['\"]([A-Za-z_][A-Za-z0-9_]{1,40})['\"]"),
        re.compile(r"\bname\s*=\s*['\"]([A-Za-z_][A-Za-z0-9_]{1,40})['\"]"),
    )
    for item in js_resources or []:
        body = ""
        try:
            body = item[1] or ""
        except (TypeError, IndexError):
            continue
        for pattern in patterns:
            for match in pattern.finditer(body):
                candidate = match.group(1)
                if candidate and candidate not in found:
                    found.append(candidate)
    return found[:120]


def _body_with(template: str, kind: str, name: str, value: str) -> str:
    """Add or replace one field in a JSON or form body."""
    if kind == "json":
        try:
            data = json.loads(template or "{}")
        except ValueError:
            data = None
        if isinstance(data, dict):
            data[name] = value
            return json.dumps(data)
        # Not a JSON object: fall back to appending a member before the last brace.
        stripped = (template or "{}").rstrip()
        if stripped.endswith("}"):
            return stripped[:-1] + f',"{name}":"{value}"}}'
        return template or ""
    pairs = urllib.parse.parse_qsl(template or "", keep_blank_values=True)
    pairs = [(k, v) for k, v in pairs if k != name]
    pairs.append((name, value))
    return urllib.parse.urlencode(pairs)


def _body_keys(template: str, kind: str) -> list[str]:
    """Top-level member names already present in a body template.

    A documented member is not a discovery, and probing it again would report
    the caller's own body back as a hidden property.
    """
    if kind == "form":
        return [name for name, _value in urllib.parse.parse_qsl(template or "")]
    try:
        data = json.loads(template or "{}")
    except (ValueError, TypeError):
        return []
    return [str(key) for key in data] if isinstance(data, dict) else []


def body_with(template: str, kind: str, name: str, value: str = "1") -> str:
    """``template`` with one extra body member carrying ``value``.

    Public because the CLI merges discovered property names back into the body
    the injection-point builder walks; the mutation and the discovery have to
    agree on how a member is added for the names to be testable.
    """
    return _body_with(template, kind, name, value)


def discover_body(http, url: str, template: str, kind: str = "json",
                 headers: list[tuple[str, str]] | None = None, log=None,
                 wordlist: list[str] | None = None, max_params: int = 120,
                 batch_size: int = 30, max_followups: int = 8) -> Discovery:
    """The same discovery, aimed at a request body instead of the query string.

    Body sinks are where a modern API lives, and a query-only prober silently
    does nothing on them. JSON gets its own builder because adding a key to an
    existing object is enough to reach most handlers.
    """
    result = Discovery(url=url)
    result.note = f"{kind} body"
    headers = list(headers or [])
    existing = set(_body_keys(template, kind))
    names = [name for name in dict.fromkeys(list(wordlist or []) + list(CANDIDATES))
             if name not in existing][:max_params]
    result.tested = len(names)
    if not names:
        return result

    def send(body: str):
        return http.post(url, body.encode("utf-8"), headers=headers)

    try:
        base = send(template)
        second = send(template)
    except Exception as exc:
        result.note = f"baseline request failed: {str(exc)[:100]}"
        return result
    result.requests += 2
    result.baseline_status = base.status
    result.baseline_length = _shape(base.body)
    noise = abs(_shape(base.body) - _shape(second.body))

    seen: dict[str, Discovered] = {}
    pending: list[tuple[str, str]] = []
    for start in range(0, len(names), max(1, batch_size)):
        chunk = names[start:start + max(1, batch_size)]
        body = template
        markers: dict[str, str] = {}
        for offset, name in enumerate(chunk):
            token = f"xsq{start + offset}zq"
            body = _body_with(body, kind, name, token)
            markers[token] = name
        try:
            resp = send(body)
        except Exception:
            continue
        result.requests += 1
        text = getattr(resp, "text", "") or ""
        for token, name in markers.items():
            if token in text:
                seen[name] = Discovered(
                    name=name, reflected=True, signal="reflection",
                    evidence=f"body value reflected in the response ({resp.status})",
                    status=resp.status)
            else:
                pending.append((name, token))

    threshold = max(48, noise + 32, int(result.baseline_length * 0.05))
    confirmed = 0
    for name, _token in pending:
        # The budget is in *requests*, not names: a two-shot confirmation costs
        # twice as much per candidate, and the caller's cap has to mean the
        # same thing however many shots the confirmation takes.
        if confirmed + 2 > max_followups:
            break
        deltas: list[int] = []
        statuses: list[int] = []
        for _attempt in range(2):
            try:
                resp = send(_body_with(template, kind, name, "1"))
            except Exception:
                break
            result.requests += 1
            confirmed += 1
            deltas.append(_shape(resp.body) - result.baseline_length)
            statuses.append(resp.status)
        if len(deltas) < 2:
            continue
        status_changed = all(status != result.baseline_status for status in statuses)
        big_enough = all(abs(delta) > threshold for delta in deltas)
        same_direction = (deltas[0] > 0) == (deltas[1] > 0)
        if status_changed or (big_enough and same_direction):
            seen[name] = Discovered(
                name=name, reflected=False, signal="shape",
                evidence=(f"body field changed the response: status {statuses[0]}, "
                          f"delta {deltas[0]:+d} then {deltas[1]:+d}"),
                status=statuses[0], delta=deltas[0])

    result.found = sorted(seen.values(),
                          key=lambda d: (not d.reflected, d.signal != "error", d.name))
    if log is not None:
        if result.found:
            listed = ", ".join(d.name for d in result.found[:10])
            log.ok(f"{kind} body discovery: {len(result.found)} field(s) accepted - {listed}")
        else:
            log.info(f"{kind} body discovery: none of {result.tested} candidate field(s) "
                     "changed the response")
    return result


def _shape(body: bytes) -> int:
    return len(body or b"")


_VALIDATION_WORDS = (r"invalid|unknown|missing|required|unsupported|unexpected|"
                     r"not\s+allowed|unrecognised|unrecognized|parameter|argument")


def _validation_mention(text: str, name: str) -> bool:
    """True when the body complains about this name specifically.

    A bare substring search is useless here ("name" and "type" appear in every
    page), so the name has to sit next to a validation word within one clause.
    """
    if not text or len(text) > 200000:
        return False
    import re
    quoted = re.escape(name)
    patterns = (
        rf"(?i)(?:{_VALIDATION_WORDS})[^.\n]{{0,40}}\b{quoted}\b",
        rf"(?i)\b{quoted}\b[^.\n]{{0,40}}(?:{_VALIDATION_WORDS})",
    )
    return any(re.search(pattern, text) for pattern in patterns)


def discover(http, url: str, headers: list[tuple[str, str]] | None = None,
             log=None, wordlist: list[str] | None = None,
             max_params: int = 120, batch_size: int = 30,
             max_followups: int = 12) -> Discovery:
    """Find parameters the target reads but does not advertise.

    Two baseline requests establish the noise floor, then one request per batch
    of names carries a unique marker per name. Reflected markers are reported as
    ``reflection``; names that change the response without reflecting are
    reported as ``shape`` after a bounded single-parameter confirmation.
    """
    result = Discovery(url=url)
    headers = list(headers or [])
    # A user-supplied wordlist comes first so that the ``max_params`` budget
    # cannot silently truncate it behind the built-in candidates.
    names = list(dict.fromkeys(list(wordlist or []) + list(CANDIDATES)))
    existing = {k for k, _ in urllib.parse.parse_qsl(
        urllib.parse.urlsplit(url).query, keep_blank_values=True)}
    names = [n for n in names if n not in existing][:max_params]
    result.tested = len(names)
    if not names:
        result.note = "every candidate is already in the URL"
        return result

    baselines = []
    for _ in range(2):
        try:
            baselines.append(http.get(url, headers=headers))
        except Exception as exc:
            result.note = f"baseline request failed: {str(exc)[:100]}"
            return result
    result.requests += len(baselines)
    base = baselines[0]
    result.baseline_status = base.status
    result.baseline_length = _shape(base.body)
    noise = abs(_shape(baselines[0].body) - _shape(baselines[1].body))

    seen: dict[str, Discovered] = {}
    pending_shape: list[tuple[str, str]] = []
    for start in range(0, len(names), max(1, batch_size)):
        chunk = names[start:start + max(1, batch_size)]
        pairs = []
        markers: dict[str, str] = {}
        for offset, name in enumerate(chunk):
            token = f"xsq{start + offset}zq"
            pairs.append((name, token))
            markers[token] = name
        try:
            resp = http.get(_with_params(url, pairs), headers=headers)
        except Exception:
            continue
        result.requests += 1
        text = getattr(resp, "text", "") or ""
        for token, name in markers.items():
            if token in text:
                seen[name] = Discovered(
                    name=name, reflected=True, signal="reflection",
                    evidence=f"value reflected verbatim in the response ({resp.status})",
                    status=resp.status)
            elif _validation_mention(text, name):
                seen[name] = Discovered(
                    name=name, reflected=False, signal="error",
                    evidence="parameter name appears in a validation-style message",
                    status=resp.status)
            else:
                pending_shape.append((name, token))

    # Second pass: a parameter that changes the page without echoing its value.
    # Two things make this trustworthy. First, drift: a page with a timestamp or
    # a rotating token differs from its own baseline, so the threshold is raised
    # by however much two identical baselines differ. Second, confirmation: a
    # shape change has to reproduce on a second request, because one lucky sample
    # is exactly what a nonce looks like.
    threshold = max(48, noise + 32, int(result.baseline_length * 0.05))
    confirmed = 0
    for name, _token in pending_shape:
        # Budget in requests, not names: confirming twice per candidate must not
        # silently double the traffic a caller allowed.
        if confirmed + 2 > max_followups:
            break
        deltas: list[int] = []
        statuses: list[int] = []
        for _attempt in range(2):
            try:
                resp = http.get(_with_params(url, [(name, "1")]), headers=headers)
            except Exception:
                break
            result.requests += 1
            confirmed += 1
            deltas.append(_shape(resp.body) - result.baseline_length)
            statuses.append(resp.status)
        if len(deltas) < 2:
            continue
        status_changed = all(status != result.baseline_status for status in statuses)
        big_enough = all(abs(delta) > threshold for delta in deltas)
        same_direction = (deltas[0] > 0) == (deltas[1] > 0)
        if status_changed or (big_enough and same_direction):
            seen[name] = Discovered(
                name=name, reflected=False, signal="shape",
                evidence=(f"status {statuses[0]} vs {result.baseline_status}, "
                          f"length delta {deltas[0]:+d} then {deltas[1]:+d} "
                          f"(confirmed twice)"),
                status=statuses[0], delta=deltas[0])

    result.found = sorted(seen.values(),
                          key=lambda d: (not d.reflected, d.signal != "error", d.name))
    if log is not None:
        if result.found:
            names_txt = ", ".join(d.name for d in result.found[:12])
            log.ok(f"parameter discovery: {len(result.found)} hidden parameter(s) - "
                   f"{names_txt}{'...' if len(result.found) > 12 else ''}")
        else:
            log.info(f"parameter discovery: none of {result.tested} candidate name(s) "
                     "changed the response")
    return result
