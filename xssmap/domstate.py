"""State stores and server-rendered state: flows a single-script taint pass misses.

``domscan.analyze_js`` follows a value inside one JavaScript resource. Real
applications break that chain in three ways the single-resource pass cannot see:

* a value is written to ``localStorage``/``sessionStorage`` by one script (or
  one page) and read back later, possibly by a different script or page;
* it travels through an application store (Redux/Vuex/NgRx-style ``state.key``
  mutation) as a dispatched payload;
* the server embeds it in a hydration blob (``__NEXT_DATA__``,
  ``__INITIAL_STATE__``, a ``data-`` attribute) and the client re-reads it.

Each case leaves a *write* site and a *read* site with a key in common. This
module extracts both sides and joins them on (store kind, key). The caller owns
the two decisions that need context this module does not have: whether the two
sites are same-origin (storage is origin-scoped) and whether the browser can
actually be driven through the write step before the read step.

Nothing here claims a vulnerability. A join is a *candidate*; only the runtime
step in :mod:`xssmap.domscan` turns it into a finding.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# -- URL-derived origins ---------------------------------------------------
# Narrower than domscan.SOURCES on purpose: a store write is only worth joining
# when the value provably comes from the request. ``document.cookie`` and a bare
# ``localStorage`` read are excluded -- they are not attacker-deliverable.
URL_SOURCES = (
    "location.search",
    "document.location.search",
    "location.hash",
    "document.location.hash",
    "location.href",
    "document.location.href",
    "document.URL",
    "document.documentURI",
    "document.referrer",
    "window.name",
    "URLSearchParams",
    "location.pathname",
)

HASH_SOURCES = {"location.hash", "document.location.hash"}
REFERRER_SOURCES = {"document.referrer"}
WINDOW_NAME_SOURCES = {"window.name"}

# -- hydration blobs -------------------------------------------------------
# Server-rendered state that the client parses and renders. These names are
# stable across frameworks, which is why they are worth matching literally.
HYDRATION_SOURCES = {
    "__NEXT_DATA__": "Next.js",
    "__NUXT__": "Nuxt",
    "__INITIAL_STATE__": "generic SSR",
    "__PRELOADED_STATE__": "generic SSR",
    "__APOLLO_STATE__": "Apollo",
    "__REDUX_STATE__": "Redux SSR",
    "__INITIAL_DATA__": "generic SSR",
}

# -- storage access --------------------------------------------------------
_SET_CALL = re.compile(
    r"(?P<kind>localStorage|sessionStorage)\s*\.\s*setItem\s*\(\s*"
    r"(?P<key>'[^']{0,80}'|\"[^\"]{0,80}\"|[A-Za-z_$][\w$]{0,60})\s*,\s*(?P<expr>[^;]{0,300})"
)
_SET_PROP = re.compile(
    r"(?P<kind>localStorage|sessionStorage)\s*(?:\.\s*(?P<key>[A-Za-z_$][\w$]{0,60})"
    r"|\[\s*(?P<key2>'[^']{0,80}'|\"[^\"]{0,80}\")\s*\])\s*=(?!=)(?P<expr>[^;]{0,300})"
)
_GET_CALL = re.compile(
    r"(?P<kind>localStorage|sessionStorage)\s*\.\s*getItem\s*\(\s*"
    r"(?P<key>'[^']{0,80}'|\"[^\"]{0,80}\"|[A-Za-z_$][\w$]{0,60})\s*\)"
)
_GET_PROP = re.compile(
    r"(?P<kind>localStorage|sessionStorage)\s*(?:\.\s*(?P<key>[A-Za-z_$][\w$]{0,60})"
    r"|\[\s*(?P<key2>'[^']{0,80}'|\"[^\"]{0,80}\")\s*\])"
)

# -- application stores ----------------------------------------------------
# A reducer/commit mutating one state field: `state.draft = action.payload`.
_STORE_SET = re.compile(
    r"(?:\$store\.state|store\.state|this\.state|state)\s*(?:\.\s*(?P<key>[A-Za-z_$][\w$]{0,60})"
    r"|\[\s*(?P<key2>'[^']{0,80}'|\"[^\"]{0,80}\")\s*\])\s*=(?!=)(?P<expr>[^;\n]{0,200})"
)
# Redux dispatch({type, payload: X}) / Vuex commit('type', X).
_DISPATCH = re.compile(
    r"(?:dispatch|commit)\s*\(\s*(?:\{[^{}]{0,200}?type\s*:\s*"
    r"(?P<type2>'[^']{0,60}'|\"[^\"]{0,60}\")[^{}]{0,160}?"
    r"payload\s*:\s*(?P<payload>[^,}]{0,200})"
    r"|(?P<type>'[^']{0,60}'|\"[^\"]{0,60}\")\s*,\s*(?P<value>[^)]{0,200}))"
)
# Reads: state.draft, store.getState().draft, useSelector(s => s.draft).
_STORE_GET = re.compile(
    r"(?:\$store\.state|store\.state|getState\s*\(\s*\)|useSelector\s*\([^)]{0,80}"
    r"|this\.state|state)\s*(?:\.\s*(?P<key>[A-Za-z_$][\w$]{0,60})"
    r"|\[\s*(?P<key2>'[^']{0,80}'|\"[^\"]{0,80}\")\s*\])"
)

# -- component-local state ------------------------------------------------
# A class component never assigns this.state.field directly; it calls
# setState({field: value}) and reads the field back through this.state.field.
# One call can set several fields, so the object body is split into pairs
# instead of matching a single key:value.
_SET_STATE_HEAD = re.compile(r"(?:this\.)?setState\s*\(\s*\{")
_OBJ_PAIR = re.compile(
    r"(?:'(?P<k1>[^']{0,80})'|\"(?P<k2>[^\"]{0,80})\"|(?P<k3>[A-Za-z_$][\w$]{0,60}))\s*:\s*"
)

# -- reducers -------------------------------------------------------------
# `case 'SET_QUERY': return {...state, query: action.payload}` is the only place
# that maps the action type a dispatch carries to the field a selector reads.
_REDUCER_CASE = re.compile(r"case\s+(['\"])(?P<action>[^'\"]{1,60})\1\s*:")
_REDUCER_FIELD = re.compile(r"\bstate\.(?P<field>[A-Za-z_$][\w$]{0,60})\s*=(?!=)")
_REDUCER_SPREAD = re.compile(
    r"\b(?P<field>[A-Za-z_$][\w$]{0,60})\s*:\s*(?:action\.payload|payload)\b"
)

# -- pub/sub --------------------------------------------------------------
# A value travels through an event bus: emit('draft:set', value) in one place,
# on('draft:set', handler) in another. The handler body holds the sink.
_PUB_WRITE = re.compile(
    r"(?P<kind>emit|publish|trigger)\s*\(\s*"
    r"(?P<key>'[^']{0,80}'|\"[^\"]{0,80}\"|[A-Za-z_$][\w$]{0,60})\s*"
    r"(?:,\s*(?P<expr>[^;]{0,240}))?"
)
_CUSTOM_EVENT = re.compile(
    r"new\s+CustomEvent\s*\(\s*(?P<key>'[^']{0,80}'|\"[^\"]{0,80}\")\s*,\s*\{"
    r"[^{}]{0,160}?detail\s*:\s*(?P<expr>[^}]{0,200})"
)
_PUB_READ = re.compile(
    r"(?P<kind>addEventListener|on|once|subscribe)\s*\(\s*"
    r"(?P<key>'[^']{0,80}'|\"[^\"]{0,80}\")\s*,\s*(?P<handler>[^;]{0,400})"
)
_HANDLER_PARAM = re.compile(
    r"^\s*(?:function\s*[\w$]*\s*\(\s*([A-Za-z_$][\w$]{0,40})"
    r"|\(?\s*([A-Za-z_$][\w$]{0,40})\s*\)?\s*=>)"
)

_CONST_STR = re.compile(
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]{0,60})\s*=\s*('([^']{0,80})'|\"([^\"]{0,80})\")\s*[;,\n]"
)

_STRIP_QUOTES = re.compile(r"^['\"]|['\"]$")
_GET_PARAM = re.compile(r"\.get\s*\(\s*['\"]([^'\"]{1,60})['\"]\s*\)")

# A store key that could not be resolved to a literal. Kept distinct from ""
# so callers can report *why* a flow stayed unjoined.
UNKNOWN_KEY = "*"


@dataclass
class StoreWrite:
    """A value from the request landing in a state store."""

    kind: str            # localStorage | sessionStorage | state | dispatch
    key: str
    source: str
    delivery: str
    resource: str
    line: int
    parameter: str = ""
    snippet: str = ""

    def label(self) -> str:
        return f"{self.kind}.{self.key}"


@dataclass
class StoreRead:
    """A state store entry reaching a sink (or being bound to a variable)."""

    kind: str
    key: str
    resource: str
    line: int
    sink: str = ""
    var: str = ""
    parameter: str = ""
    statement: str = ""


@dataclass
class StoreFlow:
    """A joined write→read pair: the candidate the browser has to prove."""

    write: StoreWrite
    read: StoreRead

    @property
    def sink(self) -> str:
        return self.read.sink


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def delivery_of(source: str, stmt: str, default: str = "query") -> str:
    """Which part of the request the flow reads, judged from the statement.

    ``new URLSearchParams(location.hash.slice(1))`` reads the fragment even
    though the wrapper alone says "query", so an explicit ``location.<member>``
    in the same statement outranks the caller's default.
    """
    if "location" in stmt:
        if re.search(r"location(?:\.|\[['\"])hash", stmt):
            return "hash"
        if re.search(r"location(?:\.|\[['\"])search", stmt):
            return "query"
    if source in HASH_SOURCES:
        return "hash"
    if source in REFERRER_SOURCES:
        return "referrer"
    if source in WINDOW_NAME_SOURCES:
        return "window.name"
    return default


def locate_url_source(text: str) -> tuple[str, int] | None:
    """Earliest URL-derived source in *text* (source name, offset)."""
    if not text:
        return None
    best: tuple[str, int] | None = None
    for src in URL_SOURCES:
        i = text.find(src)
        if i >= 0 and (best is None or i < best[1]):
            best = (src, i)
    return best


def _line_of(body: str, offset: int) -> int:
    return body.count("\n", 0, offset) + 1


def _statement_at(body: str, offset: int, radius: int = 240) -> str:
    """Readable statement window around *offset*; works on minified code."""
    start = max(body.rfind(";", 0, offset), body.rfind("\n", 0, offset)) + 1
    if start == 0:
        start = max(0, offset - radius)
    end = len(body)
    for delim in (";", "\n"):
        i = body.find(delim, offset)
        if i >= 0:
            end = min(end, i)
    return body[start:min(end, offset + radius)].strip()[:400]


def _clean_key(raw: str, consts: dict[str, str]) -> str:
    """Resolve a literal or a simple string constant; UNKNOWN_KEY otherwise."""
    if not raw:
        return UNKNOWN_KEY
    if raw[0] in "'\"":
        return _STRIP_QUOTES.sub("", raw)
    if raw in consts:
        return consts[raw]
    return UNKNOWN_KEY


def _group_key(m: re.Match[str], consts: dict[str, str]) -> str:
    raw = m.groupdict().get("key2") or m.groupdict().get("key") or ""
    return _clean_key(raw, consts)


def _clean_member_key(raw: str, consts: dict[str, str]) -> str:
    """Key of a member expression: ``state.draft`` names the field ``draft``.

    A bare identifier is unambiguous here -- it is the property name, not a
    variable that might hold one (which is why ``setItem(KEY, ...)`` still goes
    through the stricter :func:`_clean_key`).
    """
    if not raw:
        return UNKNOWN_KEY
    if raw[0] in "'\"":
        return _STRIP_QUOTES.sub("", raw)
    if raw in consts:
        return consts[raw]
    if re.fullmatch(r"[A-Za-z_$][\w$]{0,60}", raw):
        return raw
    return UNKNOWN_KEY


def _group_member_key(m: re.Match[str], consts: dict[str, str]) -> str:
    raw = m.groupdict().get("key2") or m.groupdict().get("key") or ""
    return _clean_member_key(raw, consts)


def _param_of(stmt: str) -> str:
    m = _GET_PARAM.search(stmt)
    if m:
        return m.group(1)
    m = re.search(r"(?:[?&])([A-Za-z_][\w-]{0,40})=", stmt)
    return m.group(1) if m else ""


def _var_of(body: str, offset: int) -> str:
    """Variable this expression was assigned to, if the shape is ``x = ...``."""
    start = max(body.rfind(";", 0, offset), body.rfind("\n", 0, offset)) + 1
    head = body[start:offset]
    m = re.search(r"(?:var|let|const)?\s*([A-Za-z_$][\w$]{0,40})\s*=\s*[^=]*$", head)
    return m.group(1) if m else ""


def _first_ident(expr: str) -> str:
    """Bare identifier on the right-hand side, ignoring trailing punctuation.

    ``setItem('k', term)`` captures ``term)`` because the expression ends at the
    closing paren, and an object literal pair ends with a comma, so both tails
    have to be tolerated.
    """
    m = re.match(r"\s*([A-Za-z_$][\w$]{0,60})\s*[)\]},]?\s*$", expr)
    return m.group(1) if m else ""


def _param_from_binding(body: str, ident: str) -> str:
    """Parameter name from the statement that produced *ident*.

    ``var term = new URLSearchParams(location.search).get('q')`` is where the
    parameter is named; the write site only sees the variable.
    """
    if not ident:
        return ""
    pattern = r"(?:var|let|const)\s+" + re.escape(ident) + r"\s*=[^;\n]{0,240}"
    for m in re.finditer(pattern, body):
        found = _GET_PARAM.search(m.group(0))
        if found:
            return found.group(1)
    return ""


def _expr_source(expr: str, taint: dict) -> tuple[str, str]:
    """(source, bound identifier) for a value expression written to a store."""
    hit = locate_url_source(expr)
    if hit:
        return hit[0], ""
    ident = _first_ident(expr)
    if ident and ident in taint:
        return taint[ident][0], ident
    return "", ident


def _handler_param(handler: str) -> str:
    m = _HANDLER_PARAM.match(handler or "")
    if not m:
        return ""
    return m.group(1) or m.group(2) or ""


# ---------------------------------------------------------------------------
# extraction
# ---------------------------------------------------------------------------

def scan_state(resource: str, body: str, taint: dict | None = None,
               sinks: list | tuple = ()) -> tuple[list[StoreWrite], list[StoreRead]]:
    """Find store writes and store reads in one resource.

    *taint* is ``analyze_js``'s variable→(source, delivery, line) map, used to
    resolve ``var v = location.search; setItem('k', v)``. *sinks* is the
    ``(name, compiled regex)`` table, so a read is only recorded as a sink read
    when the sink call sits in the same statement.
    """
    if not body:
        return [], []
    consts = {
        m.group(1): (m.group(3) if m.group(3) is not None else m.group(4))
        for m in _CONST_STR.finditer(body)
    }
    taint = taint or {}
    writes: list[StoreWrite] = []
    reads: list[StoreRead] = []

    for rx, resolver in ((_SET_CALL, _group_key), (_SET_PROP, _group_member_key)):
        for m in rx.finditer(body):
            key = resolver(m, consts)
            if key == UNKNOWN_KEY:
                continue
            expr = m.group("expr")
            hit = locate_url_source(expr)
            source = hit[0] if hit else ""
            ident = _first_ident(expr) if not source else ""
            if ident and ident in taint:
                source = taint[ident][0]
            if not source:
                continue
            stmt = _statement_at(body, m.start())
            param = _param_of(stmt) or _param_from_binding(body, ident)
            writes.append(StoreWrite(
                kind=m.group("kind"), key=key, source=source,
                delivery=delivery_of(source, stmt), resource=resource,
                line=_line_of(body, m.start()), parameter=param,
                snippet=stmt,
            ))

    # application store writes: `state.draft = <expr from the request>`
    for m in _STORE_SET.finditer(body):
        key = _group_member_key(m, consts)
        if key == UNKNOWN_KEY:
            continue
        expr = m.group("expr")
        hit = locate_url_source(expr)
        source = hit[0] if hit else ""
        if not source:
            ident = _first_ident(expr)
            if ident and ident in taint:
                source = taint[ident][0]
        if not source:
            continue
        stmt = _statement_at(body, m.start())
        writes.append(StoreWrite(kind="state", key=key, source=source,
                                 delivery=delivery_of(source, stmt), resource=resource,
                                 line=_line_of(body, m.start()), parameter=_param_of(stmt),
                                 snippet=stmt))

    # dispatch/commit payloads keep the action type as the store key
    for m in _DISPATCH.finditer(body):
        payload = m.group("payload") or m.group("value") or ""
        hit = locate_url_source(payload)
        source = hit[0] if hit else ""
        if not source:
            ident = _first_ident(payload)
            if ident and ident in taint:
                source = taint[ident][0]
        if not source:
            continue
        action = (_STRIP_QUOTES.sub("", m.group("type") or m.group("type2") or "")
                  or "payload")
        stmt = _statement_at(body, m.start())
        writes.append(StoreWrite(kind="dispatch", key=action, source=source,
                                 delivery=delivery_of(source, stmt), resource=resource,
                                 line=_line_of(body, m.start()), parameter=_param_of(stmt),
                                 snippet=stmt))

    # React class state: setState({draft: <expr>}) is read back as this.state.draft
    for head in _SET_STATE_HEAD.finditer(body):
        tail = body[head.end(): head.end() + 400]
        pairs = list(_OBJ_PAIR.finditer(tail))
        for i, pair in enumerate(pairs):
            key = pair.group("k1") or pair.group("k2") or pair.group("k3") or ""
            if not key:
                continue
            end = pairs[i + 1].start() if i + 1 < len(pairs) else len(tail)
            expr = tail[pair.end():end].split("}")[0]
            source, ident = _expr_source(expr, taint)
            if not source:
                continue
            stmt = _statement_at(body, head.end() + pair.start())
            writes.append(StoreWrite(
                kind="state", key=key, source=source,
                delivery=delivery_of(source, stmt), resource=resource,
                line=_line_of(body, head.end() + pair.start()),
                parameter=_param_of(stmt) or _param_from_binding(body, ident),
                snippet=stmt,
            ))

    # Event bus / custom events: emit('draft:set', <expr>)
    for rx in (_PUB_WRITE, _CUSTOM_EVENT):
        for m in rx.finditer(body):
            key = _clean_key(m.group("key"), consts)
            if key == UNKNOWN_KEY:
                continue
            source, ident = _expr_source(m.group("expr") or "", taint)
            if not source:
                continue
            stmt = _statement_at(body, m.start())
            writes.append(StoreWrite(
                kind="event", key=key, source=source,
                delivery=delivery_of(source, stmt), resource=resource,
                line=_line_of(body, m.start()),
                parameter=_param_of(stmt) or _param_from_binding(body, ident),
                snippet=stmt,
            ))

    for rx, resolver in ((_GET_CALL, _group_key), (_GET_PROP, _group_member_key)):
        for m in rx.finditer(body):
            key = resolver(m, consts)
            if key == UNKNOWN_KEY:
                continue
            kind = m.group("kind")
            stmt = _statement_at(body, m.start())
            sink = ""
            for name, sink_rx in sinks:
                if sink_rx.search(stmt):
                    sink = name
                    break
            var = _var_of(body, m.start())
            if not sink and not var:
                continue
            reads.append(StoreRead(kind=kind, key=key, resource=resource,
                                   line=_line_of(body, m.start()), sink=sink,
                                   var=var, parameter=_param_of(stmt), statement=stmt))

    for m in _STORE_GET.finditer(body):
        key = _group_member_key(m, consts)
        if key == UNKNOWN_KEY:
            continue
        stmt = _statement_at(body, m.start())
        sink = ""
        for name, sink_rx in sinks:
            if sink_rx.search(stmt):
                sink = name
                break
        var = _var_of(body, m.start())
        if not sink and not var:
            continue
        reads.append(StoreRead(kind="state", key=key, resource=resource,
                               line=_line_of(body, m.start()), sink=sink, var=var,
                               parameter=_param_of(stmt), statement=stmt))

    # Event bus reads: the sink sits inside the handler, not in the statement
    # that registers it, so the handler body is what has to be searched.
    for m in _PUB_READ.finditer(body):
        key = _clean_key(m.group("key"), consts)
        if key == UNKNOWN_KEY:
            continue
        handler = m.group("handler")
        sink = ""
        for name, sink_rx in sinks:
            if sink_rx.search(handler):
                sink = name
                break
        var = _handler_param(handler)
        if not sink and not var:
            continue
        reads.append(StoreRead(kind="event", key=key, resource=resource,
                               line=_line_of(body, m.start()), sink=sink, var=var,
                               parameter=_param_of(handler), statement=handler.strip()[:400]))
    return writes, reads


def reducer_map(body: str) -> dict[str, str]:
    """Action type -> state field, read from switch/case reducers.

    A dispatch carries the action type; the reducer is where that type turns
    into a field name. Joining the two is what lets a ``dispatch({type:
    'SET_QUERY', payload})`` write be paired with a ``state.query`` read.
    """
    out: dict[str, str] = {}
    if not body:
        return out
    for m in _REDUCER_CASE.finditer(body):
        window = body[m.end(): m.end() + 600]
        field = _REDUCER_FIELD.search(window) or _REDUCER_SPREAD.search(window)
        if field:
            action = _STRIP_QUOTES.sub("", m.group("action"))
            out.setdefault(action, field.group("field"))
    return out


def expand_dispatch(writes: list[StoreWrite], reducers: dict[str, str],
                    limit: int = 24) -> list[StoreWrite]:
    """Add the ``state.<field>`` write that a dispatched action turns into."""
    out = list(writes)
    if not reducers:
        return out
    seen = {(w.kind, w.key, w.resource, w.line) for w in out}
    for write in writes:
        if write.kind != "dispatch":
            continue
        field = reducers.get(write.key)
        if not field:
            continue
        marker = ("state", field, write.resource, write.line)
        if marker in seen:
            continue
        seen.add(marker)
        out.append(StoreWrite(kind="state", key=field, source=write.source,
                              delivery=write.delivery, resource=write.resource,
                              line=write.line, parameter=write.parameter,
                              snippet=write.snippet))
        if len(out) >= limit:
            break
    return out


def join_state(writes: list[StoreWrite], reads: list[StoreRead],
               limit: int = 12) -> list[StoreFlow]:
    """Pair every sink-reaching read with a write of the same (kind, key).

    Ordering is deterministic (first write in resource order wins) so a report
    does not shuffle between runs. Reads without a sink are skipped here: the
    caller joins those against ``analyze_js`` candidates through ``var``.
    """
    out: list[StoreFlow] = []
    seen: set[tuple[str, str, str, str]] = set()
    for read in reads:
        if not read.sink:
            continue
        for write in writes:
            if write.kind != read.kind or write.key != read.key:
                continue
            key = (read.sink, read.resource, write.key, write.kind)
            if key in seen:
                break
            seen.add(key)
            out.append(StoreFlow(write=write, read=read))
            break
        if len(out) >= limit:
            break
    return out


def read_for_var(reads: list[StoreRead], var: str, resource: str) -> StoreRead | None:
    """The storage read that produced *var* (for taint-tracked candidates)."""
    if not var:
        return None
    for read in reads:
        if read.var == var and read.resource == resource:
            return read
    for read in reads:
        if read.var == var:
            return read
    return None


def write_for(kind: str, key: str, writes: list[StoreWrite]) -> StoreWrite | None:
    for write in writes:
        if write.kind == kind and write.key == key:
            return write
    return None
