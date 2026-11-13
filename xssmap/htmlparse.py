"""HTML analysis for xssmap.

Two jobs:
  1. Crawler extraction: links, forms (inputs incl. hidden), scripts, base href.
  2. Injection surface discovery: every parameter-bearing URL and every place a
     value could be reflected (attribute values with exact offsets, <script>
     bodies, text nodes, event handlers, JS string literals, style, comments).

We keep offsets for attribute values so payload injection can be surgical and
so reflections can be matched to a specific syntactic context.
"""
from __future__ import annotations

import html
import re
import urllib.parse
from dataclasses import dataclass, field
from html.parser import HTMLParser

URL_ATTRS = {
    "href", "src", "action", "formaction", "data", "poster", "cite", "background",
    "longdesc", "usemap", "manifest", "ping", "srcset", "data-src", "data-url",
    "data-href", "data-action", "xlink:href", "profile", "codebase", "archive",
}

SKIP_EXTENSIONS = re.compile(
    r"\.(?:png|jpe?g|gif|bmp|svg|webp|ico|tiff?|css|woff2?|ttf|eot|otf|mp4|webm|"
    r"mp3|wav|ogg|avi|mov|wmv|flv|pdf|zip|rar|7z|gz|tar|bz2|xz|docx?|xlsx?|pptx?|"
    r"exe|msi|dmg|apk|ipa|bin|iso|img|jar|woff|map)$",
    re.I,
)

JS_URL_HINTS = (
    "url", "href", "path", "link", "redirect", "return", "next", "target",
    "dest", "destination", "src", "page", "continue", "callback",
)


@dataclass
class AttrValue:
    tag: str
    name: str
    value: str
    start: int          # offset of value text inside raw html
    end: int
    quote: str          # '"', "'" or '' (unquoted)
    tag_index: int      # ordinal of the owning tag in document order
    attr_index: int     # ordinal of the attribute inside the tag


@dataclass
class ScriptBlock:
    src: str | None
    body: str
    start: int          # offset of body
    end: int
    type: str = ""

    @property
    def is_inline(self) -> bool:
        return not self.src and bool(self.body.strip())


@dataclass
class Comment:
    text: str
    start: int
    end: int


@dataclass
class Form:
    action: str
    method: str
    enctype: str
    params: list[tuple[str, str, str]] = field(default_factory=list)  # name, value, type
    has_file: bool = False
    origin_url: str = ""

    @property
    def names(self) -> list[str]:
        return [p[0] for p in self.params if p[0]]


@dataclass
class Link:
    url: str
    text: str = ""
    rel: str = ""
    tag: str = "a"
    source: str = "html"      # html | script | sitemap | robots | form | jsfile


class _Extractor(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.tags: list[tuple[str, dict[str, str], int]] = []
        self.attrs: list[AttrValue] = []
        self.scripts: list[ScriptBlock] = []
        self.comments: list[Comment] = []
        self.links: list[Link] = []
        self.forms: list[Form] = []
        self.base_href: str | None = None
        self.title = ""
        self._in_title = False
        self._tag_index = 0
        self._script_start: int | None = None
        self._script_attrs: dict[str, str] = {}
        self._script_src: str | None = None
        self._script_type = ""
        self._current_form: Form | None = None
        self._form_depth = 0
        self._line_starts = [0]
        self.raw = ""

    def set_raw(self, raw: str) -> None:
        self.raw = raw
        starts = [0]
        for m in re.finditer("\n", raw):
            starts.append(m.end())
        self._line_starts = starts

    def _offset(self) -> int:
        line, col = self.getpos()
        if line - 1 < len(self._line_starts):
            return self._line_starts[line - 1] + col
        return 0

    # -- tags --------------------------------------------------------
    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        pos = self._get_starttag_pos()
        raw_attrs: list[tuple[str, str | None]] = attrs
        adict: dict[str, str] = {}
        for name, value in raw_attrs:
            if name:
                adict.setdefault(name.lower(), value if value is not None else "")
                self._record_attr(tag, name.lower(), value, pos, len(adict) - 1)
        self.tags.append((tag, adict, pos))

        if tag == "base" and adict.get("href"):
            self.base_href = adict["href"]
        if tag == "title":
            self._in_title = True
        if tag == "script":
            self._script_start = self._offset()
            self._script_attrs = adict
            self._script_src = adict.get("src")
            self._script_type = adict.get("type", "")
            if self._script_src:
                self.links.append(Link(self._resolve(self._script_src), tag="script", source="html"))
        if tag == "form":
            self._current_form = Form(
                action=self._resolve(adict.get("action", "")),
                method=(adict.get("method") or "GET").upper(),
                enctype=(adict.get("enctype") or "application/x-www-form-urlencoded").lower(),
                origin_url=self.base_url,
            )
            self._form_depth = 1
        elif tag in ("input", "select", "textarea", "button") and self._current_form is not None:
            name = adict.get("name", "")
            itype = (adict.get("type") or ("text" if tag == "input" else tag)).lower()
            if itype == "file":
                self._current_form.has_file = True
            if name:
                self._current_form.params.append((name, adict.get("value", ""), itype))
        self._tag_index += 1

    def _get_starttag_pos(self) -> int:
        # getpos() points at the '<' of the start tag for start tags
        return self._offset()

    def _record_attr(self, tag: str, name: str, value: str | None, tag_pos: int, attr_index: int):
        if value is None:
            return
        raw = self.raw
        start = tag_pos
        tag_text = ""
        if start is not None and 0 <= start < len(raw):
            # locate this tag's raw text and find the attribute value within it
            gt = raw.find(">", start)
            tag_text = raw[start:gt if gt != -1 else start + 4000]
        if not tag_text:
            return
        pattern = re.compile(
            r"""(?is)(?<![\w-])""" + re.escape(name) + r"""\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))"""
        )
        m = pattern.search(tag_text)
        if not m:
            return
        if m.group(1) is not None:
            quote, val = '"', m.group(1)
            vstart = start + m.start(1)
        elif m.group(2) is not None:
            quote, val = "'", m.group(2)
            vstart = start + m.start(2)
        else:
            quote, val = "", m.group(3)
            vstart = start + m.start(3)
        self.attrs.append(AttrValue(
            tag=tag, name=name, value=html.unescape(val) if "&" in val else val,
            start=vstart, end=vstart + len(val), quote=quote,
            tag_index=self._tag_index, attr_index=attr_index,
        ))
        if name in URL_ATTRS and val:
            if name == "srcset":
                for part in val.split(","):
                    u = part.strip().split(" ")[0]
                    if u:
                        self.links.append(Link(self._resolve(u), tag=tag, source="html"))
            else:
                self.links.append(Link(self._resolve(val), tag=tag, source="html"))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag.lower() == "script":
            self._script_start = None

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == "title":
            self._in_title = False
        if tag == "script" and self._script_start is not None:
            end = self._offset()
            # body starts after the '>' that closes the start tag
            gt = self.raw.find(">", self._script_start)
            body_start = gt + 1 if gt != -1 else self._script_start
            if end > body_start:
                self.scripts.append(ScriptBlock(
                    src=self._script_src,
                    body=self.raw[body_start:end],
                    start=body_start, end=end, type=self._script_type,
                ))
            self._script_start = None
            self._script_src = None
            self._script_type = ""
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None
            self._form_depth = 0

    def handle_data(self, data):
        if self._in_title:
            self.title += data

    def handle_comment(self, data):
        pos = self._offset()
        self.comments.append(Comment(text=data, start=pos, end=pos + len(data)))

    # -- helpers -----------------------------------------------------
    def _resolve(self, url: str) -> str:
        if not url:
            return ""
        url = html.unescape(url.strip())
        if url.startswith(("javascript:", "data:", "mailto:", "tel:", "#", "about:")):
            return url
        try:
            return urllib.parse.urljoin(self.base_url, url)
        except Exception:
            return url

    def close(self):
        super().close()
        if self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


@dataclass
class ParsedPage:
    url: str
    raw: str
    links: list[Link]
    forms: list[Form]
    scripts: list[ScriptBlock]
    attrs: list[AttrValue]
    comments: list[Comment]
    title: str
    base_href: str | None
    tags: list[tuple[str, dict[str, str], int]]


def parse_page(url: str, body: str) -> ParsedPage:
    ex = _Extractor(url)
    ex.set_raw(body)
    try:
        ex.feed(body)
        ex.close()
    except Exception:
        pass
    base = url
    links = ex.links
    if ex.base_href:
        base = urllib.parse.urljoin(url, ex.base_href)
        if base != url:
            links = [Link(urllib.parse.urljoin(base, link.url), link.text, link.rel,
                          link.tag, link.source) for link in links]
            for f in ex.forms:
                f.action = urllib.parse.urljoin(base, f.action)
    clean_links = [link for link in links
                   if link.url and not link.url.lower().startswith(
                       ("javascript:", "data:", "mailto:", "tel:", "about:"))]
    return ParsedPage(
        url=url, raw=body, links=clean_links, forms=ex.forms, scripts=ex.scripts,
        attrs=ex.attrs, comments=ex.comments, title=ex.title.strip(),
        base_href=ex.base_href, tags=ex.tags,
    )


# ---------------------------------------------------------------------------
# URL parameter handling
# ---------------------------------------------------------------------------

def parse_qs_ordered(query: str) -> list[tuple[str, str]]:
    """Like urllib.parse.parse_qsl but keeps blanks and order, doesn't drop '='."""
    out: list[tuple[str, str]] = []
    if not query:
        return out
    for part in query.split("&"):
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
        else:
            k, v = part, ""
        out.append((urllib.parse.unquote_plus(k), urllib.parse.unquote_plus(v)))
    return out


def build_query(pairs: list[tuple[str, str]]) -> str:
    return "&".join(
        f"{urllib.parse.quote_plus(k, safe='')}={urllib.parse.quote_plus(str(v), safe='')}"
        for k, v in pairs
    )


def set_query_param(url: str, index: int, value: str) -> str:
    parts = urllib.parse.urlsplit(url)
    pairs = parse_qs_ordered(parts.query)
    if index < 0 or index >= len(pairs):
        return url
    pairs[index] = (pairs[index][0], value)
    return urllib.parse.urlunsplit((
        parts.scheme, parts.netloc, parts.path, build_query(pairs), parts.fragment,
    ))


def query_pairs(url: str) -> list[tuple[str, str]]:
    return parse_qs_ordered(urllib.parse.urlsplit(url).query)


def param_names(url: str) -> list[str]:
    return [k for k, _ in query_pairs(url)]


def is_page_url(url: str) -> bool:
    path = urllib.parse.urlsplit(url).path
    if not path or path == "/":
        return True
    return not bool(SKIP_EXTENSIONS.search(path))


def same_site(a: str, b: str) -> bool:
    ha = (urllib.parse.urlsplit(a).hostname or "").lower()
    hb = (urllib.parse.urlsplit(b).hostname or "").lower()
    if ha == hb:
        return True
    # allow www stripping
    strip = lambda h: h[4:] if h.startswith("www.") else h
    return strip(ha) == strip(hb)


# ---------------------------------------------------------------------------
# JS analysis (lightweight, regex based)
# ---------------------------------------------------------------------------

JS_STRING_RE = re.compile(r"""(?P<q>["'`])(?P<body>(?:\\.|(?!(?P=q)).){0,4000})(?P=q)""", re.S)
JS_URL_RE = re.compile(
    r"""(?:location(?:\.href)?\s*=|location\.(?:assign|replace)\s*\(|window\.open\s*\(|"""
    r"""\.src\s*=|\.href\s*=|\.action\s*=|innerHTML\s*=|outerHTML\s*=|insertAdjacentHTML\s*\(|"""
    r"""document\.write(?:ln)?\s*\(|eval\s*\(|setTimeout\s*\(\s*["'`]|"""
    r"""fetch\s*\(|axios\.(?:get|post)\s*\(|\$\.(?:get|post|ajax)\s*\()""")
JS_SINK_RE = re.compile(
    r"""(?P<sink>innerHTML|outerHTML|insertAdjacentHTML|document\.write(?:ln)?|eval|"""
    r"""setTimeout|setInterval|Function|location\.href|location\.assign|location\.replace|"""
    r"""window\.open|jQuery\.html|\.html\s*\(|\.append\s*\(|\.after\s*\(|\.before\s*\(|"""
    r"""\.prepend\s*\(|\.replaceWith\s*\(|dangerouslySetInnerHTML|v-html)\s*(?:=|\()?[^;\n]{0,120}""")
JS_ROUTER_RE = re.compile(
    r"""(?:path|route|url|href|to|redirect)\s*:\s*["'`](/[^"'`\s]{1,120})["'`]""")
JS_FETCH_RE = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|delete)|\.open)\s*\(\s*["'`]([^"'`\s]{1,300})["'`]""")
JS_ENDPOINT_RE = re.compile(r"""["'`]((?:/|https?://)[\w./\-{}$:?=&%#]{3,200})["'`]""")

DYNAMIC_ATTR_SINKS = {
    "innerhtml", "outerhtml", "insertadjacenthtml", "document.write", "document.writeln",
    "eval", "settimeout", "setinterval", "function", "src", "href", "action", "srcdoc",
}


def find_js_sinks(body: str) -> list[tuple[int, str, str]]:
    """Return (offset, sink_name, snippet) for dangerous DOM sink usages."""
    out = []
    for m in JS_SINK_RE.finditer(body):
        snippet = body[max(0, m.start() - 40):m.end() + 80].replace("\n", " ")[:200]
        out.append((m.start(), m.group("sink"), snippet))
    return out


def extract_js_urls(body: str, base: str) -> list[str]:
    urls: list[str] = []
    for m in JS_ENDPOINT_RE.finditer(body):
        u = m.group(1).replace("\\/", "/")
        if any(t in u for t in ("${", "{{", "<%", "%s", "{0}")):
            continue
        if u.startswith("/") or u.startswith("http"):
            urls.append(urllib.parse.urljoin(base, u))
    for m in JS_ROUTER_RE.finditer(body):
        urls.append(urllib.parse.urljoin(base, m.group(1)))
    return urls


def extract_js_fetch_targets(body: str) -> list[tuple[str, str]]:
    """Return (url, method) pairs for fetch/ajax calls found in inline JS."""
    out = []
    for m in re.finditer(r"""fetch\s*\(\s*["'`]([^"'`]+)["'`]""", body):
        out.append((m.group(1), "GET"))
    for m in re.finditer(r"""axios\.(get|post|put|delete)\s*\(\s*["'`]([^"'`]+)["'`]""", body):
        out.append((m.group(2), m.group(1).upper()))
    return out


def extract_textarea_bodies(raw: str) -> list[tuple[int, int]]:
    out = []
    for m in re.finditer(r"(?is)<textarea[^>]*>(.*?)</textarea>", raw):
        out.append((m.start(1), m.end(1)))
    return out
