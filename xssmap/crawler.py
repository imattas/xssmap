"""Bounded, scope-aware crawler for xssmap.

Discovers:
  * HTML pages (BFS, depth/limit bounded)
  * links, redirects, canonical/alternate tags
  * forms and their fields
  * endpoints referenced from inline JS and external JS bundles
  * sitemap.xml / robots.txt entries
  * URLs carrying query parameters (the main XSS surface)
"""
from __future__ import annotations

import re
import threading
import urllib.parse
import urllib.robotparser
from collections import deque
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field

from .htmlparse import (
    Form,
    ParsedPage,
    extract_js_fetch_targets,
    extract_js_urls,
    is_page_url,
    parse_page,
    parse_qs_ordered,
    same_site,
)

MAX_JS_BODY = 512_000   # analyse slices this large; keeps memory bounded on huge bundles

# <script> types that are not executable code: state blobs, import maps and
# client-side templates. Feeding them to the taint pass only adds noise.
DATA_SCRIPT_TYPES = frozenset({
    "application/json", "application/ld+json", "importmap", "speculationrules",
    "text/template", "text/x-template", "text/html", "text/plain",
})


def is_js_script_type(value: str) -> bool:
    """True when a <script type=...> block should be treated as JavaScript."""
    v = (value or "").strip().lower()
    if not v:
        return True
    return v not in DATA_SCRIPT_TYPES


TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "gclid", "fbclid", "msclkid", "yclid", "dclid", "mc_cid", "mc_eid",
    "_ga", "_gl", "ref", "referrer", "affiliate_id",
}

COMMON_PATHS = [
    "/", "/index.html", "/index.php", "/search", "/search.php", "/search.jsp",
    "/login", "/register", "/profile", "/user", "/users", "/account", "/admin",
    "/api", "/api/v1", "/contact", "/feedback", "/comment", "/comments",
    "/upload", "/download", "/redirect", "/redir", "/url", "/link", "/out",
    "/page", "/pages", "/view", "/item", "/product", "/products", "/detail",
    "/blog", "/news", "/article", "/category", "/tag", "/s", "/q", "/query",
    "/error", "/404", "/preview", "/share", "/print", "/lang", "/locale",
]


@dataclass
class Page:
    url: str
    status: int
    content_type: str
    length: int
    title: str = ""
    depth: int = 0
    params: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class JsFile:
    url: str
    length: int = 0
    targets: list[str] = field(default_factory=list)
    body: str = ""                                  # capped copy, analysed for DOM sinks
    pages: list[str] = field(default_factory=list)   # pages that load this script


@dataclass
class CrawlResult:
    pages: dict[str, Page] = field(default_factory=dict)
    param_urls: list[str] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    js_files: dict[str, JsFile] = field(default_factory=dict)
    external_hosts: set[str] = field(default_factory=set)
    sitemap_urls: list[str] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)
    skipped_scope: int = 0
    #: Headers of the first HTML response. The server-stack pass reads them so
    #: it does not have to send a second request the target already answered.
    root_headers: list[tuple[str, str]] = field(default_factory=list)
    #: Content of <meta name="generator"> on the seed page, if it has one.
    generator: str = ""


def normalize_url(url: str) -> str:
    try:
        parts = urllib.parse.urlsplit(url)
    except Exception:
        return url
    scheme = parts.scheme.lower() or "http"
    host = (parts.hostname or "").lower()
    port = parts.port
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"
    else:
        netloc = host
    if parts.username:
        netloc = f"{parts.username}@{netloc}"
    path = parts.path or "/"
    # collapse duplicate slashes in path but keep leading
    path = re.sub(r"/{2,}", "/", path)
    pairs = parse_qs_ordered(parts.query)
    pairs = [(k, v) for k, v in pairs if k and k not in TRACKING_PARAMS]
    query = "&".join(f"{k}={v}" for k, v in pairs)
    return urllib.parse.urlunsplit((scheme, netloc, path, query, ""))


def dedupe_key(url: str) -> str:
    """Two URLs collide when host, path and parameter names match."""
    parts = urllib.parse.urlsplit(url)
    names = sorted({k for k, _ in parse_qs_ordered(parts.query)})
    return f"{parts.hostname}{parts.path}?{','.join(names)}"


class Scope:
    def __init__(self, base: str, mode: str = "host"):
        parts = urllib.parse.urlsplit(base)
        self.base_host = (parts.hostname or "").lower()
        self.mode = mode
        self.port = parts.port
        self.scheme = parts.scheme

    def allows(self, url: str) -> bool:
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https"):
            return False
        host = (parts.hostname or "").lower()
        if not host:
            return False
        if self.mode == "any":
            return True
        if self.mode == "subdomain":
            return host == self.base_host or host.endswith("." + self.base_host)
        return host == self.base_host

    def describe(self) -> str:
        return f"host={self.base_host} mode={self.mode}"


class Crawler:
    def __init__(self, http, scope: Scope, log, max_depth: int = 3, max_pages: int = 200,
                 concurrency: int = 4, exclude: list[str] | None = None,
                 include: list[str] | None = None, crawl_js: bool = True,
                 crawl_forms: bool = True, ajax: bool = True, respect_robots: bool = False,
                 max_js_files: int = 25, headers: list[tuple[str, str]] | None = None):
        self.http = http
        self.scope = scope
        self.log = log
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.concurrency = max(1, concurrency)
        self.exclude = [re.compile(p, re.I) for p in (exclude or [])]
        self.include = [re.compile(p, re.I) for p in (include or [])]
        self.crawl_js = crawl_js
        self.crawl_forms = crawl_forms
        self.ajax = ajax
        self.respect_robots = respect_robots
        self.max_js_files = max_js_files
        self.headers = headers or []
        self.cfg = {"headers": self.headers}
        self.result = CrawlResult()
        self.robots: urllib.robotparser.RobotFileParser | None = None
        self._lock = threading.RLock()
        self._seen: set[str] = set()
        self._seen_keys: set[str] = set()
        self._js_queue: list[str] = []
        self._js_owners: dict[str, list[str]] = {}
        self._param_keys: dict[str, int] = {}
        self._fetched = 0

    # -- filters -----------------------------------------------------
    def _excluded(self, url: str) -> bool:
        if any(rx.search(url) for rx in self.exclude):
            return True
        if self.include and not any(rx.search(url) for rx in self.include):
            return True
        low = url.lower()
        return any(bad in low for bad in
                   ("/logout", "/signout", "/delete", "/remove", "/destroy"))

    def _robots_allows(self, url: str) -> bool:
        if not self.respect_robots or self.robots is None:
            return True
        try:
            return self.robots.can_fetch("*", url)
        except Exception:
            return True

    # -- entry -------------------------------------------------------
    def run(self, seeds: list[str]) -> CrawlResult:
        """Crawl from ``seeds`` with a continuously fed worker pool.

        The queue is fed as results arrive instead of level by level. A level
        barrier idles every worker until the slowest page of that level answers,
        which on a 150-page site with one slow page per level costs more than the
        crawl itself. Depth is carried per URL (the seed is depth 0, so
        ``max_depth`` still means hops from the seed) and children are only
        queued while ``depth < max_depth``.
        """
        seeds = [normalize_url(u) for u in seeds if self.scope.allows(u)]
        self._collect_robots(seeds[0] if seeds else "")
        self._add_seed_urls(seeds)
        pending: deque[tuple[str, int]] = deque((u, 0) for u in seeds)
        self.log.info(f"  crawl start: {len(pending)} seed(s), depth {self.max_depth}, "
                      f"{self.concurrency} worker(s), max {self.max_pages} page(s)")
        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            futures: dict = {}
            while pending or futures:
                # Keep every worker busy: refill as soon as a slot frees up.
                while pending and len(futures) < self.concurrency * 2 \
                        and self._fetched < self.max_pages:
                    url, depth = pending.popleft()
                    if url in self._seen:
                        continue
                    self._seen.add(url)
                    self._fetched += 1
                    futures[pool.submit(self._fetch_and_parse, url, depth)] = (url, depth)
                if not futures:
                    if pending:
                        self.log.info(f"  page budget {self.max_pages} reached")
                    break
                done, _ = wait(futures, return_when=FIRST_COMPLETED)
                for fut in done:
                    url, depth = futures.pop(fut)
                    try:
                        found = fut.result()
                    except Exception as exc:  # keep crawling on individual failures
                        self.result.errors.append((url, str(exc)))
                        continue
                    if depth < self.max_depth:
                        pending.extend((u, depth + 1) for u in found if u not in self._seen)
        self.log.info(f"  crawl stopped: {self._fetched} page(s) fetched, "
                      f"{len(self.result.errors)} error(s)")
        self._crawl_js_bundles()
        self._finish_param_urls()
        return self.result

    def _add_seed_urls(self, seeds: list[str]):
        for u in seeds:
            self._register_url(u, is_seed=True)

    def _collect_robots(self, base: str):
        if not base:
            return
        parts = urllib.parse.urlsplit(base)
        root = f"{parts.scheme}://{parts.netloc}"
        # Both probes are on the critical path before the first page is fetched,
        # so ask for them at the same time instead of paying two round trips.
        with ThreadPoolExecutor(max_workers=2) as pool:
            f_robots = pool.submit(self.http.get, root + "/robots.txt", self.headers)
            f_map = pool.submit(self.http.get, root + "/sitemap.xml", self.headers)
        try:
            resp = f_robots.result()
            if resp.status == 200 and "html" not in (resp.content_type or ""):
                text = resp.text
                rp = urllib.robotparser.RobotFileParser()
                rp.parse(text.splitlines())
                self.robots = rp
                sitemaps = re.findall(r"(?im)^\s*sitemap:\s*(\S+)", text)
                for sm in sitemaps[:5]:
                    self._ingest_sitemap(sm)
        except Exception:
            pass
        try:
            resp = f_map.result()
            if resp.status == 200 and ("xml" in (resp.content_type or "") or resp.text.lstrip().startswith("<?xml")):
                self._ingest_sitemap_xml(resp.text)
        except Exception:
            pass

    def _ingest_sitemap(self, url: str):
        try:
            resp = self.http.get(url, headers=self.headers)
        except Exception:
            return
        if resp.status == 200:
            self._ingest_sitemap_xml(resp.text, sitemap_url=url)

    def _ingest_sitemap_xml(self, text: str, sitemap_url: str = ""):
        locs = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", text, re.I)
        for loc in locs[:400]:
            loc = loc.strip().replace("&amp;", "&")
            if loc.endswith(".xml") and ("sitemap" in loc.lower()):
                continue
            self.result.sitemap_urls.append(loc)
            self._register_url(normalize_url(loc))

    # -- fetching ----------------------------------------------------
    def _fetch_and_parse(self, url: str, depth: int) -> list[str]:
        found: list[str] = []
        if not self.scope.allows(url):
            with self._lock:
                self.result.skipped_scope += 1
            return found
        if not self._robots_allows(url):
            return found
        try:
            resp = self.http.get(url, headers=self.headers)
        except Exception as exc:
            with self._lock:
                self.result.errors.append((url, str(exc)))
                self.result.pages[url] = Page(url, 0, "", 0, error=str(exc), depth=depth)
            return found

        # record the page plus redirect hops
        final_url = resp.url
        with self._lock:
            self.result.pages[url] = Page(
                url=url, status=resp.status, content_type=resp.content_type,
                length=len(resp.body),
                title=_title_of(resp.text) if resp.is_html else "",
                depth=depth, params=[k for k, _ in parse_qs_ordered(urllib.parse.urlsplit(url).query)],
            )
            if final_url != url:
                self.result.pages.setdefault(final_url, Page(
                    url=final_url, status=resp.status, content_type=resp.content_type,
                    length=len(resp.body), depth=depth))
            for hop in resp.history:
                if hop.location:
                    loc = urllib.parse.urljoin(hop.url, hop.location)
                    if self.scope.allows(loc):
                        self._register_url(normalize_url(loc))
                        found.append(normalize_url(loc))

        if resp.is_html:
            page = parse_page(final_url, resp.text)
            with self._lock:
                if not self.result.root_headers:
                    self.result.root_headers = list(getattr(resp, "headers", None) or [])
                    self.result.generator = _generator_of(page)
            found.extend(self._harvest_page(page, final_url, depth))
        elif resp.is_javascript and self.crawl_js:
            self._queue_js(final_url, resp.text)
        return [u for u in found if u and self.scope.allows(u) and not self._excluded(u) and is_page_url(u)]

    def _harvest_page(self, page: ParsedPage, url: str, depth: int) -> list[str]:
        found: list[str] = []
        for link in page.links:
            u = normalize_url(link.url)
            if not u or u.startswith(("javascript:", "mailto:", "tel:", "data:")):
                continue
            target = urllib.parse.urlsplit(u).hostname or ""
            base_host = urllib.parse.urlsplit(url).hostname or ""
            if target and base_host and target != base_host and not same_site(u, url):
                self.result.external_hosts.add(target)
            if self.scope.allows(u) and not self._excluded(u):
                self._register_url(u)
                found.append(u)

        if self.crawl_forms:
            for form in page.forms:
                action = normalize_url(form.action or url)
                if not self.scope.allows(action):
                    continue
                with self._lock:
                    self.result.forms.append(form)
                if form.method == "GET" and form.params:
                    from .htmlparse import build_query
                    pairs = [(n, v) for n, v, _ in form.params if n]
                    if pairs:
                        sep = "" if not urllib.parse.urlsplit(action).query else "&"
                        u = action + sep + build_query(pairs)
                        self._register_url(u)
                        found.append(u)

        if self.crawl_js:
            # Every inline block of a page belongs to one virtual resource: a flow
            # routinely assigns a variable in one block and sinks it in another,
            # and keying each block as its own `#inline` resource silently kept
            # only the first one. Data blocks (JSON state blobs, templates) are
            # not scripts; they are read through their element id instead.
            inline: list[str] = []
            for script in page.scripts:
                if script.is_inline:
                    if is_js_script_type(script.type):
                        inline.append(script.body)
                    if self.ajax:
                        for target, _method in extract_js_fetch_targets(script.body):
                            cand = normalize_url(urllib.parse.urljoin(url, target))
                            if self.scope.allows(cand) and not self._excluded(cand):
                                self._register_url(cand)
                                if is_page_url(cand):
                                    found.append(cand)
                elif script.src:
                    # remember which page pulls the bundle in (DOM scan needs a host page)
                    script_url = normalize_url(urllib.parse.urljoin(url, script.src))
                    if script_url and self.scope.allows(script_url):
                        self._register_url(script_url)
                        self._js_owners.setdefault(script_url, []).append(url)
            if inline:
                self._queue_js(url + "#inline", "\n".join(inline), owner=url)
        return found

    # -- JS ----------------------------------------------------------
    def _queue_js(self, url: str, body: str, owner: str = ""):
        with self._lock:
            if url in self.result.js_files:
                if owner and owner not in self.result.js_files[url].pages:
                    self.result.js_files[url].pages.append(owner)
                return
            file = JsFile(url=url, length=len(body), body=body[:MAX_JS_BODY])
            for page_url in self._js_owners.get(url, [])[:5]:
                file.pages.append(page_url)
            if owner and owner not in file.pages:
                file.pages.append(owner)
            targets = extract_js_urls(body, url)
            file.targets = [t for t in targets if self.scope.allows(t)]
            self.result.js_files[url] = file
            if len(self.result.js_files) <= self.max_js_files:
                for t in file.targets:
                    self._register_url(normalize_url(t))
                    if is_page_url(t):
                        self._js_queue.append(normalize_url(t))

    def _crawl_js_bundles(self):
        """Fetch external JS bundles queued during the HTML crawl and mine them.

        Bundles are independent resources, so they go through the same pool as
        pages. Sequential fetches cost one full round trip each and made the JS
        phase the longest part of a crawl on a high-latency target.
        """
        pending = [url for url, info in list(self.result.js_files.items())[: self.max_js_files]
                   if not info.length]
        if not pending:
            return
        self.log.info(f"  fetching {len(pending)} JS bundle(s) for endpoint discovery")

        def fetch(url: str) -> None:
            try:
                resp = self.http.get(url, headers=self.headers)
            except Exception:
                return
            if resp.status != 200:
                return
            with self._lock:
                cached = self.result.js_files.get(url)
                if not cached:
                    return
                body = resp.text
                cached.length = len(body)
                cached.body = body[:MAX_JS_BODY]
                targets = extract_js_urls(body, url)
                cached.targets = [t for t in targets if self.scope.allows(t)]
                for t in cached.targets:
                    self._register_url(normalize_url(t))

        with ThreadPoolExecutor(max_workers=min(self.concurrency, len(pending))) as pool:
            list(pool.map(fetch, pending))

    # -- URL registry ------------------------------------------------
    def _register_url(self, url: str, is_seed: bool = False):
        """Track parameterised URLs and dedupe by host+path+param names."""
        if not url or not self.scope.allows(url):
            return
        parts = urllib.parse.urlsplit(url)
        if not parts.query:
            return
        pairs = parse_qs_ordered(parts.query)
        if not pairs:
            return
        key = dedupe_key(url)
        with self._lock:
            count = self._param_keys.get(key, 0)
            # keep up to 3 value variants per signature (ids/pages) and all seeds
            if count >= 3 and not is_seed:
                return
            self._param_keys[key] = count + 1
            if url not in self.result.param_urls:
                self.result.param_urls.append(url)

    def _finish_param_urls(self):
        # Shallow/short URLs get scanned first. The URL itself is the final key:
        # without it, ties were broken by crawl completion order, so the same
        # target produced a different point order (and a different --max-points
        # cut) on every run.
        self.result.param_urls.sort(
            key=lambda u: (len(urllib.parse.urlsplit(u).query), len(u), u))


def _title_of(text: str) -> str:
    m = re.search(r"(?is)<title[^>]*>(.*?)</title>", text)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:120]


def _generator_of(page: ParsedPage) -> str:
    """``<meta name="generator" content=...>``, the usual CMS disclosure."""
    for tag, attrs, _pos in page.tags:
        if tag != "meta" or (attrs.get("name") or "").lower() != "generator":
            continue
        return (attrs.get("content") or "").strip()[:120]
    return ""
