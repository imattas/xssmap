"""Bounded subdomain discovery for xssmap.

Two independent kinds of source:

  * certificate transparency, queried through crt.sh, certspotter and
    hackertarget in that order (passive: the target sees no traffic from this
    step). One source having a bad day no longer empties the result: the next
    provider is asked, and each provider's contribution is recorded.
  * DNS brute force over a small built-in wordlist (active, opt out with
    --no-subdomain-brute)

Rules that keep this safe to run against a live target:

  * every network step has a timeout, a hard cap and a shared thread budget
  * a failing source is reported and skipped; discovery never aborts a scan
  * wildcard DNS is detected first, because brute force against a wildcard
    resolver returns every candidate as "live" and is meaningless
"""
from __future__ import annotations

import json
import random
import re
import socket
import string
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from typing import Callable

# Deliberately short: ~70 names that matter for web testing. Long lists turn a
# recon step into a loud, slow DNS sweep with little extra signal.
WORDLIST = [
    "www", "api", "api-dev", "api-staging", "app", "apps", "admin", "portal",
    "dashboard", "panel", "cpanel", "manage", "internal", "intranet", "extranet",
    "vpn", "sso", "auth", "login", "id", "accounts", "oauth", "dev", "develop",
    "staging", "stage", "stg", "test", "testing", "qa", "uat", "preprod", "prod",
    "beta", "demo", "sandbox", "preview", "old", "new", "legacy", "backup",
    "blog", "news", "docs", "wiki", "help", "support", "status", "monitoring",
    "grafana", "prometheus", "kibana", "jenkins", "ci", "git", "gitlab", "repo",
    "registry", "static", "assets", "cdn", "img", "images", "media", "files",
    "upload", "download", "shop", "store", "pay", "payments", "billing", "checkout",
    "mail", "webmail", "smtp", "imap", "ftp", "ns1", "dns", "db", "mysql",
    "redis", "mongo", "elastic", "search", "queue", "mq", "ws", "socket",
]

LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
HOST_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63})*$", re.I)

# A compact subset of the Public Suffix List: the multi-label registries where
# "last two labels" is wrong. It is intentionally not the full list (20k+
# entries would dwarf the tool); --public-suffix-list FILE adds the rest when an
# engagement needs it. Single-label suffixes need no entry: the default rule
# below already treats the last label as the suffix.
BUILTIN_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "school.nz",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp", "ed.jp",
    "co.in", "net.in", "org.in", "firm.in", "gen.in", "ind.in",
    "co.za", "org.za", "web.za", "gov.za", "net.za",
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "com.mx", "com.tr", "com.sg", "com.hk", "com.tw", "com.ar", "com.co",
    "com.pl", "com.ua", "com.ru", "com.es", "com.pt", "com.gr", "com.my",
    "co.kr", "or.kr", "co.id", "co.il", "co.th", "in.th", "co.ke", "co.ug",
    # Hosting platforms where every customer gets a label under a shared suffix.
    "github.io", "gitlab.io", "herokuapp.com", "appspot.com", "azurewebsites.net",
    "cloudfront.net", "pages.dev", "workers.dev", "netlify.app", "vercel.app",
    "web.app", "firebaseapp.com", "blogspot.com", "readthedocs.io",
})


class DiscoveryError(ValueError):
    """The supplied value cannot be used as a discovery base domain."""


def normalize_domain(value: str) -> str:
    """Return a lowercase hostname, rejecting anything that is not one.

    Accepts a bare domain, a domain with a port, or a full URL whose path is
    empty. Raises DiscoveryError with an actionable message otherwise.
    """
    raw = (value or "").strip()
    if not raw:
        raise DiscoveryError("empty domain")
    parts = urllib.parse.urlsplit(raw if "://" in raw else "//" + raw)
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise DiscoveryError(
            f"{value!r} contains a path or query; --domain takes a hostname only "
            "(use -u for a full URL)")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host or not HOST_RE.match(host):
        raise DiscoveryError(f"{value!r} is not a valid hostname")
    return host


def is_ip(host: str) -> bool:
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, host)
            return True
        except OSError:
            continue
    return False


def is_under(host: str, domain: str) -> bool:
    """True when host is the domain itself or a subdomain of it.

    The trailing-dot comparison matters: 'notexample.com' must not match
    'example.com'.
    """
    host = host.lower().rstrip(".")
    domain = domain.lower().rstrip(".")
    return host == domain or host.endswith("." + domain)


def load_suffix_file(path: str) -> set[str]:
    """Read a Public Suffix List file (comments, wildcards and exceptions)."""
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            raw = handle.read()
    except OSError as exc:
        raise DiscoveryError(f"could not read --public-suffix-list: {exc}") from exc
    suffixes: set[str] = set()
    for line in raw.splitlines():
        entry = line.strip().lower()
        if not entry or entry.startswith("//"):
            continue
        entry = entry.rstrip(".")
        if entry.startswith("*."):
            entry = "*." + entry[2:]
        elif entry.startswith("!"):
            entry = "!" + entry[1:]
        if not entry or entry.startswith("//"):
            continue
        suffixes.add(entry)
    if not suffixes:
        raise DiscoveryError(f"--public-suffix-list {path} has no usable entries")
    return suffixes


def public_suffix(host: str, suffixes: set[str] | None = None) -> str:
    """Longest matching public suffix for *host* (RFC 6265 section 5.3 logic).

    Unknown registries fall back to the last label, which is what the built-in
    rule did before and is correct for the vast majority of targets.
    """
    table = BUILTIN_SUFFIXES if suffixes is None else suffixes
    labels = (host or "").lower().rstrip(".").split(".")
    if len(labels) < 2:
        return host or ""
    for index in range(len(labels)):
        candidate = ".".join(labels[index:])
        # "!city.kawasaki.jp": the name itself is registrable, so the suffix
        # is its parent tail (exception rules beat wildcard rules).
        if "!" + candidate in table:
            return ".".join(labels[index + 1:]) or candidate
        if candidate in table:
            return candidate
        # "*.ck" style rule: every label directly under the tail is a suffix.
        if index + 1 < len(labels) and "*." + ".".join(labels[index + 1:]) in table:
            return candidate
    return labels[-1]


def registrable_domain(host: str, suffixes: set[str] | None = None) -> str:
    """The registrable domain: public suffix plus one label (example.co.uk)."""
    host = (host or "").lower().rstrip(".")
    labels = host.split(".")
    suffix = public_suffix(host, suffixes).split(".")
    if len(labels) <= len(suffix):
        return host
    return ".".join(labels[-(len(suffix) + 1):])


def subdomain_base(url_or_host: str, mode: str = "auto",
                  suffixes: set[str] | None = None) -> str:
    """Pick the host to enumerate from a target URL.

    ``auto`` (the default) strips a leading ``www.`` and, when the name sits
    directly on a multi-label public suffix, widens to the registrable domain:
    ``www.example.com`` -> ``example.com`` and ``shop.example.co.uk`` ->
    ``example.co.uk``, while ``shop.example.com`` stays ``shop.example.com``
    (a plain ``.com`` does not imply that ``example.com`` owns the shop).

    ``host`` uses the target host verbatim; ``registrable`` always widens to
    the public-suffix-plus-one name. ``suffixes`` replaces the built-in table
    with a loaded Public Suffix List.
    """
    parts = urllib.parse.urlsplit(url_or_host)
    host = (parts.hostname or url_or_host).lower().rstrip(".")
    if not host or mode == "host":
        return host
    if mode not in ("auto", "registrable"):
        raise ValueError(f"unknown subdomain base mode: {mode!r}")
    registrable = registrable_domain(host, suffixes)
    if mode == "registrable":
        return registrable
    if host.startswith("www.") and host.count(".") >= 2:
        return host[4:]
    if "." in public_suffix(host, suffixes) and host != registrable:
        parent = ".".join(host.split(".")[1:])
        if parent == registrable:
            return parent
    return host


def _names_from(entries, domain: str) -> list[str]:
    """Normalise candidate names, keep only in-scope hosts, drop wildcards."""
    names: set[str] = set()
    for entry in entries:
        name = str(entry).strip().lower().rstrip(".")
        if name.startswith("*."):
            name = name[2:]
        if not name or "*" in name or " " in name:
            continue
        if is_under(name, domain):
            names.add(name)
    names.discard(domain)
    return sorted(names)


def parse_ct_json(payload: str, domain: str) -> list[str]:
    """Extract in-scope hostnames from a crt.sh JSON response.

    Certificate entries carry names in name_value (newline separated) and
    common_name. Wildcards are unwrapped to their parent name.
    """
    try:
        rows = json.loads(payload)
    except (ValueError, TypeError):
        return []
    if not isinstance(rows, list):
        return []
    raw: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        for key in ("name_value", "common_name"):
            value = row.get(key)
            if isinstance(value, str):
                raw.extend(value.splitlines())
    return _names_from(raw, domain)


def parse_certspotter_json(payload: str, domain: str) -> list[str]:
    """Extract in-scope hostnames from a certspotter issuances response."""
    try:
        rows = json.loads(payload)
    except (ValueError, TypeError):
        return []
    if not isinstance(rows, list):
        return []
    raw: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        names = row.get("dns_names")
        if isinstance(names, list):
            raw.extend(str(n) for n in names)
    return _names_from(raw, domain)


def parse_hackertarget_text(payload: str, domain: str) -> list[str]:
    """Extract in-scope hostnames from hackertarget's ``host,ip`` CSV."""
    if "API count exceeded" in payload or payload.lstrip().startswith("error"):
        return []
    raw = [line.split(",", 1)[0] for line in payload.splitlines() if "," in line]
    return _names_from(raw, domain)


# name -> (url template, parser, response byte cap). Order is the order they are
# asked; a provider that fails is skipped and the next one is tried.
CT_PROVIDERS: dict[str, tuple[str, Callable[[str, str], list[str]], int]] = {
    "crt.sh": (
        "https://crt.sh/?q={q}&output=json&exclude=expired",
        parse_ct_json, 12_000_000,
    ),
    "certspotter": (
        "https://api.certspotter.com/v1/issuances?domain={domain}"
        "&include_subdomains=true&expand=dns_names",
        parse_certspotter_json, 4_000_000,
    ),
    "hackertarget": (
        "https://api.hackertarget.com/hostsearch/?q={domain}",
        parse_hackertarget_text, 1_000_000,
    ),
}


def _default_resolve(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None)
    return sorted({str(info[4][0]) for info in infos})


def resolve_hosts(hosts: list[str], resolve_func: Callable[[str], list[str]] | None = None,
                  concurrency: int = 10, timeout: float = 15.0) -> dict[str, list[str]]:
    """Resolve hosts concurrently. Unresolvable names simply do not appear."""
    resolve = resolve_func or _default_resolve
    live: dict[str, list[str]] = {}
    if not hosts:
        return live
    pool = ThreadPoolExecutor(max_workers=max(1, min(concurrency, len(hosts))))
    futures = {pool.submit(resolve, host): host for host in hosts}
    done, pending = wait(futures, timeout=timeout)
    for fut in done:
        try:
            addresses = fut.result()
        except Exception:
            continue
        if addresses:
            live[futures[fut]] = addresses
    for fut in pending:
        fut.cancel()
    pool.shutdown(wait=False, cancel_futures=True)
    return live


def detect_wildcard(domain: str, resolve_func: Callable[[str], list[str]] | None = None,
                    attempts: int = 2) -> list[str]:
    """Return addresses for a random name under domain, or [] if none resolve."""
    resolve = resolve_func or _default_resolve
    suffix = "." + domain
    for _ in range(max(1, attempts)):
        probe = "".join(random.choices(string.ascii_lowercase + string.digits, k=16)) + suffix
        try:
            addresses = resolve(probe)
        except Exception:
            continue
        if addresses:
            return sorted(set(addresses))
    return []


def brute_hosts(domain: str, words: list[str],
                resolve_func: Callable[[str], list[str]] | None = None,
                concurrency: int = 10, timeout: float = 20.0) -> list[str]:
    """Resolve word.domain for each word, bounded by a wall-clock timeout."""
    resolve = resolve_func or _default_resolve
    candidates = [f"{word}.{domain}" for word in words]
    found: list[str] = []
    pool = ThreadPoolExecutor(max_workers=max(1, concurrency))
    futures = {pool.submit(resolve, host): host for host in candidates}
    done, pending = wait(futures, timeout=timeout)
    for fut in done:
        try:
            if fut.result():
                found.append(futures[fut])
        except Exception:
            continue
    for fut in pending:
        fut.cancel()
    pool.shutdown(wait=False, cancel_futures=True)
    return sorted(found)


@dataclass
class Discovery:
    domain: str
    hosts: list[str] = field(default_factory=list)
    by_source: dict[str, int] = field(default_factory=dict)
    # Per-certificate-transparency-provider yield, including providers that
    # answered with nothing. Kept separate from by_source so an empty provider
    # is visible instead of looking like it was never asked.
    providers: dict[str, int] = field(default_factory=dict)
    wildcard: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    skipped: str = ""

    def describe(self) -> str:
        if self.skipped:
            return f"subdomains of {self.domain}: skipped ({self.skipped})"
        parts = ", ".join(f"{k}={v}" for k, v in sorted(self.by_source.items()) if v)
        detail = f" ({parts})" if parts else ""
        wildcard = " wildcard DNS detected" if self.wildcard else ""
        return (f"subdomains of {self.domain}: {len(self.hosts)} host(s)"
                f"{detail}{wildcard}")


def discover(domain: str,
             *,
             fetch: Callable[[str], str] | None = None,
             resolve_func: Callable[[str], list[str]] | None = None,
             log=None,
             brute: bool = True,
             wordlist: list[str] | None = None,
             max_hosts: int = 25,
             concurrency: int = 10,
             min_hosts_before_brute: int = 5,
             providers: tuple[str, ...] | None = None) -> Discovery:
    """Enumerate subdomains of domain.

    fetch() must return the response body for a URL; when it is None the
    certificate-transparency step is skipped. Providers are asked in order and
    a failing one is skipped, so a single unavailable service does not empty
    the result. Resolution failures are recorded in Discovery.errors rather
    than raised.
    """
    chosen = tuple(providers) if providers is not None else tuple(CT_PROVIDERS)
    try:
        base = normalize_domain(domain)
    except DiscoveryError as exc:
        return Discovery(domain=domain, errors=[str(exc)], skipped=str(exc))
    result = Discovery(domain=base)
    if is_ip(base) or base == "localhost" or "." not in base:
        result.skipped = "not a registrable domain"
        if log is not None:
            log.warn(result.describe())
        return result

    resolve = resolve_func or _default_resolve
    result.wildcard = detect_wildcard(base, resolve)
    if result.wildcard:
        msg = (f"wildcard DNS (*.{base} resolves to {', '.join(result.wildcard[:3])}); "
               "brute force skipped because every name would look live")
        result.errors.append(msg)

    names: set[str] = set()
    if fetch is not None:
        for name in chosen:
            template, parser, cap = CT_PROVIDERS[name]
            # Once the host cap is already satisfied, another provider cannot
            # change the outcome; stop instead of spending a second request.
            if len(names) >= max_hosts:
                break
            url = template.format(domain=base,
                                  q=urllib.parse.quote("%." + base, safe=""))
            try:
                body = fetch(url)
            except Exception as exc:
                result.errors.append(f"{name} query failed: {str(exc)[:120]}")
                continue
            found = parser(body[:cap], base)
            result.providers[name] = len(found)
            names.update(found)
        if result.providers:
            result.by_source["ct"] = len(names)

    if brute and not result.wildcard:
        if len(names) < min_hosts_before_brute:
            words = wordlist if wordlist is not None else WORDLIST
            found = brute_hosts(base, words, resolve, concurrency=concurrency)
            new = [h for h in found if h not in names]
            result.by_source["dns"] = len(new)
            names.update(new)
        else:
            result.by_source["dns"] = 0

    # CT logs keep dead hosts for years; only crawl names that resolve now.
    unresolved = resolve_hosts(sorted(names), resolve, concurrency=concurrency)
    missing = len(names) - len(unresolved)
    if missing > 0:
        result.errors.append(f"{missing} discovered host(s) did not resolve and were dropped")
    hosts = sorted(unresolved)
    if len(hosts) > max_hosts:
        result.errors.append(f"host cap reached: keeping {max_hosts} of {len(hosts)}")
        hosts = hosts[:max_hosts]
    result.hosts = hosts
    if log is not None:
        if result.hosts:
            log.info(result.describe())
        elif result.skipped:
            log.warn(result.describe())
        else:
            log.warn("no subdomains discovered (every certificate source was "
                     "empty or unavailable; brute force found nothing)")
    return result
