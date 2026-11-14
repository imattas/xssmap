"""xssmap command line interface."""
from __future__ import annotations

import argparse
import datetime as dt
import os
import random
import re
import shlex
import sys
import time
import urllib.parse

from . import fuzz as fuzzmod
from . import jslib as jslibmod
from . import params as paramdisc
from . import report as rp
from . import sarif
from . import state as stateio
from . import subdomains as subs
from . import tech as techmod
from . import waf as wafmod
from .browser import BrowserVerifier
from .callback import CallbackListener
from .crawler import Crawler, Scope, normalize_url
from .domscan import DomScanner
from .exploit import ExploitProver
from .htmlparse import Form, parse_qs_ordered
from .net import HTTP, Throttle
from .payloads import build_payload_set
from .report import VERSION, Console
from .scanner import (
    CookiePoint,
    HeaderPoint,
    Scanner,
    points_from_form,
    points_from_json,
    points_from_url,
)
from .session import CookieJar, Session, is_login_form
from .stored import StoredScanner

# Discovery workers used when the user does not pass --crawl-threads.
DEFAULT_CRAWL_THREADS = 16

EPILOG = """examples:
  xssmap -u "https://target.tld/search?q=test"
  xssmap -u https://target.tld --crawl --depth 3 --max-pages 200
  xssmap --domain example.com --autonomous
  xssmap --domain example.com --subdomains --max-hosts 30 --depth 3
  xssmap -u https://target.tld/page --data "name=x&comment=y" --method POST
  xssmap -u https://target.tld/api/login --json-body '{"user":"a","pass":"b"}'
  xssmap -u https://target.tld --cookie "sid=abc; theme=dark" --headers-points
  xssmap -u https://target.tld --level 3 --risk 3 --browser --html report.html
  xssmap -u https://target.tld/search?q=1 --browser --verify --callback 9000
  xssmap -u https://target.tld -p q --param "INJECT_HERE" --proxy http://127.0.0.1:8080

testing notes:
  --level 1  classic HTML/attribute contexts
  --level 2  adds JS string/code, comments, RCDATA, forms   (default)
  --level 3  adds polyglots, header and cookie points, hidden fields
  --risk  1  non-interactive payloads only
  --risk  2  adds autofocus/onfocus handlers                (default)
  --risk  3  adds interaction-required payloads and variants

  POST forms are only submitted with --forms (they can create records).
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="xssmap",
        description="xssmap - context-aware cross-site scripting scanner with a crawler",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    tgt = p.add_argument_group("target")
    tgt.add_argument("-u", "--url", help="target URL")
    tgt.add_argument("--domain", metavar="DOMAIN",
                     help="scan a whole domain: picks https (falling back to http) and "
                          "crawls every host it finds; implies --subdomains")
    tgt.add_argument("-m", "--urls", metavar="FILE",
                     help="file with one target URL per line")
    tgt.add_argument("--method", default=None, help="HTTP method for the supplied body (default POST)")
    tgt.add_argument("--data", "--body", dest="data", help="request body, e.g. 'a=1&b=2'")
    tgt.add_argument("--json-body", dest="json_body", help="JSON request body")
    tgt.add_argument("-H", "--header", action="append", default=[], metavar="'K: V'",
                     help="extra header (repeatable)")
    tgt.add_argument("--cookie", help="Cookie header value, e.g. 'sid=abc; theme=dark'")
    tgt.add_argument("-A", "--user-agent", help="User-Agent string")
    tgt.add_argument("--random-agent", action="store_true", help="pick a random browser User-Agent")
    tgt.add_argument("-p", "--param", help="comma separated list of parameters to test")
    tgt.add_argument("--param-value", help="value to use for the baseline request")

    auto = p.add_argument_group("autonomy")
    auto.add_argument("--autonomous", action="store_true",
                      help="one-flag sweep: subdomain discovery, deep crawl, forms, stored, "
                           "DOM, browser confirmation, headers and screenshots "
                           "(explicit flags always win)")
    auto.add_argument("--max-minutes", type=float, default=0.0, metavar="N",
                      help="wall-clock budget in minutes, enforced between phases and "
                           "inside the scan/stored loops (0 = unlimited; --autonomous 30)")
    auto.add_argument("--fast", action="store_true",
                      help="triage preset: depth 1, 60 pages, 300 points, no JS mining, "
                           "no browser stages (explicit flags always win)")

    crawl = p.add_argument_group("crawling")
    crawl.add_argument("--crawl", dest="crawl", action="store_true", default=None,
                       help="force crawling (default when -u is given)")
    crawl.add_argument("--no-crawl", dest="no_crawl", action="store_true",
                       help="do not crawl, only test the supplied URL")
    crawl.add_argument("--crawl-depth", "--depth", dest="crawl_depth", type=int, default=2,
                       metavar="N", help="link depth (default 2)")
    crawl.add_argument("--max-pages", type=int, default=150, help="page budget (default 150)")
    crawl.add_argument("--scope", choices=["host", "subdomain", "any"], default="host",
                       help="crawl scope (default host); --subdomains widens it to subdomain")
    crawl.add_argument("--subdomains", action="store_true",
                       help="discover subdomains (certificate transparency + DNS) and crawl "
                            "them too")
    crawl.add_argument("--no-subdomain-brute", dest="subdomain_brute", action="store_false",
                       default=True,
                       help="passive discovery only: skip the DNS wordlist sweep")
    crawl.add_argument("--subdomain-wordlist", metavar="FILE",
                       help="extra DNS names to try, one label per line (adds to the "
                            "built-in list)")
    crawl.add_argument("--subdomain-base", choices=["auto", "host", "registrable"],
                       default="auto",
                       help="how the enumeration base is derived (default auto): auto strips "
                            "www. and widens registrable names under multi-label suffixes "
                            "(shop.example.co.uk -> example.co.uk); host uses the target "
                            "host verbatim; registrable always widens (PSL + 1 label)")
    crawl.add_argument("--public-suffix-list", metavar="FILE",
                       help="Public Suffix List file used by --subdomain-base (supports "
                            "*. and ! rules); replaces the small built-in table")
    crawl.add_argument("--max-hosts", type=int, default=25, metavar="N",
                       help="cap on discovered hosts crawled per target (default 25)")
    crawl.add_argument("--exclude", action="append", default=[], metavar="REGEX",
                       help="skip URLs matching this regex (repeatable)")
    crawl.add_argument("--include", action="append", default=[], metavar="REGEX",
                       help="only crawl URLs matching this regex (repeatable)")
    crawl.add_argument("--no-js", action="store_true", help="do not mine JS for endpoints")
    crawl.add_argument("--robots", action="store_true", help="honour robots.txt disallow rules")
    crawl.add_argument("--common-paths", action="store_true",
                       help="probe a small list of conventional parameterised paths")

    scan = p.add_argument_group("scanning")
    scan.add_argument("--level", type=int, choices=[1, 2, 3], default=2,
                      help="payload level 1-3 (default 2)")
    scan.add_argument("--risk", type=int, choices=[1, 2, 3], default=2,
                      help="payload risk 1-3 (default 2)")
    scan.add_argument("--forms", action="store_true",
                      help="also submit POST forms (can create records)")
    scan.add_argument("--no-forms", dest="no_forms", action="store_true",
                      help="never submit POST forms (overrides --autonomous)")
    scan.add_argument("--headers-points", action="store_true",
                      help="test User-Agent/Referer/X-Forwarded-Host reflection")
    scan.add_argument("--threads", type=int, default=10,
                      help="payload-testing workers (default 10)")
    scan.add_argument("--crawl-threads", type=int, default=0, metavar="N",
                      help="discovery workers for the crawl (default: 16, or --threads "
                           "if larger)")
    scan.add_argument("--delay", type=float, default=0.0, help="minimum delay between requests")
    scan.add_argument("--timeout", type=float, default=15.0, help="per-request timeout")
    scan.add_argument("--retries", type=int, default=2, help="retries on transport errors")
    scan.add_argument("--proxy", help="http://host:port or socks5://host:port")
    scan.add_argument("--insecure", action="store_true", help="do not verify TLS certificates")
    scan.add_argument("--max-points", type=int, default=1500, help="cap on injection points")
    scan.add_argument("--state", metavar="FILE", default=None,
                      help="resume file: skip injection points already completed and "
                           "merge the findings recorded there (written atomically)")
    scan.add_argument("--no-profile", dest="no_profile", action="store_true",
                      help="skip filter-fingerprinting probes (fewer requests, no mutation bypass)")
    scan.add_argument("--mutations", type=int, default=3, metavar="N",
                      help="filter-bypass mutations tried per payload (default 3, 0 disables)")

    ev = p.add_argument_group("evasion and discovery")
    ev.add_argument("--waf", dest="waf", action="store_true", default=True,
                    help="fingerprint the WAF in front of the target and route payloads "
                         "around it (default on; --no-waf disables)")
    ev.add_argument("--no-waf", dest="no_waf", action="store_true",
                    help="skip WAF fingerprinting and evasion")
    ev.add_argument("--evade", dest="evade", action="store_true", default=True,
                    help="use vendor-specific obfuscation when a blocking WAF is detected "
                         "(default on)")
    ev.add_argument("--no-evade", dest="no_evade", action="store_true",
                    help="detect the WAF but keep payloads unchanged")
    ev.add_argument("--brute", action="store_true",
                    help="character-level filter brute force: when every crafted payload "
                         "fails on a reflecting point, map the characters that survive "
                         "and synthesise a payload from them (bounded by --brute-budget)")
    ev.add_argument("--brute-budget", type=int, default=40, metavar="N",
                    help="request budget for --brute across the whole scan (default 40)")
    ev.add_argument("--evasion-budget", type=int, default=240, metavar="N",
                    help="cap on WAF-evasion variants added across the whole scan "
                         "(default 240; every point gets its own share, so one hostile "
                         "point cannot starve the rest)")
    ev.add_argument("--osv", action="store_true",
                    help="ask osv.dev for advisories on every identified library version "
                         "(off by default: it is an outbound call to a third party, "
                         "capped at 12 lookups)")
    ev.add_argument("--discover-params", action="store_true",
                    help="probe undocumented parameter names on each target and test the "
                         "ones that change the response")
    ev.add_argument("--fuzz", action="store_true",
                    help="fuzz parameters for reflection/filter behaviour and report "
                         "raw, encoded, stripped and template-evaluated results")
    ev.add_argument("--fuzz-budget", type=int, default=200, metavar="N",
                    help="request budget for --fuzz (default 200)")
    ev.add_argument("--js-libs", dest="js_libs", action="store_true", default=True,
                    help="fingerprint outdated JavaScript libraries found while crawling "
                         "and list the CVEs they are known for (default on)")
    ev.add_argument("--no-js-libs", dest="no_js_libs", action="store_true",
                    help="skip JavaScript library fingerprinting")

    br = p.add_argument_group("verification")
    br.add_argument("--browser", dest="browser", action="store_true", default=None,
                    help="confirm execution in a headless Chromium (default: auto)")
    br.add_argument("--no-browser", dest="no_browser", action="store_true",
                    help="disable headless browser confirmation")
    br.add_argument("--dom", dest="dom", action="store_true", default=None,
                    help="force DOM XSS analysis (requires a browser)")
    br.add_argument("--no-dom", dest="no_dom", action="store_true",
                    help="skip DOM XSS analysis")
    br.add_argument("--dom-flows", type=int, default=15, metavar="N",
                    help="cap on DOM flows proven in the browser (default 15)")
    br.add_argument("--stored", dest="stored", action="store_true", default=False,
                    help="plant payloads in forms and prove stored XSS (writes data)")
    br.add_argument("--no-stored", dest="no_stored", action="store_true",
                    help="never plant stored payloads (overrides --autonomous)")
    br.add_argument("--stored-max-forms", type=int, default=20, metavar="N",
                    help="cap on forms used for stored-XSS planting (default 20)")
    br.add_argument("--stored-json", action="append", default=[], metavar="URL",
                    help="JSON write endpoint to plant stored payloads in (repeatable)")
    br.add_argument("--stored-json-field", default="comment", metavar="NAME",
                    help="JSON property that carries the payload (default comment)")
    br.add_argument("--viewer-url", action="append", default=[], metavar="URL",
                    help="page that renders stored content, e.g. a moderation queue or "
                         "admin inbox (repeatable; needed to observe blind stored XSS)")
    br.add_argument("--callback", nargs="?", const=0, type=int, default=None,
                    metavar="PORT",
                    help="start a loopback callback listener for blind XSS proof")
    br.add_argument("--callback-bind", default="127.0.0.1", metavar="ADDR",
                    help="address the callback listener binds to (default 127.0.0.1; use "
                         "0.0.0.0 to accept beacons from another host on the network)")
    br.add_argument("--callback-url", default="", metavar="URL",
                    help="public URL to embed in beacons when the listener is reached "
                         "through a tunnel or port-forward, e.g. https://abc.ngrok.app")
    br.add_argument("--capture-cookies", dest="capture_cookies", action="store_true",
                    default=False,
                    help="let the callback beacon send document.cookie (off by default: "
                         "an OOB hit already proves execution)")
    br.add_argument("--headless", choices=["new", "old"], default="new",
                    help="headless mode for Chrome (default new)")
    br.add_argument("--verify", dest="verify", action="store_true", default=False,
                    help="exploit stage: replay each finding with a weaponised payload and "
                         "measure what the script can reach (cookies, anti-CSRF token, "
                         "same-origin reads, callback) instead of only proving execution")
    br.add_argument("--no-verify", dest="no_verify", action="store_true",
                    help="skip the exploit stage (overrides --autonomous)")
    br.add_argument("--verify-max", type=int, default=10, metavar="N",
                    help="cap on findings replayed by --verify (default 10)")

    auth = p.add_argument_group("authentication")
    auth.add_argument("--login-url", metavar="URL",
                        help="sign in through this page's form before scanning")
    auth.add_argument("--login-user", metavar="USER", help="username for --login-url")
    auth.add_argument("--login-pass", metavar="PASS", help="password for --login-url")
    auth.add_argument("--login-user-field", default="", metavar="NAME",
                      help="username field name (auto-detected by default)")
    auth.add_argument("--login-pass-field", default="", metavar="NAME",
                      help="password field name (auto-detected by default)")
    auth.add_argument("--login-data", action="append", default=[], metavar="K=V",
                      help="extra login form field, e.g. csrf_token=... or remember=1")
    auth.add_argument("--login-check", metavar="URL",
                      help="URL that must stop redirecting to login once authenticated")
    auth.add_argument("--cookie-jar", metavar="FILE",
                      help="preload cookies from a Netscape cookies.txt file")
    auth.add_argument("--save-cookies", metavar="FILE",
                      help="write the final cookie jar (sensitive: live session secrets)")
    auth.add_argument("--no-csrf-refresh", dest="csrf_refresh", action="store_false",
                      default=True,
                      help="do not re-read anti-CSRF tokens before each submission")

    out = p.add_argument_group("output")
    out.add_argument("-o", "--output", help="write JSON results to this file")
    out.add_argument("--html", help="write an HTML report to this file")
    out.add_argument("--markdown", "--md", dest="markdown", help="write a Markdown report")
    out.add_argument("--screenshots", action="store_true",
                     help="save a PNG screenshot for every browser-confirmed finding")
    out.add_argument("--output-dir", default="xssmap-out",
                     help="directory for default report files (default xssmap-out)")
    out.add_argument("--sarif", help="write a SARIF 2.1.0 report (CI integrations)")
    out.add_argument("--evidence", dest="evidence_dir", metavar="DIR",
                     help="write one evidence file per finding into DIR")
    out.add_argument("--quiet", "-q", action="store_true", help="only findings")
    out.add_argument("--verbose", "-v", action="store_true", help="show every request")
    out.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    out.add_argument("--fail-on-findings", action="store_true",
                     help="exit with status 1 when something is found (CI mode)")
    out.add_argument("--list-payloads", action="store_true", help="print the payload catalogue")
    out.add_argument("--version", action="version", version=f"xssmap {VERSION}")
    return p


# What --autonomous turns on. Values are only applied when the user did not
# pass the flag themselves, so "--autonomous --max-pages 50" still honours 50.
AUTONOMOUS_DEFAULTS: dict[str, object] = {
    "crawl_depth": 3,
    "max_pages": 400,
    "max_points": 3000,
    "max_minutes": 30.0,
    "subdomains": True,
    "common_paths": True,
    "forms": True,
    "stored": True,
    "headers_points": True,
    "dom": True,
    "browser": True,
    "verify": True,
    "screenshots": True,
    "waf": True,
    "evade": True,
    "brute": True,
    "discover_params": True,
    "js_libs": True,
}

# dest -> the flag that switches the same feature off. An explicit off switch
# must survive the preset.
_NEGATED = {
    "browser": "no_browser",
    "verify": "no_verify",
    "dom": "no_dom",
    "crawl": "no_crawl",
    "forms": "no_forms",
    "stored": "no_stored",
    "waf": "no_waf",
    "evade": "no_evade",
    "js_libs": "no_js_libs",
}


def explicit_dests(parser: argparse.ArgumentParser, argv: list[str]) -> set[str]:
    """Return the option dests the user actually typed.

    argparse does not record whether a value came from the command line or a
    default, so the preset reads the argument vector instead.
    """
    known: dict[str, str] = {}
    for action in parser._actions:
        for opt in action.option_strings:
            known[opt] = action.dest
    explicit: set[str] = set()
    for token in argv:
        if not token.startswith("-"):
            continue
        dest = known.get(token.split("=", 1)[0])
        if dest:
            explicit.add(dest)
    return explicit


def option_flags(parser: argparse.ArgumentParser) -> dict[str, str]:
    """Map option dests back to the flag a user would recognise."""
    return {action.dest: action.option_strings[0]
            for action in parser._actions if action.option_strings}


# What --fast turns on: the cheap path to a first answer. A shallow crawl and a
# capped point budget still find reflected XSS; the expensive stages (JS bundle
# mining, DOM and browser runs) are what a triage pass can afford to skip.
FAST_DEFAULTS: dict[str, object] = {
    "crawl_depth": 1,
    "max_pages": 60,
    "max_points": 300,
    "no_js": True,
    "dom": False,
    "browser": False,
}


def apply_preset(args: argparse.Namespace, explicit: set[str],
                 defaults: dict[str, object]) -> list[str]:
    """Apply a preset, keeping every choice the user typed themselves."""
    applied: list[str] = []
    for dest, value in defaults.items():
        if dest in explicit:
            continue
        off = _NEGATED.get(dest)
        if off and off in explicit:
            continue
        if getattr(args, dest, None) == value:
            continue
        setattr(args, dest, value)
        applied.append(dest)
    return applied


def apply_autonomous(args: argparse.Namespace, explicit: set[str]) -> list[str]:
    """Apply the autonomous defaults, keeping every explicit choice."""
    return apply_preset(args, explicit, AUTONOMOUS_DEFAULTS)


def finalize_args(args: argparse.Namespace) -> None:
    """Collapse paired flags into one truth for the rest of the program."""
    if getattr(args, "no_forms", False):
        args.forms = False
    if getattr(args, "no_stored", False):
        args.stored = False
    if getattr(args, "no_verify", False):
        args.verify = False
    if getattr(args, "no_waf", False):
        args.waf = False
    if getattr(args, "no_evade", False):
        args.evade = False
    if getattr(args, "no_js_libs", False):
        args.js_libs = False
    if args.no_crawl:
        args.crawl = False
    elif args.crawl is None:
        args.crawl = True
    if getattr(args, "crawl_threads", 0) <= 0:
        # Discovery only fetches the site's own links, and the shared throttle
        # already backs off on 429/503, so it does not need to run at the same
        # narrow width as payload testing. Measured on a 4096-page lab target:
        # 5 workers 46 s, 16 workers 15 s, 32 workers 7 s.
        args.crawl_threads = max(DEFAULT_CRAWL_THREADS, args.threads)


def read_wordlist(path: str) -> list[str]:
    """Read extra DNS labels, one per line. Blank lines and # comments skipped."""
    words: list[str] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            word = line.strip().lower().strip(".")
            if not word or word.startswith("#"):
                continue
            if not subs.LABEL_RE.match(word):
                continue
            if word not in words:
                words.append(word)
    return words


def probe_base(http: HTTP, host: str, port: int | None, headers,
               log: Console, announce: bool = True) -> str | None:
    """Find a working scheme for a bare host, https first."""
    netloc = f"{host}:{port}" if port else host
    for scheme in ("https", "http"):
        url = f"{scheme}://{netloc}"
        try:
            resp = http.get(url + "/", headers=headers)
        except Exception as exc:
            (log.info if announce else log.debug)(f"  {url}: {str(exc)[:80]}")
            continue
        (log.ok if announce else log.debug)(f"  {url}: HTTP {resp.status}")
        return url
    return None


def domain_host(value: str) -> tuple[str, int | None]:
    """Split --domain into (host, port), rejecting paths and queries."""
    host = subs.normalize_domain(value)
    parts = urllib.parse.urlsplit(value if "://" in value else "//" + value)
    try:
        port = parts.port
    except ValueError as exc:
        raise subs.DiscoveryError(f"invalid port in {value!r}") from exc
    return host, port


def ct_fetcher(http: HTTP, headers):
    """Wrap the client so certificate-source failures raise instead of returning ""."""
    def fetch(url: str) -> str:
        resp = http.get(url, headers=headers)
        if resp.status >= 400:
            host = urllib.parse.urlsplit(url).hostname or "certificate source"
            raise RuntimeError(f"{host} returned HTTP {resp.status}")
        return resp.text or ""
    return fetch


UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
]


def parse_headers(raw_headers: list[str], cookie: str | None, ua: str | None,
                  random_agent: bool) -> list[tuple[str, str]]:
    headers: list[tuple[str, str]] = []
    for raw in raw_headers:
        if ":" not in raw:
            raise SystemExit(f"[-] bad header (expected 'Name: value'): {raw}")
        name, value = raw.split(":", 1)
        headers.append((name.strip(), value.strip()))
    if cookie:
        # --cookie seeds the cookie jar (host scoped, refreshed by Set-Cookie)
        # instead of pinning one stale header onto every request.
        headers = [(k, v) for k, v in headers if k.lower() != "cookie"]
    if ua:
        headers.append(("User-Agent", ua))
    elif random_agent:
        headers.append(("User-Agent", random.choice(UA_POOL)))
    return headers


def load_targets(args) -> list[str]:
    targets: list[str] = []
    if args.url:
        targets.append(args.url)
    if args.urls:
        with open(args.urls, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)
    out = []
    for t in targets:
        if not re.match(r"^https?://", t, re.I):
            t = "https://" + t
        out.append(normalize_url(t) if "?" in t else t.rstrip("/"))
    return out


def csrf_fetcher_factory(http: HTTP, headers, log):
    def fetch(url: str) -> dict[str, str]:
        resp = http.get(url, headers=headers)
        if not resp.is_html:
            return {}
        from .htmlparse import parse_page
        page = parse_page(resp.url, resp.text)
        tokens = {}
        for form in page.forms:
            for name, value, typ in form.params:
                if typ == "hidden" and re.search(r"(csrf|token|nonce|authenticity|_wpnonce)", name, re.I):
                    tokens[name] = value
        if not tokens:
            m = re.search(r"""(?i)name=["'](csrf[^"']*|_token|authenticity_token)["']\s+value=["']([^"']+)""",
                          resp.text)
            if m:
                tokens[m.group(1)] = m.group(2)
        return tokens
    return fetch


def print_payload_catalogue(log: Console):
    payloads = build_payload_set()
    log.banner(f"payload catalogue ({len(payloads)} payloads)")
    by_ctx: dict[str, list] = {}
    for p in payloads:
        by_ctx.setdefault(p.context, []).append(p)
    for ctx in sorted(by_ctx):
        print(f"\n  {ctx}")
        for p in by_ctx[ctx]:
            flags = []
            if p.interaction:
                flags.append("interaction")
            if p.danger != "low":
                flags.append(p.danger)
            print(f"    - {p.name:<22} {p.template}")
            if flags:
                print(f"      {', '.join(flags)}")
    print(f"\n  contexts: {', '.join(sorted(by_ctx))}\n")


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    colour = not args.no_color and (sys.stdout.isatty() or os.name == "nt")
    log = Console(quiet=args.quiet, color=colour, verbose=args.verbose)
    explicit = explicit_dests(parser, list(sys.argv[1:] if argv is None else argv))

    if args.list_payloads:
        print_payload_catalogue(log)
        return 0

    if args.fast:
        applied = apply_preset(args, explicit, FAST_DEFAULTS)
        if applied:
            log.action("fast: " + ", ".join(
                f"{dest}={FAST_DEFAULTS[dest]}" for dest in applied))
    if args.autonomous:
        applied = apply_autonomous(args, explicit)
        if applied:
            log.action("autonomous: enabled " + ", ".join(
                f"{dest}={AUTONOMOUS_DEFAULTS[dest]}" for dest in applied))
        flags = option_flags(parser)
        kept = (explicit & set(AUTONOMOUS_DEFAULTS)) | {
            off for off in _NEGATED.values() if off in explicit}
        if kept:
            log.info("autonomous: kept your explicit " + ", ".join(
                sorted(flags.get(dest, dest) for dest in kept)))
        if not args.no_stored and not args.no_forms:
            log.warn("autonomous submits forms and plants stored payloads (writes data); "
                     "pass --no-forms / --no-stored to keep the target read-only")
    finalize_args(args)

    if args.domain and (args.url or args.urls):
        log.error("use either --domain or -u/-m, not both")
        return 2

    headers = parse_headers(args.header, args.cookie, args.user_agent, args.random_agent)
    throttle = Throttle(delay=args.delay, max_workers=args.threads)
    http = HTTP(
        timeout=args.timeout, retries=args.retries, proxy=args.proxy,
        verify=not args.insecure, user_agent=args.user_agent or "xssmap/" + VERSION,
        throttle=throttle, debug=args.verbose,
    )
    if args.user_agent or args.random_agent:
        http.extra_headers = {}

    if args.domain:
        try:
            host, port = domain_host(args.domain)
        except (subs.DiscoveryError, ValueError) as exc:
            log.error(f"--domain: {exc}")
            return 2
        base = probe_base(http, host, port, headers, log)
        if not base:
            log.error(f"--domain {args.domain}: no HTTP endpoint answered on {host}")
            return 2
        targets = [base]
        if args.crawl:
            args.subdomains = True
        else:
            log.warn("--domain without crawling only tests the root URL; drop --no-crawl "
                     "to sweep the domain")
    else:
        targets = load_targets(args)
    if not targets:
        log.error("no target: use -u URL, --domain DOMAIN or -m FILE")
        return 2

    extra_words: list[str] | None = None
    if args.subdomain_wordlist:
        try:
            extra_words = read_wordlist(args.subdomain_wordlist)
        except OSError as exc:
            log.error(f"could not read --subdomain-wordlist: {exc}")
            return 2
        extra_words = list(dict.fromkeys(subs.WORDLIST + extra_words))
        log.info(f"subdomain wordlist: {len(extra_words)} label(s) after merging "
                 f"the built-in list")

    suffix_table = None
    if args.public_suffix_list:
        try:
            suffix_table = subs.load_suffix_file(args.public_suffix_list)
        except subs.DiscoveryError as exc:
            log.error(str(exc))
            return 2
        log.info(f"public suffix list: {len(suffix_table)} rule(s) loaded")

    if not args.quiet:
        log.splash(VERSION, f"{len(targets)} target(s)  |  level {args.level}  "
                            f"risk {args.risk}")
    browser_enabled = (not args.no_browser) if args.browser is None else bool(args.browser)
    if args.no_browser:
        browser_enabled = False
    browser = BrowserVerifier(enabled=browser_enabled, log=log, headless=args.headless,
                             proxy=args.proxy)

    # ---- authenticated session -------------------------------------
    jar = CookieJar()
    for target in targets:
        if args.cookie:
            jar.add_raw(target, args.cookie)
    http.jar = jar
    login_summary = ""
    if args.cookie_jar:
        try:
            seeded = jar.load_netscape(args.cookie_jar)
            log.info(f"cookie jar: {seeded} cookie(s) loaded from {args.cookie_jar}")
        except OSError as exc:
            log.error(f"could not read --cookie-jar {args.cookie_jar}: {exc}")
            return 2
    session = None
    if args.login_url:
        if not (args.login_user and args.login_pass):
            log.error("--login-url also needs --login-user and --login-pass")
            return 2
        extra = dict(item.split("=", 1) for item in args.login_data if "=" in item)
        session = Session(http, log=log)
        log.action(f"signing in at {args.login_url}")
        result = session.login(args.login_url, args.login_user, args.login_pass,
                               user_field=args.login_user_field,
                               pass_field=args.login_pass_field, extra=extra)
        login_summary = result.describe()
        if result.ok:
            log.ok(login_summary)
            log.info(f"cookie jar: {jar.describe()}")
            browser.set_cookies(jar.cdp_cookies())
            if args.login_check:
                try:
                    check = http.get(args.login_check, allow_redirects=True)
                    from .htmlparse import parse_page as _parse_page
                    forms_there = _parse_page(check.url, check.text or "").forms
                    still_login = any(is_login_form(f) for f in forms_there)
                except Exception as exc:
                    log.warn(f"--login-check could not be fetched: {str(exc)[:120]}")
                else:
                    if still_login:
                        log.warn(f"--login-check {check.url} still shows a login form; "
                                 "the session may not be valid")
                        result.ok = False
                        result.confident = True
                        login_summary += "; login-check still shows the login form"
                    else:
                        log.ok(f"--login-check {check.url} is reachable while signed in")
        else:
            for note in result.notes:
                log.debug(f"  login: {note}")
            log.error(login_summary)
            if result.confident:
                log.error("refusing to scan with an unauthenticated session "
                          "(drop --login-url to scan anonymously)")
                return 2
            log.warn("continuing although authentication could not be confirmed")

    dom_enabled = bool(args.dom) or (not args.no_dom and not args.no_browser)
    dom_enabled = dom_enabled and browser.available
    screenshot_dir = os.path.join(args.output_dir, "evidence") if args.screenshots else None

    callback = None
    if args.callback is not None:
        callback = CallbackListener(host=args.callback_bind, port=args.callback, log=log,
                                    capture_cookies=args.capture_cookies,
                                    public_url=args.callback_url)
        try:
            callback.start()
            log.ok(f"callback listener: {callback.url} (blind XSS proof)")
        except OSError as exc:
            log.error(f"could not start the callback listener: {exc}")
            callback = None

    started = dt.datetime.now()
    resume = stateio.load_state(args.state) if args.state else stateio.empty_state()
    if resume.get("error"):
        log.warn(f"ignoring --state: {resume['error']}")
    done_keys = set(resume["done"])
    all_findings = list(resume["findings"])
    all_leads = list(resume["leads"])
    if done_keys or all_findings or all_leads:
        log.info(f"resume: {len(done_keys)} completed point(s), "
                 f"{len(all_findings)} confirmed and {len(all_leads)} lead finding(s) "
                 f"carried over from {args.state}")
    crawl_stats = {}
    points_total = 0
    reflected_total = 0
    mxss_total = 0
    charset_total = 0
    dom_total = 0
    stored_total = 0
    resumed_total = 0
    tokens_total = 0
    json_total = 0
    waf_variants_total = 0
    brute_probes_total = 0
    brute_reports: list[dict] = []
    discoveries: list[dict] = []
    libs_found: list = []
    server_tech: list = []
    waf_results: dict[str, wafmod.WAFDetection] = {}
    evasion_notes: dict[str, str] = {}
    fuzz_summary = None
    fuzz_result = None
    interrupted = False
    page_urls: list[str] = []

    deadline = time.monotonic() + args.max_minutes * 60 if args.max_minutes else None
    # A pending request must not outlive the budget it was started under.
    http.set_deadline(deadline)
    budget_hit = False

    for target in targets:
        if deadline is not None and time.monotonic() > deadline:
            budget_hit = True
            log.warn(f"time budget of {args.max_minutes:g} min reached; "
                     "skipping the remaining target(s)")
            break
        log.banner(f"target: {target}")

        do_crawl = bool(args.crawl)
        seeds = [target]
        sub_info = None
        scope_mode = args.scope
        if args.subdomains and do_crawl:
            base_host = subs.subdomain_base(target, args.subdomain_base, suffix_table)
            sources = "ct (crt.sh, certspotter, hackertarget)"
            log.action(f"discovering subdomains of {base_host} "
                       f"({sources + ' + dns' if args.subdomain_brute else 'passive ' + sources})")
            sub_info = subs.discover(
                base_host, fetch=ct_fetcher(http, headers), log=log,
                brute=args.subdomain_brute, wordlist=extra_words,
                max_hosts=args.max_hosts,
                concurrency=min(max(args.threads, 2), 12),
            )
            if sub_info.providers:
                log.debug("  ct source yields: " + ", ".join(
                    f"{name}={count}" for name, count in sub_info.providers.items()))
            for host in sub_info.hosts:
                if host == base_host:
                    continue
                url = probe_base(http, host, None, headers, log, announce=False)
                if url:
                    seeds.append(url)
                    log.info(f"  + {url}")
                else:
                    log.debug(f"  - {host}: no HTTP(S) response")
            if len(seeds) > 1 and scope_mode == "host":
                if "scope" in explicit:
                    log.warn("--scope host keeps the discovered host(s) out of this crawl; "
                             "drop --scope host to include them")
                    seeds = [target]
                else:
                    scope_mode = "subdomain"
                    log.info("scope widened to subdomain for the discovered host(s)")
        elif args.subdomains and not do_crawl:
            log.warn("--subdomains needs crawling; --no-crawl disables discovery")

        scope = Scope(target, scope_mode)
        log.info(f"scope: {scope.describe()}")

        param_urls: list[str] = []
        forms: list[Form] = []
        js_resources: list[tuple[str, str, list[str]]] = []
        crawled_pages = 0

        if do_crawl:
            hosts_note = f", {len(seeds)} host(s)" if len(seeds) > 1 else ""
            log.action(f"crawling (depth {args.crawl_depth}, max {args.max_pages} pages, "
                       f"{args.crawl_threads} workers{hosts_note})")
            crawler = Crawler(
                http, scope, log,
                max_depth=args.crawl_depth, max_pages=args.max_pages,
                concurrency=args.crawl_threads, exclude=args.exclude, include=args.include,
                crawl_js=not args.no_js, crawl_forms=True, ajax=not args.no_js,
                respect_robots=args.robots, headers=headers,
            )
            crawl_result = crawler.run(seeds)
            crawled_pages = len(crawl_result.pages)
            param_urls = list(crawl_result.param_urls)
            forms = crawl_result.forms
            js_resources = [(info.url, info.body, info.pages)
                            for info in crawl_result.js_files.values()]
            page_urls = list(crawl_result.pages)
            crawl_stats = {
                "pages": crawled_pages,
                "seeds": len(seeds),
                "hosts_crawled": len({urllib.parse.urlsplit(u).hostname
                                      for u in crawl_result.pages}),
                "subdomains_discovered": len(sub_info.hosts) if sub_info else 0,
                "parameterised_urls": len(param_urls),
                "forms": len(forms),
                "js_files": len(crawl_result.js_files),
                "external_hosts": len(crawl_result.external_hosts),
                "errors": len(crawl_result.errors),
            }
            log.ok(f"crawl finished: {crawled_pages} page(s), {len(param_urls)} parameterised URL(s), "
                   f"{len(forms)} form(s), {len(crawl_result.js_files)} JS file(s)")
            if crawl_result.errors:
                log.warn(f"{len(crawl_result.errors)} request(s) failed during crawl "
                         f"(first: {crawl_result.errors[0][1][:90]})")
            # Server-stack pass: it reads the seed response the crawl already
            # received, so it costs no extra request. An outdated version is a
            # lead for the operator, never a finding on its own.
            if crawl_result.root_headers:
                server_tech = techmod.detect(crawl_result.root_headers,
                                             crawl_result.generator)
                for entry in server_tech:
                    if entry.status == "detected":
                        log.info(entry.line())
                    else:
                        log.warn(entry.line())
        else:
            log.info("crawling disabled")

        # make sure the seed URL itself is always tested
        if "?" in target and target not in param_urls:
            param_urls.insert(0, target)

        # ---- passive fingerprints ----------------------------------
        # Both run once per host and never change the proof standard: the WAF
        # result only decides which payload variants are *offered*, and the
        # library list is evidence, not a finding on its own.
        host_key = urllib.parse.urlsplit(target).netloc.lower() or target
        if args.waf and host_key not in waf_results:
            log.action("probing for a web application firewall")
            try:
                waf_results[host_key] = wafmod.detect(http, target, headers, log=log)
            except Exception as exc:      # a fingerprint must never abort a scan
                log.warn(f"WAF probe failed: {str(exc)[:120]}")
                waf_results[host_key] = wafmod.WAFDetection(checked=True)
            current = waf_results[host_key]
            if current.detected:
                log.warn(current.describe())
                if current.evasive and args.evade:
                    log.info("evasion: " + ", ".join(current.strategies())
                             + f" (up to {wafmod.evasion_budget(current.confidence, current.blocking)} "
                             "extra variant(s) per point)")
            else:
                log.info(current.describe())
        waf_result: wafmod.WAFDetection | None = waf_results.get(host_key)

        if args.js_libs and js_resources:
            log.action(f"fingerprinting {len(js_resources)} client-side script(s)")
            try:
                target_libs = jslibmod.scan(js_resources)
            except Exception as exc:
                log.warn(f"library fingerprinting failed: {str(exc)[:120]}")
                target_libs = []
            libs_found.extend(target_libs)
            for lib in target_libs:
                if lib.vulnerable:
                    log.warn("  outdated client library: " + lib.line())
                else:
                    log.info("  client library: " + lib.line())
            if target_libs:
                lib_stats = jslibmod.summary(target_libs)
                log.ok(f"client libraries: {lib_stats['detected']} identified, "
                       f"{lib_stats['outdated']} outdated")
                if args.osv:
                    # The local table is a curated shortcut; OSV is current. Only
                    # the version is sent, never target headers or cookies.
                    log.action("querying osv.dev for these library versions")
                    try:
                        gained = jslibmod.enrich_osv(target_libs, http, log=log)
                    except Exception as exc:
                        gained = 0
                        log.debug(f"    osv enrichment failed: {str(exc)[:80]}")
                    if gained:
                        log.ok(f"OSV added advisories for {gained} library(ies)")

        if args.common_paths and do_crawl:
            from .crawler import COMMON_PATHS
            root = "{0.scheme}://{0.netloc}".format(urllib.parse.urlsplit(target))
            log.action(f"probing {len(COMMON_PATHS)} common paths for parameterised endpoints")
            for path in COMMON_PATHS[:40]:
                try:
                    resp = http.get(root + path, headers=headers)
                except Exception:
                    continue
                if resp.status < 400 and resp.is_html:
                    from .htmlparse import parse_page
                    page = parse_page(resp.url, resp.text)
                    for form in page.forms:
                        forms.append(form)

        if deadline is not None and time.monotonic() > deadline:
            budget_hit = True
            log.warn(f"time budget of {args.max_minutes:g} min reached; reporting what "
                     "has been tested so far")
            break

        only_params = [p.strip() for p in args.param.split(",")] if args.param else None

        # ---- parameter discovery -----------------------------------
        # A hidden parameter is only worth finding if the scanner then tests
        # it, so discovered names are merged into a copy of the URL and that
        # copy is queued for the new names only (no re-testing of the params
        # the URL already had).
        # A GET form is a parameterised URL that a link crawler cannot see: its
        # field names are exactly what the handler reads, so queue the action
        # with those names filled in. POST bodies are probed further below.
        form_urls = 0
        for form in forms:
            if form.method.upper() != "GET" or not form.action:
                continue
            names = [n for n, _v, typ in form.params
                     if n and typ not in ("submit", "button", "file", "image", "reset")]
            if not names:
                continue
            candidate = paramdisc.with_params(form.action, names)
            if candidate not in param_urls:
                param_urls.append(candidate)
                form_urls += 1
        if form_urls:
            log.info(f"queued {form_urls} GET form action(s) as parameterised URL(s)")

        # Names the application's own JavaScript uses: no extra request (the
        # crawler already downloaded the files) and more accurate than a generic
        # wordlist on renamed or localised parameters.
        js_names = paramdisc.names_from_js(js_resources) if js_resources else []
        if js_names:
            log.info(f"client-side script references {len(js_names)} parameter name(s)")

        if (args.discover_params or args.fuzz) and not param_urls:
            log.warn("--discover-params/--fuzz probe query strings, but no parameterised "
                     "URL was found on this target, so those stages had nothing to do "
                     "(reach body sinks with --json-body/--data instead)")

        extra_only: dict[str, list[str]] = {}
        if args.discover_params and param_urls:
            probe_urls = param_urls[:3]
            log.action(f"probing {len(probe_urls)} URL(s) for undocumented parameters")
            for url in probe_urls:
                if deadline is not None and time.monotonic() > deadline:
                    budget_hit = True
                    log.warn("time budget reached during parameter discovery")
                    break
                try:
                    # discovery details are reported below with the URL attached
                    found = paramdisc.discover(http, url, headers, wordlist=js_names)
                except Exception as exc:
                    log.debug(f"    discovery failed on {url}: {str(exc)[:90]}")
                    continue
                if not found.found:
                    log.info(f"  {url}: no undocumented parameter responded")
                    continue
                names = [n for n in found.names()
                         if not only_params or n in only_params]
                if not names:
                    log.info(f"  {url}: discovered name(s) excluded by --param")
                    continue
                augmented = paramdisc.with_params(url, names)
                if augmented in extra_only:
                    extra_only[augmented].extend(n for n in names
                                                 if n not in extra_only[augmented])
                else:
                    extra_only[augmented] = list(names)
                    param_urls.append(augmented)
                discoveries.append(found.as_dict())
                shown = ", ".join(names[:10]) + (" ..." if len(names) > 10 else "")
                log.ok(f"  {url}: {len(names)} hidden parameter(s) - {shown}")

        # ---- body parameter discovery ------------------------------
        # The query-string prober cannot see a JSON or form body, which is where
        # most current APIs put their parameters. Discovered properties are
        # merged into the body that the injection-point builder walks, so the
        # names are tested by the normal engine rather than reported and dropped.
        json_body = args.json_body
        if args.discover_params and json_body:
            log.action("probing the request body for undocumented properties")
            try:
                body_found = paramdisc.discover_body(
                    http, target, json_body, "json", headers, log=log, wordlist=js_names)
            except Exception as exc:
                body_found = None
                log.warn(f"body discovery failed: {str(exc)[:120]}")
            if body_found is not None and body_found.found:
                names = [n for n in body_found.names()
                         if not only_params or n in only_params]
                if names:
                    for name in names[:20]:
                        json_body = paramdisc.body_with(json_body, "json", name, "1")
                    discoveries.append(body_found.as_dict())
                    log.ok(f"  {target}: {len(names)} hidden body property(ies) - "
                           + ", ".join(names[:10]))

        # ---- fuzzing -----------------------------------------------
        if args.fuzz and param_urls:
            fuzz_result = None
            fuzz_urls = param_urls[:10]
            log.action(f"fuzzing parameters on {len(fuzz_urls)} URL(s) "
                       f"(budget {args.fuzz_budget} requests)")
            try:
                fuzz_result = fuzzmod.run(http, fuzz_urls, headers, log=log,
                                          max_requests=args.fuzz_budget)
            except Exception as exc:
                log.warn(f"fuzzing failed: {str(exc)[:120]}")
            if fuzz_result is not None:
                fuzz_summary = fuzzmod.summary(fuzz_result)
                if fuzz_summary["parameters_fuzzed"]:
                    log.ok(f"fuzzing: {fuzz_summary['parameters_fuzzed']} parameter(s) probed, "
                           f"{fuzz_summary['with_raw_reflection']} reflected raw, "
                           f"{fuzz_summary['encoded_only']} encoding-escaped, "
                           f"{fuzz_summary['template_evaluation']} template-evaluated")
                if fuzz_summary["truncated"]:
                    log.warn("fuzzing stopped at the request budget; "
                             "raise --fuzz-budget for full coverage")

        # ---- injection points --------------------------------------
        log.action("building injection points")
        points = []
        for url in param_urls:
            if url in extra_only:
                points.extend(points_from_url(url, headers, args.param_value,
                                              extra_only[url]))
                continue
            points.extend(points_from_url(url, headers, args.param_value, only_params))
        for form in forms:
            if form.method == "POST" and not args.forms:
                continue
            fetcher = None
            if form.method == "POST" and args.csrf_refresh:
                fetch = csrf_fetcher_factory(http, headers, log)
                token_page_url = form.origin_url or form.action
                fetcher = (lambda f=fetch, u=token_page_url: f(u))
            points.extend(points_from_form(form, headers, fetcher, only_params))

        if args.data or json_body:
            method = (args.method or "POST").upper()
            if json_body:
                points.extend(points_from_json(target, json_body.encode(), headers,
                                               only_params, method))
            else:
                pairs = parse_qs_ordered(args.data or "")
                synthetic = Form(
                    action=target, method=method,
                    enctype="application/x-www-form-urlencoded",
                    params=[(k, v, "text") for k, v in pairs],
                    origin_url=target,
                )
                fetcher = None
                if method == "POST" and args.csrf_refresh:
                    fetch = csrf_fetcher_factory(http, headers, log)
                    fetcher = (lambda f=fetch, u=target: f(u))
                points.extend(points_from_form(synthetic, headers, fetcher, only_params))

        if args.headers_points:
            for hname in ("Referer", "User-Agent", "X-Forwarded-Host", "Origin"):
                points.append(HeaderPoint(target, hname, headers, "GET"))
        if args.cookie:
            for part in args.cookie.split(";"):
                if "=" in part:
                    cname = part.split("=", 1)[0].strip()
                    points.append(CookiePoint(target, cname, headers))

        # de-duplicate points
        seen = set()
        uniq = []
        for p in points:
            form_obj = getattr(p, "form", None)
            where = getattr(p, "url", "") or (form_obj.action if form_obj else "")
            key = p.label() + "|" + where
            if key in seen:
                continue
            seen.add(key)
            uniq.append(p)
        points = uniq[: args.max_points]
        # Counted per point by the engine as it actually tests them, not from the
        # queue length: a run stopped by --max-minutes must not report the points
        # it never reached as "points tested".
        findings: list = []
        if not points:
            log.warn("no parameterised injection points found")
            if not (dom_enabled and js_resources) \
                    and not (args.stored and (forms or args.stored_json)):
                continue
        else:
            log.info(f"{len(points)} injection point(s) queued")
            if args.verbose:
                for p in points[:40]:
                    log.debug(f"  - {p.label()}")

            # ---- scan -----------------------------------------------
            log.action(f"scanning {len(points)} point(s) with {args.threads} thread(s)"
                       + (f", delay {args.delay}s" if args.delay else ""))
            scanner = Scanner(
                http, level=args.level, risk=args.risk, browser=browser, log=log,
                headers=headers, params_override=args.param_value,
                profile_enabled=not args.no_profile, mutation_budget=args.mutations,
                skip_points=done_keys, deadline=deadline,
                waf_detection=waf_result, evasion=args.evade,
                waf_budget=args.evasion_budget,
                bruteforce=args.brute, brute_budget=args.brute_budget,
            )
            findings = scanner.scan_points(points, concurrency=args.threads)
            points_total += scanner.stats["points"]
            if scanner.budget_exhausted:
                # The engine already logged how much it managed to test.
                budget_hit = True
            reflected_total += scanner.stats["reflected_points"]
            mxss_total += scanner.stats.get("mxss_probes", 0)
            charset_total += scanner.stats.get("charset_probes", 0)
            waf_variants_total += scanner.stats.get("waf_variants", 0)
            learned = scanner.evasion_memory.describe()
            if learned:
                log.info(f"evasion learned from this target: {learned}")
                evasion_notes[host_key] = learned
            brute_probes_total += scanner.stats.get("brute_probes", 0)
            if scanner.brute_reports:
                brute_reports.extend(scanner.brute_reports)
                log.ok(f"brute force: learned the filter map for "
                       f"{len(scanner.brute_reports)} point(s)")
            all_findings.extend(findings)
            all_leads.extend(scanner.leads)
            done_keys |= scanner.completed_points
            resumed_total += scanner.resumed_points
            if scanner.interrupted:
                interrupted = True
                log.warn("interrupted: writing a partial report from the results that "
                         "completed before the stop")
            if browser.available and scanner.stats["verified"] == 0 and findings:
                log.info("browser verification ran but did not observe execution "
                         "(CSP or an interaction requirement can cause this)")

        if interrupted:
            break

        # ---- DOM XSS ------------------------------------------------
        if dom_enabled and js_resources:
            log.action(f"tracing DOM sources and sinks in {len(js_resources)} script resource(s)")
            dom = DomScanner(browser=browser, log=log, max_flows=args.dom_flows,
                             screenshot_dir=screenshot_dir, deadline=deadline)
            outcome = dom.scan(target, js_resources)
            if dom.budget_exhausted:
                budget_hit = True
            all_findings.extend(outcome["findings"])
            all_leads.extend(outcome["leads"])
            dom_total += len(outcome["findings"])
            if outcome["findings"]:
                log.ok(f"{len(outcome['findings'])} DOM XSS flow(s) proven in the browser")
            elif outcome["flows"]:
                log.info(f"{len(outcome['flows'])} DOM flow(s) analysed, none proven")
            if outcome["leads"] and args.verbose:
                for lead in outcome["leads"][:10]:
                    log.debug(f"  DOM lead: {lead.param} at {lead.url}")

        # ---- stored / blind XSS -------------------------------------
        if deadline is not None and time.monotonic() > deadline:
            budget_hit = True
            log.warn(f"time budget of {args.max_minutes:g} min reached before the stored "
                     "stage; reporting what has been tested so far")
            break
        if args.stored and (forms or args.stored_json):
            log.action(f"planting stored-XSS payloads in {len(forms)} form(s)"
                       + (f" and {len(args.stored_json)} JSON endpoint(s)"
                          if args.stored_json else "")
                       + (f", callback {callback.url}" if callback else ""))
            store = StoredScanner(
                http, browser=browser, log=log, callback=callback,
                max_forms=args.stored_max_forms, screenshot_dir=screenshot_dir,
                json_endpoints=args.stored_json, json_field=args.stored_json_field,
                viewer_urls=args.viewer_url, deadline=deadline,
            )
            outcome = store.scan(target, forms, page_urls)
            if store.budget_exhausted:
                budget_hit = True
            all_findings.extend(outcome["findings"])
            all_leads.extend(outcome["leads"])
            stored_total += outcome["stats"]["verified"]
            st = outcome["stats"]
            tokens_total += st.get("tokens_refreshed", 0)
            json_total += st.get("json_submitted", 0)
            log.ok(f"stored: {st['markers']} marker(s) planted, {st['hits']} persisted, "
                   f"{st['verified']} proven")
            if st.get("tokens_refreshed"):
                log.info(f"stored: {st['tokens_refreshed']} anti-CSRF token(s) refreshed "
                         "before planting")
            if st.get("json_submitted"):
                log.info(f"stored: {st['json_submitted']} JSON endpoint(s) accepted the payload")
            if outcome["findings"]:
                log.warn(f"{len(outcome['findings'])} stored XSS flow(s) confirmed")

    finished = dt.datetime.now()
    findings = rp.dedupe(all_findings)

    # ---- exploit stage ---------------------------------------------
    # Detection says an input reaches an execution context; --verify replays the
    # exact request with a weaponised payload and measures what the script could
    # reach. It never upgrades a finding on the strength of a payload it only
    # sent, so a finding without an observation keeps saying so.
    verification = None
    if args.verify and findings:
        log.action(f"exploit stage: replaying up to {min(len(findings), args.verify_max)} "
                   f"of {len(findings)} finding(s) with a weaponised payload")
        prover = ExploitProver(http=http, browser=browser, log=log, callback=callback,
                               max_targets=args.verify_max, deadline=deadline,
                               session=session)
        verification = prover.run(findings)
        vstats = verification["stats"]
        if vstats.get("proven"):
            log.ok(f"exploit: {vstats['proven']} finding(s) proven to reach "
                   "cookies, tokens or same-origin data")
        if vstats.get("unproven") or vstats.get("not_tested"):
            log.warn(f"exploit: {vstats.get('unproven', 0)} unproven, "
                     f"{vstats.get('not_tested', 0)} not tested")
            first = next((f for f in findings
                          if (getattr(f, "exploit", None) or {}).get("reason")), None)
            if first is not None and not vstats.get("proven"):
                log.info(f"exploit: first reason - {first.exploit['reason'][:200]}")
                log.info("exploit: a finding that stays unproven is still a confirmed "
                         "injection; the report says which capability was measured")

    # ---- output ----------------------------------------------------
    print()
    log.banner("results")
    if not findings:
        log.ok("no cross-site scripting confirmed")
        if all_leads:
            log.info(f"{len(rp.dedupe(all_leads))} unconfirmed lead(s) - see the report's leads section")
    else:
        counts: dict[str, int] = {}
        for f in findings:
            sev = rp.severity_of(f)
            counts[sev] = counts.get(sev, 0) + 1
        summary = ", ".join(f"{counts[s]} {s}" for s in ("high", "medium", "low") if s in counts)
        log.warn(f"{len(findings)} finding(s): {summary}")
        for f in findings:
            log.found(f)

    stats = {
        "points": points_total,
        "requests": http.stats["requests"],
        "reflected_points": reflected_total,
        "mxss_probes": mxss_total,
        "charset_probes": charset_total,
        "waf_variants": waf_variants_total,
        "brute_probes": brute_probes_total,
        "verified": browser.hits,
        "dom_flows": dom_total,
        "stored_flows": stored_total,
        "resumed_points": resumed_total,
        "rate_limits": http.stats.get("rate_limits", 0),
        "tokens_refreshed": tokens_total,
        "json_submitted": json_total,
        "callback_hits": len(callback.hits) if callback else 0,
        "errors": http.stats["errors"],
        "bytes": http.stats["bytes"],
    }
    meta = rp.build_meta(
        targets=targets, started=started, finished=finished,
        stats={k: v for k, v in stats.items() if v is not None},
        crawl_stats=crawl_stats,
        browser_note=browser.describe(),
        command=" ".join(shlex.quote(a) for a in sys.argv),
    )
    if interrupted:
        meta["interrupted"] = True
    if budget_hit:
        meta["partial"] = f"time budget of {args.max_minutes:g} min reached"
    if verification is not None:
        meta["verification"] = verification["stats"]
    if args.autonomous:
        meta["autonomous"] = True
    if waf_results:
        meta["waf"] = [dict(detection.as_dict(), target=host)
                       for host, detection in waf_results.items()]
        meta["waf_note"] = "; ".join(detection.describe()
                                      for detection in waf_results.values())
    if evasion_notes:
        meta["evasion_learned"] = evasion_notes
    if libs_found:
        uniq_libs: dict[tuple[str, str], jslibmod.Library] = {}
        for lib in libs_found:
            uniq_libs.setdefault((lib.name, lib.version), lib)
        lib_list = list(uniq_libs.values())
        meta["js_libraries"] = [lib.as_dict() for lib in lib_list]
        meta["js_library_summary"] = {
            k: v for k, v in jslibmod.summary(lib_list).items() if k != "libraries"}
    if server_tech:
        meta["server_stack"] = techmod.rows(server_tech)
        meta["server_stack_summary"] = {
            k: v for k, v in techmod.summary(server_tech).items() if v}
    if discoveries:
        meta["discovered_parameters"] = discoveries
    if fuzz_summary is not None:
        meta["fuzzing"] = fuzz_summary
        meta["fuzzed_parameters"] = (fuzz_result or {}).get("params", [])
    if brute_reports:
        # A hostile target can reflect hundreds of points; the report stays
        # readable and the JSON records how many entries were dropped.
        meta["brute_force"] = brute_reports[:80]
        if len(brute_reports) > 80:
            meta["brute_force_truncated"] = len(brute_reports) - 80
    if login_summary:
        meta["authentication"] = {"login_url": args.login_url,
                                  "result": login_summary,
                                  "cookies": jar.names()}
    if all_leads:
        lead_rows = rp.dedupe(all_leads)
        meta["leads"] = [
            {"url": f.url, "param": f.param, "context": f.context,
             "location": f.location, "confidence": f.confidence, "notes": f.notes,
             "kind": (f.filter_profile or {}).get("lead_kind", "")}
            for f in lead_rows[:200]
        ]
        if len(lead_rows) > 200:
            meta["leads_truncated"] = True

    written = []
    output_dir = args.output_dir
    stamp = finished.strftime("%Y%m%d-%H%M%S")
    json_path = args.output or os.path.join(output_dir, f"xssmap-{stamp}.json")
    html_path = args.html or os.path.join(output_dir, f"xssmap-{stamp}.html")
    md_path = args.markdown or os.path.join(output_dir, f"xssmap-{stamp}.md")
    sarif_path = args.sarif or os.path.join(output_dir, f"xssmap-{stamp}.sarif")
    try:
        written.append(rp.write_json(json_path, findings, meta))
        written.append(rp.write_html(html_path, findings, meta))
        written.append(rp.write_markdown(md_path, findings, meta))
        written.append(sarif.write_sarif(sarif_path, findings, meta))
        if args.evidence_dir or args.screenshots:
            evidence_dir = args.evidence_dir or os.path.join(output_dir, "evidence")
            sarif.write_evidence(findings, evidence_dir)
            if args.screenshots:
                sarif.capture_screenshots(browser, findings, evidence_dir)
    except OSError as exc:
        log.error(f"could not write report: {exc}")

    if written and not args.quiet:
        print()
        log.info(f"{http.stats['requests']} request(s), "
                 f"{http.stats['bytes'] / 1024:.0f} KB transferred, "
                 f"{meta['duration_s']}s")
        for path in written:
            log.info(f"report: {path}")
    if args.state:
        try:
            stateio.save_state(args.state, targets, done_keys, findings, rp.dedupe(all_leads))
            log.info(f"state: {len(done_keys)} completed point(s) saved to {args.state}")
        except OSError as exc:
            log.error(f"could not write --state: {exc}")
    if args.save_cookies:
        try:
            jar.save_netscape(args.save_cookies)
            log.info(f"cookies written to {args.save_cookies} (sensitive: live secrets)")
        except OSError as exc:
            log.error(f"could not write --save-cookies: {exc}")
    if callback is not None:
        callback.stop()
    browser.cleanup()

    if interrupted:
        return 130
    if args.fail_on_findings and findings:
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[-] interrupted")
        sys.exit(130)
