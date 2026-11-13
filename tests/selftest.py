"""End-to-end accuracy harness for xssmap.

Starts the vulnerable lab app, scans it for real over HTTP, then scores the
results against the app's /manifest.json expectations:

    TP  vulnerable endpoint detected
    FP  safe endpoint reported as vulnerable
    FN  vulnerable endpoint missed

Run:  python tests/selftest.py            (crawl + direct scan)
      python tests/selftest.py --browser  (also verify execution in Chrome)
      python tests/selftest.py --forms    (also submit the POST form)
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import subprocess
import sys
import tempfile
import urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from testapp.vuln_app import AUTH_EXPECT, EXPECT, serve_in_thread  # noqa: E402

GREEN, RED, YELLOW, GREY, RESET, BOLD = "\033[92m", "\033[91m", "\033[93m", "\033[90m", "\033[0m", "\033[1m"


def run_scan(args: list[str], outdir: str) -> dict:
    cmd = [sys.executable, os.path.join(ROOT, "run.py"), *args,
           "--output-dir", outdir, "--quiet", "--no-color", "--threads", "4"]
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=600,
                          stdin=subprocess.DEVNULL)
    files = sorted(glob.glob(os.path.join(outdir, "*.json")), key=os.path.getmtime)
    if not files:
        print(proc.stdout[-3000:])
        print(proc.stderr[-3000:])
        raise SystemExit("scan produced no JSON report")
    with open(files[-1], encoding="utf-8") as fh:
        return json.load(fh)


def key_of(url: str, param: str) -> tuple[str, str]:
    path = "/" + url.split("://", 1)[1].split("/", 1)[1].split("?")[0] if "://" in url else url
    return path.rstrip("/") or "/", param


def score(report: dict, expectations: list[dict], label: str) -> tuple[int, int, int]:
    expected_vuln = {(e["path"], e["param"]): e for e in expectations if e.get("vulnerable")}
    # A stored payload executes on the page that *renders* it, which for blind XSS
    # is an admin view (e.g. /admin/inbox) rather than the form that stored it.
    # Attribute those findings to their expectation by parameter, not by path.
    stored_by_param = {e["param"]: (e["path"], e["param"])
                       for e in expectations if e.get("stored")}
    found = {}
    for f in report.get("findings", []):
        if f.get("confidence") == "low":
            continue
        k = key_of(f["url"], f["parameter"])
        if k not in expected_vuln and f.get("context") == "stored_xss":
            k = stored_by_param.get(f["parameter"], k)
        found.setdefault(k, f)
    expected_safe = [e for e in expectations if not e.get("vulnerable")]

    tp = sum(1 for k in expected_vuln if k in found)
    fn_keys = [k for k in expected_vuln if k not in found]
    fp_keys = [k for k in found if k not in expected_vuln]

    print(f"\n{BOLD}{label}{RESET}")
    print(f"  {'RESULT':<6} {'ENDPOINT':<34} {'CONTEXT':<18} DETAIL")
    for k in sorted(expected_vuln):
        e = expected_vuln[k]
        if k in found:
            f = found[k]
            extra = []
            if f.get("csp_blocked"):
                extra.append("csp-blocked-execution")
            if f.get("browser_verified"):
                extra.append("browser-confirmed")
            if e.get("stored") and not f.get("browser_verified"):
                extra.append("stored but unproven")
            if e.get("csp") and f.get("browser_verified"):
                extra.append("unexpected: csp did not block")
            print(f"  {GREEN}TP{RESET}     {e['path'] + '?' + e['param']:<34} "
                  f"{f['context']:<18} {', '.join(extra)}")
        else:
            print(f"  {RED}FN{RESET}     {e['path'] + '?' + e['param']:<34} "
                  f"{e.get('context', ''):<18} missed")
    for k in fp_keys:
        f = found[k]
        print(f"  {RED}FP{RESET}     {k[0] + '?' + k[1]:<34} {f['context']:<18} "
              f"{f.get('payload', '')[:40]}")
    for e in expected_safe:
        k = (e["path"], e["param"])
        state = f"{RED}FP{RESET}" if k in found else f"{GREEN}TN{RESET}"
        print(f"  {state}     {e['path'] + '?' + e['param']:<34} {'-':<18} {e.get('reason', '')}")

    total = len(expected_vuln)
    precision = tp / (tp + len(fp_keys)) if (tp + len(fp_keys)) else 1.0
    recall = tp / total if total else 1.0
    print(f"  {GREY}-> {tp}/{total} detected ({recall:.0%} recall), "
          f"{len(fp_keys)} false positive(s) ({precision:.0%} precision){RESET}")
    return tp, len(fp_keys), len(fn_keys)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--browser", action="store_true", help="enable headless browser confirmation")
    ap.add_argument("--forms", action="store_true", help="crawl with POST form submission")
    ap.add_argument("--stored", action="store_true",
                    help="also plant stored/blind payloads (needs --browser)")
    ap.add_argument("--keep", action="store_true", help="keep the output directory")
    ap.add_argument("--port", type=int, default=0)
    args = ap.parse_args()

    httpd, port = serve_in_thread(args.port)
    base = f"http://127.0.0.1:{port}"
    print(f"lab app on {base}")
    outdir = tempfile.mkdtemp(prefix="xssmap-selftest-")

    failures = 0
    try:
        # ---- phase 1: crawl + scan ---------------------------------
        # 60 pages: the lab links a two-step storage flow (/dom-state ->
        # /dom-state-read), so a tighter cap silently drops the page that holds
        # the sink and the flow looks untested rather than missed.
        scan_args = ["-u", base + "/", "--crawl-depth", "2", "--max-pages", "60",
                     "--evidence", os.path.join(outdir, "evidence")]
        if not args.browser:
            scan_args.append("--no-browser")
        else:
            scan_args.append("--dom")
            if args.stored:
                scan_args += ["--stored", "--callback"]
        scan_args.append("--fail-on-findings")
        report = run_scan(scan_args, outdir)
        # Without a browser there is no way to observe DOM flows or stored payloads,
        # so they are out of scope for this phase rather than counted as misses.
        phase1_expect = EXPECT if args.browser else [
            e for e in EXPECT if not e.get("dom") and not e.get("stored")]
        _tp, fp, fn = score(report, phase1_expect,
                            "phase 1 - crawl and scan (default level 2)")
        failures += fp + fn
        crawl = report.get("crawl") or {}
        print(f"  {GREY}crawl: {crawl.get('pages', 0)} pages, "
              f"{crawl.get('parameterised_urls', 0)} parameterised URLs, "
              f"{crawl.get('forms', 0)} forms; "
              f"{report['statistics'].get('requests', 0)} requests{RESET}")
        if args.browser:
            verified = sum(1 for f in report["findings"] if f.get("browser_verified"))
            print(f"  {GREY}browser-confirmed findings: {verified}{RESET}")
            if verified == 0:
                print(f"  {RED}browser verification produced no confirmations{RESET}")
                failures += 1

        # ---- phase 2: direct scan of every endpoint -----------------
        tmp2 = tempfile.mkdtemp(prefix="xssmap-selftest-direct-")
        # Phase 2 is a raw request-only scan: DOM and stored flows cannot be
        # observed without a browser or a crawler, so they are out of scope here.
        direct_expect = [e for e in EXPECT if not e.get("dom") and not e.get("stored")]
        urls = [f"{base}{e['path']}?{e['param']}=probe" for e in direct_expect]
        urls_file = os.path.join(tmp2, "urls.txt")
        with open(urls_file, "w", encoding="utf-8") as fh:
            fh.write("\n".join(urls))
        direct_args = ["-m", urls_file, "--no-crawl", "--no-browser"]
        report2 = run_scan(direct_args, tmp2)
        _tp2, fp2, fn2 = score(report2, direct_expect,
                              "phase 2 - direct per-endpoint scan (reflected only)")
        failures += fp2 + fn2

        # ---- phase 3: POST form with CSRF ---------------------------------
        if args.forms:
            tmp3 = tempfile.mkdtemp(prefix="xssmap-selftest-form-")
            report3 = run_scan(["-u", base + "/form-post", "--forms", "--no-browser",
                                "--crawl-depth", "1", "--max-pages", "3"], tmp3)
            hits = [f for f in report3["findings"] if f["parameter"] == "comment"]
            if hits:
                print(f"\n{BOLD}phase 3 - POST form with CSRF token{RESET}")
                print(f"  {GREEN}TP{RESET}     /form-post?comment{'':<16} {hits[0]['context']:<18} "
                      f"token handled")
            else:
                print(f"\n{BOLD}phase 3 - POST form with CSRF token{RESET}")
                print(f"  {RED}FN{RESET}     /form-post?comment{'':<16} {'':<18} form not exploited")
                failures += 1
            if not args.keep:
                _rm(tmp3)

        # ---- phase 4: machine-readable outputs -----------------------
        sarif_files = glob.glob(os.path.join(outdir, "*.sarif"))
        evidence = glob.glob(os.path.join(outdir, "evidence", "*.txt"))
        print(f"\n{BOLD}phase 4 - machine-readable outputs{RESET}")
        problems = []
        if not sarif_files:
            problems.append("no SARIF file written")
        else:
            with open(sorted(sarif_files)[-1], encoding="utf-8") as fh:
                doc = json.load(fh)
            results = len(doc.get("runs", [{}])[0].get("results", []))
            if doc.get("version") != "2.1.0":
                problems.append(f"unexpected SARIF version {doc.get('version')}")
            if results != len(report["findings"]):
                problems.append(f"SARIF has {results} results for "
                                f"{len(report['findings'])} findings")
        if len(evidence) < len(report["findings"]):
            problems.append(f"{len(evidence)} evidence file(s) for "
                            f"{len(report['findings'])} findings")
        if problems:
            for problem in problems:
                print(f"  {RED}FAIL{RESET}     {problem}")
            failures += len(problems)
        else:
            print(f"  {GREEN}OK{RESET}       SARIF 2.1.0 valid, "
                  f"{len(evidence)} evidence file(s)")

        # ---- phase 5: mutation XSS round trip -----------------------
        # The mXSS stage is a positive *and* negative control: /mxss runs a
        # naive sanitise-then-reserialise round trip that re-creates an
        # executable handler, /mxss-safe escapes at the boundary and must stay
        # silent. Neither is linked from the index or listed in EXPECT, so this
        # phase scores the two endpoints directly and browser-only.
        if args.browser:
            print(f"\n{BOLD}phase 5 - mutation XSS round trip{RESET}")
            for path, want in (("/mxss", 1), ("/mxss-safe", 0)):
                tmp5 = tempfile.mkdtemp(prefix="xssmap-selftest-mxss-")
                report5 = run_scan(["-u", f"{base}{path}?q=probe", "--no-crawl"], tmp5)
                hits = [f for f in report5["findings"] if f.get("context") == "mxss"]
                proven = [f for f in hits
                          if f.get("verify_state") == "confirmed"
                          and f.get("severity") == "high"]
                label = f"{path}?q=probe"
                if want:
                    if len(hits) == want and len(proven) == want:
                        print(f"  {GREEN}TP{RESET}     {label:<34} {'mxss':<18} "
                              f"round trip re-executed, high/confirmed")
                    else:
                        print(f"  {RED}FN{RESET}     {label:<34} {'mxss':<18} "
                              f"{len(hits)} finding(s), {len(proven)} high/confirmed")
                        failures += 1
                elif hits:
                    f = hits[0]
                    print(f"  {RED}FP{RESET}     {label:<34} {'mxss':<18} "
                          f"escaped page reported ({f.get('verify_state') or 'no verdict'})")
                    failures += 1
                else:
                    print(f"  {GREEN}TN{RESET}     {label:<34} {'-':<18} "
                          f"escaped at the boundary, no finding")
                stats5 = report5.get("statistics") or {}
                print(f"  {GREY}   mXSS probes: {stats5.get('mxss_probes', 0)}{RESET}")
                if not args.keep:
                    _rm(tmp5)

        # ---- phase 6: multibyte charset escaping --------------------
        # /charset backslash-escapes quotes on a page the server really encodes
        # as GBK, where 0xBF 0x5C is a single character; /charset-safe does the
        # same escaping and serves UTF-8, where it is not. The third run checks
        # the honest middle state: without a browser the byte-level breakout is
        # still reported, but as medium / not_tested, never as confirmed.
        if args.browser:
            print(f"\n{BOLD}phase 6 - multibyte charset escaping{RESET}")
            for path, want in (("/charset", 1), ("/charset-safe", 0)):
                tmp6 = tempfile.mkdtemp(prefix="xssmap-selftest-charset-")
                report6 = run_scan(["-u", f"{base}{path}?q=probe", "--no-crawl"], tmp6)
                hits = [f for f in report6["findings"] if f.get("context") == "charset"]
                proven = [f for f in hits
                          if f.get("verify_state") == "confirmed"
                          and f.get("severity") == "high"]
                label = f"{path}?q=probe"
                if want:
                    if len(hits) == want and len(proven) == want:
                        print(f"  {GREEN}TP{RESET}     {label:<34} {'charset':<18} "
                              f"bare quote after the lead byte, high/confirmed")
                    else:
                        print(f"  {RED}FN{RESET}     {label:<34} {'charset':<18} "
                              f"{len(hits)} finding(s), {len(proven)} high/confirmed")
                        failures += 1
                elif hits:
                    print(f"  {RED}FP{RESET}     {label:<34} {'charset':<18} "
                          f"utf-8 page reported ({hits[0].get('verify_state') or 'no verdict'})")
                    failures += 1
                else:
                    print(f"  {GREEN}TN{RESET}     {label:<34} {'-':<18} "
                          f"utf-8 decoding keeps the escape")
                stats6 = report6.get("statistics") or {}
                print(f"  {GREY}   charset probes: {stats6.get('charset_probes', 0)}{RESET}")
                if not args.keep:
                    _rm(tmp6)

            tmp6b = tempfile.mkdtemp(prefix="xssmap-selftest-charset-nb-")
            report6b = run_scan(["-u", f"{base}/charset?q=probe", "--no-crawl",
                                 "--no-browser"], tmp6b)
            hits = [f for f in report6b["findings"] if f.get("context") == "charset"]
            if (len(hits) == 1 and hits[0].get("verify_state") == "not_tested"
                    and hits[0].get("confidence") == "medium"):
                print(f"  {GREEN}OK{RESET}     {'/charset (no browser)':<34} {'bytes':<18} "
                      f"breakout proven, execution reported not_tested")
            else:
                state = hits[0].get("verify_state") if hits else "no finding"
                print(f"  {RED}FAIL{RESET}     {'/charset (no browser)':<34} {'bytes':<18} "
                      f"expected medium/not_tested, got {state}")
                failures += 1
            if not args.keep:
                _rm(tmp6b)

        # ---- phase 7: authenticated and JSON stored flows -----------
        # Phase 1 runs anonymously; /account redirects to /login there, so it can
        # only be reached with a real session. This phase signs in, lets the
        # rotating CSRF token be refreshed before planting, plants a stored
        # payload through a JSON API too, and requires browser proof for both.
        if args.browser and args.stored:
            print(f"\n{BOLD}phase 7 - authenticated session and JSON planting{RESET}")
            tmp7 = tempfile.mkdtemp(prefix="xssmap-selftest-auth-")
            jar_path = os.path.join(tmp7, "cookies.txt")
            report7 = run_scan([
                "-u", base + "/", "--crawl", "--max-pages", "40", "--forms",
                "--stored", "--stored-json", base + "/api/guestbook",
                "--login-url", base + "/login", "--login-user", "alice",
                "--login-pass", "s3cret", "--login-check", base + "/account",
                "--save-cookies", jar_path,
            ], tmp7)
            auth = report7.get("authentication") or {}
            logged_in = str(auth.get("result", "")).startswith("logged in")
            stored = [f for f in report7["findings"] if f.get("context") == "stored_xss"]
            proven = {urllib.parse.urlsplit(f.get("url") or "").path for f in stored
                      if f.get("browser_verified") and f.get("severity") == "high"}
            want = {e["path"] for e in AUTH_EXPECT}
            missing = sorted(want - proven)
            if logged_in and not missing:
                print(f"  {GREEN}TP{RESET}     {'/account + /guestbook-json':<34} "
                      f"{'stored_xss':<18} session kept, CSRF token refreshed, both proven")
            else:
                print(f"  {RED}FN{RESET}     {'/account + /guestbook-json':<34} "
                      f"{'stored_xss':<18} logged_in={logged_in} missing={missing or '-'}")
                failures += 1
            saved = os.path.isfile(jar_path) and os.path.getsize(jar_path) > 0
            with open(jar_path, encoding="utf-8", errors="replace") as fh:
                has_sid = "\tsid\t" in fh.read()
            if saved and has_sid:
                print(f"  {GREEN}OK{RESET}     {'--save-cookies':<34} {'jar':<18} "
                      f"cookie names persisted (values not printed)")
            else:
                print(f"  {RED}FAIL{RESET}     {'--save-cookies':<34} {'jar':<18} "
                      f"saved={saved} sid={has_sid}")
                failures += 1
            stats7 = report7.get("statistics") or {}
            print(f"  {GREY}   tokens refreshed: {stats7.get('tokens_refreshed', 0)}, "
                  f"JSON submissions accepted: {stats7.get('json_submitted', 0)}, "
                  f"stored proven: {stats7.get('stored_flows', 0)}{RESET}")
            if not args.keep:
                _rm(tmp7)

        # ---- phase 8: resume state and operator-supplied viewers ------
        # --state must carry findings across runs and skip the points it already
        # finished. --viewer-url is the only way a blind sink (the admin inbox)
        # becomes visible, so the same plant is run with and without it.
        if args.forms and args.stored:
            print(f"\n{BOLD}phase 8 - resume state and viewer pages{RESET}")
            tmp8 = tempfile.mkdtemp(prefix="xssmap-selftest-ops-")
            state_path = os.path.join(tmp8, "state.json")
            first = run_scan(["-u", base + "/search?q=probe", "--no-crawl", "--no-browser",
                              "--state", state_path], os.path.join(tmp8, "first"))
            second = run_scan(["-u", base + "/search?q=probe", "--no-crawl", "--no-browser",
                               "--state", state_path], os.path.join(tmp8, "second"))
            stats8 = second.get("statistics") or {}
            first_requests = (first.get("statistics") or {}).get("requests", 0)
            carried = [f for f in second.get("findings", [])
                       if f.get("context") == "html_text"]
            # Host-level WAF fingerprinting still runs on a resumed scan, so "the
            # point was not re-tested" means strictly less traffic than the first
            # run - not zero requests.
            if (stats8.get("resumed_points", 0) >= 1 and carried
                    and 0 < stats8.get("requests", 0) < first_requests):
                print(f"  {GREEN}OK{RESET}     {'--state resume':<34} {'state':<18} "
                      f"{stats8.get('resumed_points')} point(s) skipped, "
                      f"{len(carried)} finding(s) carried over, "
                      f"{stats8.get('requests')} vs {first_requests} request(s)")
            else:
                print(f"  {RED}FAIL{RESET}     {'--state resume':<34} {'state':<18} "
                      f"resumed={stats8.get('resumed_points')} "
                      f"requests={stats8.get('requests')} vs {first_requests} "
                      f"carried={len(carried)}")
                failures += 1

            blind_without = run_scan([
                "-u", base + "/feedback", "--forms", "--stored", "--no-browser",
                "--crawl", "--crawl-depth", "0", "--max-pages", "1",
            ], os.path.join(tmp8, "no-viewer"))
            blind_with = run_scan([
                "-u", base + "/feedback", "--forms", "--stored", "--no-browser",
                "--crawl", "--crawl-depth", "0", "--max-pages", "1",
                "--viewer-url", base + "/admin/inbox",
            ], os.path.join(tmp8, "viewer"))

            def _inbox(data):
                return [lead for lead in (data.get("leads") or [])
                        if "/admin/inbox" in (lead.get("url") or "")]
            # Other reflecting points on the form page legitimately produce leads
            # now that every reflection is reported, so the assertion is about
            # the inbox flow specifically: it exists only with the viewer page.
            seen, leaked = _inbox(blind_with), _inbox(blind_without)
            if seen and not leaked:
                print(f"  {GREEN}OK{RESET}     {'--viewer-url':<34} {'blind stored':<18} "
                      f"inbox flow visible only when the viewer page is supplied")
            else:
                print(f"  {RED}FAIL{RESET}     {'--viewer-url':<34} {'blind stored':<18} "
                      f"inbox leads without={len(leaked)} with={len(seen)} "
                      f"urls={[lead.get('url') for lead in leaked][:2]}")
                failures += 1
            if not args.keep:
                _rm(tmp8)

        if not args.keep:
            _rm(tmp2)
    finally:
        httpd.shutdown()
        if not args.keep:
            _rm(outdir)

    print()
    if failures:
        print(f"{RED}{failures} problem(s) found{RESET}")
        return 1
    print(f"{GREEN}all checks passed{RESET}")
    return 0


def _rm(path: str):
    import shutil
    shutil.rmtree(path, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
