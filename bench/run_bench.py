"""Score xssmap against a lab whose ground truth was written before the run.

The point of a benchmark is to be able to fail. This runner:

1. starts bench/lab2 on an ephemeral port;
2. re-checks the lab's declared labels against its real responses, so a stale
   label cannot quietly inflate the score;
3. runs the scanner exactly as a user would (crawler, forms, JSON report);
4. compares the reported (path, parameter) pairs with the labels and prints
   precision/recall plus a per-endpoint table.

Exit status is non-zero when any safe endpoint is reported, when a vulnerable
endpoint is missed, or when recall falls below --min-recall.

    python bench/run_bench.py                 # reflection-level (no browser)
    python bench/run_bench.py --browser       # also require proven execution
    python bench/run_bench.py --min-recall 1.0
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from bench.lab2.app import LABELS, serve_in_thread  # noqa: E402
from bench.verify_lab import check as check_lab  # noqa: E402


def path_of(url: str) -> str:
    return urllib.parse.urlsplit(url).path.rstrip("/") or "/"


def score(report: dict, labels: list[dict], require_confirmed: bool = False) -> dict:
    """Compare one scanner report with the lab labels.

    A finding counts for a label when its path and parameter match. Stored-XSS
    findings are attributed by parameter because the sink page differs from the
    page that stored the value.
    """
    expected = {(lab["path"], lab["param"]): lab for lab in labels if lab["vulnerable"]}
    safe = {(lab["path"], lab["param"]) for lab in labels if not lab["vulnerable"]}
    stored_by_param = {lab["param"]: (lab["path"], lab["param"])
                       for lab in labels if lab.get("stored")}

    found: dict[tuple[str, str], dict] = {}
    extra: list[dict] = []
    for finding in report.get("findings", []):
        key = (path_of(finding.get("url", "")), finding.get("parameter", ""))
        if key not in expected and finding.get("context") == "stored_xss":
            key = stored_by_param.get(finding.get("parameter", ""), key)
        if key in expected or key in safe:
            found.setdefault(key, finding)
        else:
            extra.append(finding)

    rows = []
    tp = fn = 0
    for key, lab in expected.items():
        finding = found.get(key)
        hit = finding is not None
        if hit and require_confirmed:
            hit = finding.get("verify_state") == "confirmed"
        rows.append({
            "path": key[0], "param": key[1], "expected": "vulnerable",
            "result": "TP" if hit else "FN",
            "context": (finding or {}).get("context", ""),
            "context_ok": bool(finding) and
            (finding.get("context") == lab.get("context") or
             finding.get("context") == "stored_xss"),
            "confidence": (finding or {}).get("confidence", ""),
            "verify_state": (finding or {}).get("verify_state", ""),
        })
        tp += 1 if hit else 0
        fn += 0 if hit else 1

    tn = fp = 0
    for key in sorted(safe):
        finding = found.get(key)
        rows.append({
            "path": key[0], "param": key[1], "expected": "safe",
            "result": "FP" if finding else "TN",
            "context": (finding or {}).get("context", ""),
            "context_ok": True,
            "confidence": (finding or {}).get("confidence", ""),
            "verify_state": (finding or {}).get("verify_state", ""),
        })
        fp += 1 if finding else 0
        tn += 0 if finding else 1

    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "rows": rows,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "unexpected_findings": [
            {"url": f.get("url"), "parameter": f.get("parameter"),
             "context": f.get("context")} for f in extra],
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def run_scanner(base: str, outdir: str, browser: bool, extra: list[str]) -> dict:
    cmd = [sys.executable, os.path.join(ROOT, "run.py"),
           "-u", base + "/", "--crawl", "--crawl-depth", "2",
           "--forms", "--max-pages", "30", "--max-points", "80",
           "--threads", "4", "--quiet", "--no-color",
           "--output-dir", outdir]
    cmd += ["--browser"] if browser else ["--no-browser"]
    cmd += extra
    started = time.time()
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                          timeout=900, stdin=subprocess.DEVNULL)
    files = sorted(glob.glob(os.path.join(outdir, "*.json")), key=os.path.getmtime)
    if not files:
        sys.stderr.write(proc.stdout[-4000:] + proc.stderr[-4000:])
        raise SystemExit(f"scanner produced no JSON report (exit {proc.returncode})")
    with open(files[-1], encoding="utf-8") as handle:
        report = json.load(handle)
    report["_meta"] = {"seconds": round(time.time() - started, 2),
                       "returncode": proc.returncode, "args": cmd[1:]}
    return report


def print_table(result: dict) -> None:
    width = max(len(f"{row['path']} {row['param']}") for row in result["rows"]) + 2
    print(f"{'endpoint':<{width}}{'expected':<11}{'result':<8}{'context'}")
    for row in result["rows"]:
        name = f"{row['path']} {row['param']}"
        flag = "" if row["context_ok"] else "  (context differs)"
        print(f"{name:<{width}}{row['expected']:<11}{row['result']:<8}{row['context']}{flag}")
    if result["unexpected_findings"]:
        print("\nfindings outside the labelled corpus:")
        for item in result["unexpected_findings"]:
            print(f"  {item['url']} [{item['parameter']}] {item['context']}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", action="store_true",
                        help="require browser-confirmed execution for a true positive")
    parser.add_argument("--min-recall", type=float, default=1.0)
    parser.add_argument("--out", default=os.path.join(ROOT, "bench", "results.json"))
    # Unknown flags are forwarded to the scanner, so --level/--delay/... work
    # here without this runner having to mirror the whole CLI.
    args, extra = parser.parse_known_args()

    server, _thread = serve_in_thread(0)
    base = f"http://127.0.0.1:{server.server_port}"
    tmp = tempfile.mkdtemp(prefix="xssmap-bench-")
    try:
        problems = check_lab(base)
        if problems:
            for problem in problems:
                print(f"LABEL FAIL  {problem}")
            print("refusing to score against labels the lab does not match")
            return 2
        report = run_scanner(base, tmp, args.browser, extra)
    finally:
        server.shutdown()
        server.server_close()

    result = score(report, LABELS, require_confirmed=args.browser)
    print_table(result)
    print()
    print(f"TP {result['tp']}  FP {result['fp']}  FN {result['fn']}  TN {result['tn']}")
    print(f"precision {result['precision']:.3f}  recall {result['recall']:.3f}  "
          f"F1 {result['f1']:.3f}   ({report['_meta']['seconds']}s)")

    payload = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "mode": "browser" if args.browser else "reflection",
        "scanner": report["_meta"]["args"],
        "metrics": {k: result[k] for k in ("tp", "fp", "fn", "tn",
                                           "precision", "recall", "f1")},
        "rows": result["rows"],
        "unexpected_findings": result["unexpected_findings"],
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    print(f"results written to {args.out}")

    if result["fp"]:
        print("FAIL: a safe endpoint was reported")
        return 1
    if result["recall"] < args.min_recall:
        print(f"FAIL: recall {result['recall']:.3f} < {args.min_recall:.3f}")
        return 1
    if result["fn"]:
        print("FAIL: a vulnerable endpoint was missed")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
