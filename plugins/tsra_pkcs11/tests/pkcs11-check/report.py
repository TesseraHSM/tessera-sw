#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Judge a pkcs11-check run by its report files. run.sh calls this; the tool's
own exit status says nothing useful, it is non-zero whenever any test fails.

    report.py gate|full <out-dir> <include-list> <baseline>

A test's outcome is its call-phase record in report.jsonl: passed, failed, or
xfailed (an xfail is a skipped record with wasxfail). A test without a call
record was skipped or broke in set-up, and a test whose teardown fails after
it passed is an error too. Crashes come from results.json, where the isolated
runner records the tests a crashing child process took down.

gate: every listed test passed, and nothing crashed except the baseline's
known crashes (the gate runs whole files, so it meets them too).
full: the same, and every test that passed is listed or in the baseline with
a reason.
"""
import json
import os
import re
import sys
from collections import Counter

# Node ids are relative to wherever the package is installed; keep the part
# inside the package ("testcases/...").
NODE_PREFIX = re.compile(r"^.*?pkcs11_check/")


def node(nodeid):
    return NODE_PREFIX.sub("", nodeid)


def names(path):
    with open(path) as f:
        return [l.strip() for l in f if l.strip() and not l.lstrip().startswith("#")]


def outcomes(out_dir):
    """Map every test to its outcome, crashes taking precedence."""
    result = {}
    with open(os.path.join(out_dir, "report.jsonl")) as f:
        for line in f:
            r = json.loads(line)
            if r.get("$report_type") != "TestReport":
                continue
            n = node(r["nodeid"])
            if r["when"] == "call":
                xfail = (r["outcome"] == "skipped") and (r.get("wasxfail") is not None)
                result[n] = "xfailed" if xfail else r["outcome"]
            elif (r["when"] == "setup") and (r["outcome"] != "passed"):
                result.setdefault(n, "skipped" if r["outcome"] == "skipped" else "error")
            elif r["when"] == "teardown":
                if (r["outcome"] == "failed") and (result.get(n) == "passed"):
                    result[n] = "error"
    with open(os.path.join(out_dir, "results.json")) as f:
        units = json.load(f)["units"]
    for u in units:
        for t in u.get("tests", []):
            if t["outcome"] == "crashed":
                result[node(t["nodeid"])] = "crashed"
        if (u["status"] == "crashed") and not any(
            t["outcome"] == "crashed" for t in u.get("tests", [])
        ):
            result[node(u["target"]) + " (whole file)"] = "crashed"
    return result


def report(title, items):
    if items:
        print(f"--- {title} ({len(items)}) ---")
        for i in items:
            print(f"  {i}")
    return len(items)


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if (mode not in ("gate", "full")) or (len(sys.argv) != 5):
        sys.exit(__doc__)
    result = outcomes(sys.argv[2])
    listed = names(sys.argv[3])
    baseline = {}
    for line in names(sys.argv[4]):
        tag, n = line.split(None, 1)
        baseline[n] = tag

    bad = report(
        "listed but not passed",
        [f"{n}: {result.get(n, 'not run')}" for n in listed if result.get(n) != "passed"],
    )
    known = {n for n, t in baseline.items() if t == "crash"}
    crashed = sorted(n for n, o in result.items() if o == "crashed")
    bad += report("crashed", [n for n in crashed if n not in known])
    if mode == "full":
        listed_set = set(listed)
        bad += report(
            "passed but neither listed nor in the baseline (put it on the list)",
            sorted(n for n, o in result.items()
                   if (o == "passed") and (n not in listed_set) and (n not in baseline)),
        )
        report("known crashes that no longer crash (drop them from the baseline)",
               sorted(n for n in known if result.get(n) != "crashed"))
        report("baseline passes that no longer pass",
               sorted(n for n, t in baseline.items() if (t != "crash") and (result.get(n) != "passed")))

    counts = Counter(result.values())
    passed = sum(1 for n in listed if result.get(n) == "passed")
    print(f"pkcs11-check {mode}: {passed}/{len(listed)} listed tests passed; run totals "
          + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
