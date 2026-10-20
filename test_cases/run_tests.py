"""
Runs the 15 test cases through the analyzer and records expected vs. actual.

  py -3.12 test_cases/run_tests.py                 use Joern if it is running, else the fallback
  py -3.12 test_cases/run_tests.py --engine off    force the AST fallback (for the comparison)
  py -3.12 test_cases/run_tests.py --verbose       also print every finding

Writes test_cases/results/results_<engine>.md and .csv. Exit code 1 if any case fails unexpectedly.
A case marked needs_joern is expected to fail on the fallback; that is reported, not counted as a failure.
"""
import argparse
import csv
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SECTIONS = ["security", "correctness", "context_gaps", "hallucinations"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", choices=["auto", "off", "required"], default="auto")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    os.environ["USE_JOERN"] = args.engine
    sys.path.insert(0, str(HERE.parent / "backend"))
    import joern_engine
    from analyzer import analyze, analyze_project

    print(f"Joern status: {joern_engine.status()}\n")
    rows, engines = [], set()
    for case in json.loads((HERE / "cases.json").read_text(encoding="utf-8")):
        path = HERE / case["path"]
        if path.is_dir():
            files = {p.relative_to(path).as_posix(): p.read_text(encoding="utf-8") for p in sorted(path.rglob("*.py"))}
            report = analyze_project(files)
        else:
            report = analyze(case["prompt"], path.read_text(encoding="utf-8"), case.get("language", "python"))

        found = [s for s in SECTIONS if report[s]["findings"]]
        verdict = report["recommendation"]["verdict"]
        ok = verdict == case["expect_verdict"] and found == case["expect_findings"]
        if ok and case.get("expect_file"):
            ok = all(f.get("file") == case["expect_file"] for f in report["security"]["findings"])
        engine = report["engine"]
        engines.add(engine)
        if ok:
            result = "pass"
        elif case.get("needs_joern") and engine != "joern":
            result = "expected miss (needs Joern)"
        else:
            result = "FAIL"
        rows.append({"id": case["id"], "category": case["category"], "file": case["path"], "engine": engine,
                     "expected": case["expect_verdict"], "actual": verdict,
                     "expected_findings": ", ".join(case["expect_findings"]) or "none",
                     "actual_findings": ", ".join(found) or "none", "result": result, "why": case["why"]})
        print(f"{case['id']:<3} {result:<28} expected {case['expect_verdict']:<7} got {verdict:<7} "
              f"[{', '.join(found) or 'no findings'}]")
        if args.verbose or result == "FAIL":
            for s in SECTIONS:
                for f in report[s]["findings"]:
                    where = f"{f['file']}:{f['line']}" if f.get("file") else f"line {f['line']}"
                    print(f"      {s}: {where}: {f.get('message') or f.get('issue')}")
            print(f"      action: {report['recommendation']['action']}")
            for step in report["recommendation"]["steps"]:
                print(f"        - {step}")
            if report.get("engine_note"):
                print(f"      note: {report['engine_note']}")

    passed = sum(r["result"] == "pass" for r in rows)
    missed = sum(r["result"].startswith("expected miss") for r in rows)
    failed = sum(r["result"] == "FAIL" for r in rows)
    label = "joern" if "joern" in engines else "ast_fallback"
    summary = f"{passed}/{len(rows)} passed, {missed} expected misses, {failed} failed (Python engine: {label})"
    print("\n" + summary)

    out = HERE / "results"
    out.mkdir(exist_ok=True)
    with open(out / f"results_{label}.csv", "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    lines = [f"# Test results ({label})", "", summary, "",
             "| ID | Category | Expected | Actual | Findings in | Result |", "|---|---|---|---|---|---|"]
    lines += [f"| {r['id']} | {r['category']} | {r['expected']} | {r['actual']} | {r['actual_findings']} | {r['result']} |"
              for r in rows]
    (out / f"results_{label}.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
