"""
Analysis pipeline for the AI Code Security Analyzer.

Four checks, one verdict:
  security        Joern taint tracking (joern_engine.py), or the AST fallback when Joern is not running
  logic errors    checks.python_correctness
  context gaps    checks.python_context_gaps
  hallucinations  checks.python_hallucinations
Then _recommend() turns the findings into Accept / Review / Reject plus what to do next.

Entry points: analyze() for one pasted snippet, analyze_project() for several Python files.
"""
import ast

import ast_fallback
import checks
import joern_engine
from rules import RULES

MAX_STEPS = 8


def analyze(prompt: str, code: str, language: str) -> dict:
    if language != "python":
        return _report(language, "pattern_scan", "JavaScript uses the pattern scan; Joern covers Python.",
                       ast_fallback.js_security(code), checks.js_correctness(code), [],
                       checks.js_hallucinations(code))
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return _syntax_error_report(language, e)

    security, engine, note = _python_security({"snippet.py": code}, {"snippet.py": tree})
    return _report(language, engine, note, security, checks.python_correctness(tree),
                   checks.python_context_gaps(tree), checks.python_hallucinations(tree))


def analyze_project(files: dict) -> dict:
    """files: {relative path: source} for the Python files of one project."""
    trees, correctness = {}, []
    for path, code in sorted(files.items()):
        try:
            trees[path] = ast.parse(code)
        except SyntaxError as e:
            correctness.append({"file": path, "line": e.lineno or 1, "issue": f"Syntax error: {e.msg}",
                                "fix": "Fix the syntax error so the file can be analyzed."})
    if not trees:
        report = _syntax_error_report("python", SyntaxError("no parsable Python files"))
        report["correctness"]["findings"] = [dict(f) for f in correctness] or report["correctness"]["findings"]
        for f in report["correctness"]["findings"]:
            f.pop("fix", None)
        return report

    # What each submitted module exports, so imports between the files can be checked
    exports, local = {}, set()
    for path, tree in trees.items():
        parts = path[:-3].split("/")
        if parts[-1] == "__init__":
            parts = parts[:-1]
        names = checks.top_level_names(tree)
        for i in range(len(parts)):
            exports[".".join(parts[i:])] = names
        local.update(parts)

    context_gaps, hallucinations = [], []
    for path, tree in trees.items():
        correctness += _tag(checks.python_correctness(tree), path)
        context_gaps += _tag(checks.python_context_gaps(tree, local_modules=local), path)
        hallucinations += _tag(checks.python_hallucinations(tree, project_modules=exports), path)

    security, engine, note = _python_security({p: files[p] for p in trees}, trees)
    return _report("python", engine, note, security, correctness, context_gaps, hallucinations)


def _tag(findings, path):
    return [dict(f, file=path) for f in findings]


def _python_security(files, trees):
    """Joern when it is up and passes its self-test, otherwise the AST fallback. Returns (findings, engine, note)."""
    note = None
    state = joern_engine.status()
    if state == "ok":
        try:
            return joern_engine.analyze_files(files)["findings"], "joern", None
        except joern_engine.JoernError as e:
            note = f"Joern failed, used the AST fallback instead: {e}"
    elif state != "off":
        note = f"Joern not used ({state}); ran the AST fallback."
    if joern_engine.USE_JOERN == "required":
        raise RuntimeError(note or "Joern is required but switched off.")

    findings = []
    for path, tree in trees.items():
        found = ast_fallback.python_security(tree, files[path])
        findings += _tag(found, path) if len(files) > 1 else found
    return findings, "ast_fallback", note


# ── Verdict and what to do next ───────────────────────────────────────────────
def _where(findings):
    spots = []
    for f in findings:
        spot = f"{f['file']}:{f['line']}" if f.get("file") else f"line {f['line']}"
        if spot not in spots:
            spots.append(spot)
    shown = ", ".join(spots[:4])
    return shown + (f" and {len(spots) - 4} more" if len(spots) > 4 else "")


def _recommend(security, correctness, context_gaps, hallucinations):
    sev = [f["severity"] for f in security]
    if "critical" in sev or "high" in sev:
        verdict, reason = "Reject", "Security vulnerabilities found."
        action = "Do not use this code. Fix the security issues first, then re-run the analysis."
    elif hallucinations:
        verdict, reason = "Reject", "Code calls APIs that do not exist."
        action = "Do not use this code. It will fail at runtime until the made-up APIs are replaced."
    elif correctness or context_gaps:
        verdict, reason = "Review", "No security issues, but logic or context problems need fixing."
        action = "Usable after a developer reviews and fixes the items below."
    else:
        verdict, reason = "Accept", "No issues found."
        action = ("No changes needed. Static analysis cannot prove code correct, so still run its tests "
                  "before merging.")

    steps = []
    by_rule = {}
    for f in security:
        by_rule.setdefault(f["rule"], []).append(f)
    for rule, group in by_rule.items():
        steps.append(f"Fix {RULES[rule]['type']} ({_where(group)}): {RULES[rule]['fix']}")
    for label, group in (("Hallucinated API", hallucinations), ("Context gap", context_gaps),
                         ("Logic error", correctness)):
        by_fix = {}
        for f in group:
            by_fix.setdefault(f.get("fix") or f["issue"], []).append(f)
        for fix, same in by_fix.items():
            items = [f["item"] for f in same if f.get("item")]
            steps.append(f"{label} ({_where(same)}): {fix.replace('{items}', ', '.join(dict.fromkeys(items)))}")
    if len(steps) > MAX_STEPS:
        steps = steps[:MAX_STEPS] + [f"{len(steps) - MAX_STEPS} more items are listed in the findings."]
    if steps and verdict != "Accept":
        steps.append("Re-run the analysis after the fixes.")

    return {
        "verdict": verdict,
        "reason": reason,
        "action": action,
        "steps": steps,
        "counts": {"security": len(security), "correctness": len(correctness),
                   "context_gaps": len(context_gaps), "hallucinations": len(hallucinations)},
    }


def _report(language, engine, note, security, correctness, context_gaps, hallucinations):
    recommendation = _recommend(security, correctness, context_gaps, hallucinations)
    for group in (security, correctness, context_gaps, hallucinations):
        for f in group:           # fixes are reported once, in the recommendation
            for key in ("fix", "rule", "item"):
                f.pop(key, None)
    return {
        "language": language,
        "engine": engine,
        "engine_note": note,
        "security": {"findings": security},
        "correctness": {"findings": correctness},
        "context_gaps": {"findings": context_gaps},
        "hallucinations": {"findings": hallucinations},
        "recommendation": recommendation,
    }


def _syntax_error_report(language, e):
    issue = {"line": e.lineno or 1, "issue": f"Syntax error: {e.msg}"}
    return {"language": language, "engine": "none", "engine_note": None,
            "security": {"findings": []}, "correctness": {"findings": [issue]},
            "context_gaps": {"findings": []}, "hallucinations": {"findings": []},
            "recommendation": {"verdict": "Reject", "reason": "Code does not parse.",
                               "action": "Do not use this code. It is not valid Python.",
                               "steps": [f"Fix the syntax error on line {e.lineno or 1}: {e.msg}.",
                                         "Re-run the analysis after the fix."],
                               "counts": {"security": 0, "correctness": 1, "context_gaps": 0,
                                          "hallucinations": 0}}}
