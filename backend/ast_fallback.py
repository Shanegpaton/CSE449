"""
Fallback security scan, used when Joern is not running.
  - Python: AST walk with taint tracking inside one file and one scope.
  - JavaScript: line-based pattern scan.
Limits (the reason Joern exists): no flow through function calls or returns,
no cross-file flow, and any dynamically built SQL string is flagged even when
it is built from constants.
"""
import ast
import re

from rules import RULES

PY_SOURCES = [
    r"\brequest\.(args|form|json|get_json|values|cookies|headers|data|files)\b",
    r"^input\(",
    r"\bsys\.argv\b",
]
JS_SOURCES = [r"\breq\.(body|query|params|cookies|headers)\b", r"\bprocess\.argv\b",
              r"\b(window|document)\.location\b"]

PY_SINKS = {"execute": "sql", "executemany": "sql", "executescript": "sql",
            "system": "cmd", "popen": "cmd", "eval": "code", "exec": "code"}
SUBPROCESS_CALLS = {"run", "call", "Popen", "check_output", "check_call"}


def _text(node) -> str:
    return ast.unparse(node)


def _is_source(node) -> bool:
    t = _text(node)
    return any(re.search(p, t) for p in PY_SOURCES)


def _is_dynamic_string(node) -> bool:
    """f-string, "..." + x, "..." % x, or "...".format(x)"""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return node.func.attr == "format"
    return False


def python_security(tree, code):
    lines = code.splitlines()
    tainted = {}     # var name -> line where taint came in
    dynamic = set()  # vars built with string formatting

    # Route handler params (Flask @app.route) are user input
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if any(re.search(r"\.(route|get|post|put|delete|patch)\(", _text(d)) for d in fn.decorator_list):
                for a in fn.args.args:
                    tainted[a.arg] = fn.lineno

    # Propagate taint through assignments until nothing changes
    assigns = [n for n in ast.walk(tree) if isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign))]
    changed = True
    while changed:
        changed = False
        for n in assigns:
            value = n.value
            if value is None:
                continue
            targets = n.targets if isinstance(n, ast.Assign) else [n.target]
            names = [t.id for tgt in targets for t in ast.walk(tgt) if isinstance(t, ast.Name)]
            src_line = None
            if _is_source(value):
                src_line = n.lineno
            else:
                for x in ast.walk(value):
                    if isinstance(x, ast.Name) and x.id in tainted:
                        src_line = tainted[x.id]
                        break
            for name in names:
                if src_line and name not in tainted:
                    tainted[name] = src_line
                    changed = True
                if _is_dynamic_string(value) and name not in dynamic:
                    dynamic.add(name)
                    changed = True

    def taint_line(expr):
        if _is_source(expr):
            return expr.lineno
        for x in ast.walk(expr):
            if isinstance(x, ast.Name) and x.id in tainted:
                return tainted[x.id]
        return None

    def built_dynamically(expr):
        return _is_dynamic_string(expr) or (isinstance(expr, ast.Name) and expr.id in dynamic)

    findings = []
    for call in ast.walk(tree):
        if not isinstance(call, ast.Call) or not call.args:
            continue
        fname = _text(call.func)
        last = fname.split(".")[-1]
        first = call.args[0]
        rule = None

        if last in ("execute", "executemany", "executescript"):
            # Parameterized queries (static string + params tuple) are safe
            if built_dynamically(first):
                rule = "sql"
        elif last in ("eval", "exec", "system", "popen"):
            if built_dynamically(first) or taint_line(first):
                rule = PY_SINKS[last]
        elif fname.startswith("subprocess.") and last in SUBPROCESS_CALLS:
            shell = any(k.arg == "shell" and _text(k.value) == "True" for k in call.keywords)
            if shell and (built_dynamically(first) or taint_line(first)):
                rule = "cmd"

        if rule:
            src = taint_line(first)
            findings.append({
                "rule": rule,
                "type": RULES[rule]["type"],
                "cwe": RULES[rule]["cwe"],
                "severity": "critical" if src else "high",
                "line": call.lineno,
                "sink": fname,
                "source_line": src,
                "evidence": lines[call.lineno - 1].strip(),
                "message": (f"User input from line {src} reaches {fname}() on line {call.lineno}."
                            if src else f"{fname}() receives a dynamically built string."),
            })
    return findings


def js_security(code):
    out = []
    has_source = any(re.search(p, code) for p in JS_SOURCES)
    checks = [
        (r"\.(query|raw|execute)\(\s*(`[^`]*\$\{|['\"][^'\"]*['\"]\s*\+)", "sql"),
        (r"\beval\(", "code"),
        (r"\bexec(Sync)?\(\s*(`[^`]*\$\{|['\"][^'\"]*['\"]\s*\+)", "cmd"),
        (r"\.innerHTML\s*=\s*(?!['\"`][^$+]*['\"`]\s*;?$)", "xss"),
        (r"\bdocument\.write\(", "xss"),
    ]
    for i, line in enumerate(code.splitlines(), 1):
        for pattern, rule in checks:
            if re.search(pattern, line):
                kind = RULES[rule]["type"]
                out.append({"rule": rule, "type": kind, "cwe": RULES[rule]["cwe"],
                            "severity": "critical" if has_source else "high",
                            "line": i, "sink": None, "source_line": None,
                            "evidence": line.strip(),
                            "message": f"Possible {kind.lower()} (pattern match)."})
    return out
