"""
The three non-security checks. They run the same way with or without Joern.

  logic errors    python_correctness / js_correctness
  context gaps    python_context_gaps      (code depends on things it was never given)
  hallucinations  python_hallucinations / js_hallucinations   (APIs that do not exist)

Every finding is {"line", "issue", "fix"}; "fix" feeds the overall recommendation
("item" fills the {items} slot when several findings share one fix).
"""
import ast
import builtins
import difflib
import importlib
import re
import sys
import types

# ══ Logic errors ══════════════════════════════════════════════════════════════
_STOPS = (ast.Return, ast.Raise, ast.Break, ast.Continue)


def _always_exits(stmts) -> bool:
    """True if this block always ends in return/raise."""
    if not stmts:
        return False
    last = stmts[-1]
    if isinstance(last, (ast.Return, ast.Raise)):
        return True
    if isinstance(last, ast.If):
        return _always_exits(last.body) and _always_exits(last.orelse)
    if isinstance(last, ast.Try):
        if last.finalbody and _always_exits(last.finalbody):
            return True
        return (_always_exits(last.body) or _always_exits(last.orelse)) and \
            all(_always_exits(h.body) for h in last.handlers)
    if isinstance(last, (ast.With, ast.AsyncWith)):
        return _always_exits(last.body)
    if isinstance(last, ast.While):
        endless = isinstance(last.test, ast.Constant) and bool(last.test.value)
        return endless and not any(isinstance(n, ast.Break) for n in ast.walk(last))
    if isinstance(last, ast.Match):
        has_default = any(isinstance(c.pattern, ast.MatchAs) and c.pattern.pattern is None and c.guard is None
                          for c in last.cases)
        return has_default and all(_always_exits(c.body) for c in last.cases)
    return False


def _own_nodes(fn):
    """Nodes of a function, without the bodies of functions or classes nested in it."""
    stack = list(fn.body)
    while stack:
        n = stack.pop()
        yield n
        if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            stack.extend(ast.iter_child_nodes(n))


def python_correctness(tree):
    out = []

    def add(node, issue, fix):
        out.append({"line": node.lineno, "issue": issue, "fix": fix})

    for n in ast.walk(tree):
        # Unreachable code
        for field in ("body", "orelse", "finalbody"):
            block = getattr(n, field, None)
            if isinstance(block, list):
                for stmt, nxt in zip(block, block[1:]):
                    if isinstance(stmt, _STOPS):
                        word = type(stmt).__name__.lower()
                        add(nxt, f"Unreachable code after '{word}' on line {stmt.lineno}.",
                            "Remove the dead code or move it before the statement that exits.")
                        break

        if isinstance(n, ast.ExceptHandler):
            only_pass = all(isinstance(s, ast.Pass) or
                            (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)) for s in n.body)
            if n.type is None:
                add(n, "Bare except hides all errors, including typos and Ctrl+C.",
                    "Catch the specific exception you expect.")
            elif only_pass and ast.unparse(n.type) in ("Exception", "BaseException"):
                add(n, "Every exception is caught and silently ignored.",
                    "Handle the error or at least log it.")

        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for d in n.args.defaults + [d for d in n.args.kw_defaults if d is not None]:
                if isinstance(d, (ast.List, ast.Dict, ast.Set)):
                    add(n, f"Mutable default argument in {n.name}() is shared between calls.",
                        "Default to None and create the list/dict inside the function.")
            own = list(_own_nodes(n))
            returns_value = any(isinstance(x, ast.Return) and x.value is not None and
                                not (isinstance(x.value, ast.Constant) and x.value.value is None) for x in own)
            is_generator = any(isinstance(x, (ast.Yield, ast.YieldFrom)) for x in own)
            if returns_value and not is_generator and not _always_exits(n.body):
                add(n, f"{n.name}() returns a value on some paths and None on others.",
                    "Add a return (or raise) for every path through the function.")

        if isinstance(n, ast.Compare):
            for op, c in zip(n.ops, n.comparators):
                if isinstance(op, (ast.Eq, ast.NotEq)) and isinstance(c, ast.Constant) and c.value is None:
                    add(n, "Comparison to None with '==' can be overridden by the object.",
                        "Use 'is None' / 'is not None'.")
                if isinstance(op, (ast.Is, ast.IsNot)) and isinstance(c, ast.Constant) and \
                        isinstance(c.value, (str, int, float, bytes)) and not isinstance(c.value, bool):
                    add(n, "'is' compares identity, not value; with a literal the result is unreliable.",
                        "Use '==' to compare values.")

        if isinstance(n, ast.Expr) and isinstance(n.value, ast.Compare):
            add(n, "Comparison result is not used; this statement does nothing.",
                "If an assignment was intended, use '='.")

        if isinstance(n, ast.Assert) and isinstance(n.test, ast.Tuple) and n.test.elts:
            add(n, "assert on a tuple is always true.", "Write assert condition, \"message\" without parentheses.")

        if isinstance(n, ast.Call) and ast.unparse(n.func) == "range" and n.args:
            if re.match(r"len\(.+\)\s*\+\s*1$", ast.unparse(n.args[-1])):
                add(n, "range(len(x) + 1) runs one index past the end.", "Use range(len(x)).")

        if isinstance(n, ast.For) and isinstance(n.iter, ast.Name):
            for x in ast.walk(n):
                if isinstance(x, ast.Call) and isinstance(x.func, ast.Attribute) and \
                        isinstance(x.func.value, ast.Name) and x.func.value.id == n.iter.id and \
                        x.func.attr in ("remove", "pop", "append", "insert", "clear"):
                    add(x, f"'{n.iter.id}' is modified while it is being looped over, so items get skipped.",
                        f"Loop over a copy ({n.iter.id}[:]) or build a new list.")
                    break

        if isinstance(n, ast.While) and not isinstance(n.test, ast.Constant):
            names = {x.id for x in ast.walk(n.test) if isinstance(x, ast.Name)}
            simple = all(isinstance(x, (ast.Name, ast.Constant, ast.Compare, ast.BoolOp, ast.UnaryOp, ast.BinOp,
                                        ast.expr_context, ast.cmpop, ast.boolop, ast.unaryop, ast.operator))
                         for x in ast.walk(n.test))
            if names and simple:
                body = [x for s in n.body for x in ast.walk(s)]
                changed = any(isinstance(x, ast.Name) and isinstance(x.ctx, ast.Store) and x.id in names for x in body)
                touched = any(isinstance(x, (ast.Attribute, ast.Subscript)) and isinstance(x.value, ast.Name) and
                              x.value.id in names for x in body)
                passed = any(isinstance(x, ast.Call) and
                             any(isinstance(a, ast.Name) and a.id in names for a in x.args) for x in body)
                leaves = any(isinstance(x, (ast.Break, ast.Return, ast.Raise, ast.Global, ast.Nonlocal)) for x in body)
                counting = any(isinstance(x, (ast.Lt, ast.LtE, ast.Gt, ast.GtE)) for x in ast.walk(n.test))
                if not (changed or touched or leaves or (passed and not counting)):
                    add(n, f"Loop condition never changes ({', '.join(sorted(names))} is not updated): infinite loop.",
                        "Update the loop variable inside the loop.")
    return _dedupe(out)


def js_correctness(code):
    out = []
    for i, line in enumerate(code.splitlines(), 1):
        if re.search(r"[^=!<>]==[^=]", line):
            out.append({"line": i, "issue": "'==' converts types before comparing.", "fix": "Use '==='."})
        if re.search(r"catch\s*(\(\w*\))?\s*\{\s*\}", line):
            out.append({"line": i, "issue": "Empty catch block hides errors.", "fix": "Handle or log the error."})
        if re.search(r"\b(if|while)\s*\([^=!<>()]*[^=!<>]=[^=>][^()]*\)", line):
            out.append({"line": i, "issue": "Assignment inside a condition; it is always the assigned value.",
                        "fix": "Use '===' to compare."})
    return out


# ══ Context gaps ══════════════════════════════════════════════════════════════
# Module names that almost always mean "a file in my own project"
LOCAL_MODULE_NAMES = {"utils", "util", "helpers", "helper", "config", "settings", "models", "model", "db",
                      "database", "auth", "constants", "common", "schemas", "services", "service", "app",
                      "extensions", "forms", "views", "routes", "crud", "dependencies", "core"}
_IMPLICIT = {"__file__", "__name__", "__doc__", "__builtins__", "__spec__", "__package__", "__class__",
             "__path__", "__annotations__", "__dict__", "__debug__"}


def python_context_gaps(tree, local_modules=None):
    """
    local_modules: names of the other modules submitted with this file (project mode).
    None means a single pasted snippet, where no other file exists.
    """
    out = []
    star_import = False
    defined = set(dir(builtins)) | _IMPLICIT
    used = {}
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            defined.add(n.name)
        elif isinstance(n, ast.arg):
            defined.add(n.arg)
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            for a in n.names:
                if a.name == "*":
                    star_import = True
                defined.add((a.asname or a.name).split(".")[0])
            module = (n.module or "") if isinstance(n, ast.ImportFrom) else None
            roots = [module.split(".")[0]] if module else [a.name.split(".")[0] for a in n.names]
            if isinstance(n, ast.ImportFrom) and n.level > 0:
                name = "." * n.level + (n.module or "")
                root = (n.module or n.names[0].name).split(".")[0]
                if local_modules is None or root not in local_modules:
                    out.append({"line": n.lineno,
                                "issue": f"Relative import '{name}' needs a project file that was not provided.",
                                "fix": f"Provide '{name}' or include the needed code in this file."})
            else:
                for root in roots:
                    if root in LOCAL_MODULE_NAMES and root not in sys.stdlib_module_names and \
                            (local_modules is None or root not in local_modules):
                        out.append({"line": n.lineno,
                                    "issue": f"Import of '{root}' looks like a project file that was not provided.",
                                    "fix": f"Confirm '{root}' exists in the project and exports what is imported."})
        elif isinstance(n, ast.ExceptHandler) and n.name:
            defined.add(n.name)
        elif isinstance(n, (ast.Global, ast.Nonlocal)):
            defined.update(n.names)
        elif isinstance(n, (ast.MatchAs, ast.MatchStar)) and n.name:
            defined.add(n.name)
        elif isinstance(n, ast.MatchMapping) and n.rest:
            defined.add(n.rest)
        elif isinstance(n, ast.Name):
            if isinstance(n.ctx, (ast.Store, ast.Del)):
                defined.add(n.id)
            else:
                used.setdefault(n.id, n.lineno)
    if not star_import:
        for name, line in used.items():
            if name not in defined:
                out.append({"line": line, "issue": f"'{name}' is used but never defined or imported.",
                            "item": name, "fix": "Define or import {items}, or pass them in as parameters."})
    return sorted(_dedupe(out), key=lambda f: f["line"])


# ══ Hallucinated APIs ═════════════════════════════════════════════════════════
# Standard-library modules are imported and inspected, so any made-up attribute is caught.
_NO_IMPORT = {"antigravity", "this", "idlelib", "tkinter", "turtle", "turtledemo", "__main__",
              "__hello__", "__phello__"}
# These differ between Windows and Linux, so they are only checked against the lists below.
_PLATFORM = {"os", "signal", "socket", "select", "resource", "fcntl", "pwd", "grp", "termios", "tty", "pty",
             "curses", "readline", "msvcrt", "winreg", "winsound", "asyncio", "multiprocessing", "time",
             "shutil", "subprocess", "mmap", "errno", "stat", "posix", "nt", "sys", "ssl", "locale"}

# Known inventions -> what to use instead (also covers third-party libraries, which are never imported here)
KNOWN_BAD = {
    "json.parse": "json.loads", "json.stringify": "json.dumps",
    "os.exec": "subprocess.run", "os.make_dir": "os.mkdir or os.makedirs", "os.delete": "os.remove",
    "os.path.exist": "os.path.exists", "os.read_file": "open(path).read()",
    "sys.args": "sys.argv", "time.now": "time.time() or datetime.now()",
    "subprocess.execute": "subprocess.run", "shutil.delete": "shutil.rmtree or os.remove",
    "requests.fetch": "requests.get", "requests.get_json": "requests.get(url).json()",
    "pandas.read_db": "pandas.read_sql", "pandas.read_database": "pandas.read_sql",
    "pandas.load_csv": "pandas.read_csv", "numpy.length": "len() or numpy.size",
    "flask.json_response": "flask.jsonify", "flask.get_request": "flask.request",
    "datetime.datetime.now_utc": "datetime.now(timezone.utc)", "math.round": "round()",
    "random.random_int": "random.randint", "re.find": "re.search or re.findall",
    "hashlib.hash": "hashlib.sha256", "string.contains": "the 'in' operator",
}
# Third-party modules whose whole public surface is small and stable enough to list
KNOWN_API = {
    "requests": {"get", "post", "put", "patch", "delete", "head", "options", "request", "Session", "session",
                 "Request", "PreparedRequest", "Response", "exceptions", "codes", "adapters", "auth", "cookies",
                 "utils", "structures", "models", "status_codes", "api", "sessions", "hooks", "compat", "certs",
                 "packages", "RequestException", "Timeout", "URLRequired", "TooManyRedirects", "HTTPError",
                 "ConnectionError", "FileModeWarning", "ConnectTimeout", "ReadTimeout", "JSONDecodeError",
                 "check_compatibility", "__version__"},
}
DEFAULT_ALIASES = {"pd": "pandas", "np": "numpy", "plt": "matplotlib.pyplot"}

# Methods AI tools carry over from other languages
METHOD_HINTS = {
    ("list", "push"): "append()", ("list", "add"): "append()", ("list", "push_back"): "append()",
    ("list", "length"): "len(x)", ("list", "size"): "len(x)", ("list", "contains"): "the 'in' operator",
    ("list", "includes"): "the 'in' operator", ("list", "find"): "index() or the 'in' operator",
    ("list", "remove_at"): "pop(i)", ("list", "join"): "'sep'.join(x)", ("list", "map"): "a list comprehension",
    ("list", "filter"): "a list comprehension", ("list", "first"): "x[0]", ("list", "last"): "x[-1]",
    ("str", "contains"): "the 'in' operator", ("str", "includes"): "the 'in' operator",
    ("str", "length"): "len(x)", ("str", "trim"): "strip()", ("str", "to_upper"): "upper()",
    ("str", "to_lower"): "lower()", ("str", "toUpperCase"): "upper()", ("str", "toLowerCase"): "lower()",
    ("str", "substring"): "slicing x[a:b]", ("str", "starts_with"): "startswith()",
    ("str", "ends_with"): "endswith()", ("str", "reverse"): "x[::-1]", ("str", "push"): "x + y",
    ("dict", "has_key"): "the 'in' operator", ("dict", "contains"): "the 'in' operator",
    ("dict", "put"): "x[key] = value", ("dict", "add"): "x[key] = value", ("dict", "length"): "len(x)",
    ("dict", "remove"): "pop(key) or del x[key]", ("dict", "has"): "the 'in' operator",
    ("set", "push"): "add()", ("set", "append"): "add()", ("set", "contains"): "the 'in' operator",
    ("set", "has"): "the 'in' operator", ("tuple", "append"): "a list (tuples cannot change)",
}
_LITERAL_TYPES = {ast.List: list, ast.ListComp: list, ast.Dict: dict, ast.DictComp: dict, ast.Set: set,
                  ast.SetComp: set, ast.JoinedStr: str, ast.Tuple: tuple}
_modules = {}


def _stdlib(name):
    """Import a standard-library module by dotted name, or return None."""
    if name not in _modules:
        mod = None
        root = name.split(".")[0]
        if root in sys.stdlib_module_names and root not in _NO_IMPORT and not root.startswith("_"):
            try:
                mod = importlib.import_module(name)
            except Exception:
                mod = None
        _modules[name] = mod
    return _modules[name]


def _literal_type(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return str
    for cls, typ in _LITERAL_TYPES.items():
        if isinstance(node, cls):
            return typ
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and \
            node.func.id in ("list", "dict", "set", "str", "tuple"):
        return getattr(builtins, node.func.id)
    return None


def _chain(node):
    """a.b.c -> ['a', 'b', 'c'] when the base is a plain name."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        return [node.id] + parts[::-1]
    return None


def python_hallucinations(tree, project_modules=None):
    """
    project_modules: {module name: set of top-level names, or None if unknown} for the other
    submitted files, so imports between project files are checked too.
    """
    out = []
    project_modules = project_modules or {}

    def add(node, what, hint=None, close_to=None):
        if not hint and close_to:
            near = difflib.get_close_matches(what.split(".")[-1], close_to, n=1, cutoff=0.6)
            hint = ".".join(what.split(".")[:-1] + [near[0]]) if near else None
        out.append({"line": node.lineno, "issue": f"{what} does not exist.",
                    "fix": f"Replace {what} with {hint}." if hint else f"Replace {what} with a real API."})

    # 1. What each name refers to
    aliases = {}          # local name -> dotted module name
    rebound = set()       # names that are also assigned, so they may not be the module any more
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.asname:
                    aliases[a.asname] = a.name
                else:
                    aliases[a.name.split(".")[0]] = a.name.split(".")[0]
        elif isinstance(n, ast.ImportFrom) and n.level == 0 and n.module:
            exported = project_modules.get(n.module)
            mod = None if n.module in project_modules else _stdlib(n.module)
            for a in n.names:
                if a.name == "*":
                    continue
                full = f"{n.module}.{a.name}"
                if full in KNOWN_BAD:
                    add(n, full, KNOWN_BAD[full])
                elif exported is not None and a.name not in exported:
                    add(n, f"{n.module}.{a.name}", close_to=sorted(exported))
                elif mod is not None and n.module.split(".")[0] not in _PLATFORM and not hasattr(mod, a.name) \
                        and _stdlib(full) is None:
                    add(n, full, close_to=dir(mod))
                elif n.module in KNOWN_API and a.name not in KNOWN_API[n.module]:
                    add(n, full, close_to=sorted(KNOWN_API[n.module]))
                else:
                    aliases[a.asname or a.name] = full
        elif isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
            rebound.add(n.id)
        elif isinstance(n, ast.arg):
            rebound.add(n.arg)
    for short, full in DEFAULT_ALIASES.items():
        aliases.setdefault(short, full)

    # 2. Attribute chains on modules: json.parse, requests.fetch, pd.read_db, auth.login_user
    seen = set()
    for n in ast.walk(tree):
        if not isinstance(n, ast.Attribute):
            continue
        chain = _chain(n)
        if not chain or chain[0] not in aliases or chain[0] in rebound:
            continue
        dotted = aliases[chain[0]].split(".") + chain[1:]
        for i in range(2, len(dotted) + 1):
            prefix = ".".join(dotted[:i])
            label = ".".join(chain[:len(chain) - (len(dotted) - i)])
            if (n.lineno, label) in seen:
                break
            module, attr = ".".join(dotted[:i - 1]), dotted[i - 1]
            bad = None
            if prefix in KNOWN_BAD:
                bad = (KNOWN_BAD[prefix], None)
            elif module in project_modules:
                exported = project_modules[module]
                if exported is not None and attr not in exported:
                    bad = (None, sorted(exported))
            elif module in KNOWN_API and attr not in KNOWN_API[module]:
                bad = (None, sorted(KNOWN_API[module]))
            else:
                obj = _stdlib(dotted[0]) if dotted[0] not in _PLATFORM else None
                for part in dotted[1:i - 1]:
                    obj = getattr(obj, part, None) if isinstance(obj, (types.ModuleType, type)) else None
                if isinstance(obj, (types.ModuleType, type)) and not hasattr(obj, attr) and \
                        not (isinstance(obj, types.ModuleType) and _stdlib(prefix) is not None):
                    bad = (None, [x for x in dir(obj) if not x.startswith("_")])
            if bad:
                seen.add((n.lineno, label))
                add(n, label, bad[0], bad[1])
                break

    # 3. Methods that do not exist on built-in types: items.push(x), text.contains("a"), d.has_key(k)
    literal_types, literal_count, stores = {}, {}, {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
            stores[n.id] = stores.get(n.id, 0) + 1
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            typ = _literal_type(n.value)
            if typ is not None:
                name = n.targets[0].id
                literal_types.setdefault(name, set()).add(typ)
                literal_count[name] = literal_count.get(name, 0) + 1
    params = {n.arg for n in ast.walk(tree) if isinstance(n, ast.arg)}

    for n in ast.walk(tree):
        if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)):
            continue
        recv, method = n.func.value, n.func.attr
        typ = _literal_type(recv)
        if typ is None and isinstance(recv, ast.Name):
            name = recv.id
            # only when every binding of the name is a literal of one built-in type
            if len(literal_types.get(name, ())) == 1 and stores.get(name) == literal_count.get(name) \
                    and name not in params:
                typ = next(iter(literal_types[name]))
        if typ is not None and not hasattr(typ, method):
            label = f"{typ.__name__}.{method}()"
            hint = METHOD_HINTS.get((typ.__name__, method))
            out.append({"line": n.lineno,
                        "issue": f"{label} does not exist ({ast.unparse(n.func)}).",
                        "fix": f"Use {hint} instead of .{method}()." if hint
                        else f"Replace .{method}() with a real {typ.__name__} method."})
    return sorted(_dedupe(out), key=lambda f: f["line"])


JS_KNOWN_BAD = [
    (r"\bres\.send_json\(", "res.json()"), (r"\bres\.sendJson\(", "res.json()"),
    (r"\bJSON\.decode\(", "JSON.parse()"), (r"\bJSON\.encode\(", "JSON.stringify()"),
    (r"\b(arr|array|list|items|names|ids|values|str|string|text)\w*\.contains\(", "includes()"),
    (r"\bfs\.readFileAsync\(", "fs.promises.readFile()"),
    (r"\bconsole\.print\(", "console.log()"),
    (r"\bObject\.length\(", "Object.keys(x).length"), (r"\bArray\.range\(", "Array.from({length: n}, (_, i) => i)"),
    (r"\b\w+\.push_back\(", "push()"),
    (r"\bfetch\.get\(", "fetch(url)"), (r"\bfs\.exists_sync\(", "fs.existsSync()"),
    (r"\bString\.format\(", "a template literal"), (r"\b\w+\.has_key\(", "the 'in' operator or hasOwnProperty()"),
]


def js_hallucinations(code):
    out = []
    for i, line in enumerate(code.splitlines(), 1):
        for pattern, hint in JS_KNOWN_BAD:
            m = re.search(pattern, line)
            if not m:
                continue
            what = m.group(0).rstrip("('\"`[{ ").rstrip("(")
            what = re.sub(r"\(.*$", "", what)
            out.append({"line": i, "issue": f"{what}() does not exist.", "fix": f"Use {hint} instead of {what}()."})
    return _dedupe(out)


def top_level_names(tree):
    """Names a module exports, or None when that cannot be known (star import)."""
    names = set()
    for n in tree.body:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(n.name)
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            for a in n.names:
                if a.name == "*":
                    return None
                names.add((a.asname or a.name).split(".")[0])
        else:
            for x in ast.walk(n):
                if isinstance(x, ast.Name) and isinstance(x.ctx, ast.Store):
                    names.add(x.id)
    return names


def _dedupe(findings):
    seen, out = set(), []
    for f in findings:
        key = (f["line"], f["issue"])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out
