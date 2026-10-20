"""
Joern engine: interprocedural, cross-file taint tracking on a Joern server.

Joern runs in Docker in server mode (see ../docker-compose.yml). For each analysis:
  1. the code is copied into joern_workspace/<job>/src   (Joern sees it as /work/<job>/src)
  2. importCode(...) builds the Code Property Graph
  3. taint_queries/python_taint.sc asks which sources reach which sinks and writes
     the answer to joern_workspace/<job>/result.json
  4. the flows are turned into findings in the same shape the API already returns

Settings (environment variables):
  USE_JOERN                auto (default) | off | required
  JOERN_URL                default http://localhost:8080
  JOERN_HOST_WORKDIR       default <repo>/joern_workspace
  JOERN_CONTAINER_WORKDIR  default /work
  JOERN_TIMEOUT            seconds per query, default 180
"""
import json
import os
import re
import shutil
import threading
import time
import uuid
from pathlib import Path

import requests

from rules import RULES, SINK_NAMES

USE_JOERN = os.environ.get("USE_JOERN", "auto").lower()
JOERN_URL = os.environ.get("JOERN_URL", "http://localhost:8080").rstrip("/")
HOST_WORKDIR = Path(os.environ.get("JOERN_HOST_WORKDIR",
                                   Path(__file__).resolve().parent.parent / "joern_workspace"))
CONTAINER_WORKDIR = os.environ.get("JOERN_CONTAINER_WORKDIR", "/work").rstrip("/")
TIMEOUT = int(os.environ.get("JOERN_TIMEOUT", "180"))
QUERY_FILE = Path(__file__).resolve().parent / "taint_queries" / "python_taint.sc"

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_lock = threading.Lock()      # the Joern server has one shared session
_status = {"value": None, "checked": 0.0}


class JoernError(Exception):
    pass


# ── Talking to the server ─────────────────────────────────────────────────────
def _run(query: str) -> str:
    """Run one CPGQL query and return its printed output."""
    try:
        r = requests.post(f"{JOERN_URL}/query-sync", json={"query": query}, timeout=TIMEOUT)
        if r.status_code in (404, 405):
            return _run_async(query)
        r.raise_for_status()
        body = r.json()
    except requests.RequestException as e:
        raise JoernError(f"Joern server not reachable at {JOERN_URL}: {e}") from e
    except ValueError as e:
        raise JoernError(f"Joern returned a non-JSON response: {e}") from e
    if not body.get("success", False):
        raise JoernError(f"Joern query failed: {str(body.get('stderr') or body.get('err') or body)[:500]}")
    return _ANSI.sub("", body.get("stdout", "") or "")


def _run_async(query: str) -> str:
    """Older servers: POST /query returns a uuid, the result is polled from /result/<uuid>."""
    r = requests.post(f"{JOERN_URL}/query", json={"query": query}, timeout=30)
    r.raise_for_status()
    job = r.json().get("uuid")
    if not job:
        raise JoernError("Joern did not return a query id.")
    deadline = time.time() + TIMEOUT
    while time.time() < deadline:
        res = requests.get(f"{JOERN_URL}/result/{job}", timeout=30).json()
        if res.get("success"):
            return _ANSI.sub("", res.get("stdout", "") or "")
        time.sleep(0.5)
    raise JoernError(f"Joern query timed out after {TIMEOUT}s.")


# ── Running one analysis ──────────────────────────────────────────────────────
def analyze_files(files: dict) -> dict:
    """
    files: {relative path: source code}, Python only.
    Returns {"findings": [...], "sources": n, "sinks": n}. Raises JoernError on any failure.
    """
    job = "job_" + uuid.uuid4().hex[:12]
    job_dir = HOST_WORKDIR / job
    src_dir = job_dir / "src"
    with _lock:
        try:
            for rel, text in files.items():
                target = src_dir / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text, encoding="utf-8", newline="\n")
            container_src = f"{CONTAINER_WORKDIR}/{job}/src"
            _run(f'importCode(inputPath = "{container_src}", projectName = "{job}", language = "PYTHONSRC")')
            result_file = job_dir / "result.json"
            query = QUERY_FILE.read_text(encoding="utf-8").replace("__RESULT_FILE__", f"{CONTAINER_WORKDIR}/{job}/result.json")
            out = _run(query)
            if not result_file.exists():
                raise JoernError("Taint query wrote no result. Joern said: " + out.strip()[-600:])
            try:
                data = json.loads(result_file.read_text(encoding="utf-8"))
            except ValueError as e:
                raise JoernError(f"Could not read the taint query result: {e}") from e
            if "error" in data:
                raise JoernError("Taint query failed inside Joern: " + str(data["error"])[:600])
            return {"findings": _to_findings(data.get("flows", []), files, container_src),
                    "sources": data.get("sources", 0), "sinks": data.get("sinks", 0)}
        finally:
            try:
                _run(f'delete("{job}")')
            except JoernError:
                pass
            shutil.rmtree(job_dir, ignore_errors=True)


def _rel(path: str, container_src: str, files: dict) -> str:
    """Joern may report absolute or relative file names; map both back to the submitted path."""
    p = (path or "").replace("\\", "/")
    if p.startswith(container_src + "/"):
        p = p[len(container_src) + 1:]
    p = p.lstrip("./")
    if p in files:
        return p
    hits = [f for f in files if p and (p.endswith("/" + f) or f.endswith("/" + p))]
    return hits[0] if len(hits) == 1 else p


def _to_findings(flows, files, container_src):
    multi = len(files) > 1
    best = {}  # (rule, file, line of sink) -> flow; confirmed input beats parameter, shorter path beats longer
    for flow in flows:
        path = [dict(step, file=_rel(step.get("file"), container_src, files))
                for step in flow.get("path", []) if step.get("line", -1) > 0]
        if not path or flow.get("rule") not in RULES:
            continue
        sink = path[-1]
        key = (flow["rule"], sink["file"], sink["line"])
        rank = (0 if flow.get("kind") == "input" else 1, len(path))
        if key not in best or rank < best[key][0]:
            best[key] = (rank, flow["kind"], path)

    findings = []
    for (rule, sink_file, sink_line), (_, kind, path) in sorted(best.items(), key=lambda kv: (kv[0][1], kv[0][2])):
        source = path[0]
        lines = files.get(sink_file, "").splitlines()
        evidence = lines[sink_line - 1].strip() if 0 < sink_line <= len(lines) else path[-1]["code"]
        m = re.search(r"([\w.]*\b(?:%s))\s*\(" % "|".join(SINK_NAMES[rule]), evidence)
        sink_name = m.group(1) if m else SINK_NAMES[rule][0]

        steps = []  # taint path without repeated lines
        for s in path:
            if not steps or (steps[-1]["file"], steps[-1]["line"]) != (s["file"], s["line"]):
                steps.append({"file": s["file"], "line": s["line"], "code": s["code"][:200]})

        where_src = f"{source['file']} line {source['line']}" if multi else f"line {source['line']}"
        where_sink = f"{sink_file} line {sink_line}" if multi else f"line {sink_line}"
        if kind == "input":
            message = f"User input from {where_src} reaches {sink_name}() on {where_sink}."
        else:
            message = (f"Parameter '{source['code']}' ({where_src}) reaches {sink_name}() on {where_sink}. "
                       f"Exploitable if any caller passes user input.")
        finding = {
            "rule": rule,
            "type": RULES[rule]["type"],
            "cwe": RULES[rule]["cwe"],
            "severity": "critical" if kind == "input" else "high",
            "line": sink_line,
            "sink": sink_name,
            "source_line": source["line"],
            "evidence": evidence,
            "message": message,
            "path": steps,
        }
        if multi:
            finding["file"] = sink_file
            finding["source_file"] = source["file"]
        findings.append(finding)
    return findings


# ── Is Joern usable? ──────────────────────────────────────────────────────────
_CANARY_VULN = '''from flask import Flask, request
import sqlite3
app = Flask(__name__)

def lookup(uid):
    cur = sqlite3.connect("app.db").cursor()
    cur.execute("SELECT * FROM users WHERE id = " + uid)
    return cur.fetchone()

@app.route("/user")
def get_user():
    return str(lookup(request.args.get("id")))
'''
_CANARY_SAFE = '''from flask import Flask, request
import sqlite3
app = Flask(__name__)

@app.route("/user")
def get_user():
    cur = sqlite3.connect("app.db").cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (request.args.get("id"),))
    return str(cur.fetchone())
'''


def status(force: bool = False) -> str:
    """
    'ok'             Joern is up and finds a known vulnerability (and stays quiet on a safe query)
    'off'            disabled with USE_JOERN=off
    'unreachable: …' server is not running
    'canary_failed: …' server answers, but the taint query does not behave as expected
    The result is cached; a failure is re-checked after 30 seconds.
    """
    if USE_JOERN == "off":
        return "off"
    now = time.time()
    cached = _status["value"]
    if cached and not force and (cached == "ok" or now - _status["checked"] < 30):
        return cached
    try:
        requests.get(JOERN_URL, timeout=3)
    except requests.RequestException as e:
        value = f"unreachable: {type(e).__name__}"
    else:
        try:
            vuln = analyze_files({"canary.py": _CANARY_VULN})["findings"]
            safe = analyze_files({"canary.py": _CANARY_SAFE})["findings"]
            if not any(f["rule"] == "sql" and f["severity"] == "critical" for f in vuln):
                value = "canary_failed: known SQL injection was not detected"
            elif safe:
                value = "canary_failed: parameterized query was flagged"
            else:
                value = "ok"
        except JoernError as e:
            value = f"canary_failed: {e}"
    _status.update(value=value, checked=now)
    return value
