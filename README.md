# AI Code Security Analyzer — Phase 2

Phase 2 adds Joern taint tracking, the four-check analyzer, an overall recommendation, and 15 test cases.

## Run it

```powershell
# 1. Joern (once Docker Desktop is running)
docker compose up -d joern

# 2. Backend
cd backend
py -3.12 -m pip install -r requirements.txt
py -3.12 -m uvicorn main:app --reload

# 3. Frontend (second window)
cd frontend
npm install
npm run dev

# 4. Test cases (from the evaluator folder)
py -3.12 test_cases/run_tests.py
```

`http://127.0.0.1:8000/health` shows whether Joern is in use:

| `joern` value | Meaning |
|---|---|
| `ok` | Joern is up and passed its self-test. Python security findings come from Joern. |
| `unreachable: ...` | Container is not running. The AST fallback is used. |
| `canary_failed: ...` | Joern answered but the taint query did not behave as expected. The AST fallback is used and the message says why. |
| `off` | Disabled with `USE_JOERN=off`. |

Without Joern everything still runs; each report says which engine produced it.

## What changed from V1

| File | Role |
|---|---|
| `docker-compose.yml` | Joern in server mode on `localhost:8080`; `joern_workspace/` is shared with the container as `/work`. |
| `backend/joern_engine.py` | Sends code to Joern, runs the taint query, converts flows into findings, runs the self-test. |
| `backend/taint_queries/python_taint.sc` | The CPGQL query: sources, sinks, `reachableByFlows`. Edit this to add sources or sinks. |
| `backend/rules.py` | Names, CWE ids and fix text per vulnerability type. |
| `backend/ast_fallback.py` | The V1 security scan, used when Joern is not available. |
| `backend/checks.py` | Logic errors, context gaps, hallucinated APIs. |
| `backend/analyzer.py` | Runs the four checks, sets the verdict, builds the recommendation. |
| `backend/main.py` | `/analyze` (unchanged request), new `/analyze-project` (zip upload), `/health` reports Joern. |
| `frontend/src/components/` | "What to do" panel, taint path steps, zip upload button. |
| `test_cases/` | 15 cases, `cases.json`, `run_tests.py`. |

Response changes: `recommendation` now has `action`, `steps` and `counts` next to `verdict` and `reason`;
`engine` is `joern`, `ast_fallback`, `pattern_scan` or `none`; `engine_note` explains a fallback.
Joern findings carry a `path` list (each step from source to sink). `os.environ` is no longer treated as user input.

## The four checks

| Check | Finds | Verdict |
|---|---|---|
| Security | User input reaching SQL, shell or eval/exec calls (CWE-89, 78, 95). Joern follows it through functions and files. | Reject |
| Hallucinated APIs | Calls that do not exist: standard-library attributes (checked against the real modules), `requests`, known inventions for pandas/flask/others, methods on list/str/dict/set, imports between project files. | Reject |
| Logic errors | Off-by-one range, missing return path, list changed while looped over, infinite loop, unreachable code, bare/swallowed except, mutable default, `== None`, `is` with a literal, unused comparison. | Review |
| Context gaps | Undefined names, relative imports, imports of project files that were not provided. | Review |

Nothing found gives Accept.

## Test cases

`py -3.12 test_cases/run_tests.py` prints expected vs. actual and writes `test_cases/results/results_<engine>.md` and `.csv`.
Add `--engine off` to force the fallback and `--verbose` to print every finding.

| ID | Category | Expected | What it shows |
|---|---|---|---|
| S1 | Security | Reject | SQL built with an f-string from the query string |
| S2 | Security | Accept | Same endpoint, parameterized (control) |
| S3 | Security | Reject | Input passes through two helper functions to `os.system` — needs Joern |
| S4 | Security | Accept | SQL built from a constant (control) — the fallback wrongly flags it |
| S5 | Security | Reject | Cross-file: input in `routes.py`, SQL in `auth.py`; `orders.py` stays clean |
| L1–L3 | Logic | Review | Off-by-one, missing return, list modified in loop |
| L4 | Logic | Accept | Correct binary search (control) |
| C1–C3 | Context | Review | Undefined app objects, missing project files, undefined config |
| H1–H3 | Hallucination | Reject | Fake stdlib calls, fake `requests`/list calls, fake Express/JS calls |

On the fallback the expected result is 13 pass and 2 "expected miss (needs Joern)" (S3, S4).
With Joern the target is 15 of 15; S3 and S4 are the before/after evidence for the report.

## Limits

- JavaScript is still a pattern scan. Joern is wired up for Python only.
- Joern reports a function parameter that reaches a sink as `high` even when no user input is traced to it.
- One analysis at a time goes through Joern; each takes a few seconds to build the graph.
- Sources and sinks are curated lists (Flask request data, `input()`, `sys.argv`; SQL, shell and eval sinks).
