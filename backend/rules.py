"""Shared vulnerability rules: what each sink category is called and how to fix it."""

RULES = {
    "sql": {
        "type": "SQL injection",
        "cwe": "CWE-89",
        "fix": "Pass user input as query parameters, e.g. cursor.execute(\"... WHERE id = ?\", (user_id,)), "
               "instead of building the SQL string.",
    },
    "cmd": {
        "type": "Command injection",
        "cwe": "CWE-78",
        "fix": "Do not send user input through a shell. Use subprocess.run([...]) with an argument list "
               "and no shell=True, and check the value against an allowlist.",
    },
    "code": {
        "type": "Code injection",
        "cwe": "CWE-95",
        "fix": "Remove eval/exec on user input. Use ast.literal_eval for literals or a fixed mapping of "
               "allowed operations.",
    },
    "xss": {
        "type": "Cross-site scripting",
        "cwe": "CWE-79",
        "fix": "Insert user data with textContent, or escape it before writing HTML.",
    },
}

# Sink call names per rule (used to label the sink in a finding)
SINK_NAMES = {
    "sql": ("execute", "executemany", "executescript"),
    "cmd": ("system", "popen", "run", "call", "Popen", "check_output", "check_call"),
    "code": ("eval", "exec"),
}
