#!/usr/bin/env python3
\"\"\"snyk_vuln_examples.py

A single-file collection of small, intentionally vulnerable Python examples
to test static analyzers like Snyk Code.

Each example is wrapped in a function and annotated with the vulnerability type.
DO NOT run this with untrusted input or in production.

Usage:
  - Inspect the file and run specific functions for testing in a controlled environment.
  - The script can also dump each example into a separate file if you want.
\"\"\"

import sys
import subprocess
import pickle
import sqlite3
import requests
from urllib.parse import urlparse
import ast

# ---------------------- Examples ---------------------- #

def vuln_eval(user_expr: str = "1+1"):
    \"\"\"Vulnerability: Code injection via eval()
    Snyk flag: python/CodeInjection
    \"\"\"
    print(\"[vuln_eval] Running eval on user input (unsafe):\", user_expr)
    # Vulnerable: executes arbitrary Python expressions
    result = eval(user_expr)   # <- vulnerable
    print(\"Result:\", result)

def vuln_ssrf(url: str):
    \"\"\"Vulnerability: Server-Side Request Forgery (SSRF)
    Snyk flag: python/Ssrf
    \"\"\"
    print(f\"[vuln_ssrf] Fetching URL without validation: {url}\")
    # Vulnerable: uses attacker-controlled URL directly
    r = requests.get(url, timeout=5)  # <- vulnerable
    print(\"Status code:\", r.status_code)
    return r.text

def vuln_command_injection(dirpath: str):
    \"\"\"Vulnerability: OS command injection via shell=True
    Snyk flag: python/CommandInjection
    \"\"\"
    print(f\"[vuln_command_injection] Listing files in: {dirpath}\")
    # Vulnerable: passes untrusted input into a shell string
    cmd = f\"ls -la {dirpath}\"\n    subprocess.check_output(cmd, shell=True)  # <- vulnerable

def vuln_pickle_deser(path: str):
    \"\"\"Vulnerability: Insecure deserialization with pickle
    Snyk flag: python/PickleDeserialization
    \"\"\"
    print(f\"[vuln_pickle_deser] Loading pickle from: {path}\")
    with open(path, \"rb\") as f:
        data = pickle.load(f)  # <- vulnerable if file is attacker-controlled
    print(\"Loaded:\", data)
    return data

def vuln_sql_injection(username: str):
    \"\"\"Vulnerability: SQL injection by string interpolation
    Snyk flag: python/SQLInjection
    \"\"\"
    print(f\"[vuln_sql_injection] Querying for username: {username}\")
    conn = sqlite3.connect(\":memory:\")
    conn.execute(\"CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, username TEXT)\")
    conn.execute(\"INSERT INTO users (name, username) VALUES ('Alice', 'alice')\")
    # Vulnerable: user input interpolated directly into SQL
    query = f\"SELECT id, name FROM users WHERE username = '{username}'\"
    cur = conn.execute(query)  # <- vulnerable
    rows = cur.fetchall()
    print(\"Rows:\", rows)
    conn.close()
    return rows

def vuln_hardcoded_creds():
    \"\"\"Vulnerability: Hard-coded credentials in source
    Snyk flag: python/HardcodedSecrets
    \"\"\"
    API_KEY = \"AKIA...FAKE...SECRET\"  # <- vulnerable
    print(\"[vuln_hardcoded_creds] Using API key:\", API_KEY)

def vuln_insecure_tls():
    \"\"\"Vulnerability: TLS verification disabled (requests.verify=False)
    Snyk flag: python/InsecureTLS
    \"\"\"
    print(\"[vuln_insecure_tls] Making request with verify=False (insecure)\")
    r = requests.get(\"https://example.com\", verify=False)  # <- vulnerable
    print(\"Status:\", r.status_code)
    return r.text

# ---------------------- Helpers / Safe Examples ---------------------- #
def safe_eval_literal(user_expr: str):
    \"\"\"Safe replacement for eval when expecting Python literals\"\"\"
    return ast.literal_eval(user_expr)

def validate_jira_url(jira_url: str) -> str:
    \"\"\"Example of a strict validator (not vulnerable)\"\"\"
    parsed = urlparse(jira_url)
    if parsed.scheme not in (\"http\", \"https\"):
        raise ValueError(\"Invalid scheme\")
    if not parsed.netloc:
        raise ValueError(\"Missing hostname\")
    # Example allowlist - adjust for your environment
    if not parsed.netloc.endswith(\"atlassian.net\") and not parsed.netloc.endswith(\"example.com\"):
        raise ValueError(\"Disallowed domain\")
    return jira_url.rstrip(\"/\")

# ---------------------- CLI & Dump Utility ---------------------- #
def dump_examples(out_dir: str = \"./examples_out\"):
    \"\"\"Write individual example files to out_dir for easier scanning/testing.\"\"\"
    import os
    os.makedirs(out_dir, exist_ok=True)
    examples = {
        \"vuln_eval.py\": \"\"\"# vuln_eval.py\nimport sys\nuser_expr = sys.argv[1] if len(sys.argv) > 1 else '1+1'\nresult = eval(user_expr)\nprint('Result:', result)\n\"\"\",\n        \"vuln_ssrf.py\": \"\"\"# vuln_ssrf.py\nimport requests\nimport sys\nprint(requests.get(sys.argv[1]).text)\n\"\"\",\n        \"vuln_command_injection.py\": \"\"\"# vuln_command_injection.py\nimport subprocess, sys\ncmd = f\"ls -la {sys.argv[1]}\"\nsubprocess.check_output(cmd, shell=True)\n\"\"\",\n        \"vuln_pickle_deser.py\": \"\"\"# vuln_pickle_deser.py\nimport pickle\nwith open('data.pickle','rb') as f:\n    print(pickle.load(f))\n\"\"\",\n        \"vuln_sql_injection.py\": \"\"\"# vuln_sql_injection.py\nimport sqlite3, sys\nconn = sqlite3.connect(':memory:')\nconn.execute(\"CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, username TEXT)\")\nconn.execute(\"INSERT INTO users (name, username) VALUES ('Alice', 'alice')\")\nquery = f\"SELECT id, name FROM users WHERE username = '{sys.argv[1]}'\"\nprint(conn.execute(query).fetchall())\n\"\"\",\n        \"vuln_hardcoded_creds.py\": \"\"\"# vuln_hardcoded_creds.py\nAPI_KEY = 'AKIA...FAKE...SECRET'\nprint('Using', API_KEY)\n\"\"\",\n        \"vuln_insecure_tls.py\": \"\"\"# vuln_insecure_tls.py\nimport requests\nprint(requests.get('https://example.com', verify=False).status_code)\n\"\"\",\n    }\n    for fname, txt in examples.items():\n        with open(os.path.join(out_dir, fname), 'w', encoding='utf-8') as f:\n            f.write(txt)\n    print(f\"Wrote {len(examples)} example files to {out_dir}\")\n\nif __name__ == '__main__':\n    # Simple CLI to call examples or dump files\n    if len(sys.argv) == 1:\n        print(\"snyk_vuln_examples.py - contains multiple intentionally vulnerable examples.\")\n        print(\"Usage: python snyk_vuln_examples.py dump   -> write separate example files into ./examples_out\")\n        print(\"       python snyk_vuln_examples.py run <name> [args...]  -> run a named example\")\n        print(\"Available examples: vuln_eval, vuln_ssrf, vuln_command_injection, vuln_pickle_deser, vuln_sql_injection, vuln_hardcoded_creds, vuln_insecure_tls\")\n        sys.exit(0)\n    cmd = sys.argv[1]\n    if cmd == 'dump':\n        out = sys.argv[2] if len(sys.argv) > 2 else './examples_out'\n        dump_examples(out)\n    elif cmd == 'run':\n        name = sys.argv[2] if len(sys.argv) > 2 else ''\n        if name == 'vuln_eval':\n            vuln_eval(sys.argv[3] if len(sys.argv) > 3 else '1+1')\n        elif name == 'vuln_ssrf':\n            vuln_ssrf(sys.argv[3])\n        elif name == 'vuln_command_injection':\n            vuln_command_injection(sys.argv[3])\n        elif name == 'vuln_pickle_deser':\n            vuln_pickle_deser(sys.argv[3])\n        elif name == 'vuln_sql_injection':\n            vuln_sql_injection(sys.argv[3])\n        elif name == 'vuln_hardcoded_creds':\n            vuln_hardcoded_creds()\n        elif name == 'vuln_insecure_tls':\n            vuln_insecure_tls()\n        else:\n            print('Unknown example:', name)\n            sys.exit(1)\n    else:\n        print('Unknown command')\n        sys.exit(1)\n