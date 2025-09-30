#!/usr/bin/env python3
"""
Create or update a JIRA issue based on Snyk results.
- Parses OSS JSON and Code SARIF
- Counts findings by severity
- Creates/updates a JIRA ticket
- Attaches snyk-oss.json and snyk-code.sarif

Exit codes:
  0 -> No issues >= threshold
  2 -> Issues found, ticket created/updated
  1 -> Error
"""
import argparse
import base64
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List
import requests
from urllib.parse import urlparse, urljoin

SEV_ORDER = ["low", "medium", "high", "critical"]

# ------------------ Helpers ------------------ #
def validate_jira_url(jira_url: str) -> str:
    """
    Ensure JIRA URL is safe to use.
    - Must start with http/https
    - Must include a hostname
    - Restrict to Atlassian-hosted domains to prevent SSRF
    """
    parsed = urlparse(jira_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Invalid JIRA URL scheme: {parsed.scheme}")
    if not parsed.netloc:
        raise ValueError("JIRA URL must include a hostname")
    # Enforce strict Atlassian domain pattern
    if not re.fullmatch(r"[a-zA-Z0-9-]+\.atlassian\.net", parsed.netloc):
        raise ValueError(f"JIRA URL {jira_url} not allowed – must be Atlassian-hosted")
    return jira_url.rstrip("/")


def safe_join(base: str, path: str) -> str:
    """Safely join base URL with path, preventing domain escape."""
    joined = urljoin(base + "/", path.lstrip("/"))
    parsed_base = urlparse(base)
    parsed_joined = urlparse(joined)
    if parsed_base.netloc != parsed_joined.netloc:
        raise ValueError("URL join resulted in domain escape")
    return joined


def sev_index(sev: str) -> int:
    return SEV_ORDER.index(sev.lower()) if sev and sev.lower() in SEV_ORDER else 0


def meets_threshold(sev: str, threshold: str) -> bool:
    return sev_index(sev) >= sev_index(threshold)


def count_by_severity(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {sev: 0 for sev in SEV_ORDER}
    for f in findings:
        counts[f["severity"]] += 1
    return counts


def summarize(findings: List[Dict[str, Any]], limit: int = 10) -> str:
    lines: List[str] = []
    for f in findings[:limit]:
        if f["type"] == "oss":
            lines.append(
                f"- [OSS] {f['severity'].upper()}: {f['title']} in {f['package']}@{f.get('version')}\n"
                f"  - From: {f.get('from')}\n  - Ref: {f.get('url')}"
            )
        else:
            lines.append(
                f"- [CODE] {f['severity'].upper()}: {f['title']}\n"
                f"  - Location: {f.get('location') or 'N/A'}"
            )
    extra = len(findings) - limit
    if extra > 0:
        lines.append(f"... and {extra} more.")
    return "\n".join(lines)

def load_json(path: Path):
    """Load JSON file with safe encoding fallback."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except UnicodeDecodeError:
        # Retry with UTF-16 (common when BOM is present)
        with open(path, "r", encoding="utf-16") as f:
            return json.load(f)


# ------------------ Parsers ------------------ #
def parse_oss(data: Dict[str, Any], threshold: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if not data:
        return findings
    for v in data.get("vulnerabilities", []) or []:
        sev = v.get("severity", "low")
        if not meets_threshold(sev, threshold):
            continue
        findings.append({
            "type": "oss",
            "severity": sev,
            "title": v.get("title") or v.get("name") or "Dependency vulnerability",
            "package": v.get("packageName") or v.get("package") or "unknown",
            "version": v.get("version"),
            "from": " > ".join(v.get("from") or []),
            "url": v.get("url"),
            "id": v.get("id"),
        })
    return findings


def parse_sarif(sarif: Dict[str, Any], threshold: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if not sarif:
        return findings
    runs = sarif.get("runs") or []
    for run in runs:
        tool = (run.get("tool") or {}).get("driver", {}).get("name", "Snyk Code")
        rules_by_id = {r.get("id"): r for r in (run.get("tool") or {}).get("driver", {}).get("rules", []) or []}
        for r in run.get("results", []) or []:
            level = (r.get("level") or "warning").lower()
            level_map = {"error": "high", "warning": "medium", "note": "low"}
            sev = level_map.get(level, "medium")
            rid = r.get("ruleId")
            rule = rules_by_id.get(rid, {})
            props = rule.get("properties") or {}
            snyk_sev = (props.get("security-severity") or props.get("problem.severity") or "").lower()
            if snyk_sev in SEV_ORDER:
                sev = snyk_sev
            if not meets_threshold(sev, threshold):
                continue
            loc = ""
            if r.get("locations"):
                phys = r["locations"][0].get("physicalLocation", {})
                art = (phys.get("artifactLocation") or {}).get("uri", "")
                line = (phys.get("region") or {}).get("startLine")
                loc = f"{art}:{line}" if art else ""
            findings.append({
                "type": "code",
                "severity": sev,
                "title": (r.get("message") or {}).get("text") or rid or "Snyk Code issue",
                "location": loc,
                "tool": tool,
                "id": rid,
            })
    return findings

# ------------------ JIRA API ------------------ #
def jira_headers(email: str, token: str) -> Dict[str, str]:
    auth = base64.b64encode(f"{email}:{token}".encode()).decode()
    return {"Authorization": f"Basic {auth}", "Accept": "application/json", "Content-Type": "application/json"}


def jira_search(url: str, headers: Dict[str, str], jql: str) -> List[Dict[str, Any]]:
    resp = requests.get(safe_join(url, "/rest/api/3/search"), headers={"Authorization": headers["Authorization"], "Accept": "application/json"}, params={"jql": jql, "maxResults": 5}, timeout=30)
    resp.raise_for_status()
    return resp.json().get("issues", [])


def jira_create_issue(url: str, headers: Dict[str, str], payload: Dict[str, Any]) -> Dict[str, Any]:
    resp = requests.post(safe_join(url, "/rest/api/3/issue"), headers=headers, data=json.dumps(payload), timeout=30)
    resp.raise_for_status()
    return resp.json()


def jira_add_comment(url: str, headers: Dict[str, str], key: str, body: str) -> None:
    h = {"Authorization": headers["Authorization"], "Accept": "application/json", "Content-Type": "application/json"}
    resp = requests.post(safe_join(url, f"/rest/api/3/issue/{key}/comment"), headers=h, data=json.dumps({"body": body}), timeout=30)
    resp.raise_for_status()


def jira_attach(url: str, email: str, token: str, key: str, files: List[Path]) -> None:
    auth = base64.b64encode(f"{email}:{token}".encode()).decode()
    h = {"Authorization": f"Basic {auth}", "X-Atlassian-Token": "no-check"}
    for p in files:
        if not p.exists():
            continue
        with p.open("rb") as f:
            resp = requests.post(safe_join(url, f"/rest/api/3/issue/{key}/attachments"), headers=h, files={"file": (p.name, f)}, timeout=60)
            resp.raise_for_status()

# ------------------ Main ------------------ #
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--oss", default="snyk-oss.json")
    ap.add_argument("--sarif", default="snyk-code.sarif")
    ap.add_argument("--threshold", default="high")
    ap.add_argument("--jira-url", required=True)
    ap.add_argument("--jira-project", required=True)
    ap.add_argument("--jira-issue-type", default="Bug")
    ap.add_argument("--build-url", default="")
    ap.add_argument("--branch", default="")
    ap.add_argument("--commit", default="")
    ap.add_argument("--repo", default="")
    args = ap.parse_args()
    args.jira_url = validate_jira_url(args.jira_url)

    oss = load_json(Path(args.oss))
    sarif = load_json(Path(args.sarif))

    findings = parse_oss(oss, args.threshold) + parse_sarif(sarif, args.threshold)
    if not findings:
        print("No issues >= threshold")
        sys.exit(0)

    counts = count_by_severity(findings)
    email, token = os.environ.get("JIRA_EMAIL"), os.environ.get("JIRA_API_TOKEN")
    if not email or not token:
        print("[ERROR] Missing JIRA_EMAIL or JIRA_API_TOKEN in environment")
        sys.exit(1)

    headers = jira_headers(email, token)
    short_sha = (args.commit or "unknown")[:8]
    summary = f"Snyk Scan Failed [{args.repo} @ {short_sha}] – {counts['high'] + counts['critical']} high+ issues"

    description = (
        f"h2. Snyk Security Scan Failed (Threshold: {args.threshold})\\n\\n"
        f"*Repo:* {args.repo}\\n"
        f"*Branch:* {args.branch}\\n"
        f"*Commit:* {args.commit}\\n"
        f"*Build:* {args.build_url}\\n\\n"
        f"*Summary of Findings:*\\n"
        f"- Critical: {counts['critical']}\\n"
        f"- High: {counts['high']}\\n"
        f"- Medium: {counts['medium']}\\n"
        f"- Low: {counts['low']}\\n\\n"
        f"h3. Top Findings (showing {min(10, len(findings))})\\n"
        f"{summarize(findings, limit=10)}\\n\\n"
        f"h3. Attachments\\n"
        f"The full reports are attached as *snyk-code.sarif* and *snyk-oss.json*."
    )

    # Check for existing JIRA issue
    jql = f'project = {args.jira_project} AND summary ~ "Snyk Scan Failed" AND summary ~ "{args.repo}" AND summary ~ "{short_sha}" ORDER BY created DESC'
    existing = []
    try:
        existing = jira_search(args.jira_url, headers, jql)
    except Exception as e:
        print(f"[WARN] JIRA search failed: {e}")

    if existing:
        key = existing[0].get("key")
        print(f"[INFO] Updating existing JIRA issue {key}")
        jira_add_comment(args.jira_url, headers, key, f"Re-scan detected {len(findings)} issues >= {args.threshold}.\\n\\n{summarize(findings, limit=8)}")
        jira_attach(args.jira_url, email, token, key, [Path(args.oss), Path(args.sarif)])
        sys.exit(2)

    payload = {
        "fields": {
            "project": {"key": args.jira_project},
            "summary": summary,
            "description": description,
            "issuetype": {"name": args.jira_issue_type},
            "priority": {"name": "High"},
            "labels": ["snyk", "security", "ci-failure"],
        }
    }

    created = jira_create_issue(args.jira_url, headers, payload)
    key = created.get("key")
    print(f"[INFO] Created JIRA issue {key}")
    jira_attach(args.jira_url, email, token, key, [Path(args.oss), Path(args.sarif)])
    sys.exit(2)

if __name__ == "__main__":
    main()
