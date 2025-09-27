#!/usr/bin/env python3
import argparse, base64, json, os, sys
from pathlib import Path
from typing import Any, Dict, List
import requests

SEV_ORDER = ['low','medium','high','critical']

def sev_index(s): return SEV_ORDER.index(s.lower()) if s and s.lower() in SEV_ORDER else 0
def meets(s, thresh): return sev_index(s) >= sev_index(thresh)

def load_json(p: Path):
    if not p.exists(): return None
    with p.open('r', encoding='utf-8') as f: return json.load(f)

def parse_oss(data, thresh):
    out=[]
    if not data: return out
    for v in data.get('vulnerabilities',[]) :
        sev = v.get('severity','low')
        if meets(sev, thresh):
            out.append({'type':'oss','severity':sev,'title':v.get('title'),'package':v.get('packageName'),'version':v.get('version'),'url':v.get('url')})
    return out

def parse_sarif(sarif, thresh):
    out=[]
    if not sarif: return out
    for run in sarif.get('runs',[]):
        for r in run.get('results',[]):
            level = (r.get('level') or 'warning').lower()
            sev = 'high' if level=='error' else 'medium'
            if meets(sev, thresh):
                text = (r.get('message') or {}).get('text') or r.get('ruleId') or 'Snyk Code issue'
                loc = ''
                if r.get('locations'):
                    phys = r['locations'][0].get('physicalLocation',{})
                    art = (phys.get('artifactLocation') or {}).get('uri','')
                    line = (phys.get('region') or {}).get('startLine')
                    loc = f"{art}:{line}" if art else ''
                out.append({'type':'code','severity':sev,'title':text,'location':loc})
    return out

def summarize(findings, limit=12):
    lines=[]
    for f in findings[:limit]:
        if f['type']=='oss':
            lines.append(f"- [OSS] {f['severity'].upper()}: {f['title']} in {f.get('package')}@{f.get('version')}")
        else:
            lines.append(f"- [CODE] {f['severity'].upper()}: {f['title']} (loc: {f.get('location')})")
    if len(findings)>limit: lines.append(f"... and {len(findings)-limit} more.")
    return '\n'.join(lines)

def jira_headers(email, token):
    auth = base64.b64encode(f"{email}:{token}".encode()).decode()
    return {'Authorization':f'Basic {auth}','Content-Type':'application/json','Accept':'application/json'}

def jira_create(url, headers, payload):
    r = requests.post(f"{url}/rest/api/3/issue", headers=headers, json=payload, timeout=30)
    r.raise_for_status(); return r.json()

def jira_search(url, headers, jql):
    r = requests.get(f"{url}/rest/api/3/search", headers={'Authorization':headers['Authorization'],'Accept':'application/json'}, params={'jql':jql,'maxResults':5}, timeout=30)
    r.raise_for_status(); return r.json().get('issues',[])

def jira_comment(url, headers, key, body):
    r = requests.post(f"{url}/rest/api/3/issue/{key}/comment", headers=headers, json={'body':body}, timeout=30); r.raise_for_status()

def jira_attach(url, email, token, key, files):
    auth = base64.b64encode(f"{email}:{token}".encode()).decode()
    headers={'Authorization':f'Basic {auth}','X-Atlassian-Token':'no-check'}
    for p in files:
        if not p.exists(): continue
        with p.open('rb') as fh:
            r = requests.post(f"{url}/rest/api/3/issue/{key}/attachments", headers=headers, files={'file':(p.name,fh)}, timeout=60); r.raise_for_status()

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--oss', default='snyk-oss.json')
    ap.add_argument('--sarif', default='snyk-code.sarif')
    ap.add_argument('--threshold', default='high')
    ap.add_argument('--jira-url', required=True)
    ap.add_argument('--jira-project', required=True)
    ap.add_argument('--jira-issue-type', default='Bug')
    ap.add_argument('--build-url', default='')
    ap.add_argument('--branch', default='')
    ap.add_argument('--commit', default='')
    ap.add_argument('--repo', default='')
    args=ap.parse_args()

    oss = load_json(Path(args.oss))
    sarif = load_json(Path(args.sarif))
    findings = parse_oss(oss, args.threshold) + parse_sarif(sarif, args.threshold)
    if not findings:
        print('No findings >= threshold'); sys.exit(0)

    email=os.environ.get('JIRA_EMAIL'); token=os.environ.get('JIRA_API_TOKEN')
    if not email or not token: print('Missing JIRA creds'); sys.exit(1)
    headers=jira_headers(email, token)
    short = (args.commit or 'unknown')[:8]
    summary = f"Snyk Scan Failed [{args.repo} @ {short}] - {len(findings)} issues >= {args.threshold}"
    jql = f'project = {args.jira_project} AND summary ~ "Snyk Scan Failed" AND summary ~ "{args.repo}" AND summary ~ "{short}" ORDER BY created DESC'
    existing=[]
    try: existing = jira_search(args.jira_url, headers, jql)
    except Exception as e: print('JIRA search failed, will create new', e)

    desc = f"Repo: {args.repo}\nBranch: {args.branch}\nCommit: {args.commit}\nBuild: {args.build_url}\n\nTop findings:\n" + summarize(findings, limit=12)
    oss_path=Path(args.oss); sarif_path=Path(args.sarif)
    if existing:
        key=existing[0].get('key'); jira_comment(args.jira_url, headers, key, f'Re-scan: {len(findings)} issues\n\n' + summarize(findings,8)); jira_attach(args.jira_url, email, token, key, [oss_path, sarif_path]); print('Updated',key); sys.exit(2)

    payload={'fields':{'project':{'key':args.jira_project},'summary':summary,'description':desc,'issuetype':{'name':args.jira_issue_type},'priority':{'name':'High'},'labels':['snyk','security'] }}
    created=jira_create(args.jira_url, headers, payload); key=created.get('key'); jira_attach(args.jira_url, email, token, key, [oss_path, sarif_path]); print('Created',key); sys.exit(2)

if __name__=='__main__': main()
