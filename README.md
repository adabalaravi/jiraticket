# Auto-create JIRA ticket when Snyk analysis fails

This sample repo runs Snyk Code (SARIF) and Snyk OSS (JSON) in CI and auto-creates/updates a JIRA ticket when vulnerabilities at/above a severity threshold are found.

Files:
- Jenkinsfile
- README.md
- requirements.txt (vulnerable deps for OSS scan)
- app/main.py (intentionally insecure code for Snyk Code)
- tools/create_jira_issue.py (helper to parse results and call JIRA)
- tools/requirements.txt (requests)

Usage:
1. Install Snyk CLI: `npm i -g snyk`
2. Add Jenkins credentials: `snyk-token` (secret text), `jira-cloud` (username+password where password is API token)
3. Update JIRA_URL and JIRA_PROJECT_KEY in Jenkinsfile
4. Create a Jenkins pipeline pointing to this repo and run it.
