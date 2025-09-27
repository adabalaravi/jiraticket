pipeline {
  agent any
  options { timestamps() }

  https://ravindradevops25.atlassian.net/jira/software/projects/SCRUM/boards/1?atlOrigin=eyJpIjoiNGQ0YzFjOTcxMjBmNDI5MDk0ODdlMmRhYjExYWFhM2EiLCJwIjoiaiJ9

  environment {
    JIRA_URL = 'https://ravindradevops25.atlassian.net'
    JIRA_PROJECT_KEY = 'myprojecct'
    JIRA_ISSUE_TYPE = 'Bug'
    SEVERITY_THRESHOLD = 'high'
  }

  stages {
    stage('Checkout') {
      steps { checkout scm }
    }

    stage('Tool Check') {
      steps {
        script {
          if (isUnix()) {
            sh 'node --version; npm --version; snyk --version || { echo "Install Snyk"; exit 1; }; python3 --version'
          } else {
            powershell 'node --version; npm --version; snyk --version; python --version'
          }
        }
      }
    }

    stage('Snyk Auth') {
      steps {
        withCredentials([string(credentialsId: 'snyk-token', variable: 'SNYK_TOKEN')]) {
          script {
            if (isUnix()) { sh 'snyk auth "$SNYK_TOKEN"' } else { powershell 'snyk auth $env:SNYK_TOKEN' }
          }
        }
      }
    }

    stage('Snyk Scans') {
      steps {
        script {
          if (isUnix()) {
            sh 'snyk code test --sarif --sarif-file-output=snyk-code.sarif || true; snyk test --file=requirements.txt --json-file-output=snyk-oss.json || true'
          } else {
            powershell 'snyk code test --sarif --sarif-file-output=snyk-code.sarif; if ($LASTEXITCODE -ne 0) { Write-Host "Continuing..." }; snyk test --file=requirements.txt --json-file-output=snyk-oss.json; if ($LASTEXITCODE -ne 0) { Write-Host "Continuing..." }'
          }
        }
      }
    }

    stage('Create/Update JIRA Ticket if Needed') {
      steps {
        withCredentials([usernamePassword(credentialsId: 'jira-cloud', usernameVariable: 'JIRA_EMAIL', passwordVariable: 'JIRA_API_TOKEN')]) {
          script {
            if (isUnix()) {
              sh '''
                python3 -m venv .venv || python -m venv .venv
                . .venv/bin/activate
                pip install -r tools/requirements.txt
                python tools/create_jira_issue.py --oss snyk-oss.json --sarif snyk-code.sarif --threshold "$SEVERITY_THRESHOLD" --jira-url "$JIRA_URL" --jira-project "$JIRA_PROJECT_KEY" --jira-issue-type "$JIRA_ISSUE_TYPE" --build-url "$BUILD_URL" --branch "$BRANCH_NAME" --commit "$GIT_COMMIT" --repo "$JOB_NAME"
              '''
            } else {
              powershell '''
                  python -m venv .venv
                  ./.venv/Scripts/pip install -r tools/requirements.txt
                  ./.venv/Scripts/python tools/create_jira_issue.py --oss snyk-oss.json --sarif snyk-code.sarif --threshold $env:SEVERITY_THRESHOLD --jira-url $env:JIRA_URL --jira-project $env:JIRA_PROJECT_KEY --jira-issue-type $env:JIRA_ISSUE_TYPE --build-url "$env:BUILD_URL" --branch "$env:BRANCH_NAME" --commit "$env:GIT_COMMIT" --repo "$env:JOB_NAME"
              '''
            }
          }
        }
      }
    }
  }

  post {
    always { archiveArtifacts artifacts: 'snyk-*.json, snyk-*.sarif', onlyIfSuccessful: false }
  }
}
