pipeline {
  agent any
  options { timestamps() }

  environment {
    JIRA_URL = 'https://ravindradevops25.atlassian.net'
    JIRA_PROJECT_KEY = 'SCRUM'
    JIRA_ISSUE_TYPE = 'Bug'
    SEVERITY_THRESHOLD = 'high'
  }

  stages {
    stage('Checkout') {
      steps {
        echo "Checking out source code..."
        checkout scm
      }
    }

    stage('Check Tools') {
      steps {
        powershell '''
          Write-Output "[DEBUG] Starting tool verification..."
          $env:Path = "C:\\Program Files\\nodejs;" + $env:Path

          $nodePath    = "C:\\Program Files\\nodejs\\node.exe"
          $npmPath     = "C:\\Program Files\\nodejs\\npm.cmd"
          $snykPath    = "C:\\Users\\DELL\\AppData\\Roaming\\npm\\snyk.cmd"
          $pythonPath  = "C:\\Users\\DELL\\AppData\\Local\\Programs\\Python\\Python312\\python.exe"

          if (-Not (Test-Path $nodePath))   { Write-Error "Node.js not found at $nodePath"; exit 1 }
          if (-Not (Test-Path $npmPath))    { Write-Error "npm not found at $npmPath"; exit 1 }
          if (-Not (Test-Path $snykPath))   { Write-Error "Snyk not found at $snykPath"; exit 1 }
          if (-Not (Test-Path $pythonPath)) { Write-Error "Python not found at $pythonPath"; exit 1 }

          & $nodePath --version
          & $npmPath --version
          & $pythonPath --version
          & $snykPath --version
          Write-Output "[DEBUG] Tool verification completed successfully."
        '''
      }
    }

    stage('Install Python Dependencies') {
      steps {
        powershell '''
          Write-Output "[DEBUG] Installing Python dependencies from requirements.txt..."
          $pythonPath = "C:\\Users\\DELL\\AppData\\Local\\Programs\\Python\\Python312\\python.exe"
          & $pythonPath -m pip install --upgrade pip setuptools wheel
          & $pythonPath -m pip install -r requirements.txt
          Write-Output "[DEBUG] Dependencies installed successfully."
        '''
      }
    }

    stage('Snyk Auth') {
      steps {
        withCredentials([string(credentialsId: 'snyk-token', variable: 'SNYK_TOKEN')]) {
          powershell '''
            Write-Output "[DEBUG] Starting Snyk authentication..."
            $env:Path = "C:\\Program Files\\nodejs;" + $env:Path
            $snykPath = "C:\\Users\\DELL\\AppData\\Roaming\\npm\\snyk.cmd"
            & $snykPath auth $env:SNYK_TOKEN
            Write-Output "[DEBUG] Snyk authentication completed."
          '''
        }
      }
    }

    stage('Snyk Scan') {
      steps {
        powershell '''
          snyk code test --sarif --sarif-file-output=snyk-code.sarif
          if ($LASTEXITCODE -ne 0) { Write-Host "Continuing..." }
          snyk test --file=requirements.txt --json-file-output=snyk-oss.json
          if ($LASTEXITCODE -ne 0) { Write-Host "Continuing..." }
        '''
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
                python tools/create_jira_issue.py \
                  --oss snyk-oss.json \
                  --sarif snyk-code.sarif \
                  --threshold "$SEVERITY_THRESHOLD" \
                  --jira-url "$JIRA_URL" \
                  --jira-project "$JIRA_PROJECT_KEY" \
                  --jira-issue-type "$JIRA_ISSUE_TYPE" \
                  --build-url "$BUILD_URL" \
                  --branch "$BRANCH_NAME" \
                  --commit "$GIT_COMMIT" \
                  --repo "$JOB_NAME"
              '''
            } else {
              powershell '''
                python -m venv .venv
                .\\.venv\\Scripts\\pip install -r tools\\requirements.txt
                .\\.venv\\Scripts\\python tools\\create_jira_issue.py `
                  --oss snyk-oss.json `
                  --sarif snyk-code.sarif `
                  --threshold $env:SEVERITY_THRESHOLD `
                  --jira-url $env:JIRA_URL `
                  --jira-project $env:JIRA_PROJECT_KEY `
                  --jira-issue-type $env:JIRA_ISSUE_TYPE `
                  --build-url "$env:BUILD_URL" `
                  --branch "$env:BRANCH_NAME" `
                  --commit "$env:GIT_COMMIT" `
                  --repo "$env:JOB_NAME"
              '''
            }
          }
        }
      }
    }
  }
}
