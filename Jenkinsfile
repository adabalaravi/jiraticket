pipeline {
  agent any
  options { timestamps() }

  environment {
    JIRA_URL = 'https://ravindradevops25.atlassian.net'
    JIRA_PROJECT_KEY = 'myprojecct'
    JIRA_ISSUE_TYPE = 'Bug'
    SEVERITY_THRESHOLD = 'high'
  }

  stages {
    stage('Checkout') {
      steps {
        echo 'Checking out source code...'
        checkout scm
      }
    }

    stage('Check Tools') {
      steps {
        powershell '''
            Write-Host "[DEBUG] Starting tool verification..."

            $env:Path = "C:\\Program Files\\nodejs;" + $env:Path
            Write-Host "[DEBUG] PATH is now: $env:Path"

            $nodePath    = "C:\\Program Files\\nodejs\\node.exe"
            $npmPath     = "C:\\Program Files\\nodejs\\npm.cmd"
            $snykPath    = "C:\\Users\\DELL\\AppData\\Roaming\\npm\\snyk.cmd"
            $pythonPath  = "C:\\Users\\DELL\\AppData\\Local\\Programs\\Python\\Python312\\python.exe"

            Write-Host "[DEBUG] Checking for Node.js at $nodePath"
            Write-Host "[DEBUG] Checking for npm at $npmPath"
            Write-Host "[DEBUG] Checking for Snyk at $snykPath"
            Write-Host "[DEBUG] Checking for Python at $pythonPath"

            if (-Not (Test-Path $nodePath))   { Write-Error "Node.js not found at $nodePath"; exit 1 }
            if (-Not (Test-Path $npmPath))    { Write-Error "npm not found at $npmPath"; exit 1 }
            if (-Not (Test-Path $snykPath))   { Write-Error "Snyk not found at $snykPath"; exit 1 }
            if (-Not (Test-Path $pythonPath)) { Write-Error "Python not found at $pythonPath"; exit 1 }

            & $nodePath --version
            & $npmPath --version
            & $pythonPath --version
            & $snykPath --version

            Write-Host "[DEBUG] Tool verification completed successfully."
        '''
      }
    }

    stage('Snyk Auth') {
      steps {
        withCredentials([string(credentialsId: 'snyk-token', variable: 'SNYK_TOKEN')]) {
          powershell '''
            Write-Host "[DEBUG] Starting Snyk authentication..."

            $env:Path = "C:\\Program Files\\nodejs;" + $env:Path
            $snykPath = "C:\\Users\\DELL\\AppData\\Roaming\\npm\\snyk.cmd"

            Write-Host "[DEBUG] Using Snyk at $snykPath"

            if (-Not (Test-Path $snykPath)) {
              Write-Error "Snyk CLI not found at $snykPath. Install it with: npm install -g snyk"
              exit 1
            }

            & $snykPath auth $env:SNYK_TOKEN

            Write-Host "[DEBUG] Snyk authentication completed."
          '''
        }
      }
    }

    stage('Snyk Scan') {
      steps {
        powershell '''
          Write-Host "[DEBUG] Starting Snyk scan..."

          $env:Path = "C:\\Program Files\\nodejs;" + $env:Path
          $snykPath = "C:\\Users\\DELL\\AppData\\Roaming\\npm\\snyk.cmd"
          $pythonPath = "C:\\Users\\DELL\\AppData\\Local\\Programs\\Python\\Python312\\python.exe"

          if (-Not (Test-Path $snykPath)) {
            Write-Error "Snyk CLI not found at $snykPath. Install it with: npm install -g snyk"
            exit 1
          }

          if (Test-Path "requirements.txt") {
            Write-Host "[DEBUG] Found requirements.txt, running Python Snyk scan with explicit Python command..."
            & $snykPath test --file=requirements.txt --command="$pythonPath" --json > snyk-results.json
          } elseif (Test-Path "package.json") {
            Write-Host "[DEBUG] Found package.json, running Node.js Snyk scan..."
            & $snykPath test --file=package.json --json > snyk-results.json
          } else {
            Write-Host "[DEBUG] No requirements.txt or package.json found, running default Snyk scan..."
            & $snykPath test --json > snyk-results.json
          }

          Write-Host "[DEBUG] Snyk scan completed. Results saved to snyk-results.json"

          Write-Host "[DEBUG] Printing snyk-results.json contents:"
          Get-Content snyk-results.json | ForEach-Object { Write-Host $_ }
        '''
      }
    }

    stage('Parse Snyk Results') {
      steps {
        script {
          echo "[DEBUG] Parsing Snyk results..."
          def snykResults = readJSON file: 'snyk-results.json'
          def highVulns = snykResults.vulnerabilities.findAll { it.severity == env.SEVERITY_THRESHOLD }

          echo "[DEBUG] Found ${snykResults.vulnerabilities?.size() ?: 0} vulnerabilities total"
          echo "[DEBUG] Found ${highVulns.size()} high severity vulnerabilities"

          if (highVulns.size() > 0) {
            echo "[DEBUG] Marking build as UNSTABLE due to high vulnerabilities"
            currentBuild.result = 'UNSTABLE'
          } else {
            echo '[DEBUG] No high severity vulnerabilities found.'
          }
        }
      }
    }

    stage('Create JIRA Ticket') {
      when {
        expression { currentBuild.result == 'UNSTABLE' }
      }
      steps {
        withCredentials([string(credentialsId: 'jira-token', variable: 'JIRA_TOKEN')]) {
          script {
            echo "[DEBUG] Preparing to create JIRA ticket..."

            def summary = "High severity vulnerabilities detected in build ${env.BUILD_NUMBER}"
            def description = readFile('snyk-results.json')

            sh """
              echo '[DEBUG] Sending request to JIRA API...'
              curl -X POST \
                -H 'Content-Type: application/json' \
                -H 'Authorization: Bearer $JIRA_TOKEN' \
                --data '{
                  "fields": {
                    "project": {"key": "${env.JIRA_PROJECT_KEY}"},
                    "summary": "${summary}",
                    "description": "${description}",
                    "issuetype": {"name": "${env.JIRA_ISSUE_TYPE}"}
                  }
                }' \
                ${env.JIRA_URL}/rest/api/2/issue/
            """
            echo "[DEBUG] JIRA ticket request sent."
          }
        }
      }
    }
  }
}