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
        echo "Checking out source code..."
        checkout scm
      }
    }

    stage('Check Tools') {
      steps {
        powershell '''
          Write-Host "[DEBUG] Starting tool verification..."
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
          Write-Host "[DEBUG] Tool verification completed successfully."
        '''
      }
    }

    stage('Install Python Dependencies') {
      steps {
        powershell '''
          Write-Host "[DEBUG] Installing Python dependencies from requirements.txt..."
          & "C:\\Users\\DELL\\AppData\\Local\\Programs\\Python\\Python312\\python.exe" -m pip install -r requirements.txt
          Write-Host "[DEBUG] Dependencies installed successfully."
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

          if (-Not (Test-Path $snykPath)) {
            Write-Error "Snyk CLI not found at $snykPath. Install it with: npm install -g snyk"
            exit 1
          }

          if (Test-Path "requirements.txt") {
            Write-Host "[DEBUG] Found requirements.txt, running Python Snyk scan..."
            & $snykPath test --file=requirements.txt --json | Out-File snyk-results.json -Encoding UTF8
          } else {
            Write-Host "[DEBUG] No requirements.txt found, running default Snyk scan..."
            & $snykPath test --json | Out-File snyk-results.json -Encoding UTF8
          }

          if ($LASTEXITCODE -ne 0) {
            Write-Host "[DEBUG] Snyk exited with code $LASTEXITCODE (vulnerabilities found). Forcing success so pipeline continues..."
          }

          Write-Host "[DEBUG] Snyk scan completed. Results saved to snyk-results.json"
          Write-Host "[DEBUG] Printing snyk-results.json contents:"
          Get-Content snyk-results.json | Write-Host
        '''
      }
    }

    stage('Parse Snyk Results') {
      steps {
        script {
          echo "[DEBUG] Parsing snyk-results.json safely"
          def rawJson = readFile(file: 'snyk-results.json', encoding: 'UTF-8')
          def jsonText = rawJson.replaceAll('^\\uFEFF', '')
          def parsed = new groovy.json.JsonSlurper().parseText(jsonText)

          if (!parsed.vulnerabilities) {
            echo "[DEBUG] No vulnerabilities found"
            env.BUILD_STATUS = 'STABLE'
          } else {
            def highVulns = parsed.vulnerabilities.findAll { it.severity in ['high', 'critical'] }
            echo "[DEBUG] Found ${parsed.vulnerabilities.size()} total vulnerabilities, ${highVulns.size()} are high/critical"
            env.BUILD_STATUS = highVulns.size() > 0 ? 'UNSTABLE' : 'STABLE'
          }

          echo "[DEBUG] Build status set to: ${env.BUILD_STATUS}"
        }
      }
    }

    stage('Create JIRA Ticket') {
      when {
        expression { env.BUILD_STATUS == 'UNSTABLE' }
      }
      steps {
        withCredentials([usernamePassword(credentialsId: 'jira-credentials', usernameVariable: 'JIRA_USER', passwordVariable: 'JIRA_TOKEN')]) {
          script {
            echo "[DEBUG] Creating JIRA ticket..."
            def issueSummary = "Snyk scan found high/critical vulnerabilities"
            def issueDescription = readFile('snyk-results.json')

            def jiraPayload = """
            {
              "fields": {
                "project": { "key": "${env.JIRA_PROJECT_KEY}" },
                "summary": "${issueSummary}",
                "description": "${issueDescription.replace('"', '\\"')}",
                "issuetype": { "name": "${env.JIRA_ISSUE_TYPE}" }
              }
            }
            """

            def response = httpRequest(
              acceptType: 'APPLICATION_JSON',
              contentType: 'APPLICATION_JSON',
              httpMode: 'POST',
              requestBody: jiraPayload,
              url: "${env.JIRA_URL}/rest/api/2/issue",
              authentication: 'jira-credentials'
            )

            def respJson = new groovy.json.JsonSlurper().parseText(response.content)
            def issueKey = respJson.key

            echo "[DEBUG] JIRA Ticket created: ${issueKey}"
            echo "[DEBUG] JIRA URL: ${env.JIRA_URL}/browse/${issueKey}"
          }
        }
      }
    }
  }
}