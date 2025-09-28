pipeline {
  agent any
  options { timestamps() }

  environment {
    JIRA_URL = 'https://ravindradevops25.atlassian.net'
    JIRA_PROJECT_KEY = 'SCRUM'
    JIRA_ISSUE_TYPE = 'Task'
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
          Write-Output "[DEBUG] Starting Snyk scan..."
          $env:Path = "C:\\Program Files\\nodejs;" + $env:Path
          $snykPath = "C:\\Users\\DELL\\AppData\\Roaming\\npm\\snyk.cmd"
          $pythonPath = "C:\\Users\\DELL\\AppData\\Local\\Programs\\Python\\Python312\\python.exe"

          if (Test-Path "requirements.txt") {
            Write-Output "[DEBUG] Found requirements.txt, running Python Snyk scan..."
            & $snykPath test --file=requirements.txt --package-manager=pip --command="$pythonPath" --json | Out-File -FilePath snyk-results.json -Encoding UTF8
            if ($LASTEXITCODE -ne 0) {
              Write-Output "[DEBUG] Snyk exited with code $LASTEXITCODE (vulnerabilities found). Forcing success so pipeline continues..."
              exit 0
            }
          } else {
            Write-Output "[DEBUG] No requirements.txt found, running generic Snyk scan..."
            & $snykPath test --json | Out-File -FilePath snyk-results.json -Encoding UTF8
          }

          Write-Output "[DEBUG] Snyk scan completed. Results saved to snyk-results.json"
          Write-Output "[DEBUG] Printing snyk-results.json contents:"
          Get-Content snyk-results.json | Write-Output
        '''
      }
    }

    stage('Parse Snyk Results') {
      steps {
        script {
          echo "[DEBUG] Parsing snyk-results.json safely"

          def rawJson = readFile(file: 'snyk-results.json', encoding: 'UTF-8')
          def jsonText = rawJson.replaceAll('^\\uFEFF', '') // strip BOM
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
    steps {
        withCredentials([usernamePassword(credentialsId: 'jira-credentials', usernameVariable: 'JIRA_USER', passwordVariable: 'JIRA_TOKEN')]) {
            powershell '''
                Write-Host "[DEBUG] Creating JIRA ticket..."

                # Build Basic Auth header
                $pair = "$env:JIRA_USER`:$env:JIRA_TOKEN"
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($pair)
                $encodedAuth = [Convert]::ToBase64String($bytes)

                $summary   = "Snyk Vulnerabilities found in build $($env:BUILD_NUMBER)"
                $project   = $env:JIRA_PROJECT_KEY
                $issueType = $env:JIRA_ISSUE_TYPE
                $priority  = "High"

                $description = @{
                    type = "doc"
                    version = 1
                    content = @(
                        @{
                            type = "paragraph"
                            content = @(
                                @{
                                    type = "text"
                                    text = "Snyk scan detected vulnerabilities. Please review."
                                }
                            )
                        }
                    )
                }
                $payload = @{
                    fields = @{
                        project     = @{ key = $project }
                        summary     = $summary
                        description = $description
                        issuetype   = @{ name = $issueType }
                        priority    = @{ name = $priority }
                    }
                } | ConvertTo-Json -Depth 10

                Write-Host "[DEBUG] Final payload: $payload"
                try {
                    Invoke-RestMethod -Uri "$env:JIRA_URL/rest/api/3/issue" -Method Post -Headers @{
                        Authorization = "Basic $encodedAuth"
                        "Content-Type" = "application/json"
                    } -Body $payload
                } catch {
                    Write-Host "Jira API error:" $_.Exception.Response.StatusDescription
                    $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                    $reader.BaseStream.Position = 0
                    $reader.DiscardBufferedData()
                    $responseBody = $reader.ReadToEnd()
                    Write-Host "Response Body: $responseBody"
                }
            '''
        }
    }
}



  }
}
