# Qualys Security Scanner for Azure DevOps

Integrate Qualys vulnerability scanning into your Azure Pipelines using the QScanner CLI.

## Features

- **Container Security Scanning**: Scan Docker images for OS and application vulnerabilities
- **Software Composition Analysis (SCA)**: Scan code dependencies for known vulnerabilities
- **Secrets Detection**: Find exposed credentials, API keys, and tokens in your code
- **Policy-Based Gating**: Use centralized Qualys policies to control build pass/fail
- **SBOM Generation**: Generate Software Bill of Materials in SPDX or CycloneDX format
- **SARIF Reports**: Publish results to Azure DevOps code scanning

## Installation

### From Visual Studio Marketplace

1. Go to your Azure DevOps organization
2. Navigate to **Organization Settings > Extensions**
3. Click **Browse Marketplace**
4. Search for "Qualys Security Scanner"
5. Click **Get it free** and install to your organization

### From VSIX File

1. Go to **Organization Settings > Extensions**
2. Click **Upload extension**
3. Upload the `.vsix` file

## Setup

### 1. Get Qualys Access Token

1. Log into the Qualys portal
2. Navigate to **Container Security > Configuration > Access Token**
3. Copy the access token

### 2. Create a Service Connection

1. In Azure DevOps, go to **Project Settings > Service connections**
2. Click **New service connection**
3. Select **Qualys API Connection**
4. Enter your **Access Token** from Container Security
5. Select your **Pod** (region: US1, CA1, EU1, etc.)
6. Give it a name (e.g., "QualysConnection")
7. Click **Save**

## Tasks

### QualysContainerScan@2

Scans Docker container images for vulnerabilities.

```yaml
- task: QualysContainerScan@2
  inputs:
    # Required
    qualysConnection: 'QualysConnection'
    imageId: 'myregistry/myapp:$(Build.BuildId)'

    # Policy Evaluation (recommended)
    usePolicyEvaluation: true          # Use Qualys centralized policies
    policyTags: 'production,ci-cd'     # Filter which policies apply

    # Local Thresholds (when usePolicyEvaluation=false)
    failOnSeverity: '4'                # 5=Critical, 4=High, 3=Medium, 2=Low

    # Scan Options
    scanSecrets: false                 # Enable secrets detection
    storageDriver: 'none'              # none, docker-overlay2, containerd-overlayfs
    platform: 'linux/amd64'            # For multi-arch images

    # Advanced
    scanTimeout: 300                   # Timeout in seconds
    continueOnError: false             # Continue pipeline if scan fails
    publishResults: true               # Publish SARIF to Azure DevOps
```

#### Output Variables

| Variable | Description |
|----------|-------------|
| `vulnerabilityCount` | Total vulnerabilities found |
| `criticalCount` | Critical severity count |
| `highCount` | High severity count |
| `mediumCount` | Medium severity count |
| `lowCount` | Low severity count |
| `policyResult` | ALLOW, DENY, or AUDIT |
| `scanPassed` | true/false |
| `reportPath` | Path to SARIF report |

### QualysSCAScan@2

Scans code dependencies for vulnerabilities.

```yaml
- task: QualysSCAScan@2
  inputs:
    # Required
    qualysConnection: 'QualysConnection'
    scanPath: '$(Build.SourcesDirectory)'

    # Policy Evaluation
    usePolicyEvaluation: true
    policyTags: 'sca-policy'

    # Scan Options
    scanSecrets: false                 # Enable secrets detection
    excludeDirs: 'node_modules,vendor' # Directories to skip
    offlineScan: false                 # Scan without uploading to Qualys

    # SBOM Generation
    generateSbom: true
    sbomFormat: 'spdx'                 # spdx, cyclonedx, or both

    # Advanced
    continueOnError: false
    publishResults: true
```

## Pipeline Examples

### Basic Container Scan

```yaml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: Docker@2
    displayName: 'Build Docker Image'
    inputs:
      command: build
      Dockerfile: Dockerfile
      tags: |
        $(Build.BuildId)

  - task: QualysContainerScan@2
    displayName: 'Qualys Security Scan'
    inputs:
      qualysConnection: 'QualysConnection'
      imageId: 'myapp:$(Build.BuildId)'
      usePolicyEvaluation: true
```

### Full Security Pipeline

```yaml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

stages:
  - stage: Build
    jobs:
      - job: BuildAndScan
        steps:
          - task: Docker@2
            displayName: 'Build Image'
            inputs:
              command: build
              tags: $(Build.BuildId)

          - task: QualysContainerScan@2
            displayName: 'Container Security Scan'
            inputs:
              qualysConnection: 'QualysConnection'
              imageId: 'myapp:$(Build.BuildId)'
              usePolicyEvaluation: true
              policyTags: 'production'
              scanSecrets: true
              publishResults: true

          - task: QualysSCAScan@2
            displayName: 'Dependency Scan'
            inputs:
              qualysConnection: 'QualysConnection'
              scanPath: '$(Build.SourcesDirectory)'
              usePolicyEvaluation: true
              scanSecrets: true
              generateSbom: true
              sbomFormat: 'spdx,cyclonedx'

          # Only push if scans passed
          - task: Docker@2
            displayName: 'Push to Registry'
            condition: succeeded()
            inputs:
              command: push
```

### Using Output Variables

```yaml
- task: QualysContainerScan@2
  name: qualysScan
  inputs:
    qualysConnection: 'QualysConnection'
    imageId: 'myapp:latest'

- script: |
    echo "Vulnerabilities found: $(qualysScan.vulnerabilityCount)"
    echo "Critical: $(qualysScan.criticalCount)"
    echo "Policy Result: $(qualysScan.policyResult)"
  displayName: 'Show Scan Results'
```

## Qualys Policy Setup

Configure policies in the Qualys portal for automated pass/fail decisions:

1. Log into Qualys and navigate to **Container Security > Policies**
2. Create a policy with:
   - **Severity thresholds**: Fail on Critical or High vulnerabilities
   - **Specific CVE blocks**: Block known dangerous CVEs like Log4Shell
   - **Age-based rules**: Fail if vulnerabilities remain unfixed beyond a threshold
3. Tag the policy (e.g., `production`, `ci-cd`)
4. Reference the tag in your pipeline: `policyTags: 'production'`

## Supported Platforms

| Platform | Architecture |
|----------|--------------|
| Linux | amd64, arm64 |
| macOS | amd64, arm64 |
| Windows | amd64 |

## Qualys Pods

| Pod | Region |
|-----|--------|
| US1, US2, US3, US4 | United States |
| EU1, EU2 | Europe |
| CA1 | Canada |
| IN1 | India |
| AU1 | Australia |
| UK1 | United Kingdom |
| AE1 | UAE |
| KSA1 | Saudi Arabia |

## Development

### Prerequisites

- Node.js 20+
- npm 9+

### Build

```bash
# Install dependencies
npm install
npm run install:tasks

# Compile TypeScript
npm run compile

# Run tests
npm test

# Package extension
npm run package
```

### Project Structure

```
qualys-ado/
├── src/
│   ├── common/
│   │   ├── api/types.ts           # Type definitions
│   │   ├── qscanner/              # QScanner CLI runner
│   │   ├── thresholds/            # Local threshold evaluation
│   │   └── utils/                 # Logging, retry utilities
│   └── tasks/
│       ├── QualysContainerScan/   # Container scan task
│       └── QualysSCAScan/         # SCA scan task
├── docs/                          # Documentation
├── vss-extension.json             # Extension manifest
├── overview.md                    # Marketplace description
└── package.json
```

## Troubleshooting

### QScanner binary not found

The task downloads QScanner automatically. Ensure the build agent has internet access to `www.qualys.com`.

### Authentication failed

Verify your access token is valid and not expired. Tokens can be regenerated in Container Security > Configuration > Access Token.

### Policy evaluation returned AUDIT

AUDIT means no policies matched. Create policies in Qualys and tag them, then reference the tags in `policyTags`.

### Scan takes too long

- Use `storageDriver: 'docker-overlay2'` if Docker is available (faster than pulling image)
- Increase `scanTimeout` if needed
- Consider `offlineScan: true` for SCA to skip upload

## License

MIT

## Support

- [Qualys Documentation](https://docs.qualys.com/en/cs/latest/)
- [Report Issues](https://github.com/nelssec/qualys-ado/issues)
