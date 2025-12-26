# Qualys Azure DevOps Extension

Azure DevOps extension for integrating Qualys security scanning into your CI/CD pipelines using the QScanner CLI.

## Features

- **Container Security Scanning** - Scan Docker images for OS and application vulnerabilities
- **Software Composition Analysis (SCA)** - Scan code dependencies for known vulnerabilities
- **Policy-Based Gating** - Use centralized Qualys policies to control build pass/fail
- **SBOM Generation** - Generate Software Bill of Materials in SPDX or CycloneDX format
- **SARIF Reports** - Publish results to Azure DevOps code scanning

## Installation

### From Visual Studio Marketplace

1. Go to your Azure DevOps organization
2. Navigate to **Organization Settings → Extensions**
3. Click **Browse Marketplace**
4. Search for "Qualys Security Scanner"
5. Click **Get it free** and install to your organization

### From VSIX File (Private)

1. Go to **Organization Settings → Extensions**
2. Click **Upload extension**
3. Upload the `.vsix` file

## Setup

### 1. Create Qualys API Credentials

1. Log into the Qualys portal
2. Navigate to **Administration → Users → API Credentials**
3. Create a new API credential with Container Security permissions
4. Note your **Client ID** and **Client Secret**

### 2. Create a Service Connection

1. In Azure DevOps, go to **Project Settings → Service connections**
2. Click **New service connection**
3. Select **Qualys API Connection**
4. Enter:
   - **Client ID** - Your Qualys API Client ID
   - **Client Secret** - Your Qualys API Client Secret
   - **Pod** - Select your Qualys platform region (US1, CA1, EU1, etc.)
5. Give it a name (e.g., "QualysConnection")
6. Click **Save**

## Tasks

### QualysContainerScan@2

Scans Docker container images for vulnerabilities using Qualys QScanner.

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
    scanTypes: 'os,sca'                # os, sca, secret
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
    scanTypes: 'sca'                   # sca, sca+secret, os+sca
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
              publishResults: true

          - task: QualysSCAScan@2
            displayName: 'Dependency Scan'
            inputs:
              qualysConnection: 'QualysConnection'
              scanPath: '$(Build.SourcesDirectory)'
              usePolicyEvaluation: true
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

For best results, configure policies in the Qualys portal:

1. Log into Qualys → **Container Security → Policies**
2. Create a policy with:
   - **Severity thresholds** (e.g., fail on Critical/High)
   - **Specific CVE blocks** (e.g., block Log4Shell)
   - **Age-based rules** (e.g., fail if vuln > 30 days old)
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
cd src/tasks/QualysContainerScan && npm install && cd ../../..
cd src/tasks/QualysSCAScan && npm install && cd ../../..

# Compile TypeScript
npm run compile

# Run tests
npm test

# Package extension
npx tfx-cli extension create --manifest-globs vss-extension.json
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
├── vss-extension.json             # Extension manifest
├── overview.md                    # Marketplace description
└── package.json
```

## Troubleshooting

### "QScanner binary not found"
The task downloads QScanner automatically. Ensure the build agent has internet access to `www.qualys.com`.

### "Authentication failed"
Verify your Client ID and Client Secret are correct. Check that the API credential has Container Security permissions.

### "Policy evaluation returned AUDIT"
AUDIT means no policies matched. Create policies in Qualys and tag them, then reference the tags in `policyTags`.

### Scan takes too long
- Use `storageDriver: 'docker-overlay2'` if Docker is available (faster than pulling image)
- Increase `scanTimeout` if needed
- Consider `offlineScan: true` for SCA to skip upload

## License

MIT

## Support

- [Qualys Documentation](https://docs.qualys.com/en/cs/latest/)
- [Report Issues](https://github.com/your-org/qualys-ado/issues)
