# Qualys Security Scanner for Azure DevOps

Shift-left security with Qualys vulnerability scanning directly in your Azure DevOps pipelines. Detect vulnerabilities, misconfigurations, and secrets in container images and code dependencies before they reach production.

![Qualys Scan Results](images/scan-results.png)

## Features

- **Container Image Scanning** - Scan Docker images for OS package and application vulnerabilities using the Qualys vulnerability database
- **Software Composition Analysis (SCA)** - Analyze dependencies (npm, Maven, pip, Go, NuGet) for known CVEs
- **Policy-Based Build Gating** - Automatically pass/fail builds using centralized Qualys policies with severity thresholds, CVE blocking, and compliance rules
- **SBOM Generation** - Generate Software Bill of Materials in SPDX and CycloneDX formats for supply chain security
- **Secrets Detection** - Identify exposed credentials, API keys, and tokens in your code and containers

## Getting Started

### 1. Create a Service Connection

Navigate to **Project Settings > Service connections** and create a new **Qualys API Connection**:

1. Enter your **Access Token** from Container Security > Configuration > Access Token
2. Select your **Pod** (region)
3. Save the connection

![Service Connection Setup](images/service-connection.png)

### 2. Add Tasks to Your Pipeline

```yaml
# Container image scanning
- task: QualysContainerScan@1
  inputs:
    qualysConnection: 'QualysConnection'
    imageId: 'myregistry/myapp:$(Build.BuildId)'
    usePolicyEvaluation: false
    maxCritical: 0      # Fail on any critical vulnerabilities
    maxHigh: 5          # Allow up to 5 high severity
    scanSecrets: true   # Optional: enable secrets detection

# Code scanning (SCA)
- task: QualysCodeScan@1
  inputs:
    qualysConnection: 'QualysConnection'
    scanPath: '$(Build.SourcesDirectory)'
    usePolicyEvaluation: false
    maxCritical: 0      # Fail on any critical vulnerabilities
    maxHigh: -1         # Unlimited high severity allowed (-1 = unlimited)
    generateSbom: true
    scanSecrets: true   # Optional: enable secrets detection
```

## Requirements

- Qualys subscription with Container Security module enabled
- Qualys Access Token from Container Security
- Linux-based Azure DevOps build agent (amd64)

## Supported Platforms

| Platform | Architecture |
|----------|--------------|
| Linux | amd64 |

> **Note:** Use a Linux-based build agent (e.g., `ubuntu-latest`).

## Supported Qualys Pods

US1, US2, US3, US4, EU1, EU2, CA1, IN1, AU1, UK1, AE1, KSA1

## Documentation

For detailed configuration options and advanced usage, see the [Qualys Container Security documentation](https://docs.qualys.com/en/cs/latest/).

## Support

For questions and issues, contact [Qualys Support](https://www.qualys.com/support/) or visit the [GitHub repository](https://github.com/nelssec/qualys-ado).

## Release Notes

### 1.0.0
**Initial Release**

**Tasks:**
- **QualysContainerScan@1** - Scan Docker container images for vulnerabilities
- **QualysCodeScan@1** - Scan code dependencies (SCA) for vulnerabilities

**Features:**
- Access Token authentication with Qualys Container Security
- Support for all Qualys pods worldwide (US, EU, CA, IN, AU, UK, AE, KSA)
- Qualys cloud policy evaluation for centralized pass/fail decisions
- Count-based vulnerability thresholds (e.g., fail if >1 Critical or >3 High)
- SBOM generation in SPDX and CycloneDX formats
- Secrets detection for exposed credentials, API keys, and tokens
- SARIF report publishing to Azure DevOps
- Automatic Bug work item creation for discovered vulnerabilities
- Linux amd64 agent support

**Build Results UI:**
- Dedicated scan results tabs for Container and Code scans
- Vulnerability table with QID, CVE, severity, CVSS score, package details, and layer info
- Software inventory table showing all packages found
- Severity breakdown cards (Critical, High, Medium, Low, Info)
- Sortable and filterable vulnerability list with search
- Layer-based filtering to see vulnerabilities by container layer
- Pagination controls (Show 25/50/All)
- Direct links to CVE details on NVD
