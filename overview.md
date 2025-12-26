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
- task: QualysContainerScan@2
  inputs:
    qualysConnection: 'QualysConnection'
    imageId: 'myregistry/myapp:$(Build.BuildId)'
    usePolicyEvaluation: true
    scanSecrets: true  # Optional: enable secrets detection

# Software composition analysis
- task: QualysSCAScan@2
  inputs:
    qualysConnection: 'QualysConnection'
    scanPath: '$(Build.SourcesDirectory)'
    generateSbom: true
    scanSecrets: true  # Optional: enable secrets detection
```

## Requirements

- Qualys subscription with Container Security module enabled
- Qualys Access Token from Container Security
- Azure DevOps build agent (Linux, macOS, or Windows)

## Supported Platforms

| Platform | Agent Support |
|----------|---------------|
| Linux | Supported |
| macOS | Supported |
| Windows | Supported |

## Supported Qualys Pods

US1, US2, US3, US4, EU1, EU2, CA1, IN1, AU1, UK1, AE1, KSA1

## Documentation

For detailed configuration options and advanced usage, see the [Qualys Container Security documentation](https://docs.qualys.com/en/cs/latest/).

## Support

For questions and issues, contact [Qualys Support](https://www.qualys.com/support/) or visit the [GitHub repository](https://github.com/nelssec/qualys-ado).

## Release Notes

### 1.0.0
- Simplified service connection with Access Token authentication
- Streamlined setup with pod selection dropdown
- Unified package scanning (pkg) combining OS and application vulnerabilities
- Optional secrets detection for containers and source code
- SBOM generation in SPDX and CycloneDX formats
- Policy-based build gating with Qualys centralized policies
- Support for all Qualys pods worldwide
- Linux, macOS, and Windows agent support
