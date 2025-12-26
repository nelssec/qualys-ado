# Qualys Security Scanner for Azure DevOps

Integrate Qualys vulnerability scanning directly into your Azure DevOps pipelines. Scan container images and code dependencies before deployment to catch security issues early.

## Features

### Container Security Scanning
Scan Docker images for vulnerabilities in OS packages and application dependencies before pushing to production.

### Software Composition Analysis (SCA)
Analyze your code dependencies (npm, Maven, pip, Go modules, etc.) for known vulnerabilities.

### Policy-Based Build Gating
Use Qualys centralized policies to automatically pass or fail builds based on your security requirements:
- Severity thresholds
- Specific CVE blocking
- Age-based rules
- License compliance

### SBOM Generation
Generate Software Bill of Materials in industry-standard formats (SPDX, CycloneDX) for compliance and supply chain security.

## Quick Start

### 1. Install the Extension
Click **Get it free** above to install this extension in your Azure DevOps organization.

### 2. Create a Service Connection
1. Go to **Project Settings → Service connections**
2. Create a new **Qualys API Connection**
3. Enter your Qualys Client ID, Client Secret, and select your Pod

### 3. Add to Your Pipeline

```yaml
# Scan a container image
- task: QualysContainerScan@2
  inputs:
    qualysConnection: 'QualysConnection'
    imageId: 'myregistry/myapp:$(Build.BuildId)'
    usePolicyEvaluation: true

# Scan code dependencies
- task: QualysSCAScan@2
  inputs:
    qualysConnection: 'QualysConnection'
    scanPath: '$(Build.SourcesDirectory)'
    generateSbom: true
```

## Task Reference

### QualysContainerScan@2

| Input | Required | Description |
|-------|----------|-------------|
| `qualysConnection` | Yes | Qualys service connection |
| `imageId` | Yes | Docker image ID or name:tag |
| `usePolicyEvaluation` | No | Use Qualys policies (default: true) |
| `policyTags` | No | Policy tags to filter |
| `failOnSeverity` | No | Local threshold (5=Critical...1=Info) |
| `scanTypes` | No | os, sca, secret (default: os,sca) |
| `storageDriver` | No | docker-overlay2, containerd-overlayfs |
| `continueOnError` | No | Don't fail pipeline on scan failure |

### QualysSCAScan@2

| Input | Required | Description |
|-------|----------|-------------|
| `qualysConnection` | Yes | Qualys service connection |
| `scanPath` | Yes | Path to scan |
| `usePolicyEvaluation` | No | Use Qualys policies (default: true) |
| `generateSbom` | No | Generate SBOM (default: true) |
| `sbomFormat` | No | spdx, cyclonedx, or both |
| `excludeDirs` | No | Directories to skip |
| `offlineScan` | No | Don't upload results to Qualys |

## Output Variables

Both tasks set these pipeline variables:

- `vulnerabilityCount` - Total vulnerabilities found
- `criticalCount` - Critical severity count
- `highCount` - High severity count
- `policyResult` - ALLOW, DENY, or AUDIT
- `scanPassed` - true or false
- `reportPath` - Path to SARIF report

## Requirements

- **Qualys Subscription** with Container Security module
- **API Credentials** (Client ID + Client Secret) from Qualys portal
- **Build Agent** with internet access (Linux, macOS, or Windows)

## Supported Qualys Pods

US1, US2, US3, US4, EU1, EU2, CA1, IN1, AU1, UK1, AE1, KSA1

## Documentation

- [Full Documentation](https://github.com/your-org/qualys-ado)
- [Qualys Container Security Docs](https://docs.qualys.com/en/cs/latest/)

## Support

For issues and feature requests, please visit our [GitHub repository](https://github.com/your-org/qualys-ado/issues).
