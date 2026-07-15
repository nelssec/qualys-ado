# Qualys Security Scanner for Azure DevOps

> ⚠️ **Unofficial project.** This is a personal project and is not affiliated with, endorsed by, or supported by Qualys, Inc.

Integrate Qualys vulnerability scanning directly into your Azure Pipelines. Scan container images and code dependencies for vulnerabilities, enforce security policies, and gate builds — all powered by the Qualys QScanner CLI.

## What This Extension Does

This extension adds two pipeline tasks to Azure DevOps:

| Task | What It Scans | Use Case |
|------|---------------|----------|
| **QualysContainerScan@1** | Docker container images | Find OS and application vulnerabilities in your images before pushing to a registry |
| **QualysCodeScan@1** | Code dependencies (SCA) | Find known CVEs in your npm, Maven, pip, Go, and NuGet packages |

Both tasks support:
- **Vulnerability thresholds** — fail the build if critical/high/medium/low counts exceed your limits
- **Qualys policy evaluation** — use centralized policies configured in the Qualys portal
- **Secrets detection** — find exposed credentials, API keys, and tokens
- **SARIF reports** — publish results to Azure DevOps code scanning
- **Work item creation** — automatically create Bug work items for discovered vulnerabilities
- **SBOM generation** (Code Scan only) — generate SPDX and/or CycloneDX SBOMs

## Prerequisites

- A **Qualys subscription** with the Container Security module enabled
- A **Qualys Access Token** (found in Container Security > Configuration > Access Token)
- A **Linux-based** Azure DevOps build agent (`ubuntu-latest` or self-hosted Linux amd64)

## Quick Start

### Step 1: Install the Extension

1. In Azure DevOps, go to **Organization Settings > Extensions > Browse Marketplace**
2. Search for **"Qualys Security Scanner"**
3. Click **Get it free** and install to your organization

### Step 2: Create a Service Connection

1. Go to **Project Settings > Service connections > New service connection**
2. Select **Qualys API Connection**
3. Enter your **Access Token**
4. Select your **Pod** (e.g., US1, EU1, CA1 — see [full list](#qualys-pods) below)
5. Name it (e.g., `QualysConnection`) and click **Save**

### Step 3: Add a Scan Task to Your Pipeline

**Container image scan:**

```yaml
- task: QualysContainerScan@1
  displayName: 'Qualys Container Scan'
  inputs:
    qualysConnection: 'QualysConnection'
    imageId: 'myregistry/myapp:$(Build.BuildId)'
    maxCritical: 0    # Fail on any critical vulnerability
    maxHigh: 0        # Fail on any high vulnerability
```

**Code dependency scan (SCA):**

```yaml
- task: QualysCodeScan@1
  displayName: 'Qualys Code Scan'
  inputs:
    qualysConnection: 'QualysConnection'
    scanPath: '$(Build.SourcesDirectory)'
    maxCritical: 0
    maxHigh: 0
    generateSbom: true
```

That's it. The task downloads QScanner automatically — no manual binary installation required.

---

## Configuration Reference

### QualysContainerScan@1

Scans a Docker container image for vulnerabilities.

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `qualysConnection` | Yes | — | Qualys service connection name |
| `imageId` | Yes | — | Image to scan (e.g., `myregistry/myapp:tag` or SHA256) |
| `usePolicyEvaluation` | No | `false` | Use Qualys cloud policies instead of local thresholds |
| `policyTags` | No | — | Comma-separated policy tags (requires `usePolicyEvaluation: true`) |
| `maxCritical` | No | `0` | Max critical vulns before failing (`-1` = unlimited) |
| `maxHigh` | No | `0` | Max high vulns before failing (`-1` = unlimited) |
| `maxMedium` | No | `-1` | Max medium vulns before failing (`-1` = unlimited) |
| `maxLow` | No | `-1` | Max low vulns before failing (`-1` = unlimited) |
| `scanSecrets` | No | `false` | Enable secrets detection |
| `storageDriver` | No | `none` | `none`, `docker-overlay2`, `containerd-overlayfs`, `podman-overlay` |
| `platform` | No | — | Platform for multi-arch images (e.g., `linux/amd64`) |
| `scanTimeout` | No | `300` | Timeout in seconds |
| `continueOnError` | No | `false` | Continue pipeline even if scan fails |
| `publishResults` | No | `true` | Publish SARIF to Azure DevOps |
| `createWorkItems` | No | `false` | Create Bug work items for vulnerabilities |
| `workItemSeverities` | No | `4` | Min severity for work items (5=Critical, 4=High, 3=Medium, 2=Low, 1=All) |
| `workItemAreaPath` | No | — | Area path for created work items |

### QualysCodeScan@1

Scans code dependencies for known vulnerabilities (Software Composition Analysis).

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `qualysConnection` | Yes | — | Qualys service connection name |
| `scanPath` | Yes | `$(Build.SourcesDirectory)` | Path to source code directory |
| `usePolicyEvaluation` | No | `false` | Use Qualys cloud policies instead of local thresholds |
| `policyTags` | No | — | Comma-separated policy tags (requires `usePolicyEvaluation: true`) |
| `maxCritical` | No | `0` | Max critical vulns before failing (`-1` = unlimited) |
| `maxHigh` | No | `0` | Max high vulns before failing (`-1` = unlimited) |
| `maxMedium` | No | `-1` | Max medium vulns before failing (`-1` = unlimited) |
| `maxLow` | No | `-1` | Max low vulns before failing (`-1` = unlimited) |
| `scanSecrets` | No | `false` | Enable secrets detection |
| `excludeDirs` | No | — | Comma-separated directories to skip (e.g., `node_modules,vendor`) |
| `offlineScan` | No | `false` | Scan without uploading to Qualys platform |
| `generateSbom` | No | `true` | Generate Software Bill of Materials |
| `sbomFormat` | No | `spdx` | `spdx`, `cyclonedx`, or `spdx,cyclonedx` |
| `scanTimeout` | No | `300` | Timeout in seconds |
| `continueOnError` | No | `false` | Continue pipeline even if scan fails |
| `publishResults` | No | `true` | Publish SARIF to Azure DevOps |
| `createWorkItems` | No | `false` | Create Bug work items for vulnerabilities |
| `workItemSeverities` | No | `4` | Min severity for work items (5=Critical, 4=High, 3=Medium, 2=Low, 1=All) |
| `workItemAreaPath` | No | — | Area path for created work items |

### Output Variables

Both tasks set the following output variables (access via `$(taskName.variableName)`):

| Variable | Description |
|----------|-------------|
| `vulnerabilityCount` | Total vulnerabilities found |
| `criticalCount` | Critical severity count |
| `highCount` | High severity count |
| `mediumCount` | Medium severity count |
| `lowCount` | Low severity count |
| `policyResult` | `ALLOW`, `DENY`, or `AUDIT` |
| `scanPassed` | `true` or `false` |
| `reportPath` | Path to SARIF report file |
| `sbomPath` | Path to SBOM file(s) (Code Scan only) |
| `workItemsCreated` | Number of work items created |

---

## Pipeline Examples

### Basic Container Scan

```yaml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: Docker@2
    displayName: 'Build Image'
    inputs:
      command: build
      Dockerfile: Dockerfile
      tags: $(Build.BuildId)

  - task: QualysContainerScan@1
    displayName: 'Qualys Container Scan'
    inputs:
      qualysConnection: 'QualysConnection'
      imageId: 'myapp:$(Build.BuildId)'
      maxCritical: 0
      maxHigh: 0
```

### Full Security Pipeline (Container + Code Scan)

```yaml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: Docker@2
    displayName: 'Build Image'
    inputs:
      command: build
      tags: $(Build.BuildId)

  - task: QualysContainerScan@1
    displayName: 'Container Security Scan'
    inputs:
      qualysConnection: 'QualysConnection'
      imageId: 'myapp:$(Build.BuildId)'
      maxCritical: 0
      maxHigh: 0
      scanSecrets: true
      publishResults: true

  - task: QualysCodeScan@1
    displayName: 'Code Dependency Scan'
    inputs:
      qualysConnection: 'QualysConnection'
      scanPath: '$(Build.SourcesDirectory)'
      maxCritical: 0
      maxHigh: 0
      scanSecrets: true
      generateSbom: true
      sbomFormat: 'spdx,cyclonedx'

  - task: Docker@2
    displayName: 'Push to Registry'
    condition: succeeded()
    inputs:
      command: push
```

### Using Qualys Cloud Policies

Instead of local thresholds, use centralized policies configured in the Qualys portal:

```yaml
- task: QualysContainerScan@1
  inputs:
    qualysConnection: 'QualysConnection'
    imageId: 'myapp:$(Build.BuildId)'
    usePolicyEvaluation: true
    policyTags: 'production,ci-cd'
```

To set up policies:
1. In Qualys, go to **Container Security > Policies**
2. Create a policy with severity thresholds, CVE blocks, or age-based rules
3. Tag the policy (e.g., `production`)
4. Reference the tag in `policyTags`

### Using Output Variables

```yaml
- task: QualysContainerScan@1
  name: qualysScan
  inputs:
    qualysConnection: 'QualysConnection'
    imageId: 'myapp:latest'

- script: |
    echo "Total vulnerabilities: $(qualysScan.vulnerabilityCount)"
    echo "Critical: $(qualysScan.criticalCount)"
    echo "High: $(qualysScan.highCount)"
    echo "Policy result: $(qualysScan.policyResult)"
    echo "Scan passed: $(qualysScan.scanPassed)"
  displayName: 'Show Results'
```

### Auto-Creating Work Items

Automatically create Bug work items in Azure Boards for discovered vulnerabilities:

```yaml
- task: QualysContainerScan@1
  displayName: 'Scan and Create Work Items'
  inputs:
    qualysConnection: 'QualysConnection'
    imageId: 'myapp:$(Build.BuildId)'
    maxCritical: 0
    maxHigh: 0
    createWorkItems: true
    workItemSeverities: '4'
    workItemAreaPath: 'MyProject\Security'
  env:
    SYSTEM_ACCESSTOKEN: $(System.AccessToken)
```

**Requirements for work item creation:**
- Enable **"Allow scripts to access OAuth token"** in pipeline settings, OR pass the token via `env: SYSTEM_ACCESSTOKEN: $(System.AccessToken)`
- The build service account needs permission to create work items

Work items include severity in the title, are tagged with `qualys-vuln:{id}` for duplicate detection, and link to CVE details.

---

## Qualys Pods

| Pod | Region |
|-----|--------|
| US1 | United States (Platform 1) |
| US2 | United States (Platform 2) |
| US3 | United States (Platform 3) |
| US4 | United States (Platform 4) |
| EU1 | Europe (Platform 1) |
| EU2 | Europe (Platform 2) |
| CA1 | Canada |
| IN1 | India |
| AU1 | Australia |
| UK1 | United Kingdom |
| AE1 | UAE |
| KSA1 | Saudi Arabia |

## Troubleshooting

| Problem | Solution |
|---------|----------|
| **QScanner binary not found** | Ensure the build agent has internet access to `raw.githubusercontent.com`. The task downloads QScanner automatically. |
| **Authentication failed** | Verify your access token is valid. Regenerate in Container Security > Configuration > Access Token. |
| **Policy returned AUDIT** | No policies matched. Create policies in Qualys and tag them, then set `policyTags` in your task. |
| **Scan is slow** | Use `storageDriver: 'docker-overlay2'` if Docker is available. Increase `scanTimeout` if needed. |
| **Work items not created** | Check OAuth token access, build service permissions, and severity filter. See [work items example](#auto-creating-work-items). |
| **Unsupported platform** | QScanner currently supports **Linux amd64 only**. Use `ubuntu-latest` or a compatible self-hosted agent. |

## Development

```bash
npm install && npm run install:tasks   # Install dependencies
npm run compile                        # Build TypeScript
npm test                               # Run tests
npm run package                        # Package .vsix
```

## License

MIT

## Support

- [GitHub Issues](https://github.com/nelssec/qualys-ado/issues)
