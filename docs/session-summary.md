# Qualys Azure DevOps Extension - Session Summary

## What Was Built

A complete Azure DevOps extension that integrates Qualys security scanning into CI/CD pipelines using the QScanner CLI.

### Two Tasks

1. **QualysContainerScan@2** - Scans Docker container images
2. **QualysSCAScan@2** - Scans code dependencies (SCA)

### Key Features

- Downloads QScanner binary from GitHub (`nelssec/qualys-lambda`)
- SHA256 checksum verification for binary integrity
- Two authentication methods: Access Token or Username/Password
- Policy-based gating (ALLOW/DENY/AUDIT)
- SBOM generation (SPDX/CycloneDX)
- SARIF report output for Azure DevOps code scanning

---

## Files Structure

```
qualys-ado/
├── vss-extension.json              # Extension manifest (v1.0.1)
├── overview.md                     # Marketplace description
├── package.json                    # Build tooling
├── tsconfig.base.json
├── images/
│   └── extension-icon.png          # Qualys logo
├── docs/
│   ├── architecture.md             # Technical diagrams
│   ├── blog-shift-left-security.md # Blog post with Mermaid diagrams
│   └── session-summary.md          # This file
├── src/
│   ├── common/
│   │   ├── api/types.ts            # Type definitions, POD_GATEWAY_URLS
│   │   ├── qscanner/QScannerRunner.ts  # Core CLI runner
│   │   ├── thresholds/ThresholdEvaluator.ts
│   │   ├── utils/logger.ts
│   │   ├── utils/retry.ts
│   │   └── index.ts
│   └── tasks/
│       ├── QualysContainerScan/
│       │   ├── task.json           # Task definition
│       │   ├── index.ts            # Task logic
│       │   └── package.json
│       └── QualysSCAScan/
│           ├── task.json
│           ├── index.ts
│           └── package.json
└── dist/                           # Compiled JavaScript
```

---

## Security Review Completed

### Passed Checks
- HTTPS for all connections
- TLS certificate verification enabled by default
- Credentials marked confidential in service connection
- Auth token passed via environment variable (not CLI args)
- Credential masking in logs
- Input validation (Pod whitelist)
- Task restrictions configured
- Node20 runtime

### Fixes Applied
1. Changed auth from `--client-id/--client-secret` to `--access-token` (via env var)
2. Fixed download URL to use GitHub source with SHA256 verification
3. Removed unused `qscannerVersion` input
4. Fixed duplicate token field in service connection (changed to `endpoint-auth-scheme-none`)

---

## Current State

### Extension Published
- **Publisher**: `qualys-ext`
- **Extension ID**: `qualys-security-scanner`
- **Version**: 1.0.1 (local), 1.0.0 (marketplace)
- **Marketplace URL**: https://marketplace.visualstudio.com/manage/publishers/qualys-ext/extensions/qualys-security-scanner

### Installed In
- **Organization**: `anqualys`
- **Project**: `Qualys`

### Service Connection Created
- **Name**: `QualysConnection`
- **Pod**: CA1
- **Auth**: Access Token

### VSIX Files
- v1.0.0: `qualys-ext.qualys-security-scanner-1.0.0.vsix` (installed)
- v1.0.1: `qualys-ext.qualys-security-scanner-1.0.1.vsix` (fixed duplicate token field)

---

## To Complete Testing

### 1. Update Extension (Optional)
Upload v1.0.1 to fix the duplicate token field:
```
https://marketplace.visualstudio.com/manage/publishers/qualys-ext/extensions/qualys-security-scanner
→ Update → Upload qualys-ext.qualys-security-scanner-1.0.1.vsix
```

### 2. Create Test Repo
User is creating a separate vulnerable test repo with:
- Dockerfile with vulnerable base image
- package.json with vulnerable dependencies
- Will be pushed to GitHub

### 3. Create Pipeline
Connect the test repo to Azure DevOps and run:

```yaml
trigger: none

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: QualysSCAScan@2
    displayName: 'Qualys SCA Scan'
    inputs:
      qualysConnection: 'QualysConnection'
      scanPath: '$(Build.SourcesDirectory)'
      usePolicyEvaluation: false
      failOnSeverity: '0'
      generateSbom: true
      continueOnError: true
```

### 4. For Container Scan
```yaml
steps:
  - task: Docker@2
    inputs:
      command: build
      tags: test:$(Build.BuildId)

  - task: QualysContainerScan@2
    inputs:
      qualysConnection: 'QualysConnection'
      imageId: 'test:$(Build.BuildId)'
      usePolicyEvaluation: true
```

---

## QScanner Binary Details

- **Source**: `https://github.com/nelssec/qualys-lambda/raw/main/scanner-lambda/qscanner.gz`
- **SHA256**: `1a31b854154ee4594bb94e28aa86460b14a75687085d097f949e91c5fd00413d`
- **Platform**: Linux amd64 only
- **Auth**: Uses `QUALYS_ACCESS_TOKEN` environment variable

---

## Qualys Credentials (For Testing)

- **Pod**: CA1
- **Access Token**: (stored in Azure DevOps service connection)
- **Token expires**: ~2027 (based on JWT exp claim)

**Note**: Token was shared in chat - should be rotated after testing.

---

## Commands Reference

### Build Extension
```bash
cd /Users/andrew/git_base/qualys-ado
npm install
npm run compile
npx tfx-cli extension create --manifest-globs vss-extension.json
```

### Bump Version and Rebuild
```bash
npm run compile
npx tfx-cli extension create --manifest-globs vss-extension.json --rev-version
```

---

## Known Issues

1. **Service connection shows duplicate token fields** (v1.0.0)
   - Fixed in v1.0.1 by changing to `endpoint-auth-scheme-none`
   - Workaround: Enter same token in both fields

2. **QScanner only supports linux-amd64**
   - Build agents must use `ubuntu-latest` or similar
   - Will error on Windows/macOS agents

3. **GitHub CI emails**
   - `.github/workflows` was deleted locally but may still exist on remote
   - Push to delete from remote
