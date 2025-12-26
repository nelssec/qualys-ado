# Shift-Left Security: Integrating Qualys Scanning into Azure DevOps Pipelines

Modern software delivery demands security at every stage. With the Qualys Azure DevOps Extension, teams can embed vulnerability scanning directly into their CI/CD pipelines—catching security issues before they reach production.

## The Problem: Security as an Afterthought

Traditional security workflows create friction:

```mermaid
flowchart LR
    A[Dev Writes Code] --> B[Build & Deploy]
    B --> C[Production]
    C --> D[Security Scan]
    D --> E{Vulnerabilities?}
    E -->|Yes| F[Emergency Fix]
    F --> A
    E -->|No| G[Continue]
```

Issues found in production are expensive to fix and risk customer data.

## The Solution: Shift-Left with Pipeline Integration

By integrating Qualys scanning into Azure DevOps, security becomes part of the build process:

```mermaid
flowchart LR
    A[Dev Writes Code] --> B[Build Image]
    B --> C[Qualys Scan]
    C --> D{Policy Pass?}
    D -->|Yes| E[Deploy to Prod]
    D -->|No| F[Block & Alert]
    F --> A
```

Vulnerabilities are caught before deployment, reducing risk and remediation costs.

## How It Works

The extension uses the Qualys QScanner CLI to scan container images and code dependencies directly on the build agent:

```mermaid
sequenceDiagram
    participant Pipeline as Azure Pipeline
    participant Task as Qualys Task
    participant QScanner as QScanner CLI
    participant Qualys as Qualys Platform

    Pipeline->>Task: Trigger scan
    Task->>QScanner: Download binary
    QScanner->>QScanner: Scan image/code
    QScanner->>Qualys: Upload results
    Qualys->>QScanner: Policy evaluation
    QScanner->>Task: Exit code (ALLOW/DENY)
    Task->>Pipeline: Pass/Fail build
```

## Architecture Overview

```mermaid
graph TB
    subgraph "Azure DevOps"
        A[Pipeline YAML] --> B[QualysContainerScan Task]
        A --> C[QualysSCAScan Task]
    end

    subgraph "Build Agent"
        B --> D[QScanner CLI]
        C --> D
        D --> E[SARIF Reports]
        D --> F[SBOM Files]
    end

    subgraph "Qualys Platform"
        D <--> G[Vulnerability DB]
        D <--> H[Policy Engine]
    end

    E --> I[Azure DevOps Code Scanning]
    F --> J[Artifact Storage]
```

## Two Scanning Modes

### Container Security

Scan Docker images for OS package and application vulnerabilities:

```mermaid
flowchart TB
    A[Docker Image] --> B[QScanner]
    B --> C[Layer Analysis]
    C --> D[OS Package Scan]
    C --> E[App Dependency Scan]
    C --> F[Secret Detection]
    D --> G[Vulnerability Report]
    E --> G
    F --> G
    G --> H{Policy Evaluation}
    H -->|ALLOW| I[Build Passes]
    H -->|DENY| J[Build Fails]
```

### Software Composition Analysis (SCA)

Scan code repositories for vulnerable dependencies:

```mermaid
flowchart TB
    A[Source Code] --> B[QScanner]
    B --> C[Manifest Detection]
    C --> D[package.json]
    C --> E[pom.xml]
    C --> F[requirements.txt]
    C --> G[go.mod]
    D --> H[Dependency Analysis]
    E --> H
    F --> H
    G --> H
    H --> I[SBOM Generation]
    H --> J[Vulnerability Matching]
    I --> K[SPDX/CycloneDX]
    J --> L[Policy Evaluation]
```

## Policy-Based Gating

Define security policies in Qualys and enforce them automatically:

```mermaid
flowchart LR
    subgraph "Qualys Portal"
        A[Create Policy] --> B[Set Severity Threshold]
        A --> C[Block Specific CVEs]
        A --> D[License Restrictions]
        B --> E[Tag: production]
        C --> E
        D --> E
    end

    subgraph "Pipeline"
        F[policyTags: production] --> G[QScanner]
        G --> H[Evaluate Against Policy]
        H --> I[ALLOW/DENY/AUDIT]
    end

    E -.-> H
```

## Exit Code Flow

QScanner uses exit codes to communicate results:

```mermaid
stateDiagram-v2
    [*] --> Scanning
    Scanning --> Success: Exit 0
    Scanning --> PolicyDeny: Exit 42
    Scanning --> PolicyAudit: Exit 43
    Scanning --> Error: Exit 1-41

    Success --> BuildPasses
    PolicyDeny --> BuildFails
    PolicyAudit --> BuildPasses: No matching policy
    Error --> BuildFails

    BuildPasses --> [*]
    BuildFails --> [*]
```

## Sample Pipeline

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

  - task: QualysContainerScan@2
    displayName: 'Security Scan'
    inputs:
      qualysConnection: 'QualysConnection'
      imageId: 'myapp:$(Build.BuildId)'
      usePolicyEvaluation: true
      policyTags: 'production'

  - task: Docker@2
    displayName: 'Push to Registry'
    condition: succeeded()
    inputs:
      command: push
```

## Benefits

| Before | After |
|--------|-------|
| Manual security reviews | Automated scanning |
| Vulnerabilities in production | Issues caught at build time |
| Reactive remediation | Proactive prevention |
| Security as blocker | Security as enabler |

## Getting Started

1. Install the extension from the Visual Studio Marketplace
2. Create a Qualys service connection with your API credentials
3. Add scanning tasks to your pipeline YAML
4. Configure policies in the Qualys portal
5. Build with confidence

## Conclusion

Integrating Qualys scanning into Azure DevOps transforms security from a gate at the end of development into a continuous practice. Developers get immediate feedback, security teams get visibility, and organizations reduce risk—all without slowing down delivery.

The Qualys Azure DevOps Extension brings enterprise-grade vulnerability scanning to your pipelines with minimal configuration and maximum impact.

---

*Ready to shift left? Install the Qualys Security Scanner extension today.*
