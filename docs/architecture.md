# Qualys Azure DevOps Extension - Architecture

## High-Level Architecture

```mermaid
graph TB
    subgraph "Azure DevOps Organization"
        subgraph "Project"
            A[Service Connection<br/>Client ID + Secret + Pod]
            B[Pipeline YAML]
        end
    end

    subgraph "Build Agent"
        C[QualysContainerScan Task]
        D[QualysSCAScan Task]
        E[QScanner Binary<br/>Auto-downloaded]
        F[Scan Output<br/>SARIF + SBOM]
    end

    subgraph "Qualys Cloud"
        G[Authentication<br/>OAuth 2.0]
        H[Vulnerability Database]
        I[Policy Engine]
        J[Results Storage]
    end

    A --> C
    A --> D
    B --> C
    B --> D
    C --> E
    D --> E
    E <--> G
    E <--> H
    E <--> I
    E --> J
    E --> F
```

## Container Scan Flow

```mermaid
sequenceDiagram
    participant P as Pipeline
    participant T as Task
    participant Q as QScanner
    participant D as Docker
    participant C as Qualys Cloud

    P->>T: Execute QualysContainerScan
    T->>T: Read service connection
    T->>Q: Download binary (if needed)
    T->>Q: Execute: qscanner image <id>

    alt Storage Driver
        Q->>D: Read layers directly
    else No Storage Driver
        Q->>D: docker save
        Q->>Q: Extract layers
    end

    Q->>Q: Scan OS packages
    Q->>Q: Scan app dependencies
    Q->>Q: Detect secrets
    Q->>C: Upload scan results
    C->>C: Match vulnerabilities
    C->>C: Evaluate policies
    C->>Q: Return policy result
    Q->>T: Exit code (0/42/43)
    T->>T: Parse SARIF report
    T->>P: Set output variables
    T->>P: Pass/Fail build
```

## SCA Scan Flow

```mermaid
sequenceDiagram
    participant P as Pipeline
    participant T as Task
    participant Q as QScanner
    participant F as File System
    participant C as Qualys Cloud

    P->>T: Execute QualysSCAScan
    T->>T: Read service connection
    T->>Q: Download binary (if needed)
    T->>Q: Execute: qscanner repo <path>
    Q->>F: Find manifest files

    Note over Q,F: package.json, pom.xml,<br/>requirements.txt, go.mod, etc.

    Q->>Q: Parse dependencies
    Q->>Q: Generate SBOM
    Q->>C: Upload dependency list
    C->>C: Match vulnerabilities
    C->>C: Evaluate policies
    C->>Q: Return policy result
    Q->>T: Exit code (0/42/43)
    T->>T: Parse SARIF report
    T->>P: Set output variables
    T->>P: Pass/Fail build
```

## Policy Evaluation

```mermaid
flowchart TB
    subgraph "QScanner Execution"
        A[Scan Complete] --> B{Mode?}
        B -->|get-report| C[Generate Report Only]
        B -->|evaluate-policy| D[Send to Policy Engine]
    end

    subgraph "Qualys Policy Engine"
        D --> E[Match Policies by Tags]
        E --> F{Policies Found?}
        F -->|No| G[AUDIT<br/>Exit 43]
        F -->|Yes| H[Evaluate Rules]
        H --> I{All Pass?}
        I -->|Yes| J[ALLOW<br/>Exit 0]
        I -->|No| K[DENY<br/>Exit 42]
    end

    subgraph "Task Result"
        C --> L[Parse Locally]
        G --> M[Build Passes<br/>Warning Logged]
        J --> N[Build Passes]
        K --> O[Build Fails]
        L --> P{Local Threshold?}
        P -->|Pass| N
        P -->|Fail| O
    end
```

## Exit Codes

```mermaid
graph LR
    subgraph "Success Codes"
        A[0 - SUCCESS]
        B[43 - AUDIT]
    end

    subgraph "Failure Codes"
        C[42 - POLICY DENY]
        D[1-41 - Various Errors]
    end

    A --> E[Build Passes]
    B --> E
    C --> F[Build Fails]
    D --> F

    style A fill:#4CAF50
    style B fill:#FF9800
    style C fill:#f44336
    style D fill:#f44336
```

## File Output Structure

```mermaid
graph TB
    subgraph "Output Directory"
        A[qualys-scan-results/]
        A --> B[*-ScanResult.json]
        A --> C[*-Report.sarif.json]
        A --> D[*-sbom.spdx.json]
        A --> E[*-sbom.cdx.json]
    end

    B --> F[Raw scan data]
    C --> G[Vulnerability report<br/>Azure DevOps compatible]
    D --> H[SPDX format SBOM]
    E --> I[CycloneDX format SBOM]
```

## Service Connection Configuration

```mermaid
graph LR
    subgraph "Service Connection Fields"
        A[Client ID]
        B[Client Secret]
        C[Pod Selection]
    end

    subgraph "Pod Options"
        C --> D[US1-US4]
        C --> E[EU1-EU2]
        C --> F[CA1]
        C --> G[IN1, AU1, UK1, AE1, KSA1]
    end

    A --> H[QScanner --client-id]
    B --> I[QScanner --client-secret]
    C --> J[QScanner --pod]
```

## Task Input/Output

```mermaid
flowchart LR
    subgraph "Inputs"
        A[qualysConnection]
        B[imageId / scanPath]
        C[usePolicyEvaluation]
        D[policyTags]
        E[scanTypes]
        F[continueOnError]
    end

    subgraph "Task Execution"
        G[QScanner CLI]
    end

    subgraph "Outputs"
        H[vulnerabilityCount]
        I[criticalCount]
        J[highCount]
        K[policyResult]
        L[scanPassed]
        M[reportPath]
    end

    A --> G
    B --> G
    C --> G
    D --> G
    E --> G
    F --> G
    G --> H
    G --> I
    G --> J
    G --> K
    G --> L
    G --> M
```
