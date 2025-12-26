export type AuthMethod = 'access-token' | 'credentials';

export interface QScannerConfig {
  authMethod: AuthMethod;
  accessToken?: string;
  username?: string;
  password?: string;
  pod: string;
  version?: string;
  proxy?: string;
  skipTlsVerify?: boolean;
}

export interface TokenResponse {
  token: string;
  expiresAt: Date;
}

export const POD_GATEWAY_URLS: Record<string, string> = {
  US1: 'https://gateway.qg1.apps.qualys.com',
  US2: 'https://gateway.qg2.apps.qualys.com',
  US3: 'https://gateway.qg3.apps.qualys.com',
  US4: 'https://gateway.qg4.apps.qualys.com',
  EU1: 'https://gateway.qg1.apps.qualys.eu',
  EU2: 'https://gateway.qg2.apps.qualys.eu',
  CA1: 'https://gateway.qg4.apps.qualys.ca',
  IN1: 'https://gateway.qg1.apps.qualys.in',
  AU1: 'https://gateway.qg1.apps.qualys.com.au',
  UK1: 'https://gateway.qg1.apps.qualys.co.uk',
  AE1: 'https://gateway.qg1.apps.qualys.ae',
  KSA1: 'https://gateway.qg1.apps.qualysksa.com',
};

export interface QScannerOptions {
  mode: 'inventory-only' | 'scan-only' | 'get-report' | 'evaluate-policy';
  scanTypes?: ('os' | 'sca' | 'secret' | 'malware' | 'fileinsight' | 'compliance')[];
  format?: ('json' | 'table' | 'spdx' | 'cyclonedx' | 'sarif')[];
  reportFormat?: ('table' | 'sarif' | 'json' | 'gitlab')[];
  outputDir?: string;
  policyTags?: string[];
  timeout?: number;
  logLevel?: 'debug' | 'info' | 'warn' | 'error';
}

export interface ContainerScanOptions extends QScannerOptions {
  imageId: string;
  storageDriver?: 'none' | 'docker-overlay2' | 'containerd-overlayfs' | 'podman-overlay';
  platform?: string;
}

export interface RepoScanOptions extends QScannerOptions {
  scanPath: string;
  excludeDirs?: string[];
  excludeFiles?: string[];
  offlineScan?: boolean;
}

export enum QScannerExitCode {
  SUCCESS = 0,
  GENERIC_ERROR = 1,
  INVALID_PARAMETER = 2,
  LOGGER_INIT_FAILED = 3,
  FILESYSTEM_ARTIFACT_FAILED = 5,
  IMAGE_ARTIFACT_FAILED = 6,
  IMAGE_ARCHIVE_ARTIFACT_FAILED = 7,
  IMAGE_STORAGE_DRIVER_ARTIFACT_FAILED = 8,
  CONTAINER_ARTIFACT_FAILED = 9,
  OTHER_ARTIFACT_FAILED = 10,
  METADATA_SCAN_FAILED = 11,
  OS_SCAN_FAILED = 12,
  SCA_SCAN_FAILED = 13,
  SECRET_SCAN_FAILED = 14,
  OS_NOT_FOUND = 15,
  MALWARE_SCAN_FAILED = 16,
  OS_NOT_SUPPORTED = 17,
  FILE_INSIGHT_SCAN_FAILED = 18,
  COMPLIANCE_SCAN_FAILED = 19,
  MANIFEST_SCAN_FAILED = 20,
  WINREGISTRY_SCAN_FAILED = 21,
  JSON_RESULT_HANDLER_FAILED = 30,
  CHANGELIST_CREATION_FAILED = 31,
  CHANGELIST_COMPRESSION_FAILED = 32,
  CHANGELIST_UPLOAD_FAILED = 33,
  SPDX_HANDLER_FAILED = 34,
  CDX_HANDLER_FAILED = 35,
  SBOM_COMPRESSION_FAILED = 36,
  SBOM_UPLOAD_FAILED = 37,
  SECRET_RESULT_CREATION_FAILED = 38,
  SECRET_RESULT_UPLOAD_FAILED = 39,
  FAILED_TO_GET_VULN_REPORT = 40,
  FAILED_TO_GET_POLICY_EVALUATION_RESULT = 41,
  POLICY_EVALUATION_DENY = 42,
  POLICY_EVALUATION_AUDIT = 43,
}

export interface QScannerResult {
  exitCode: number;
  success: boolean;
  policyResult: 'ALLOW' | 'DENY' | 'AUDIT' | 'NONE';
  outputDir: string;
  scanResultFile?: string;
  reportFile?: string;
  stdout: string;
  stderr: string;
}

export interface SarifReport {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

export interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
}

export interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription?: { text: string };
  defaultConfiguration?: {
    level: 'error' | 'warning' | 'note' | 'none';
  };
  properties?: Record<string, unknown>;
}

export interface SarifResult {
  ruleId: string;
  level: 'error' | 'warning' | 'note' | 'none';
  message: { text: string };
  locations?: SarifLocation[];
  properties?: {
    qid?: number;
    cves?: string[];
    severity?: number;
    cvssScore?: number;
    packageName?: string;
    installedVersion?: string;
    fixedVersion?: string;
    [key: string]: unknown;
  };
}

export interface SarifLocation {
  physicalLocation?: {
    artifactLocation?: {
      uri: string;
    };
  };
  logicalLocations?: {
    name: string;
    kind: string;
  }[];
}

export interface QScannerScanResult {
  SchemaVersion: number;
  QScannerVersion: string;
  ScansPerformed: ScanPerformed[];
  Metadata: ScanMetadata;
  OSResults?: OSResult[];
  SCAResults?: SCAResult[];
  SecretResults?: SecretResult[];
  FileInsightResults?: FileInsightResult[];
}

export interface ScanPerformed {
  ScanType: string;
  ScanDuration: number;
  Status: 'SUCCESS' | 'FAILED';
  PartialScanInfo?: Record<string, boolean>;
}

export interface ScanMetadata {
  ScanStartTime: number;
  ScanEndTime: number;
  Target?: {
    OS?: string;
    Architecture?: string;
    ImageID?: string;
    RepoTags?: string[];
    RepoDigests?: string[];
  };
}

export interface OSResult {
  Target: string;
  Packages: OSPackage[];
}

export interface OSPackage {
  Name: string;
  Version: string;
  Release?: string;
  Arch?: string;
  SrcName?: string;
  SrcVersion?: string;
}

export interface SCAResult {
  Target: string;
  Packages: SCAPackage[];
}

export interface SCAPackage {
  Name: string;
  Version: string;
  Language: string;
  Licenses?: string[];
  PURL?: string;
  FilePath?: string;
}

export interface SecretResult {
  Target: string;
  Secrets: DetectedSecret[];
}

export interface DetectedSecret {
  RuleID: string;
  Category: string;
  Severity: string;
  Title: string;
  StartLine: number;
  EndLine: number;
  Match?: string;
}

export interface FileInsightResult {
  FilePath: string;
  MimeType: string;
  Permission: string;
  Size: number;
  SHA256Digest?: string;
  ExecutableInfo?: {
    Name: string;
    Version: string;
    PURL: string;
  };
}

export interface VulnerabilitySummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
}

export interface ThresholdConfig {
  failOnSeverity: number;
  failOnCvss?: number;
  failOnCves?: string[];
  failOnLicenses?: string[];
  excludeQids?: number[];
}

export interface TaskResult {
  passed: boolean;
  policyResult: 'ALLOW' | 'DENY' | 'AUDIT' | 'NONE';
  failureReasons: string[];
  summary: VulnerabilitySummary;
  reportPath?: string;
}
