import { VulnerabilitySummary, ThresholdConfig, TaskResult, SarifResult } from '../api/types';

export class ThresholdEvaluator {
  private config: ThresholdConfig;

  constructor(config: ThresholdConfig) {
    this.config = config;
  }

  evaluateSummary(summary: VulnerabilitySummary): TaskResult {
    const failureReasons: string[] = [];

    if (this.config.failOnSeverity > 0) {
      if (this.config.failOnSeverity <= 5 && summary.critical > 0) {
        failureReasons.push(`Found ${summary.critical} critical vulnerabilities`);
      }
      if (this.config.failOnSeverity <= 4 && summary.high > 0) {
        failureReasons.push(`Found ${summary.high} high severity vulnerabilities`);
      }
      if (this.config.failOnSeverity <= 3 && summary.medium > 0) {
        failureReasons.push(`Found ${summary.medium} medium severity vulnerabilities`);
      }
      if (this.config.failOnSeverity <= 2 && summary.low > 0) {
        failureReasons.push(`Found ${summary.low} low severity vulnerabilities`);
      }
      if (this.config.failOnSeverity <= 1 && summary.informational > 0) {
        failureReasons.push(`Found ${summary.informational} informational vulnerabilities`);
      }
    }

    return {
      passed: failureReasons.length === 0,
      policyResult: 'NONE',
      failureReasons,
      summary,
    };
  }

  evaluateSarifResults(results: SarifResult[]): TaskResult {
    const summary: VulnerabilitySummary = {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      informational: 0,
    };

    const failureReasons: string[] = [];
    const blockedCves: string[] = [];
    const vulnsAboveCvss: SarifResult[] = [];

    const filteredResults = results.filter(
      (r) => !this.config.excludeQids?.includes(r.properties?.qid ?? 0)
    );

    for (const result of filteredResults) {
      summary.total++;
      const severity = result.properties?.severity as number | undefined;

      if (severity === 5) {
        summary.critical++;
      } else if (severity === 4) {
        summary.high++;
      } else if (severity === 3) {
        summary.medium++;
      } else if (severity === 2) {
        summary.low++;
      } else {
        summary.informational++;
      }

      if (this.config.failOnCvss !== undefined && this.config.failOnCvss > 0) {
        const cvssScore = result.properties?.cvssScore as number | undefined;
        if (cvssScore !== undefined && cvssScore >= this.config.failOnCvss) {
          vulnsAboveCvss.push(result);
        }
      }

      if (this.config.failOnCves && this.config.failOnCves.length > 0) {
        const cves = result.properties?.cves as string[] | undefined;
        if (cves) {
          for (const cve of cves) {
            if (this.config.failOnCves.includes(cve)) {
              blockedCves.push(cve);
            }
          }
        }
      }
    }

    if (this.config.failOnSeverity > 0) {
      if (this.config.failOnSeverity <= 5 && summary.critical > 0) {
        failureReasons.push(`Found ${summary.critical} critical vulnerabilities`);
      }
      if (this.config.failOnSeverity <= 4 && summary.high > 0) {
        failureReasons.push(`Found ${summary.high} high severity vulnerabilities`);
      }
      if (this.config.failOnSeverity <= 3 && summary.medium > 0) {
        failureReasons.push(`Found ${summary.medium} medium severity vulnerabilities`);
      }
      if (this.config.failOnSeverity <= 2 && summary.low > 0) {
        failureReasons.push(`Found ${summary.low} low severity vulnerabilities`);
      }
    }

    if (vulnsAboveCvss.length > 0) {
      failureReasons.push(
        `Found ${vulnsAboveCvss.length} vulnerabilities with CVSS score >= ${this.config.failOnCvss}`
      );
    }

    if (blockedCves.length > 0) {
      const uniqueCves = [...new Set(blockedCves)];
      failureReasons.push(`Found blocked CVEs: ${uniqueCves.join(', ')}`);
    }

    return {
      passed: failureReasons.length === 0,
      policyResult: 'NONE',
      failureReasons,
      summary,
    };
  }
}

export function createThresholdConfig(inputs: {
  failOnSeverity?: string;
  failOnCvss?: string;
  failOnCves?: string;
  failOnLicenses?: string;
  excludeQids?: string;
}): ThresholdConfig {
  return {
    failOnSeverity: parseInt(inputs.failOnSeverity || '0', 10),
    failOnCvss: inputs.failOnCvss ? parseFloat(inputs.failOnCvss) : undefined,
    failOnCves: inputs.failOnCves
      ? inputs.failOnCves
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean)
      : undefined,
    failOnLicenses: inputs.failOnLicenses
      ? inputs.failOnLicenses
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean)
      : undefined,
    excludeQids: inputs.excludeQids
      ? inputs.excludeQids
          .split(',')
          .map((s) => parseInt(s.trim(), 10))
          .filter((n) => !isNaN(n))
      : undefined,
  };
}
