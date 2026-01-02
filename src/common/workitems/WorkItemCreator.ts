import * as azdev from 'azure-devops-node-api';
import * as witApi from 'azure-devops-node-api/WorkItemTrackingApi';
import { JsonPatchOperation, Operation } from 'azure-devops-node-api/interfaces/common/VSSInterfaces';
import { WorkItem, Wiql } from 'azure-devops-node-api/interfaces/WorkItemTrackingInterfaces';
import { SarifReport, SarifResult, SarifRule } from '../api/types';

export interface WorkItemConfig {
  organizationUrl: string;
  project: string;
  accessToken: string;
  areaPath?: string;
  minSeverity: number;
}

export interface VulnerabilityInfo {
  id: string;
  title: string;
  description: string;
  severity: number;
  cvssScore?: number;
  packageName?: string;
  installedVersion?: string;
  fixedVersion?: string;
  source: 'container' | 'sca';
  location?: string;
}

export interface WorkItemCreationResult {
  created: number;
  skipped: number;
  failed: number;
  workItemIds: number[];
  errors: string[];
}

const SEVERITY_LABELS: Record<number, string> = {
  5: 'Critical',
  4: 'High',
  3: 'Medium',
  2: 'Low',
  1: 'Informational',
};

const SEVERITY_TO_PRIORITY: Record<number, number> = {
  5: 1, // Critical -> Priority 1
  4: 2, // High -> Priority 2
  3: 3, // Medium -> Priority 3
  2: 4, // Low -> Priority 4
  1: 4, // Informational -> Priority 4
};

export class WorkItemCreator {
  private config: WorkItemConfig;
  private connection: azdev.WebApi | null = null;
  private witClient: witApi.IWorkItemTrackingApi | null = null;

  constructor(config: WorkItemConfig) {
    this.config = config;
  }

  /**
   * Initialize the Azure DevOps connection
   */
  async initialize(): Promise<void> {
    const authHandler = azdev.getPersonalAccessTokenHandler(this.config.accessToken);
    this.connection = new azdev.WebApi(this.config.organizationUrl, authHandler);
    this.witClient = await this.connection.getWorkItemTrackingApi();
  }

  /**
   * Extract vulnerabilities from a SARIF report
   */
  extractVulnerabilitiesFromSarif(
    sarifReport: SarifReport,
    source: 'container' | 'sca'
  ): VulnerabilityInfo[] {
    const vulnerabilities: VulnerabilityInfo[] = [];
    const ruleMap = new Map<string, SarifRule>();

    for (const run of sarifReport.runs || []) {
      // Build rule map for looking up descriptions
      for (const rule of run.tool?.driver?.rules || []) {
        ruleMap.set(rule.id, rule);
      }

      for (const result of run.results || []) {
        const severity = this.getSeverityFromResult(result, ruleMap);

        // Skip if below minimum severity
        if (severity < this.config.minSeverity) {
          continue;
        }

        const rule = ruleMap.get(result.ruleId);
        const vulnId = this.getVulnerabilityId(result, rule);

        if (!vulnId) {
          continue;
        }

        const vuln: VulnerabilityInfo = {
          id: vulnId,
          title: rule?.shortDescription?.text || result.message?.text || vulnId,
          description: rule?.fullDescription?.text || result.message?.text || '',
          severity,
          cvssScore: result.properties?.cvssScore as number | undefined,
          packageName: result.properties?.packageName as string | undefined,
          installedVersion: result.properties?.installedVersion as string | undefined,
          fixedVersion: result.properties?.fixedVersion as string | undefined,
          source,
          location: this.getLocationFromResult(result),
        };

        vulnerabilities.push(vuln);
      }
    }

    // Deduplicate by vulnerability ID
    const uniqueVulns = new Map<string, VulnerabilityInfo>();
    for (const vuln of vulnerabilities) {
      if (!uniqueVulns.has(vuln.id)) {
        uniqueVulns.set(vuln.id, vuln);
      }
    }

    return Array.from(uniqueVulns.values());
  }

  /**
   * Create work items for the given vulnerabilities
   */
  async createWorkItems(vulnerabilities: VulnerabilityInfo[]): Promise<WorkItemCreationResult> {
    if (!this.witClient) {
      await this.initialize();
    }

    const result: WorkItemCreationResult = {
      created: 0,
      skipped: 0,
      failed: 0,
      workItemIds: [],
      errors: [],
    };

    for (const vuln of vulnerabilities) {
      try {
        const exists = await this.checkDuplicate(vuln.id);
        if (exists) {
          console.log(`Skipping duplicate: ${vuln.id}`);
          result.skipped++;
          continue;
        }

        const workItem = await this.createBug(vuln);
        if (workItem?.id) {
          result.created++;
          result.workItemIds.push(workItem.id);
          console.log(`Created work item #${workItem.id} for ${vuln.id}`);
        }
      } catch (error) {
        result.failed++;
        const errorMsg = error instanceof Error ? error.message : String(error);
        result.errors.push(`Failed to create work item for ${vuln.id}: ${errorMsg}`);
        console.error(`Failed to create work item for ${vuln.id}: ${errorMsg}`);
      }
    }

    return result;
  }

  /**
   * Check if a work item already exists for this vulnerability
   */
  private async checkDuplicate(vulnId: string): Promise<boolean> {
    if (!this.witClient) {
      throw new Error('Work item client not initialized');
    }

    const tag = `qualys-vuln:${vulnId}`;
    const query: Wiql = {
      query: `SELECT [System.Id] FROM WorkItems WHERE [System.TeamProject] = '${this.config.project}' AND [System.Tags] CONTAINS '${tag}'`,
    };

    try {
      const queryResult = await this.witClient.queryByWiql(query, { project: this.config.project });
      return (queryResult.workItems?.length || 0) > 0;
    } catch {
      // If query fails, assume no duplicate to allow creation
      return false;
    }
  }

  /**
   * Create a Bug work item for a vulnerability
   */
  private async createBug(vuln: VulnerabilityInfo): Promise<WorkItem | undefined> {
    if (!this.witClient) {
      throw new Error('Work item client not initialized');
    }

    const severityLabel = SEVERITY_LABELS[vuln.severity] || 'Unknown';
    const priority = SEVERITY_TO_PRIORITY[vuln.severity] || 3;
    const sourceLabel = vuln.source === 'container' ? 'Container Scan' : 'SCA Scan';

    const title = `[${severityLabel}] ${vuln.id}: ${this.truncate(vuln.title, 200)}`;
    const description = this.buildDescription(vuln, sourceLabel);
    const tags = this.buildTags(vuln);

    const patchDocument: JsonPatchOperation[] = [
      {
        op: Operation.Add,
        path: '/fields/System.Title',
        value: title,
      },
      {
        op: Operation.Add,
        path: '/fields/System.Description',
        value: description,
      },
      {
        op: Operation.Add,
        path: '/fields/Microsoft.VSTS.Common.Priority',
        value: priority,
      },
      {
        op: Operation.Add,
        path: '/fields/System.Tags',
        value: tags,
      },
    ];

    // Add area path if specified
    if (this.config.areaPath) {
      patchDocument.push({
        op: Operation.Add,
        path: '/fields/System.AreaPath',
        value: this.config.areaPath,
      });
    }

    return await this.witClient.createWorkItem(
      undefined, // Custom headers
      patchDocument,
      this.config.project,
      'Bug'
    );
  }

  /**
   * Build HTML description for the work item
   */
  private buildDescription(vuln: VulnerabilityInfo, sourceLabel: string): string {
    const severityLabel = SEVERITY_LABELS[vuln.severity] || 'Unknown';

    let html = `<h3>Vulnerability Details</h3>
<table>
  <tr><td><b>ID</b></td><td>${this.escapeHtml(vuln.id)}</td></tr>
  <tr><td><b>Severity</b></td><td>${severityLabel} (${vuln.severity})</td></tr>`;

    if (vuln.cvssScore !== undefined) {
      html += `\n  <tr><td><b>CVSS Score</b></td><td>${vuln.cvssScore}</td></tr>`;
    }

    if (vuln.packageName) {
      html += `\n  <tr><td><b>Package</b></td><td>${this.escapeHtml(vuln.packageName)}`;
      if (vuln.installedVersion) {
        html += ` ${this.escapeHtml(vuln.installedVersion)}`;
      }
      html += `</td></tr>`;
    }

    if (vuln.fixedVersion) {
      html += `\n  <tr><td><b>Fixed Version</b></td><td>${this.escapeHtml(vuln.fixedVersion)}</td></tr>`;
    }

    if (vuln.location) {
      html += `\n  <tr><td><b>Location</b></td><td>${this.escapeHtml(vuln.location)}</td></tr>`;
    }

    html += `\n  <tr><td><b>Source</b></td><td>${sourceLabel}</td></tr>
</table>`;

    if (vuln.description) {
      html += `\n<h3>Description</h3>\n<p>${this.escapeHtml(vuln.description)}</p>`;
    }

    if (vuln.fixedVersion) {
      html += `\n<h3>Remediation</h3>\n<p>Update ${this.escapeHtml(vuln.packageName || 'the affected package')} to version ${this.escapeHtml(vuln.fixedVersion)} or later.</p>`;
    }

    html += `\n<hr>\n<p><i>Created by Qualys Security Scanner</i></p>`;

    return html;
  }

  /**
   * Build tags string for the work item
   */
  private buildTags(vuln: VulnerabilityInfo): string {
    const tags: string[] = [
      `qualys-vuln:${vuln.id}`,
      'security',
      SEVERITY_LABELS[vuln.severity]?.toLowerCase() || 'unknown',
      vuln.source === 'container' ? 'qualys-container-scan' : 'qualys-sca-scan',
    ];

    return tags.join('; ');
  }

  /**
   * Get vulnerability ID from SARIF result
   */
  private getVulnerabilityId(result: SarifResult, _rule?: SarifRule): string | null {
    // Try to get CVE from properties
    const cves = result.properties?.cves as string[] | undefined;
    if (cves && cves.length > 0) {
      return cves[0];
    }

    // Try QID
    const qid = result.properties?.qid as number | undefined;
    if (qid) {
      return `QID-${qid}`;
    }

    // Use rule ID as fallback
    if (result.ruleId) {
      return result.ruleId;
    }

    return null;
  }

  /**
   * Get severity from SARIF result
   */
  private getSeverityFromResult(result: SarifResult, ruleMap: Map<string, SarifRule>): number {
    // Try direct severity property
    if (result.properties?.severity !== undefined) {
      return result.properties.severity as number;
    }

    // Try rule properties
    const rule = ruleMap.get(result.ruleId);
    if (rule?.properties?.severity !== undefined) {
      return rule.properties.severity as number;
    }

    // Map from SARIF level
    switch (result.level) {
      case 'error':
        return 5; // Critical
      case 'warning':
        return 3; // Medium
      case 'note':
        return 2; // Low
      default:
        return 1; // Informational
    }
  }

  /**
   * Get location string from SARIF result
   */
  private getLocationFromResult(result: SarifResult): string | undefined {
    const location = result.locations?.[0];
    if (location?.physicalLocation?.artifactLocation?.uri) {
      return location.physicalLocation.artifactLocation.uri;
    }
    if (location?.logicalLocations?.[0]?.name) {
      return location.logicalLocations[0].name;
    }
    return undefined;
  }

  /**
   * Escape HTML special characters
   */
  private escapeHtml(text: string): string {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  /**
   * Truncate string to max length
   */
  private truncate(text: string, maxLength: number): string {
    if (text.length <= maxLength) {
      return text;
    }
    return text.substring(0, maxLength - 3) + '...';
  }
}
