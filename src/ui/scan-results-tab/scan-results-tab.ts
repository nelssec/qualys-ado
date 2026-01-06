import * as SDK from "azure-devops-extension-sdk";
import { CommonServiceIds, IProjectPageService, getClient } from "azure-devops-extension-api";
import { BuildRestClient } from "azure-devops-extension-api/Build";
import "./scan-results-tab.css";

interface SarifReport {
    $schema: string;
    version: string;
    runs: SarifRun[];
}

interface SarifRun {
    tool: {
        driver: {
            name: string;
            version: string;
            rules: SarifRule[];
        };
    };
    results: SarifResult[];
}

interface SarifRule {
    id: string;
    name: string;
    shortDescription: { text: string };
    fullDescription?: { text: string };
    defaultConfiguration?: {
        level: "error" | "warning" | "note" | "none";
    };
    properties?: Record<string, unknown>;
}

interface SarifResult {
    ruleId: string;
    level: "error" | "warning" | "note" | "none";
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

interface SarifLocation {
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

interface VulnerabilityRow {
    id: string;
    severity: number;
    severityLabel: string;
    cves: string[];
    qid?: number;
    cvssScore?: number;
    packageName: string;
    installedVersion: string;
    fixedVersion: string;
    description: string;
    location: string;
}

interface ScanSummary {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    passed: boolean;
    policyResult: string;
    scanType: string;
    toolVersion: string;
}

class QualysScanResultsTab {
    private buildClient!: BuildRestClient;
    private projectId!: string;
    private buildId!: number;
    private vulnerabilities: VulnerabilityRow[] = [];
    private filteredVulnerabilities: VulnerabilityRow[] = [];
    private currentPage = 1;
    private pageSize = 25;
    private sortColumn = "severity";
    private sortDirection: "asc" | "desc" = "desc";
    private filterSeverity = "all";
    private searchQuery = "";

    async initialize(): Promise<void> {
        try {
            await SDK.init();
            await SDK.ready();

            const config = SDK.getConfiguration();
            this.buildId = config.buildId || (config.build && config.build.id);

            if (!this.buildId) {
                throw new Error("Build ID not available");
            }

            const projectService = await SDK.getService<IProjectPageService>(
                CommonServiceIds.ProjectPageService
            );
            const project = await projectService.getProject();
            if (!project) {
                throw new Error("Project not available");
            }
            this.projectId = project.id;

            this.buildClient = getClient(BuildRestClient);

            await this.loadScanResults();

            SDK.notifyLoadSucceeded();
        } catch (error) {
            this.showError(error instanceof Error ? error.message : "Failed to initialize");
            SDK.notifyLoadSucceeded();
        }
    }

    private async loadScanResults(): Promise<void> {
        try {
            // Get build artifacts
            const artifacts = await this.buildClient.getArtifacts(this.projectId, this.buildId);

            // Look for Qualys scan result artifacts
            const qualysArtifacts = artifacts.filter(
                a => a.name === "QualysScanResults" ||
                     a.name === "QualysSCAResults" ||
                     a.name === "CodeAnalysisLogs"
            );

            if (qualysArtifacts.length === 0) {
                this.showNoResults("No Qualys scan results found for this build.");
                return;
            }

            let sarifReport: SarifReport | null = null;

            // Try to download artifact content
            for (const artifact of qualysArtifacts) {
                if (!artifact.resource?.downloadUrl) continue;

                try {
                    // Fetch the artifact ZIP
                    const response = await fetch(artifact.resource.downloadUrl, {
                        headers: {
                            "Accept": "application/zip"
                        }
                    });

                    if (!response.ok) continue;

                    // For simplicity, try direct JSON fetch (works if artifact is exposed)
                    // In production, you'd need to handle ZIP extraction
                    const artifactUrl = artifact.resource.downloadUrl.replace("format=zip", "format=file");
                    const sarifUrl = `${artifactUrl}&subPath=/${artifact.name}`;

                    const sarifResponse = await fetch(sarifUrl);
                    if (sarifResponse.ok) {
                        const text = await sarifResponse.text();
                        if (text.includes('"$schema"') && text.includes('"runs"')) {
                            sarifReport = JSON.parse(text);
                            break;
                        }
                    }
                } catch {
                    // Continue to next artifact
                    continue;
                }
            }

            if (!sarifReport) {
                // Show summary from build with download link
                const artifactNames = qualysArtifacts.map(a => a.name).join(", ");
                this.showNoResults(
                    `Scan results available in artifacts: ${artifactNames}. Download the artifact to view the full SARIF report.`
                );
                return;
            }

            this.parseSarifReport(sarifReport);
            this.renderResults();

        } catch (error) {
            console.error("Error loading scan results:", error);
            this.showError("Failed to load scan results: " + (error instanceof Error ? error.message : "Unknown error"));
        }
    }

    private parseSarifReport(report: SarifReport): void {
        const run = report.runs?.[0];
        if (!run) {
            return;
        }

        const rulesMap = new Map<string, SarifRule>();
        run.tool.driver.rules?.forEach(rule => {
            rulesMap.set(rule.id, rule);
        });

        this.vulnerabilities = run.results.map(result => {
            const rule = rulesMap.get(result.ruleId);
            const severity = this.getSeverity(result, rule);

            return {
                id: result.ruleId,
                severity,
                severityLabel: this.getSeverityLabel(severity),
                cves: result.properties?.cves || [],
                qid: result.properties?.qid,
                cvssScore: result.properties?.cvssScore,
                packageName: result.properties?.packageName || this.extractPackageName(result),
                installedVersion: result.properties?.installedVersion || "",
                fixedVersion: result.properties?.fixedVersion || "",
                description: result.message.text || rule?.shortDescription?.text || "",
                location: this.extractLocation(result)
            };
        });

        this.filteredVulnerabilities = [...this.vulnerabilities];
        this.sortVulnerabilities();
    }

    private getSeverity(result: SarifResult, rule?: SarifRule): number {
        // First check result properties
        if (result.properties?.severity !== undefined) {
            return result.properties.severity;
        }

        // Then check rule properties
        if (rule?.properties?.severity !== undefined) {
            return rule.properties.severity as number;
        }

        // Fall back to SARIF level mapping
        const levelMap: Record<string, number> = {
            error: 5,
            warning: 3,
            note: 2,
            none: 1
        };
        return levelMap[result.level] || levelMap[rule?.defaultConfiguration?.level || "none"];
    }

    private getSeverityLabel(severity: number): string {
        const labels: Record<number, string> = {
            5: "Critical",
            4: "High",
            3: "Medium",
            2: "Low",
            1: "Info"
        };
        return labels[severity] || "Unknown";
    }

    private extractPackageName(result: SarifResult): string {
        // Try to extract from locations
        const loc = result.locations?.[0];
        if (loc?.logicalLocations?.[0]?.name) {
            return loc.logicalLocations[0].name;
        }
        if (loc?.physicalLocation?.artifactLocation?.uri) {
            return loc.physicalLocation.artifactLocation.uri;
        }
        return result.ruleId;
    }

    private extractLocation(result: SarifResult): string {
        const loc = result.locations?.[0];
        if (loc?.physicalLocation?.artifactLocation?.uri) {
            return loc.physicalLocation.artifactLocation.uri;
        }
        if (loc?.logicalLocations?.[0]?.name) {
            return loc.logicalLocations[0].name;
        }
        return "";
    }

    private getSummary(): ScanSummary {
        const summary: ScanSummary = {
            total: this.vulnerabilities.length,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
            passed: true,
            policyResult: "NONE",
            scanType: "Unknown",
            toolVersion: ""
        };

        this.vulnerabilities.forEach(v => {
            switch (v.severity) {
                case 5: summary.critical++; break;
                case 4: summary.high++; break;
                case 3: summary.medium++; break;
                case 2: summary.low++; break;
                default: summary.info++; break;
            }
        });

        // Consider failed if critical or high vulnerabilities exist
        summary.passed = summary.critical === 0 && summary.high === 0;

        return summary;
    }

    private renderResults(): void {
        const content = document.getElementById("content");
        const loading = document.getElementById("loading");

        if (!content || !loading) return;

        loading.style.display = "none";
        content.style.display = "block";

        const summary = this.getSummary();

        content.innerHTML = `
            ${this.renderHeader(summary)}
            ${this.renderSummaryCards(summary)}
            ${this.renderVulnerabilityTable()}
            ${this.renderScanInfo()}
        `;

        this.attachEventListeners();
    }

    private renderHeader(summary: ScanSummary): string {
        const statusClass = summary.passed ? "passed" : "failed";
        const statusText = summary.passed ? "Passed" : "Failed";
        const statusIcon = summary.passed ? "\u2713" : "\u2717";

        return `
            <div class="results-header">
                <svg class="qualys-logo" viewBox="0 0 100 100">
                    <circle cx="50" cy="50" r="45" fill="#ed1c24"/>
                    <text x="50" y="60" text-anchor="middle" fill="white" font-size="30" font-weight="bold">Q</text>
                </svg>
                <h1 class="results-title">Qualys Security Scan Results</h1>
                <div class="scan-status ${statusClass}">
                    <span class="status-icon">${statusIcon}</span>
                    <span>${statusText}</span>
                </div>
            </div>
        `;
    }

    private renderSummaryCards(summary: ScanSummary): string {
        return `
            <div class="summary-section">
                <div class="summary-cards">
                    <div class="summary-card total">
                        <div class="summary-count">${summary.total}</div>
                        <div class="summary-label">Total</div>
                    </div>
                    <div class="summary-card critical">
                        <div class="summary-count">${summary.critical}</div>
                        <div class="summary-label">Critical</div>
                    </div>
                    <div class="summary-card high">
                        <div class="summary-count">${summary.high}</div>
                        <div class="summary-label">High</div>
                    </div>
                    <div class="summary-card medium">
                        <div class="summary-count">${summary.medium}</div>
                        <div class="summary-label">Medium</div>
                    </div>
                    <div class="summary-card low">
                        <div class="summary-count">${summary.low}</div>
                        <div class="summary-label">Low</div>
                    </div>
                    <div class="summary-card info">
                        <div class="summary-count">${summary.info}</div>
                        <div class="summary-label">Info</div>
                    </div>
                </div>
            </div>
        `;
    }

    private renderVulnerabilityTable(): string {
        if (this.filteredVulnerabilities.length === 0) {
            return `
                <div class="vulnerabilities-section">
                    <div class="no-results">
                        <div class="no-results-icon">\u2713</div>
                        <p>No vulnerabilities found!</p>
                    </div>
                </div>
            `;
        }

        const startIdx = (this.currentPage - 1) * this.pageSize;
        const endIdx = Math.min(startIdx + this.pageSize, this.filteredVulnerabilities.length);
        const pageVulns = this.filteredVulnerabilities.slice(startIdx, endIdx);

        const rows = pageVulns.map(v => this.renderVulnerabilityRow(v)).join("");

        return `
            <div class="vulnerabilities-section">
                <div class="section-header">
                    <h2 class="section-title">Vulnerabilities</h2>
                    <div class="filter-controls">
                        <input type="text"
                               class="search-input"
                               id="search-input"
                               placeholder="Search CVE, package..."
                               value="${this.escapeHtml(this.searchQuery)}">
                        <select class="filter-select" id="severity-filter">
                            <option value="all" ${this.filterSeverity === "all" ? "selected" : ""}>All Severities</option>
                            <option value="5" ${this.filterSeverity === "5" ? "selected" : ""}>Critical</option>
                            <option value="4" ${this.filterSeverity === "4" ? "selected" : ""}>High</option>
                            <option value="3" ${this.filterSeverity === "3" ? "selected" : ""}>Medium</option>
                            <option value="2" ${this.filterSeverity === "2" ? "selected" : ""}>Low</option>
                            <option value="1" ${this.filterSeverity === "1" ? "selected" : ""}>Info</option>
                        </select>
                    </div>
                </div>
                <table class="vuln-table">
                    <thead>
                        <tr>
                            <th data-sort="severity" class="${this.sortColumn === "severity" ? "sorted" : ""}">
                                Severity <span class="sort-icon">${this.sortDirection === "desc" ? "\u25BC" : "\u25B2"}</span>
                            </th>
                            <th data-sort="cves">CVE / QID</th>
                            <th data-sort="cvssScore" class="${this.sortColumn === "cvssScore" ? "sorted" : ""}">
                                CVSS <span class="sort-icon">${this.sortDirection === "desc" ? "\u25BC" : "\u25B2"}</span>
                            </th>
                            <th data-sort="packageName" class="${this.sortColumn === "packageName" ? "sorted" : ""}">
                                Package <span class="sort-icon">${this.sortDirection === "desc" ? "\u25BC" : "\u25B2"}</span>
                            </th>
                            <th>Version</th>
                            <th>Fixed In</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${rows}
                    </tbody>
                </table>
                ${this.renderPagination()}
            </div>
        `;
    }

    private renderVulnerabilityRow(v: VulnerabilityRow): string {
        const severityClass = v.severityLabel.toLowerCase();
        const cveDisplay = v.cves.length > 0
            ? v.cves.map(cve =>
                `<a href="https://nvd.nist.gov/vuln/detail/${cve}" target="_blank" class="cve-link">${cve}</a>`
              ).join(", ")
            : (v.qid ? `QID-${v.qid}` : v.id);

        const cvssDisplay = v.cvssScore !== undefined
            ? `<span class="cvss-score ${this.getCvssClass(v.cvssScore)}">${v.cvssScore.toFixed(1)}</span>`
            : "-";

        return `
            <tr class="vuln-row">
                <td><span class="severity-badge ${severityClass}">${v.severityLabel}</span></td>
                <td>${cveDisplay}</td>
                <td>${cvssDisplay}</td>
                <td><span class="package-name">${this.escapeHtml(v.packageName)}</span></td>
                <td><span class="version-info">${this.escapeHtml(v.installedVersion)}</span></td>
                <td>${v.fixedVersion ? `<span class="fixed-version">${this.escapeHtml(v.fixedVersion)}</span>` : "-"}</td>
            </tr>
        `;
    }

    private getCvssClass(score: number): string {
        if (score >= 9.0) return "critical";
        if (score >= 7.0) return "high";
        if (score >= 4.0) return "medium";
        return "low";
    }

    private renderPagination(): string {
        const totalPages = Math.ceil(this.filteredVulnerabilities.length / this.pageSize);
        if (totalPages <= 1) return "";

        const startIdx = (this.currentPage - 1) * this.pageSize + 1;
        const endIdx = Math.min(this.currentPage * this.pageSize, this.filteredVulnerabilities.length);

        return `
            <div class="pagination">
                <div class="pagination-info">
                    Showing ${startIdx}-${endIdx} of ${this.filteredVulnerabilities.length} vulnerabilities
                </div>
                <div class="pagination-controls">
                    <button class="pagination-btn" id="prev-page" ${this.currentPage === 1 ? "disabled" : ""}>
                        Previous
                    </button>
                    <span style="padding: 0 12px; line-height: 32px;">
                        Page ${this.currentPage} of ${totalPages}
                    </span>
                    <button class="pagination-btn" id="next-page" ${this.currentPage === totalPages ? "disabled" : ""}>
                        Next
                    </button>
                </div>
            </div>
        `;
    }

    private renderScanInfo(): string {
        return `
            <div class="scan-info">
                <div class="scan-info-grid">
                    <div class="scan-info-item">
                        <strong>Build ID:</strong> ${this.buildId}
                    </div>
                    <div class="scan-info-item">
                        <strong>Scanner:</strong> Qualys QScanner
                    </div>
                </div>
            </div>
        `;
    }

    private attachEventListeners(): void {
        // Severity filter
        const severityFilter = document.getElementById("severity-filter") as HTMLSelectElement;
        if (severityFilter) {
            severityFilter.addEventListener("change", (e) => {
                this.filterSeverity = (e.target as HTMLSelectElement).value;
                this.applyFilters();
            });
        }

        // Search input
        const searchInput = document.getElementById("search-input") as HTMLInputElement;
        if (searchInput) {
            let debounceTimer: ReturnType<typeof setTimeout>;
            searchInput.addEventListener("input", (e) => {
                clearTimeout(debounceTimer);
                debounceTimer = setTimeout(() => {
                    this.searchQuery = (e.target as HTMLInputElement).value;
                    this.applyFilters();
                }, 300);
            });
        }

        // Sort headers
        const sortHeaders = document.querySelectorAll("th[data-sort]");
        sortHeaders.forEach(header => {
            header.addEventListener("click", () => {
                const column = header.getAttribute("data-sort");
                if (column) {
                    if (this.sortColumn === column) {
                        this.sortDirection = this.sortDirection === "asc" ? "desc" : "asc";
                    } else {
                        this.sortColumn = column;
                        this.sortDirection = "desc";
                    }
                    this.sortVulnerabilities();
                    this.renderResults();
                }
            });
        });

        // Pagination
        const prevBtn = document.getElementById("prev-page");
        const nextBtn = document.getElementById("next-page");

        if (prevBtn) {
            prevBtn.addEventListener("click", () => {
                if (this.currentPage > 1) {
                    this.currentPage--;
                    this.renderResults();
                }
            });
        }

        if (nextBtn) {
            nextBtn.addEventListener("click", () => {
                const totalPages = Math.ceil(this.filteredVulnerabilities.length / this.pageSize);
                if (this.currentPage < totalPages) {
                    this.currentPage++;
                    this.renderResults();
                }
            });
        }
    }

    private applyFilters(): void {
        this.filteredVulnerabilities = this.vulnerabilities.filter(v => {
            // Severity filter
            if (this.filterSeverity !== "all" && v.severity !== parseInt(this.filterSeverity)) {
                return false;
            }

            // Search filter
            if (this.searchQuery) {
                const query = this.searchQuery.toLowerCase();
                const searchFields = [
                    v.id,
                    v.packageName,
                    v.description,
                    ...v.cves,
                    v.qid?.toString() || ""
                ].join(" ").toLowerCase();

                if (!searchFields.includes(query)) {
                    return false;
                }
            }

            return true;
        });

        this.currentPage = 1;
        this.sortVulnerabilities();
        this.renderResults();
    }

    private sortVulnerabilities(): void {
        this.filteredVulnerabilities.sort((a, b) => {
            let aVal: string | number = "";
            let bVal: string | number = "";

            switch (this.sortColumn) {
                case "severity":
                    aVal = a.severity;
                    bVal = b.severity;
                    break;
                case "cvssScore":
                    aVal = a.cvssScore ?? -1;
                    bVal = b.cvssScore ?? -1;
                    break;
                case "packageName":
                    aVal = a.packageName.toLowerCase();
                    bVal = b.packageName.toLowerCase();
                    break;
                default:
                    return 0;
            }

            if (aVal < bVal) return this.sortDirection === "asc" ? -1 : 1;
            if (aVal > bVal) return this.sortDirection === "asc" ? 1 : -1;
            return 0;
        });
    }

    private showError(message: string): void {
        const loading = document.getElementById("loading");
        const error = document.getElementById("error");
        const errorMessage = document.getElementById("error-message");

        if (loading) loading.style.display = "none";
        if (error) error.style.display = "flex";
        if (errorMessage) errorMessage.textContent = message;
    }

    private showNoResults(message: string): void {
        const loading = document.getElementById("loading");
        const content = document.getElementById("content");

        if (loading) loading.style.display = "none";
        if (content) {
            content.style.display = "block";
            content.innerHTML = `
                <div class="results-header">
                    <svg class="qualys-logo" viewBox="0 0 100 100">
                        <circle cx="50" cy="50" r="45" fill="#ed1c24"/>
                        <text x="50" y="60" text-anchor="middle" fill="white" font-size="30" font-weight="bold">Q</text>
                    </svg>
                    <h1 class="results-title">Qualys Security Scan Results</h1>
                </div>
                <div class="no-results">
                    <div class="no-results-icon">\u2139</div>
                    <p>${this.escapeHtml(message)}</p>
                </div>
            `;
        }
    }

    private escapeHtml(text: string): string {
        const div = document.createElement("div");
        div.textContent = text;
        return div.innerHTML;
    }
}

// Initialize when DOM is ready
document.addEventListener("DOMContentLoaded", () => {
    const tab = new QualysScanResultsTab();
    tab.initialize();
});
