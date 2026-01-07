import * as SDK from "azure-devops-extension-sdk";
import { CommonServiceIds, IProjectPageService } from "azure-devops-extension-api";
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
    properties?: {
        severity?: number;
        customerSeverity?: number;
        "cve-ids"?: string[];
        cvss3Info?: {
            baseScore?: string;
            temporalScore?: string;
        };
        cvssInfo?: {
            baseScore?: string;
            temporalScore?: string;
        };
        [key: string]: unknown;
    };
}

interface VulnerableSoftware {
    name: string;
    path: string;
    installedVersion: string;
    fixedVersion: string;
    layerSHA?: string;
}

interface SarifResult {
    ruleId: string;
    ruleIndex?: number;
    level: "error" | "warning" | "note" | "none";
    message: { text: string };
    locations?: SarifLocation[];
    properties?: {
        QID?: number;
        vulnerableSoftware?: VulnerableSoftware[];
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
    layerSHA?: string;
}

interface PackageInfo {
    name: string;
    version: string;
    type: string;
    layerSHA?: string;
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
    private projectId!: string;
    private buildId!: number;
    private vulnerabilities: VulnerabilityRow[] = [];
    private filteredVulnerabilities: VulnerabilityRow[] = [];
    private packages: PackageInfo[] = [];
    private filteredPackages: PackageInfo[] = [];
    private layers: string[] = [];
    private currentPage = 1;
    private pageSize: number | "all" = 25;
    private sortColumn = "severity";
    private sortDirection: "asc" | "desc" = "desc";
    private filterSeverity = "all";
    private filterLayer = "all";
    private searchQuery = "";
    // Package table state
    private pkgPageSize: number | "all" = 25;
    private pkgFilterLayer = "all";
    private pkgSearchQuery = "";
    private scanType: "container" | "sca" | "all" = "all";
    private initialized = false;

    async initialize(): Promise<void> {
        try {
            await SDK.init();
            await SDK.ready();

            // Determine scan type from contribution ID
            const contributionId = SDK.getContributionId();
            console.log("Contribution ID:", contributionId);

            if (contributionId.includes("container") || contributionId.includes("image")) {
                this.scanType = "container";
            } else if (contributionId.includes("sca") || contributionId.includes("code")) {
                this.scanType = "sca";  // Internal type stays as "sca" for compatibility
            }
            console.log("Scan type:", this.scanType);

            // Get project info first
            const projectService = await SDK.getService<IProjectPageService>(
                CommonServiceIds.ProjectPageService
            );
            const project = await projectService.getProject();
            if (!project) {
                throw new Error("Project not available");
            }
            this.projectId = project.id;
            this.initialized = true;

            const config = SDK.getConfiguration();
            console.log("SDK Configuration:", JSON.stringify(config, null, 2));

            // For build result tabs, register contribution and get build via callback
            SDK.register(SDK.getContributionId(), () => {
                return {
                    // Called when build changes/loads
                    onBuildChanged: (build: { id: number; buildNumber: string }) => {
                        console.log("Build changed:", build);
                        if (build && build.id) {
                            this.buildId = build.id;
                            this.onBuildAvailable();
                        }
                    }
                };
            });

            // Also try to get build from the configuration callbacks
            if (config.onBuildChanged) {
                config.onBuildChanged((build: { id: number; buildNumber: string }) => {
                    console.log("Build from config callback:", build);
                    if (build && build.id && !this.buildId) {
                        this.buildId = build.id;
                        this.onBuildAvailable();
                    }
                });
            }

            SDK.notifyLoadSucceeded();
        } catch (error) {
            this.showError(error instanceof Error ? error.message : "Failed to initialize");
            SDK.notifyLoadSucceeded();
        }
    }

    private async onBuildAvailable(): Promise<void> {
        if (!this.buildId || !this.initialized) return;

        console.log("Loading results for build:", this.buildId, "scan type:", this.scanType);
        try {
            await this.loadScanResults();
        } catch (error) {
            console.error("Error loading scan results:", error);
            this.showError(error instanceof Error ? error.message : "Failed to load results");
        }
    }

    private async loadScanResults(): Promise<void> {
        try {
            // Get access token for API calls
            const accessToken = await SDK.getAccessToken();
            const hostUrl = SDK.getHost().name;
            const baseUrl = `https://dev.azure.com/${hostUrl}`;

            console.log("Fetching artifacts from:", `${baseUrl}/${this.projectId}/_apis/build/builds/${this.buildId}/artifacts`);

            // Get build artifacts using REST API directly
            const artifactsResponse = await fetch(
                `${baseUrl}/${this.projectId}/_apis/build/builds/${this.buildId}/artifacts?api-version=7.0`,
                {
                    headers: {
                        "Authorization": `Bearer ${accessToken}`,
                        "Content-Type": "application/json"
                    }
                }
            );

            if (!artifactsResponse.ok) {
                throw new Error(`Failed to fetch artifacts: ${artifactsResponse.status} ${artifactsResponse.statusText}`);
            }

            const artifactsData = await artifactsResponse.json();
            console.log("Artifacts response:", JSON.stringify(artifactsData, null, 2));

            // Log all artifact names
            const allArtifactNames = (artifactsData.value || []).map((a: { name: string }) => a.name);
            console.log("All artifact names:", allArtifactNames);

            // Filter artifacts based on scan type - use exact pattern matching
            // Note: "sca" is a substring of "scan", so we need careful matching
            let qualysArtifacts = (artifactsData.value || []).filter((a: { name: string }) => {
                const name = a.name.toLowerCase();
                // Check for specific patterns using word boundaries
                const isContainerScan = name.includes("container") || name.includes("image");
                const isCodeScan = name.includes("-sca-") || name.endsWith("-sca") ||
                                   name.includes("sca-scan") || name === "qualys-sca-scan" ||
                                   name.includes("-code-") || name.endsWith("-code") ||
                                   name.includes("code-scan") || name === "qualys-code-scan";

                if (this.scanType === "container") {
                    // Match container/image scans only
                    return name.includes("qualys") && isContainerScan && !isCodeScan;
                } else if (this.scanType === "sca") {
                    // Match code/sca scans only
                    return name.includes("qualys") && isCodeScan && !isContainerScan;
                } else {
                    return name.includes("qualys");
                }
            });

            console.log("Filtered artifacts for scan type", this.scanType, ":", qualysArtifacts.map((a: { name: string }) => a.name));

            // If no matches, try broader search for any artifact with SARIF
            if (qualysArtifacts.length === 0) {
                console.log("No scan-type specific artifacts found, trying all artifacts");
                qualysArtifacts = artifactsData.value || [];
            }

            if (qualysArtifacts.length === 0) {
                this.showNoResults("No artifacts found for this build.");
                return;
            }

            let sarifReport: SarifReport | null = null;

            // Try to download artifact content
            for (const artifact of qualysArtifacts) {
                console.log("Processing artifact:", JSON.stringify(artifact, null, 2));

                const downloadUrl = artifact.resource?.downloadUrl;
                const containerData = artifact.resource?.data;

                console.log("Artifact details - name:", artifact.name, "containerData:", containerData, "downloadUrl:", downloadUrl);

                if (!containerData) {
                    console.log("No container data for artifact:", artifact.name);
                    continue;
                }

                // Parse container data format: "#/36383091/QualysSCAResults"
                // Extract container ID and path
                const containerMatch = containerData.match(/^#\/(\d+)\/(.+)$/);
                if (!containerMatch) {
                    console.log("Unable to parse container data format:", containerData);
                    continue;
                }

                const containerId = containerMatch[1];
                const containerPath = containerMatch[2];
                console.log("Parsed container ID:", containerId, "path:", containerPath);

                try {
                    // Use the File Container Items API to list files in the container
                    // Format: /_apis/resources/Containers/{containerId}?itemPath={path}&isShallow=false
                    // Note: Container API requires -preview suffix
                    const containerUrl = `${baseUrl}/_apis/resources/Containers/${containerId}?itemPath=${encodeURIComponent(containerPath)}&isShallow=false&%24format=json&api-version=7.0-preview`;
                    console.log("Container URL:", containerUrl);

                    const containerResponse = await fetch(containerUrl, {
                        headers: {
                            "Authorization": `Bearer ${accessToken}`,
                            "Accept": "application/json"
                        }
                    });

                    console.log("Container response status:", containerResponse.status);

                    if (containerResponse.ok) {
                        const containerItems = await containerResponse.json();
                        console.log("Container items:", JSON.stringify(containerItems, null, 2));

                        const items = containerItems.value || [];

                        // List all items
                        const allItems = items.map((f: { path?: string; itemType?: string }) =>
                            `${f.path || "unknown"} (${f.itemType || "?"})`
                        );
                        console.log("Items in container:", allItems);

                        // Find SARIF file - look for files (itemType=file or folder) with .sarif extension
                        const sarifFile = items.find((f: { path?: string; itemType?: string }) => {
                            const itemPath = f.path || "";
                            return (itemPath.endsWith(".sarif.json") || itemPath.endsWith(".sarif") ||
                                    itemPath.includes("-Report.sarif")) && f.itemType === "file";
                        });

                        if (sarifFile) {
                            console.log("Found SARIF file:", sarifFile.path);

                            // Download the file content
                            const sarifUrl = `${baseUrl}/_apis/resources/Containers/${containerId}?itemPath=${encodeURIComponent(sarifFile.path)}&api-version=7.0-preview`;
                            console.log("SARIF download URL:", sarifUrl);

                            const sarifResponse = await fetch(sarifUrl, {
                                headers: {
                                    "Authorization": `Bearer ${accessToken}`,
                                    "Accept": "application/octet-stream"
                                }
                            });

                            console.log("SARIF response status:", sarifResponse.status);

                            if (sarifResponse.ok) {
                                const text = await sarifResponse.text();
                                console.log("SARIF content preview:", text.substring(0, 500));

                                if (text.includes('"$schema"') || text.includes('"runs"')) {
                                    sarifReport = JSON.parse(text);
                                    console.log("SARIF loaded successfully, runs:", sarifReport?.runs?.length);
                                    break;
                                } else {
                                    console.log("Content doesn't look like SARIF");
                                }
                            } else {
                                console.log("Failed to download SARIF:", sarifResponse.statusText);
                            }
                        } else {
                            console.log("No SARIF file found in container items. Looking for any file...");
                            // Try to find any file if no SARIF pattern match
                            const anyFile = items.find((f: { itemType?: string }) => f.itemType === "file");
                            console.log("First file found:", anyFile?.path);
                        }
                    } else {
                        const errorText = await containerResponse.text();
                        console.log("Container API error:", errorText);
                    }
                } catch (err) {
                    console.error("Error loading artifact:", artifact.name, err);
                    continue;
                }
            }

            if (!sarifReport) {
                const names = qualysArtifacts.map((a: { name: string }) => a.name).join(", ");
                this.showNoResults(
                    `Scan results available in artifacts: ${names}. Unable to load SARIF content automatically.`
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
            console.log("No runs found in SARIF report");
            return;
        }

        console.log("Parsing SARIF with", run.results?.length, "results and", run.tool?.driver?.rules?.length, "rules");

        const rulesMap = new Map<string, SarifRule>();
        run.tool.driver.rules?.forEach(rule => {
            rulesMap.set(rule.id, rule);
        });

        const layerSet = new Set<string>();
        const seenPackages = new Set<string>();
        this.packages = [];
        this.vulnerabilities = [];

        // Process results - create one vulnerability per package (like Jenkins)
        run.results.forEach(result => {
            const rule = rulesMap.get(result.ruleId);
            const severity = this.getSeverity(result, rule);

            // Get CVEs from rule properties (cve-ids array)
            const cves = rule?.properties?.["cve-ids"] || [];

            // Get CVSS score from rule properties
            let cvssScore: number | undefined;
            if (rule?.properties?.cvss3Info?.baseScore) {
                cvssScore = parseFloat(rule.properties.cvss3Info.baseScore);
            } else if (rule?.properties?.cvssInfo?.baseScore) {
                cvssScore = parseFloat(rule.properties.cvssInfo.baseScore);
            }

            // Get package info from vulnerableSoftware array
            const vulnSoftwareList = result.properties?.vulnerableSoftware || [];

            if (vulnSoftwareList.length > 0) {
                // Create one vulnerability row per affected package
                vulnSoftwareList.forEach(vulnSoftware => {
                    const packageName = vulnSoftware.name || this.extractPackageName(result);
                    const installedVersion = vulnSoftware.installedVersion || "";
                    const fixedVersion = vulnSoftware.fixedVersion || "";
                    const layerSHA = vulnSoftware.layerSHA;

                    // Track layers
                    if (layerSHA) {
                        layerSet.add(layerSHA);
                    }

                    // Track packages for software inventory
                    const pkgKey = `${packageName}:${installedVersion}`;
                    if (!seenPackages.has(pkgKey) && packageName) {
                        seenPackages.add(pkgKey);
                        this.packages.push({
                            name: packageName,
                            version: installedVersion,
                            type: this.detectPackageType(vulnSoftware.path || packageName),
                            layerSHA
                        });
                    }

                    this.vulnerabilities.push({
                        id: result.ruleId,
                        severity,
                        severityLabel: this.getSeverityLabel(severity),
                        cves,
                        qid: result.properties?.QID,
                        cvssScore,
                        packageName,
                        installedVersion,
                        fixedVersion,
                        description: result.message.text || rule?.shortDescription?.text || "",
                        location: this.extractLocation(result),
                        layerSHA
                    });
                });
            } else {
                // No vulnerableSoftware - create single vulnerability row
                const packageName = this.extractPackageName(result);
                this.vulnerabilities.push({
                    id: result.ruleId,
                    severity,
                    severityLabel: this.getSeverityLabel(severity),
                    cves,
                    qid: result.properties?.QID,
                    cvssScore,
                    packageName,
                    installedVersion: "",
                    fixedVersion: "",
                    description: result.message.text || rule?.shortDescription?.text || "",
                    location: this.extractLocation(result)
                });
            }
        });

        // Store unique layers sorted
        this.layers = Array.from(layerSet).sort();

        console.log("Parsed", this.vulnerabilities.length, "vulnerabilities,", this.packages.length, "packages,", this.layers.length, "layers");
        this.filteredVulnerabilities = [...this.vulnerabilities];
        this.filteredPackages = [...this.packages];
        this.sortVulnerabilities();
    }

    private detectPackageType(pathOrName: string): string {
        const lower = pathOrName.toLowerCase();
        if (lower.includes("node_modules") || lower.endsWith(".js") || lower.includes("npm")) return "npm";
        if (lower.endsWith(".jar") || lower.includes("maven") || lower.includes("gradle")) return "maven";
        if (lower.endsWith(".whl") || lower.includes("pip") || lower.includes("python")) return "pip";
        if (lower.includes("apt") || lower.endsWith(".deb")) return "deb";
        if (lower.includes("rpm") || lower.includes("yum")) return "rpm";
        if (lower.includes("apk")) return "apk";
        if (lower.includes("gem") || lower.endsWith(".gem")) return "gem";
        if (lower.includes("nuget") || lower.endsWith(".nupkg")) return "nuget";
        if (lower.includes("cargo") || lower.endsWith(".crate")) return "cargo";
        if (lower.includes("go") || lower.includes("golang")) return "go";
        return "unknown";
    }

    private getSeverity(result: SarifResult, rule?: SarifRule): number {
        // Get severity from rule properties (Qualys uses severity or customerSeverity)
        if (rule?.properties?.severity !== undefined) {
            return rule.properties.severity;
        }
        if (rule?.properties?.customerSeverity !== undefined) {
            return rule.properties.customerSeverity;
        }

        // Fall back to SARIF level mapping
        const levelMap: Record<string, number> = {
            error: 4,  // High
            warning: 3, // Medium
            note: 2,   // Low
            none: 1    // Info
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
            ${this.renderPackagesTable()}
            ${this.renderScanInfo()}
        `;

        this.attachEventListeners();
    }

    private renderHeader(summary: ScanSummary): string {
        const statusClass = summary.passed ? "passed" : "failed";
        const statusText = summary.passed ? "Passed" : "Failed";
        const statusIcon = summary.passed ? "\u2713" : "\u2717";

        let title = "Qualys Security Scan Results";
        if (this.scanType === "container") {
            title = "Qualys Container Image Scan Results";
        } else if (this.scanType === "sca") {
            title = "Qualys Code Scan Results";
        }

        return `
            <div class="results-header">
                <img class="qualys-logo" src="data:image/png;base64,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
dBz" alt="Qualys Logo" />
                <h1 class="results-title">${title}</h1>
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
        if (this.vulnerabilities.length === 0) {
            return `
                <div class="vulnerabilities-section">
                    <div class="no-results">
                        <div class="no-results-icon">\u2713</div>
                        <p>No vulnerabilities found!</p>
                    </div>
                </div>
            `;
        }

        const effectivePageSize = this.pageSize === "all" ? this.filteredVulnerabilities.length : this.pageSize;
        const startIdx = (this.currentPage - 1) * effectivePageSize;
        const endIdx = Math.min(startIdx + effectivePageSize, this.filteredVulnerabilities.length);
        const pageVulns = this.filteredVulnerabilities.slice(startIdx, endIdx);

        const rows = pageVulns.map(v => this.renderVulnerabilityRow(v)).join("");

        const layerOptions = this.layers.length > 0
            ? this.layers.map(layer => {
                const shortLayer = layer.startsWith("sha256:") ? layer.substring(7, 19) : layer.substring(0, 12);
                return `<option value="${this.escapeHtml(layer)}" ${this.filterLayer === layer ? "selected" : ""}>${shortLayer}</option>`;
              }).join("")
            : "";

        return `
            <div class="vulnerabilities-section">
                <div class="section-header">
                    <h2 class="section-title">Vulnerabilities (<span id="vuln-count">${this.filteredVulnerabilities.length}</span>)</h2>
                    <div class="filter-controls">
                        <input type="text"
                               class="search-input"
                               id="search-input"
                               placeholder="Search CVE, package, QID..."
                               value="${this.escapeHtml(this.searchQuery)}">
                        <select class="filter-select" id="severity-filter">
                            <option value="all" ${this.filterSeverity === "all" ? "selected" : ""}>All Severities</option>
                            <option value="5" ${this.filterSeverity === "5" ? "selected" : ""}>Critical</option>
                            <option value="4" ${this.filterSeverity === "4" ? "selected" : ""}>High</option>
                            <option value="3" ${this.filterSeverity === "3" ? "selected" : ""}>Medium</option>
                            <option value="2" ${this.filterSeverity === "2" ? "selected" : ""}>Low</option>
                            <option value="1" ${this.filterSeverity === "1" ? "selected" : ""}>Info</option>
                        </select>
                        ${this.layers.length > 0 ? `
                        <select class="filter-select" id="layer-filter">
                            <option value="all" ${this.filterLayer === "all" ? "selected" : ""}>All Layers</option>
                            ${layerOptions}
                        </select>
                        ` : ""}
                        <select class="filter-select" id="page-size-select">
                            <option value="25" ${this.pageSize === 25 ? "selected" : ""}>Show 25</option>
                            <option value="50" ${this.pageSize === 50 ? "selected" : ""}>Show 50</option>
                            <option value="all" ${this.pageSize === "all" ? "selected" : ""}>Show All</option>
                        </select>
                    </div>
                </div>
                <div id="vuln-no-results" class="no-results" style="display: ${this.filteredVulnerabilities.length === 0 ? "block" : "none"};">
                    <p>No vulnerabilities match your search criteria.</p>
                </div>
                <table class="vuln-table" style="display: ${this.filteredVulnerabilities.length === 0 ? "none" : "table"};">
                    <thead>
                        <tr>
                            <th data-sort="severity" class="${this.sortColumn === "severity" ? "sorted" : ""}">
                                Severity <span class="sort-icon">${this.sortDirection === "desc" ? "\u25BC" : "\u25B2"}</span>
                            </th>
                            <th data-sort="qid">QID</th>
                            <th data-sort="cves">CVE</th>
                            <th data-sort="cvssScore" class="${this.sortColumn === "cvssScore" ? "sorted" : ""}">
                                CVSS <span class="sort-icon">${this.sortDirection === "desc" ? "\u25BC" : "\u25B2"}</span>
                            </th>
                            <th data-sort="packageName" class="${this.sortColumn === "packageName" ? "sorted" : ""}">
                                Package <span class="sort-icon">${this.sortDirection === "desc" ? "\u25BC" : "\u25B2"}</span>
                            </th>
                            <th>Version</th>
                            <th>Fixed In</th>
                            ${this.layers.length > 0 ? "<th>Layer</th>" : ""}
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
        const qidDisplay = v.qid ? `QID-${v.qid}` : "-";
        const cveDisplay = v.cves.length > 0
            ? v.cves.map(cve =>
                `<a href="https://nvd.nist.gov/vuln/detail/${cve}" target="_blank" class="cve-link">${cve}</a>`
              ).join(", ")
            : "-";

        const cvssDisplay = v.cvssScore !== undefined
            ? `<span class="cvss-score ${this.getCvssClass(v.cvssScore)}">${v.cvssScore.toFixed(1)}</span>`
            : "-";

        const layerDisplay = this.layers.length > 0
            ? (v.layerSHA
                ? `<span class="layer-badge" title="${this.escapeHtml(v.layerSHA)}">${this.getShortLayer(v.layerSHA)}</span>`
                : "-")
            : "";

        return `
            <tr class="vuln-row">
                <td><span class="severity-badge ${severityClass}">${v.severityLabel}</span></td>
                <td>${qidDisplay}</td>
                <td>${cveDisplay}</td>
                <td>${cvssDisplay}</td>
                <td><span class="package-name">${this.escapeHtml(v.packageName)}</span></td>
                <td><span class="version-info">${this.escapeHtml(v.installedVersion)}</span></td>
                <td>${v.fixedVersion ? `<span class="fixed-version">${this.escapeHtml(v.fixedVersion)}</span>` : "-"}</td>
                ${this.layers.length > 0 ? `<td>${layerDisplay}</td>` : ""}
            </tr>
        `;
    }

    private getShortLayer(layerSHA: string): string {
        if (layerSHA.startsWith("sha256:")) {
            return layerSHA.substring(7, 19);
        }
        return layerSHA.substring(0, 12);
    }

    private getCvssClass(score: number): string {
        if (score >= 9.0) return "critical";
        if (score >= 7.0) return "high";
        if (score >= 4.0) return "medium";
        return "low";
    }

    private renderPagination(): string {
        if (this.pageSize === "all") {
            return `
                <div class="pagination">
                    <div class="pagination-info">
                        Showing all ${this.filteredVulnerabilities.length} vulnerabilities
                    </div>
                </div>
            `;
        }

        const totalPages = Math.ceil(this.filteredVulnerabilities.length / this.pageSize);
        if (totalPages <= 1) {
            return `
                <div class="pagination">
                    <div class="pagination-info">
                        Showing ${this.filteredVulnerabilities.length} of ${this.filteredVulnerabilities.length} vulnerabilities
                    </div>
                </div>
            `;
        }

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

    private renderPackagesTable(): string {
        if (this.packages.length === 0) {
            return "";
        }

        const effectivePageSize = this.pkgPageSize === "all" ? this.filteredPackages.length : this.pkgPageSize;
        const displayedPackages = this.filteredPackages.slice(0, effectivePageSize);

        const layerOptions = this.layers.length > 0
            ? this.layers.map(layer => {
                const shortLayer = layer.startsWith("sha256:") ? layer.substring(7, 19) : layer.substring(0, 12);
                return `<option value="${this.escapeHtml(layer)}" ${this.pkgFilterLayer === layer ? "selected" : ""}>${shortLayer}</option>`;
              }).join("")
            : "";

        const rows = displayedPackages.map(pkg => {
            const layerDisplay = this.layers.length > 0
                ? (pkg.layerSHA
                    ? `<span class="layer-badge" title="${this.escapeHtml(pkg.layerSHA)}">${this.getShortLayer(pkg.layerSHA)}</span>`
                    : "-")
                : "";
            return `
                <tr>
                    <td><span class="package-name">${this.escapeHtml(pkg.name)}</span></td>
                    <td><span class="version-info">${this.escapeHtml(pkg.version || "-")}</span></td>
                    <td>${this.escapeHtml(pkg.type || "-")}</td>
                    ${this.layers.length > 0 ? `<td>${layerDisplay}</td>` : ""}
                </tr>
            `;
        }).join("");

        const showingCount = displayedPackages.length;
        const totalCount = this.filteredPackages.length;

        return `
            <div class="packages-section">
                <div class="section-header">
                    <h2 class="section-title">Software Inventory (<span id="pkg-count">${this.filteredPackages.length}</span>)</h2>
                    <div class="filter-controls">
                        <input type="text"
                               class="search-input"
                               id="pkg-search-input"
                               placeholder="Search package name..."
                               value="${this.escapeHtml(this.pkgSearchQuery)}">
                        ${this.layers.length > 0 ? `
                        <select class="filter-select" id="pkg-layer-filter">
                            <option value="all" ${this.pkgFilterLayer === "all" ? "selected" : ""}>All Layers</option>
                            ${layerOptions}
                        </select>
                        ` : ""}
                        <select class="filter-select" id="pkg-page-size-select">
                            <option value="25" ${this.pkgPageSize === 25 ? "selected" : ""}>Show 25</option>
                            <option value="50" ${this.pkgPageSize === 50 ? "selected" : ""}>Show 50</option>
                            <option value="all" ${this.pkgPageSize === "all" ? "selected" : ""}>Show All</option>
                        </select>
                    </div>
                </div>
                <div id="pkg-no-results" class="no-results" style="display: ${this.filteredPackages.length === 0 ? "block" : "none"};">
                    <p>No packages match your search criteria.</p>
                </div>
                <table class="vuln-table pkg-table" style="display: ${this.filteredPackages.length === 0 ? "none" : "table"};">
                    <thead>
                        <tr>
                            <th>Package Name</th>
                            <th>Version</th>
                            <th>Type</th>
                            ${this.layers.length > 0 ? "<th>Layer</th>" : ""}
                        </tr>
                    </thead>
                    <tbody>
                        ${rows}
                    </tbody>
                </table>
                <div class="pagination">
                    <div class="pagination-info">
                        Showing ${showingCount} of ${totalCount} packages
                    </div>
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

        // Layer filter (vulnerability table)
        const layerFilter = document.getElementById("layer-filter") as HTMLSelectElement;
        if (layerFilter) {
            layerFilter.addEventListener("change", (e) => {
                this.filterLayer = (e.target as HTMLSelectElement).value;
                this.applyFilters();
            });
        }

        // Page size selector (vulnerability table)
        const pageSizeSelect = document.getElementById("page-size-select") as HTMLSelectElement;
        if (pageSizeSelect) {
            pageSizeSelect.addEventListener("change", (e) => {
                const value = (e.target as HTMLSelectElement).value;
                this.pageSize = value === "all" ? "all" : parseInt(value);
                this.currentPage = 1;
                this.renderResults();
            });
        }

        // Search input (vulnerability table)
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

        // Package search input
        const pkgSearchInput = document.getElementById("pkg-search-input") as HTMLInputElement;
        if (pkgSearchInput) {
            let debounceTimer: ReturnType<typeof setTimeout>;
            pkgSearchInput.addEventListener("input", (e) => {
                clearTimeout(debounceTimer);
                debounceTimer = setTimeout(() => {
                    this.pkgSearchQuery = (e.target as HTMLInputElement).value;
                    this.applyPackageFilters();
                }, 300);
            });
        }

        // Package layer filter
        const pkgLayerFilter = document.getElementById("pkg-layer-filter") as HTMLSelectElement;
        if (pkgLayerFilter) {
            pkgLayerFilter.addEventListener("change", (e) => {
                this.pkgFilterLayer = (e.target as HTMLSelectElement).value;
                this.applyPackageFilters();
            });
        }

        // Package page size selector
        const pkgPageSizeSelect = document.getElementById("pkg-page-size-select") as HTMLSelectElement;
        if (pkgPageSizeSelect) {
            pkgPageSizeSelect.addEventListener("change", (e) => {
                const value = (e.target as HTMLSelectElement).value;
                this.pkgPageSize = value === "all" ? "all" : parseInt(value);
                this.renderResults();
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
                if (this.pageSize !== "all") {
                    const totalPages = Math.ceil(this.filteredVulnerabilities.length / this.pageSize);
                    if (this.currentPage < totalPages) {
                        this.currentPage++;
                        this.renderResults();
                    }
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

            // Layer filter
            if (this.filterLayer !== "all" && v.layerSHA !== this.filterLayer) {
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

    private applyPackageFilters(): void {
        this.filteredPackages = this.packages.filter(pkg => {
            // Layer filter
            if (this.pkgFilterLayer !== "all" && pkg.layerSHA !== this.pkgFilterLayer) {
                return false;
            }

            // Search filter
            if (this.pkgSearchQuery) {
                const query = this.pkgSearchQuery.toLowerCase();
                const searchFields = [
                    pkg.name,
                    pkg.version || "",
                    pkg.type || ""
                ].join(" ").toLowerCase();

                if (!searchFields.includes(query)) {
                    return false;
                }
            }

            return true;
        });

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
                case "qid":
                    aVal = a.qid ?? 0;
                    bVal = b.qid ?? 0;
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
                    <img class="qualys-logo" src="data:image/png;base64,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" alt="Qualys Logo" />
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
