import * as tl from 'azure-pipelines-task-lib/task';
import * as path from 'path';
import * as fs from 'fs';
import {
  QScannerRunner,
  QScannerConfig,
  RepoScanOptions,
  QScannerExitCode,
  VulnerabilitySummary,
  AuthMethod,
  WorkItemCreator,
  SarifReport,
} from '../../common';

async function run(): Promise<void> {
  try {
    const qualysConnection = tl.getInput('qualysConnection', true)!;

    // Get the endpoint authorization object directly
    // This works with endpoint-auth-scheme-none where parameters are stored in authorization.parameters
    const endpointAuth = tl.getEndpointAuthorization(qualysConnection, false);

    if (!endpointAuth) {
      throw new Error('Could not get endpoint authorization. Please check your service connection configuration.');
    }

    const params = endpointAuth.parameters || {};

    const accessToken = params['accessToken'];
    const pod = params['pod'];

    if (!accessToken) {
      throw new Error('Access token not found in service connection. Please configure your Qualys API Connection with an access token.');
    }

    if (!pod) {
      throw new Error('Pod not found in service connection. Please configure your Qualys API Connection with a pod selection.');
    }

    const authMethod: AuthMethod = 'access-token';

    console.log(`Pod: ${pod}`);
    console.log(`Auth Method: ${authMethod}`);
    console.log('Access Token: [CONFIGURED]');

    // Get task inputs
    const scanPath = tl.getPathInput('scanPath', true, true)!;
    const usePolicyEvaluation = tl.getBoolInput('usePolicyEvaluation', false);
    const policyTags = tl.getInput('policyTags', false) || '';
    const failOnSeverity = parseInt(tl.getInput('failOnSeverity', false) || '4', 10);
    const scanSecrets = tl.getBoolInput('scanSecrets', false);
    const scanTimeout = parseInt(tl.getInput('scanTimeout', false) || '300', 10);
    const continueOnError = tl.getBoolInput('continueOnError', false);
    const publishResults = tl.getBoolInput('publishResults', false);
    const generateSbom = tl.getBoolInput('generateSbom', false);
    const sbomFormat = tl.getInput('sbomFormat', false) || 'spdx';
    const excludeDirs = tl.getInput('excludeDirs', false) || '';
    const excludeFiles = tl.getInput('excludeFiles', false) || '';
    const offlineScan = tl.getBoolInput('offlineScan', false);
    const createWorkItems = tl.getBoolInput('createWorkItems', false);
    const workItemSeverities = parseInt(tl.getInput('workItemSeverities', false) || '4', 10);
    const workItemAreaPath = tl.getInput('workItemAreaPath', false) || '';

    // Build scan types array: always use 'pkg' (os+sca), optionally add 'secret'
    const scanTypes: ('pkg' | 'secret')[] = ['pkg'];
    if (scanSecrets) {
      scanTypes.push('secret');
    }

    console.log('========================================');
    console.log('Qualys SCA Dependency Scan');
    console.log('========================================');
    console.log(`Scan Path: ${scanPath}`);
    console.log(`Pod: ${pod}`);
    console.log(`Policy Evaluation: ${usePolicyEvaluation}`);
    console.log(`Scan Types: ${scanTypes.join(',')}`);
    console.log(`Secrets Scanning: ${scanSecrets ? 'Enabled' : 'Disabled'}`);
    console.log(`Generate SBOM: ${generateSbom}`);
    if (generateSbom) {
      console.log(`SBOM Format: ${sbomFormat}`);
    }
    console.log('');

    const config: QScannerConfig = {
      authMethod,
      accessToken,
      pod,
    };

    const runner = new QScannerRunner(config);

    console.log('Setting up QScanner CLI...');
    await runner.setup();

    // Configure scan options
    const outputDir = path.join(tl.getVariable('Agent.TempDirectory') || '/tmp', 'qualys-sca-results');
    try {
      if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
      }
    } catch (err) {
      throw new Error(`Failed to create output directory ${outputDir}: ${err instanceof Error ? err.message : String(err)}`);
    }

    // Build format array based on SBOM preferences
    const formats: RepoScanOptions['format'] = ['json'];
    if (generateSbom) {
      const sbomFormats = sbomFormat.split(',').map((s) => s.trim());
      if (sbomFormats.includes('spdx')) {
        formats.push('spdx');
      }
      if (sbomFormats.includes('cyclonedx')) {
        formats.push('cyclonedx');
      }
    }

    const scanOptions: RepoScanOptions = {
      scanPath,
      mode: usePolicyEvaluation ? 'evaluate-policy' : 'get-report',
      scanTypes: scanTypes as RepoScanOptions['scanTypes'],
      format: formats,
      reportFormat: ['sarif', 'table'],
      outputDir,
      timeout: scanTimeout,
      logLevel: 'info',
      offlineScan,
    };

    if (excludeDirs) {
      scanOptions.excludeDirs = excludeDirs.split(',').map((d) => d.trim()).filter(Boolean);
    }

    if (excludeFiles) {
      scanOptions.excludeFiles = excludeFiles.split(',').map((f) => f.trim()).filter(Boolean);
    }

    if (usePolicyEvaluation && policyTags) {
      scanOptions.policyTags = policyTags.split(',').map((t) => t.trim());
    }

    // Execute scan
    console.log('');
    console.log('Starting SCA dependency scan...');
    console.log('----------------------------------------');

    const result = await runner.scanRepo(scanOptions);

    console.log('----------------------------------------');
    console.log('');

    // Parse results
    let summary: VulnerabilitySummary = {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      informational: 0,
    };

    if (result.reportFile && fs.existsSync(result.reportFile)) {
      const parsed = runner.parseSarifReport(result.reportFile);
      summary = parsed.summary;
    }

    // Find SBOM files if generated
    let sbomPath = '';
    if (generateSbom && fs.existsSync(outputDir)) {
      const sbomFiles: string[] = [];
      const files = fs.readdirSync(outputDir);
      for (const file of files) {
        if (file.endsWith('.spdx.json') || file.endsWith('.cdx.json') || file.includes('cyclonedx')) {
          sbomFiles.push(path.join(outputDir, file));
        }
      }
      if (sbomFiles.length > 0) {
        sbomPath = sbomFiles.join(';');
      }
    }

    // Set output variables
    tl.setVariable('vulnerabilityCount', summary.total.toString());
    tl.setVariable('criticalCount', summary.critical.toString());
    tl.setVariable('highCount', summary.high.toString());
    tl.setVariable('mediumCount', summary.medium.toString());
    tl.setVariable('lowCount', summary.low.toString());
    tl.setVariable('policyResult', result.policyResult);
    tl.setVariable('reportPath', result.reportFile || '');
    tl.setVariable('sbomPath', sbomPath);

    // Print summary
    console.log('========================================');
    console.log('Scan Results Summary');
    console.log('========================================');
    console.log(`Scan Path: ${scanPath}`);
    console.log(`Total Vulnerabilities: ${summary.total}`);
    console.log(`  Critical: ${summary.critical}`);
    console.log(`  High: ${summary.high}`);
    console.log(`  Medium: ${summary.medium}`);
    console.log(`  Low: ${summary.low}`);
    console.log(`  Informational: ${summary.informational}`);
    console.log('');

    if (usePolicyEvaluation) {
      console.log(`Policy Evaluation Result: ${result.policyResult}`);
    }

    if (generateSbom && sbomPath) {
      console.log('');
      console.log(`SBOM generated: ${sbomPath}`);
    }

    // Publish SARIF results if enabled
    if (publishResults && result.reportFile && fs.existsSync(result.reportFile)) {
      console.log('');
      console.log(`SARIF report available at: ${result.reportFile}`);
      tl.uploadArtifact('QualysSCAResults', result.reportFile, 'qualys-sca-scan');
    }

    // Create work items if enabled
    let workItemsCreated = 0;
    if (createWorkItems && result.reportFile && fs.existsSync(result.reportFile)) {
      const accessToken = tl.getVariable('System.AccessToken');
      const organizationUrl = tl.getVariable('System.TeamFoundationCollectionUri');
      const project = tl.getVariable('System.TeamProject');

      if (!accessToken) {
        console.warn('Warning: System.AccessToken not available. Enable "Allow scripts to access OAuth token" in pipeline settings to create work items.');
      } else if (!organizationUrl || !project) {
        console.warn('Warning: Could not determine Azure DevOps organization or project.');
      } else {
        console.log('');
        console.log('Creating work items for vulnerabilities...');

        try {
          const sarifContent = fs.readFileSync(result.reportFile, 'utf8');
          const sarifReport: SarifReport = JSON.parse(sarifContent);

          const workItemCreator = new WorkItemCreator({
            organizationUrl,
            project,
            accessToken,
            areaPath: workItemAreaPath || undefined,
            minSeverity: workItemSeverities,
          });

          const vulns = workItemCreator.extractVulnerabilitiesFromSarif(sarifReport, 'sca');
          console.log(`Found ${vulns.length} vulnerabilities at or above severity ${workItemSeverities}`);

          if (vulns.length > 0) {
            const workItemResult = await workItemCreator.createWorkItems(vulns);
            workItemsCreated = workItemResult.created;

            console.log('');
            console.log('Work Item Summary:');
            console.log(`  Created: ${workItemResult.created}`);
            console.log(`  Skipped (duplicates): ${workItemResult.skipped}`);
            if (workItemResult.failed > 0) {
              console.log(`  Failed: ${workItemResult.failed}`);
              for (const error of workItemResult.errors) {
                console.warn(`    - ${error}`);
              }
            }
          }
        } catch (error) {
          const errorMsg = error instanceof Error ? error.message : String(error);
          console.warn(`Warning: Failed to create work items: ${errorMsg}`);
        }
      }
    }
    tl.setVariable('workItemsCreated', workItemsCreated.toString());

    // Determine pass/fail
    let scanPassed = false;
    const failureReasons: string[] = [];

    if (usePolicyEvaluation) {
      // Use QScanner's policy evaluation result
      scanPassed = result.policyResult === 'ALLOW';
      if (result.policyResult === 'DENY') {
        failureReasons.push('Qualys policy evaluation returned DENY');
      } else if (result.policyResult === 'AUDIT') {
        // AUDIT means no policy matched - treat as pass but warn
        scanPassed = true;
        console.log('Warning: No Qualys policies matched for evaluation (AUDIT)');
      }
    } else {
      // Use local threshold evaluation based on severity
      if (failOnSeverity > 0) {
        if (failOnSeverity <= 5 && summary.critical > 0) {
          failureReasons.push(`Found ${summary.critical} critical vulnerabilities`);
        }
        if (failOnSeverity <= 4 && summary.high > 0) {
          failureReasons.push(`Found ${summary.high} high severity vulnerabilities`);
        }
        if (failOnSeverity <= 3 && summary.medium > 0) {
          failureReasons.push(`Found ${summary.medium} medium severity vulnerabilities`);
        }
        if (failOnSeverity <= 2 && summary.low > 0) {
          failureReasons.push(`Found ${summary.low} low severity vulnerabilities`);
        }

        scanPassed = failureReasons.length === 0;
      } else {
        scanPassed = true;
      }
    }

    // Check for scan execution errors
    if (
      result.exitCode !== QScannerExitCode.SUCCESS &&
      result.exitCode !== QScannerExitCode.POLICY_EVALUATION_DENY &&
      result.exitCode !== QScannerExitCode.POLICY_EVALUATION_AUDIT
    ) {
      failureReasons.push(`QScanner exited with code ${result.exitCode}`);
      scanPassed = false;
    }

    tl.setVariable('scanPassed', scanPassed.toString());

    console.log('');
    console.log('========================================');
    if (scanPassed) {
      console.log('SCAN PASSED');
      tl.setResult(tl.TaskResult.Succeeded, 'SCA scan completed successfully');
    } else {
      console.log('SCAN FAILED');
      for (const reason of failureReasons) {
        console.log(`  - ${reason}`);
      }

      if (continueOnError) {
        console.log('');
        console.log('Continuing due to continueOnError=true');
        tl.setResult(tl.TaskResult.SucceededWithIssues, failureReasons.join('; '));
      } else {
        tl.setResult(tl.TaskResult.Failed, failureReasons.join('; '));
      }
    }
    console.log('========================================');

    // Cleanup
    runner.cleanup();
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    console.error(`Error: ${errorMessage}`);

    const continueOnError = tl.getBoolInput('continueOnError', false);
    if (continueOnError) {
      tl.setResult(tl.TaskResult.SucceededWithIssues, errorMessage);
    } else {
      tl.setResult(tl.TaskResult.Failed, errorMessage);
    }
  }
}

run();
