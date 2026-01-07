import * as tl from 'azure-pipelines-task-lib/task';
import * as path from 'path';
import * as fs from 'fs';
import {
  QScannerRunner,
  QScannerConfig,
  ContainerScanOptions,
  QScannerExitCode,
  VulnerabilitySummary,
  AuthMethod,
  WorkItemCreator,
  SarifReport,
} from '../../common';

async function run(): Promise<void> {
  try {
    const qualysConnection = tl.getInput('qualysConnection', true)!;
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

    const imageId = tl.getInput('imageId', true)!;
    const storageDriver = tl.getInput('storageDriver', false) || 'none';
    const platform = tl.getInput('platform', false) || '';
    const usePolicyEvaluation = tl.getBoolInput('usePolicyEvaluation', false);
    const policyTags = tl.getInput('policyTags', false) || '';
    const maxCritical = parseInt(tl.getInput('maxCritical', false) || '0', 10);
    const maxHigh = parseInt(tl.getInput('maxHigh', false) || '0', 10);
    const maxMedium = parseInt(tl.getInput('maxMedium', false) || '-1', 10);
    const maxLow = parseInt(tl.getInput('maxLow', false) || '-1', 10);
    const scanSecrets = tl.getBoolInput('scanSecrets', false);
    const scanTimeout = parseInt(tl.getInput('scanTimeout', false) || '300', 10);
    const continueOnError = tl.getBoolInput('continueOnError', false);
    const publishResults = tl.getBoolInput('publishResults', false);
    const createWorkItems = tl.getBoolInput('createWorkItems', false);
    const workItemSeverities = parseInt(tl.getInput('workItemSeverities', false) || '4', 10);
    const workItemAreaPath = tl.getInput('workItemAreaPath', false) || '';

    const scanTypes: ('pkg' | 'secret')[] = ['pkg'];
    if (scanSecrets) {
      scanTypes.push('secret');
    }

    console.log('========================================');
    console.log('Qualys Container Security Scan');
    console.log('========================================');
    console.log(`Image: ${imageId}`);
    console.log(`Pod: ${pod}`);
    console.log(`Policy Evaluation: ${usePolicyEvaluation}`);
    if (!usePolicyEvaluation) {
      console.log(`Thresholds: Critical=${maxCritical}, High=${maxHigh}, Medium=${maxMedium}, Low=${maxLow} (-1=unlimited)`);
    }
    console.log(`Scan Types: ${scanTypes.join(',')}`);
    console.log(`Secrets Scanning: ${scanSecrets ? 'Enabled' : 'Disabled'}`);
    console.log('');

    const config: QScannerConfig = {
      authMethod,
      accessToken,
      pod,
    };

    const runner = new QScannerRunner(config);

    console.log('Setting up QScanner CLI...');
    await runner.setup();

    const outputDir = path.join(tl.getVariable('Agent.TempDirectory') || '/tmp', 'qualys-scan-results');
    try {
      if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
      }
    } catch (err) {
      throw new Error(`Failed to create output directory ${outputDir}: ${err instanceof Error ? err.message : String(err)}`);
    }

    const scanOptions: ContainerScanOptions = {
      imageId,
      mode: usePolicyEvaluation ? 'evaluate-policy' : 'get-report',
      scanTypes: scanTypes as ContainerScanOptions['scanTypes'],
      format: ['json', 'spdx'],
      reportFormat: ['sarif', 'table'],
      outputDir,
      timeout: scanTimeout,
      logLevel: 'info',
    };

    if (storageDriver !== 'none') {
      scanOptions.storageDriver = storageDriver as ContainerScanOptions['storageDriver'];
    }

    if (platform) {
      scanOptions.platform = platform;
    }

    if (usePolicyEvaluation && policyTags) {
      scanOptions.policyTags = policyTags.split(',').map((t) => t.trim());
    }

    console.log('');
    console.log('Starting container image scan...');
    console.log('----------------------------------------');

    const MAX_RETRIES = 5;
    const RETRY_DELAYS = [30, 60, 90, 120, 150];
    let result = await runner.scanImage(scanOptions);
    let retryCount = 0;

    while (result.exitCode === QScannerExitCode.FAILED_TO_GET_VULN_REPORT && retryCount < MAX_RETRIES) {
      const delay = RETRY_DELAYS[retryCount] || 60;
      retryCount++;
      console.log('');
      console.log(`Vulnerability report not ready yet. Waiting ${delay}s before retry ${retryCount}/${MAX_RETRIES}...`);
      await new Promise(resolve => setTimeout(resolve, delay * 1000));
      console.log('Retrying vulnerability report fetch...');
      console.log('----------------------------------------');
      result = await runner.scanImage(scanOptions);
    }

    console.log('----------------------------------------');
    console.log('');

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

    tl.setVariable('vulnerabilityCount', summary.total.toString());
    tl.setVariable('criticalCount', summary.critical.toString());
    tl.setVariable('highCount', summary.high.toString());
    tl.setVariable('mediumCount', summary.medium.toString());
    tl.setVariable('lowCount', summary.low.toString());
    tl.setVariable('policyResult', result.policyResult);
    tl.setVariable('reportPath', result.reportFile || '');

    console.log('========================================');
    console.log('Scan Results Summary');
    console.log('========================================');
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

    if (publishResults && result.reportFile && fs.existsSync(result.reportFile)) {
      console.log('');
      console.log(`SARIF report available at: ${result.reportFile}`);

      const stagingDir = tl.getVariable('Build.ArtifactStagingDirectory');
      if (stagingDir) {
        const artifactDir = path.join(stagingDir, 'qualys-container-scan');
        if (!fs.existsSync(artifactDir)) {
          fs.mkdirSync(artifactDir, { recursive: true });
        }
        const destPath = path.join(artifactDir, path.basename(result.reportFile));
        fs.copyFileSync(result.reportFile, destPath);
        console.log(`SARIF copied to: ${destPath}`);
        console.log('Add a PublishBuildArtifacts@1 task to publish the qualys-container-scan artifact');
      }

      const reportFileName = path.basename(result.reportFile);
      tl.addAttachment('qualys.container.sarif', reportFileName, result.reportFile);
      console.log(`SARIF attachment added: ${reportFileName}`);
    }

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

          const vulns = workItemCreator.extractVulnerabilitiesFromSarif(sarifReport, 'container');
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

    let scanPassed = false;
    const failureReasons: string[] = [];

    if (usePolicyEvaluation) {
      scanPassed = result.policyResult === 'ALLOW';
      if (result.policyResult === 'DENY') {
        failureReasons.push('Qualys policy evaluation returned DENY');
      } else if (result.policyResult === 'AUDIT') {
        scanPassed = true;
        console.log('Warning: No Qualys policies matched for evaluation (AUDIT)');
      }
    } else {
      if (maxCritical >= 0 && summary.critical > maxCritical) {
        failureReasons.push(`Found ${summary.critical} critical vulnerabilities (max: ${maxCritical})`);
      }
      if (maxHigh >= 0 && summary.high > maxHigh) {
        failureReasons.push(`Found ${summary.high} high severity vulnerabilities (max: ${maxHigh})`);
      }
      if (maxMedium >= 0 && summary.medium > maxMedium) {
        failureReasons.push(`Found ${summary.medium} medium severity vulnerabilities (max: ${maxMedium})`);
      }
      if (maxLow >= 0 && summary.low > maxLow) {
        failureReasons.push(`Found ${summary.low} low severity vulnerabilities (max: ${maxLow})`);
      }

      scanPassed = failureReasons.length === 0;
    }

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
      tl.setResult(tl.TaskResult.Succeeded, 'Container scan completed successfully');
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
