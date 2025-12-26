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
} from '../../common';

async function run(): Promise<void> {
  try {
    const qualysConnection = tl.getInput('qualysConnection', true)!;
    const authScheme = tl.getEndpointAuthorizationScheme(qualysConnection, false);

    let authMethod: AuthMethod;
    let accessToken: string | undefined;
    let username: string | undefined;
    let password: string | undefined;
    let pod: string | undefined;

    if (authScheme === 'Token') {
      authMethod = 'access-token';
      accessToken = tl.getEndpointAuthorizationParameter(qualysConnection, 'accessToken', false);
      pod = tl.getEndpointAuthorizationParameter(qualysConnection, 'pod', false);
      if (!accessToken || !pod) {
        throw new Error('Qualys service connection must have accessToken and pod configured');
      }
    } else if (authScheme === 'UsernamePassword') {
      authMethod = 'credentials';
      username = tl.getEndpointAuthorizationParameter(qualysConnection, 'username', false);
      password = tl.getEndpointAuthorizationParameter(qualysConnection, 'password', false);
      pod = tl.getEndpointAuthorizationParameter(qualysConnection, 'pod', false);
      if (!username || !password || !pod) {
        throw new Error('Qualys service connection must have username, password, and pod configured');
      }
    } else {
      throw new Error(`Unsupported authentication scheme: ${authScheme}. Use Token or UsernamePassword.`);
    }

    // Get task inputs
    const imageId = tl.getInput('imageId', true)!;
    const storageDriver = tl.getInput('storageDriver', false) || 'none';
    const platform = tl.getInput('platform', false) || '';
    const usePolicyEvaluation = tl.getBoolInput('usePolicyEvaluation', false);
    const policyTags = tl.getInput('policyTags', false) || '';
    const failOnSeverity = parseInt(tl.getInput('failOnSeverity', false) || '4', 10);
    const scanTypesInput = tl.getInput('scanTypes', false) || 'os,sca';
    const scanTimeout = parseInt(tl.getInput('scanTimeout', false) || '300', 10);
    const continueOnError = tl.getBoolInput('continueOnError', false);
    const publishResults = tl.getBoolInput('publishResults', false);

    console.log('========================================');
    console.log('Qualys Container Security Scan');
    console.log('========================================');
    console.log(`Image: ${imageId}`);
    console.log(`Pod: ${pod}`);
    console.log(`Policy Evaluation: ${usePolicyEvaluation}`);
    console.log(`Scan Types: ${scanTypesInput}`);
    console.log('');

    const config: QScannerConfig = {
      authMethod,
      accessToken,
      username,
      password,
      pod: pod!,
    };

    const runner = new QScannerRunner(config);

    console.log('Setting up QScanner CLI...');
    await runner.setup();

    // Configure scan options
    const outputDir = path.join(tl.getVariable('Agent.TempDirectory') || '/tmp', 'qualys-scan-results');
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    const scanTypes = scanTypesInput.split(',').map((s) => s.trim()) as ContainerScanOptions['scanTypes'];

    const scanOptions: ContainerScanOptions = {
      imageId,
      mode: usePolicyEvaluation ? 'evaluate-policy' : 'get-report',
      scanTypes,
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

    // Execute scan
    console.log('');
    console.log('Starting container image scan...');
    console.log('----------------------------------------');

    const result = await runner.scanImage(scanOptions);

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

    // Set output variables
    tl.setVariable('vulnerabilityCount', summary.total.toString());
    tl.setVariable('criticalCount', summary.critical.toString());
    tl.setVariable('highCount', summary.high.toString());
    tl.setVariable('mediumCount', summary.medium.toString());
    tl.setVariable('lowCount', summary.low.toString());
    tl.setVariable('policyResult', result.policyResult);
    tl.setVariable('reportPath', result.reportFile || '');

    // Print summary
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

    // Publish SARIF results if enabled
    if (publishResults && result.reportFile && fs.existsSync(result.reportFile)) {
      console.log('');
      console.log(`SARIF report available at: ${result.reportFile}`);
      tl.uploadArtifact('QualysScanResults', result.reportFile, 'qualys-container-scan');
    }

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
