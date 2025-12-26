import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { execSync, spawn, ChildProcess } from 'child_process';
import * as https from 'https';
import * as http from 'http';
import {
  QScannerConfig,
  QScannerResult,
  QScannerExitCode,
  ContainerScanOptions,
  RepoScanOptions,
  SarifReport,
  VulnerabilitySummary,
} from '../api/types';

const DEFAULT_QSCANNER_VERSION = 'v4.8.0';
const DOWNLOAD_BASE_URL = 'https://www.qualys.com/qscanner/download';

export class QScannerRunner {
  private config: QScannerConfig;
  private binaryPath: string | null = null;
  private workDir: string;

  constructor(config: QScannerConfig) {
    this.config = config;
    this.workDir = path.join(os.tmpdir(), 'qscanner-ado');
    if (!fs.existsSync(this.workDir)) {
      fs.mkdirSync(this.workDir, { recursive: true });
    }
  }

  async setup(): Promise<void> {
    const version = this.config.version || DEFAULT_QSCANNER_VERSION;
    const platform = this.getPlatform();
    const arch = this.getArchitecture();

    console.log(`Setting up QScanner ${version} for ${platform}-${arch}...`);

    const binaryDir = path.join(this.workDir, `${platform}-${arch}`);
    const binaryName = platform === 'windows' ? 'qscanner.exe' : 'qscanner';
    this.binaryPath = path.join(binaryDir, binaryName);

    if (fs.existsSync(this.binaryPath)) {
      console.log('QScanner binary already exists, skipping download.');
      return;
    }

    const scriptUrl = `${DOWNLOAD_BASE_URL}/${version}/download_qscanner.sh`;
    const scriptPath = path.join(this.workDir, 'download_qscanner.sh');

    console.log(`Downloading QScanner download script from ${scriptUrl}...`);
    await this.downloadFile(scriptUrl, scriptPath);

    fs.chmodSync(scriptPath, '755');

    try {
      const env = {
        ...process.env,
        QSCANNER_VERSION: version,
      };

      execSync(`sh ${scriptPath}`, {
        cwd: this.workDir,
        env,
        stdio: 'inherit',
      });

      if (!fs.existsSync(this.binaryPath)) {
        throw new Error(`QScanner binary not found at ${this.binaryPath} after download`);
      }

      fs.chmodSync(this.binaryPath, '755');
      console.log(`QScanner binary ready at ${this.binaryPath}`);
    } catch (error) {
      throw new Error(`Failed to download QScanner: ${error}`);
    }
  }

  async scanImage(options: ContainerScanOptions): Promise<QScannerResult> {
    if (!this.binaryPath) {
      throw new Error('QScanner not set up. Call setup() first.');
    }

    const args = this.buildCommonArgs(options);
    args.push('image', options.imageId);

    if (options.storageDriver && options.storageDriver !== 'none') {
      args.push('--storage-driver', options.storageDriver);
    }

    if (options.platform) {
      args.push('--platform', options.platform);
    }

    return this.executeQScanner(args, options.outputDir);
  }

  async scanRepo(options: RepoScanOptions): Promise<QScannerResult> {
    if (!this.binaryPath) {
      throw new Error('QScanner not set up. Call setup() first.');
    }

    const args = this.buildCommonArgs(options);
    args.push('repo', options.scanPath);

    if (options.excludeDirs && options.excludeDirs.length > 0) {
      args.push('--exclude-dirs', options.excludeDirs.join(','));
    }

    if (options.excludeFiles && options.excludeFiles.length > 0) {
      args.push('--exclude-files', options.excludeFiles.join(','));
    }

    if (options.offlineScan) {
      args.push('--offline-scan=true');
    }

    return this.executeQScanner(args, options.outputDir);
  }

  async scanRootfs(scanPath: string, options: RepoScanOptions): Promise<QScannerResult> {
    if (!this.binaryPath) {
      throw new Error('QScanner not set up. Call setup() first.');
    }

    const args = this.buildCommonArgs(options);
    args.push('rootfs', scanPath);

    if (options.excludeDirs && options.excludeDirs.length > 0) {
      args.push('--exclude-dirs', options.excludeDirs.join(','));
    }

    return this.executeQScanner(args, options.outputDir);
  }

  parseSarifReport(reportPath: string): { summary: VulnerabilitySummary; report: SarifReport } {
    if (!fs.existsSync(reportPath)) {
      throw new Error(`SARIF report not found at ${reportPath}`);
    }

    const reportContent = fs.readFileSync(reportPath, 'utf-8');
    const report: SarifReport = JSON.parse(reportContent);

    const summary: VulnerabilitySummary = {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      informational: 0,
    };

    if (report.runs && report.runs.length > 0) {
      for (const run of report.runs) {
        if (run.results) {
          for (const result of run.results) {
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
          }
        }
      }
    }

    return { summary, report };
  }

  getBinaryPath(): string | null {
    return this.binaryPath;
  }

  getWorkDir(): string {
    return this.workDir;
  }

  cleanup(): void {}

  private buildCommonArgs(options: ContainerScanOptions | RepoScanOptions): string[] {
    const args: string[] = [];

    args.push('--pod', this.config.pod);
    args.push('--client-id', this.config.clientId);
    args.push('--client-secret', this.config.clientSecret);
    args.push('--mode', options.mode);

    if (options.scanTypes && options.scanTypes.length > 0) {
      args.push('--scan-types', options.scanTypes.join(','));
    }

    if (options.format && options.format.length > 0) {
      args.push('--format', options.format.join(','));
    }

    if (options.reportFormat && options.reportFormat.length > 0) {
      args.push('--report-format', options.reportFormat.join(','));
    }

    if (options.outputDir) {
      args.push('--output-dir', options.outputDir);
    }

    if (options.policyTags && options.policyTags.length > 0) {
      args.push('--policy-tags', options.policyTags.join(','));
    }

    if (options.timeout) {
      args.push('--scan-timeout', `${options.timeout}s`);
    }

    if (options.logLevel) {
      args.push('--log-level', options.logLevel);
    }

    if (this.config.skipTlsVerify) {
      args.push('--skip-verify-tls=true');
    }

    if (this.config.proxy) {
      args.push('--proxy', this.config.proxy);
    }

    return args;
  }

  private async executeQScanner(args: string[], outputDir?: string): Promise<QScannerResult> {
    if (!this.binaryPath) {
      throw new Error('QScanner binary path not set');
    }

    const resultOutputDir = outputDir || path.join(this.workDir, 'output');
    if (!fs.existsSync(resultOutputDir)) {
      fs.mkdirSync(resultOutputDir, { recursive: true });
    }

    if (!args.includes('--output-dir')) {
      args.push('--output-dir', resultOutputDir);
    }

    console.log(`Executing: ${this.binaryPath} ${args.join(' ')}`);

    return new Promise((resolve, reject) => {
      let stdout = '';
      let stderr = '';

      const proc: ChildProcess = spawn(this.binaryPath!, args, {
        env: {
          ...process.env,
          QUALYS_CLIENT_ID: this.config.clientId,
          QUALYS_CLIENT_SECRET: this.config.clientSecret,
        },
      });

      proc.stdout?.on('data', (data) => {
        const text = data.toString();
        stdout += text;
        process.stdout.write(text);
      });

      proc.stderr?.on('data', (data) => {
        const text = data.toString();
        stderr += text;
        process.stderr.write(text);
      });

      proc.on('close', (code) => {
        const exitCode = code ?? 1;
        const result = this.buildResult(exitCode, resultOutputDir, stdout, stderr);
        resolve(result);
      });

      proc.on('error', (err) => {
        reject(new Error(`Failed to execute QScanner: ${err.message}`));
      });
    });
  }

  private buildResult(exitCode: number, outputDir: string, stdout: string, stderr: string): QScannerResult {
    let policyResult: 'ALLOW' | 'DENY' | 'AUDIT' | 'NONE' = 'NONE';
    if (exitCode === QScannerExitCode.SUCCESS) {
      policyResult = 'ALLOW';
    } else if (exitCode === QScannerExitCode.POLICY_EVALUATION_DENY) {
      policyResult = 'DENY';
    } else if (exitCode === QScannerExitCode.POLICY_EVALUATION_AUDIT) {
      policyResult = 'AUDIT';
    }

    let scanResultFile: string | undefined;
    let reportFile: string | undefined;

    if (fs.existsSync(outputDir)) {
      const files = fs.readdirSync(outputDir);
      for (const file of files) {
        if (file.endsWith('-ScanResult.json')) {
          scanResultFile = path.join(outputDir, file);
        } else if (file.endsWith('-Report.sarif.json')) {
          reportFile = path.join(outputDir, file);
        }
      }
    }

    return {
      exitCode,
      success: exitCode === QScannerExitCode.SUCCESS,
      policyResult,
      outputDir,
      scanResultFile,
      reportFile,
      stdout,
      stderr,
    };
  }

  private getPlatform(): string {
    const platform = os.platform();
    switch (platform) {
      case 'linux':
        return 'linux';
      case 'darwin':
        return 'darwin';
      case 'win32':
        return 'windows';
      default:
        throw new Error(`Unsupported platform: ${platform}`);
    }
  }

  private getArchitecture(): string {
    const arch = os.arch();
    switch (arch) {
      case 'x64':
        return 'amd64';
      case 'arm64':
        return 'arm64';
      default:
        throw new Error(`Unsupported architecture: ${arch}`);
    }
  }

  private downloadFile(url: string, destPath: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const file = fs.createWriteStream(destPath);
      const protocol = url.startsWith('https') ? https : http;

      protocol
        .get(url, (response) => {
          if (response.statusCode === 301 || response.statusCode === 302) {
            const redirectUrl = response.headers.location;
            if (redirectUrl) {
              file.close();
              fs.unlinkSync(destPath);
              this.downloadFile(redirectUrl, destPath).then(resolve).catch(reject);
              return;
            }
          }

          if (response.statusCode !== 200) {
            reject(new Error(`Failed to download: HTTP ${response.statusCode}`));
            return;
          }

          response.pipe(file);
          file.on('finish', () => {
            file.close();
            resolve();
          });
        })
        .on('error', (err) => {
          fs.unlink(destPath, () => {});
          reject(err);
        });
    });
  }
}

export default QScannerRunner;
