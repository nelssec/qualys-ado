import * as tmrm from 'azure-pipelines-task-lib/mock-run';
import * as path from 'path';

const taskPath = path.join(__dirname, '..', 'dist', 'tasks', 'QualysSCAScan', 'index.js');
const tmr = new tmrm.TaskMockRunner(taskPath);

// Mock inputs - using policy evaluation which will fail
tmr.setInput('qualysConnection', 'qualys-conn-id');
tmr.setInput('scanPath', '/test/project');
tmr.setInput('usePolicyEvaluation', 'true');
tmr.setInput('scanTypes', 'sca');
tmr.setInput('scanTimeout', '300');
tmr.setInput('generateSbom', 'false');
tmr.setInput('continueOnError', 'false');
tmr.setInput('publishResults', 'false');
tmr.setInput('qscannerVersion', 'v4.8.0');

// Mock endpoint authorization
process.env['ENDPOINT_AUTH_PARAMETER_qualys-conn-id_CLIENTID'] = 'mock-client-id';
process.env['ENDPOINT_AUTH_PARAMETER_qualys-conn-id_CLIENTSECRET'] = 'mock-client-secret';
process.env['ENDPOINT_AUTH_PARAMETER_qualys-conn-id_POD'] = 'qg4.apps.qualys.ca';

// Mock Agent.TempDirectory
process.env['AGENT_TEMPDIRECTORY'] = '/tmp/mock-agent';

// Create mock SARIF report with critical vulnerability (Log4Shell)
const mockSarifReport = JSON.stringify({
  $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
  version: '2.1.0',
  runs: [
    {
      tool: {
        driver: {
          name: 'QScanner',
          version: '4.8.0',
          rules: [],
        },
      },
      results: [
        {
          ruleId: 'QID-44228',
          level: 'error',
          message: { text: 'Log4Shell RCE vulnerability in log4j-core' },
          properties: {
            severity: 5,
            cvssScore: 10.0,
            cves: ['CVE-2021-44228'],
            packageName: 'log4j-core',
            installedVersion: '2.14.0',
            fixedVersion: '2.17.0',
          },
        },
      ],
    },
  ],
});

// Mock file system
tmr.registerMock('fs', {
  existsSync: (p: string) => {
    if (p.includes('qscanner')) return true;
    if (p.includes('qualys-sca-results')) return true;
    if (p.includes('-Report.sarif.json')) return true;
    if (p === '/test/project') return true;
    return false;
  },
  mkdirSync: () => {},
  chmodSync: () => {},
  createWriteStream: () => ({
    on: (event: string, cb: () => void) => {
      if (event === 'finish') setTimeout(cb, 10);
    },
    close: () => {},
  }),
  unlinkSync: () => {},
  readFileSync: (p: string) => {
    if (p.includes('-Report.sarif.json')) {
      return mockSarifReport;
    }
    return '';
  },
  readdirSync: () => ['scan-Report.sarif.json'],
});

// Mock child_process - QScanner returns exit code 42 (POLICY_EVALUATION_DENY)
tmr.registerMock('child_process', {
  execSync: () => Buffer.from(''),
  spawn: () => {
    const EventEmitter = require('events');
    const proc = new EventEmitter();
    proc.stdout = new EventEmitter();
    proc.stderr = new EventEmitter();

    // Simulate scan with policy DENY due to critical vulnerability
    setTimeout(() => {
      proc.stdout.emit(
        'data',
        Buffer.from('QScanner v4.8.0\nScanning repo...\nFound critical vulnerability: Log4Shell\nPolicy evaluation: DENY\n')
      );
      proc.emit('close', 42); // Exit code 42 = POLICY_EVALUATION_DENY
    }, 100);

    return proc;
  },
});

// Mock https/http for download
tmr.registerMock('https', {
  get: (url: string, callback: (res: unknown) => void) => {
    const EventEmitter = require('events');
    const res = new EventEmitter();
    res.statusCode = 200;
    res.headers = {};
    res.pipe = () => {};
    setTimeout(() => {
      callback(res);
      res.emit('end');
    }, 10);
    return {
      on: () => {},
    };
  },
});

tmr.registerMock('http', {
  get: () => ({ on: () => {} }),
});

tmr.run();
