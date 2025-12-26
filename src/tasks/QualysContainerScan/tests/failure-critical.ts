import * as tmrm from 'azure-pipelines-task-lib/mock-run';
import * as path from 'path';

const taskPath = path.join(__dirname, '..', 'dist', 'tasks', 'QualysContainerScan', 'index.js');
const tmr = new tmrm.TaskMockRunner(taskPath);

// Mock inputs - using policy evaluation which will fail
tmr.setInput('qualysConnection', 'qualys-conn-id');
tmr.setInput('imageId', 'myregistry/vulnerable-image:latest');
tmr.setInput('usePolicyEvaluation', 'true');
tmr.setInput('scanTypes', 'os,sca');
tmr.setInput('scanTimeout', '300');
tmr.setInput('continueOnError', 'false');
tmr.setInput('publishResults', 'false');
tmr.setInput('qscannerVersion', 'v4.8.0');

// Mock endpoint authorization
process.env['ENDPOINT_AUTH_PARAMETER_qualys-conn-id_CLIENTID'] = 'mock-client-id';
process.env['ENDPOINT_AUTH_PARAMETER_qualys-conn-id_CLIENTSECRET'] = 'mock-client-secret';
process.env['ENDPOINT_AUTH_PARAMETER_qualys-conn-id_POD'] = 'qg4.apps.qualys.ca';

// Mock Agent.TempDirectory
process.env['AGENT_TEMPDIRECTORY'] = '/tmp/mock-agent';

// Create mock SARIF report with critical vulnerabilities
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
          message: { text: 'Log4Shell RCE vulnerability' },
          properties: {
            severity: 5,
            cvssScore: 10.0,
            cves: ['CVE-2021-44228'],
          },
        },
        {
          ruleId: 'QID-22965',
          level: 'error',
          message: { text: 'Spring4Shell RCE vulnerability' },
          properties: {
            severity: 4,
            cvssScore: 9.8,
            cves: ['CVE-2022-22965'],
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
    if (p.includes('qualys-scan-results')) return true;
    if (p.includes('-Report.sarif.json')) return true;
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

    // Simulate scan with policy DENY result
    setTimeout(() => {
      proc.stdout.emit(
        'data',
        Buffer.from('QScanner v4.8.0\nScanning image...\nPolicy evaluation: DENY\n')
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
