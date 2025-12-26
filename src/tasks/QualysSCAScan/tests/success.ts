import * as tmrm from 'azure-pipelines-task-lib/mock-run';
import * as path from 'path';

const taskPath = path.join(__dirname, '..', 'dist', 'tasks', 'QualysSCAScan', 'index.js');
const tmr = new tmrm.TaskMockRunner(taskPath);

// Mock inputs
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

// Create mock SARIF report content with only low severity issues
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
          ruleId: 'QID-123',
          level: 'warning',
          message: { text: 'Medium severity dependency issue' },
          properties: {
            severity: 3,
            cvssScore: 5.5,
            packageName: 'express',
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

// Mock child_process
tmr.registerMock('child_process', {
  execSync: () => Buffer.from(''),
  spawn: () => {
    const EventEmitter = require('events');
    const proc = new EventEmitter();
    proc.stdout = new EventEmitter();
    proc.stderr = new EventEmitter();

    // Simulate successful scan with ALLOW result
    setTimeout(() => {
      proc.stdout.emit('data', Buffer.from('QScanner v4.8.0\nScanning repo...\nScan complete.\n'));
      proc.emit('close', 0); // Exit code 0 = SUCCESS/ALLOW
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
