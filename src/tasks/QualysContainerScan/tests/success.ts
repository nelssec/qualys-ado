import * as tmrm from 'azure-pipelines-task-lib/mock-run';
import * as path from 'path';

const taskPath = path.join(__dirname, '..', 'dist', 'tasks', 'QualysContainerScan', 'index.js');
const tmr = new tmrm.TaskMockRunner(taskPath);

// Mock inputs
tmr.setInput('qualysConnection', 'qualys-conn-id');
tmr.setInput('imageId', 'myregistry/myimage:latest');
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

// Create mock SARIF report content
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
          message: { text: 'Medium vulnerability' },
          properties: {
            severity: 3,
            cvssScore: 5.5,
          },
        },
        {
          ruleId: 'QID-456',
          level: 'note',
          message: { text: 'Low vulnerability' },
          properties: {
            severity: 2,
            cvssScore: 3.0,
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
      proc.stdout.emit('data', Buffer.from('QScanner v4.8.0\nScanning image...\nScan complete.\n'));
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
