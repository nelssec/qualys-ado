import * as path from 'path';
import * as assert from 'assert';
import * as ttm from 'azure-pipelines-task-lib/mock-test';

describe('QualysContainerScan Task Tests', function () {
  this.timeout(10000);

  it('should succeed with valid image and no vulnerabilities above threshold', function (done) {
    const tp = path.join(__dirname, 'success.js');
    const tr = new ttm.MockTestRunner(tp);

    tr.runAsync()
      .then(() => {
        assert.equal(tr.succeeded, true, 'Should have succeeded');
        assert.equal(tr.warningIssues.length, 0, 'Should have no warnings');
        assert.equal(tr.errorIssues.length, 0, 'Should have no errors');
        assert(tr.stdout.includes('Scan completed successfully'), 'Should report success');
        done();
      })
      .catch(done);
  });

  it('should fail when critical vulnerabilities found', function (done) {
    const tp = path.join(__dirname, 'failure-critical.js');
    const tr = new ttm.MockTestRunner(tp);

    tr.runAsync()
      .then(() => {
        assert.equal(tr.succeeded, false, 'Should have failed');
        assert(
          tr.stdout.includes('vulnerabilities at') || tr.stdout.includes('Threshold Violations'),
          'Should mention threshold violation'
        );
        done();
      })
      .catch(done);
  });

  it('should continue on error when configured', function (done) {
    const tp = path.join(__dirname, 'continue-on-error.js');
    const tr = new ttm.MockTestRunner(tp);

    tr.runAsync()
      .then(() => {
        assert.equal(tr.succeeded, true, 'Should succeed with issues');
        done();
      })
      .catch(done);
  });
});
