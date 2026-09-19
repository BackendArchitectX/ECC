'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  REQUEST_SCHEMA,
  RESULT_SCHEMA,
  buildPreview,
  buildReviewerEnv,
  characterLength,
  createRequest,
  loadConfig,
  runReviewer,
  scanEvidence,
  sensitiveDiffPathReason,
  sensitivePathReason,
  validateConfig,
  validateResult,
  writeConfig,
} = require('../../scripts/cross-review-runtime');

function validRequest(overrides = {}) {
  return createRequest({
    mode: 'diff',
    evidence: [{
      id: 'diff',
      kind: 'diff',
      source: 'git diff HEAD',
      content: 'diff --git a/src/a.js b/src/a.js\n--- a/src/a.js\n+++ b/src/a.js\n+const answer = 42;\n',
    }],
    ...overrides,
  });
}

function cleanResult() {
  return {
    schema: RESULT_SCHEMA,
    status: 'clean',
    summary: 'No material issue found in the supplied evidence.',
    findings: [],
  };
}

function findingResult(evidenceId = 'diff') {
  return {
    schema: RESULT_SCHEMA,
    status: 'findings',
    summary: 'One correctness concern.',
    findings: [{
      id: 'R-001',
      severity: 'high',
      category: 'correctness',
      claim: 'The new branch can return a stale value.',
      evidenceRefs: [{ evidenceId, location: 'src/a.js:1' }],
      verification: 'Add a regression test that exercises the stale branch.',
    }],
  };
}

function test(name, fn) {
  try {
    fn();
    console.log('  PASS ' + name);
    return true;
  } catch (error) {
    console.log('  FAIL ' + name);
    console.log('    Error: ' + error.message);
    return false;
  }
}

function main() {
  console.log('\n=== Testing bounded cross-review runtime ===\n');

  let passed = 0;
  let failed = 0;
  const cases = [
    ['builds a bounded advisory request', () => {
      const request = validRequest();
      assert.strictEqual(request.schema, REQUEST_SCHEMA);
      assert.strictEqual(request.trust.reviewerAuthority, 'advisory');
      assert.strictEqual(request.trust.repositoryWrite, false);
      assert.strictEqual(request.trust.shellAuthority, false);
      assert.strictEqual(request.evidence.length, 1);
    }],
    ['rejects duplicate evidence ids', () => {
      assert.throws(() => createRequest({
        mode: 'final',
        evidence: [
          { id: 'same', kind: 'diff', source: 'a.patch', content: 'one' },
          { id: 'same', kind: 'test', source: 'tests.txt', content: 'two' },
        ],
      }), /duplicate id/);
    }],
    ['rejects unsupported request fields', () => {
      const request = validRequest();
      request.extraAuthority = true;
      assert.throws(
        () => require('../../scripts/cross-review-runtime').validateRequest(request),
        /unsupported field/
      );
    }],
    ['recognizes sensitive direct paths', () => {
      assert.strictEqual(sensitivePathReason('.env'), 'dotenv-file');
      assert.strictEqual(sensitivePathReason('config/prod.pem'), 'private-key-file');
      assert.strictEqual(sensitivePathReason('src/app.js'), null);
    }],
    ['recognizes sensitive paths across text, rename, and binary diff headers', () => {
      const dotenvDiff = [
        'diff --git a/.env b/.env',
        '--- a/.env',
        '+++ b/.env',
        '+SAFE_LOOKING=value',
      ].join('\n');
      const renamedSecret = [
        'diff --git a/config.txt b/.env.production',
        'similarity index 100%',
        'rename from config.txt',
        'rename to .env.production',
      ].join('\n');
      const binaryKey = [
        'diff --git a/cert.p12 b/cert.p12',
        'Binary files a/cert.p12 and b/cert.p12 differ',
      ].join('\n');

      assert.strictEqual(sensitiveDiffPathReason(dotenvDiff), 'dotenv-file');
      assert.strictEqual(sensitiveDiffPathReason(renamedSecret), 'dotenv-file');
      const binaryEnv = [
        'diff --git a/.env b/.env',
        'Binary files a/.env and b/.env differ',
      ].join('\n');

      assert.strictEqual(sensitiveDiffPathReason(binaryKey), 'private-key-file');
      assert.strictEqual(sensitiveDiffPathReason(binaryEnv), 'dotenv-file');
    }],
    ['counts Unicode code points consistently with schema and Python validation', () => {
      const smile = String.fromCodePoint(0x1F642);
      const euro = String.fromCodePoint(0x20AC);
      assert.strictEqual(characterLength('A' + smile + euro), 3);
    }],
    ['detects high-confidence credential text without returning the secret', () => {
      const secret = 'ghp_' + 'A'.repeat(36);
      const blocked = scanEvidence([{
        id: 'log',
        kind: 'failure',
        source: 'failure.txt',
        content: 'token=' + secret,
      }]);
      assert.strictEqual(blocked.length, 1);
      assert.strictEqual(blocked[0].reason, 'github-token');
      assert.ok(!JSON.stringify(blocked).includes(secret));
    }],
    ['rejects UTF-8 request payloads that exceed the transport byte limit', () => {
      const euroChunk = String.fromCodePoint(0x20AC).repeat(40_000);
      assert.throws(() => createRequest({
        mode: 'final',
        evidence: [
          { id: 'a', kind: 'context', source: 'a.txt', content: euroChunk },
          { id: 'b', kind: 'context', source: 'b.txt', content: euroChunk },
          { id: 'c', kind: 'context', source: 'c.txt', content: euroChunk },
        ],
      }), /transport limit/);
    }],
    ['dry-run preview never marks data as transmitted', () => {
      const preview = buildPreview(
        validRequest(),
        { command: 'reviewer', args: [], passEnv: [], timeoutMs: 120000 },
        '/tmp/review.json'
      );
      assert.strictEqual(preview.transmitted, false);
      assert.strictEqual(preview.message, 'No data transmitted.');
      assert.strictEqual(preview.secretScan.passed, true);
    }],
    ['accepts structured findings tied to supplied evidence', () => {
      const result = validateResult(findingResult(), validRequest());
      assert.strictEqual(result.findings[0].id, 'R-001');
    }],
    ['rejects findings that cite evidence not sent', () => {
      assert.throws(
        () => validateResult(findingResult('whole-repo'), validRequest()),
        /not supplied/
      );
    }],
    ['rejects oversized reviewer summary', () => {
      const result = cleanResult();
      result.summary = 'x'.repeat(4001);
      assert.throws(() => validateResult(result, validRequest()), /summary exceeds/);
    }],
    ['rejects unsupported reviewer result fields', () => {
      const result = cleanResult();
      result.command = 'rm -rf';
      assert.throws(() => validateResult(result, validRequest()), /unsupported field/);
    }],
    ['rejects high-confidence secrets persisted in reviewer args', () => {
      const token = 'sk-' + 'A'.repeat(32);
      assert.throws(
        () => validateConfig({
          command: 'reviewer',
          args: ['--api-key', token],
          passEnv: [],
          timeoutMs: 120000,
        }),
        /pass credentials through --pass-env/
      );
    }],
    ['rejects unsupported reviewer config fields', () => {
      assert.throws(
        () => validateConfig({
          command: 'reviewer',
          args: [],
          passEnv: [],
          timeoutMs: 120000,
          cwd: '/repo',
        }),
        /unsupported field/
      );
    }],
    ['keeps reviewer child environment minimal and explicit', () => {
      const child = buildReviewerEnv(
        {
          command: 'reviewer',
          args: [],
          passEnv: ['OPENAI_API_KEY'],
          timeoutMs: 120000,
        },
        {
          PATH: '/bin',
          HOME: '/home/test',
          OPENAI_API_KEY: 'allowed',
          AWS_SECRET_ACCESS_KEY: 'must-not-leak',
          RANDOM_PRIVATE_VALUE: 'must-not-leak',
        },
        'linux'
      );
      assert.strictEqual(child.OPENAI_API_KEY, 'allowed');
      assert.strictEqual(child.HOME, undefined);
      assert.strictEqual(child.AWS_SECRET_ACCESS_KEY, undefined);
      assert.strictEqual(child.RANDOM_PRIVATE_VALUE, undefined);
      assert.strictEqual(child.ECC_CROSS_REVIEW_PROTOCOL, 'ecc.review.v1');
    }],
    ['blocks secret-bearing objective before reviewer executes', () => {
      let calls = 0;
      const request = validRequest({
        objective: 'Review with token ' + 'ghp_' + 'A'.repeat(36),
      });
      assert.throws(
        () => runReviewer(
          request,
          { command: 'never-run', args: [], passEnv: [], timeoutMs: 120000 },
          { spawnSync: () => { calls += 1; return { status: 0, stdout: '{}' }; } }
        ),
        /secret scan/
      );
      assert.strictEqual(calls, 0);
    }],
    ['does not start reviewer when deterministic secret scan blocks', () => {
      let calls = 0;
      const request = validRequest({
        evidence: [{
          id: 'diff',
          kind: 'diff',
          source: 'git diff HEAD',
          content: '--- a/.env\n+++ b/.env\n+NAME=value\n',
        }],
      });
      assert.throws(
        () => runReviewer(
          request,
          { command: 'never-run', args: [], passEnv: [], timeoutMs: 120000 },
          { spawnSync: () => { calls += 1; return { status: 0, stdout: '{}' }; } }
        ),
        /secret scan/
      );
      assert.strictEqual(calls, 0);
    }],
    ['uses and removes a private temporary reviewer working directory', () => {
      let observedCwd;
      const result = runReviewer(
        validRequest(),
        { command: 'reviewer', args: [], passEnv: [], timeoutMs: 120000 },
        {
          env: { PATH: '/bin' },
          platform: 'linux',
          spawnSync: (command, args, options) => {
            observedCwd = options.cwd;
            assert.ok(fs.existsSync(observedCwd));
            if (process.platform !== 'win32') {
              assert.strictEqual(fs.statSync(observedCwd).mode & 0o777, 0o700);
            }
            return {
              status: 0,
              signal: null,
              stdout: JSON.stringify(cleanResult()),
              stderr: '',
            };
          },
        }
      );
      assert.strictEqual(result.status, 'clean');
      assert.match(path.basename(observedCwd), /^ecc-cross-review-/);
      assert.strictEqual(fs.existsSync(observedCwd), false);
    }],
    ['runs configured reviewer without a shell and validates its output', () => {
      let invocation;
      const request = validRequest();
      const result = runReviewer(
        request,
        {
          command: '/usr/bin/reviewer',
          args: ['--mode', 'json'],
          passEnv: [],
          timeoutMs: 120000,
        },
        {
          env: { PATH: '/bin', HOME: '/home/test' },
          platform: 'linux',
          cwd: '/tmp/cross-review-test',
          spawnSync: (command, args, options) => {
            invocation = { command, args, options };
            return {
              status: 0,
              signal: null,
              stdout: JSON.stringify(cleanResult()),
              stderr: '',
            };
          },
        }
      );
      assert.strictEqual(result.status, 'clean');
      assert.strictEqual(invocation.command, '/usr/bin/reviewer');
      assert.deepStrictEqual(invocation.args, ['--mode', 'json']);
      assert.strictEqual(invocation.options.shell, false);
      assert.strictEqual(invocation.options.cwd, '/tmp/cross-review-test');
      assert.ok(invocation.options.input.includes(REQUEST_SCHEMA));
    }],
    ['rejects malformed reviewer JSON', () => {
      assert.throws(
        () => runReviewer(
          validRequest(),
          { command: 'reviewer', args: [], passEnv: [], timeoutMs: 120000 },
          {
            spawnSync: () => ({
              status: 0,
              signal: null,
              stdout: 'not-json',
              stderr: '',
            }),
          }
        ),
        /malformed JSON/
      );
    }],
    ['writes and reloads user reviewer config without secret values', () => {
      const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ecc-cross-review-config-'));
      try {
        const configPath = path.join(root, 'cross-review.json');
        writeConfig({
          command: 'llm-review-adapter',
          args: [],
          passEnv: ['LLM_PROVIDER', 'OPENAI_API_KEY'],
          timeoutMs: 30000,
        }, configPath);
        const loaded = loadConfig(configPath);
        assert.strictEqual(loaded.command, 'llm-review-adapter');
        assert.deepStrictEqual(loaded.passEnv, ['LLM_PROVIDER', 'OPENAI_API_KEY']);
        const raw = fs.readFileSync(configPath, 'utf8');
        assert.ok(!raw.includes('sk-'));
        if (process.platform !== 'win32') {
          assert.strictEqual(fs.statSync(configPath).mode & 0o777, 0o600);
        }
      } finally {
        fs.rmSync(root, { recursive: true, force: true });
      }
    }],
    ['rejects symlink reviewer config', () => {
      if (process.platform === 'win32') return;
      const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ecc-cross-review-symlink-'));
      try {
        const target = path.join(root, 'target.json');
        const link = path.join(root, 'link.json');
        fs.writeFileSync(target, JSON.stringify({
          command: 'reviewer',
          args: [],
          passEnv: [],
          timeoutMs: 120000,
        }));
        fs.symlinkSync(target, link);
        assert.throws(() => loadConfig(link), /non-symlink/);
      } finally {
        fs.rmSync(root, { recursive: true, force: true });
      }
    }],
  ];

  for (const [name, fn] of cases) {
    if (test(name, fn)) passed += 1;
    else failed += 1;
  }

  console.log('\nResults: Passed: ' + passed + ', Failed: ' + failed);
  process.exit(failed > 0 ? 1 : 0);
}

main();
