'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const SCRIPT = path.join(__dirname, '..', '..', 'scripts', 'cross-review.js');

function runCli(args, options = {}) {
  return spawnSync(process.execPath, [SCRIPT, ...args], {
    cwd: options.cwd || process.cwd(),
    env: { ...process.env, ...(options.env || {}) },
    encoding: 'utf8',
    maxBuffer: 4 * 1024 * 1024,
  });
}

function tempDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
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

function initGitRepo(root) {
  const commands = [
    ['init'],
    ['config', 'user.email', 'cross-review@example.invalid'],
    ['config', 'user.name', 'Cross Review Test'],
  ];
  for (const args of commands) {
    const result = spawnSync('git', args, { cwd: root, encoding: 'utf8' });
    assert.strictEqual(result.status, 0, result.stderr);
  }
  fs.writeFileSync(path.join(root, 'app.js'), 'module.exports = 1;\n');
  assert.strictEqual(spawnSync('git', ['add', 'app.js'], { cwd: root }).status, 0);
  const commit = spawnSync('git', ['commit', '-m', 'base'], { cwd: root, encoding: 'utf8' });
  assert.strictEqual(commit.status, 0, commit.stderr);
}

function makeReviewer(root, options = {}) {
  const reviewerPath = path.join(root, options.name || 'reviewer.js');
  const sentinel = options.sentinel || '';
  const source = [
    "'use strict';",
    "const fs = require('fs');",
    "let input = '';",
    "process.stdin.setEncoding('utf8');",
    "process.stdin.on('data', chunk => { input += chunk; });",
    "process.stdin.on('end', () => {",
    sentinel ? "  fs.writeFileSync(" + JSON.stringify(sentinel) + ", 'called');" : "",
    "  const request = JSON.parse(input);",
    "  const result = {",
    "    schema: 'ecc.review.result.v1',",
    "    status: 'clean',",
    "    summary: 'No material issue found in supplied evidence.',",
    "    findings: []",
    "  };",
    "  process.stdout.write(JSON.stringify(result) + '\\n');",
    "});",
    "",
  ].filter(Boolean).join('\n');
  fs.writeFileSync(reviewerPath, source);
  return reviewerPath;
}

function configure(configPath, reviewerPath) {
  const result = runCli([
    'configure',
    '--command', process.execPath,
    '--arg', reviewerPath,
    '--config', configPath,
    '--json',
  ]);
  assert.strictEqual(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

function main() {
  console.log('\n=== Testing cross-review CLI ===\n');

  let passed = 0;
  let failed = 0;
  const cases = [
    ['shows bounded-review help', () => {
      const result = runCli(['--help']);
      assert.strictEqual(result.status, 0, result.stderr);
      assert.match(result.stdout, /bounded second-opinion review/i);
      assert.match(result.stdout, /No data transmitted/i);
      assert.match(result.stdout, /plan\|diff\|failure\|final/);
    }],
    ['status is safe when reviewer is not configured', () => {
      const root = tempDir('ecc-cross-review-status-');
      try {
        const configPath = path.join(root, 'missing.json');
        const result = runCli(['status', '--config', configPath, '--json']);
        assert.strictEqual(result.status, 0, result.stderr);
        const payload = JSON.parse(result.stdout);
        assert.strictEqual(payload.configured, false);
        assert.strictEqual(payload.reviewer, null);
      } finally {
        fs.rmSync(root, { recursive: true, force: true });
      }
    }],
    ['configure stores command metadata but no secret values', () => {
      const root = tempDir('ecc-cross-review-configure-');
      try {
        const configPath = path.join(root, 'config.json');
        const result = runCli([
          'configure',
          '--command', 'llm-review-adapter',
          '--pass-env', 'OPENAI_API_KEY',
          '--pass-env', 'LLM_PROVIDER',
          '--config', configPath,
          '--json',
        ], {
          env: { OPENAI_API_KEY: 'sk-' + 'Z'.repeat(32) },
        });
        assert.strictEqual(result.status, 0, result.stderr);
        const payload = JSON.parse(result.stdout);
        assert.strictEqual(payload.configured, true);
        assert.deepStrictEqual(
          payload.reviewer.passEnv,
          ['OPENAI_API_KEY', 'LLM_PROVIDER']
        );
        const raw = fs.readFileSync(configPath, 'utf8');
        assert.ok(!raw.includes('sk-'));
      } finally {
        fs.rmSync(root, { recursive: true, force: true });
      }
    }],
    ['dry-run validates a plan without contacting reviewer', () => {
      const root = tempDir('ecc-cross-review-dry-');
      try {
        const planPath = path.join(root, 'plan.md');
        const configPath = path.join(root, 'config.json');
        const sentinel = path.join(root, 'called.txt');
        fs.writeFileSync(planPath, '# Plan\nUse a bounded adapter.\n');
        const reviewer = makeReviewer(root, { sentinel });
        configure(configPath, reviewer);

        const result = runCli([
          'plan',
          '--evidence', 'plan:plan=' + planPath,
          '--config', configPath,
          '--dry-run',
          '--json',
        ]);
        assert.strictEqual(result.status, 0, result.stderr);
        const payload = JSON.parse(result.stdout);
        assert.strictEqual(payload.schema, 'ecc.review.preview.v1');
        assert.strictEqual(payload.transmitted, false);
        assert.strictEqual(payload.secretScan.passed, true);
        assert.strictEqual(fs.existsSync(sentinel), false);
      } finally {
        fs.rmSync(root, { recursive: true, force: true });
      }
    }],
    ['invokes configured reviewer and returns validated JSON', () => {
      const root = tempDir('ecc-cross-review-run-');
      try {
        const planPath = path.join(root, 'plan.md');
        const configPath = path.join(root, 'config.json');
        fs.writeFileSync(planPath, '# Plan\nKeep the external reviewer advisory.\n');
        const reviewer = makeReviewer(root);
        configure(configPath, reviewer);

        const result = runCli([
          'plan',
          '--evidence', 'plan:plan=' + planPath,
          '--config', configPath,
          '--json',
        ]);
        assert.strictEqual(result.status, 0, result.stderr);
        const payload = JSON.parse(result.stdout);
        assert.strictEqual(payload.schema, 'ecc.review.result.v1');
        assert.strictEqual(payload.status, 'clean');
      } finally {
        fs.rmSync(root, { recursive: true, force: true });
      }
    }],
    ['blocks secret-bearing evidence before reviewer executes', () => {
      const root = tempDir('ecc-cross-review-secret-');
      try {
        const evidencePath = path.join(root, 'failure.txt');
        const configPath = path.join(root, 'config.json');
        const sentinel = path.join(root, 'called.txt');
        fs.writeFileSync(
          evidencePath,
          'Authorization: Bearer ' + 'A'.repeat(40) + '\n'
        );
        const reviewer = makeReviewer(root, { sentinel });
        configure(configPath, reviewer);

        const result = runCli([
          'failure',
          '--evidence', 'failure:failure=' + evidencePath,
          '--config', configPath,
          '--json',
        ]);
        assert.strictEqual(result.status, 1);
        assert.match(result.stderr, /secret scan/i);
        assert.strictEqual(fs.existsSync(sentinel), false);
      } finally {
        fs.rmSync(root, { recursive: true, force: true });
      }
    }],
    ['rejects sensitive files before reading them', () => {
      const root = tempDir('ecc-cross-review-sensitive-');
      try {
        const envPath = path.join(root, '.env');
        fs.writeFileSync(envPath, 'NOT_A_REAL_SECRET=value\n');
        const result = runCli([
          'plan',
          '--evidence', 'plan:plan=' + envPath,
          '--dry-run',
          '--json',
        ]);
        assert.strictEqual(result.status, 1);
        assert.match(result.stderr, /blocked before read: dotenv-file/);
      } finally {
        fs.rmSync(root, { recursive: true, force: true });
      }
    }],
    ['diff mode gathers tracked changes but transmits nothing in dry-run', () => {
      const root = tempDir('ecc-cross-review-git-');
      try {
        initGitRepo(root);
        fs.writeFileSync(path.join(root, 'app.js'), 'module.exports = 2;\n');
        const result = runCli(['diff', '--dry-run', '--json'], { cwd: root });
        assert.strictEqual(result.status, 0, result.stderr);
        const payload = JSON.parse(result.stdout);
        assert.strictEqual(payload.transmitted, false);
        assert.strictEqual(payload.evidence[0].id, 'diff');
        assert.strictEqual(payload.evidence[0].source, 'git diff HEAD');
        assert.ok(payload.evidence[0].characters > 0);
      } finally {
        fs.rmSync(root, { recursive: true, force: true });
      }
    }],
    ['diff mode blocks sensitive paths from diff headers', () => {
      const root = tempDir('ecc-cross-review-git-secret-');
      try {
        initGitRepo(root);
        fs.writeFileSync(path.join(root, '.env'), 'SAFE=value\n');
        spawnSync('git', ['add', '.env'], { cwd: root });
        spawnSync('git', ['commit', '-m', 'add env'], { cwd: root });
        fs.writeFileSync(path.join(root, '.env'), 'SAFE=changed\n');

        const result = runCli(['diff', '--dry-run', '--json'], { cwd: root });
        assert.strictEqual(result.status, 1);
        const payload = JSON.parse(result.stdout);
        assert.strictEqual(payload.transmitted, false);
        assert.strictEqual(payload.secretScan.passed, false);
        assert.strictEqual(payload.secretScan.blocked[0].reason, 'dotenv-file');
      } finally {
        fs.rmSync(root, { recursive: true, force: true });
      }
    }],
    ['plan mode fails closed without explicit evidence', () => {
      const result = runCli(['plan', '--dry-run', '--json']);
      assert.strictEqual(result.status, 1);
      assert.match(result.stderr, /requires --evidence/);
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
