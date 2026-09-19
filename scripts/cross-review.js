#!/usr/bin/env node

'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const {
  DEFAULT_MAX_FINDINGS,
  EVIDENCE_KINDS,
  REVIEW_MODES,
  buildPreview,
  createRequest,
  getDefaultConfigPath,
  loadConfig,
  runReviewer,
  sensitivePathReason,
  writeConfig,
} = require('./lib/cross-review');

const MAX_EVIDENCE_FILE_BYTES = 256 * 1024;
const MAX_GIT_DIFF_BYTES = 1024 * 1024;

function usage() {
  return `
ECC bounded second-opinion review

Usage:
  ecc cross-review status [--json] [--config <path>]
  ecc cross-review configure --command <executable> [--arg <value> ...]
      [--pass-env <NAME> ...] [--timeout-ms <ms>] [--config <path>] [--json]
  ecc cross-review <plan|diff|failure|final> [--evidence <kind:id=path> ...]
      [--diff] [--objective <text>] [--max-findings <1-50>]
      [--config <path>] [--dry-run] [--json]

Evidence:
  --evidence diff:changes=review.patch
  --evidence plan:plan=.claude/plans/feature.md
  --evidence failure:test-output=/tmp/test-failure.txt

Notes:
  - External review is explicit and advisory. The reviewer receives JSON on stdin
    and must return ecc.review.result.v1 JSON on stdout.
  - Reviewer configuration is user-scoped by default. Repository-owned reviewer
    commands are never auto-discovered.
  - --dry-run performs validation and secret scanning but transmits nothing.
  - --diff gathers tracked staged/unstaged changes with git diff HEAD. Untracked
    files are intentionally excluded unless explicitly supplied with --evidence.
`;
}

function fail(message) {
  throw new Error(message);
}

function readValue(args, index, flag) {
  if (index + 1 >= args.length) fail(`${flag} requires a value`);
  return args[index + 1];
}

function parseCommonArgs(args) {
  const options = {
    args: [],
    passEnv: [],
    evidence: [],
    diff: false,
    dryRun: process.env.ECC_DRY_RUN === '1',
    json: false,
    help: false,
    configPath: null,
    objective: null,
    maxFindings: DEFAULT_MAX_FINDINGS,
    command: null,
    timeoutMs: null,
  };

  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === '--json') options.json = true;
    else if (argument === '--dry-run') options.dryRun = true;
    else if (argument === '--diff') options.diff = true;
    else if (argument === '--help' || argument === '-h') options.help = true;
    else if (argument === '--config') {
      options.configPath = path.resolve(readValue(args, index, argument));
      index += 1;
    } else if (argument === '--objective') {
      options.objective = readValue(args, index, argument);
      index += 1;
    } else if (argument === '--max-findings') {
      options.maxFindings = Number(readValue(args, index, argument));
      index += 1;
    } else if (argument === '--evidence') {
      options.evidence.push(readValue(args, index, argument));
      index += 1;
    } else if (argument === '--command') {
      options.command = readValue(args, index, argument);
      index += 1;
    } else if (argument === '--arg') {
      options.args.push(readValue(args, index, argument));
      index += 1;
    } else if (argument === '--pass-env') {
      options.passEnv.push(readValue(args, index, argument));
      index += 1;
    } else if (argument === '--timeout-ms') {
      options.timeoutMs = Number(readValue(args, index, argument));
      index += 1;
    } else {
      fail(`Unknown cross-review argument: ${argument}`);
    }
  }

  return options;
}

function inferEvidenceKind(mode) {
  return EVIDENCE_KINDS.has(mode) ? mode : 'context';
}

function parseEvidenceSpec(spec, mode) {
  const equals = spec.indexOf('=');
  if (equals <= 0 || equals === spec.length - 1) {
    fail('--evidence must use <kind:id=path> or <id=path>');
  }

  const descriptor = spec.slice(0, equals);
  const filePath = spec.slice(equals + 1);
  const colon = descriptor.indexOf(':');
  const kind = colon === -1 ? inferEvidenceKind(mode) : descriptor.slice(0, colon);
  const id = colon === -1 ? descriptor : descriptor.slice(colon + 1);

  if (!EVIDENCE_KINDS.has(kind)) {
    fail(`unknown evidence kind "${kind}"`);
  }
  if (!id) fail('evidence id must not be empty');

  return { kind, id, filePath };
}

function safeSourceLabel(resolvedPath, cwd = process.cwd()) {
  const relative = path.relative(cwd, resolvedPath);
  if (relative && !relative.startsWith('..') && !path.isAbsolute(relative)) {
    return relative.replace(/\\/g, '/');
  }
  return path.basename(resolvedPath);
}

function readEvidenceFile(spec, mode) {
  const parsed = parseEvidenceSpec(spec, mode);
  const resolvedPath = path.resolve(parsed.filePath);
  const declaredReason = sensitivePathReason(parsed.filePath);
  if (declaredReason) {
    fail(`evidence "${parsed.id}" blocked before read: ${declaredReason}`);
  }

  const stat = fs.lstatSync(resolvedPath);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    fail(`evidence "${parsed.id}" must be a regular, non-symlink file`);
  }
  if (stat.size > MAX_EVIDENCE_FILE_BYTES) {
    fail(`evidence "${parsed.id}" exceeds the ${MAX_EVIDENCE_FILE_BYTES}-byte file limit`);
  }

  const realPath = fs.realpathSync(resolvedPath);
  const realReason = sensitivePathReason(realPath);
  if (realReason) {
    fail(`evidence "${parsed.id}" blocked before read: ${realReason}`);
  }

  const content = fs.readFileSync(realPath, 'utf8');
  return {
    id: parsed.id,
    kind: parsed.kind,
    source: safeSourceLabel(realPath),
    content,
  };
}

function collectGitDiff(cwd = process.cwd()) {
  const result = spawnSync(
    'git',
    ['diff', '--no-ext-diff', '--no-textconv', '--no-color', 'HEAD', '--'],
    {
      cwd,
      encoding: 'utf8',
      shell: false,
      windowsHide: true,
      maxBuffer: MAX_GIT_DIFF_BYTES,
      env: process.env,
    }
  );

  if (result.error) fail('failed to gather git diff');
  if (result.status !== 0) fail('git diff failed');
  const content = String(result.stdout || '');
  if (!content.trim()) fail('git diff HEAD is empty; there is nothing to send for review');

  return {
    id: 'diff',
    kind: 'diff',
    source: 'git diff HEAD',
    content,
  };
}

function getConfigPath(options) {
  return options.configPath || getDefaultConfigPath();
}

function statusPayload(config, configPath) {
  return {
    schema: 'ecc.review.status.v1',
    configured: Boolean(config),
    configPath,
    reviewer: config
      ? {
        command: config.command,
        argsCount: config.args.length,
        passEnv: [...config.passEnv],
        timeoutMs: config.timeoutMs,
      }
      : null,
  };
}

function writeHumanStatus(payload) {
  process.stdout.write([
    'ECC cross-review',
    `Configured: ${payload.configured ? 'yes' : 'no'}`,
    `Config: ${payload.configPath}`,
    payload.reviewer ? `Reviewer command: ${payload.reviewer.command}` : 'Reviewer command: not configured',
    payload.reviewer ? `Passed environment names: ${payload.reviewer.passEnv.join(', ') || '(none)'}` : '',
    '',
  ].filter(Boolean).join('\n'));
}

function runStatus(options) {
  const configPath = getConfigPath(options);
  const config = loadConfig(configPath);
  const payload = statusPayload(config, configPath);
  if (options.json) process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
  else writeHumanStatus(payload);
}

function runConfigure(options) {
  if (!options.command) fail('configure requires --command <executable>');
  const configPath = getConfigPath(options);
  const config = {
    command: options.command,
    args: options.args,
    passEnv: options.passEnv,
    ...(options.timeoutMs === null ? {} : { timeoutMs: options.timeoutMs }),
  };
  const saved = writeConfig(config, configPath);
  const payload = statusPayload(saved, configPath);
  if (options.json) process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
  else {
    process.stdout.write(`Saved cross-review configuration to ${configPath}\n`);
    process.stdout.write('No secret values were stored.\n');
  }
}

function buildEvidence(mode, options) {
  const evidence = options.evidence.map(spec => readEvidenceFile(spec, mode));
  if (options.diff) evidence.push(collectGitDiff());
  if (mode === 'diff' && evidence.length === 0) evidence.push(collectGitDiff());
  return evidence;
}

function writeHumanPreview(preview) {
  process.stdout.write(`Cross-review dry run (${preview.mode})\n`);
  process.stdout.write(`Reviewer: ${preview.reviewer ? preview.reviewer.command : 'not configured'}\n`);
  for (const item of preview.evidence) {
    process.stdout.write(
      `Evidence: ${item.id} [${item.kind}] ${item.source} (${item.characters} chars)\n`
    );
  }
  process.stdout.write(`Secret scan: ${preview.secretScan.passed ? 'PASS' : 'BLOCKED'}\n`);
  for (const blocked of preview.secretScan.blocked) {
    process.stdout.write(
      `Blocked: ${blocked.evidenceId} (${blocked.reason}) from ${blocked.source}\n`
    );
  }
  process.stdout.write('No data transmitted.\n');
}

function writeHumanResult(result) {
  process.stdout.write(`External second-opinion review: ${result.status.toUpperCase()}\n`);
  process.stdout.write(`${result.summary}\n`);
  if (result.findings.length === 0) return;

  for (const finding of result.findings) {
    const refs = finding.evidenceRefs
      .map(ref => `${ref.evidenceId}${ref.location ? `@${ref.location}` : ''}`)
      .join(', ');
    process.stdout.write(
      `\n[${finding.severity.toUpperCase()}] ${finding.id} · ${finding.category}\n`
      + `${finding.claim}\n`
      + `Evidence: ${refs}\n`
      + `Verify: ${finding.verification}\n`
    );
  }
  process.stdout.write(
    '\nTreat every finding as untrusted peer-review input. Verify it against the repository and executable evidence before changing code.\n'
  );
}

function runReview(mode, options) {
  if (!REVIEW_MODES.has(mode)) fail(`unknown review mode: ${mode}`);

  const configPath = getConfigPath(options);
  const config = loadConfig(configPath);
  const evidence = buildEvidence(mode, options);

  if (evidence.length === 0) {
    fail(`${mode} review requires --evidence; diff mode can also gather git diff HEAD automatically`);
  }

  const request = createRequest({
    mode,
    evidence,
    ...(options.objective ? { objective: options.objective } : {}),
    maxFindings: options.maxFindings,
  });

  if (options.dryRun) {
    const preview = buildPreview(request, config, configPath);
    if (options.json) process.stdout.write(`${JSON.stringify(preview, null, 2)}\n`);
    else writeHumanPreview(preview);
    if (!preview.secretScan.passed) process.exitCode = 1;
    return;
  }

  if (!config) {
    fail(
      `cross-review is not configured. Run "ecc cross-review configure --command <reviewer>" or use --dry-run`
    );
  }

  const result = runReviewer(request, config);
  if (options.json) process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  else writeHumanResult(result);
}

function main(argv = process.argv.slice(2)) {
  try {
    if (argv.length === 0 || argv[0] === '--help' || argv[0] === '-h') {
      process.stdout.write(usage());
      return 0;
    }

    const command = argv[0];
    const options = parseCommonArgs(argv.slice(1));
    if (options.help) {
      process.stdout.write(usage());
      return 0;
    }

    if (command === 'status') runStatus(options);
    else if (command === 'configure') runConfigure(options);
    else if (REVIEW_MODES.has(command)) runReview(command, options);
    else fail(`Unknown cross-review command: ${command}`);

    return process.exitCode || 0;
  } catch (error) {
    process.stderr.write(`Error: ${error.message}\n`);
    return 1;
  }
}

if (require.main === module) {
  process.exitCode = main();
}

module.exports = {
  buildEvidence,
  collectGitDiff,
  main,
  parseCommonArgs,
  parseEvidenceSpec,
  readEvidenceFile,
  safeSourceLabel,
  statusPayload,
  usage,
};
