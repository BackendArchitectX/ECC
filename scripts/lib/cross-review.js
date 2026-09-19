'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const REQUEST_SCHEMA = 'ecc.review.request.v1';
const RESULT_SCHEMA = 'ecc.review.result.v1';
const PREVIEW_SCHEMA = 'ecc.review.preview.v1';

const REVIEW_MODES = new Set(['plan', 'diff', 'failure', 'final']);
const EVIDENCE_KINDS = new Set(['plan', 'diff', 'test', 'failure', 'context']);
const SEVERITIES = new Set(['critical', 'high', 'medium', 'low']);
const CATEGORIES = new Set([
  'correctness',
  'security',
  'reliability',
  'performance',
  'architecture',
  'testing',
  'maintainability',
]);

const MAX_EVIDENCE_ITEMS = 8;
const MAX_EVIDENCE_ITEM_CHARS = 50_000;
const MAX_EVIDENCE_TOTAL_CHARS = 120_000;
const DEFAULT_MAX_FINDINGS = 20;
const MAX_FINDINGS = 50;
const DEFAULT_TIMEOUT_MS = 120_000;
const DEFAULT_MAX_BUFFER_BYTES = 4 * 1024 * 1024;

const SENSITIVE_PATH_RULES = Object.freeze([
  ['dotenv-file', /(^|\/)\.env(?:$|[.\/])/i],
  ['credential-file', /(^|\/)(?:credentials?|secrets?)(?:$|[._\/-])/i],
  ['private-key-file', /\.(?:pem|key|p12|pfx)$/i],
  ['ssh-private-key', /(^|\/)id_(?:rsa|dsa|ecdsa|ed25519)$/i],
  ['aws-credentials-file', /(^|\/)\.aws\/credentials$/i],
  ['npm-credentials-file', /(^|\/)\.npmrc$/i],
]);

const SECRET_PATTERNS = Object.freeze([
  ['private-key', /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/],
  ['aws-secret-access-key', /(?:^|[\s"'\x60])AWS_SECRET_ACCESS_KEY\s*[:=]\s*["']?[A-Za-z0-9/+=]{32,}/im],
  ['authorization-bearer', /\bAuthorization\s*:\s*Bearer\s+[A-Za-z0-9._~+/=-]{16,}/i],
  ['openai-api-key', /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/],
  ['github-token', /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/],
  ['slack-token', /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/],
]);

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function assertNoExtraKeys(value, allowedKeys, label) {
  const extras = Object.keys(value).filter(key => !allowedKeys.has(key));
  if (extras.length > 0) {
    throw new Error(`${label} contains unsupported field(s): ${extras.join(', ')}`);
  }
}

function requireString(value, label, { allowEmpty = false } = {}) {
  if (typeof value !== 'string' || (!allowEmpty && value.trim() === '')) {
    throw new Error(`${label} must be ${allowEmpty ? 'a string' : 'a non-empty string'}`);
  }
  if (value.includes('\0')) {
    throw new Error(`${label} must not contain NUL bytes`);
  }
  return value;
}

function normalizeSource(source) {
  return String(source || '').replace(/\\/g, '/');
}

function sensitivePathReason(source) {
  const normalized = normalizeSource(source);
  for (const [reason, pattern] of SENSITIVE_PATH_RULES) {
    if (pattern.test(normalized)) return reason;
  }
  return null;
}

function sensitiveDiffPathReason(content) {
  for (const line of String(content || '').split(/\r?\n/)) {
    const match = line.match(/^(?:---|\+\+\+)\s+(?:[ab]\/(.+)|(.+))$/);
    if (!match) continue;
    const candidate = (match[1] || match[2] || '').trim();
    if (!candidate || candidate === '/dev/null') continue;
    const reason = sensitivePathReason(candidate);
    if (reason) return reason;
  }
  return null;
}

function scanSecretText(content) {
  for (const [reason, pattern] of SECRET_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(content)) return reason;
  }
  return null;
}

function scanEvidence(evidence) {
  const blocked = [];
  for (const item of evidence) {
    const pathReason = sensitivePathReason(item.source);
    if (pathReason) {
      blocked.push({ evidenceId: item.id, source: item.source, reason: pathReason });
      continue;
    }

    const diffPathReason = item.kind === 'diff' ? sensitiveDiffPathReason(item.content) : null;
    if (diffPathReason) {
      blocked.push({ evidenceId: item.id, source: item.source, reason: diffPathReason });
      continue;
    }

    const secretReason = scanSecretText(item.content);
    if (secretReason) {
      blocked.push({ evidenceId: item.id, source: item.source, reason: secretReason });
    }
  }
  return blocked;
}

function validateEvidence(evidence) {
  if (!Array.isArray(evidence) || evidence.length === 0) {
    throw new Error('request.evidence must contain at least one evidence item');
  }
  if (evidence.length > MAX_EVIDENCE_ITEMS) {
    throw new Error(`request.evidence exceeds the ${MAX_EVIDENCE_ITEMS}-item limit`);
  }

  const ids = new Set();
  let totalChars = 0;
  for (const [index, item] of evidence.entries()) {
    if (!isPlainObject(item)) {
      throw new Error(`request.evidence[${index}] must be an object`);
    }
    assertNoExtraKeys(
      item,
      new Set(['id', 'kind', 'source', 'content']),
      `request.evidence[${index}]`
    );
    requireString(item.id, `request.evidence[${index}].id`);
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(item.id)) {
      throw new Error(`request.evidence[${index}].id must be a stable identifier up to 64 characters`);
    }
    if (ids.has(item.id)) {
      throw new Error(`request.evidence contains duplicate id: ${item.id}`);
    }
    ids.add(item.id);

    if (!EVIDENCE_KINDS.has(item.kind)) {
      throw new Error(`request.evidence[${index}].kind must be one of: ${[...EVIDENCE_KINDS].join(', ')}`);
    }
    requireString(item.source, `request.evidence[${index}].source`);
    requireString(item.content, `request.evidence[${index}].content`);

    if (item.content.length > MAX_EVIDENCE_ITEM_CHARS) {
      throw new Error(
        `request.evidence[${index}].content exceeds the ${MAX_EVIDENCE_ITEM_CHARS}-character item limit`
      );
    }
    totalChars += item.content.length;
  }

  if (totalChars > MAX_EVIDENCE_TOTAL_CHARS) {
    throw new Error(
      `request.evidence exceeds the ${MAX_EVIDENCE_TOTAL_CHARS}-character total limit`
    );
  }
  return { ids, totalChars };
}

function validateRequest(request) {
  if (!isPlainObject(request)) throw new Error('review request must be an object');
  assertNoExtraKeys(
    request,
    new Set(['schema', 'mode', 'objective', 'evidence', 'constraints', 'trust']),
    'request'
  );
  if (request.schema !== REQUEST_SCHEMA) {
    throw new Error(`request.schema must be ${REQUEST_SCHEMA}`);
  }
  if (!REVIEW_MODES.has(request.mode)) {
    throw new Error(`request.mode must be one of: ${[...REVIEW_MODES].join(', ')}`);
  }
  requireString(request.objective, 'request.objective');

  const evidenceMeta = validateEvidence(request.evidence);

  if (!isPlainObject(request.constraints)) {
    throw new Error('request.constraints must be an object');
  }
  assertNoExtraKeys(request.constraints, new Set(['maxFindings']), 'request.constraints');
  const maxFindings = request.constraints.maxFindings;
  if (!Number.isInteger(maxFindings) || maxFindings < 1 || maxFindings > MAX_FINDINGS) {
    throw new Error(`request.constraints.maxFindings must be an integer from 1 to ${MAX_FINDINGS}`);
  }

  if (!isPlainObject(request.trust)) throw new Error('request.trust must be an object');
  assertNoExtraKeys(
    request.trust,
    new Set(['reviewerAuthority', 'repositoryWrite', 'shellAuthority']),
    'request.trust'
  );
  if (
    request.trust.reviewerAuthority !== 'advisory'
    || request.trust.repositoryWrite !== false
    || request.trust.shellAuthority !== false
  ) {
    throw new Error(
      'request.trust must keep reviewerAuthority=advisory, repositoryWrite=false, and shellAuthority=false'
    );
  }

  return evidenceMeta;
}

function createRequest({
  mode,
  evidence,
  objective = 'Provide an independent second-opinion review. Return findings only; do not assume implementation authority.',
  maxFindings = DEFAULT_MAX_FINDINGS,
} = {}) {
  const request = {
    schema: REQUEST_SCHEMA,
    mode,
    objective,
    evidence: Array.isArray(evidence) ? evidence.map(item => ({ ...item })) : evidence,
    constraints: { maxFindings },
    trust: {
      reviewerAuthority: 'advisory',
      repositoryWrite: false,
      shellAuthority: false,
    },
  };
  validateRequest(request);
  return request;
}

function validateEvidenceRefs(finding, evidenceIds, index) {
  if (!Array.isArray(finding.evidenceRefs) || finding.evidenceRefs.length === 0) {
    throw new Error(`result.findings[${index}].evidenceRefs must contain at least one reference`);
  }

  for (const [refIndex, ref] of finding.evidenceRefs.entries()) {
    if (!isPlainObject(ref)) {
      throw new Error(`result.findings[${index}].evidenceRefs[${refIndex}] must be an object`);
    }
    assertNoExtraKeys(
      ref,
      new Set(['evidenceId', 'location']),
      `result.findings[${index}].evidenceRefs[${refIndex}]`
    );
    requireString(ref.evidenceId, `result.findings[${index}].evidenceRefs[${refIndex}].evidenceId`);
    if (!evidenceIds.has(ref.evidenceId)) {
      throw new Error(
        `result.findings[${index}] references evidence that was not supplied: ${ref.evidenceId}`
      );
    }
    if (ref.location !== undefined) {
      requireString(ref.location, `result.findings[${index}].evidenceRefs[${refIndex}].location`);
    }
  }
}

function validateResult(result, request) {
  const { ids: evidenceIds } = validateRequest(request);
  if (!isPlainObject(result)) throw new Error('review result must be an object');
  assertNoExtraKeys(result, new Set(['schema', 'status', 'summary', 'findings']), 'result');
  if (result.schema !== RESULT_SCHEMA) {
    throw new Error(`result.schema must be ${RESULT_SCHEMA}`);
  }
  if (!['clean', 'findings'].includes(result.status)) {
    throw new Error('result.status must be clean or findings');
  }
  requireString(result.summary, 'result.summary');

  if (!Array.isArray(result.findings)) throw new Error('result.findings must be an array');
  if (result.findings.length > request.constraints.maxFindings || result.findings.length > MAX_FINDINGS) {
    throw new Error('result.findings exceeds the configured finding limit');
  }
  if (result.status === 'clean' && result.findings.length !== 0) {
    throw new Error('result.status=clean requires an empty findings array');
  }
  if (result.status === 'findings' && result.findings.length === 0) {
    throw new Error('result.status=findings requires at least one finding');
  }

  const findingIds = new Set();
  for (const [index, finding] of result.findings.entries()) {
    if (!isPlainObject(finding)) throw new Error(`result.findings[${index}] must be an object`);
    assertNoExtraKeys(
      finding,
      new Set(['id', 'severity', 'category', 'claim', 'evidenceRefs', 'verification']),
      `result.findings[${index}]`
    );
    requireString(finding.id, `result.findings[${index}].id`);
    if (findingIds.has(finding.id)) throw new Error(`duplicate finding id: ${finding.id}`);
    findingIds.add(finding.id);

    if (!SEVERITIES.has(finding.severity)) {
      throw new Error(`result.findings[${index}].severity is invalid`);
    }
    if (!CATEGORIES.has(finding.category)) {
      throw new Error(`result.findings[${index}].category is invalid`);
    }
    requireString(finding.claim, `result.findings[${index}].claim`);
    requireString(finding.verification, `result.findings[${index}].verification`);
    validateEvidenceRefs(finding, evidenceIds, index);
  }

  return result;
}

function getDefaultConfigPath(env = process.env, platform = process.platform) {
  if (env.ECC_CROSS_REVIEW_CONFIG) return path.resolve(env.ECC_CROSS_REVIEW_CONFIG);

  if (platform === 'win32' && env.APPDATA) {
    return path.join(env.APPDATA, 'ecc', 'cross-review.json');
  }

  const configRoot = env.XDG_CONFIG_HOME
    ? path.resolve(env.XDG_CONFIG_HOME)
    : path.join(env.HOME || os.homedir(), '.config');
  return path.join(configRoot, 'ecc', 'cross-review.json');
}

function validateConfig(config) {
  if (!isPlainObject(config)) throw new Error('cross-review config must be an object');
  requireString(config.command, 'config.command');

  const args = config.args === undefined ? [] : config.args;
  if (!Array.isArray(args) || !args.every(value => typeof value === 'string' && !value.includes('\0'))) {
    throw new Error('config.args must be an array of strings');
  }

  const passEnv = config.passEnv === undefined ? [] : config.passEnv;
  if (
    !Array.isArray(passEnv)
    || !passEnv.every(value => typeof value === 'string' && /^[A-Za-z_][A-Za-z0-9_]*$/.test(value))
  ) {
    throw new Error('config.passEnv must be an array of environment-variable names');
  }
  if (new Set(passEnv).size !== passEnv.length) {
    throw new Error('config.passEnv must not contain duplicates');
  }

  const timeoutMs = config.timeoutMs === undefined ? DEFAULT_TIMEOUT_MS : config.timeoutMs;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1_000 || timeoutMs > 300_000) {
    throw new Error('config.timeoutMs must be an integer from 1000 to 300000');
  }

  return {
    command: config.command,
    args: [...args],
    passEnv: [...passEnv],
    timeoutMs,
  };
}

function loadConfig(configPath = getDefaultConfigPath()) {
  if (!fs.existsSync(configPath)) return null;

  const stat = fs.lstatSync(configPath);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error('cross-review config must be a regular, non-symlink file');
  }

  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  } catch {
    throw new Error('cross-review config is not valid JSON');
  }
  return validateConfig(parsed);
}

function writeConfig(config, configPath = getDefaultConfigPath()) {
  const normalized = validateConfig(config);
  fs.mkdirSync(path.dirname(configPath), { recursive: true, mode: 0o700 });

  const temporaryPath = `${configPath}.tmp-${process.pid}`;
  try {
    fs.writeFileSync(temporaryPath, `${JSON.stringify(normalized, null, 2)}\n`, {
      encoding: 'utf8',
      mode: 0o600,
      flag: 'wx',
    });
    try {
      fs.chmodSync(temporaryPath, 0o600);
    } catch {
      // Best effort on filesystems that do not implement POSIX modes.
    }
    fs.renameSync(temporaryPath, configPath);
  } finally {
    try {
      if (fs.existsSync(temporaryPath)) fs.unlinkSync(temporaryPath);
    } catch {
      // Do not mask the original write error with cleanup failure.
    }
  }
  return normalized;
}

function buildReviewerEnv(config, env = process.env, platform = process.platform) {
  const allowedBase = platform === 'win32'
    ? ['PATH', 'Path', 'PATHEXT', 'SystemRoot', 'ComSpec', 'TEMP', 'TMP', 'USERPROFILE', 'APPDATA']
    : ['PATH', 'HOME', 'TMPDIR', 'TMP', 'TEMP', 'LANG', 'LC_ALL'];

  const childEnv = {};
  for (const name of [...allowedBase, ...config.passEnv]) {
    if (Object.prototype.hasOwnProperty.call(env, name) && typeof env[name] === 'string') {
      childEnv[name] = env[name];
    }
  }
  childEnv.ECC_CROSS_REVIEW_PROTOCOL = 'ecc.review.v1';
  return childEnv;
}

function runReviewer(request, config, options = {}) {
  validateRequest(request);
  const blocked = scanEvidence(request.evidence);
  if (blocked.length > 0) {
    const reasons = blocked.map(item => `${item.evidenceId}:${item.reason}`).join(', ');
    throw new Error(`external review blocked by deterministic secret scan (${reasons})`);
  }

  const normalizedConfig = validateConfig(config);
  const runner = options.spawnSync || spawnSync;
  const result = runner(
    normalizedConfig.command,
    normalizedConfig.args,
    {
      input: `${JSON.stringify(request)}\n`,
      encoding: 'utf8',
      shell: false,
      windowsHide: true,
      timeout: normalizedConfig.timeoutMs,
      maxBuffer: options.maxBufferBytes || DEFAULT_MAX_BUFFER_BYTES,
      cwd: options.cwd || os.tmpdir(),
      env: buildReviewerEnv(normalizedConfig, options.env || process.env, options.platform || process.platform),
    }
  );

  if (result.error) {
    const timedOut = result.error.code === 'ETIMEDOUT';
    throw new Error(timedOut ? 'external reviewer timed out' : 'external reviewer failed to start');
  }
  if (result.signal) throw new Error(`external reviewer terminated by signal ${result.signal}`);
  if (result.status !== 0) {
    throw new Error(`external reviewer exited with status ${result.status}`);
  }

  let parsed;
  try {
    parsed = JSON.parse(String(result.stdout || '').trim());
  } catch {
    throw new Error('external reviewer returned malformed JSON');
  }
  return validateResult(parsed, request);
}

function buildPreview(request, config, configPath = getDefaultConfigPath()) {
  const { totalChars } = validateRequest(request);
  const blocked = scanEvidence(request.evidence);
  return {
    schema: PREVIEW_SCHEMA,
    mode: request.mode,
    reviewer: config
      ? {
        command: config.command,
        argsCount: config.args.length,
        passEnv: [...config.passEnv],
        configPath,
      }
      : null,
    evidence: request.evidence.map(item => ({
      id: item.id,
      kind: item.kind,
      source: item.source,
      characters: item.content.length,
    })),
    totalCharacters: totalChars,
    secretScan: {
      passed: blocked.length === 0,
      blocked: blocked.map(item => ({
        evidenceId: item.evidenceId,
        source: item.source,
        reason: item.reason,
      })),
    },
    transmitted: false,
    message: 'No data transmitted.',
  };
}

module.exports = {
  CATEGORIES,
  DEFAULT_MAX_FINDINGS,
  DEFAULT_TIMEOUT_MS,
  EVIDENCE_KINDS,
  MAX_EVIDENCE_ITEM_CHARS,
  MAX_EVIDENCE_ITEMS,
  MAX_EVIDENCE_TOTAL_CHARS,
  MAX_FINDINGS,
  PREVIEW_SCHEMA,
  REQUEST_SCHEMA,
  RESULT_SCHEMA,
  REVIEW_MODES,
  SEVERITIES,
  assertNoExtraKeys,
  buildPreview,
  buildReviewerEnv,
  createRequest,
  getDefaultConfigPath,
  loadConfig,
  runReviewer,
  scanEvidence,
  scanSecretText,
  sensitiveDiffPathReason,
  sensitivePathReason,
  validateConfig,
  validateRequest,
  validateResult,
  writeConfig,
};
