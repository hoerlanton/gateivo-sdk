#!/usr/bin/env node
/** Local readiness check only. This script never publishes or contacts a service. */
import { createHash } from 'node:crypto';
import { lstat, readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const artifacts = path.join(root, 'artifacts');
const requiredDocuments = ['README.md', 'LICENSE', 'docs/authentication.md', 'docs/workos-connection.md',
  'docs/workos-reference.md', 'docs/password-login.md', 'SECURITY.md'];
const exampleFiles = ['actions.mjs', 'client.mjs', 'constants.mjs', 'demo-approvals.mjs',
  'index.mjs', 'repository.mjs', 'server.mjs', 'exercise.mjs'];
const entries = ['index', 'core', 'express', 'oauth', 'workos-connect', 'workos-connect-express', 'workos-connect-postgres',
  'login-express', 'login-postgres', 'workos-standalone', 'workos-password'];
const extensions = ['js', 'cjs', 'd.ts', 'd.cts'];
const distPattern = /^dist\/[A-Za-z0-9_-]+(?:\.d\.(?:ts|cts)|\.(?:js|cjs))$/;
const maxFileBytes = 16 * 1024 * 1024;

class ReadinessError extends Error {}
function requireCondition(condition, message) {
  if (!condition) throw new ReadinessError(message);
}
function sorted(values) { return [...values].sort(); }
function sameStrings(left, right) {
  return Array.isArray(left) && Array.isArray(right)
    && left.every((value) => typeof value === 'string')
    && right.every((value) => typeof value === 'string')
    && JSON.stringify(sorted(left)) === JSON.stringify(sorted(right));
}
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  }
  return value;
}
function digest(bytes, algorithm, encoding = 'hex') {
  return createHash(algorithm).update(bytes).digest(encoding);
}
async function readLocal(filename) {
  const information = await lstat(filename);
  requireCondition(information.isFile() && information.size <= maxFileBytes,
    'A release artifact is missing, oversized, or is not a regular file.');
  return readFile(filename);
}
async function readJson(filename) {
  return JSON.parse((await readLocal(filename)).toString('utf8'));
}
function permitted(name) {
  return name === 'package.json' || name === 'NOTICE'
    || requiredDocuments.includes(name) || distPattern.test(name);
}

// npm's short, flat package paths use ordinary tar entries. Reject links,
// extended paths and unknown metadata rather than extracting any files.
function tarFiles(compressed) {
  const tar = gunzipSync(compressed, { maxOutputLength: 64 * 1024 * 1024 });
  const files = new Map();
  let offset = 0;
  let terminated = false;
  const octal = (bytes) => {
    const value = bytes.toString('ascii').replace(/\0.*$/, '').trim();
    requireCondition(/^[0-7]+$/.test(value), 'The package tar archive contains invalid metadata.');
    return Number.parseInt(value, 8);
  };
  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      requireCondition(tar.subarray(offset).every((byte) => byte === 0),
        'The package tar archive has data after its terminator.');
      terminated = true;
      break;
    }
    const checksum = header.reduce((sum, byte, index) => sum + (index >= 148 && index < 156 ? 32 : byte), 0);
    requireCondition(checksum === octal(header.subarray(148, 156)),
      'The package tar archive checksum is invalid.');
    const field = (start, end) => header.subarray(start, end).toString('utf8').replace(/\0.*$/, '');
    const name = field(0, 100);
    requireCondition((header[156] === 0 || header[156] === 48)
      && field(345, 500) === '' && field(157, 257) === '' && name.startsWith('package/'),
    'The package tar archive contains an unsupported entry.');
    const relative = name.slice('package/'.length);
    requireCondition(permitted(relative) && !files.has(relative),
      'The package archive contains an unexpected or duplicate file.');
    const size = octal(header.subarray(124, 136));
    requireCondition(Number.isSafeInteger(size) && size <= maxFileBytes && offset + 512 + size <= tar.length,
      'The package tar archive contains an invalid file size.');
    files.set(relative, tar.subarray(offset + 512, offset + 512 + size));
    offset += 512 + Math.ceil(size / 512) * 512;
    requireCondition(files.size <= 200, 'The package archive contains too many files.');
  }
  requireCondition(terminated && files.size > 0, 'The package tar archive is incomplete.');
  return files;
}

async function main() {
  const manifest = await readJson(path.join(root, 'package.json'));
  requireCondition(manifest.name === '@gateivo/sdk'
    && /^\d+\.\d+\.\d+-preview\.\d+$/.test(manifest.version), 'The SDK package identity or preview version is invalid.');
  requireCondition(manifest.private === true, 'Registry publication must remain disabled with private: true.');
  requireCondition(typeof manifest.license === 'string' && manifest.license.trim() !== ''
    && !/\bUNLICENSED\b/i.test(manifest.license), 'Choose a distribution licence and add LICENSE before release readiness can pass.');
  const lock = await readJson(path.join(root, 'package-lock.json'));
  const lockedRoot = lock.packages?.[''];
  requireCondition(lock.name === manifest.name && lock.version === manifest.version
    && lockedRoot?.name === manifest.name && lockedRoot?.version === manifest.version
    && lockedRoot?.license === manifest.license,
  'The lockfile package identity and licence must match the current manifest.');
  for (const field of ['dependencies', 'devDependencies', 'engines']) {
    requireCondition(JSON.stringify(canonical(lockedRoot[field])) === JSON.stringify(canonical(manifest[field])),
      'The lockfile dependency or runtime metadata differs from the current manifest. Refresh it before release.');
  }
  for (const document of requiredDocuments) {
    requireCondition((await readLocal(path.join(root, document))).toString('utf8').trim().length > 0,
      'Required release documentation or LICENSE is missing or empty.');
  }

  const receipt = await readJson(path.join(artifacts, 'package-manifest.json'));
  const filename = `gateivo-sdk-${manifest.version}.tgz`;
  requireCondition(receipt.filename === filename && receipt.name === manifest.name && receipt.version === manifest.version,
    'The archive receipt does not match the current SDK package.');
  const bytes = await readLocal(path.join(artifacts, filename));
  const integrity = `sha512-${digest(bytes, 'sha512', 'base64')}`;
  requireCondition(receipt.integrity === integrity && receipt.sha256 === digest(bytes, 'sha256'),
    'The package archive does not match its recorded hashes.');

  const archive = tarFiles(bytes);
  const files = sorted(archive.keys());
  requireCondition(sameStrings(receipt.files, files), 'The archive file list does not match its receipt.');
  for (const name of ['package.json', ...requiredDocuments,
    ...entries.flatMap((entry) => extensions.map((extension) => `dist/${entry}.${extension}`))]) {
    requireCondition(archive.has(name), 'The package archive is missing a required public file.');
  }
  const packedManifest = JSON.parse(archive.get('package.json').toString('utf8'));
  requireCondition(JSON.stringify(canonical(packedManifest)) === JSON.stringify(canonical(manifest)),
    'The packed package manifest differs from the current manifest. Repack and rerun both consumer checks.');
  const currentDist = await readdir(path.join(root, 'dist'), { withFileTypes: true });
  requireCondition(currentDist.every((entry) => entry.isFile() && distPattern.test(`dist/${entry.name}`))
    && sameStrings(currentDist.map((entry) => `dist/${entry.name}`), files.filter((name) => name.startsWith('dist/'))),
  'The current dist file list differs from the package archive.');
  for (const name of files.filter((name) => name !== 'package.json')) {
    requireCondition(archive.get(name).equals(await readLocal(path.join(root, name))),
      'A packed build or documentation file has changed. Repack and rerun both consumer checks.');
  }

  for (const [reportName, expectedMajor] of [
    ['consumer-node22-verification.json', 22], ['consumer-verification.json', 24],
  ]) {
    const report = await readJson(path.join(artifacts, reportName));
    const version = typeof report.node === 'string' && /^v(\d+)\.(\d+)\.(\d+)$/.exec(report.node);
    requireCondition(version && Number(version[1]) === expectedMajor
      && (expectedMajor !== 22 || Number(version[2]) >= 6),
    'Consumer verification must cover Node 22.6 or newer in 22.x and Node 24.x separately.');
    requireCondition(report.status === 'passed' && report.isolatedInstallation === true,
      'Both independent consumer installations must pass before release readiness can pass.');
    requireCondition(report.package?.name === manifest.name && report.package?.version === manifest.version
      && report.package?.integrity === integrity && report.package?.fileCount === files.length
      && sameStrings(report.package?.files, files),
    'A consumer report tested a different package archive. Rerun both consumer checks.');
    const exampleHashes = report.example?.files;
    requireCondition(exampleHashes && sameStrings(Object.keys(exampleHashes), exampleFiles),
      'A consumer report does not cover the complete current workouts example.');
    for (const example of exampleFiles) {
      requireCondition(/^[a-f0-9]{64}$/.test(exampleHashes[example])
        && exampleHashes[example] === digest(await readLocal(path.join(root, 'examples/workouts', example)), 'sha256'),
      'The workouts example changed after consumer verification. Rerun both consumer checks.');
    }
  }
  for (const [reportName, expectedMajor] of [
    ['workos-postgres-node22-verification.json', 22], ['workos-postgres-verification.json', 24],
  ]) {
    const report = await readJson(path.join(artifacts, reportName));
    const version = typeof report.node === 'string' && /^v(\d+)\.(\d+)\.(\d+)$/.exec(report.node);
    requireCondition(version && Number(version[1]) === expectedMajor
      && (expectedMajor !== 22 || Number(version[2]) >= 6)
      && report.status === 'passed' && report.isolatedInstallation === true
      && report.storage === 'postgresql',
    'Packaged connection acceptance must pass with PostgreSQL on Node 22.6+ and Node 24 separately.');
    requireCondition(report.package?.name === manifest.name && report.package?.version === manifest.version
      && report.package?.integrity === integrity && report.package?.fileCount === files.length,
    'A PostgreSQL connection report tested a different archive. Rerun packaged connection acceptance.');
    const exampleHashes = report.example?.files;
    requireCondition(exampleHashes && Object.keys(exampleHashes).length > 0,
      'The connection acceptance report must record its reference source files.');
    for (const [name, hash] of Object.entries(exampleHashes)) {
      requireCondition(/^[A-Za-z0-9_-]+\.mjs$/.test(name) && /^[a-f0-9]{64}$/.test(hash)
        && hash === digest(await readLocal(path.join(root, 'examples/workos-reference', name)), 'sha256'),
      'Connection reference source changed after acceptance. Rerun packaged connection acceptance.');
    }
  }
  console.log(`Release readiness passed for ${manifest.name}@${manifest.version}: archive, current files, two SDK consumers and two packaged PostgreSQL connection runtimes match.`);
  console.log('Local check only; registry publishing remains disabled. Build before packing: source-to-dist compilation freshness is not recorded by these receipts.');
}

try {
  await main();
} catch (error) {
  console.error(error instanceof ReadinessError ? error.message
    : 'Unable to read or parse local release artifacts. Build, pack and verify SDK and PostgreSQL connection consumers on Node 22.6+ and Node 24 before retrying.');
  process.exitCode = 1;
}
