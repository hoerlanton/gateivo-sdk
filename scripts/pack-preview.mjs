import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execute = promisify(execFile);
const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const artifacts = path.join(root, 'artifacts');
const manifest = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
assert.equal(manifest.name, '@gateivo/sdk');
assert.equal(manifest.private, true, 'This command creates an archive, never a registry publication.');
assert.match(manifest.version, /^\d+\.\d+\.\d+-preview\.\d+$/);
await mkdir(artifacts, { recursive: true });

const args = ['pack', '--json', '--ignore-scripts', '--pack-destination', artifacts];
const packed = await execute(
  process.env.npm_execpath ? process.execPath : 'npm',
  process.env.npm_execpath ? [process.env.npm_execpath, ...args] : args,
  { cwd: root, timeout: 60_000, maxBuffer: 1024 * 1024 },
);
const [archive] = JSON.parse(packed.stdout);
assert.equal(archive.filename, `gateivo-sdk-${manifest.version}.tgz`);
const permitted = (name) => name === 'package.json' || name === 'README.md' || name === 'LICENSE'
  || name === 'docs/authentication.md' || name === 'SECURITY.md'
  || name.startsWith('dist/');
for (const file of archive.files) assert.ok(permitted(file.path), `Unexpected package file: ${file.path}`);
const bytes = await readFile(path.join(artifacts, archive.filename));
const integrity = `sha512-${createHash('sha512').update(bytes).digest('base64')}`;
assert.equal(archive.integrity, integrity);
const receipt = {
  name: manifest.name,
  version: manifest.version,
  filename: archive.filename,
  integrity,
  sha256: createHash('sha256').update(bytes).digest('hex'),
  files: archive.files.map(({ path: name }) => name),
};
await writeFile(path.join(artifacts, 'package-manifest.json'), `${JSON.stringify(receipt, null, 2)}\n`);
console.log(JSON.stringify(receipt));
