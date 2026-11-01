#!/usr/bin/env node
import { randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { mkdir, open } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { hashPassword, requirePrivateDirectory, validateHostConfig } from './host-config.mjs';

const usage = `Create a private fictional WorkOS reference fixture (Node.js 24).

node examples/workos-reference/setup.mjs \\
  --config /absolute/private/reference/config.json \\
  --public-url https://YOUR_REFERENCE_HOST \\
  --issuer https://YOUR_DEVELOPMENT_ENVIRONMENT.authkit.app \\
  --client-id client_YOUR_CLIENT_ID \\
  --application-id connect_app_YOUR_APPLICATION_ID \\
  --alice-user-id user_VERIFIED_ALICE_ID \\
  --bob-user-id user_VERIFIED_BOB_ID \\
  --token-type JWT

Required token profile: JWT, at+jwt, or absent. Inspect the development
provider's signed access-token profile before choosing. Optional:
  --port 5196
  --transport loopback-proxy   (default; TLS terminates at a local proxy)
  --transport tls              (provide certificate/key file paths at startup)

This command creates only two fictional app accounts. It does not create
WorkOS users, verify their email, grant assistant access, or contact WorkOS.
It prints the new fictional passwords once; run it in a private terminal.
The file contains password hashes and a secret, and must stay outside Git.
Existing configuration is never overwritten.`;

export async function createFixtureConfiguration(settings) {
  const credentials = [];
  const accounts = [];
  for (const [id, name, providerSubject] of [
    ['alice', 'Alice', settings.aliceUserId], ['bob', 'Bob', settings.bobUserId],
  ]) {
    const password = randomBytes(24).toString('base64url');
    accounts.push({ id, email: `${id}@gateivo.example`, label: `${name} — fictional workout account`,
      providerSubject, enabled: true, authVersion: randomBytes(24).toString('base64url'),
      password: await hashPassword(password, randomBytes(16)) });
    credentials.push(Object.freeze({ email: `${id}@gateivo.example`, password }));
  }
  const config = validateHostConfig({ version: 1,
    publicUrl: settings.publicUrl, issuer: settings.issuer, clientId: settings.clientId,
    applicationId: settings.applicationId, accessTokenType: settings.accessTokenType,
    transport: settings.transport ?? 'loopback-proxy', port: settings.port ?? 5196,
    secret: randomBytes(32).toString('base64url'),
    databasePath: path.join(path.dirname(settings.configPath), 'connections.sqlite'), accounts,
  }, { configPath: settings.configPath });
  return Object.freeze({ config, credentials: Object.freeze(credentials) });
}

export async function writeFixtureConfiguration(configPath, config) {
  if (typeof configPath !== 'string' || !path.isAbsolute(configPath)) {
    throw new TypeError('An absolute private configuration path is required.');
  }
  validateHostConfig(config, { configPath });
  await mkdir(path.dirname(configPath), { recursive: true, mode: 0o700 });
  await requirePrivateDirectory(path.dirname(configPath));
  let file;
  try {
    file = await open(configPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL
      | constants.O_NOFOLLOW, 0o600);
    await file.writeFile(`${JSON.stringify(config, null, 2)}\n`, 'utf8');
    await file.sync();
  } finally { await file?.close(); }
}

export function parseSetupArguments(args) {
  const accepted = new Set(['config', 'public-url', 'issuer', 'client-id', 'application-id',
    'alice-user-id', 'bob-user-id', 'token-type', 'port', 'transport']);
  const values = new Map();
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index]?.slice(2);
    const value = args[index + 1];
    if (!args[index]?.startsWith('--') || !accepted.has(name) || values.has(name)
      || typeof value !== 'string' || !value || value.startsWith('--')) {
      throw new TypeError('Setup arguments are incomplete or invalid. Use --help.');
    }
    values.set(name, value);
  }
  for (const name of ['config', 'public-url', 'issuer', 'client-id', 'application-id',
    'alice-user-id', 'bob-user-id', 'token-type']) {
    if (!values.has(name)) throw new TypeError('Setup arguments are incomplete or invalid. Use --help.');
  }
  if (!['JWT', 'at+jwt', 'absent'].includes(values.get('token-type'))
    || (values.has('port') && !/^\d{4,5}$/.test(values.get('port')))) {
    throw new TypeError('Setup arguments are incomplete or invalid. Use --help.');
  }
  return { configPath: values.get('config'), publicUrl: values.get('public-url'),
    issuer: values.get('issuer'), clientId: values.get('client-id'), applicationId: values.get('application-id'),
    aliceUserId: values.get('alice-user-id'), bobUserId: values.get('bob-user-id'),
    accessTokenType: values.get('token-type') === 'absent' ? null : values.get('token-type'),
    ...(values.has('port') ? { port: Number(values.get('port')) } : {}),
    ...(values.has('transport') ? { transport: values.get('transport') } : {}) };
}

export async function runSetup(args = process.argv.slice(2), output = console) {
  if (args.length === 1 && args[0] === '--help') { output.log(usage); return; }
  if (Number(process.versions.node.split('.')[0]) !== 24) {
    throw new TypeError('The authenticated reference host requires Node.js 24.');
  }
  const settings = parseSetupArguments(args);
  const { config, credentials } = await createFixtureConfiguration(settings);
  await writeFixtureConfiguration(settings.configPath, config);
  output.log('Private reference configuration created. No provider request was made.');
  output.log('Fictional app passwords (shown once; keep them out of source control and public logs):');
  for (const account of credentials) output.log(`${account.email}: ${account.password}`);
  output.log('Set GATEIVO_REFERENCE_CONFIG to the private configuration path and provide WORKOS_API_KEY at startup.');
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runSetup().catch(() => {
    console.error('Reference setup failed. Check --help, development identifiers and private file permissions.');
    process.exitCode = 1;
  });
}
