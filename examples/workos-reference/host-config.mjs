import { constants } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import path from 'node:path';
import { createHash, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(scryptCallback);
const SCRYPT = Object.freeze({ N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
const accountIds = ['alice', 'bob'];
const USER_ID = /^user_[A-Za-z0-9]{8,64}$/;
const OPAQUE_ID = /^[A-Za-z0-9]{8,64}$/;
const invalid = () => { throw new TypeError('Reference configuration is invalid.'); };
const exactKeys = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const base64 = (value, length) => typeof value === 'string'
  && /^[A-Za-z0-9_-]+$/.test(value) && Buffer.from(value, 'base64url').length === length
  && Buffer.from(value, 'base64url').toString('base64url') === value;

function httpsOrigin(value) {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.origin === value && !url.username && !url.password
      && url.hostname !== '0.0.0.0' && url.hostname !== '[::]';
  } catch { return false; }
}

/** Only operator-controlled configuration creates the account/provider binding. */
export function validateHostConfig(input, { configPath } = {}) {
  if (!exactKeys(input, ['version', 'publicUrl', 'issuer', 'clientId', 'applicationId',
    'accessTokenType', 'transport', 'port', 'secret', 'databasePath', 'accounts'])
    || input.version !== 1 || !httpsOrigin(input.publicUrl) || !httpsOrigin(input.issuer)
    || !new RegExp(`^client_${OPAQUE_ID.source.slice(1, -1)}$`).test(input.clientId)
    || !new RegExp(`^connect_app_${OPAQUE_ID.source.slice(1, -1)}$`).test(input.applicationId)
    || !['JWT', 'at+jwt', null].includes(input.accessTokenType)
    || !['loopback-proxy', 'tls'].includes(input.transport)
    || !Number.isSafeInteger(input.port) || input.port < 1024 || input.port > 65535
    || !base64(input.secret, 32) || typeof input.databasePath !== 'string'
    || !path.isAbsolute(input.databasePath) || !Array.isArray(input.accounts)
    || input.accounts.length !== 2) invalid();
  if (configPath !== undefined && (!path.isAbsolute(configPath)
    || input.databasePath !== path.join(path.dirname(configPath), 'connections.sqlite'))) invalid();
  const accounts = input.accounts.map((account, index) => {
    if (!exactKeys(account, ['id', 'email', 'label', 'providerSubject', 'enabled', 'authVersion', 'password'])
      || account.id !== accountIds[index] || account.email !== `${account.id}@gateivo.example`
      || account.label !== `${index === 0 ? 'Alice' : 'Bob'} — fictional workout account`
      || !USER_ID.test(account.providerSubject) || typeof account.enabled !== 'boolean'
      || !base64(account.authVersion, 24)
      || !exactKeys(account.password, ['algorithm', 'salt', 'digest'])
      || account.password.algorithm !== 'scrypt' || !base64(account.password.salt, 16)
      || !base64(account.password.digest, 64)) invalid();
    return Object.freeze({ ...account, password: Object.freeze({ ...account.password }) });
  });
  if (accounts[0].providerSubject === accounts[1].providerSubject) invalid();
  return Object.freeze({ ...input, accounts: Object.freeze(accounts) });
}

export function validateTestApiKey(value) {
  if (typeof value !== 'string' || !/^sk_test_[A-Za-z0-9_-]{16,256}$/.test(value)) {
    throw new TypeError('A server-only WorkOS development API key is required.');
  }
  return value;
}

export async function requirePrivateDirectory(directory) {
  const stat = await lstat(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0
    || (typeof process.getuid === 'function' && stat.uid !== process.getuid())) {
    throw new TypeError('Reference data must use a private owner-controlled directory.');
  }
}

export async function readPrivateFile(filename, maxBytes = 32 * 1024) {
  if (typeof filename !== 'string' || !path.isAbsolute(filename)) invalid();
  let file;
  try {
    file = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stat = await file.stat();
    if (!stat.isFile() || stat.size < 1 || stat.size > maxBytes || (stat.mode & 0o077) !== 0
      || (typeof process.getuid === 'function' && stat.uid !== process.getuid())) invalid();
    const buffer = Buffer.alloc(maxBytes + 1);
    const { bytesRead } = await file.read(buffer, 0, buffer.length, 0);
    if (bytesRead < 1 || bytesRead > maxBytes) invalid();
    return buffer.subarray(0, bytesRead);
  } finally { await file?.close(); }
}

export async function readHostConfig(configPath) {
  try {
    await requirePrivateDirectory(path.dirname(configPath));
    const input = JSON.parse((await readPrivateFile(configPath)).toString('utf8'));
    return validateHostConfig(input, { configPath });
  } catch {
    throw new TypeError('Private reference configuration could not be verified.');
  }
}

export async function hashPassword(password, salt) {
  if (typeof password !== 'string' || password.length < 16 || password.length > 128
    || !(salt instanceof Uint8Array) || salt.length !== 16) invalid();
  const digest = await scrypt(password, salt, 64, SCRYPT);
  return Object.freeze({ algorithm: 'scrypt', salt: Buffer.from(salt).toString('base64url'),
    digest: Buffer.from(digest).toString('base64url') });
}

export async function verifyPassword(password, saved) {
  if (typeof password !== 'string' || password.length < 1 || password.length > 128) return false;
  const digest = Buffer.from(await scrypt(password, Buffer.from(saved.salt, 'base64url'), 64, SCRYPT));
  return timingSafeEqual(digest, Buffer.from(saved.digest, 'base64url'));
}

export function accountVersion(account) {
  return createHash('sha256').update(JSON.stringify([account.id, account.email, account.enabled,
    account.providerSubject, account.authVersion, account.password])).digest('hex');
}

export function configurationIdentity(config) {
  const { accounts: _accounts, ...settings } = config;
  return createHash('sha256').update(JSON.stringify(Object.fromEntries(
    Object.keys(settings).sort().map(key => [key, settings[key]])))).digest('hex');
}
