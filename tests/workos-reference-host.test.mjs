import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { chmod, lstat, mkdtemp, readFile, rm, symlink } from 'node:fs/promises';
import { createServer, request as httpRequest } from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import express from 'express';
import { createReferenceHost } from '../examples/workos-reference/host.mjs';
import { createWorkOSReferenceStore } from '../examples/workos-reference/store.mjs';
import { accountVersion, readHostConfig, validateHostConfig, validateTestApiKey,
  verifyPassword } from '../examples/workos-reference/host-config.mjs';
import { createFixtureConfiguration, parseSetupArguments, runSetup,
  writeFixtureConfiguration } from '../examples/workos-reference/setup.mjs';

const PUBLIC_URL = 'https://reference.example';
const TEST_KEY = `sk_test_${'synthetic'.repeat(5)}`;
const settings = configPath => ({ configPath, publicUrl: PUBLIC_URL,
  issuer: 'https://issuer.example', clientId: 'client_reference123456',
  applicationId: 'connect_app_reference123456', aliceUserId: 'user_alice12345678',
  bobUserId: 'user_bob1234567890', accessTokenType: 'JWT' });

async function fixture(t, customize = value => value, { realReference = false } = {}) {
  const directory = await mkdtemp(path.join(tmpdir(), 'gateivo-reference-host-'));
  await chmod(directory, 0o700);
  t.after(() => rm(directory, { recursive: true, force: true }));
  const generated = await createFixtureConfiguration(settings(path.join(directory, 'config.json')));
  let current = customize(structuredClone(generated.config));
  let unavailable = false;
  let hooks;
  let providerRequests = 0;
  const observedTargets = [];
  const realStore = realReference ? createWorkOSReferenceStore({ path: current.databasePath }) : null;
  const store = realStore ? Object.freeze({ ...realStore,
    getState(input, context) { observedTargets.push(structuredClone(input)); return realStore.getState(input, context); },
  }) : Object.freeze({});
  const host = await createReferenceHost({ config: current, apiKey: TEST_KEY }, {
    store,
    loadConfig: async () => { if (unavailable) throw new Error('PRIVATE_CONFIG_FAILURE'); return current; },
    provider: { fetch: async () => { providerRequests++; throw new Error('Unexpected provider request in host smoke test.'); } },
    referenceFactory: realReference ? undefined : function (options) {
      hooks = options;
      const router = express.Router();
      router.get('/account/assistant', async (request, response) => {
        const session = await options.authenticateSession(request, { signal: AbortSignal.timeout(1000) });
        if (!session) { response.status(401).json({ error: 'UNAUTHORIZED' }); return; }
        response.json({ subject: session.appSubject, label: session.accountLabel });
      });
      return Object.freeze({ router, isAuthorized: async () => true });
    },
  });
  const server = createServer(host.app);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    await new Promise(resolve => server.close(resolve)); await host.close(); await realStore?.close();
  });
  const request = (method, route, { headers = {}, body = '' } = {}) => new Promise((resolve, reject) => {
    const payload = typeof body === 'string' ? body : new URLSearchParams(body).toString();
    const req = httpRequest({ host: '127.0.0.1', port: server.address().port, method, path: route,
      headers: { host: new URL(PUBLIC_URL).host, 'x-forwarded-proto': 'https',
        ...(payload ? { 'content-type': 'application/x-www-form-urlencoded', 'content-length': Buffer.byteLength(payload) } : {}),
        ...headers } }, response => {
      let text = '';
      response.setEncoding('utf8'); response.on('data', chunk => { text += chunk; });
      response.on('end', () => resolve({ status: response.statusCode, headers: response.headers, text }));
    });
    req.once('error', reject); req.end(payload);
  });
  const form = async () => {
    const response = await request('GET', '/sign-in');
    assert.equal(response.status, 200);
    return { csrf: /name="csrf" value="([^"]+)"/.exec(response.text)[1],
      cookie: response.headers['set-cookie'][0].split(';')[0] };
  };
  const login = async (which = 0, extra = {}) => {
    const bootstrap = await form();
    return request('POST', '/sign-in', { headers: { origin: PUBLIC_URL, cookie: bootstrap.cookie },
      body: { ...generated.credentials[which], csrf: bootstrap.csrf, ...extra } });
  };
  const sessionCookie = response => response.headers['set-cookie'].find(value =>
    value.startsWith('__Host-gateivo-reference-app=')).split(';')[0];
  return { directory, generated, host, request, form, login, sessionCookie, get hooks() { return hooks; },
    observedTargets, get providerRequests() { return providerRequests; },
    get config() { return current; }, setConfig(value) { current = value; },
    setUnavailable() { unavailable = true; } };
}

test('fixture setup writes private hashed accounts without overwriting an existing configuration', async t => {
  const directory = await mkdtemp(path.join(tmpdir(), 'gateivo-reference-config-'));
  await chmod(directory, 0o700); t.after(() => rm(directory, { recursive: true, force: true }));
  const configPath = path.join(directory, 'config.json');
  const generated = await createFixtureConfiguration(settings(configPath));
  await writeFixtureConfiguration(configPath, generated.config);
  assert.equal((await lstat(configPath)).mode & 0o777, 0o600);
  const text = await readFile(configPath, 'utf8');
  for (const account of generated.credentials) assert.ok(!text.includes(account.password));
  const stored = await readHostConfig(configPath);
  assert.equal(stored.accounts[0].id, 'alice');
  assert.equal(await verifyPassword(generated.credentials[0].password, stored.accounts[0].password), true);
  assert.equal(await verifyPassword(generated.credentials[1].password, stored.accounts[0].password), false);
  await assert.rejects(writeFixtureConfiguration(configPath, generated.config));
  assert.equal(await readFile(configPath, 'utf8'), text);
});

test('configuration reading refuses public files, symlinks and permissive data directories', async t => {
  const directory = await mkdtemp(path.join(tmpdir(), 'gateivo-reference-config-'));
  await chmod(directory, 0o700); t.after(() => rm(directory, { recursive: true, force: true }));
  const configPath = path.join(directory, 'config.json');
  const { config } = await createFixtureConfiguration(settings(configPath));
  await writeFixtureConfiguration(configPath, config);
  await chmod(configPath, 0o644);
  await assert.rejects(readHostConfig(configPath), /could not be verified/);
  await chmod(configPath, 0o600);
  await symlink(configPath, path.join(directory, 'link.json'));
  await assert.rejects(readHostConfig(path.join(directory, 'link.json')), /could not be verified/);
  await chmod(directory, 0o755);
  await assert.rejects(readHostConfig(configPath), /could not be verified/);
});

test('host configuration requires exact HTTPS origins, unique prelinked users and development credentials', async t => {
  const f = await fixture(t);
  for (const edit of [
    value => { value.publicUrl = 'http://reference.example'; },
    value => { value.publicUrl += '/other'; },
    value => { value.issuer += '?client=other'; },
    value => { value.accounts[1].providerSubject = value.accounts[0].providerSubject; },
    value => { value.accounts[0].email = 'real-user@example.com'; },
    value => { value.accessTokenType = undefined; },
    value => { value.extraOwnerId = 'bob'; },
  ]) {
    const changed = structuredClone(f.config); edit(changed);
    assert.throws(() => validateHostConfig(changed), /configuration is invalid/);
  }
  assert.throws(() => validateTestApiKey(`sk_live_${'synthetic'.repeat(5)}`), /development API key/);
  assert.equal(validateTestApiKey(TEST_KEY), TEST_KEY);
});

test('a successful login creates a secure opaque session bound to the canonical account', async t => {
  const f = await fixture(t);
  const result = await f.login();
  assert.equal(result.status, 303);
  assert.equal(result.headers.location, '/account/assistant');
  const rawCookie = result.headers['set-cookie'].find(value => value.startsWith('__Host-gateivo-reference-app='));
  for (const expected of ['Secure', 'HttpOnly', 'SameSite=Lax', 'Path=/']) assert.ok(rawCookie.includes(expected));
  assert.ok(!rawCookie.includes('alice'));
  const session = f.sessionCookie(result);
  const page = await f.request('GET', '/account/assistant?ownerId=bob', { headers: { cookie: session } });
  assert.equal(page.status, 200);
  assert.equal(JSON.parse(page.text).subject, 'alice');
  const authority = await f.hooks.resolveAccount({ issuer: f.config.issuer, appSubject: 'alice' },
    { signal: AbortSignal.timeout(1000) });
  assert.equal(authority.providerSubject, f.config.accounts[0].providerSubject);
  assert.equal(await f.hooks.resolveAccount({ issuer: 'https://attacker.example', appSubject: 'alice' }), null);
});

test('the runnable host composes with the real reference and SQLite using the current canonical mapping', async t => {
  const f = await fixture(t, value => value, { realReference: true });
  const anonymous = await f.request('GET', '/account/assistant');
  assert.equal(anonymous.status, 303);
  assert.equal(anonymous.headers.location, '/sign-in');
  const aliceLogin = await f.login();
  const aliceCookie = f.sessionCookie(aliceLogin);
  const alicePage = await f.request('GET', '/account/assistant', { headers: { cookie: aliceCookie } });
  assert.equal(alicePage.status, 200);
  assert.ok(alicePage.text.includes('Alice — fictional workout account'));
  assert.ok(alicePage.text.includes(`action="${PUBLIC_URL}/account/assistant/start"`));
  assert.ok(alicePage.text.includes('workouts:read'));
  assert.equal(f.observedTargets.at(-1).appSubject, 'alice');
  assert.equal(f.observedTargets.at(-1).providerSubject, f.config.accounts[0].providerSubject);
  assert.equal(f.observedTargets.at(-1).resource, `${PUBLIC_URL}/agent/mcp`);

  const bobLogin = await f.login(1);
  const bobCookie = f.sessionCookie(bobLogin);
  const bobPage = await f.request('GET', '/account/assistant', { headers: { cookie: bobCookie } });
  assert.equal(bobPage.status, 200);
  assert.ok(bobPage.text.includes('Bob — fictional workout account'));
  assert.equal(f.observedTargets.at(-1).appSubject, 'bob');
  assert.equal(f.observedTargets.at(-1).providerSubject, f.config.accounts[1].providerSubject);

  const disabled = structuredClone(f.config); disabled.accounts[0].enabled = false; f.setConfig(disabled);
  const denied = await f.request('GET', '/account/assistant', { headers: { cookie: aliceCookie } });
  assert.equal(denied.status, 303);
  assert.equal(denied.headers.location, '/sign-in');
  assert.equal((await f.request('GET', '/account/assistant', { headers: { cookie: bobCookie } })).status, 200);
  assert.equal(f.providerRequests, 0);
});

test('login rejects forged CSRF, cross-origin posts, injected account fields and oversized bodies', async t => {
  const f = await fixture(t);
  const bootstrap = await f.form();
  const payload = { ...f.generated.credentials[0], csrf: bootstrap.csrf };
  assert.equal((await f.request('POST', '/sign-in', { headers: { origin: PUBLIC_URL }, body: payload })).status, 403);
  assert.equal((await f.request('POST', '/sign-in', { headers: { origin: 'https://attacker.example',
    cookie: bootstrap.cookie }, body: payload })).status, 403);
  assert.equal((await f.request('POST', '/sign-in', { headers: { origin: PUBLIC_URL, cookie: bootstrap.cookie },
    body: { ...payload, ownerId: 'bob' } })).status, 403);
  assert.equal((await f.request('POST', '/sign-in', { headers: { origin: PUBLIC_URL, cookie: bootstrap.cookie },
    body: { ...payload, password: 'x'.repeat(5000) } })).status, 400);
  assert.equal((await f.request('POST', '/sign-in', { headers: { origin: PUBLIC_URL, cookie: bootstrap.cookie },
    body: `${new URLSearchParams(payload)}&email=bob%40gateivo.example` })).status, 403);
});

test('the app rejects wrong hosts, untrusted HTTPS markers and redirect parameters', async t => {
  const f = await fixture(t);
  assert.equal((await f.request('GET', '/sign-in', { headers: { host: 'attacker.example' } })).status, 403);
  assert.equal((await f.request('GET', '/sign-in', { headers: { 'x-forwarded-proto': 'http' } })).status, 403);
  assert.equal((await f.request('GET', '/sign-in', { headers: { 'x-forwarded-proto': 'https,http' } })).status, 403);
  const redirected = await f.request('GET', '/sign-in?returnTo=https://attacker.example');
  assert.equal(redirected.status, 403);
  assert.equal(redirected.headers.location, undefined);
  const normalNavigation = await f.request('GET', '/sign-in', { headers: {
    'sec-fetch-site': 'cross-site', 'sec-fetch-mode': 'navigate', 'sec-fetch-dest': 'document' } });
  assert.equal(normalNavigation.status, 200);
});

test('disabled or changed accounts invalidate browser sessions and the current provider mapping', async t => {
  const f = await fixture(t);
  const result = await f.login();
  const cookie = f.sessionCookie(result);
  const before = await f.hooks.authenticateSession({ headers: { cookie } });
  assert.equal(before.appSubject, 'alice');
  const changed = structuredClone(f.config);
  changed.accounts[0].enabled = false; f.setConfig(changed);
  assert.equal(await f.hooks.authenticateSession({ headers: { cookie } }), null);
  assert.equal(await f.hooks.resolveAccount({ issuer: changed.issuer, appSubject: 'alice' }), null);
  changed.accounts[0].enabled = true; f.setConfig(changed);
  assert.equal(await f.hooks.authenticateSession({ headers: { cookie } }), null);
  const relogin = await f.login();
  assert.equal(relogin.status, 303);
  const fresh = f.sessionCookie(relogin);
  changed.accounts[0].password.digest = randomBytes(64).toString('base64url'); f.setConfig(changed);
  assert.equal(await f.hooks.authenticateSession({ headers: { cookie: fresh } }), null);
});

test('sign-out is CSRF protected and reconnecting a browser login never restores its old session', async t => {
  const f = await fixture(t);
  const result = await f.login();
  const cookie = f.sessionCookie(result);
  const before = await f.hooks.authenticateSession({ headers: { cookie } });
  const home = await f.request('GET', '/', { headers: { cookie } });
  const csrf = /name="csrf" value="([^"]+)"/.exec(home.text)[1];
  assert.equal((await f.request('POST', '/sign-out', { headers: { origin: PUBLIC_URL, cookie },
    body: { csrf: 'forged' } })).status, 403);
  const loggedOut = await f.request('POST', '/sign-out', { headers: { origin: PUBLIC_URL, cookie }, body: { csrf } });
  assert.equal(loggedOut.status, 303);
  assert.equal(loggedOut.headers.location, '/sign-in');
  assert.equal(await f.hooks.authenticateSession({ headers: { cookie } }), null);
  const newLogin = await f.login();
  const after = await f.hooks.authenticateSession({ headers: { cookie: f.sessionCookie(newLogin) } });
  assert.notEqual(before.sessionId, after.sessionId);
  assert.equal(await f.hooks.authenticateSession({ headers: { cookie } }), null);
});

test('configuration failure or unexpected server-setting changes deny authority without leaking details', async t => {
  const f = await fixture(t);
  const result = await f.login();
  const cookie = f.sessionCookie(result);
  const changed = structuredClone(f.config); changed.secret = randomBytes(32).toString('base64url'); f.setConfig(changed);
  assert.equal(await f.hooks.authenticateSession({ headers: { cookie } }), null);
  assert.equal(await f.hooks.resolveAccount({ issuer: changed.issuer, appSubject: 'alice' }), null);
  f.setUnavailable();
  const response = await f.request('GET', '/', { headers: { cookie } });
  assert.equal(response.status, 303);
  assert.ok(!response.text.includes('PRIVATE_CONFIG_FAILURE'));
});

test('the login throttle bounds repeated password work while preserving generic errors', async t => {
  const f = await fixture(t);
  for (let index = 0; index < 12; index++) {
    const response = await f.login(0, { password: 'incorrect-fictional-password' });
    assert.equal(response.status, 401);
    assert.ok(!response.text.includes(f.generated.credentials[0].password));
  }
  assert.equal((await f.login()).status, 429);
});

test('direct TLS mode never falls back to trusting an HTTP forwarding header', async t => {
  const f = await fixture(t, config => ({ ...config, transport: 'tls' }));
  assert.equal((await f.request('GET', '/sign-in')).status, 403);
});

test('setup requires explicit token profile and help never creates files or prints credentials', async () => {
  const output = [];
  await runSetup(['--help'], { log: value => output.push(value) });
  assert.ok(output[0].includes('--token-type'));
  assert.ok(!output[0].includes('sk_test_'));
  assert.throws(() => parseSetupArguments(['--config', '/tmp/config.json']), /arguments are incomplete/);
  assert.throws(() => parseSetupArguments(['--help', 'ignored']), /arguments are incomplete/);
  assert.equal(typeof accountVersion, 'function');
});
