#!/usr/bin/env node
/**
 * Install the actual SDK tarball outside this checkout, then exercise the
 * WorkOS reference with synthetic signed responses. Never reads credentials or
 * contacts WorkOS; this is not evidence of a hosted provider/assistant test.
 */
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFile, mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execute = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const sdkDirectory = root;
const exampleDirectory = path.join(root, 'examples/workos-reference');
const postgres = process.argv.includes('--postgres');
const reportPath = path.join(root, postgres ? 'artifacts/workos-postgres-verification.json' : 'artifacts/workos-reference-verification.json');
const checks = [];
const report = { status: 'running', checkedAt: new Date().toISOString(), node: process.version, storage: postgres ? 'postgresql' : 'sqlite', checks };
const childEnv = { ...process.env };
for (const name of Object.keys(childEnv)) {
  if (/^(?:NODE_PATH|NODE_OPTIONS|TS_NODE_PROJECT|TSX_TSCONFIG_PATH|WORKOS_|GATEIVO_|DATABASE_URL)/.test(name)) delete childEnv[name];
}
childEnv.npm_config_audit = 'false';
childEnv.npm_config_fund = 'false';
childEnv.npm_config_ignore_scripts = 'true';
if (postgres) {
  let target;
  try { target = new URL(process.env.GATEIVO_REFERENCE_TEST_DATABASE_URL); }
  catch { throw new Error('PostgreSQL acceptance requires the explicit local GATEIVO_REFERENCE_TEST_DATABASE_URL.'); }
  assert.ok(['postgres:', 'postgresql:'].includes(target.protocol)
    && ['localhost', '127.0.0.1', '[::1]'].includes(target.hostname)
    && target.pathname === '/gateivo_reference_test' && !target.search && !target.hash,
  'PostgreSQL acceptance only permits loopback gateivo_reference_test without URL overrides.');
  childEnv.GATEIVO_REFERENCE_TEST_DATABASE_URL = target.href;
}

function inside(parent, child) {
  const relative = path.relative(parent, child);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

async function run(program, args, cwd, label) {
  try { return await execute(program, args, { cwd, env: childEnv, timeout: 300_000, maxBuffer: 4 * 1024 * 1024 }); }
  catch (error) {
    const code = error && typeof error === 'object' && 'code' in error ? String(error.code) : 'unknown';
    throw new Error(`${label} failed (exit ${code}). No child output was logged.`);
  }
}

async function npm(args, cwd, label) {
  return process.env.npm_execpath ? run(process.execPath, [process.env.npm_execpath, ...args], cwd, label) : run('npm', args, cwd, label);
}

const typesFixture = `import { createWorkOSConnectVerifier, createWorkOSConnectProvider,
  type WorkOSConnectVerifierOptions, type WorkOSConnectProviderOptions,
  type VerifiedWorkOSConnectIdentity } from '@gateivo/sdk/workos-connect';
import { type Principal } from '@gateivo/sdk';
const options: WorkOSConnectVerifierOptions = {
  appId: 'workouts', issuer: 'https://issuer.example', clientId: 'client_reference123456',
  resource: 'https://publisher.example/agent/mcp', accessTokenType: null,
  resolveConsent: async (identity, context) => {
    const captured: VerifiedWorkOSConnectIdentity = identity;
    const scopes: readonly string[] = captured.scopes;
    const consent: string = captured.consentId;
    context.signal.throwIfAborted();
    // @ts-expect-error A verified identity must be read-only.
    captured.subject = 'replacement';
    // @ts-expect-error Scopes cannot be widened by mutating the verified identity.
    scopes.push('admin');
    // @ts-expect-error Access tokens are not exposed to consent resolution.
    captured.accessToken;
    return { subject: 'local-account', authorizationId: consent, scopes: ['workouts:read'], expiresAt: captured.expiresAt };
  },
};
const verify = createWorkOSConnectVerifier(options, { fetch });
const principal: Promise<Principal | null> = verify('token', { audience: options.resource, signal: AbortSignal.timeout(1000) });
const providerOptions: WorkOSConnectProviderOptions = {
  ...options, apiKey: 'synthetic-provider-key', applicationId: 'connect_app_reference123456',
  redirectUri: 'https://publisher.example/account/assistant/callback', requiredScopes: ['workouts:read'],
};
const provider = createWorkOSConnectProvider(providerOptions, { fetch });
provider.authorizationUrl({ state: 'state', codeChallenge: 'challenge' });
provider.resetAuthorization('user_reference123456', { signal: AbortSignal.timeout(1000), beforeDelete: async () => {} });
const identity: Promise<VerifiedWorkOSConnectIdentity> = provider.exchangeCode({ code: 'code', codeVerifier: 'verifier', expectedUserId: 'user_reference123456' }, { signal: AbortSignal.timeout(1000) });
// @ts-expect-error Required scopes belong to the publisher and cannot be omitted.
createWorkOSConnectProvider({ apiKey: 'synthetic-provider-key', issuer: options.issuer, clientId: options.clientId,
 applicationId: 'connect_app_reference123456', resource: options.resource,
 redirectUri: providerOptions.redirectUri, accessTokenType: null });
void principal; void identity;
`;

const runtimeFixture = String.raw`import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { createServer, request as httpRequest } from 'node:http';
import { createRequire } from 'node:module';
import { Readable } from 'node:stream';
import { readFile, realpath, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import express from 'express';
import { z } from 'zod/v4';
import * as sdk from '@gateivo/sdk';
import * as connectEntry from '@gateivo/sdk/workos-connect';
import { createWorkOSReference } from './index.mjs';
import { createWorkOSReferenceStore } from './store.mjs';
import { createWorkOSPostgresStore } from './postgres-store.mjs';

const { createWorkOSConnectVerifier, createWorkOSConnectProvider } = connectEntry;
const directory = await realpath(path.dirname(fileURLToPath(import.meta.url)));
const require = createRequire(import.meta.url);
const evidence = [];
const clients = [];
const servers = [];
const stores = [];
const pools = [];
const postgresUrl = process.env.GATEIVO_REFERENCE_TEST_DATABASE_URL;
const schema = 'gateivo_ref_http_' + randomUUID().replaceAll('-', '');
let admin;
let ownsSchema = false;
let phase = 'package imports';
const pass = (message) => evidence.push(message);
const ISSUER = 'https://reference-staging.authkit.app';
const RESOURCE = 'https://publisher.example.invalid/agent/mcp';
const CLIENT = 'client_reference123456789';
const APPLICATION = 'connect_app_reference123456789';
const ALICE = 'user_referencealice123456';
const BOB = 'user_referencebob12345678';
const API_KEY = 'sk_test_SYNTHETIC_REFERENCE_ACCEPTANCE_ONLY';
const context = () => ({ signal: AbortSignal.timeout(3000) });
const key = await generateKeyPair('RS256', { extractable: true });
const publicJwk = { ...await exportJWK(key.publicKey), kid: 'reference-acceptance-key', alg: 'RS256', use: 'sig' };
async function token(consentId, subject = ALICE, overrides = {}, header = {}) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ iss: ISSUER, aud: RESOURCE, sub: subject, client_id: CLIENT, sid: consentId,
    iat: now - 1, exp: now + 300, jti: randomUUID(), scope: 'openid offline_access workouts:read', ...overrides })
    .setProtectedHeader({ alg: 'RS256', kid: publicJwk.kid, ...header }).sign(key.privateKey);
}

function providerTransport() {
  const calls = [];
  const codes = new Map();
  const authorized = new Set();
  let uncertainDelete = false;
  let listHook;
  const transport = async (raw, init = {}) => {
    const url = new URL(typeof raw === 'string' ? raw : raw instanceof URL ? raw.href : raw.url);
    const headers = new Headers(init.headers);
    assert.equal(init.credentials, 'omit');
    assert.ok(init.signal, 'Provider calls must have a deadline');
    assert.ok(['manual', 'error'].includes(init.redirect));
    calls.push({ origin: url.origin, path: url.pathname, method: init.method ?? 'GET' });
    if (url.origin === ISSUER) {
      assert.equal(headers.has('authorization'), false, 'Provider API key must not reach the OAuth issuer');
      if (url.pathname === '/oauth2/jwks') {
        assert.equal(init.body, undefined, 'Public key requests must not carry credentials');
        return Response.json({ keys: [publicJwk] });
      }
      if (url.pathname === '/oauth2/token' && init.method === 'POST') {
        const body = new URLSearchParams(init.body);
        assert.equal(body.get('grant_type'), 'authorization_code');
        assert.equal(body.get('client_id'), CLIENT);
        assert.equal(body.get('resource'), RESOURCE);
        assert.equal(body.get('redirect_uri'), 'https://publisher.example.invalid/account/assistant/callback');
        assert.equal(body.has('client_secret'), false);
        assert.ok(!String(init.body).includes(API_KEY));
        const entry = codes.get(body.get('code'));
        if (!entry || entry.challenge !== createHash('sha256').update(body.get('code_verifier') ?? '').digest('base64url')) {
          return Response.json({ error: 'invalid_grant' }, { status: 400 });
        }
        codes.delete(body.get('code'));
        authorized.add(entry.subject);
        return Response.json({ access_token: entry.token, token_type: 'bearer',
          refresh_token: 'SYNTHETIC_REFRESH_TOKEN_MUST_NOT_PERSIST', id_token: 'SYNTHETIC_ID_TOKEN_MUST_NOT_PERSIST' });
      }
    }
    if (url.origin === 'https://api.workos.com') {
      assert.equal(headers.get('authorization'), 'Bearer ' + API_KEY);
      assert.equal(init.body, undefined, 'Management requests must not carry user tokens');
      if (url.pathname === '/connect/applications/' + CLIENT) return Response.json({ id: APPLICATION, client_id: CLIENT });
      const match = url.pathname.match(/^\/user_management\/users\/(user_[A-Za-z0-9]+)\/authorized_applications(?:\/(connect_app_[A-Za-z0-9]+))?$/);
      if (match && !match[2] && init.method === 'GET') {
        assert.equal(url.searchParams.get('limit'), '100');
        await listHook?.(match[1]);
        return Response.json({ data: authorized.has(match[1]) ? [{ id: 'authorized_' + match[1],
          application: { id: APPLICATION, client_id: CLIENT } }] : [], list_metadata: { before: null, after: null } });
      }
      if (match && match[2] === APPLICATION && init.method === 'DELETE') {
        if (uncertainDelete) return new Response(null, { status: 202 });
        authorized.delete(match[1]);
        return new Response(null, { status: 204 });
      }
    }
    throw new Error('Unexpected provider destination in synthetic transport');
  };
  return { transport, calls, authorized, setUncertain: (value) => { uncertainDelete = value; },
    setListHook: (hook) => { listHook = hook; },
    issue: async ({ consentId, subject = ALICE, challenge, overrides = {} }) => {
      const code = 'synthetic_' + randomUUID();
      const accessToken = await token(consentId, subject, overrides);
      codes.set(code, { token: accessToken, challenge, subject });
      return { code, token: accessToken };
    } };
}

try {
  const installed = await realpath(require.resolve('@gateivo/sdk/workos-connect'));
  assert.ok(installed.startsWith(path.join(directory, 'node_modules/@gateivo/sdk/') ));
  assert.deepEqual(Object.keys(connectEntry).sort(), ['createWorkOSConnectProvider', 'createWorkOSConnectVerifier']);
  assert.equal(sdk.createWorkOSConnectVerifier, undefined, 'Generic root must remain provider-neutral');
  const common = require('@gateivo/sdk/workos-connect');
  assert.deepEqual(Object.keys(common).sort(), Object.keys(connectEntry).sort());
  for (const [factory, AccessError] of [[createWorkOSConnectProvider, sdk.AccessError], [common.createWorkOSConnectProvider, require('@gateivo/sdk').AccessError]]) {
    const adapter = factory({ apiKey: API_KEY, issuer: ISSUER, clientId: CLIENT, applicationId: APPLICATION,
      resource: RESOURCE, redirectUri: 'https://publisher.example.invalid/account/assistant/callback',
      accessTokenType: null, requiredScopes: ['workouts:read'] });
    assert.throws(() => adapter.authorizationUrl({ state: 'bad', codeChallenge: 'bad' }), AccessError);
  }
  pass('Opt-in WorkOS ESM/CommonJS subpath resolves only from installed tarball and preserves shared AccessError identity');
  phase = 'synthetic provider exchange';
  const fake = providerTransport();
  const provider = createWorkOSConnectProvider({ apiKey: API_KEY, issuer: ISSUER, clientId: CLIENT, applicationId: APPLICATION,
    resource: RESOURCE, redirectUri: 'https://publisher.example.invalid/account/assistant/callback',
    accessTokenType: null, requiredScopes: ['workouts:read'] }, { fetch: fake.transport });
  const verifier = 'v'.repeat(43);
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const consentId = 'app_consent_referenceinitial123';
  const issued = await fake.issue({ consentId, challenge });
  const authUrl = new URL(provider.authorizationUrl({ state: 's'.repeat(43), codeChallenge: challenge }));
  assert.equal(authUrl.origin, ISSUER);
  assert.equal(authUrl.searchParams.get('resource'), RESOURCE);
  assert.equal(authUrl.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(authUrl.searchParams.get('scope'), 'openid offline_access workouts:read');
  const identity = await provider.exchangeCode({ code: issued.code, codeVerifier: verifier, expectedUserId: ALICE }, context());
  assert.equal(identity.consentId, consentId);
  assert.equal(identity.subject, ALICE);
  assert.ok(Object.isFrozen(identity));
  assert.doesNotMatch(JSON.stringify(identity), /SYNTHETIC_|access_token|refresh_token|id_token/);
  await assert.rejects(provider.exchangeCode({ code: issued.code, codeVerifier: verifier, expectedUserId: ALICE }, context()), (error) => error instanceof sdk.AccessError && error.code === 'UNAUTHENTICATED');
  const substituted = await fake.issue({ consentId: 'app_consent_substitute123456', subject: BOB, challenge });
  await assert.rejects(provider.exchangeCode({ code: substituted.code, codeVerifier: verifier, expectedUserId: ALICE }, context()), (error) => error instanceof sdk.AccessError && error.code === 'UNAUTHENTICATED');
  pass('Installed provider performs PKCE code exchange, validates signed identity, rejects code replay/account substitution and returns no bearer tokens');
  let claimed = false;
  await provider.resetAuthorization(ALICE, { ...context(), beforeDelete: async () => { claimed = true; } });
  assert.equal(claimed, true);
  assert.equal(fake.authorized.has(ALICE), false);
  assert.equal(fake.calls.filter((call) => call.method === 'DELETE').length, 1);
  pass('Installed provider confines management credentials to WorkOS API and claims before one scoped reset with confirmed absence');

  phase = 'reference HTTP startup';
  const PUBLIC = 'https://publisher.example.invalid';
  const sessions = {
    alice: { sessionId: 'a'.repeat(64), authVersion: randomUUID(), appSubject: 'local-alice', accountLabel: 'Alice', expiresAt: Date.now() + 60 * 60_000 },
    bob: { sessionId: 'b'.repeat(64), authVersion: randomUUID(), appSubject: 'local-bob', accountLabel: 'Bob', expiresAt: Date.now() + 60 * 60_000 },
  };
  const mappings = new Map([
    ['local-alice', { providerSubject: ALICE, enabled: true }],
    ['local-bob', { providerSubject: BOB, enabled: true }],
  ]);
  const rows = [
    { id: 'alice-1', owner: 'local-alice', title: 'Alice ride', privateNote: 'PRIVATE_REFERENCE_ALICE' },
    { id: 'bob-1', owner: 'local-bob', title: 'Bob run', privateNote: 'PRIVATE_REFERENCE_BOB' },
  ];
  const readAction = sdk.defineAction({
    name: 'workouts_get', title: 'Read my workout', description: 'Read one owned workout.', requiredScopes: ['workouts:read'],
    inputSchema: z.strictObject({ workoutId: z.string() }),
    outputSchema: z.strictObject({ id: z.string(), title: z.string() }),
    execute: async ({ workoutId }, { principal }) => {
      const row = rows.find((value) => value.id === workoutId && value.owner === principal.subject);
      if (!row) throw new sdk.AccessError('NOT_FOUND');
      return { id: row.id, title: row.title };
    },
  });
  const dbPath = path.join(directory, 'acceptance-private.sqlite');
  const providerFake = providerTransport();
  let store;
  let reference;
  const server = createServer(); servers.push(server);
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const address = server.address(); assert.ok(address && typeof address === 'object');
  const LOCAL = 'http://127.0.0.1:' + address.port;
  // Deliberately model the HTTPS reverse proxy over a loopback HTTP socket.
  // Native fetch normalizes Host; node:http preserves the pinned public Host.
  async function localFetch(input, init = {}) {
    const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
    assert.equal(url.origin, LOCAL, 'Acceptance HTTP transport must stay on loopback');
    const headers = new Headers(init.headers ?? (input instanceof Request ? input.headers : undefined));
    const method = init.method ?? (input instanceof Request ? input.method : 'GET');
    const body = init.body ?? (input instanceof Request && !['GET', 'HEAD'].includes(method) ? Buffer.from(await input.arrayBuffer()) : undefined);
    return new Promise((resolve, reject) => {
      const request = httpRequest(url, { method, headers: Object.fromEntries(headers), signal: init.signal }, (response) => {
        const responseHeaders = new Headers();
        for (let i = 0; i < response.rawHeaders.length; i += 2) responseHeaders.append(response.rawHeaders[i], response.rawHeaders[i + 1]);
        const status = response.statusCode ?? 500;
        resolve(new Response([204, 205, 304].includes(status) ? null : Readable.toWeb(response), { status, headers: responseHeaders }));
      });
      request.once('error', reject);
      request.end(body instanceof URLSearchParams ? body.toString() : body);
    });
  }
  const secret = new Uint8Array(32).fill(73);
  let Pool;
  const poolOptions = postgresUrl ? { connectionString: postgresUrl,
    port: Number(new URL(postgresUrl).port || 5432), max: 5,
    connectionTimeoutMillis: 3000, idleTimeoutMillis: 1000 } : undefined;
  if (postgresUrl) {
    Pool = (await import('pg')).default.Pool;
    admin = new Pool(poolOptions);
    admin.on('error', () => {});
    const actual = (await admin.query('SELECT current_database() AS database, host(inet_server_addr()) AS address')).rows[0];
    assert.equal(actual.database, 'gateivo_reference_test');
    assert.ok(['127.0.0.1', '::1'].includes(actual.address));
    assert.equal((await admin.query('SELECT to_regnamespace($1) AS namespace', [schema])).rows[0].namespace, null);
    ownsSchema = true;
  }
  async function startReference() {
    if (postgresUrl) {
      const pool = new Pool(poolOptions); pools.push(pool);
      pool.on('error', () => {});
      store = createWorkOSPostgresStore({ pool, schema });
      if (stores.length === 0) await store.migrate();
      await store.checkReady();
    } else store = createWorkOSReferenceStore({ path: dbPath });
    stores.push(store);
    reference = createWorkOSReference({
      appId: 'workouts', publicUrl: PUBLIC, issuer: ISSUER, clientId: CLIENT, applicationId: APPLICATION,
      apiKey: API_KEY, accessTokenType: null, requiredScopes: ['workouts:read'], secret, store,
      authenticateSession: async (request) => sessions[request.headers['x-reference-user']] ?? null,
      resolveAccount: async ({ issuer, appSubject }) => {
        assert.equal(issuer, ISSUER);
        return mappings.get(appSubject) ?? null;
      }, actions: [readAction], trustProxyHttps: true,
    }, { fetch: providerFake.transport });
    const app = express(); app.use(reference.router);
    server.removeAllListeners('request'); server.on('request', app);
  }
  await startReference();
  const jar = new Map();
  function updateCookie(response) {
    for (const header of response.headers.getSetCookie()) {
      const pair = header.split(';')[0];
      const at = pair.indexOf('=');
      if (at > 0) { if (pair.slice(at + 1)) jar.set(pair.slice(0, at), pair.slice(at + 1)); else jar.delete(pair.slice(0, at)); }
    }
  }
  const cookies = () => [...jar].map(([name, value]) => name + '=' + value).join('; ');
  async function browser(route, { user = 'alice', method = 'GET', fields, origin = PUBLIC, cookie = cookies(), update = true } = {}) {
    const response = await localFetch(LOCAL + route, { method, redirect: 'manual', headers: {
      host: 'publisher.example.invalid', 'x-forwarded-proto': 'https',
      ...(user ? { 'x-reference-user': user } : {}), ...(cookie ? { cookie } : {}),
      ...(method === 'POST' ? { origin, 'content-type': 'application/x-www-form-urlencoded' } : {}),
    }, ...(fields ? { body: new URLSearchParams(fields) } : {}) });
    if (update) updateCookie(response);
    return response;
  }
  const decode = (value) => value.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>');
  function form(html, route) {
    const forms = [...html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)];
    for (const entry of forms) {
      const action = entry[1].match(/\baction="([^"]*)"/i)?.[1];
      if (!action || new URL(decode(action), PUBLIC).pathname !== route) continue;
      const fields = {};
      for (const input of entry[2].matchAll(/<input\b([^>]*)>/gi)) {
        const name = input[1].match(/\bname="([^"]*)"/i)?.[1];
        const value = input[1].match(/\bvalue="([^"]*)"/i)?.[1];
        if (name && value !== undefined) fields[decode(name)] = decode(value);
      }
      assert.ok(fields.csrf && fields.revision && fields.approvedExpiresAt, 'Consent form includes complete session-bound fields');
      return fields;
    }
    throw new Error('Expected connection form missing');
  }
  async function currentForm(route, user = 'alice') {
    const page = await browser('/account/assistant', { user });
    assert.equal(page.status, 200);
    assert.equal(page.headers.get('cache-control'), 'no-store');
    return form(await page.text(), route);
  }
  async function begin(user = 'alice') {
    const fields = await currentForm('/account/assistant/start', user);
    const response = await browser('/account/assistant/start', { method: 'POST', fields, user });
    assert.ok([302, 303].includes(response.status), 'Consent start redirects to provider');
    const url = new URL(response.headers.get('location'));
    assert.equal(url.origin, ISSUER);
    assert.equal(url.pathname, '/oauth2/authorize');
    assert.equal(url.searchParams.get('resource'), RESOURCE);
    assert.equal(url.searchParams.get('redirect_uri'), PUBLIC + '/account/assistant/callback');
    assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
    assert.ok(url.searchParams.get('state'));
    assert.ok(cookies(), 'Consent start creates a browser-bound envelope');
    assert.ok(response.headers.getSetCookie().some((value) => /;\s*Secure/i.test(value)
      && /;\s*HttpOnly/i.test(value) && /;\s*SameSite=Lax/i.test(value) && /;\s*Path=\//i.test(value)));
    await response.body?.cancel();
    return { url, cookie: cookies(), fields };
  }
  async function finish(attempt, consentId, user = 'alice') {
    const issued = await providerFake.issue({ consentId, subject: user === 'alice' ? ALICE : BOB,
      challenge: attempt.url.searchParams.get('code_challenge') });
    const route = '/account/assistant/callback?' + new URLSearchParams({ code: issued.code, state: attempt.url.searchParams.get('state') });
    const response = await browser(route, { user, cookie: attempt.cookie });
    assert.ok([302, 303].includes(response.status), 'Verified callback redirects to connection page');
    await response.body?.cancel();
    return { ...issued, route, cookie: attempt.cookie };
  }
  const raw = async (bearer, method = 'tools/list', params = {}) => localFetch(LOCAL + '/agent/mcp', {
    method: 'POST', redirect: 'error', headers: { host: 'publisher.example.invalid', 'x-forwarded-proto': 'https',
      'content-type': 'application/json', accept: 'application/json, text/event-stream',
      ...(bearer ? { authorization: 'Bearer ' + bearer } : {}) },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  async function denied(bearer) {
    const response = await raw(bearer);
    assert.equal(response.status, 401);
    assert.deepEqual(await response.json(), { error: { code: 'UNAUTHENTICATED' } });
  }
  async function mcpClient(bearer) {
    const client = new Client({ name: 'gateivo-workos-reference-acceptance', version: '0.1.0' }); clients.push(client);
    await client.connect(new StreamableHTTPClientTransport(new URL(LOCAL + '/agent/mcp'), {
      fetch: localFetch,
      requestInit: { headers: { authorization: 'Bearer ' + bearer, host: 'publisher.example.invalid', 'x-forwarded-proto': 'https' }, redirect: 'error' },
      redirectPolicy: 'same-origin',
    }));
    return client;
  }

  phase = 'browser session and CSRF gates';
  const anonymous = await browser('/account/assistant', { user: null });
  assert.equal(anonymous.status, 401); await anonymous.body?.cancel();
  const firstForm = await currentForm('/account/assistant/start');
  for (const request of [
    { fields: { ...firstForm, csrf: 'forged-csrf' } },
    { fields: firstForm, origin: 'https://attacker.example.invalid' },
    { fields: firstForm, user: 'bob' },
  ]) {
    const response = await browser('/account/assistant/start', { method: 'POST', ...request });
    assert.ok([400, 403].includes(response.status)); await response.body?.cancel();
  }
  assert.equal(providerFake.calls.length, 0, 'Invalid browser approval must not call provider');
  const unknown = await token('app_consent_unapproved123456');
  await denied(unknown); await denied(undefined);
  pass('Actual browser routes reject missing sessions, forged/cross-account CSRF and wrong-origin approvals; unknown signed consent never creates a grant');

  phase = 'consent cancellation and retry';
  const cancelledAttempt = await begin();
  const cancelledRoute = '/account/assistant/callback?' + new URLSearchParams({ error: 'access_denied', state: cancelledAttempt.url.searchParams.get('state') });
  const cancelled = await browser(cancelledRoute, { cookie: cancelledAttempt.cookie });
  assert.equal(cancelled.status, 403); await cancelled.body?.cancel();
  const cancellationReplay = await browser(cancelledRoute, { cookie: cancelledAttempt.cookie });
  assert.ok([400, 403].includes(cancellationReplay.status)); await cancellationReplay.body?.cancel();
  assert.equal(providerFake.calls.filter((call) => call.path === '/oauth2/token').length, 0);
  await currentForm('/account/assistant/start');
  pass('A verified user cancellation consumes the attempt without code exchange and leaves a safe retry available');

  phase = 'browser PKCE approval and callback replay';
  const attempt = await begin();
  const pendingPage = await browser('/account/assistant');
  assert.equal(pendingPage.status, 200);
  const pendingHtml = await pendingPage.text();
  assert.match(pendingHtml, /approval is already in progress/i);
  assert.match(pendingHtml, /five minutes/i);
  assert.ok(!pendingHtml.includes('action="' + PUBLIC + '/account/assistant/start"'), 'Pending approval must not offer another start form');
  pass('A pending browser approval shows bounded retry guidance and does not offer a conflicting start form');
  const malformed = await browser('/account/assistant/callback?' + new URLSearchParams({ code: 'synthetic_unissued_code', state: 'z'.repeat(43) }), { cookie: attempt.cookie, update: false });
  assert.ok([400, 403].includes(malformed.status));
  assert.equal(malformed.headers.getSetCookie().length, 0, 'An unrelated invalid callback must not erase a valid in-progress browser envelope');
  await malformed.body?.cancel();
  assert.equal(providerFake.calls.some((call) => call.path === '/oauth2/token'), false, 'Wrong state cannot exchange a code');
  const original = await finish(attempt, 'app_consent_referencealice0001');
  const replay = await browser(original.route, { cookie: original.cookie });
  assert.ok([400, 403].includes(replay.status)); await replay.body?.cancel();
  assert.equal(providerFake.calls.filter((call) => call.path === '/oauth2/token').length, 1, 'Callback replay must not exchange a code again');
  pass('Actual consent callback completes signed PKCE verification once; wrong state and replay are rejected before provider exchange');

  phase = 'MCP owned read and token profile';
  const aliceClient = await mcpClient(original.token);
  const tools = await aliceClient.listTools();
  assert.deepEqual(tools.tools.map((tool) => tool.name), ['workouts_get']);
  const owned = await aliceClient.callTool({ name: 'workouts_get', arguments: { workoutId: 'alice-1' } });
  assert.notEqual(owned.isError, true); assert.deepEqual(owned.structuredContent, { id: 'alice-1', title: 'Alice ride' });
  const foreign = await aliceClient.callTool({ name: 'workouts_get', arguments: { workoutId: 'bob-1' } });
  assert.equal(foreign.isError, true); assert.match(JSON.stringify(foreign), /NOT_FOUND/);
  assert.doesNotMatch(JSON.stringify([owned, foreign]), /PRIVATE_REFERENCE_|privateNote|owner/);
  for (const invalid of [
    await token('app_consent_referencealice0001', BOB),
    await token('app_consent_referencealice0001', ALICE, { aud: CLIENT }),
    await token('app_consent_referencealice0001', ALICE, {}, { typ: 'JWT' }),
  ]) await denied(invalid);
  const noScope = await token('app_consent_referencealice0001', ALICE, { scope: 'openid' });
  await denied(noScope);
  pass('Official MCP client reads only mapped owned data; wrong account, audience, token type and narrowed-away scope fail closed');

  phase = 'live account mapping';
  mappings.set('local-alice', { providerSubject: ALICE, enabled: false });
  await denied(original.token);
  mappings.set('local-alice', { providerSubject: BOB, enabled: true });
  await denied(original.token);
  mappings.set('local-alice', { providerSubject: ALICE, enabled: true });
  assert.notEqual((await aliceClient.callTool({ name: 'workouts_get', arguments: { workoutId: 'alice-1' } })).isError, true);
  pass('Disabling or changing the publisher account mapping immediately denies an otherwise valid approved token');

  phase = 'current authority before provider reset';
  const CHARLIE = 'user_referencecharlie1234';
  sessions.charlie = { sessionId: 'c'.repeat(64), authVersion: randomUUID(), appSubject: 'local-charlie', accountLabel: 'Charlie', expiresAt: Date.now() + 60 * 60_000 };
  mappings.set('local-charlie', { providerSubject: CHARLIE, enabled: true });
  providerFake.authorized.add(CHARLIE);
  for (const mutation of ['mapping', 'session', 'mapping-without-existing-authorization']) {
    if (mutation === 'mapping-without-existing-authorization') providerFake.authorized.delete(CHARLIE);
    const fields = await currentForm('/account/assistant/start', 'charlie');
    const beforeDelete = providerFake.calls.filter((call) => call.method === 'DELETE').length;
    providerFake.setListHook((subject) => {
      if (subject !== CHARLIE) return;
      providerFake.setListHook(undefined);
      if (mutation === 'session') sessions.charlie.authVersion = randomUUID();
      else mappings.set('local-charlie', { providerSubject: CHARLIE, enabled: false });
    });
    const invalidated = await browser('/account/assistant/start', { method: 'POST', fields, user: 'charlie' });
    assert.equal(invalidated.status, 403);
    assert.equal(invalidated.headers.has('location'), false);
    await invalidated.body?.cancel();
    assert.equal(providerFake.calls.filter((call) => call.method === 'DELETE').length, beforeDelete,
      'Account/session invalidation during provider reads must stop the following provider mutation');
    mappings.set('local-charlie', { providerSubject: CHARLIE, enabled: true });
  }
  await denied(await token('app_consent_referencecharlie001', CHARLIE));
  const authorityRetry = await begin('charlie');
  const retryCancelled = await browser('/account/assistant/callback?' + new URLSearchParams({
    error: 'access_denied', state: authorityRetry.url.searchParams.get('state'),
  }), { user: 'charlie', cookie: authorityRetry.cookie });
  assert.equal(retryCancelled.status, 403); await retryCancelled.body?.cancel();
  pass('Fresh session and mapping checks stop provider DELETE or approval redirects when authority changes mid-request; safe pre-mutation failures can retry');

  phase = 'durable disconnect';
  const disconnect = await currentForm('/account/assistant/disconnect');
  assert.ok(disconnect.authorizationId);
  const disconnected = await browser('/account/assistant/disconnect', { method: 'POST', fields: disconnect });
  assert.ok([302, 303].includes(disconnected.status)); await disconnected.body?.cancel();
  await denied(original.token);
  await assert.rejects(aliceClient.callTool({ name: 'workouts_get', arguments: { workoutId: 'alice-1' } }));
  await store.close();
  await startReference();
  await denied(original.token);
  pass('Disconnect denies established MCP clients and remains revoked after reopening the persistent reference store with a new connection');

  phase = 'fresh reconnect and old family replay';
  const freshAttempt = await begin();
  const replacement = await finish(freshAttempt, 'app_consent_referencealice0002');
  const newClient = await mcpClient(replacement.token);
  assert.notEqual((await newClient.callTool({ name: 'workouts_get', arguments: { workoutId: 'alice-1' } })).isError, true);
  await denied(original.token);
  await denied(await token('app_consent_referencealice0001'));
  await denied(unknown);
  pass('Reconnect authorizes a fresh consent generation while original tokens, refreshed tokens from the old family and unknown consents remain denied');

  phase = 'independent account approval';
  const bobAttempt = await begin('bob');
  const bobApproval = await finish(bobAttempt, 'app_consent_referencebob000001', 'bob');
  const bobClient = await mcpClient(bobApproval.token);
  const bobRead = await bobClient.callTool({ name: 'workouts_get', arguments: { workoutId: 'bob-1' } });
  assert.deepEqual(bobRead.structuredContent, { id: 'bob-1', title: 'Bob run' });
  const cross = await bobClient.callTool({ name: 'workouts_get', arguments: { workoutId: 'alice-1' } });
  assert.equal(cross.isError, true);
  const aliceDisconnect = await currentForm('/account/assistant/disconnect');
  const crossDisconnect = await browser('/account/assistant/disconnect', { method: 'POST', fields: aliceDisconnect, user: 'bob' });
  assert.ok([400, 403].includes(crossDisconnect.status)); await crossDisconnect.body?.cancel();
  assert.notEqual((await newClient.callTool({ name: 'workouts_get', arguments: { workoutId: 'alice-1' } })).isError, true);
  pass('A second publisher account approves independently and cannot read or disconnect the first account');

  phase = 'uncertain provider reset fencing';
  providerFake.setUncertain(true);
  const resetForm = await currentForm('/account/assistant/start');
  const failedReset = await browser('/account/assistant/start', { method: 'POST', fields: resetForm });
  assert.equal(failedReset.status, 503); await failedReset.body?.cancel();
  await denied(replacement.token);
  const deletesBeforeRetry = providerFake.calls.filter((call) => call.method === 'DELETE').length;
  const retryReset = await browser('/account/assistant/start', { method: 'POST', fields: resetForm });
  assert.ok([400, 403, 409, 503].includes(retryReset.status)); await retryReset.body?.cancel();
  assert.equal(providerFake.calls.filter((call) => call.method === 'DELETE').length, deletesBeforeRetry, 'An uncertain reset must not repeat provider deletion');
  await store.close(); await startReference();
  await denied(replacement.token);
  const retryAfterRestart = await browser('/account/assistant/start', { method: 'POST', fields: resetForm });
  assert.ok([400, 403, 409, 503].includes(retryAfterRestart.status)); await retryAfterRestart.body?.cancel();
  assert.equal(providerFake.calls.filter((call) => call.method === 'DELETE').length, deletesBeforeRetry);
  assert.notEqual((await bobClient.callTool({ name: 'workouts_get', arguments: { workoutId: 'bob-1' } })).isError, true);
  pass('An uncertain provider reset fences the connection across restart without retrying a destructive provider call; other accounts stay authorized');

  phase = 'private persistence';
  await store.close();
  let database;
  if (postgresUrl) {
    const tables = (await admin.query('SELECT tablename FROM pg_tables WHERE schemaname = $1', [schema])).rows;
    const contents = [];
    for (const { tablename } of tables) {
      assert.match(tablename, /^[a-z_]+$/);
      contents.push((await admin.query('SELECT row_to_json(t) AS row FROM "' + schema + '"."' + tablename + '" t')).rows);
    }
    database = Buffer.from(JSON.stringify(contents));
  } else database = await readFile(dbPath);
  for (const secretValue of [API_KEY, original.token, original.code, replacement.token, replacement.code,
    bobApproval.token, bobApproval.code, 'SYNTHETIC_REFRESH_TOKEN_MUST_NOT_PERSIST', 'SYNTHETIC_ID_TOKEN_MUST_NOT_PERSIST']) {
    assert.equal(database.includes(Buffer.from(secretValue)), false, 'Private credentials must not be persisted');
  }
  pass('Persistent reference database contains no provider API key, access/refresh/ID tokens or authorization codes');

  await writeFile('./consumer-result.json', JSON.stringify({ status: 'passed', checks: evidence }, null, 2));
} catch (error) {
  await writeFile('./consumer-result.json', JSON.stringify({ status: 'failed', phase,
    errorType: error?.constructor?.name ?? 'Error',
    line: Number(error?.stack?.match(/verify-runtime\.mjs:(\d+):/)?.[1]) || undefined,
    ...(typeof error?.actual === 'number' && typeof error?.expected === 'number'
      ? { actualNumber: error.actual, expectedNumber: error.expected } : {}), checks: evidence }, null, 2));
  process.exitCode = 1;
} finally {
  await Promise.allSettled(clients.map((client) => client.close()));
  for (const server of servers) if (server.listening) {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
  for (const store of stores) await store.close?.();
  await Promise.allSettled(pools.map((pool) => pool.end()));
  if (admin) {
    try { if (ownsSchema) await admin.query('DROP SCHEMA "' + schema + '" CASCADE'); }
    finally { await admin.end(); }
  }
}
`;

let temporary;
try {
  assert.equal(process.versions.node.split('.')[0], '24', 'Reference verification requires Node 24');
  await mkdir(path.dirname(reportPath), { recursive: true });
  await writeFile(reportPath, JSON.stringify(report, null, 2) + '\n');
  const [manifest, rootManifest] = await Promise.all([
    readFile(path.join(sdkDirectory, 'package.json'), 'utf8').then(JSON.parse),
    readFile(path.join(root, 'package.json'), 'utf8').then(JSON.parse),
  ]);
  await readFile(path.join(sdkDirectory, 'dist/workos-connect.js')).catch(() => {
    throw new Error('WorkOS SDK build is missing. Run npm run build before this script.');
  });
  assert.equal(manifest.name, '@gateivo/sdk');
  assert.equal(manifest.private, true);
  assert.equal(manifest.license, 'MIT');
  for (const name of Object.keys(manifest.dependencies)) assert.doesNotMatch(name, /@workos-inc|^pg$/);
  temporary = await realpath(await mkdtemp(path.join(tmpdir(), 'gateivo-workos-consumer-')));
  assert.ok(!inside(await realpath(root), temporary));
  childEnv.npm_config_cache = path.join(temporary, 'npm-cache');
  const { stdout } = await npm(['pack', '--json', '--ignore-scripts', '--pack-destination', temporary], sdkDirectory, 'Packing reference SDK');
  const packed = JSON.parse(stdout);
  assert.equal(packed.length, 1);
  const pack = packed[0];
  assert.equal(pack.name, manifest.name);
  assert.equal(pack.version, manifest.version);
  for (const file of pack.files) {
    assert.ok(['package.json', 'README.md', 'LICENSE', 'SECURITY.md', 'docs/authentication.md'].includes(file.path) || /^dist\/[A-Za-z0-9_-]+(?:\.d\.(?:ts|cts)|\.(?:js|cjs))$/.test(file.path));
    assert.doesNotMatch(file.path, /sagly|pilot|\.env|secret|service/i);
  }
  for (const extension of ['js', 'cjs', 'd.ts', 'd.cts']) assert.ok(pack.files.some((file) => file.path === `dist/workos-connect.${extension}`));
  for (const required of ['LICENSE', 'README.md', 'SECURITY.md', 'docs/authentication.md']) {
    assert.ok(pack.files.some((file) => file.path === required), 'Required public documentation or licence is missing');
  }
  report.package = { name: pack.name, version: pack.version, integrity: pack.integrity, fileCount: pack.files.length };
  checks.push('Actual SDK tarball exposes optional WorkOS entry point without application-specific, PostgreSQL or provider SDK dependencies');
  const consumer = path.join(temporary, 'consumer');
  await mkdir(consumer);
  // Copy only source modules. Never copy an example user's
  // .env file, database, credentials, dependencies, nested folders or symlinks.
  const exampleFiles = (await readdir(exampleDirectory, { withFileTypes: true }))
    .filter((entry) => /^[A-Za-z0-9_-]+\.mjs$/.test(entry.name));
  assert.ok(exampleFiles.some((entry) => entry.name === 'index.mjs'));
  assert.ok(exampleFiles.some((entry) => entry.name === 'store.mjs'));
  report.example = { files: {} };
  for (const file of exampleFiles) {
    assert.ok(file.isFile() && !file.isSymbolicLink(), 'Reference source must be an ordinary file');
    const source = path.join(exampleDirectory, file.name);
    const contents = await readFile(source);
    if (file.name.endsWith('.mjs')) assert.doesNotMatch(contents.toString(), /(?:from\s*|import\s*\()['"](?:\.\.\/|[^'"]*(?:\/service\/|\/src\/|sagly))/i);
    report.example.files[file.name] = createHash('sha256').update(contents).digest('hex');
    await copyFile(source, path.join(consumer, file.name));
  }
  const consumerManifest = {
    name: 'gateivo-independent-authentication-reference', version: '0.0.0', private: true, type: 'module',
    dependencies: {
      '@gateivo/sdk': `file:${path.join(temporary, pack.filename)}`,
      express: rootManifest.dependencies.express,
      jose: rootManifest.dependencies.jose,
      zod: rootManifest.dependencies.zod,
    },
  };
  if (postgres) consumerManifest.dependencies.pg = '8.16.3';
  consumerManifest.devDependencies = { ...consumerManifest.devDependencies,
    '@modelcontextprotocol/client': rootManifest.devDependencies['@modelcontextprotocol/client'],
    '@types/node': rootManifest.devDependencies['@types/node'], typescript: rootManifest.devDependencies.typescript };
  await writeFile(path.join(consumer, 'package.json'), JSON.stringify(consumerManifest, null, 2) + '\n');
  await npm(['install', '--ignore-scripts', '--no-audit', '--no-fund'], consumer, 'Installing isolated reference');
  assert.ok(inside(consumer, await realpath(path.join(consumer, 'node_modules/@gateivo/sdk'))));
  const lock = JSON.parse(await readFile(path.join(consumer, 'package-lock.json'), 'utf8'));
  assert.ok(!Object.keys(lock.packages).some((name) => /(?:^|\/)node_modules\/@workos-inc\/node$/.test(name)));
  assert.equal(Object.hasOwn(lock.packages, 'node_modules/pg'), postgres, 'PostgreSQL remains an optional host dependency');
  report.isolatedInstallation = true;
  checks.push('Reference installs the npm tarball in an independent temporary project with no checkout module resolution');
  await Promise.all(['mts', 'cts'].map((extension) => writeFile(path.join(consumer, `consumer-types.${extension}`), typesFixture)));
  await run(process.execPath, ['node_modules/typescript/bin/tsc', '--noEmit', '--strict', '--module', 'NodeNext',
    '--moduleResolution', 'NodeNext', '--target', 'ES2022', '--types', 'node', '--esModuleInterop',
    'consumer-types.mts', 'consumer-types.cts'], consumer, 'Strict WorkOS ESM/CommonJS declarations');
  checks.push('Strict NodeNext declarations retain verified identity immutability, resolver typing and required provider scope configuration');
  await writeFile(path.join(consumer, 'verify-runtime.mjs'), runtimeFixture);
  try { await run(process.execPath, ['verify-runtime.mjs'], consumer, 'Reference acceptance'); }
  catch (error) {
    const result = await readFile(path.join(consumer, 'consumer-result.json'), 'utf8').then(JSON.parse).catch(() => null);
    if (result?.status === 'failed') throw new Error(`Reference acceptance failed during ${result.phase} (${result.errorType}, fixture line ${result.line ?? 'unknown'}${result.actualNumber !== undefined ? `, actual ${result.actualNumber}, expected ${result.expectedNumber}` : ''}).`);
    throw error;
  }
  const result = JSON.parse(await readFile(path.join(consumer, 'consumer-result.json'), 'utf8'));
  assert.equal(result.status, 'passed');
  checks.push(...result.checks);
  for (const [file, hash] of Object.entries(report.example.files)) {
    assert.equal(createHash('sha256').update(await readFile(path.join(exampleDirectory, file))).digest('hex'), hash,
      'Reference changed during acceptance; rerun verification.');
  }
  checks.push('Evidence records original reference source hashes and confirms tested files stayed unchanged');
  report.status = 'passed';
  report.scope = `Isolated installed package, ${report.storage} persistence, local HTTP reference and synthetic signed provider responses. Not a hosted WorkOS or assistant acceptance test.`;
  console.log(`WorkOS ${report.storage} reference verified: ${checks.length} checks passed from an isolated installed tarball.`);
} catch (error) {
  report.status = 'failed';
  report.failure = error instanceof Error ? error.message : 'Unknown verification failure';
  console.error(report.failure);
  process.exitCode = 1;
} finally {
  if (temporary) await rm(temporary, { recursive: true, force: true });
  await mkdir(path.dirname(reportPath), { recursive: true });
  await writeFile(reportPath, JSON.stringify(report, null, 2) + '\n');
}
