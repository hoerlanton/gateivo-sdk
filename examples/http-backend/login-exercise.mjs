import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { chmod, lstat, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer, request as httpRequest } from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { createAuthenticatedHttpBackendHost } from './authenticated.mjs';
import { createLoginProviderFixture } from './login-provider-fixture.mjs';
import { accountVersion, readHostConfig } from '../workos-reference/host-config.mjs';
import { createFixtureConfiguration, writeFixtureConfiguration } from '../workos-reference/setup.mjs';

const PUBLIC = 'https://http-login-reference.example.invalid';
const ISSUER = 'https://http-login-reference-staging.authkit.app';
const APP_COOKIE = '__Host-gateivo-reference-app';
const PRIVATE = /PRIVATE_HTTP_LOGIN_|internalNote|billingReference|privateEnvelope/;
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const decode = value => value.replace(/&quot;/g, '"').replace(/&#39;/g, "'")
  .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>');

function form(html, route) {
  for (const entry of html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)) {
    const action = entry[1].match(/\baction="([^"]*)"/i)?.[1];
    if (!action || new URL(decode(action), PUBLIC).pathname !== route) continue;
    return Object.fromEntries([...entry[2].matchAll(/<input\b([^>]*)>/gi)].flatMap(input => {
      const name = input[1].match(/\bname="([^"]*)"/i)?.[1];
      const value = input[1].match(/\bvalue="([^"]*)"/i)?.[1];
      return name && value !== undefined ? [[decode(name), decode(value)]] : [];
    }));
  }
  throw new Error('Expected a server-rendered form in the local exercise.');
}

async function startUpstream() {
  // These existing per-user API credentials are provisioned before any login.
  // They are not minted from a password, OAuth token, cookie, or model input.
  const credentials = new Map(['alice', 'bob'].map((subject, index) =>
    [subject, `${index + 17}|${randomBytes(32).toString('base64url')}`]));
  const observations = [];
  let hold = false;
  let pending;
  const server = createServer((request, response) => {
    const subject = [...credentials].find(([, credential]) =>
      request.headers.authorization === `Bearer ${credential}`)?.[0];
    observations.push({ authenticated: Boolean(subject), cookieReceived: Boolean(request.headers.cookie) });
    response.setHeader('content-type', 'application/json');
    if (!subject) { response.writeHead(401).end('{}'); return; }
    if (request.url === '/api/me/workouts/workout-error') {
      response.writeHead(503).end(JSON.stringify({ error: 'PRIVATE_HTTP_LOGIN_ERROR',
        credential: credentials.get(subject) })); return;
    }
    if (request.method !== 'GET' || request.url !== `/api/me/workouts/workout-${subject}-1`) {
      response.writeHead(404).end('{"privateError":"PRIVATE_HTTP_LOGIN_NOT_FOUND"}'); return;
    }
    const send = () => response.end(JSON.stringify({ workout: {
      id: `workout-${subject}-1`, title: subject === 'alice' ? 'Morning trail ride' : 'Evening run',
      ownerId: subject, internalNote: 'PRIVATE_HTTP_LOGIN_NOTE', billingReference: 'PRIVATE_HTTP_LOGIN_BILLING',
    }, privateEnvelope: 'PRIVATE_HTTP_LOGIN_ENVELOPE' }));
    if (hold) pending = send; else send();
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject); server.listen(0, '127.0.0.1', resolve);
  });
  return {
    credentials, observations, origin: `http://127.0.0.1:${server.address().port}`,
    hold() { assert.ok(!hold); hold = true; },
    release() { assert.ok(pending, 'Expected a pending authenticated backend request.');
      const send = pending; pending = undefined; hold = false; send(); },
    async close() { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); },
  };
}

/**
 * Node 24 source acceptance: real password/session and SDK consent routes,
 * signed synthetic provider responses, real SQLite, official MCP, local HTTP.
 * No manual session, principal, or grant is inserted. This is not a hosted
 * WorkOS/Claude test or a validated Laravel deployment.
 */
export async function runLoginHttpBackendExercise() {
  if (Number(process.versions.node.split('.')[0]) !== 24) throw new Error('This login exercise requires Node.js 24.');
  const directory = await mkdtemp(path.join(tmpdir(), 'gateivo-http-login-'));
  let upstream;
  let server;
  let host;
  let releaseLookup;
  let phase = 'private fixture setup';
  const clients = [];
  try {
    await chmod(directory, 0o700);
    const filename = path.join(directory, 'config.json');
    const apiKey = `sk_test_${randomBytes(24).toString('base64url')}`;
    const generated = await createFixtureConfiguration({ configPath: filename, publicUrl: PUBLIC,
      issuer: ISSUER, clientId: 'client_httploginreference123456', applicationId: 'connect_app_httploginreference123456',
      aliceUserId: 'user_httploginalice123456', bobUserId: 'user_httploginbob12345678', accessTokenType: 'JWT' });
    await writeFixtureConfiguration(filename, generated.config);
    upstream = await startUpstream();
    const provider = await createLoginProviderFixture({ config: generated.config, apiKey });
    server = createServer();
    const results = [];
    const diagnostics = [];
    const checks = [];
    const capturedSecrets = [apiKey, generated.config.secret,
      ...generated.credentials.map(account => account.password), ...upstream.credentials.values()];
    const credentialRecords = new Map(generated.config.accounts.map(account => [account.id, Object.freeze({
      appId: 'workouts-example', subject: account.id, issuer: generated.config.issuer,
      providerSubject: account.providerSubject, authVersion: accountVersion(account),
      credential: upstream.credentials.get(account.id), expiresAt: Date.now() + 5 * 60_000,
    })]));
    const lookupBindings = [];
    let blockLookup = false;
    const pass = message => checks.push(message);
    const setConfig = async config => writeFile(filename, JSON.stringify(config), { mode: 0o600 });
    const startHost = async () => {
      host = await createAuthenticatedHttpBackendHost({ config: await readHostConfig(filename), apiKey,
        backend: { baseUrl: upstream.origin, allowLoopbackHttp: true, timeoutMs: 1500, maxResponseBytes: 4096 },
        async resolveBackendCredential(binding, { signal }) {
          assert.ok(Object.isFrozen(binding), 'The application binding must be immutable.');
          assert.deepEqual(Object.keys(binding).sort(), ['appId', 'authVersion', 'issuer', 'providerSubject', 'subject']);
          lookupBindings.push(binding);
          const existing = credentialRecords.get(binding.subject);
          const deliberatelyUncooperative = blockLookup;
          if (deliberatelyUncooperative) await new Promise(resolve => { releaseLookup = resolve; });
          // The held branch deliberately returns late even after cancellation.
          // The composition/client must suppress it without relying on the hook.
          if (!deliberatelyUncooperative) signal.throwIfAborted();
          return existing ?? null;
        },
      }, { loadConfig: () => readHostConfig(filename), provider: { fetch: provider.fetch,
        onConsentDiagnostic: diagnostic => { diagnostics.push(diagnostic); } } });
      server.removeAllListeners('request'); server.on('request', host.app);
    };
    await startHost();
    await new Promise((resolve, reject) => {
      server.once('error', reject); server.listen(0, '127.0.0.1', resolve);
    });
    const local = `http://127.0.0.1:${server.address().port}`;
    // Simulate a loopback TLS-terminating proxy. No external destination can be
    // contacted by this transport; cookie flags and proxy checks stay real.
    const localFetch = async (raw, init = {}) => {
      const target = new URL(typeof raw === 'string' ? raw : raw instanceof URL ? raw.href : raw.url);
      assert.ok(target.origin === local, 'The exercise transport permits only its loopback host.');
      const headers = new Headers(init.headers ?? (raw instanceof Request ? raw.headers : undefined));
      headers.set('host', new URL(PUBLIC).host); headers.set('x-forwarded-proto', 'https');
      const method = init.method ?? (raw instanceof Request ? raw.method : 'GET');
      const body = init.body ?? (raw instanceof Request && !['GET', 'HEAD'].includes(method)
        ? Buffer.from(await raw.arrayBuffer()) : undefined);
      const caller = init.signal ?? (raw instanceof Request ? raw.signal : undefined);
      const signal = AbortSignal.any([AbortSignal.timeout(5000), ...(caller ? [caller] : [])]);
      // Native fetch normalizes Host. node:http preserves this explicitly pinned
      // proxy header. The fixture buffers finite responses under a strict cap.
      return new Promise((resolve, reject) => {
        let settled = false;
        const fail = error => { if (!settled) { settled = true; reject(error); } };
        const request = httpRequest(target, { method, headers: Object.fromEntries(headers), signal }, response => {
          const responseHeaders = new Headers();
          for (let index = 0; index < response.rawHeaders.length; index += 2) {
            responseHeaders.append(response.rawHeaders[index], response.rawHeaders[index + 1]);
          }
          const chunks = []; let bytes = 0;
          response.on('data', chunk => {
            bytes += chunk.byteLength;
            if (bytes > 256 * 1024) { const error = new Error('Local fixture response exceeded its byte cap.');
              fail(error); response.destroy(error); request.destroy(error); return; }
            chunks.push(chunk);
          });
          response.once('aborted', () => fail(new Error('Local fixture response was interrupted.')));
          response.once('error', fail);
          response.once('end', () => {
            if (settled) return;
            const status = response.statusCode ?? 500;
            settled = true;
            resolve(new Response([204, 205, 304].includes(status) ? null : Buffer.concat(chunks), {
              status, headers: responseHeaders,
            }));
          });
        });
        request.once('error', fail); request.end(body instanceof URLSearchParams ? body.toString() : body);
      });
    };
    const browser = () => {
      const jar = new Map();
      return {
        cookie: () => [...jar].map(([name, value]) => `${name}=${value}`).join('; '),
        async request(route, { method = 'GET', fields, cookie, origin = PUBLIC } = {}) {
          const response = await localFetch(local + route, { method, redirect: 'manual', headers: {
            cookie: cookie ?? [...jar].map(([name, value]) => `${name}=${value}`).join('; '),
            ...(method === 'POST' ? { origin, 'content-type': 'application/x-www-form-urlencoded' } : {}),
          }, ...(fields ? { body: new URLSearchParams(fields) } : {}) });
          for (const raw of response.headers.getSetCookie()) {
            const pair = raw.split(';')[0]; const at = pair.indexOf('=');
            if (pair.slice(at + 1)) jar.set(pair.slice(0, at), pair.slice(at + 1)); else jar.delete(pair.slice(0, at));
            capturedSecrets.push(pair.slice(at + 1));
          }
          return { status: response.status, headers: response.headers, text: await response.text() };
        },
      };
    };
    const aliceBrowser = browser();
    const bobBrowser = browser();
    const login = async (which, selectedBrowser) => {
      const page = await selectedBrowser.request('/sign-in');
      assert.equal(page.status, 200);
      const fields = form(page.text, '/sign-in');
      const response = await selectedBrowser.request('/sign-in', {
        method: 'POST', fields: { ...fields, ...generated.credentials[which] },
      });
      assert.equal(response.status, 303);
      assert.ok(response.headers.get('location') === '/account/assistant');
      const cookie = response.headers.getSetCookie().find(value => value.startsWith(`${APP_COOKIE}=`));
      assert.ok(cookie && ['Secure', 'HttpOnly', 'SameSite=Lax', 'Path=/'].every(part => cookie.includes(part)));
      const value = cookie.split(';')[0].split('=')[1];
      assert.ok(/^[A-Za-z0-9_-]{43}$/.test(value), 'Login creates an opaque session, not an account identifier.');
    };
    const currentForm = async (selectedBrowser, route) => {
      const page = await selectedBrowser.request('/account/assistant');
      assert.equal(page.status, 200); return form(page.text, route);
    };
    const approve = async (selectedBrowser, accountIndex, { inspect = false } = {}) => {
      const fields = await currentForm(selectedBrowser, '/account/assistant/start');
      const started = await selectedBrowser.request('/account/assistant/start', { method: 'POST', fields });
      assert.equal(started.status, 303);
      const issued = await provider.approve(started.headers.get('location'), generated.config.accounts[accountIndex].providerSubject);
      capturedSecrets.push(issued.token, issued.code, issued.state);
      const route = '/account/assistant/callback?' + new URLSearchParams({ code: issued.code, state: issued.state });
      if (inspect) {
        await deniedBearer(issued.token);
        const before = provider.counts.exchanges;
        const forged = await selectedBrowser.request('/account/assistant/callback?' + new URLSearchParams({
          code: issued.code, state: randomBytes(32).toString('base64url'),
        }));
        assert.ok([400, 403].includes(forged.status));
        assert.equal(provider.counts.exchanges, before);
      }
      const finished = await selectedBrowser.request(route);
      assert.equal(finished.status, 303);
      assert.ok(finished.headers.get('location') === `${PUBLIC}/account/assistant`);
      if (inspect) {
        const before = provider.counts.exchanges;
        const replay = await selectedBrowser.request(route);
        assert.ok([400, 403].includes(replay.status)); assert.equal(provider.counts.exchanges, before);
      }
      return issued;
    };
    const rawMcp = async (token, cookie) => {
      const response = await localFetch(`${local}/agent/mcp`, { method: 'POST', redirect: 'error', headers: {
        'content-type': 'application/json', accept: 'application/json, text/event-stream',
        ...(token ? { authorization: `Bearer ${token}` } : {}), ...(cookie ? { cookie } : {}),
      }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }) });
      const payload = await response.json(); results.push(payload); return { status: response.status, payload };
    };
    const deniedBearer = async token => {
      const before = lookupBindings.length;
      const result = await rawMcp(token);
      assert.ok([401, 403].includes(result.status));
      assert.equal(lookupBindings.length, before, 'Invalid delegation must fail before application credentials are requested.');
    };
    const clientFor = async token => {
      const client = new Client({ name: 'gateivo-http-login-reference', version: '0.1.0' }, {
        versionNegotiation: { mode: 'auto' },
      }); clients.push(client);
      await client.connect(new StreamableHTTPClientTransport(new URL(`${local}/agent/mcp`), {
        fetch: localFetch, requestInit: { headers: { authorization: `Bearer ${token}` }, redirect: 'error' },
        redirectPolicy: 'same-origin',
      }), { timeout: 5000 }); return client;
    };
    const call = async (client, id, extra = {}, options = {}) => {
      const result = await client.callTool({ name: 'workouts_get', arguments: { workoutId: id, ...extra } }, {
        timeout: 5000, ...options,
      }); results.push(result);
      assert.ok(!PRIVATE.test(JSON.stringify(result)), 'Upstream bodies must not escape the public projection.');
      return result;
    };
    const toolDenied = (result, code = 'FORBIDDEN') => {
      assert.equal(result.isError, true);
      assert.ok(JSON.stringify(result).includes(code), 'Expected a stable redacted error code.');
      assert.ok(!JSON.stringify(result).includes('Morning trail ride'));
    };
    const waitFor = async predicate => {
      for (let index = 0; index < 200 && !predicate(); index++) await delay(5);
      assert.ok(predicate(), 'Expected a bounded local fixture phase.');
    };

    phase = 'password login and session boundary';
    assert.equal((await aliceBrowser.request('/account/assistant')).status, 303);
    const initial = await aliceBrowser.request('/sign-in');
    const initialFields = form(initial.text, '/sign-in');
    assert.equal((await aliceBrowser.request('/sign-in', { method: 'POST', fields: {
      ...initialFields, ...generated.credentials[0], csrf: 'forged',
    } })).status, 403);
    assert.equal((await aliceBrowser.request('/account/assistant', {
      cookie: `${APP_COOKIE}=${randomBytes(32).toString('base64url')}`,
    })).status, 303);
    await login(0, aliceBrowser); await login(1, bobBrowser);
    const bareCookie = await rawMcp(undefined, aliceBrowser.cookie());
    assert.equal(bareCookie.status, 401); assert.equal(lookupBindings.length, 0);
    pass('Password login validates CSRF and creates a secure opaque session; browser cookies alone never authorize MCP.');

    phase = 'signed PKCE consent and durable grant';
    const first = await approve(aliceBrowser, 0, { inspect: true });
    assert.ok(provider.counts.exchanges === 1 && provider.counts.jwks > 0);
    assert.equal((await lstat(generated.config.databasePath)).mode & 0o777, 0o600);
    const alice = await clientFor(first.token);
    const tools = await alice.listTools();
    assert.deepEqual(tools.tools.map(tool => tool.name), ['workouts_get']);
    const owned = await call(alice, 'workout-alice-1');
    assert.deepEqual(owned.structuredContent, { workout: { id: 'workout-alice-1', title: 'Morning trail ride' } });
    assert.ok(lookupBindings.at(-1).subject === 'alice'
      && lookupBindings.at(-1).providerSubject === generated.config.accounts[0].providerSubject);
    pass('Actual consent routes exchange PKCE once, verify a signed provider JWT, persist approval, and resolve the current account’s existing API credential.');

    phase = 'second account and input isolation';
    const bobApproval = await approve(bobBrowser, 1);
    const bob = await clientFor(bobApproval.token);
    const [bobOwned, parallelAlice] = await Promise.all([
      call(bob, 'workout-bob-1'), call(alice, 'workout-alice-1'),
    ]);
    assert.deepEqual(bobOwned.structuredContent, { workout: { id: 'workout-bob-1', title: 'Evening run' } });
    assert.deepEqual(parallelAlice.structuredContent, { workout: { id: 'workout-alice-1', title: 'Morning trail ride' } });
    toolDenied(await call(alice, 'workout-bob-1'), 'NOT_FOUND');
    toolDenied(await call(bob, 'workout-alice-1'), 'NOT_FOUND');
    const beforeInvalidInput = lookupBindings.length;
    const invalid = await call(alice, 'workout-alice-1', { ownerId: 'bob', credential: 'model-supplied' });
    assert.equal(invalid.isError, true); assert.equal(lookupBindings.length, beforeInvalidInput);
    toolDenied(await call(alice, 'workout-error'), 'UNAVAILABLE');
    pass('Parallel independent account reads preserve upstream ownership, strict inputs and a public id/title projection.');

    phase = 'JWT profile and current account binding';
    for (const payload of [
      { iss: 'https://wrong-issuer.example.invalid' }, { aud: generated.config.clientId },
      { client_id: 'client_wrongfixture123456' }, { scope: 'openid' },
      { exp: Math.floor(Date.now() / 1000) - 100 }, { sub: generated.config.accounts[1].providerSubject },
      { sid: 'app_consent_unknownfixture123456' },
    ]) await deniedBearer(await provider.variant(first, payload));
    await deniedBearer(await provider.variant(first, {}, { typ: 'at+jwt' }));
    const pieces = first.token.split('.'); pieces[2] = (pieces[2][0] === 'a' ? 'b' : 'a') + pieces[2].slice(1);
    await deniedBearer(pieces.join('.'));
    const disabled = structuredClone(generated.config); disabled.accounts[0].enabled = false;
    await setConfig(disabled); await deniedBearer(first.token);
    assert.equal((await aliceBrowser.request('/account/assistant')).status, 303);
    const rebound = structuredClone(generated.config); rebound.accounts[0].providerSubject = 'user_changedmapping123456';
    await setConfig(rebound); await deniedBearer(first.token);
    await setConfig(generated.config);
    pass('Wrong signatures, issuer/audience/client/scope/expiry/consent and disabled or remapped accounts fail before credential lookup.');

    phase = 'stored credential binding and application auth version';
    const originalRecord = credentialRecords.get('alice');
    for (const changed of [null, { ...originalRecord, subject: 'bob' },
      { ...originalRecord, providerSubject: generated.config.accounts[1].providerSubject },
      { ...originalRecord, expiresAt: Date.now() - 1 }]) {
      credentialRecords.set('alice', changed);
      const before = upstream.observations.length;
      toolDenied(await call(alice, 'workout-alice-1'));
      assert.equal(upstream.observations.length, before);
    }
    credentialRecords.set('alice', originalRecord);
    const changedVersion = structuredClone(generated.config);
    changedVersion.accounts[0].authVersion = randomBytes(24).toString('base64url');
    await setConfig(changedVersion);
    const beforeChangedVersion = upstream.observations.length;
    toolDenied(await call(alice, 'workout-alice-1'));
    assert.equal(upstream.observations.length, beforeChangedVersion);
    await setConfig(generated.config);
    pass('Missing, cross-bound, expired and stale auth-version credential records are refused before upstream HTTP.');

    phase = 'in-flight lookup and backend rechecks';
    blockLookup = true;
    const beforeLookupRace = lookupBindings.length;
    const beforeLookupHttp = upstream.observations.length;
    const pendingLookup = call(alice, 'workout-alice-1');
    await waitFor(() => lookupBindings.length > beforeLookupRace && Boolean(releaseLookup));
    await setConfig(changedVersion); blockLookup = false; releaseLookup(); releaseLookup = undefined;
    toolDenied(await pendingLookup);
    assert.equal(upstream.observations.length, beforeLookupHttp);
    await setConfig(generated.config);
    upstream.hold();
    const beforeReadRace = upstream.observations.length;
    const pendingRead = call(alice, 'workout-alice-1');
    await waitFor(() => upstream.observations.length > beforeReadRace);
    await setConfig(changedVersion); upstream.release();
    toolDenied(await pendingRead);
    await setConfig(generated.config);
    pass('Changes during credential lookup stop HTTP; changes during an upstream read suppress the response.');

    phase = 'late cancelled credential lookup';
    blockLookup = true;
    const beforeCancelledLookup = lookupBindings.length;
    const beforeCancelledHttp = upstream.observations.length;
    const controller = new AbortController();
    const cancelled = call(alice, 'workout-alice-1', {}, { signal: controller.signal });
    const rejectedCancellation = assert.rejects(cancelled);
    await waitFor(() => lookupBindings.length > beforeCancelledLookup && Boolean(releaseLookup));
    controller.abort(); await rejectedCancellation;
    await delay(25); blockLookup = false; releaseLookup(); releaseLookup = undefined;
    await delay(25); assert.equal(upstream.observations.length, beforeCancelledHttp);
    pass('A cancelled lookup cannot later forward the resolved user credential to the backend.');

    phase = 'disconnect, durable reopen and reconnect';
    await login(0, aliceBrowser);
    const disconnectFields = await currentForm(aliceBrowser, '/account/assistant/disconnect');
    assert.equal((await bobBrowser.request('/account/assistant/disconnect', {
      method: 'POST', fields: disconnectFields,
    })).status, 403);
    assert.equal((await aliceBrowser.request('/account/assistant/disconnect', {
      method: 'POST', fields: disconnectFields,
    })).status, 303);
    await deniedBearer(first.token);
    await host.close(); await startHost();
    await deniedBearer(first.token);
    await login(0, aliceBrowser);
    const replacement = await approve(aliceBrowser, 0);
    const replacementClient = await clientFor(replacement.token);
    assert.notEqual((await call(replacementClient, 'workout-alice-1')).isError, true);
    await deniedBearer(first.token);
    await deniedBearer(await provider.variant(first));
    assert.notEqual((await call(bob, 'workout-bob-1')).isError, true);
    pass('Disconnect survives SQLite reopen; reconnect admits a new consent while old tokens and their signed family remain denied.');

    phase = 'privacy and cleanup evidence';
    assert.ok(upstream.observations.every(observation => observation.authenticated && !observation.cookieReceived));
    const rendered = JSON.stringify({ results, diagnostics, checks });
    assert.ok(!PRIVATE.test(rendered));
    const sensitive = [...capturedSecrets.filter(Boolean),
      ...provider.issued.flatMap(approval => [approval.token, approval.code, approval.state, approval.payload.sid]),
      ...generated.config.accounts.flatMap(account => [account.providerSubject, account.authVersion,
        account.password.salt, account.password.digest, accountVersion(account)])];
    assert.ok(sensitive.every(value => !rendered.includes(value)), 'Public output and diagnostics must omit credential and identity material.');
    const persisted = await readFile(generated.config.databasePath);
    assert.ok([...generated.credentials.map(account => account.password), ...upstream.credentials.values(),
      ...provider.issued.map(approval => approval.token), apiKey,
      'SYNTHETIC_REFRESH_MUST_NOT_PERSIST', 'SYNTHETIC_ID_MUST_NOT_PERSIST']
      .every(value => !persisted.includes(Buffer.from(value))), 'Delegation persistence must not retain credentials.');
    pass('Public checks and diagnostics omit passwords, cookies, tokens, provider identities and private backend bodies.');
    return Object.freeze({ checks: Object.freeze(checks), scope: 'Local signed-provider fixture, real password/session/consent/SQLite/MCP, fictional existing HTTP API.' });
  } catch (error) {
    // No request URL, assertion values, provider response or credentials escape.
    const failure = new Error(`Authenticated HTTP exercise failed during ${phase}.`);
    failure.name = 'LoginExerciseError';
    failure.kind = error instanceof Error ? error.name : 'Error';
    failure.location = /(?:login-exercise|login-provider-fixture)\.mjs:\d+(?::\d+)?/.exec(error?.stack ?? '')?.[0];
    throw failure;
  } finally {
    releaseLookup?.();
    await Promise.allSettled(clients.map(client => client.close()));
    server?.closeAllConnections();
    if (server?.listening) await new Promise(resolve => server.close(resolve));
    await host?.close();
    await upstream?.close();
    await rm(directory, { recursive: true, force: true });
  }
}
