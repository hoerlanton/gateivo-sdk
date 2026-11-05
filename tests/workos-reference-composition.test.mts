import assert from 'node:assert/strict';
import { createServer, request as httpRequest, type IncomingHttpHeaders } from 'node:http';
import type { AddressInfo } from 'node:net';
import { test, type TestContext } from 'node:test';
import express from 'express';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { z } from 'zod/v4';

// Source-level checks exercise the same optional entry point built into the SDK.
// Clean archive installation remains verify-workos-reference's job.
import { createWorkOSConnection as createWorkOSReference,
  type WorkOSConnectionOptions } from '../src/workos-connect-express.js';

const PUBLIC = 'https://publisher.example.invalid';
const ISSUER = 'https://issuer.example.invalid';
const SUBJECT = '10000000-0000-4000-8000-000000000001';
const PROVIDER_SUBJECT = 'user_referencealice123456';
const AUTHORIZATION = '20000000-0000-4000-8000-000000000002';
const revision = '30000000-0000-4000-8000-000000000003';
const context = () => ({ signal: new AbortController().signal });

function fixture(overrides: Record<string, unknown> = {}, syntheticFetch?: typeof fetch) {
  const calls = { provider: 0, session: 0, mapping: 0, active: 0, begin: 0,
    state: [] as Array<Record<string, unknown>>, onActive: undefined as (() => void) | undefined };
  const store = {
    async isActive(_principal: unknown, details: Record<string, unknown>) {
      calls.active++;
      if (details.providerSubject !== undefined) {
        assert.equal(details.providerSubject, PROVIDER_SUBJECT);
        assert.equal(details.resource, `${PUBLIC}/agent/mcp`);
      }
      calls.onActive?.();
      return true;
    },
    async getState(target: Record<string, unknown>) {
      calls.state.push(target);
      return { revision, phase: null, attemptExpiresAt: null, active: false };
    },
    async begin() { calls.begin++; throw new Error('Unexpected reset in composition test'); },
    ...Object.fromEntries(['claimReset', 'completeReset', 'fail', 'consume', 'cancel', 'complete',
      'resolveConsent', 'revoke'].map(name => [name, async () => {
      throw new Error(`Unexpected ${name} in composition test`);
    }])),
  };
  const options = {
    appId: 'example', publicUrl: PUBLIC, issuer: ISSUER,
    clientId: 'client_reference123456', applicationId: 'connect_app_reference123456',
    apiKey: 'synthetic-provider-key', accessTokenType: null, requiredScopes: ['workouts:read'],
    secret: new Uint8Array(32).fill(7), trustProxyHttps: true, mountMcp: false,
    async authenticateSession() {
      calls.session++;
      return { sessionId: 'browser-session', authVersion: 'login-version', appSubject: SUBJECT,
        accountLabel: 'Synthetic account', expiresAt: Date.now() + 3600_000 };
    },
    async resolveAccount(input: { issuer: string; appSubject: string }) {
      calls.mapping++;
      assert.equal(input.issuer, ISSUER);
      assert.equal(input.appSubject, SUBJECT);
      return { enabled: true, providerSubject: PROVIDER_SUBJECT };
    },
    ...overrides,
    store: overrides.store && typeof overrides.store === 'object'
      ? { ...store, ...overrides.store } : ('store' in overrides ? overrides.store : store),
  };
  const reference = createWorkOSReference(options as unknown as WorkOSConnectionOptions, { fetch: async (...args: Parameters<typeof fetch>) => {
    calls.provider++;
    if (syntheticFetch) return syntheticFetch(...args);
    throw new Error('No live provider transport is allowed in this test');
  } });
  const principal = { appId: 'example', subject: SUBJECT, authorizationId: AUTHORIZATION,
    scopes: ['workouts:read'], expiresAt: Date.now() + 60_000 };
  return { reference, calls, principal };
}

async function serve(t: TestContext, reference: { router: express.Router }) {
  const app = express();
  app.use(reference.router);
  app.all('/agent/mcp', (_req, res) => res.status(218).json({ owner: 'application' }));
  const server = createServer(app);
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  t.after(async () => { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); });
  return (path: string, form?: URLSearchParams, headers: Record<string, string | undefined> = {}) => new Promise<{
    status: number; text: string; headers: IncomingHttpHeaders;
  }>((resolve, reject) => {
    const body = form?.toString();
    const requestHeaders: Record<string, string | number | undefined> = {
      host: new URL(PUBLIC).host, 'x-forwarded-proto': 'https',
      ...(body === undefined ? {} : { origin: PUBLIC, 'content-type': 'application/x-www-form-urlencoded',
        'content-length': Buffer.byteLength(body) }), ...headers,
    };
    for (const name of Object.keys(requestHeaders)) if (requestHeaders[name] === undefined) delete requestHeaders[name];
    const req = httpRequest({ host: '127.0.0.1', port: (server.address() as AddressInfo).port,
      path, method: body === undefined ? 'GET' : 'POST', agent: false,
      headers: requestHeaders,
    }, res => {
      const chunks: Buffer[] = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode!, text: Buffer.concat(chunks).toString('utf8'), headers: res.headers }));
      res.on('error', reject);
    });
    req.on('error', reject);
    req.setTimeout(5000, () => req.destroy(new Error('Composition HTTP request timed out')));
    req.end(body);
  });
}

test('controls-only mode leaves the MCP path to the host and retains metadata and live grant checks', async t => {
  const h = fixture();
  const request = await serve(t, h.reference);
  assert.equal(h.reference.registry, undefined);
  assert.equal((await request('/agent/mcp')).status, 218);
  const metadata = await request('/.well-known/oauth-protected-resource/agent/mcp');
  assert.equal(metadata.status, 200);
  assert.equal(JSON.parse(metadata.text).resource, `${PUBLIC}/agent/mcp`);
  assert.equal(await h.reference.isAuthorized(h.principal, context()), true);
  assert.equal(h.calls.active, 2);
  assert.equal(h.calls.mapping, 1);
  assert.equal(h.calls.provider, 0);
  assert.equal(await h.reference.isAuthorized({ ...h.principal, appId: 'another-app' }, context()), false);
  assert.equal(h.calls.active, 2);
});

test('default mode still requires actions and owns its authenticated MCP route', async t => {
  assert.throws(() => fixture({ mountMcp: undefined }), /configuration/);
  const h = fixture({ mountMcp: undefined, actions: [{ name: 'example_read', title: 'Read', description: 'Read example',
    requiredScopes: ['workouts:read'], inputSchema: z.strictObject({}), outputSchema: z.strictObject({ ok: z.boolean() }),
    execute: async () => ({ ok: true }) }] });
  const request = await serve(t, h.reference);
  assert.ok(h.reference.registry);
  assert.equal((await request('/agent/mcp')).status, 401);
  assert.equal(h.calls.provider, 0);
});

test('case variants cannot bypass HTTPS or the access cutoff on owned routes', async t => {
  const action = { name: 'example_read', title: 'Read', description: 'Read example',
    requiredScopes: ['workouts:read'], inputSchema: z.strictObject({}),
    outputSchema: z.strictObject({ ok: z.boolean() }), execute: async () => ({ ok: true }) };
  const active = fixture({ mountMcp: true, actions: [action] });
  const request = await serve(t, active.reference);
  for (const route of ['/agent/mcp', '/AGENT/MCP', '/Account/Assistant']) {
    assert.equal((await request(route, undefined, { 'x-forwarded-proto': 'http' })).status, 403, route);
  }
  const expired = fixture({ mountMcp: true, actions: [action], accessExpiresAt: Date.now() - 1 });
  const expiredRequest = await serve(t, expired.reference);
  for (const route of ['/agent/mcp', '/AGENT/MCP', '/Account/Assistant']) {
    assert.equal((await expiredRequest(route)).status, 410, route);
  }
});

test('an elapsed fixed cutoff is valid configuration and closes controls, verifier and grant checks', async t => {
  const h = fixture({ accessExpiresAt: Date.now() - 1 });
  const request = await serve(t, h.reference);
  assert.equal(await h.reference.verifyToken('synthetic-token', { ...context(), audience: `${PUBLIC}/agent/mcp` }), null);
  assert.equal(await h.reference.isAuthorized(h.principal, context()), false);
  assert.equal((await request('/account/assistant')).status, 410);
  assert.equal((await request('/agent/mcp')).status, 410);
  assert.equal(h.calls.provider, 0);
  assert.equal(h.calls.session, 0);
  assert.equal(h.calls.active, 0);
});

test('approval display is clamped to the cutoff and a submitted extension cannot start a provider reset', async t => {
  const cutoff = Date.now() + 60_000;
  const h = fixture({ accessExpiresAt: cutoff });
  const request = await serve(t, h.reference);
  const page = await request('/account/assistant');
  assert.equal(page.status, 200);
  assert.equal(h.calls.state[0]!.approvedExpiresAt, cutoff);
  const csrf = /name="csrf" value="([^"]+)"/.exec(page.text)?.[1];
  assert.ok(csrf);
  const rejected = await request('/account/assistant/start', new URLSearchParams({
    revision, csrf, approvedExpiresAt: String(cutoff + 1),
  }));
  assert.equal(rejected.status, 403);
  assert.equal(h.calls.begin, 0);
  assert.equal(h.calls.provider, 0);
});

test('rendered controls preserve same-origin form Origin while callbacks and rejected posts disclose no referrer', async t => {
  const cutoff = Date.now() + 60_000;
  const h = fixture({ accessExpiresAt: cutoff });
  const request = await serve(t, h.reference);
  const page = await request('/account/assistant');
  assert.equal(page.status, 200);
  assert.equal(page.headers['referrer-policy'], 'same-origin');
  const csrf = /name="csrf" value="([^"]+)"/.exec(page.text)?.[1];
  assert.ok(csrf);
  const fields = new URLSearchParams({ revision, csrf, approvedExpiresAt: String(cutoff) });
  for (const origin of [undefined, 'null', 'https://attacker.example.invalid']) {
    const rejected = await request('/account/assistant/start', fields, { origin });
    assert.equal(rejected.status, 403);
    assert.equal(rejected.headers['referrer-policy'], 'no-referrer');
  }
  for (const path of ['/account/assistant?unexpected=1',
    `/account/assistant/callback?state=${'a'.repeat(43)}&code=synthetic-private-code`]) {
    const rejected = await request(path);
    assert.equal(rejected.status, 400);
    assert.equal(rejected.headers['referrer-policy'], 'no-referrer');
    assert.doesNotMatch(rejected.text, /<form\b|synthetic-private-code/);
  }
  assert.equal(h.calls.begin, 0);
  assert.equal(h.calls.provider, 0);
});

test('approval controls explain reconnect order without claiming the assistant is connected', async t => {
  let state = { revision, phase: null as string | null, attemptExpiresAt: null as number | null,
    active: false, authorizationId: AUTHORIZATION };
  const h = fixture({ store: { async getState() { return state; } } });
  const request = await serve(t, h.reference);
  for (const phase of [null, 'completed']) {
    // A completed flow with no active grant also represents a later disconnect.
    state = { ...state, phase };
    const response = await request('/account/assistant');
    assert.equal(response.status, 200);
    assert.match(response.text, /No active approval/);
    assert.match(response.text, /even if its connector still says Connected/);
    assert.match(response.text, /First approve access below\. Then connect or reconnect/);
    assert.match(response.text, />Approve access<\/button>/);
    assert.doesNotMatch(response.text, /action="[^"]+\/disconnect"|<details>/);
  }
  state = { ...state, active: true };
  const approved = await request('/account/assistant');
  assert.equal(approved.status, 200);
  assert.match(approved.text, /Read-only access is approved for this account/);
  assert.match(approved.text, /If the connector already exists, reconnect it there/);
  assert.match(approved.text, /If there is no reconnect action, disconnect and connect again in your assistant’s settings/);
  assert.match(approved.text, /It cannot confirm whether your assistant is connected/);
  assert.doesNotMatch(approved.text, /Connected\. Read-only|First approve access/);
  assert.match(approved.text, /<details><summary>Replace this approval<\/summary>/);
  assert.match(approved.text, /This stops existing assistant access/);
  for (const phase of ['awaiting_consent', 'blocked']) {
    state = { ...state, active: false, phase, attemptExpiresAt: Date.now() + 60_000 };
    const response = await request('/account/assistant');
    assert.equal(response.status, 200);
    assert.doesNotMatch(response.text, /First approve access|action="[^"]+\/start"|<details>/);
  }
  assert.equal(h.calls.provider, 0);
  assert.equal(h.calls.begin, 0);
});

test('a live grant check crossing the cutoff cannot return authority', async t => {
  let now = Date.now();
  t.mock.method(Date, 'now', () => now);
  const cutoff = now + 1000;
  const h = fixture({ accessExpiresAt: cutoff });
  h.calls.onActive = () => { now = cutoff; };
  assert.equal(await h.reference.isAuthorized(h.principal, context()), false);
  assert.equal(h.calls.active, 1);
  assert.equal(h.calls.mapping, 0);
});

test('verified delegated tokens are capped to the cutoff and cannot survive crossing it during grant lookup', async t => {
  let now = Date.now();
  t.mock.method(Date, 'now', () => now);
  const cutoff = now + 30_000;
  const keys = await generateKeyPair('RS256');
  const jwk = { ...await exportJWK(keys.publicKey), kid: 'composition-signing-key', alg: 'RS256' };
  const issued = Math.floor(now / 1000);
  const token = await new SignJWT({ iss: ISSUER, aud: `${PUBLIC}/agent/mcp`, sub: PROVIDER_SUBJECT,
    client_id: 'client_reference123456', sid: 'app_consent_reference123456', jti: 'composition-token',
    iat: issued - 1, exp: issued + 300, scope: 'workouts:read' })
    .setProtectedHeader({ alg: 'RS256', kid: jwk.kid }).sign(keys.privateKey);
  const grant = { authorizationId: AUTHORIZATION, subject: SUBJECT, scopes: ['workouts:read'], expiresAt: now + 60_000 };
  let expireDuringLookup = false;
  const h = fixture({ accessExpiresAt: cutoff, store: { async resolveConsent() {
    if (expireDuringLookup) now = cutoff;
    return grant;
  } } }, async (url, init) => {
    assert.equal(String(url), `${ISSUER}/oauth2/jwks`);
    assert.equal(new Headers(init?.headers).has('authorization'), false);
    return Response.json({ keys: [jwk] });
  });
  const verified = await h.reference.verifyToken(token, { ...context(), audience: `${PUBLIC}/agent/mcp` });
  assert.ok(verified);
  assert.equal(verified.subject, SUBJECT);
  assert.equal(verified.expiresAt, cutoff);
  expireDuringLookup = true;
  assert.equal(await h.reference.verifyToken(token, { ...context(), audience: `${PUBLIC}/agent/mcp` }), null);
});

test('invalid explicit composition and cutoff settings are rejected', () => {
  for (const accessExpiresAt of [-1, Infinity, NaN, '123', 8_640_000_000_000_001]) {
    assert.throws(() => fixture({ accessExpiresAt }), /configuration/);
  }
  assert.throws(() => fixture({ mountMcp: null }), /configuration/);
  assert.throws(() => fixture({ resolveTokenSubject: 'email-is-not-a-binding' }), /configuration/);
});

test('trusted signed-subject mappings reach both delegated reads and callback exchange', async () => {
  const keys = await generateKeyPair('RS256');
  const jwk = { ...await exportJWK(keys.publicKey), kid: 'mapped-signing-key', alg: 'RS256' };
  const issued = Math.floor(Date.now() / 1000);
  const signedSubject = 'publisher-account-alice';
  const token = await new SignJWT({ iss: ISSUER, aud: `${PUBLIC}/agent/mcp`, sub: signedSubject,
    client_id: 'client_reference123456', sid: 'app_consent_reference123456', jti: 'mapped-token',
    iat: issued - 1, exp: issued + 300, scope: 'workouts:read' })
    .setProtectedHeader({ alg: 'RS256', kid: jwk.kid }).sign(keys.privateKey);
  let mapped = 0;
  const h = fixture({
    resolveTokenSubject: async (identity: Record<string, unknown>, details: { signal: AbortSignal }) => {
      assert.ok(Object.isFrozen(identity));
      assert.equal(identity.issuer, ISSUER);
      assert.equal(identity.subject, signedSubject);
      assert.equal(identity.clientId, 'client_reference123456');
      assert.equal(identity.audience, `${PUBLIC}/agent/mcp`);
      details.signal.throwIfAborted();
      mapped++;
      return PROVIDER_SUBJECT;
    },
    store: { async resolveConsent(identity: { subject: string }) {
      assert.equal(identity.subject, PROVIDER_SUBJECT);
      return { authorizationId: AUTHORIZATION, subject: SUBJECT,
        scopes: ['workouts:read'], expiresAt: Date.now() + 60_000 };
    } },
  }, async (url) => {
    if (String(url) === `${ISSUER}/oauth2/jwks`) return Response.json({ keys: [jwk] });
    assert.equal(String(url), `${ISSUER}/oauth2/token`);
    return Response.json({ access_token: token, token_type: 'bearer' });
  });
  const principal = await h.reference.verifyToken(token, { ...context(), audience: `${PUBLIC}/agent/mcp` });
  assert.ok(principal);
  assert.equal(principal.subject, SUBJECT);
  const verified = await h.reference.provider.exchangeCode({ code: 'synthetic-code-for-exchange',
    codeVerifier: 'v'.repeat(43), expectedUserId: PROVIDER_SUBJECT }, context());
  assert.equal(verified.subject, PROVIDER_SUBJECT);
  assert.equal(mapped, 2);
});


test('all durable store operations are required at startup', () => {
  for (const method of ['getState', 'begin', 'claimReset', 'completeReset', 'fail',
    'consume', 'cancel', 'complete', 'resolveConsent', 'revoke', 'isActive']) {
    assert.throws(() => fixture({ store: { [method]: undefined } }), /complete WorkOS connection store/);
  }
});

test('application session identifiers share the stores 256-character boundary', async t => {
  for (const field of ['sessionId', 'authVersion']) {
    for (const length of [256, 257]) {
      const h = fixture({ authenticateSession: async () => ({
        sessionId: 'browser-session', authVersion: 'login-version', appSubject: SUBJECT,
        accountLabel: 'Synthetic account', expiresAt: Date.now() + 3600_000,
        [field]: 'x'.repeat(length),
      }) });
      const request = await serve(t, h.reference);
      assert.equal((await request('/account/assistant')).status, length === 256 ? 200 : 401);
      assert.equal(h.calls.provider, 0);
    }
  }
});
