import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { createServer, request as httpRequest } from 'node:http';
import { test } from 'node:test';
import express from 'express';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { AccessError } from '../src/sdk.ts';
import { createWorkOSConnection } from '../src/workos-connect-express.ts';

const BASE = '/account/assistant';
const PUBLIC = 'https://publisher-diagnostics.example.invalid';
const ISSUER = 'https://diagnostics.authkit.app';
const PROVIDER_SUBJECT = 'user_syntheticdiagnostics1234';
const EMAIL = 'alice@diagnostics.example.invalid';
const REASONS = ['UNAUTHENTICATED', 'FORBIDDEN', 'INVALID_ARGUMENT', 'NOT_FOUND',
  'UNAVAILABLE', 'TIMEOUT', 'OUTPUT_LIMIT'];
const decode = value => value.replace(/&quot;/g, '"').replace(/&#39;/g, "'")
  .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>');

function fieldsFor(html, action) {
  for (const form of html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)) {
    const destination = form[1].match(/\baction="([^"]*)"/i)?.[1];
    if (!destination || new URL(decode(destination), PUBLIC).pathname !== action) continue;
    return Object.fromEntries([...form[2].matchAll(/<input\b([^>]*)>/gi)].map(input => {
      const name = input[1].match(/\bname="([^"]*)"/i)?.[1];
      const value = input[1].match(/\bvalue="([^"]*)"/i)?.[1];
      assert.ok(name && value !== undefined);
      return [decode(name), decode(value)];
    }));
  }
  assert.fail('Expected approval form');
}

async function browserFor(t, router) {
  const app = express(); app.use(router);
  const server = createServer(app);
  await new Promise((resolve, reject) => {
    server.once('error', reject); server.listen(0, '127.0.0.1', resolve);
  });
  t.after(async () => {
    server.closeAllConnections(); await new Promise(resolve => server.close(resolve));
  });
  const jar = new Map();
  const cookies = () => [...jar].map(([name, value]) => `${name}=${value}`).join('; ');
  const request = (route, { fields, cookie = cookies(), update = true } = {}) => new Promise((resolve, reject) => {
    const body = fields === undefined ? undefined : new URLSearchParams(fields).toString();
    const req = httpRequest({ host: '127.0.0.1', port: server.address().port, path: route,
      method: body === undefined ? 'GET' : 'POST', agent: false,
      headers: { host: new URL(PUBLIC).host, 'x-forwarded-proto': 'https',
        ...(cookie ? { cookie } : {}), ...(body === undefined ? {} : {
          origin: PUBLIC, 'content-type': 'application/x-www-form-urlencoded',
          'content-length': Buffer.byteLength(body),
        }) },
    }, res => {
      const chunks = []; let bytes = 0;
      res.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > 256 * 1024) req.destroy(new Error('Test response exceeded its bound'));
        else chunks.push(chunk);
      });
      res.on('error', reject);
      res.on('end', () => {
        if (update) for (const header of res.headers['set-cookie'] ?? []) {
          const pair = header.split(';')[0], at = pair.indexOf('=');
          if (at > 0) {
            if (pair.slice(at + 1)) jar.set(pair.slice(0, at), pair.slice(at + 1));
            else jar.delete(pair.slice(0, at));
          }
        }
        resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString('utf8'), headers: res.headers });
      });
    });
    req.once('error', reject);
    req.setTimeout(5000, () => req.destroy(new Error('Diagnostic HTTP request timed out')));
    req.end(body);
  });
  return { request, cookies };
}

async function fixture(t, { onConsentDiagnostic } = {}) {
  const state = { phase: 'idle', revision: randomUUID(), eligible: true,
    consumeCalls: 0, completeCalls: 0, failCalls: 0, grants: 0 };
  const session = { sessionId: randomUUID(), authVersion: randomBytes(32).toString('base64url'),
    appSubject: randomUUID(), accountLabel: EMAIL, expiresAt: Date.now() + 3600_000 };
  const settings = { appId: 'workouts', issuer: ISSUER, clientId: 'client_syntheticdiagnostics1234',
    applicationId: 'connect_app_syntheticdiagnostics1234', apiKey: 'sk_test_SYNTHETIC_DIAGNOSTICS_ONLY',
    publicUrl: PUBLIC, resource: PUBLIC + '/agent/mcp', accessTokenType: null };
  const key = await generateKeyPair('RS256', { extractable: true });
  const jwk = { ...await exportJWK(key.publicKey), kid: 'diagnostics-test-key', alg: 'RS256', use: 'sig' };
  let issued, destination;
  const store = {
    async getState() { return { phase: state.phase, revision: state.revision, active: state.grants > 0 }; },
    async begin(input) {
      assert.equal(state.phase, 'idle'); assert.equal(input.expectedRevision, state.revision);
      state.phase = 'reset_pending'; state.ticket = Object.freeze({ ...input, operationId: randomUUID() });
      return state.ticket;
    },
    async claimReset(ticket) { assert.equal(ticket, state.ticket); state.phase = 'reset_dispatched'; return true; },
    async completeReset(ticket) { assert.equal(ticket, state.ticket); state.phase = 'awaiting_consent'; return true; },
    async consume(input) {
      if (state.phase !== 'awaiting_consent' || ['operationId', 'stateHash', 'sessionId', 'authVersion', 'appSubject']
        .some(name => input[name] !== state.ticket[name])) return null;
      state.phase = 'exchanging'; state.consumeCalls++; return state.ticket;
    },
    async complete(ticket, identity, context) {
      assert.equal(ticket, state.ticket); assert.ok(context.signal instanceof AbortSignal); state.completeCalls++;
      if (state.completeError) throw state.completeError;
      assert.equal(identity.subject, PROVIDER_SUBJECT); state.grants++; state.phase = 'active';
    },
    async fail(ticket, context) {
      assert.equal(ticket, state.ticket); assert.ok(context.signal instanceof AbortSignal); state.failCalls++;
      if (state.failError) throw state.failError;
      state.phase = 'blocked';
    },
    ...Object.fromEntries(['cancel', 'resolveConsent', 'revoke', 'isActive'].map(name => [name, async () => {
      throw new Error(`Unexpected ${name} in callback diagnostic fixture`);
    }])),
  };
  const integration = createWorkOSConnection({ ...settings, secret: randomBytes(32), requiredScopes: ['workouts:read'],
    trustProxyHttps: true, mountMcp: false, store,
    async authenticateSession() { return state.eligible ? session : null; },
    async resolveAccount() { return state.eligible ? { providerSubject: PROVIDER_SUBJECT, enabled: true } : null; },
  }, { onConsentDiagnostic, async fetch(input, init) {
    const url = new URL(input);
    if (url.origin === 'https://api.workos.com') {
      assert.equal(new Headers(init.headers).get('authorization'), 'Bearer ' + settings.apiKey);
      if (url.pathname === '/connect/applications/' + settings.clientId) {
        return Response.json({ id: settings.applicationId, client_id: settings.clientId });
      }
      if (url.pathname === `/user_management/users/${PROVIDER_SUBJECT}/authorized_applications`) {
        return Response.json({ data: [], list_metadata: { before: null, after: null } });
      }
    }
    if (url.origin === ISSUER) {
      assert.equal(new Headers(init.headers).has('authorization'), false);
      if (url.pathname === '/oauth2/jwks') return Response.json({ keys: [jwk] });
      if (url.pathname === '/oauth2/token') {
        if (state.exchangeError) return Response.json({ error: 'PRIVATE_PROVIDER_BODY',
          access_token: 'PRIVATE_ACCESS_TOKEN', refresh_token: 'PRIVATE_REFRESH_TOKEN' }, { status: 400 });
        const form = new URLSearchParams(init.body);
        assert.equal(form.get('code'), issued.code);
        assert.equal(createHash('sha256').update(form.get('code_verifier')).digest('base64url'),
          destination.searchParams.get('code_challenge'));
        if (state.loseAuthority) state.eligible = false;
        return Response.json({ access_token: issued.token, token_type: 'bearer',
          refresh_token: 'PRIVATE_REFRESH_TOKEN', id_token: 'PRIVATE_ID_TOKEN' });
      }
    }
    assert.fail('Unexpected synthetic provider destination');
  } });
  const browser = await browserFor(t, integration.router);
  const page = await browser.request(BASE); assert.equal(page.status, 200);
  const started = await browser.request(BASE + '/start', { fields: fieldsFor(page.text, BASE + '/start') });
  assert.equal(started.status, 303);
  destination = new URL(started.headers.location);
  const now = Math.floor(Date.now() / 1000);
  issued = { code: 'synthetic_' + randomUUID(), token: await new SignJWT({
    iss: ISSUER, aud: settings.resource, sub: PROVIDER_SUBJECT, client_id: settings.clientId,
    sid: 'app_consent_' + randomUUID().replaceAll('-', ''), iat: now - 1, exp: now + 600,
    jti: randomUUID(), scope: 'openid offline_access workouts:read',
  }).setProtectedHeader({ alg: 'RS256', kid: jwk.kid }).sign(key.privateKey) };
  const cookie = browser.cookies();
  const route = BASE + '/callback?' + new URLSearchParams({ code: issued.code, state: destination.searchParams.get('state') });
  return { state, session, settings, issued, cookie, destination, browser,
    finish: () => browser.request(route, { cookie, update: false }) };
}

test('callback diagnostics identify the failing stage without changing the consumed fence', async t => {
  const cases = [
    { phase: 'token_exchange', reason: 'UNAUTHENTICATED', status: 503, change: f => { f.state.exchangeError = true; } },
    { phase: 'authority_recheck', reason: 'FORBIDDEN', status: 403, change: f => { f.state.loseAuthority = true; } },
    { phase: 'store_complete', reason: 'UNAVAILABLE', status: 503, change: f => { f.state.completeError = new AccessError('UNAVAILABLE'); } },
  ];
  for (const scenario of cases) {
    const events = [], f = await fixture(t, { onConsentDiagnostic: event => { events.push(event); } });
    scenario.change(f);
    const response = await f.finish();
    assert.equal(response.status, scenario.status); assert.equal(response.headers.location, undefined);
    assert.deepEqual(events, [{ operation: 'consent_callback', phase: scenario.phase, reason: scenario.reason }]);
    assert.equal(Object.isFrozen(events[0]), true);
    assert.equal(f.state.phase, 'blocked'); assert.equal(f.state.grants, 0);
    assert.equal(f.state.failCalls, 1); assert.equal(f.state.consumeCalls, 1);
    assert.ok(response.headers['set-cookie'].some(value => value.startsWith('__Host-gateivo-workos-reference=;')));
    const exposed = JSON.stringify(events) + response.text;
    for (const value of [f.issued.code, f.issued.token, f.cookie, f.destination.searchParams.get('state'),
      f.state.ticket.stateHash, f.state.ticket.operationId, f.session.sessionId, f.session.authVersion,
      f.session.appSubject, PROVIDER_SUBJECT, EMAIL, f.settings.apiKey,
      'PRIVATE_PROVIDER_BODY', 'PRIVATE_ACCESS_TOKEN', 'PRIVATE_REFRESH_TOKEN', 'PRIVATE_ID_TOKEN']) {
      assert.ok(!exposed.includes(value));
    }
    assert.ok(!JSON.stringify(events).includes(PUBLIC));
    assert.ok(!JSON.stringify(events).includes(ISSUER));
    f.state.eligible = true;
    assert.match((await f.browser.request(BASE)).text, /administrator review/);
    assert.equal((await f.finish()).status, 400); assert.equal(f.state.failCalls, 1); assert.equal(events.length, 1);
  }
});

test('diagnostics trust whitelisted AccessError data properties and omit private error details', async t => {
  const cases = [...REASONS.map(reason => ({ error: new AccessError(reason), reason })),
    { error: new AccessError('PRIVATE_UNKNOWN_CODE'), reason: 'internal_error' },
    { error: Object.assign(Error('PRIVATE_MESSAGE'), { code: 'FORBIDDEN' }), reason: 'internal_error' }];
  for (const { error, reason } of cases) {
    error.message = 'PRIVATE_MESSAGE'; error.cause = { token: 'PRIVATE_TOKEN', email: EMAIL };
    error.url = 'https://private.invalid/PRIVATE_URL';
    const events = [], f = await fixture(t, { onConsentDiagnostic: event => { events.push(event); } });
    f.state.completeError = error;
    const response = await f.finish(); assert.equal(response.status, reason === 'FORBIDDEN' ? 403 : 503);
    assert.deepEqual(events, [{ operation: 'consent_callback', phase: 'store_complete', reason }]);
    assert.doesNotMatch(JSON.stringify(events) + response.text, /PRIVATE_|alice@|user_synthetic|app_consent_/);
    for (const code of REASONS) assert.ok(!response.text.includes(code));
    assert.equal(f.state.failCalls, 1); assert.equal(f.state.phase, 'blocked'); assert.equal(f.state.grants, 0);
  }
});

test('observer throws, rejected promises and mutations cannot alter failure, cookies or replay denial', async t => {
  let baseline;
  for (const onConsentDiagnostic of [undefined, () => { throw Error('PRIVATE_OBSERVER'); },
    async () => { throw Error('PRIVATE_OBSERVER'); }, event => { event.reason = 'PRIVATE_MUTATION'; }]) {
    const f = await fixture(t, { onConsentDiagnostic }); f.state.completeError = Error('PRIVATE_DATABASE_ERROR');
    const response = await f.finish(); baseline ??= response;
    assert.equal(response.status, baseline.status); assert.equal(response.text, baseline.text);
    assert.deepEqual(response.headers['set-cookie'], baseline.headers['set-cookie']);
    assert.equal(response.headers.location, undefined);
    assert.equal(f.state.phase, 'blocked'); assert.equal(f.state.grants, 0); assert.equal(f.state.failCalls, 1);
    assert.equal((await f.finish()).status, 400); assert.equal(f.state.failCalls, 1);
  }
});

test('failure-store errors retain the consumed fence and original diagnostic', async t => {
  const events = [], f = await fixture(t, { onConsentDiagnostic: event => { events.push(event); } });
  f.state.exchangeError = true; f.state.failError = Error('PRIVATE_FAIL_STORE');
  assert.equal((await f.finish()).status, 503); assert.equal(f.state.phase, 'exchanging'); assert.equal(f.state.grants, 0);
  assert.equal(f.state.failCalls, 1);
  assert.deepEqual(events, [{ operation: 'consent_callback', phase: 'token_exchange', reason: 'UNAUTHENTICATED' }]);
  assert.match((await f.browser.request(BASE)).text, /administrator review/); assert.equal((await f.finish()).status, 400);
});

test('successful callbacks complete once without emitting diagnostics', async t => {
  const events = [], f = await fixture(t, { onConsentDiagnostic: event => { events.push(event); } });
  const response = await f.finish();
  assert.equal(response.status, 303); assert.equal(response.headers.location, PUBLIC + BASE);
  assert.equal(f.state.phase, 'active'); assert.equal(f.state.grants, 1);
  assert.equal(f.state.completeCalls, 1); assert.equal(f.state.failCalls, 0); assert.deepEqual(events, []);
  assert.equal((await f.finish()).status, 400); assert.equal(f.state.grants, 1);
});
