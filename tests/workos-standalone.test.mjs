import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createServer, request as httpRequest } from 'node:http';
import test from 'node:test';
import express from 'express';
import { createWorkOSStandaloneLoginRuntime as createStandalone } from '../src/workos-standalone-runtime.mjs';

const BASE = '/account/assistant';
const IDENTITY = BASE + '/identity';
const EXTERNAL = BASE + '/external-login';
const ORIGIN = 'https://publisher.example.invalid';
const ISSUER = 'https://standalone-test.authkit.app';
const CLIENT = 'client_standalone1234';
const EXTERNAL_AUTH = 'ext_auth_01J3X4Y5Z6A7B8C9D0E1F2G3H4';
const USER = 'user_standalone1234';
const csrf = response => {
  const match = /name="csrf" value="([^"]+)"/.exec(response.text); assert.ok(match); return match[1];
};
const stateCookie = response => response.headers['set-cookie'].find(value => value.startsWith('__Host-gateivo-standalone='))?.split(';')[0];
const context = () => ({ signal: new AbortController().signal });

async function fixture(t) {
  const account = { appSubject: 'alice', accountKey: 'account-alice-v1', authVersion: 'auth-v1', accountLabel: 'Alice <Account>',
    email: 'alice@example.invalid', emailVerified: true, enabled: true };
  const state = { account, session: { sessionId: 'session-alice-1', appSubject: 'alice', accountKey: account.accountKey,
    authVersion: account.authVersion, expiresAt: Date.now() + 3600_000, accountLabel: account.accountLabel },
    users: new Map(), binding: null, handoffs: new Map(), requests: [], storeCalls: [], complete: 0, fallthrough: 0 };
  const store = {
    async getBinding(input) {
      assert.deepEqual(Object.keys(input).sort(), ['accountKey', 'appSubject', 'issuer']);
      state.storeCalls.push(['get', input]); return state.binding
      && state.binding.issuer === input.issuer && state.binding.appSubject === input.appSubject
      && state.binding.accountKey === input.accountKey ? { ...state.binding } : null; },
    async bindAccount(input) {
      state.storeCalls.push(['bind', input]);
      if (state.afterBind) await state.afterBind();
      if (state.binding && JSON.stringify(state.binding) !== JSON.stringify(input)) throw Error('PRIVATE_BINDING_ERROR');
      state.binding = { ...input }; return { ...input };
    },
    async findBinding(input) { return state.binding?.issuer === input.issuer && state.binding.externalId === input.subject ? { ...state.binding } : null; },
    async beginHandoff(input) {
      if (state.handoffs.has(input.externalAuthIdHash) || [...state.handoffs.values()].some(row => row.browserNonceHash === input.browserNonceHash)) return false;
      state.handoffs.set(input.externalAuthIdHash, { ...input }); return true;
    },
    async consumeHandoff(input) {
      const row = state.handoffs.get(input.externalAuthIdHash);
      if (!row || row.consumed || row.expiresAt !== input.expiresAt || row.browserNonceHash !== input.browserNonceHash || row.expiresAt <= Date.now()) return false;
      row.consumed = true; row.claim = { ...input }; return true;
    },
  };
  const options = { appId: 'fixture-app', publicUrl: ORIGIN, issuer: ISSUER, clientId: CLIENT, apiKey: 'sk_test_standalone123456',
    secret: randomBytes(32), store, trustProxyHttps: true, accessExpiresAt: Date.now() + 3600_000,
    async authenticateSession(request) {
      return request.headers.cookie?.split(';').some(part => part.trim() === 'signed-in=yes') && state.session ? { ...state.session } : null;
    },
    async resolveLoginAccount(subject) { return state.account?.appSubject === subject ? { ...state.account } : null; },
  };
  const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
  const transport = async (input, init) => {
    const url = new URL(input); assert.equal(url.origin, 'https://api.workos.com');
    assert.equal(init.headers.Authorization, 'Bearer ' + options.apiKey); assert.equal(init.redirect, 'error');
    assert.ok(init.signal instanceof AbortSignal);
    const body = init.body ? JSON.parse(init.body) : null;
    state.requests.push({ method: init.method, path: url.pathname, body });
    if (state.providerOverride) { const result = await state.providerOverride(url, init, body); if (result) return result; }
    if (url.pathname.startsWith('/user_management/users/external_id/')) {
      const key = decodeURIComponent(url.pathname.split('/').at(-1));
      const user = state.users.get(key); return user ? json(user) : json({}, 404);
    }
    if (url.pathname === '/user_management/users' && init.method === 'POST') {
      const user = { id: USER, ...body }; state.users.set(body.external_id, user);
      if (state.afterProvision) await state.afterProvision();
      return json({ ...user, ...state.userPatch }, 201);
    }
    if (url.pathname === '/authkit/oauth2/complete') {
      state.complete++; if (state.afterComplete) await state.afterComplete();
      return json({ redirect_uri: state.redirect ?? ISSUER + '/oauth2/external/callback?state=provider-state' });
    }
    throw Error('Unexpected synthetic provider request.');
  };
  const servers = [];
  const mount = async (changed = {}, changedDependencies = {}) => {
    const module = createStandalone({ ...options, ...changed }, { fetch: transport, ...changedDependencies });
    const app = express(); app.use(module.router); app.use((_req, res) => { state.fallthrough++; res.status(418).end(); });
    const server = createServer(app); await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
    servers.push(server);
    const request = (path, patch = {}) => new Promise((resolve, reject) => {
      const headers = { host: new URL(ORIGIN).host, 'x-forwarded-proto': 'https', connection: 'close', ...patch.headers };
      let body = patch.body;
      if (patch.form) { body = new URLSearchParams(patch.form).toString(); headers['content-type'] = 'application/x-www-form-urlencoded'; }
      if (body !== undefined) headers['content-length'] = Buffer.byteLength(body);
      const req = httpRequest({ hostname: '127.0.0.1', port: server.address().port, path, method: patch.method ?? 'GET', headers, agent: false }, res => {
        const chunks = []; res.on('data', chunk => chunks.push(chunk));
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString() }));
      });
      req.on('error', reject); req.setTimeout(17000, () => req.destroy(Error('Test request timeout.'))); req.end(body);
    });
    return { module, request };
  };
  t.after(async () => { for (const server of servers) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); } });
  const { module, request } = await mount();
  const start = async (externalAuth = EXTERNAL_AUTH) => {
    const captured = await request(EXTERNAL + '?external_auth_id=' + externalAuth); assert.equal(captured.status, 303);
    const cookie = 'signed-in=yes; ' + stateCookie(captured);
    const shown = await request(EXTERNAL, { headers: { cookie } }); assert.equal(shown.status, 200);
    return { captured, shown, cookie, csrf: csrf(shown) };
  };
  const submit = (started, patch = {}) => request(EXTERNAL, { method: 'POST', headers: { origin: ORIGIN, cookie: started.cookie, ...patch.headers },
    form: { csrf: started.csrf, ...patch.form }, ...patch });
  const prepare = async () => {
    const shown = await request(IDENTITY, { headers: { cookie: 'signed-in=yes' } });
    return request(IDENTITY, { method: 'POST', headers: { origin: ORIGIN, cookie: 'signed-in=yes' }, form: { csrf: csrf(shown) } });
  };
  return { state, options, store, transport, module, request, mount, start, submit, prepare, json };
}

test('standalone capture is encrypted, strips URL identity and performs no provider work on GET', async t => {
  const f = await fixture(t);
  assert.equal((await f.request(BASE)).headers.location, BASE + '/login');
  const started = await f.start();
  assert.equal(started.captured.headers.location, EXTERNAL);
  assert.equal(started.captured.headers['referrer-policy'], 'no-referrer');
  const cookie = started.captured.headers['set-cookie'][0];
  for (const flag of ['Secure', 'HttpOnly', 'SameSite=Lax', 'Path=/', 'Max-Age=']) assert.ok(cookie.includes(flag));
  assert.ok(!cookie.includes(EXTERNAL_AUTH)); assert.ok(!cookie.includes(f.state.account.email));
  assert.match(started.shown.text, /Alice &lt;Account&gt;/);
  assert.equal((await f.request(BASE, { headers: { cookie: started.cookie } })).headers.location, EXTERNAL);
  assert.equal(f.state.requests.length, 0); assert.equal(f.state.handoffs.size, 0);
});

test('identity preparation produces an immutable opaque binding without granting assistant permission', async t => {
  const f = await fixture(t);
  assert.equal((await f.request(BASE, { headers: { cookie: 'signed-in=yes' } })).headers.location, IDENTITY);
  const result = await f.prepare(); assert.equal(result.status, 303); assert.equal(result.headers.location, BASE);
  assert.match(f.state.binding.externalId, /^gateivo:[a-f0-9]{64}$/);
  assert.ok(!f.state.binding.externalId.includes('alice'));
  assert.equal(f.state.binding.providerSubject, USER); assert.equal(f.state.complete, 0);
  assert.equal((await f.request(BASE, { headers: { cookie: 'signed-in=yes' } })).status, 418);
  assert.deepEqual(await f.module.resolveAccount({ issuer: ISSUER, appSubject: 'alice' }, context()), { providerSubject: USER, enabled: true });
  assert.equal(f.state.requests.filter(row => row.method === 'POST').length, 1);
});

test('external completion consumes once, reuses canonical binding and exposes only a pinned continuation link', async t => {
  const f = await fixture(t); const started = await f.start(); const result = await f.submit(started);
  assert.equal(result.status, 200); assert.equal(result.headers.location, undefined);
  assert.ok(result.text.includes(ISSUER + '/oauth2/external/callback?state=provider-state'));
  assert.ok(result.headers['content-security-policy'].includes("form-action 'self'"));
  assert.ok(!result.text.includes(EXTERNAL_AUTH)); assert.equal(f.state.complete, 1);
  const record = [...f.state.handoffs.values()][0];
  assert.equal(record.claim.accountKey, f.state.account.accountKey); assert.equal(record.claim.authVersion, f.state.account.authVersion);
  assert.ok(!JSON.stringify(record).includes(EXTERNAL_AUTH));
  assert.equal((await f.submit(started)).status, 409); assert.equal(f.state.complete, 1);
});

test('a recaptured external request ID remains consumed and is not reusable from a different browser nonce', async t => {
  const f = await fixture(t); assert.equal((await f.submit(await f.start())).status, 200);
  assert.equal((await f.submit(await f.start())).status, 409); assert.equal(f.state.complete, 1);
});

test('forged CSRF, extra identity fields and browser account switching fail before provider calls', async t => {
  const f = await fixture(t); const started = await f.start();
  assert.equal((await f.submit(started, { form: { csrf: 'forged' } })).status, 403);
  assert.equal((await f.submit(started, { form: { csrf: started.csrf, email: 'bob@example.invalid' } })).status, 400);
  f.state.session.sessionId = 'different-session';
  assert.equal((await f.submit(started)).status, 403); assert.equal(f.state.requests.length, 0);
});

test('cross-origin, unauthorized browser bearer, malformed pending state and missing HTTPS fail closed', async t => {
  const f = await fixture(t); const started = await f.start();
  assert.equal((await f.submit(started, { headers: { cookie: started.cookie, origin: 'https://attacker.example' } })).status, 403);
  assert.equal((await f.request(BASE, { headers: { authorization: 'Bearer irrelevant' } })).status, 403);
  assert.equal((await f.request(BASE, { headers: { 'x-forwarded-proto': 'http' } })).status, 403);
  assert.equal((await f.request(EXTERNAL, { headers: { cookie: 'signed-in=yes; __Host-gateivo-standalone=forged' } })).status, 400);
  assert.equal((await f.request(EXTERNAL + '?external_auth_id=' + EXTERNAL_AUTH + '&external_auth_id=' + EXTERNAL_AUTH)).status, 400);
  assert.equal(f.state.requests.length, 0);
});

for (const change of ['disabled', 'unverified', 'accountKey', 'authVersion', 'email']) {
  test(`current account ${change} changes during provisioning stop binding and completion`, async t => {
    const f = await fixture(t); const started = await f.start();
    f.state.afterProvision = () => {
      if (change === 'disabled') f.state.account.enabled = false;
      else if (change === 'unverified') f.state.account.emailVerified = false;
      else f.state.account[change] += '-changed';
    };
    const result = await f.submit(started); assert.equal(result.status, 403);
    assert.equal(f.state.binding, null); assert.equal(f.state.complete, 0);
  });
}

test('current session changes during binding prevent provider completion', async t => {
  const f = await fixture(t); const started = await f.start();
  f.state.afterBind = () => { f.state.session.sessionId = 'rotated-session'; };
  assert.equal((await f.submit(started)).status, 403); assert.equal(f.state.complete, 0);
});

test('changes during completion suppress the returned provider continuation', async t => {
  const f = await fixture(t); const started = await f.start();
  f.state.afterComplete = () => { f.state.account.enabled = false; };
  const result = await f.submit(started); assert.equal(result.status, 403);
  assert.ok(!result.text.includes('provider-state'));
});

test('provider user must match exact external identity and verified email; never relink by email', async t => {
  const f = await fixture(t); f.state.userPatch = { external_id: 'gateivo:' + 'f'.repeat(64) };
  assert.equal((await f.prepare()).status, 503); assert.equal(f.state.binding, null);
  assert.equal(f.state.requests.some(row => row.path.includes('email')), false);
});

test('account hooks require verified printable email and a nonempty safe label while allowing Unicode labels', async t => {
  const f = await fixture(t);
  const initial = { ...f.state.account };
  for (const patch of [{ email: 'álîce@example.invalid' }, { email: 'alice@localhost' }, { accountLabel: '' },
    { accountLabel: 'Alice\u0000private' }, { accountLabel: 'Alice\u0085private' }]) {
    f.state.account = { ...initial, ...patch };
    assert.equal((await f.request(IDENTITY, { headers: { cookie: 'signed-in=yes' } })).status, 403);
  }
  f.state.account = { ...initial, accountLabel: 'Älice — 山' };
  const shown = await f.request(IDENTITY, { headers: { cookie: 'signed-in=yes' } });
  assert.equal(shown.status, 200); assert.ok(shown.text.includes('Älice — 山')); assert.equal(f.state.requests.length, 0);
});

test('provider create conflict is resolved only by rereading the exact external identity', async t => {
  const f = await fixture(t); let creates = 0;
  f.state.providerOverride = (url, init, body) => {
    if (url.pathname === '/user_management/users' && init.method === 'POST') {
      creates++; f.state.users.set(body.external_id, { id: USER, ...body }); return f.json({}, 422);
    }
  };
  assert.equal((await f.prepare()).status, 303); assert.equal(creates, 1);
  assert.deepEqual(f.state.requests.map(row => row.method), ['GET', 'POST', 'GET']);
});

test('immutable provider binding conflicts cannot overwrite an existing identity', async t => {
  const f = await fixture(t); assert.equal((await f.prepare()).status, 303);
  const original = { ...f.state.binding }; f.state.users.get(original.externalId).id = 'user_otheraccount123';
  assert.equal((await f.prepare()).status, 403); assert.deepEqual(f.state.binding, original);
});

for (const redirect of ['https://attacker.example/oauth2/external/callback', ISSUER + '/unexpected',
  ISSUER + '/oauth2/external/callback#fragment', 'https://user:password@standalone-test.authkit.app/oauth2/external/callback']) {
  test(`untrusted provider redirect is withheld: ${new URL(redirect).pathname}`, async t => {
    const f = await fixture(t); f.state.redirect = redirect;
    const result = await f.submit(await f.start()); assert.equal(result.status, 503);
    assert.ok(!result.text.includes('attacker.example')); assert.ok(!result.text.includes('password'));
  });
}

test('token subject resolution requires pinned claims, exact stored binding and current account incarnation', async t => {
  const f = await fixture(t); assert.equal((await f.prepare()).status, 303);
  const identity = { issuer: ISSUER, clientId: CLIENT, audience: ORIGIN + '/agent/mcp', subject: f.state.binding.externalId };
  assert.equal(await f.module.resolveTokenSubject(identity, context()), USER);
  for (const patch of [{ issuer: 'https://wrong.authkit.app' }, { clientId: 'client_wrong123456' },
    { audience: ORIGIN + '/different' }, { subject: USER }, { subject: f.state.account.email }]) {
    assert.equal(await f.module.resolveTokenSubject({ ...identity, ...patch }, context()), null);
  }
  f.state.account.accountKey = 'new-alice-incarnation';
  assert.equal(await f.module.resolveTokenSubject(identity, context()), null);
  assert.equal(await f.module.resolveAccount({ issuer: ISSUER, appSubject: 'alice' }, context()), null);
});

test('external identities are stable for one key and segregated across app IDs and secret rotation', async t => {
  const f = await fixture(t); assert.equal((await f.prepare()).status, 303);
  const original = { ...f.state.binding };
  const same = await f.mount();
  assert.deepEqual(await same.module.resolveAccount({ issuer: ISSUER, appSubject: 'alice' }, context()), { providerSubject: USER, enabled: true });
  const other = await f.mount({ appId: 'another-app' });
  assert.equal(await other.module.resolveAccount({ issuer: ISSUER, appSubject: 'alice' }, context()), null);
  const rotated = await f.mount({ secret: randomBytes(32) });
  assert.equal(await rotated.module.resolveAccount({ issuer: ISSUER, appSubject: 'alice' }, context()), null);
  assert.deepEqual(f.state.binding, original);
});

test('the handoff also accepts the pinned documented completion path', async t => {
  const f = await fixture(t); f.state.redirect = ISSUER + '/oauth/authorize/complete?state=second-profile';
  const result = await f.submit(await f.start()); assert.equal(result.status, 200);
  assert.ok(result.text.includes('/oauth/authorize/complete?state=second-profile'));
});

test('cancelled mapping resolution fails closed and does not look up an account', async t => {
  const f = await fixture(t); assert.equal((await f.prepare()).status, 303);
  const controller = new AbortController(); controller.abort();
  assert.equal(await f.module.resolveTokenSubject({ issuer: ISSUER, clientId: CLIENT,
    audience: ORIGIN + '/agent/mcp', subject: f.state.binding.externalId }, { signal: controller.signal }), null);
  assert.equal(await f.module.resolveAccount({ issuer: ISSUER, appSubject: 'alice' }, { signal: controller.signal }), null);
});

test('a pending browser cookie cannot be replayed at a second issuer configuration', async t => {
  const f = await fixture(t); const started = await f.start();
  const another = await f.mount({ issuer: 'https://another-environment.authkit.app' });
  assert.equal((await another.request(EXTERNAL, { headers: { cookie: started.cookie } })).status, 400);
  assert.equal(f.state.requests.length, 0);
});

test('provider transports ignoring cancellation are still bounded and their late replies cannot bind identities', async t => {
  const f = await fixture(t); let release;
  f.state.providerOverride = () => new Promise(resolve => { release = resolve; });
  const before = performance.now(); const result = await f.prepare();
  assert.equal(result.status, 503); assert.ok(performance.now() - before < 10_000);
  assert.equal(f.state.binding, null); assert.equal(f.state.complete, 0);
  release(f.json({ id: USER, external_id: 'gateivo:' + 'a'.repeat(64), email: f.state.account.email, email_verified: true }));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.state.binding, null); assert.equal(f.state.complete, 0);
});

test('strict configuration rejects live keys, noncanonical origins, alternate token resources and missing store hooks', async t => {
  const f = await fixture(t);
  for (const patch of [{ apiKey: 'sk_live_1234567890' }, { publicUrl: ORIGIN + '/' }, { issuer: 'https://attacker.example' },
    { resource: ORIGIN + '/other' }, { secret: randomBytes(31) }, { store: {} }, { resolveLoginAccount: undefined },
    { clientId: 'client_invalid!' }, { trustProxyHttps: 'true' }, { accessExpiresAt: Date.now() - 1 }]) {
    assert.throws(() => createStandalone({ ...f.options, ...patch }, { fetch: f.transport }), TypeError);
  }
});

test('oversized provider JSON and provider exceptions produce sanitized errors', async t => {
  const f = await fixture(t); f.state.providerOverride = () => f.json({ private: 'PRIVATE'.repeat(12000) });
  const result = await f.prepare(); assert.equal(result.status, 503); assert.ok(!result.text.includes('PRIVATE'));
  f.state.providerOverride = () => { throw Error('PRIVATE_PROVIDER_FAILURE'); };
  const second = await f.prepare(); assert.equal(second.status, 503); assert.ok(!second.text.includes('PRIVATE'));
});
