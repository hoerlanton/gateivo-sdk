import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createServer, type IncomingHttpHeaders, type IncomingMessage, type ServerResponse } from 'node:http';
import { test, type TestContext } from 'node:test';
import { exportJWK, generateKeyPair, SignJWT, type JWK, type JWTHeaderParameters } from 'jose';
import { createOAuthJwtVerifier, type OAuthJwtVerifierOptions, type VerifiedOAuthIdentity } from '../src/oauth-jwt.js';
import { AccessError } from '../src/types.js';

const ISSUER = 'https://issuer.example.invalid/';
const RESOURCE = 'https://example-app.example.invalid/agent/mcp';
const pause = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));
const context = (signal = new AbortController().signal) => ({ audience: RESOURCE, signal });

async function signingKey(kid = randomUUID()) {
  const pair = await generateKeyPair('ES256', { extractable: true });
  const publicJwk = { ...await exportJWK(pair.publicKey), kid, alg: 'ES256', use: 'sig' };
  return { ...pair, publicJwk, kid };
}

async function harness(t: TestContext) {
  const key = await signingKey();
  let published: JWK[] = [key.publicJwk];
  const requests: Array<{ method: string | undefined; url: string | undefined; headers: IncomingHttpHeaders }> = [];
  let responder: ((req: IncomingMessage, res: ServerResponse) => void) | undefined;
  const server = createServer((req, res) => {
    requests.push({ method: req.method, url: req.url, headers: { ...req.headers } });
    if (responder) return responder(req, res);
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ keys: published }));
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => { server.off('error', reject); resolve(); });
  });
  t.after(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Missing test server address');
  const jwksUri = `http://127.0.0.1:${address.port}/jwks`;
  const baseOptions: OAuthJwtVerifierOptions = {
    appId: 'example-app', issuer: ISSUER, resource: RESOURCE, jwksUri, jwksCooldownMs: 0,
    resolveGrant: async (identity) => ({
      subject: `app-${identity.subject}`, scopes: ['workouts:read'], expiresAt: identity.expiresAt,
    }),
  };
  async function token(
    claims: Record<string, unknown> = {},
    headers: Partial<JWTHeaderParameters> = {},
    signer = key,
  ) {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({
      iss: ISSUER, sub: 'alice', aud: RESOURCE, exp: now + 300, iat: now,
      jti: randomUUID(), client_id: 'assistant-client', scope: 'workouts:read profile:read',
      ...claims,
    }).setProtectedHeader({ alg: 'ES256', typ: 'at+jwt', kid: signer.kid, ...headers }).sign(signer.privateKey);
  }
  return {
    key, token, requests, jwksUri, baseOptions,
    verifier: (overrides: Partial<OAuthJwtVerifierOptions> = {}) => createOAuthJwtVerifier({ ...baseOptions, ...overrides }),
    publish: (keys: JWK[]) => { published = keys; },
    respond: (handler: typeof responder) => { responder = handler; },
  };
}

async function rejectsTimeout(promise: Promise<unknown>) {
  await assert.rejects(promise, (error: unknown) => {
    assert.ok(error instanceof AccessError);
    assert.equal(error.code, 'TIMEOUT');
    assert.equal(error.message, 'TIMEOUT');
    assert.equal(error.cause, undefined);
    return true;
  });
}

test('OAuth JWT verifies an access token, sanitizes identity and maps it to the existing app account', async (t) => {
  const h = await harness(t);
  const expiresAt = Math.floor(Date.now() / 1000) * 1000 + 300_000;
  const grantExpiry = expiresAt - 10_000;
  let observed: VerifiedOAuthIdentity | undefined;
  const verify = h.verifier({ resolveGrant: async (identity, ctx) => {
    observed = identity;
    assert.ok(Object.isFrozen(identity));
    assert.ok(Object.isFrozen(identity.scopes));
    assert.equal(ctx.signal.aborted, false);
    return { subject: 'existing-rider-101', scopes: ['workouts:read'], expiresAt: grantExpiry };
  } });
  const token = await h.token({ exp: expiresAt / 1000, jti: 'token-1', email: 'private@example.invalid', secret: 'PRIVATE_CLAIM' });
  const result = await verify(token, context());
  assert.deepEqual(observed, {
    issuer: ISSUER, subject: 'alice', clientId: 'assistant-client', tokenId: 'token-1',
    audience: RESOURCE, scopes: ['workouts:read', 'profile:read'], expiresAt,
  });
  assert.deepEqual(result, { appId: 'example-app', subject: 'existing-rider-101', scopes: ['workouts:read'], expiresAt: grantExpiry });
  assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result?.scopes));
  assert.doesNotMatch(JSON.stringify({ observed, result }), /PRIVATE_CLAIM|private@example/);
});

test('OAuth routing generation comes only from the trusted resolver, never a bearer claim', async t => {
  const h = await harness(t);
  const token = await h.token({ authorizationId: 'attacker-selected-generation' });
  const trusted = randomUUID();
  const verify = h.verifier({ resolveGrant: async identity => ({ subject: 'rider', scopes: ['workouts:read'],
    expiresAt: identity.expiresAt, authorizationId: trusted }) });
  assert.equal((await verify(token, context()))?.authorizationId, trusted);
  assert.equal((await h.verifier()(token, context()))?.authorizationId, undefined);
  assert.equal(await h.verifier({ resolveGrant: async identity => ({ subject: 'rider', scopes: ['workouts:read'],
    expiresAt: identity.expiresAt, authorizationId: 'bad\nidentifier' }) })(token, context()), null);
});

test('OAuth JWT rejects invalid signatures and required claims before resolving an app grant', async (t) => {
  const h = await harness(t);
  let lookups = 0;
  const verify = h.verifier({ resolveGrant: async () => { lookups++; return null; } });
  const now = Math.floor(Date.now() / 1000);
  const invalidClaims: Record<string, unknown>[] = [
    { iss: 'https://attacker.example.invalid/' }, { aud: 'https://other-app.example.invalid/mcp' },
    { exp: now - 1 }, { nbf: now + 120 }, { iat: now + 120 }, { iat: now, exp: now + 3601 },
    { sub: '' }, { sub: 'alice\nbob' }, { jti: '' }, { client_id: '' },
    { scope: ['workouts:read'] }, { scope: 'workouts:read\nadmin' }, { scope: 'workouts:read  profile:read' },
    ...['iss', 'sub', 'aud', 'exp', 'iat', 'jti', 'client_id', 'scope'].map((claim) => ({ [claim]: undefined })),
    { exp: 'tomorrow' }, { iat: 'yesterday' }, { exp: now + 100.5 }, { iat: now - 0.5 },
  ];
  for (const claims of invalidClaims) {
    assert.equal(await verify(await h.token(claims), context()), null, `Rejected claims: ${JSON.stringify(claims)}`);
  }
  const impostor = await signingKey(h.key.kid);
  assert.equal(await verify(await h.token({}, {}, impostor), context()), null);
  for (const malformed of ['', 'not.a.jwt', 'x'.repeat(8193), 'Bearer abc.def.ghi']) {
    assert.equal(await verify(malformed, context()), null);
  }
  assert.equal(lookups, 0);
});

test('OAuth JWT refuses ID-token and symmetric/unsigned token substitution', async (t) => {
  const h = await harness(t);
  let lookups = 0;
  const verify = h.verifier({ resolveGrant: async () => { lookups++; return null; } });
  for (const typ of ['JWT', 'id+jwt', undefined]) {
    assert.equal(await verify(await h.token({}, { typ }), context()), null);
  }
  const now = Math.floor(Date.now() / 1000);
  const claims = { iss: ISSUER, sub: 'alice', aud: RESOURCE, exp: now + 60, iat: now, jti: 'substitution', client_id: 'assistant-client', scope: 'workouts:read' };
  const symmetric = await new SignJWT(claims)
    .setProtectedHeader({ alg: 'HS256', typ: 'at+jwt', kid: h.key.kid })
    .sign(new TextEncoder().encode(JSON.stringify(h.key.publicJwk)));
  assert.equal(await verify(symmetric, context()), null);
  const unsigned = `${Buffer.from(JSON.stringify({ alg: 'none', typ: 'at+jwt' })).toString('base64url')}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.`;
  assert.equal(await verify(unsigned, context()), null);
  assert.equal(lookups, 0);
});

test('OAuth JWT pins issuer and JWKS, ignoring token-supplied jku and embedded keys', async (t) => {
  const h = await harness(t);
  const verify = h.verifier();
  const attackerKey = await signingKey(h.key.kid);
  const untrustedHeaders = { jku: h.jwksUri.replace('/jwks', '/attacker'), jwk: attackerKey.publicJwk };
  assert.equal(await verify(await h.token({}, untrustedHeaders, attackerKey), context()), null);
  assert.ok(await verify(await h.token({}, untrustedHeaders), context()));
  assert.ok(h.requests.length > 0);
  assert.ok(h.requests.every((request) => request.url === '/jwks'));
});

test('OAuth JWT accepts the intended audience in an array but rejects a mismatched verifier context', async (t) => {
  const h = await harness(t);
  const verify = h.verifier();
  const token = await h.token({ aud: ['https://other.example.invalid/', RESOURCE] });
  assert.ok(await verify(token, context()));
  const before = h.requests.length;
  assert.equal(await verify(token, { ...context(), audience: 'https://other.example.invalid/' }), null);
  assert.equal(h.requests.length, before);
});

test('OAuth JWT caches public keys, supports key rotation and never forwards credentials to JWKS', async (t) => {
  const h = await harness(t);
  const verify = h.verifier();
  const token = await h.token();
  assert.ok(await verify(token, context()));
  assert.ok(await verify(token, context()));
  assert.equal(h.requests.length, 1);
  const rotated = await signingKey();
  h.publish([h.key.publicJwk, rotated.publicJwk]);
  assert.ok(await verify(await h.token({}, {}, rotated), context()));
  assert.equal(h.requests.length, 2);
  for (const request of h.requests) {
    assert.equal(request.method, 'GET');
    assert.equal(request.url, '/jwks');
    assert.equal(request.headers.authorization, undefined);
    assert.equal(request.headers.cookie, undefined);
    assert.ok(!JSON.stringify(request).includes(token));
    assert.doesNotMatch(JSON.stringify(request), /assistant-client|workouts:read/);
  }
});

test('OAuth JWT rechecks consent and account revocation on every verified request', async (t) => {
  const h = await harness(t);
  let active = true;
  let calls = 0;
  const verify = h.verifier({ resolveGrant: async (identity) => {
    calls++;
    return active ? { subject: 'rider-101', scopes: ['workouts:read'], expiresAt: identity.expiresAt } : null;
  } });
  const token = await h.token();
  assert.ok(await verify(token, context()));
  active = false;
  assert.equal(await verify(token, context()), null);
  active = true;
  assert.ok(await verify(token, context()));
  assert.equal(calls, 3);
  assert.equal(h.requests.length, 1, 'Only signing keys may be cached, never the live grant decision');
});

test('OAuth JWT keeps concurrent user and client grant mappings separate', async (t) => {
  const h = await harness(t);
  const seen: string[] = [];
  const verify = h.verifier({ resolveGrant: async (identity) => {
    await pause(identity.subject === 'alice' ? 12 : 1);
    seen.push(`${identity.subject}/${identity.clientId}`);
    const linked = new Map([
      ['alice/client-a', 'rider-101'], ['bob/client-b', 'rider-202'],
    ]).get(`${identity.subject}/${identity.clientId}`);
    return linked ? { subject: linked, scopes: ['workouts:read'], expiresAt: identity.expiresAt } : null;
  } });
  const tokens = await Promise.all([
    h.token({ sub: 'alice', client_id: 'client-a' }), h.token({ sub: 'bob', client_id: 'client-b' }),
    h.token({ sub: 'alice', client_id: 'client-b' }), h.token({ sub: 'bob', client_id: 'client-a' }),
  ]);
  const results = await Promise.all(tokens.map((token) => verify(token, context())));
  assert.deepEqual(results.map((principal) => principal?.subject ?? null), ['rider-101', 'rider-202', null, null]);
  assert.equal(seen.length, 4);
});

test('OAuth JWT rejects a grant that widens scopes and caps expiry at the signed token expiry', async (t) => {
  const h = await harness(t);
  const tokenExpiry = Math.floor(Date.now() / 1000) * 1000 + 300_000;
  const token = await h.token({ exp: tokenExpiry / 1000 });
  const widened = h.verifier({ resolveGrant: async () => ({ subject: 'rider-101', scopes: ['workouts:read', 'admin'], expiresAt: tokenExpiry }) });
  assert.equal(await widened(token, context()), null);
  const extended = h.verifier({ resolveGrant: async () => ({ subject: 'rider-101', scopes: ['workouts:read'], expiresAt: tokenExpiry + 60_000 }) });
  assert.equal((await extended(token, context()))?.expiresAt, tokenExpiry);
});

test('OAuth JWT fails closed on missing, malformed, expired or failed grant lookups', async (t) => {
  const h = await harness(t);
  const token = await h.token();
  const invalidGrants = [
    null, { subject: '', scopes: ['workouts:read'], expiresAt: Date.now() + 60_000 },
    { subject: 'rider-101', scopes: ['workouts:read'], expiresAt: Date.now() - 1 },
    { subject: 'rider-101', scopes: ['workouts:read'], expiresAt: Infinity },
    { subject: 'rider-101', scopes: ['bad\nscope'], expiresAt: Date.now() + 60_000 },
  ];
  for (const grant of invalidGrants) {
    assert.equal(await h.verifier({ resolveGrant: async () => grant })(token, context()), null);
  }
  const failed = h.verifier({ resolveGrant: async () => { throw new Error('SECRET provider response and credential'); } });
  assert.equal(await failed(token, context()), null);
});

test('OAuth JWT grant lookup timeout is finite, redacted and aborts its signal', { timeout: 3000 }, async (t) => {
  const h = await harness(t);
  let hang = false;
  let observedSignal: AbortSignal | undefined;
  const verify = h.verifier({ timeoutMs: 100, resolveGrant: async (identity, ctx) => {
    if (!hang) return { subject: 'rider-101', scopes: ['workouts:read'], expiresAt: identity.expiresAt };
    observedSignal = ctx.signal;
    return new Promise(() => {});
  } });
  const token = await h.token();
  assert.ok(await verify(token, context()));
  hang = true;
  const started = Date.now();
  await rejectsTimeout(verify(token, context()));
  assert.ok(Date.now() - started < 2000);
  assert.equal(observedSignal?.aborted, true);
});

test('OAuth JWT caller cancellation prevents or interrupts a grant lookup', { timeout: 3000 }, async (t) => {
  const h = await harness(t);
  let calls = 0;
  let observedSignal: AbortSignal | undefined;
  let started!: () => void;
  const entered = new Promise<void>((resolve) => { started = resolve; });
  const verify = h.verifier({ resolveGrant: async (_identity, ctx) => {
    calls++;
    observedSignal = ctx.signal;
    started();
    return new Promise(() => {});
  } });
  const token = await h.token();
  const alreadyAborted = new AbortController();
  alreadyAborted.abort('PRIVATE abort reason');
  await rejectsTimeout(verify(token, context(alreadyAborted.signal)));
  assert.equal(calls, 0);
  assert.equal(h.requests.length, 0);
  const controller = new AbortController();
  const pending = verify(token, context(controller.signal));
  await entered;
  controller.abort('PRIVATE abort reason');
  await rejectsTimeout(pending);
  assert.equal(observedSignal?.aborted, true);
});

test('OAuth JWT denies access when token or grant expires during its account lookup', { timeout: 5000 }, async (t) => {
  const h = await harness(t);
  const grantExpired = h.verifier({ resolveGrant: async () => {
    const expiresAt = Date.now() + 15;
    await pause(30);
    return { subject: 'rider-101', scopes: ['workouts:read'], expiresAt };
  } });
  assert.equal(await grantExpired(await h.token(), context()), null);
  const expiresAt = (Math.ceil(Date.now() / 1000) + 1) * 1000;
  let entered = false;
  const tokenExpired = h.verifier({ timeoutMs: 3000, resolveGrant: async () => {
    entered = true;
    await pause(Math.max(0, expiresAt - Date.now()) + 30);
    return { subject: 'rider-101', scopes: ['workouts:read'], expiresAt: expiresAt + 60_000 };
  } });
  assert.equal(await tokenExpired(await h.token({ exp: expiresAt / 1000 }), context()), null);
  assert.equal(entered, true);
});

test('OAuth JWT rejects JWKS redirects instead of following an unpinned location', async (t) => {
  const h = await harness(t);
  h.respond((_req, res) => {
    res.writeHead(302, { location: h.jwksUri.replace('/jwks', '/redirected-keys') });
    res.end();
  });
  assert.equal(await h.verifier()(await h.token(), context()), null);
  assert.deepEqual(h.requests.map((request) => request.url), ['/jwks']);
});

test('OAuth JWT bounds a stalled JWKS endpoint without invoking the grant lookup', { timeout: 3000 }, async (t) => {
  const h = await harness(t);
  h.respond(() => {});
  let called = false;
  const verify = h.verifier({ timeoutMs: 60, resolveGrant: async () => { called = true; return null; } });
  await rejectsTimeout(verify(await h.token(), context()));
  assert.equal(called, false);
});

test('OAuth JWT rejects unsafe configuration before fetching any signing keys', async (t) => {
  const h = await harness(t);
  const invalidOptions: Partial<OAuthJwtVerifierOptions>[] = [
    { appId: '' }, { issuer: 'http://public.example.invalid/' }, { resource: 'http://public.example.invalid/mcp' },
    { jwksUri: 'http://public.example.invalid/jwks' }, { jwksUri: 'https://user:password@example.invalid/jwks' },
    { jwksUri: 'https://example.invalid/jwks?token=secret' }, { jwksUri: 'https://example.invalid/jwks#fragment' },
    { algorithms: [] }, { algorithms: ['HS256'] as never },
    { timeoutMs: 0 }, { timeoutMs: 30001 }, { timeoutMs: NaN },
    { maxTokenLifetimeSeconds: 0 }, { maxTokenLifetimeSeconds: 86401 },
    { jwksCooldownMs: -1 }, { jwksCacheMaxAgeMs: 0 },
    { resolveGrant: undefined as unknown as OAuthJwtVerifierOptions['resolveGrant'] },
  ];
  for (const options of invalidOptions) assert.throws(() => h.verifier(options));
  assert.equal(h.requests.length, 0);
});
