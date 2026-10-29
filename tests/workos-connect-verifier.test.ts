import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { exportJWK, generateKeyPair, SignJWT, type JWK, type JWTHeaderParameters } from 'jose';
import { AccessError } from '../src/types.js';
import type { WorkOSConnectTokenSubjectResolver } from '../src/workos-connect.js';
import {
  createWorkOSConnectVerifier, type VerifiedWorkOSConnectIdentity, type WorkOSConnectVerifierOptions,
} from '../src/workos-connect.js';

const ISSUER = 'https://identity.example.invalid';
const RESOURCE = 'https://gateivo.example.invalid/agent/mcp';
const CLIENT = 'client_00000000000000000000000001';
const USER = 'user_00000000000000000000000002';
const EXTERNAL_SUBJECT = 'external|fixture-alice';
const CONSENT = 'app_consent_00000000000000000000000003';
const context = (signal = new AbortController().signal) => ({ audience: RESOURCE, signal });
const pause = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

async function signingKey(kid = randomUUID()) {
  const pair = await generateKeyPair('RS256', { extractable: true });
  return { ...pair, kid, publicJwk: { ...await exportJWK(pair.publicKey), kid, alg: 'RS256', use: 'sig' } };
}

async function harness() {
  const key = await signingKey();
  let published: JWK[] = [key.publicJwk];
  let responder: ((input: Parameters<typeof fetch>[0], init?: RequestInit) => Promise<Response>) | undefined;
  const requests: Array<{ url: string; init?: RequestInit }> = [];
  const transport: typeof fetch = async (input, init) => {
    requests.push({ url: String(input), init });
    return responder ? responder(input, init) : Response.json({ keys: published });
  };
  const baseOptions: WorkOSConnectVerifierOptions = {
    appId: 'example-app', issuer: ISSUER, clientId: CLIENT, resource: RESOURCE,
    accessTokenType: null, jwksCooldownMs: 0,
    resolveConsent: async (identity) => ({ subject: 'fixture-alice', scopes: ['workouts:read'], expiresAt: identity.expiresAt }),
  };
  const token = async (claims: Record<string, unknown> = {}, headers: Partial<JWTHeaderParameters> = {}, signer = key) => {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({
      iss: ISSUER, aud: RESOURCE, sub: USER, client_id: CLIENT, sid: CONSENT,
      jti: randomUUID(), iat: now, exp: now + 300, scope: 'workouts:read offline_access', ...claims,
    }).setProtectedHeader({ alg: 'RS256', kid: signer.kid, ...headers }).sign(signer.privateKey);
  };
  return {
    key, token, requests, baseOptions,
    verifier: (options: Partial<WorkOSConnectVerifierOptions> = {}) => createWorkOSConnectVerifier({ ...baseOptions, ...options }, { fetch: transport }),
    publish: (next: JWK[]) => { published = next; },
    respond: (next: typeof responder) => { responder = next; },
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

test('WorkOS Connect passes only verified frozen consent identity and narrows principal expiry/scopes', async () => {
  const h = await harness();
  let captured: VerifiedWorkOSConnectIdentity | undefined;
  const tokenExpiry = Math.floor(Date.now() / 1000) * 1000 + 300_000;
  const grantExpiry = tokenExpiry - 1000;
  const verify = h.verifier({ resolveConsent: async (identity, ctx) => {
    captured = identity;
    assert.equal(ctx.signal.aborted, false);
    assert.ok(Object.isFrozen(identity));
    assert.ok(Object.isFrozen(identity.scopes));
    return { subject: 'existing-fixture-account', scopes: ['workouts:read'], expiresAt: grantExpiry };
  } });
  const token = await h.token({ exp: tokenExpiry / 1000, jti: 'token-1', email: 'private@example.invalid', secret: 'PRIVATE' });
  const principal = await verify(token, context());
  assert.deepEqual(captured, {
    issuer: ISSUER, audience: RESOURCE, subject: USER, clientId: CLIENT, consentId: CONSENT,
    tokenId: 'token-1', scopes: ['workouts:read', 'offline_access'], expiresAt: tokenExpiry,
  });
  assert.deepEqual(principal, { appId: 'example-app', subject: 'existing-fixture-account', scopes: ['workouts:read'], expiresAt: grantExpiry });
  assert.ok(Object.isFrozen(principal));
  assert.ok(Object.isFrozen(principal?.scopes));
  assert.doesNotMatch(JSON.stringify({ captured, principal }), /private@|PRIVATE/);
  assert.ok(!JSON.stringify(captured).includes(token));
});

test('WorkOS routing generation is selected only by the verified consent lookup', async () => {
  const h = await harness();
  const token = await h.token({ authorizationId: 'untrusted-generation' });
  const trusted = randomUUID();
  const verify = h.verifier({ resolveConsent: async identity => ({ subject: 'fixture-alice', scopes: ['workouts:read'],
    expiresAt: identity.expiresAt, authorizationId: trusted }) });
  assert.equal((await verify(token, context()))?.authorizationId, trusted);
  assert.equal((await h.verifier()(token, context()))?.authorizationId, undefined);
  assert.equal(await h.verifier({ resolveConsent: async identity => ({ subject: 'fixture-alice', scopes: ['workouts:read'],
    expiresAt: identity.expiresAt, authorizationId: 'bad\nidentifier' }) })(token, context()), null);
});

test('WorkOS Connect maps only the frozen verified subject context before resolving the exact consent', async () => {
  const h = await harness();
  let captured: Parameters<WorkOSConnectTokenSubjectResolver>[0] | undefined;
  let mappingSignal: AbortSignal | undefined;
  const events: string[] = [];
  const verify = h.verifier({
    resolveTokenSubject: async (identity, ctx) => {
      events.push('subject'); captured = identity; mappingSignal = ctx.signal;
      assert.ok(Object.isFrozen(identity));
      assert.equal(ctx.signal.aborted, false);
      return USER;
    },
    resolveConsent: async (identity, ctx) => {
      events.push('consent');
      assert.equal(identity.subject, USER);
      assert.equal(identity.consentId, CONSENT);
      assert.equal(identity.tokenId, 'mapped-token');
      assert.deepEqual(identity.scopes, ['workouts:read', 'offline_access']);
      assert.equal(ctx.signal, mappingSignal);
      assert.ok(Object.isFrozen(identity));
      return { subject: 'approved-local-account', scopes: ['workouts:read'], expiresAt: identity.expiresAt };
    },
  });
  const signed = await h.token({ sub: EXTERNAL_SUBJECT, jti: 'mapped-token', email: 'PRIVATE_EMAIL', secret: 'PRIVATE_CLAIM' });
  const principal = await verify(signed, context());
  assert.deepEqual(captured, { issuer: ISSUER, clientId: CLIENT, audience: RESOURCE, subject: EXTERNAL_SUBJECT });
  assert.deepEqual(events, ['subject', 'consent']);
  assert.equal(principal?.subject, 'approved-local-account');
  assert.doesNotMatch(JSON.stringify(captured), /PRIVATE_|mapped-token|app_consent_|scope/);
  assert.ok(!JSON.stringify(captured).includes(signed));
});

test('WorkOS Connect keeps strict native subjects by default and never bypasses a configured subject resolver', async () => {
  const h = await harness();
  assert.equal(await h.verifier()(await h.token({ sub: EXTERNAL_SUBJECT }), context()), null);
  assert.ok(await h.verifier()(await h.token(), context()));
  const seen: string[] = [];
  const verify = h.verifier({ resolveTokenSubject: async identity => { seen.push(identity.subject); return USER; } });
  for (const subject of [EXTERNAL_SUBJECT, USER, '!', '~', 'x'.repeat(512)]) {
    assert.ok(await verify(await h.token({ sub: subject }), context()));
  }
  assert.deepEqual(seen, [EXTERNAL_SUBJECT, USER, '!', '~', 'x'.repeat(512)]);
  let consentCalls = 0;
  assert.equal(await h.verifier({ resolveTokenSubject: async () => null,
    resolveConsent: async () => { consentCalls++; return null; } })(await h.token(), context()), null);
  assert.equal(consentCalls, 0);
});

test('WorkOS Connect rejects malformed signed subjects before either resolver', async () => {
  const h = await harness();
  let subjectCalls = 0;
  let consentCalls = 0;
  const verify = h.verifier({ resolveTokenSubject: async () => { subjectCalls++; return USER; },
    resolveConsent: async () => { consentCalls++; return null; } });
  for (const sub of [undefined, null, 123, {}, [], '', ' ', 'has space', 'has\ncontrol', 'has\u0000control',
    'has\u007fcontrol', 'non-ascii-é', 'x'.repeat(513)]) {
    assert.equal(await verify(await h.token({ sub }), context()), null, `Invalid subject: ${JSON.stringify(sub)}`);
  }
  assert.equal(subjectCalls, 0);
  assert.equal(consentCalls, 0);
});

test('WorkOS Connect verifies signature, protocol, scopes and time before subject mapping', async () => {
  const h = await harness();
  let subjectCalls = 0;
  let consentCalls = 0;
  const verify = h.verifier({ resolveTokenSubject: async () => { subjectCalls++; return USER; },
    resolveConsent: async () => { consentCalls++; return null; } });
  const now = Math.floor(Date.now() / 1000);
  const invalid: Record<string, unknown>[] = [
    { iss: 'https://attacker.invalid' }, { aud: CLIENT }, { aud: [RESOURCE] }, { client_id: 'client_otherclient1234' },
    { sid: 'session_00000000000000000000000001' }, { jti: 'bad\nidentifier' }, { act: {} }, { impersonator: {} },
    { exp: now - 1 }, { nbf: now + 60 }, { iat: now + 30 }, { iat: now, exp: now + 3601 }, { exp: now + 0.5 },
    { scope: '' }, { scope: ['workouts:read'] }, { scope: 'workouts:read  offline_access' }, { scope: 'workouts:read\nadmin' },
    ...['iss', 'aud', 'client_id', 'sid', 'jti', 'iat', 'exp', 'scope'].map(claim => ({ [claim]: undefined })),
  ];
  for (const claims of invalid) {
    assert.equal(await verify(await h.token({ sub: EXTERNAL_SUBJECT, ...claims }), context()), null,
      `Invalid claims before mapping: ${JSON.stringify(claims)}`);
  }
  const rogue = await signingKey(h.key.kid);
  assert.equal(await verify(await h.token({ sub: EXTERNAL_SUBJECT }, {}, rogue), context()), null);
  assert.equal(await verify(await h.token({ sub: EXTERNAL_SUBJECT }, { typ: 'JWT' }), context()), null);
  assert.equal(await verify(await h.token({ sub: EXTERNAL_SUBJECT }, { kid: undefined }), context()), null);
  assert.equal(subjectCalls, 0);
  assert.equal(consentCalls, 0);
});

test('WorkOS Connect rejects unknown, malformed and failed subject mappings before consent resolution', async () => {
  const h = await harness();
  const signed = await h.token({ sub: EXTERNAL_SUBJECT });
  let consentCalls = 0;
  const resolveConsent = async () => { consentCalls++; return null; };
  for (const mapped of [null, undefined, 123, {}, new String(USER), '', EXTERNAL_SUBJECT, CLIENT, 'user_short',
    ` ${USER}`, `${USER}\n`, `user_${'x'.repeat(65)}`]) {
    const resolveTokenSubject = (async () => mapped) as WorkOSConnectTokenSubjectResolver;
    assert.equal(await h.verifier({ resolveTokenSubject, resolveConsent })(signed, context()), null);
  }
  for (const error of [new Error('PRIVATE mapping failure'), new AccessError('TIMEOUT')]) {
    assert.equal(await h.verifier({ resolveTokenSubject: async () => { throw error; }, resolveConsent })(signed, context()), null);
  }
  assert.equal(consentCalls, 0);
});

test('WorkOS Connect times out subject mapping and ignores its eventual result', { timeout: 3000 }, async () => {
  const h = await harness();
  let signal: AbortSignal | undefined;
  let release!: (subject: string) => void;
  const held = new Promise<string>(resolve => { release = resolve; });
  let consentCalls = 0;
  const verify = h.verifier({ timeoutMs: 80, resolveTokenSubject: async (_identity, ctx) => {
    signal = ctx.signal; return held;
  }, resolveConsent: async () => { consentCalls++; return null; } });
  await rejectsTimeout(verify(await h.token({ sub: EXTERNAL_SUBJECT }), context()));
  assert.equal(signal?.aborted, true);
  release(USER);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(consentCalls, 0);
});

test('WorkOS Connect cancellation prevents subject mapping or stops it before consent resolution', { timeout: 3000 }, async () => {
  const h = await harness();
  let started!: () => void;
  const entered = new Promise<void>(resolve => { started = resolve; });
  let release!: (subject: string) => void;
  const held = new Promise<string>(resolve => { release = resolve; });
  let mappingCalls = 0;
  let consentCalls = 0;
  let observed: AbortSignal | undefined;
  const verify = h.verifier({ resolveTokenSubject: async (_identity, ctx) => {
    mappingCalls++; observed = ctx.signal; started(); return held;
  }, resolveConsent: async () => { consentCalls++; return null; } });
  const signed = await h.token({ sub: EXTERNAL_SUBJECT });
  await rejectsTimeout(verify(signed, context(AbortSignal.abort('PRIVATE abort reason'))));
  assert.equal(mappingCalls, 0);
  assert.equal(h.requests.length, 0);
  const caller = new AbortController();
  const pending = verify(signed, context(caller.signal));
  await entered;
  caller.abort('PRIVATE abort reason');
  await rejectsTimeout(pending);
  assert.equal(observed?.aborted, true);
  release(USER);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(mappingCalls, 1);
  assert.equal(consentCalls, 0);
});

test('WorkOS Connect rechecks token expiry after subject mapping before invoking consent resolution', async t => {
  const h = await harness();
  const expiresAt = Math.floor(Date.now() / 1000) * 1000 + 300_000;
  let consentCalls = 0;
  let mappingCalls = 0;
  const verify = h.verifier({ resolveTokenSubject: async () => {
    mappingCalls++;
    await new Promise(resolve => setImmediate(resolve));
    t.mock.method(Date, 'now', () => expiresAt);
    return USER;
  }, resolveConsent: async () => { consentCalls++; return null; } });
  assert.equal(await verify(await h.token({ sub: EXTERNAL_SUBJECT, exp: expiresAt / 1000 }), context()), null);
  assert.equal(mappingCalls, 1);
  assert.equal(consentCalls, 0);
});

test('WorkOS Connect requires the exact explicitly configured protected-header typ', async () => {
  const h = await harness();
  for (const configured of [null, 'JWT', 'at+jwt'] as const) {
    const verify = h.verifier({ accessTokenType: configured });
    for (const actual of [undefined, 'JWT', 'at+jwt', 'id+jwt', 'jwt', 'application/at+jwt']) {
      const result = await verify(await h.token({}, { typ: actual }), context());
      assert.equal(Boolean(result), actual === (configured ?? undefined), `${configured} versus ${actual}`);
    }
  }
});

test('WorkOS Connect rejects wrong identity, audience, missing claims and invalid lifetimes before resolution', async () => {
  const h = await harness();
  let calls = 0;
  const verify = h.verifier({ resolveConsent: async () => { calls++; return null; } });
  const now = Math.floor(Date.now() / 1000);
  const invalid: Record<string, unknown>[] = [
    { iss: `${ISSUER}/` }, { iss: 'https://api.workos.com' },
    { aud: CLIENT }, { aud: [RESOURCE] }, { aud: [RESOURCE, 'https://another.example.invalid/mcp'] },
    { client_id: 'client_otherclient123' }, { sub: 'alice' }, { sub: CLIENT }, { sub: 'user_abc' },
    { sid: 'session_00000000000000000000000001' }, { sid: 'app_consent_bad' },
    { jti: '' }, { jti: 'has\ncontrol' }, { jti: 'x'.repeat(129) },
    { act: {} }, { impersonator: {} }, { exp: now - 1 }, { nbf: now + 60 },
    { iat: now + 30 }, { exp: now }, { exp: now + 3601 }, { iat: -1 },
    { exp: now + 0.5 }, { iat: now - 0.5 }, { exp: 'tomorrow' }, { iat: 'yesterday' },
    { scope: '' }, { scope: ['workouts:read'] }, { scope: 'workouts:read  offline_access' },
    { scope: 'workouts:read\nadmin' }, { scope: 'x'.repeat(32769) },
    ...['iss', 'sub', 'aud', 'client_id', 'sid', 'jti', 'iat', 'exp', 'scope'].map((claim) => ({ [claim]: undefined })),
  ];
  for (const claims of invalid) {
    assert.equal(await verify(await h.token(claims), context()), null, `Invalid claims: ${JSON.stringify(claims)}`);
  }
  assert.equal(calls, 0);
});

test('WorkOS Connect rejects browser, ID, machine and symmetric token substitutions', async () => {
  const h = await harness();
  let calls = 0;
  const verify = h.verifier({ resolveConsent: async () => { calls++; return null; } });
  assert.equal(await verify(await h.token({ aud: CLIENT, client_id: undefined, sid: undefined, scope: undefined }, { typ: 'JWT' }), context()), null);
  assert.equal(await verify(await h.token({ sub: CLIENT, sid: undefined }), context()), null);
  assert.equal(await verify(await h.token({ iss: `https://api.workos.com/user_management/${CLIENT}`, aud: undefined, sid: CONSENT.replace('app_consent_', 'session_') }), context()), null);
  const rogue = await signingKey(h.key.kid);
  assert.equal(await verify(await h.token({}, {}, rogue), context()), null);
  assert.equal(await verify(await h.token({}, { kid: undefined }), context()), null);
  assert.equal(await verify(await h.token({}, { kid: 'unknown-key' }), context()), null);
  const symmetric = await new SignJWT({ iss: ISSUER, aud: RESOURCE })
    .setProtectedHeader({ alg: 'HS256', kid: h.key.kid }).sign(new TextEncoder().encode(JSON.stringify(h.key.publicJwk)));
  assert.equal(await verify(symmetric, context()), null);
  const unsigned = `${Buffer.from('{"alg":"none"}').toString('base64url')}.${Buffer.from('{}').toString('base64url')}.`;
  for (const token of [unsigned, '', 'not.a.jwt', 'x'.repeat(8193), 'Bearer abc.def.ghi']) {
    assert.equal(await verify(token, context()), null);
  }
  assert.equal(calls, 0);
});

test('WorkOS Connect pins the key URL, omits credentials, caches and rotates signing keys', async () => {
  const h = await harness();
  const verify = h.verifier();
  const token = await h.token({}, { jku: 'https://attacker.invalid/keys', jwk: (await signingKey()).publicJwk });
  assert.ok(await verify(token, context()));
  assert.ok(await verify(token, context()));
  assert.equal(h.requests.length, 1);
  const rotated = await signingKey();
  h.publish([h.key.publicJwk, rotated.publicJwk]);
  assert.ok(await verify(await h.token({}, {}, rotated), context()));
  assert.equal(h.requests.length, 2);
  for (const request of h.requests) {
    assert.equal(request.url, `${ISSUER}/oauth2/jwks`);
    assert.equal(request.init?.method, 'GET');
    assert.equal(request.init?.redirect, 'manual');
    assert.equal(request.init?.credentials, 'omit');
    assert.deepEqual(request.init?.headers, { accept: 'application/json' });
    assert.ok(!JSON.stringify(request).includes(token));
  }
  const before = h.requests.length;
  assert.equal(await verify(token, { ...context(), audience: 'https://other.invalid/mcp' }), null);
  assert.equal(h.requests.length, before);
});

test('WorkOS Connect rechecks the exact consent generation on every refresh and denies unknown/revoked generations', async () => {
  const h = await harness();
  let activeConsent: string | null = CONSENT;
  const seen: VerifiedWorkOSConnectIdentity[] = [];
  const verify = h.verifier({ resolveConsent: async (identity) => {
    seen.push(identity);
    return identity.consentId === activeConsent
      ? { subject: 'fixture-alice', scopes: ['workouts:read'], expiresAt: identity.expiresAt } : null;
  } });
  const original = await h.token({ jti: 'original' });
  assert.ok(await verify(original, context()));
  assert.ok(await verify(await h.token({ jti: 'refreshed' }), context()));
  activeConsent = null;
  assert.equal(await verify(original, context()), null);
  const newConsent = `${CONSENT}new`;
  activeConsent = newConsent;
  assert.ok(await verify(await h.token({ sid: newConsent }), context()));
  assert.equal(await verify(await h.token({ jti: 'old-family-new-token' }), context()), null);
  assert.equal(await verify(await h.token({ sid: `${CONSENT}unknown` }), context()), null);
  assert.equal(seen.length, 6);
  assert.equal(h.requests.length, 1);
});

test('WorkOS Connect fails closed on grant widening, malformed grants and private resolver failures', async () => {
  const h = await harness();
  const token = await h.token();
  const invalid = [
    null, { subject: '', scopes: ['workouts:read'], expiresAt: Date.now() + 10000 },
    { subject: 'fixture-alice', scopes: ['workouts:read'], expiresAt: Date.now() - 1 },
    { subject: 'fixture-alice', scopes: ['admin'], expiresAt: Date.now() + 10000 },
    { subject: 'fixture-alice', scopes: [], expiresAt: Date.now() + 10000 },
    { subject: 'fixture-alice', scopes: ['bad\nscope'], expiresAt: Date.now() + 10000 },
    { subject: 'fixture-alice', scopes: ['workouts:read'], expiresAt: Infinity },
  ];
  for (const grant of invalid) assert.equal(await h.verifier({ resolveConsent: async () => grant })(token, context()), null);
  assert.equal(await h.verifier({ resolveConsent: async () => { throw new Error('PRIVATE token=secret'); } })(token, context()), null);
  const expiry = Math.floor(Date.now() / 1000) * 1000 + 300000;
  assert.equal((await h.verifier({ resolveConsent: async () => ({ subject: 'fixture-alice', scopes: ['workouts:read'], expiresAt: expiry + 99999 }) })(await h.token({ exp: expiry / 1000 }), context()))?.expiresAt, expiry);
});

test('WorkOS Connect aborts stalled consent resolution with a finite redacted timeout', { timeout: 3000 }, async () => {
  const h = await harness();
  let signal: AbortSignal | undefined;
  const verify = h.verifier({ timeoutMs: 80, resolveConsent: async (_identity, ctx) => {
    signal = ctx.signal;
    return new Promise(() => {});
  } });
  await rejectsTimeout(verify(await h.token(), context()));
  assert.equal(signal?.aborted, true);
});

test('WorkOS Connect refuses a grant that expires during resolution', async () => {
  const h = await harness();
  const verify = h.verifier({ resolveConsent: async () => {
    const expiresAt = Date.now() + 10;
    await pause(25);
    return { subject: 'fixture-alice', scopes: ['workouts:read'], expiresAt };
  } });
  assert.equal(await verify(await h.token(), context()), null);
});

test('WorkOS Connect caller cancellation interrupts resolution and prevents work for pre-aborted callers', async () => {
  const h = await harness();
  let started!: () => void;
  const entered = new Promise<void>((resolve) => { started = resolve; });
  let observed: AbortSignal | undefined;
  const verify = h.verifier({ resolveConsent: async (_identity, ctx) => {
    observed = ctx.signal;
    started();
    return new Promise(() => {});
  } });
  const token = await h.token();
  const preAborted = new AbortController();
  preAborted.abort('PRIVATE abort reason');
  await rejectsTimeout(verify(token, context(preAborted.signal)));
  assert.equal(h.requests.length, 0);
  const caller = new AbortController();
  const pending = verify(token, context(caller.signal));
  await entered;
  caller.abort('PRIVATE abort reason');
  await rejectsTimeout(pending);
  assert.equal(observed?.aborted, true);
});

test('WorkOS Connect cannot resolve a token after cancellation while shared public keys are loading', async () => {
  const h = await harness();
  let release!: () => void;
  let started!: () => void;
  const entered = new Promise<void>((resolve) => { started = resolve; });
  const released = new Promise<void>((resolve) => { release = resolve; });
  h.respond(async () => { started(); await released; return Response.json({ keys: [h.key.publicJwk] }); });
  let calls = 0;
  const verify = h.verifier({ resolveConsent: async () => { calls++; return null; } });
  const caller = new AbortController();
  const pending = verify(await h.token(), context(caller.signal));
  await entered;
  caller.abort();
  await rejectsTimeout(pending);
  release();
  await pause(20);
  assert.equal(calls, 0);
});

test('WorkOS Connect rejects redirected, oversized and malformed signing key responses', async () => {
  const h = await harness();
  const token = await h.token();
  const bad = [
    () => new Response('', { status: 302, headers: { location: 'https://attacker.invalid/jwks' } }),
    () => new Response('x'.repeat(128 * 1024 + 1)),
    () => new Response('{broken'),
    () => Response.json({ keys: [] }),
    () => Response.json({ keys: Array(33).fill(h.key.publicJwk) }),
    () => new Response(null, { status: 200 }),
  ];
  for (const response of bad) {
    h.respond(async () => response());
    assert.equal(await h.verifier()(token, context()), null);
  }
  assert.equal(h.requests.length, bad.length);
  assert.ok(h.requests.every((request) => request.url === `${ISSUER}/oauth2/jwks`));
});

test('WorkOS Connect bounds stalled key responses without invoking consent resolution', { timeout: 3000 }, async () => {
  const h = await harness();
  let cancelled = false;
  h.respond(async () => new Response(new ReadableStream({ cancel() { cancelled = true; } })));
  let calls = 0;
  const verify = h.verifier({ timeoutMs: 60, resolveConsent: async () => { calls++; return null; } });
  await rejectsTimeout(verify(await h.token(), context()));
  await pause(20);
  assert.equal(cancelled, true);
  assert.equal(calls, 0);
});

test('WorkOS Connect rejects unsafe configuration and missing typ profile before key retrieval', async () => {
  const h = await harness();
  const invalid: Partial<WorkOSConnectVerifierOptions>[] = [
    { appId: '' }, { clientId: '' }, { issuer: `${ISSUER}/` }, { issuer: `${ISSUER}/path` },
    { issuer: `${ISSUER}?x=1` }, { issuer: 'https://user:pass@authkit.example' }, { issuer: 'http://localhost' },
    { resource: 'http://localhost/mcp' }, { resource: `${RESOURCE}?token=secret` },
    { accessTokenType: undefined }, { accessTokenType: 'jwt' as never },
    { timeoutMs: 0 }, { timeoutMs: 30001 }, { maxTokenLifetimeSeconds: 86401 },
    { jwksCooldownMs: -1 }, { jwksCacheMaxAgeMs: 0 }, { resolveConsent: undefined },
    { resolveTokenSubject: null as never }, { resolveTokenSubject: USER as never },
  ];
  for (const options of invalid) assert.throws(() => h.verifier(options));
  assert.equal(h.requests.length, 0);
});
