import assert from 'node:assert/strict';
import { test } from 'node:test';
import { exportJWK, generateKeyPair, SignJWT, type JWTHeaderParameters } from 'jose';
import { AccessError } from '../src/types.js';
import { createWorkOSConnectProvider, type WorkOSConnectProviderOptions } from '../src/workos-connect.js';

const options: WorkOSConnectProviderOptions = {
  apiKey: 'FICTIONAL_MANAGEMENT_CREDENTIAL_FOR_TESTS',
  issuer: 'https://identity.example.invalid',
  clientId: 'client_00000000000000000000000004',
  applicationId: 'connect_app_00000000000000000000000005',
  resource: 'https://gateivo.example.invalid/agent/mcp',
  redirectUri: 'https://gateivo.example.invalid/account/connect/callback',
  accessTokenType: null,
  requiredScopes: ['workouts:read'],
};
const USER = 'user_00000000000000000000000002';
const OTHER_USER = 'user_00000000000000000000000006';
const EXTERNAL_SUBJECT = 'external|fixture-alice';
const CONSENT = 'app_consent_00000000000000000000000003';
const ENTRY = 'authorized_connect_app_00000000000000000000000007';
const LIST_PATH = `/user_management/users/${USER}/authorized_applications`;
const DELETE_PATH = `${LIST_PATH}/${options.applicationId}`;
const input = { code: 'PRIVATE_AUTHORIZATION_CODE', codeVerifier: 'v'.repeat(43), expectedUserId: USER };
const keys = await generateKeyPair('RS256');
const forgedKeys = await generateKeyPair('RS256');
const jwk = { ...await exportJWK(keys.publicKey), kid: 'connect-provider-test', alg: 'RS256' };
const context = (signal = new AbortController().signal) => ({ signal });

async function token(claims: Record<string, unknown> = {}, header: Partial<JWTHeaderParameters> = {}, signer = keys.privateKey) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ iss: options.issuer, aud: options.resource, sub: USER, client_id: options.clientId,
    sid: CONSENT, jti: 'connect-provider-token', iat: now - 1, exp: now + 300,
    scope: 'openid offline_access workouts:read', ...claims,
  }).setProtectedHeader({ alg: 'RS256', kid: jwk.kid, ...header }).sign(signer);
}

function entry(overrides: Record<string, unknown> = {}) {
  return { object: 'authorized_connect_application', id: ENTRY,
    granted_scopes: ['offline_access', 'openid', 'workouts:read'],
    // This synthetic response omits the optional oauth_resource field.
    application: { object: 'connect_application', id: options.applicationId, client_id: options.clientId },
    ...overrides,
  };
}

function page(data: unknown[] = [], after: string | null = null) {
  return { object: 'list', data, list_metadata: { before: null, after } };
}

interface Call { url: URL; init: RequestInit }
function fixture(settings: {
  accessToken?: string;
  authorized?: boolean;
  resolveTokenSubject?: WorkOSConnectProviderOptions['resolveTokenSubject'];
  respond?: (call: Call, calls: Call[]) => Response | undefined | Promise<Response | undefined>;
} = {}) {
  const calls: Call[] = [];
  let authorized = settings.authorized ?? true;
  const fetcher: typeof fetch = async (raw, init = {}) => {
    const url = new URL(typeof raw === 'string' ? raw : raw instanceof URL ? raw.href : raw.url);
    const call = { url, init }; calls.push(call);
    assert.equal(init.redirect, 'error');
    assert.equal(init.credentials, 'omit');
    assert.ok(init.signal);
    const result = await settings.respond?.(call, calls);
    if (result) return result;
    if (url.origin === 'https://api.workos.com') {
      assert.equal(new Headers(init.headers).get('authorization'), `Bearer ${options.apiKey}`);
      if (url.pathname === `/connect/applications/${options.clientId}`) return Response.json({
        object: 'connect_application', id: options.applicationId, client_id: options.clientId,
      });
      if (url.pathname === LIST_PATH) return Response.json(page(authorized ? [entry()] : []));
      if (url.pathname === DELETE_PATH && init.method === 'DELETE') {
        authorized = false;
        return new Response(null, { status: 204 });
      }
    }
    if (url.origin === options.issuer) {
      assert.equal(new Headers(init.headers).has('authorization'), false);
      if (url.pathname === '/oauth2/token') return Response.json({
        access_token: settings.accessToken ?? 'unused', token_type: 'bearer',
        refresh_token: 'PRIVATE_REFRESH_TOKEN', id_token: 'PRIVATE_ID_TOKEN',
      });
      if (url.pathname === '/oauth2/jwks') return Response.json({ keys: [jwk] });
    }
    throw new Error('Unexpected provider request');
  };
  return { provider: createWorkOSConnectProvider({ ...options, resolveTokenSubject: settings.resolveTokenSubject }, { fetch: fetcher }), calls };
}

async function rejectsCode(promise: Promise<unknown>, code: string) {
  await assert.rejects(promise, (error: unknown) => {
    assert.ok(error instanceof AccessError);
    assert.equal(error.code, code);
    assert.equal(error.message, code);
    assert.equal(error.cause, undefined);
    assert.doesNotMatch(error.stack ?? '', /PRIVATE_|fictional@/);
    return true;
  });
}

test('SDK Connect provider pins the public PKCE URL, scope, resource and hosted callback', () => {
  const { provider, calls } = fixture();
  const url = new URL(provider.authorizationUrl({ state: 's'.repeat(43), codeChallenge: 'c'.repeat(43) }));
  assert.equal(url.origin, options.issuer);
  assert.equal(url.pathname, '/oauth2/authorize');
  assert.deepEqual(Object.fromEntries(url.searchParams), {
    client_id: options.clientId, redirect_uri: options.redirectUri, response_type: 'code',
    scope: 'openid offline_access workouts:read', resource: options.resource, state: 's'.repeat(43),
    code_challenge: 'c'.repeat(43), code_challenge_method: 'S256',
  });
  assert.doesNotMatch(url.href, /PRIVATE_|client_secret|api_key/);
  assert.equal(calls.length, 0);
  assert.ok(Object.isFrozen(provider));
});

test('SDK Connect provider rejects malformed generic config and arguments before network access', async () => {
  for (const bad of [
    { apiKey: '' }, { apiKey: 'PRIVATE_KEY\n'.repeat(3) }, { clientId: '../other-client' },
    { applicationId: options.applicationId.replace('connect_app_', 'app_') },
    { issuer: '' }, { issuer: 'https://accounts.example.com/path' }, { issuer: 'https://accounts.example.com:443' },
    { issuer: `${options.issuer}/` }, { issuer: `${options.issuer}\n` }, { issuer: `${options.issuer}?other=app` },
    { issuer: options.issuer.replace('https:', 'http:') }, { issuer: 'https://user:pass@identity.example.invalid' },
    { redirectUri: 'http://gateivo.example.invalid/callback' },
    { redirectUri: 'https://other.example.invalid/callback' },
    { redirectUri: `${options.redirectUri}?return=evil` },
    { resource: `${options.resource}#fragment` }, { resource: 'https://user:pass@gateivo.example.invalid/mcp' },
    { accessTokenType: undefined }, { accessTokenType: 'id+jwt' },
    { requiredScopes: [] }, { requiredScopes: undefined }, { requiredScopes: ['read write'] },
    { requiredScopes: ['bad\nscope'] }, { requiredScopes: [3] }, { requiredScopes: ['x'.repeat(129)] },
    { requiredScopes: Array.from({ length: 257 }, (_, n) => `scope:${n}`) },
    { resolveTokenSubject: null }, { resolveTokenSubject: 'user_not_a_resolver' },
  ]) assert.throws(() => createWorkOSConnectProvider({ ...options, ...bad } as WorkOSConnectProviderOptions), /Invalid WorkOS Connect provider configuration/);
  const { provider, calls } = fixture();
  assert.throws(() => provider.authorizationUrl({ state: '', codeChallenge: 'c'.repeat(43) }), AccessError);
  assert.throws(() => provider.authorizationUrl({ state: 's'.repeat(43), codeChallenge: 'bad' }), AccessError);
  await rejectsCode(provider.exchangeCode({ ...input, code: 'bad\ncode' }, context()), 'INVALID_ARGUMENT');
  await rejectsCode(provider.exchangeCode({ ...input, codeVerifier: 'short' }, context()), 'INVALID_ARGUMENT');
  await rejectsCode(provider.exchangeCode({ ...input, expectedUserId: '../user' }, context()), 'INVALID_ARGUMENT');
  await rejectsCode(provider.resetAuthorization('../user', { ...context(), beforeDelete: async () => {} }), 'INVALID_ARGUMENT');
  assert.equal(calls.length, 0);
});

test('SDK Connect provider copies configuration before constructing any request', () => {
  const config = { ...options };
  const provider = createWorkOSConnectProvider(config);
  config.issuer = 'https://attacker.invalid';
  config.redirectUri = 'https://attacker.invalid/callback';
  const url = new URL(provider.authorizationUrl({ state: 's'.repeat(43), codeChallenge: 'c'.repeat(43) }));
  assert.equal(url.origin, options.issuer);
  assert.equal(url.searchParams.get('redirect_uri'), options.redirectUri);
});

test('SDK Connect code exchange returns only fully verified frozen claims and never sends management credentials', async () => {
  const signed = await token();
  const { provider, calls } = fixture({ accessToken: signed });
  const identity = await provider.exchangeCode(input, context());
  assert.equal(identity.issuer, options.issuer);
  assert.equal(identity.subject, USER);
  assert.equal(identity.clientId, options.clientId);
  assert.equal(identity.audience, options.resource);
  assert.equal(identity.consentId, CONSENT);
  assert.deepEqual(identity.scopes, ['openid', 'offline_access', 'workouts:read']);
  assert.ok(Object.isFrozen(identity));
  assert.ok(Object.isFrozen(identity.scopes));
  assert.doesNotMatch(JSON.stringify(identity), /PRIVATE_|access_token|refresh_token|id_token/);
  assert.equal(calls.length, 2);
  const body = new URLSearchParams(calls[0]!.init.body as URLSearchParams);
  assert.deepEqual(Object.fromEntries(body), { grant_type: 'authorization_code', client_id: options.clientId,
    code: input.code, code_verifier: input.codeVerifier, redirect_uri: options.redirectUri, resource: options.resource });
  for (const call of calls) {
    assert.equal(call.url.origin, options.issuer);
    assert.equal(new Headers(call.init.headers).has('authorization'), false);
    assert.ok(!String(call.init.body).includes(options.apiKey));
  }
  assert.equal(calls[1]!.url.pathname, '/oauth2/jwks');
  assert.equal(calls[1]!.init.body, undefined);
});

test('SDK Connect exchange rejects forged tokens, substituted identities and unrequested access profiles', async () => {
  const invalid = [
    await token({}, {}, forgedKeys.privateKey), await token({ iss: 'https://attacker.invalid' }),
    await token({ sub: OTHER_USER }), await token({ client_id: 'client_otherclient1234' }),
    await token({ aud: options.clientId }), await token({ aud: [options.resource] }),
    await token({ sid: 'session_00000000000000000000000001' }), await token({ scope: 'openid offline_access' }),
    await token({ exp: Math.floor(Date.now() / 1000) - 1 }), await token({}, { typ: 'JWT' }),
    await token({ aud: options.clientId, client_id: undefined, sid: undefined, scope: undefined }, { typ: 'JWT' }),
  ];
  for (const signed of invalid) {
    const { provider, calls } = fixture({ accessToken: signed });
    await rejectsCode(provider.exchangeCode(input, context()), 'UNAUTHENTICATED');
    assert.equal(calls.some(call => call.url.origin === 'https://api.workos.com'), false);
  }
});

test('SDK Connect exchange respects the explicitly configured token header type', async () => {
  const signed = await token({}, { typ: 'at+jwt' });
  const provider = createWorkOSConnectProvider({ ...options, accessTokenType: 'at+jwt' }, { fetch: async (raw) =>
    String(raw).endsWith('/oauth2/token') ? Response.json({ access_token: signed, token_type: 'Bearer' }) : Response.json({ keys: [jwk] }) });
  assert.equal((await provider.exchangeCode(input, context())).consentId, CONSENT);
});

test('SDK Connect exchange requires explicit external subject mapping and returns the canonical identity', async () => {
  const accessToken = await token({ sub: EXTERNAL_SUBJECT, email: 'PRIVATE_EMAIL' });
  await rejectsCode(fixture({ accessToken }).provider.exchangeCode(input, context()), 'UNAUTHENTICATED');
  let mappingCalls = 0;
  const { provider, calls } = fixture({ accessToken, resolveTokenSubject: async (identity, ctx) => {
    mappingCalls++;
    assert.deepEqual(identity, { issuer: options.issuer, clientId: options.clientId,
      audience: options.resource, subject: EXTERNAL_SUBJECT });
    assert.ok(Object.isFrozen(identity));
    assert.equal(ctx.signal.aborted, false);
    return USER;
  } });
  const identity = await provider.exchangeCode(input, context());
  assert.equal(mappingCalls, 1);
  assert.equal(identity.subject, USER);
  assert.equal(identity.consentId, CONSENT);
  assert.deepEqual(identity.scopes, ['openid', 'offline_access', 'workouts:read']);
  assert.ok(Object.isFrozen(identity));
  assert.doesNotMatch(JSON.stringify(identity), /external\||PRIVATE_/);
  assert.deepEqual(calls.map(call => call.url.pathname), ['/oauth2/token', '/oauth2/jwks']);
});

test('SDK Connect exchange enforces the mapped expected user and cannot bypass mapping with a native subject', async () => {
  for (const [subject, mapped] of [[EXTERNAL_SUBJECT, OTHER_USER], [EXTERNAL_SUBJECT, null],
    [USER, OTHER_USER], [USER, null]] as const) {
    let mappingCalls = 0;
    const { provider, calls } = fixture({ accessToken: await token({ sub: subject }), resolveTokenSubject: async identity => {
      mappingCalls++; assert.equal(identity.subject, subject); return mapped;
    } });
    await rejectsCode(provider.exchangeCode(input, context()), 'UNAUTHENTICATED');
    assert.equal(mappingCalls, 1);
    assert.equal(calls.some(call => call.url.origin === 'https://api.workos.com'), false);
  }
  const { provider } = fixture({ accessToken: await token({ sub: EXTERNAL_SUBJECT }), resolveTokenSubject: async () => USER });
  await rejectsCode(provider.exchangeCode({ ...input, expectedUserId: OTHER_USER }, context()), 'UNAUTHENTICATED');
});

test('SDK Connect exchange never maps invalid signed access profiles and sanitizes mapping failures', async () => {
  let mappingCalls = 0;
  for (const accessToken of [
    await token({ sub: EXTERNAL_SUBJECT }, {}, forgedKeys.privateKey),
    await token({ sub: EXTERNAL_SUBJECT, iss: 'https://attacker.invalid' }),
    await token({ sub: EXTERNAL_SUBJECT, client_id: 'client_otherclient1234' }),
    await token({ sub: EXTERNAL_SUBJECT, aud: options.clientId }),
    await token({ sub: EXTERNAL_SUBJECT, sid: 'session_00000000000000000000000001' }),
    await token({ sub: EXTERNAL_SUBJECT, scope: 'workouts:read\nadmin' }),
    await token({ sub: EXTERNAL_SUBJECT, exp: Math.floor(Date.now() / 1000) - 1 }),
    await token({ sub: EXTERNAL_SUBJECT }, { typ: 'JWT' }),
  ]) {
    const { provider } = fixture({ accessToken, resolveTokenSubject: async () => { mappingCalls++; return USER; } });
    await rejectsCode(provider.exchangeCode(input, context()), 'UNAUTHENTICATED');
  }
  assert.equal(mappingCalls, 0);
  const { provider, calls } = fixture({ accessToken: await token({ sub: EXTERNAL_SUBJECT }),
    resolveTokenSubject: async () => { throw new Error('PRIVATE_MAPPING_FAILURE'); } });
  await rejectsCode(provider.exchangeCode(input, context()), 'UNAUTHENTICATED');
  assert.equal(calls.length, 2);
});

test('SDK Connect exchange forwards cancellation to subject mapping and ignores late mapping completion', { timeout: 3000 }, async () => {
  let started!: () => void;
  const entered = new Promise<void>(resolve => { started = resolve; });
  let release!: (subject: string) => void;
  const held = new Promise<string>(resolve => { release = resolve; });
  let signal: AbortSignal | undefined;
  const { provider, calls } = fixture({ accessToken: await token({ sub: EXTERNAL_SUBJECT }),
    resolveTokenSubject: async (_identity, ctx) => { signal = ctx.signal; started(); return held; } });
  const caller = new AbortController();
  const pending = provider.exchangeCode(input, context(caller.signal));
  await entered;
  caller.abort('PRIVATE_ABORT_REASON');
  await rejectsCode(pending, 'TIMEOUT');
  assert.equal(signal?.aborted, true);
  release(USER);
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(calls.map(call => call.url.pathname), ['/oauth2/token', '/oauth2/jwks']);
});

test('SDK Connect reset claims durably immediately before one canonical application deletion and confirms absence', async () => {
  const events: string[] = [];
  const { provider, calls } = fixture({
    resolveTokenSubject: async () => { assert.fail('Reset must use its canonical user directly'); },
    respond: call => { events.push(`${call.init.method} ${call.url.pathname}`); return undefined; },
  });
  await provider.resetAuthorization(USER, { ...context(), beforeDelete: async () => { events.push('claim'); } });
  assert.deepEqual(events, [
    `GET /connect/applications/${options.clientId}`, `GET ${LIST_PATH}`, 'claim', `DELETE ${DELETE_PATH}`, `GET ${LIST_PATH}`,
  ]);
  assert.equal(calls.filter(call => call.init.method === 'DELETE').length, 1);
  assert.equal(calls[2]!.init.body, undefined);
  assert.ok(!calls[2]!.url.pathname.includes(ENTRY));
  assert.ok(!calls[2]!.url.pathname.includes(CONSENT));
  assert.equal(calls[1]!.url.searchParams.get('limit'), '100');
});

test('SDK Connect reset performs no durable deletion claim or DELETE when authorization is absent', async () => {
  const { provider, calls } = fixture({ authorized: false });
  await provider.resetAuthorization(USER, { ...context(), beforeDelete: async () => { assert.fail('Must not claim absent authorization'); } });
  assert.equal(calls.length, 2);
  assert.equal(calls.some(call => call.init.method === 'DELETE'), false);
});

test('SDK Connect reset exhausts bounded pagination before deleting a matching application', async () => {
  const other = entry({ id: 'authorized_other1', application: { id: 'connect_app_other1234', client_id: 'client_other1234' } });
  const { provider, calls } = fixture({ respond: (call, seen) => {
    if (call.url.pathname !== LIST_PATH || seen.some(item => item.init.method === 'DELETE')) return undefined;
    const after = call.url.searchParams.get('after');
    if (after === null) return Response.json(page([other], 'cursor_first'));
    if (after === 'cursor_first') return Response.json(page([entry()], 'cursor_second'));
    if (after === 'cursor_second') return Response.json(page());
    assert.fail('Unexpected cursor');
  } });
  let claims = 0;
  await provider.resetAuthorization(USER, { ...context(), beforeDelete: async () => {
    claims++;
    assert.equal(calls.filter(call => call.url.pathname === LIST_PATH).length, 3);
  } });
  assert.equal(claims, 1);
  assert.equal(calls.filter(call => call.init.method === 'DELETE').length, 1);
});

test('SDK Connect reset refuses ambiguous, malformed and mismatched authorization records before deletion', async () => {
  const malformed = [
    { object: 'list', data: null, list_metadata: { after: null } },
    { data: [], list_metadata: {} }, { data: [] }, page([], 'cursor_without_records'),
    page([entry(), entry({ id: 'authorized_duplicate' })]),
    page([entry(), entry()]), page([{}]), page([entry({ application: null })]),
    page([entry({ application: { id: options.applicationId, client_id: 'client_other1234' } })]),
    page([entry({ application: { id: 'connect_app_other1234', client_id: options.clientId } })]),
    page([entry({ application: { id: options.applicationId } })]),
    page(Array.from({ length: 101 }, (_, i) => entry({ id: `entry_${i}` }))),
  ];
  for (const result of malformed) {
    const { provider, calls } = fixture({ respond: call => call.url.pathname === LIST_PATH ? Response.json(result) : undefined });
    await rejectsCode(provider.resetAuthorization(USER, { ...context(), beforeDelete: async () => { assert.fail('Must not claim'); } }), 'UNAVAILABLE');
    assert.equal(calls.some(call => call.init.method === 'DELETE'), false);
  }
  for (const app of [{ id: options.applicationId, client_id: 'client_other1234' },
    { id: 'connect_app_other1234', client_id: options.clientId }, { data: { id: options.applicationId, client_id: options.clientId } }]) {
    const { provider, calls } = fixture({ respond: call => call.url.pathname.startsWith('/connect/applications/') ? Response.json(app) : undefined });
    await rejectsCode(provider.resetAuthorization(USER, { ...context(), beforeDelete: async () => {} }), 'UNAVAILABLE');
    assert.equal(calls.length, 1);
  }
});

test('SDK Connect reset rejects cyclic cursors and bounded pagination exhaustion without deleting', async () => {
  for (const cyclic of [true, false]) {
    let pages = 0;
    const { provider, calls } = fixture({ respond: call => {
      if (call.url.pathname !== LIST_PATH) return undefined;
      pages++;
      return Response.json(page([entry({ id: `entry_${pages}`, application: { id: `connect_app_other${pages}`, client_id: `client_other000${pages}` } })],
        cyclic ? 'cursor_repeat' : `cursor_${pages}`));
    } });
    await rejectsCode(provider.resetAuthorization(USER, { ...context(), beforeDelete: async () => { assert.fail('Must not claim'); } }), 'UNAVAILABLE');
    assert.equal(pages, cyclic ? 2 : 5);
    assert.equal(calls.some(call => call.init.method === 'DELETE'), false);
  }
});

test('SDK Connect reset never retries failed or uncertain DELETE responses', async () => {
  for (const status of [202, 302, 400, 404, 429, 503]) {
    let claimed = 0;
    const { provider, calls } = fixture({ respond: call => call.init.method === 'DELETE'
      ? Response.json({ error: 'PRIVATE_PROVIDER_ERROR' }, { status }) : undefined });
    await rejectsCode(provider.resetAuthorization(USER, { ...context(), beforeDelete: async () => { claimed++; } }), 'UNAVAILABLE');
    assert.equal(claimed, 1);
    assert.equal(calls.filter(call => call.init.method === 'DELETE').length, 1);
    assert.equal(calls.length, 3);
  }
});

test('SDK Connect reset rejects failed absence verification after a successful DELETE', async () => {
  const { provider, calls } = fixture({ respond: call => call.init.method === 'DELETE' ? new Response(null, { status: 200 }) : undefined });
  await rejectsCode(provider.resetAuthorization(USER, { ...context(), beforeDelete: async () => {} }), 'UNAVAILABLE');
  assert.equal(calls.filter(call => call.init.method === 'DELETE').length, 1);
  assert.equal(calls.length, 4);
});

test('SDK Connect reset cannot delete when its durable claim fails or finishes after cancellation', async () => {
  const failure = fixture();
  await rejectsCode(failure.provider.resetAuthorization(USER, { ...context(), beforeDelete: async () => {
    throw new Error('PRIVATE_DATABASE_ERROR');
  } }), 'UNAVAILABLE');
  assert.equal(failure.calls.some(call => call.init.method === 'DELETE'), false);

  const controller = new AbortController();
  let started!: () => void;
  const reachedClaim = new Promise<void>(resolve => { started = resolve; });
  let release!: () => void;
  const heldClaim = new Promise<void>(resolve => { release = resolve; });
  const delayed = fixture();
  const pending = delayed.provider.resetAuthorization(USER, { signal: controller.signal, beforeDelete: async () => {
    started(); await heldClaim;
  } });
  await reachedClaim;
  controller.abort();
  await rejectsCode(pending, 'TIMEOUT');
  release();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(delayed.calls.some(call => call.init.method === 'DELETE'), false);
});

test('SDK Connect transport failures and malformed token responses are sanitized and never retried', async () => {
  for (const result of [Response.json({ error: 'PRIVATE_REFRESH_TOKEN' }, { status: 503 }), new Response('PRIVATE_INVALID_JSON')]) {
    let requests = 0;
    const provider = createWorkOSConnectProvider(options, { fetch: async () => { requests++; return result; } });
    await rejectsCode(provider.exchangeCode(input, context()), 'UNAVAILABLE');
    assert.equal(requests, 1);
  }
  for (const value of [null, [], { access_token: 'short', token_type: 'bearer' },
    { access_token: await token(), token_type: 'other' }, { id_token: await token(), token_type: 'bearer' }]) {
    const { provider, calls } = fixture({ respond: call => call.url.pathname === '/oauth2/token' ? Response.json(value) : undefined });
    await rejectsCode(provider.exchangeCode(input, context()), 'UNAUTHENTICATED');
    assert.equal(calls.length, 1);
  }
  const { provider, calls } = fixture({ respond: call => call.url.pathname === '/oauth2/token'
    ? Response.json({ error: 'invalid_grant', error_description: 'PRIVATE_CODE' }, { status: 400 }) : undefined });
  await rejectsCode(provider.exchangeCode(input, context()), 'UNAUTHENTICATED');
  assert.equal(calls.length, 1);
});

test('SDK Connect response body sizes are bounded before parsing or deletion', async () => {
  for (const route of ['exchange', 'reset']) {
    let requests = 0;
    const provider = createWorkOSConnectProvider(options, { fetch: async () => { requests++; return new Response('x'.repeat(140_000)); } });
    await rejectsCode(route === 'exchange' ? provider.exchangeCode(input, context())
      : provider.resetAuthorization(USER, { ...context(), beforeDelete: async () => { assert.fail('Must not claim'); } }), 'UNAVAILABLE');
    assert.equal(requests, 1);
  }
});

test('SDK Connect caller cancellation bounds a transport that ignores AbortSignal and prevents new work', async () => {
  let seenSignal: AbortSignal | undefined;
  let started!: () => void;
  const requestStarted = new Promise<void>(resolve => { started = resolve; });
  let requests = 0;
  const provider = createWorkOSConnectProvider(options, { fetch: async (_url, init) => {
    requests++; seenSignal = init!.signal!; started(); return new Promise<Response>(() => {});
  } });
  const controller = new AbortController();
  const pending = provider.exchangeCode(input, context(controller.signal));
  await requestStarted; controller.abort();
  await rejectsCode(pending, 'TIMEOUT');
  assert.equal(seenSignal?.aborted, true);
  await rejectsCode(provider.resetAuthorization(USER, { signal: AbortSignal.abort(), beforeDelete: async () => {} }), 'TIMEOUT');
  assert.equal(requests, 1);
});

test('SDK Connect cancellation also interrupts and cancels a stalled response body', async () => {
  let bodyStarted!: () => void;
  const reachedBody = new Promise<void>(resolve => { bodyStarted = resolve; });
  let cancelled = false;
  const provider = createWorkOSConnectProvider(options, { fetch: async () => new Response(new ReadableStream({
    start(controller) { controller.enqueue(new TextEncoder().encode('{"access_token":"PRIVATE_')); bodyStarted(); },
    cancel() { cancelled = true; },
  })) });
  const controller = new AbortController();
  const pending = provider.exchangeCode(input, context(controller.signal));
  await reachedBody;
  await new Promise(resolve => setImmediate(resolve));
  controller.abort();
  await rejectsCode(pending, 'TIMEOUT');
  assert.equal(cancelled, true);
});

test('SDK Connect cancellation during DELETE never retries or starts absence verification', async () => {
  let started!: () => void;
  const deletionStarted = new Promise<void>(resolve => { started = resolve; });
  let deleteSignal: AbortSignal | undefined;
  const { provider, calls } = fixture({ respond: async call => {
    if (call.init.method !== 'DELETE') return undefined;
    deleteSignal = call.init.signal!; started(); return new Promise<Response>(() => {});
  } });
  const controller = new AbortController();
  const pending = provider.resetAuthorization(USER, { signal: controller.signal, beforeDelete: async () => {} });
  await deletionStarted; controller.abort();
  await rejectsCode(pending, 'TIMEOUT');
  assert.equal(deleteSignal?.aborted, true);
  assert.equal(calls.length, 3);
});

test('SDK Connect operations have a finite overall deadline even when the transport never settles', { timeout: 10_000 }, async () => {
  let requests = 0;
  const provider = createWorkOSConnectProvider(options, { fetch: async () => {
    requests++; return new Promise<Response>(() => {});
  } });
  const start = Date.now();
  await rejectsCode(provider.exchangeCode(input, context()), 'TIMEOUT');
  assert.ok(Date.now() - start < 9_500);
  assert.equal(requests, 1);
});


test('SDK Connect accepts explicit canonical AuthKit and custom HTTPS issuer origins', () => {
  for (const issuer of ['https://workouts.authkit.app', 'https://accounts.workouts.example',
    'https://accounts.workouts.example:8443', options.issuer]) {
    const provider = createWorkOSConnectProvider({ ...options, issuer });
    const url = new URL(provider.authorizationUrl({ state: 's'.repeat(43), codeChallenge: 'c'.repeat(43) }));
    assert.equal(url.origin, issuer);
    assert.equal(url.pathname, '/oauth2/authorize');
  }
});

test('SDK Connect snapshots and deduplicates scopes and requires each requested app capability', async () => {
  const scopes = ['workouts:read', 'profile:read', 'workouts:read', 'openid'];
  const configured = { ...options, requiredScopes: scopes };
  let accessToken = await token({ scope: 'openid offline_access workouts:read' });
  const provider = createWorkOSConnectProvider(configured, { fetch: async (raw) =>
    String(raw).endsWith('/oauth2/token') ? Response.json({ access_token: accessToken, token_type: 'Bearer' })
      : Response.json({ keys: [jwk] }) });
  scopes.splice(0, scopes.length, 'unexpected:write');
  const url = new URL(provider.authorizationUrl({ state: 's'.repeat(43), codeChallenge: 'c'.repeat(43) }));
  assert.equal(url.searchParams.get('scope'), 'openid offline_access workouts:read profile:read');
  await rejectsCode(provider.exchangeCode(input, context()), 'UNAUTHENTICATED');
  accessToken = await token({ scope: 'openid offline_access workouts:read profile:read' });
  assert.deepEqual((await provider.exchangeCode(input, context())).scopes,
    ['openid', 'offline_access', 'workouts:read', 'profile:read']);
});
