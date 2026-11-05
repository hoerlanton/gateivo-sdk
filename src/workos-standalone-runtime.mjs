import express from 'express';
import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

const BASE = '/account/assistant';
const IDENTITY = BASE + '/identity';
const EXTERNAL = BASE + '/external-login';
const COOKIE = '__Host-gateivo-standalone';
const WINDOW = 300_000;
const API = 'https://api.workos.com';
const EXTERNAL_AUTH_ID = /^(?:ext_auth_)?[0-7][0-9A-HJKMNP-TV-Z]{25}$/;
const EXTERNAL_ID = /^gateivo:[a-f0-9]{64}$/;
const USER = /^user_[A-Za-z0-9]{8,64}$/;
const token = value => typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value)
  && Buffer.from(value, 'base64url').toString('base64url') === value;
const opaque = (value, max = 256) => typeof value === 'string' && /^[\x21-\x7e]+$/.test(value) && value.length <= max;
const email = value => opaque(value, 254)
  && /^[^\s@\x00-\x1f\x7f]+@[^\s@\x00-\x1f\x7f]+\.[^\s@\x00-\x1f\x7f]+$/.test(value);
const hash = value => createHash('sha256').update(value).digest('hex');
const escape = value => String(value).replace(/[&<>"']/g, character =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const equal = (left, right) => typeof left === 'string' && typeof right === 'string'
  && Buffer.byteLength(left) === Buffer.byteLength(right) && timingSafeEqual(Buffer.from(left), Buffer.from(right));
const completionPath = pathname => pathname === '/oauth/authorize/complete' || pathname === '/oauth2/external/callback';
const bindingFields = ['issuer', 'appSubject', 'accountKey', 'externalId', 'providerSubject'];
const sameBinding = (left, right) => !!left && !!right && bindingFields.every(key => left[key] === right[key]);
class Failure extends Error {
  constructor(status = 400) { super('The account connection could not be completed.'); this.status = status; }
}
const reject = status => { throw new Failure(status); };
const cancelBody = response => { try { void Promise.resolve(response?.body?.cancel()).catch(() => {}); } catch {} };

// Bound the transport independently: injected transports and response readers may
// ignore AbortSignal, but their late result must never authorize a continuation.
async function providerOperation(signal, work) {
  if (!(signal instanceof AbortSignal) || signal.aborted) reject(503);
  const controller = new AbortController();
  const deadline = Date.now() + 5000;
  let fail;
  const gate = new Promise((_, no) => { fail = no; });
  const abort = () => { controller.abort(); fail(new Failure(503)); };
  signal.addEventListener('abort', abort, { once: true });
  const timer = setTimeout(abort, 5000);
  const check = () => { if (signal.aborted || controller.signal.aborted || Date.now() >= deadline) reject(503); };
  try { return await Promise.race([Promise.resolve().then(() => { check(); return work({ signal: controller.signal, check }); }), gate]); }
  catch { reject(503); }
  finally { clearTimeout(timer); signal.removeEventListener('abort', abort); controller.abort(); }
}

async function providerJson(response, context) {
  let reader;
  const stop = () => { try { void Promise.resolve(reader?.cancel()).catch(() => {}); } catch {} };
  try {
    const length = response.headers.get('content-length');
    if (!/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type') || '')
      || length !== null && (!/^\d+$/.test(length) || Number(length) > 65536)
      || typeof response.body?.getReader !== 'function') reject(503);
    reader = response.body.getReader();
    context.signal.addEventListener('abort', stop, { once: true });
    const chunks = []; let size = 0; let empty = 0;
    for (;;) {
      context.check(); const part = await reader.read(); context.check();
      if (part.done) break;
      if (!(part.value instanceof Uint8Array) || size + part.value.byteLength > 65536) reject(503);
      if (!part.value.byteLength) { if (++empty > 3) reject(503); continue; }
      empty = 0; size += part.value.byteLength; chunks.push(part.value);
    }
    const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks, size)));
    if (!value || typeof value !== 'object' || Array.isArray(value)) reject(503);
    return value;
  } finally {
    context.signal.removeEventListener('abort', stop);
    if (reader) { stop(); try { reader.releaseLock(); } catch {} } else cancelBody(response);
  }
}

function provider({ issuer, apiKey }, transport) {
  const request = async (path, method, body, context) => {
    context.check(); const url = API + path;
    const response = await transport(url, { method, redirect: 'error', credentials: 'omit', cache: 'no-store',
      headers: { Authorization: `Bearer ${apiKey}`, Accept: 'application/json', ...(body ? { 'Content-Type': 'application/json' } : {}) },
      ...(body ? { body: JSON.stringify(body) } : {}), signal: context.signal });
    try { context.check(); } catch (error) { cancelBody(response); throw error; }
    if (!response || !Number.isInteger(response.status) || response.status < 200 || response.status > 599
      || response.redirected === true || response.url && response.url !== url) { cancelBody(response); reject(503); }
    if (response.status < 200 || response.status >= 300) { cancelBody(response); return { status: response.status }; }
    return { status: response.status, value: await providerJson(response, context) };
  };
  const verify = (value, expected) => {
    if (!value || !USER.test(value.id) || value.external_id !== expected.externalId
      || value.email !== expected.email || value.email_verified !== true) reject(503);
    return Object.freeze({ providerSubject: value.id, externalId: expected.externalId, email: expected.email });
  };
  return Object.freeze({
    async ensureUser(expected, { signal }) {
      return providerOperation(signal, async context => {
        const path = '/user_management/users/external_id/' + encodeURIComponent(expected.externalId);
        const existing = await request(path, 'GET', undefined, context);
        if (existing.status === 200) return verify(existing.value, expected);
        if (existing.status !== 404) reject(503);
        const created = await request('/user_management/users', 'POST',
          { external_id: expected.externalId, email: expected.email, email_verified: true }, context);
        if ([200, 201].includes(created.status)) return verify(created.value, expected);
        // A create race may resolve only through this exact external identity.
        // An existing user with the same email is never implicitly linked.
        if (![409, 422].includes(created.status)) reject(503);
        const raced = await request(path, 'GET', undefined, context);
        if (raced.status !== 200) reject(503);
        return verify(raced.value, expected);
      });
    },
    async complete(expected, { signal }) {
      return providerOperation(signal, async context => {
        const result = await request('/authkit/oauth2/complete', 'POST', {
          external_auth_id: expected.externalAuthId, user: { id: expected.externalId, email: expected.email },
        }, context);
        if (result.status !== 200) reject(503);
        const location = result.value.redirect_uri;
        let destination; try { destination = new URL(location); } catch { reject(503); }
        if (typeof location !== 'string' || location.length > 8192 || /[\x00-\x20\x7f\\]/.test(location)
          || destination.protocol !== 'https:' || destination.origin !== issuer || destination.username
          || destination.password || location.includes('#') || !completionPath(destination.pathname)) reject(503);
        return destination.href;
      });
    },
  });
}

/** Generic identity handoff. Login/password handling and the source of verified
 * account attributes belong to the application. This module creates no consent.
 */
export function createWorkOSStandaloneLoginRuntime(options, dependencies = {}) {
  let origin; let issuer;
  try { origin = new URL(options?.publicUrl); issuer = new URL(options?.issuer); } catch { throw new TypeError('Invalid standalone login configuration.'); }
  const { appId, publicUrl, secret: inputSecret, store, authenticateSession, resolveLoginAccount, clientId } = options;
  const resource = options.resource ?? publicUrl + '/agent/mcp';
  const cutoff = options.accessExpiresAt ?? Number.MAX_SAFE_INTEGER;
  const transport = dependencies.fetch ?? globalThis.fetch;
  if (!opaque(appId, 128) || origin.protocol !== 'https:' || origin.origin !== publicUrl || origin.username || origin.password
    || issuer.protocol !== 'https:' || issuer.origin !== options.issuer || issuer.username || issuer.password || issuer.port
    || !/^[a-z0-9-]+\.authkit\.app$/.test(issuer.hostname) || !/^client_[A-Za-z0-9]{8,64}$/.test(clientId || '')
    || typeof options.apiKey !== 'string' || !/^sk_test_[A-Za-z0-9_-]{8,504}$/.test(options.apiKey) || resource !== publicUrl + '/agent/mcp'
    || !(inputSecret instanceof Uint8Array) || inputSecret.length !== 32 || typeof transport !== 'function'
    || typeof authenticateSession !== 'function' || typeof resolveLoginAccount !== 'function'
    || !['getBinding', 'bindAccount', 'findBinding', 'beginHandoff', 'consumeHandoff'].every(key => typeof store?.[key] === 'function')
    || options.trustProxyHttps !== undefined && typeof options.trustProxyHttps !== 'boolean'
    || !Number.isSafeInteger(cutoff) || cutoff <= Date.now()) throw new TypeError('Invalid standalone login configuration.');
  const secret = Buffer.from(inputSecret);
  const issuerOrigin = issuer.origin;
  const trustProxyHttps = options.trustProxyHttps === true;
  const identityKey = createHmac('sha256', secret).update('gateivo-standalone-identity-v1').digest();
  const envelopeKey = createHmac('sha256', secret).update(JSON.stringify(['gateivo-standalone-envelope-v1', appId, publicUrl, issuerOrigin])).digest();
  const csrfKey = createHmac('sha256', envelopeKey).update('csrf').digest();
  const aad = Buffer.from(EXTERNAL + ':' + publicUrl);
  const remote = provider({ issuer: issuerOrigin, apiKey: options.apiKey }, transport);
  const externalId = account => 'gateivo:' + createHmac('sha256', identityKey)
    .update(JSON.stringify([appId, publicUrl, account.appSubject, account.accountKey])).digest('hex');
  const accountFor = async (subject, context) => {
    if (!opaque(subject, 512) || context.signal.aborted || Date.now() >= cutoff) return null;
    const value = await resolveLoginAccount(subject, context);
    if (context.signal.aborted || Date.now() >= cutoff || !value || value.enabled !== true || value.emailVerified !== true
      || value.appSubject !== subject || !opaque(value.accountKey) || !opaque(value.authVersion)
      || !email(value.email) || typeof value.accountLabel !== 'string' || !value.accountLabel.length || value.accountLabel.length > 200
      || /[\u0000-\u001f\u007f-\u009f]/u.test(value.accountLabel)) return null;
    return Object.freeze({ appSubject: value.appSubject, accountKey: value.accountKey, authVersion: value.authVersion,
      email: value.email, accountLabel: value.accountLabel, emailVerified: true, enabled: true });
  };
  const bindingFor = async (account, context) => {
    const expected = { issuer: issuerOrigin, appSubject: account.appSubject, accountKey: account.accountKey, externalId: externalId(account) };
    const value = await store.getBinding({ issuer: expected.issuer, appSubject: expected.appSubject, accountKey: expected.accountKey }, context);
    if (context.signal.aborted || Date.now() >= cutoff || !value || !USER.test(value.providerSubject)
      || Object.entries(expected).some(([key, item]) => value[key] !== item)) return null;
    return Object.freeze(Object.fromEntries(bindingFields.map(key => [key, value[key]])));
  };
  const resolveAccount = async ({ issuer: requestedIssuer, appSubject }, context) => {
    if (requestedIssuer !== issuerOrigin || !(context?.signal instanceof AbortSignal)) return null;
    const before = await accountFor(appSubject, context); if (!before) return null;
    const binding = await bindingFor(before, context); if (!binding) return null;
    const after = await accountFor(appSubject, context);
    return after && ['accountKey', 'authVersion', 'email'].every(key => before[key] === after[key])
      ? Object.freeze({ providerSubject: binding.providerSubject, enabled: true }) : null;
  };
  const resolveTokenSubject = async (identity, context) => {
    if (identity?.issuer !== issuerOrigin || identity.clientId !== clientId || identity.audience !== resource
      || !EXTERNAL_ID.test(identity.subject || '') || !(context?.signal instanceof AbortSignal) || context.signal.aborted) return null;
    const found = await store.findBinding({ issuer: issuerOrigin, subject: identity.subject }, context);
    if (context.signal.aborted || !found || found.issuer !== issuerOrigin || found.externalId !== identity.subject) return null;
    const before = await accountFor(found.appSubject, context);
    if (!before || found.accountKey !== before.accountKey || externalId(before) !== identity.subject) return null;
    const current = await bindingFor(before, context);
    if (!sameBinding(found, current)) return null;
    const after = await accountFor(found.appSubject, context);
    return after && ['accountKey', 'authVersion', 'email'].every(key => before[key] === after[key]) ? current.providerSubject : null;
  };
  const router = express.Router({ caseSensitive: true, strict: true });
  const signals = new WeakMap();
  const context = req => ({ signal: signals.get(req) });
  const live = (req, res) => { if (Date.now() >= cutoff || context(req).signal.aborted || res.destroyed || res.headersSent) reject(503); };
  const sameSession = (left, right) => ['sessionId', 'appSubject', 'accountKey', 'authVersion'].every(key => left[key] === right[key]);
  const current = async (req, res, expected) => {
    const value = await authenticateSession(req, context(req)); live(req, res);
    if (!value || !opaque(value.sessionId) || !opaque(value.appSubject, 512) || !opaque(value.accountKey)
      || !opaque(value.authVersion) || !Number.isSafeInteger(value.expiresAt) || value.expiresAt <= Date.now()) reject(401);
    const session = Object.freeze({ sessionId: value.sessionId, appSubject: value.appSubject, accountKey: value.accountKey,
      authVersion: value.authVersion, expiresAt: value.expiresAt });
    if (expected && !sameSession(session, expected.session)) reject(403);
    const account = await accountFor(session.appSubject, context(req)); live(req, res);
    if (!account || session.accountKey !== account.accountKey || session.authVersion !== account.authVersion
      || expected && ['appSubject', 'accountKey', 'authVersion', 'email'].some(key => account[key] !== expected.account[key])) reject(403);
    return Object.freeze({ session, account });
  };
  const cookie = (res, value, seconds) => res.append('Set-Cookie', `${COOKIE}=${value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${seconds}`);
  const seal = value => {
    const iv = randomBytes(12); const cipher = createCipheriv('aes-256-gcm', envelopeKey, iv); cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value)), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString('base64url');
  };
  const pending = req => {
    const raw = req.headers.cookie; if (raw === undefined) return null;
    if (typeof raw !== 'string' || raw.length > 8192) reject();
    const found = raw.split(';').map(part => part.trim()).filter(part => part.startsWith(COOKIE + '='));
    if (!found.length) return null; if (found.length !== 1) reject();
    let value;
    try {
      const encoded = found[0].slice(COOKIE.length + 1); if (!/^[A-Za-z0-9_-]{64,2048}$/.test(encoded)) reject();
      const data = Buffer.from(encoded, 'base64url'); if (data.toString('base64url') !== encoded) reject();
      const decipher = createDecipheriv('aes-256-gcm', envelopeKey, data.subarray(0, 12));
      decipher.setAAD(aad); decipher.setAuthTag(data.subarray(12, 28));
      value = JSON.parse(Buffer.concat([decipher.update(data.subarray(28)), decipher.final()]).toString('utf8'));
    } catch { reject(); }
    if (!exact(value, ['externalAuthId', 'nonce', 'expiresAt']) || !EXTERNAL_AUTH_ID.test(value.externalAuthId)
      || !token(value.nonce) || !Number.isSafeInteger(value.expiresAt) || value.expiresAt <= Date.now()
      || value.expiresAt > Math.min(Date.now() + WINDOW, cutoff)) reject();
    return value;
  };
  const signature = (verified, path, expiresAt, nonce, state) => createHmac('sha256', csrfKey)
    .update(JSON.stringify([verified.session.sessionId, verified.session.appSubject, verified.session.accountKey, verified.session.authVersion,
      path, expiresAt, nonce, state ? hash(state.externalAuthId) : '', state?.nonce || ''])).digest('base64url');
  const csrf = (verified, path, state) => {
    const expiresAt = Math.min(Date.now() + WINDOW, verified.session.expiresAt, cutoff, state?.expiresAt ?? Infinity);
    const nonce = randomBytes(32).toString('base64url'); return `${expiresAt}.${nonce}.${signature(verified, path, expiresAt, nonce, state)}`;
  };
  const checkCsrf = (value, verified, path, state) => {
    if (typeof value !== 'string' || !/^\d{13}\.[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}$/.test(value)) reject(403);
    const [time, nonce, signed] = value.split('.'); const expiresAt = Number(time);
    if (expiresAt <= Date.now() || expiresAt > Math.min(Date.now() + WINDOW, verified.session.expiresAt, cutoff, state?.expiresAt ?? Infinity)
      || !equal(signed, signature(verified, path, expiresAt, nonce, state))) reject(403);
  };
  const page = body => '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
    + '<title>Connect your assistant</title><body><main>' + body + '</main></body></html>';
  const form = (res, verified, path, state) => res.type('html').send(page('<h1>Prepare your assistant connection</h1>'
    + `<p>Continue as <strong>${escape(verified.account.accountLabel)}</strong>.</p>`
    + '<p>Your application handles sign-in. Assistant permission is approved separately after this step.</p>'
    + `<form method="post" action="${path}"><input type="hidden" name="csrf" value="${csrf(verified, path, state)}">`
    + '<button type="submit">Continue</button></form>'));
  let count = 0; let resetAt = 0; let inFlight = 0;
  const copies = (req, name) => req.rawHeaders.filter((_, index) => index % 2 === 0 && req.rawHeaders[index].toLowerCase() === name).length;
  router.use((req, res, next) => {
    if (![BASE, BASE + '/', IDENTITY, EXTERNAL].includes(req.path)) { next(); return; }
    res.set({ 'Cache-Control': 'no-store', Pragma: 'no-cache', 'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'", 'X-Frame-Options': 'DENY' });
    if (copies(req, 'host') !== 1 || req.headers.host !== origin.host
      || ['cookie', 'origin', 'authorization', 'x-forwarded-proto'].some(name => copies(req, name) > 1)
      || req.headers.authorization !== undefined || !(req.socket.encrypted === true || trustProxyHttps && req.headers['x-forwarded-proto'] === 'https')) {
      res.status(403).end(); return;
    }
    if (Date.now() >= cutoff) { res.status(410).end(); return; }
    if (Date.now() >= resetAt) { count = 0; resetAt = Date.now() + 60_000; }
    if (++count > 60 || inFlight >= 4) { res.set('Retry-After', '60').status(429).end(); return; }
    const controller = new AbortController(); signals.set(req, controller.signal); inFlight++;
    let done = false;
    const stop = () => { if (!done) { done = true; clearTimeout(timer); controller.abort(); inFlight--; } };
    const timer = setTimeout(() => { if (!res.headersSent) res.status(503).end(); stop(); }, 15_000);
    res.once('close', stop); res.once('finish', stop); req.once('aborted', stop); next();
  });
  const guarded = work => (req, res, next) => { Promise.resolve().then(() => work(req, res, next)).catch(next); };
  const query = req => new URL(req.originalUrl, publicUrl).searchParams;
  const navigation = req => {
    if (req.headers.origin !== undefined && req.headers.origin !== publicUrl || req.headers['transfer-encoding'] !== undefined
      || req.headers['content-length'] !== undefined && req.headers['content-length'] !== '0') reject();
  };
  const signedIn = async (req, res) => {
    const verified = await authenticateSession(req, context(req)); live(req, res);
    if (!verified) { res.redirect(303, BASE + '/login'); return null; }
    return current(req, res);
  };
  router.get([BASE, BASE + '/'], guarded(async (req, res, next) => {
    navigation(req); if (query(req).size) reject();
    const verified = await signedIn(req, res); if (!verified) return;
    if (pending(req)) { res.redirect(303, EXTERNAL); return; }
    const binding = await bindingFor(verified.account, context(req)); live(req, res);
    await current(req, res, verified);
    if (!binding) { res.redirect(303, IDENTITY); return; } next();
  }));
  router.get(IDENTITY, guarded(async (req, res) => {
    navigation(req); if (query(req).size) reject();
    const verified = await signedIn(req, res); if (verified) form(res, verified, IDENTITY);
  }));
  router.get(EXTERNAL, guarded(async (req, res) => {
    navigation(req); const params = query(req); let state;
    if (params.size) {
      if (params.size !== 1 || !params.has('external_auth_id') || !EXTERNAL_AUTH_ID.test(params.get('external_auth_id'))) reject();
      state = { externalAuthId: params.get('external_auth_id'), nonce: randomBytes(32).toString('base64url'), expiresAt: Math.min(Date.now() + WINDOW, cutoff) };
      cookie(res, seal(state), Math.max(0, Math.floor((state.expiresAt - Date.now()) / 1000))); res.redirect(303, EXTERNAL); return;
    }
    state = pending(req); if (!state) reject();
    const verified = await signedIn(req, res); if (verified) form(res, verified, EXTERNAL, state);
  }));
  const post = (req, res, next) => {
    if (req.headers.origin !== publicUrl || req.headers['sec-fetch-site'] !== undefined && req.headers['sec-fetch-site'] !== 'same-origin' || query(req).size) {
      res.status(403).end(); return;
    }
    if (!req.is('application/x-www-form-urlencoded')) { res.status(415).end(); return; } next();
  };
  const prepare = async (req, res, verified) => {
    const expectedId = externalId(verified.account);
    const existing = await store.getBinding({ issuer: issuerOrigin, appSubject: verified.account.appSubject, accountKey: verified.account.accountKey }, context(req)); live(req, res);
    await current(req, res, verified);
    if (existing && (existing.externalId !== expectedId || existing.issuer !== issuerOrigin || existing.appSubject !== verified.account.appSubject
      || existing.accountKey !== verified.account.accountKey || !USER.test(existing.providerSubject))) reject(403);
    const user = await remote.ensureUser({ externalId: expectedId, email: verified.account.email }, context(req)); live(req, res);
    await current(req, res, verified);
    if (existing && existing.providerSubject !== user.providerSubject) reject(403);
    const expected = Object.freeze({ issuer: issuerOrigin, appSubject: verified.account.appSubject, accountKey: verified.account.accountKey,
      externalId: expectedId, providerSubject: user.providerSubject });
    const bound = await store.bindAccount(expected, context(req)); live(req, res); await current(req, res, verified);
    if (!sameBinding(bound, expected)) reject(403);
    const persisted = await bindingFor(verified.account, context(req)); live(req, res); await current(req, res, verified);
    if (!sameBinding(expected, persisted)) reject(403);
    return expected;
  };
  router.post([IDENTITY, EXTERNAL], post, express.urlencoded({ extended: false, inflate: false, limit: '1kb', parameterLimit: 1 }), guarded(async (req, res) => {
    if (!exact(req.body, ['csrf'])) reject();
    const state = req.path === EXTERNAL ? pending(req) : undefined; if (req.path === EXTERNAL && !state) reject();
    const verified = await current(req, res); checkCsrf(req.body.csrf, verified, req.path, state);
    if (state) {
      signals.set(req, AbortSignal.any([context(req).signal, AbortSignal.timeout(Math.max(1, state.expiresAt - Date.now()))]));
      const attempt = { externalAuthIdHash: hash(state.externalAuthId), browserNonceHash: hash(state.nonce), expiresAt: state.expiresAt };
      if (!await store.beginHandoff(attempt, context(req))) reject(409); live(req, res); await current(req, res, verified);
      if (!await store.consumeHandoff({ ...attempt, sessionId: verified.session.sessionId, appSubject: verified.session.appSubject,
        accountKey: verified.session.accountKey, authVersion: verified.session.authVersion }, context(req))) reject(409);
      live(req, res); await current(req, res, verified); cookie(res, '', 0);
    }
    const binding = await prepare(req, res, verified);
    if (!state) { res.redirect(303, BASE); return; }
    await current(req, res, verified); if (state.expiresAt <= Date.now()) reject();
    const location = await remote.complete({ externalAuthId: state.externalAuthId, externalId: binding.externalId, email: verified.account.email }, context(req)); live(req, res);
    await current(req, res, verified);
    const after = await bindingFor(verified.account, context(req)); live(req, res); await current(req, res, verified);
    if (!sameBinding(binding, after) || state.expiresAt <= Date.now()) reject(403);
    const destination = new URL(location);
    if (destination.origin !== issuerOrigin || !completionPath(destination.pathname) || destination.username || destination.password || destination.hash) reject(503);
    res.type('html').send(page('<h1>Continue your connection</h1><p>Your identity is ready. Assistant permission is approved separately.</p>'
      + `<p><a href="${escape(destination.href)}" rel="noreferrer">Continue to assistant connection</a></p>`));
  }));
  router.use((error, req, res, next) => {
    if (!signals.has(req)) { next(error); return; }
    const status = error instanceof Failure ? error.status : error?.type === 'entity.too.large' ? 413
      : ['entity.parse.failed', 'parameters.too.many', 'encoding.unsupported', 'charset.unsupported'].includes(error?.type) ? 400 : 503;
    if (res.headersSent) { res.end(); return; }
    cookie(res, '', 0); res.status(status).type('html').send(page('<h1>Connection could not be completed</h1>'
      + `<p>Return to assistant access to start a fresh attempt.</p><a href="${BASE}">Back to assistant access</a>`));
  });
  return Object.freeze({ router, resolveAccount, resolveTokenSubject });
}
