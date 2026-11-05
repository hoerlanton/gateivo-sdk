// Shared WorkOS connection runtime. See the repository MIT licence.
// Keep persisted protocol names stable when evolving this implementation.
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import express from 'express';
import { EncryptJWT, jwtDecrypt } from 'jose';
import { AccessError, createActionRegistry, createAgentRouter, createOAuthResource } from './sdk.js';
import { createWorkOSConnectProvider, createWorkOSConnectVerifier } from './workos-connect.js';

const ATTEMPT_MS = 5 * 60_000;
const CONSENT_REASONS = new Set(['UNAUTHENTICATED', 'FORBIDDEN', 'INVALID_ARGUMENT',
  'NOT_FOUND', 'UNAVAILABLE', 'TIMEOUT', 'OUTPUT_LIMIT']);
const opaque = (value, max = 512) => typeof value === 'string' && value.length > 0
  && value.length <= max && /^[\x21-\x7e]+$/.test(value);
const hash = (value) => createHash('sha256').update(value).digest('hex');
const secretText = (value) => typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value);
const escape = (value) => String(value).replace(/[&<>"']/g, (character) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[character]));
const hidden = (name, value) => `<input type="hidden" name="${name}" value="${escape(value)}">`;
const page = (body) => `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Assistant access</title><body><main>${body}</main></body></html>`;

/**
 * Application-owned reference, not a hosted authentication service.
 * Mount router at the app root after the publisher's existing session middleware.
 * authenticateSession and resolveAccount are mandatory trusted application hooks.
 * Optional resolveTokenSubject maps an already verified signed subject through
 * an existing immutable application binding; it never creates an account link.
 * Provider transport is a server-side test seam, never an HTTP request option.
 * Set mountMcp=false to compose these controls with an application-owned MCP
 * router; use the returned verifyToken, isAuthorized and oauth with that router.
 */
export function createWorkOSConnectionRuntime(options, dependencies = {}) {
  const { appId, issuer, clientId, resource: suppliedResource, publicUrl, applicationId,
    apiKey, accessTokenType, store, authenticateSession, resolveAccount, resolveTokenSubject } = options;
  const requiredStoreMethods = ['getState', 'begin', 'claimReset', 'completeReset', 'fail',
    'consume', 'cancel', 'complete', 'resolveConsent', 'revoke', 'isActive'];
  if (!store || requiredStoreMethods.some((name) => typeof store[name] !== 'function')) {
    throw new TypeError('A complete WorkOS connection store is required.');
  }
  const origin = new URL(publicUrl);
  const approvalLifetimeMs = options.approvalLifetimeMs ?? 24 * 60 * 60_000;
  const mountMcp = options.mountMcp === undefined ? true : options.mountMcp;
  const accessExpiresAt = options.accessExpiresAt ?? Infinity;
  const onConsentDiagnostic = dependencies.onConsentDiagnostic;
  if (origin.protocol !== 'https:' || origin.origin !== publicUrl || origin.username || origin.password
    || !opaque(appId) || !Number.isSafeInteger(approvalLifetimeMs) || approvalLifetimeMs < 60_000
    || approvalLifetimeMs > 7 * 24 * 60 * 60_000 || !(options.secret instanceof Uint8Array)
    || options.secret.length !== 32 || typeof authenticateSession !== 'function'
    || typeof resolveAccount !== 'function' || typeof mountMcp !== 'boolean'
    || (resolveTokenSubject !== undefined && typeof resolveTokenSubject !== 'function')
    || (onConsentDiagnostic !== undefined && typeof onConsentDiagnostic !== 'function')
    || (options.accessExpiresAt !== undefined && (!Number.isSafeInteger(accessExpiresAt)
      || accessExpiresAt < 0 || accessExpiresAt > 8_640_000_000_000_000))
    || (mountMcp && (!Array.isArray(options.actions) || !options.actions.length))) {
    throw new TypeError('Invalid WorkOS reference configuration.');
  }
  const resource = `${publicUrl}/agent/mcp`;
  if (suppliedResource !== undefined && suppliedResource !== resource) throw new TypeError('Unexpected resource path.');
  const base = `${publicUrl}/account/assistant`;
  const callback = `${base}/callback`;
  const scopes = Object.freeze([...new Set(options.requiredScopes)].sort());
  const provider = createWorkOSConnectProvider({ apiKey, issuer, clientId, applicationId,
    resource, redirectUri: callback, accessTokenType, requiredScopes: scopes, resolveTokenSubject }, dependencies);
  const key = createHmac('sha256', options.secret).update(`reference-envelope-v1:${base}`).digest();
  const csrfKey = createHmac('sha256', options.secret).update(`reference-csrf-v1:${base}`).digest();
  const cookieName = '__Host-gateivo-workos-reference';
  const cookieOptions = Object.freeze({ secure: true, httpOnly: true, sameSite: 'lax', path: '/' });
  const router = express.Router();
  const controls = express.Router();
  const trustProxyHttps = options.trustProxyHttps === true;
  const oauth = createOAuthResource({ resource, authorizationServers: [issuer],
    scopesSupported: scopes, requiredScopes: scopes });
  const beforeCutoff = () => Date.now() < accessExpiresAt;
  const requireBeforeCutoff = () => { if (!beforeCutoff()) throw new AccessError('FORBIDDEN'); };

  const mapping = async (appSubject, context) => {
    if (!beforeCutoff()) return null;
    const account = await resolveAccount({ issuer, appSubject }, context);
    context.signal.throwIfAborted();
    if (!beforeCutoff() || !account || account.enabled !== true || typeof account.providerSubject !== 'string'
      || !/^user_[A-Za-z0-9]{8,64}$/.test(account.providerSubject)) return null;
    return Object.freeze({ providerSubject: account.providerSubject });
  };
  const active = async (principal, context) => {
    if (!beforeCutoff() || principal?.appId !== appId) return false;
    const grant = await store.isActive(principal, context);
    if (!beforeCutoff() || grant !== true) return false;
    // Re-resolve the exact approved identity rather than any latest account mapping.
    const account = await mapping(principal.subject, context);
    const current = account !== null && await store.isActive(principal, { ...context,
      providerSubject: account.providerSubject, issuer, clientId, resource }) === true;
    return beforeCutoff() && current;
  };
  const verifyProviderToken = createWorkOSConnectVerifier({ appId, issuer, clientId, resource, accessTokenType, resolveTokenSubject,
    resolveConsent: async (identity, context) => {
      if (!beforeCutoff()) return null;
      const grant = await store.resolveConsent(identity, context);
      if (!grant) return null;
      const account = await mapping(grant.subject, context);
      if (!account || account.providerSubject !== identity.subject) return null;
      const fresh = await store.resolveConsent(identity, context);
      return beforeCutoff() && fresh?.authorizationId === grant.authorizationId ? fresh : null;
    },
  }, dependencies);
  const verifyToken = async (token, context) => {
    if (!beforeCutoff()) return null;
    const principal = await verifyProviderToken(token, context);
    if (!beforeCutoff() || !principal) return null;
    return Object.freeze({ ...principal, expiresAt: Math.min(principal.expiresAt, accessExpiresAt) });
  };
  const actions = mountMcp ? options.actions.map((action) => ({ ...action,
    async execute(input, context) {
      if (!await active(context.principal, context)) throw new AccessError('FORBIDDEN');
      const output = await action.execute(input, context);
      if (!await active(context.principal, context)) throw new AccessError('FORBIDDEN');
      return output;
    },
  })) : undefined;
  const registry = mountMcp ? createActionRegistry({ appId, actions,
    authorize: (_action, context) => active(context.principal, context), audit: options.audit }) : undefined;

  router.use((req, res, next) => {
    // Express mounts below match paths case-insensitively by default. The
    // transport and cutoff guard must cover the same paths as those mounts.
    const path = req.path.toLowerCase();
    const ownedPath = path === '/agent/mcp' || path.startsWith('/agent/mcp/')
      || path === '/account/assistant' || path.startsWith('/account/assistant/')
      || path === oauth.metadataPath.toLowerCase();
    if (!ownedPath) { next(); return; }
    if (req.headers.host !== origin.host
      || !(trustProxyHttps ? req.headers['x-forwarded-proto'] === 'https' : req.socket.encrypted === true)) {
      res.status(403).json({ error: 'FORBIDDEN' }); return;
    }
    if (!beforeCutoff()) { res.set('Cache-Control', 'no-store').status(410).json({ error: 'ACCESS_EXPIRED' }); return; }
    next();
  });
  router.use(oauth.router);
  if (mountMcp) router.use('/agent/mcp', createAgentRouter({ registry, resource, oauth, verifyToken }));
  router.use('/account/assistant', controls);
  let inFlight = 0;
  const failPage = (res, status) => res.status(status).type('html').send(page(
    `<h1>Unable to continue</h1><p>This request could not be completed.</p><a href="${base}">Back to assistant access</a>`));
  const binding = (session) => ({ sessionId: session.sessionId, authVersion: session.authVersion });
  const target = (session, account, approvedExpiresAt) => ({ issuer, clientId, resource,
    providerSubject: account.providerSubject, appSubject: session.appSubject, scopes, approvedExpiresAt });
  const verifiedSession = async (req, context) => {
    if (!beforeCutoff()) return null;
    const session = await authenticateSession(req, context);
    context.signal.throwIfAborted();
    if (!beforeCutoff() || !session || !opaque(session.sessionId, 256) || !opaque(session.authVersion, 256) || !opaque(session.appSubject)
      || typeof session.accountLabel !== 'string' || session.accountLabel.length > 128
      || !Number.isSafeInteger(session.expiresAt) || session.expiresAt <= Date.now()) return null;
    return Object.freeze({ ...session, expiresAt: Math.min(session.expiresAt, accessExpiresAt) });
  };
  const requireCurrentAuthority = async (req, session, account, context) => {
    requireBeforeCutoff();
    const currentSession = await verifiedSession(req, context);
    const currentAccount = await mapping(session.appSubject, context);
    if (!beforeCutoff() || !currentSession || currentSession.sessionId !== session.sessionId || currentSession.authVersion !== session.authVersion
      || currentSession.appSubject !== session.appSubject || currentAccount?.providerSubject !== account.providerSubject) {
      throw new AccessError('FORBIDDEN');
    }
  };
  const signature = (session, account, operation, revision, deadline, expiresAt, nonce, authorizationId = '') =>
    createHmac('sha256', csrfKey).update(JSON.stringify([base, issuer, clientId, scopes, session.sessionId,
      session.authVersion, session.appSubject, account.providerSubject, operation, revision, deadline,
      expiresAt, nonce, authorizationId])).digest('base64url');
  const csrf = (session, account, operation, revision, deadline, authorizationId = '') => {
    const expiresAt = Math.min(Date.now() + ATTEMPT_MS, session.expiresAt, deadline);
    const nonce = randomBytes(32).toString('base64url');
    return `${expiresAt}.${nonce}.${signature(session, account, operation, revision, deadline, expiresAt, nonce, authorizationId)}`;
  };
  const validCsrf = (token, session, account, operation, revision, deadline, authorizationId = '') => {
    if (typeof token !== 'string' || !/^\d{13}\.[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}$/.test(token)
      || !opaque(revision, 128) || !Number.isSafeInteger(deadline) || deadline <= Date.now()
      || deadline > Date.now() + approvalLifetimeMs || deadline > accessExpiresAt) return false;
    const [raw, nonce, signed] = token.split('.');
    const expiresAt = Number(raw);
    return expiresAt > Date.now() && expiresAt <= session.expiresAt && expiresAt <= deadline
      && expiresAt <= Date.now() + ATTEMPT_MS && timingSafeEqual(Buffer.from(signed),
        Buffer.from(signature(session, account, operation, revision, deadline, expiresAt, nonce, authorizationId)));
  };
  const fail = async (ticket) => {
    try { await store.fail(ticket, { signal: AbortSignal.timeout(2500) }); } catch { /* durable phase stays fenced */ }
  };
  // Only fixed, server-owned categories reach the optional observer. Its errors
  // and rejected promises cannot change callback failure or durable fencing.
  const consentDiagnostic = (phase, cause) => {
    if (!onConsentDiagnostic) return;
    try {
      const code = cause instanceof AccessError ? Object.getOwnPropertyDescriptor(cause, 'code')?.value : undefined;
      Promise.resolve(onConsentDiagnostic(Object.freeze({ operation: 'consent_callback', phase,
        reason: CONSENT_REASONS.has(code) ? code : 'internal_error' }))).catch(() => {});
    } catch {}
  };
  const query = (req) => new URL(req.originalUrl, publicUrl).searchParams;
  controls.use((req, res, next) => {
    res.set({ 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
      'Content-Security-Policy': `default-src 'none'; form-action 'self' ${issuer}; base-uri 'none'; frame-ancestors 'none'`,
      'Strict-Transport-Security': 'max-age=31536000', 'X-Frame-Options': 'DENY' });
    const navigation = req.method === 'GET' && ['/', '/callback'].includes(req.path)
      && req.headers['sec-fetch-mode'] === 'navigate' && req.headers['sec-fetch-dest'] === 'document';
    if ((req.headers.origin && req.headers.origin !== publicUrl)
      || (req.headers['sec-fetch-site'] === 'cross-site' && !navigation)) { failPage(res, 403); return; }
    if (inFlight >= 8) { failPage(res, 503); return; }
    inFlight++;
    const controller = new AbortController();
    let finished = false;
    const stop = () => { if (!finished) { finished = true; clearTimeout(timer); controller.abort(); inFlight--; } };
    const timer = setTimeout(() => { if (!res.headersSent) failPage(res, 503); stop(); }, 20_000);
    res.once('finish', stop); res.once('close', stop);
    const context = { signal: controller.signal };
    res.locals.context = context;
    void verifiedSession(req, context).then(async (session) => {
      if (controller.signal.aborted) return;
      if (!session) { failPage(res, 401); return; }
      const account = await mapping(session.appSubject, context);
      if (!account) { failPage(res, 403); return; }
      res.locals.session = session; res.locals.account = account; next();
    }).catch(() => { if (!controller.signal.aborted && !res.headersSent) failPage(res, 503); });
  });
  const guarded = (work) => (req, res) => {
    void work(req, res, res.locals.session, res.locals.account, res.locals.context).catch((cause) => {
      if (!res.locals.context.signal.aborted && !res.headersSent) failPage(res,
        cause instanceof AccessError && cause.code === 'FORBIDDEN' ? 403 : 503);
    });
  };
  controls.get('/', guarded(async (req, res, session, account, context) => {
    if (query(req).size) { failPage(res, 400); return; }
    const deadline = Math.min(Date.now() + approvalLifetimeMs, accessExpiresAt);
    const state = await store.getState(target(session, account, deadline), context);
    requireBeforeCutoff();
    const blocked = ['reset_dispatched', 'exchanging', 'blocked'].includes(state.phase);
    const pending = ['reset_pending', 'awaiting_consent'].includes(state.phase)
      && (!state.attemptExpiresAt || state.attemptExpiresAt > Date.now());
    const fields = (operation, authorizationId = '') => hidden('revision', state.revision)
      + hidden('approvedExpiresAt', deadline) + hidden('csrf', csrf(session, account, operation,
        state.revision, deadline, authorizationId));
    // Same-origin form navigation needs a non-null Origin. Callback/error
    // responses retain no-referrer so OAuth query values never become referrers.
    res.set('Referrer-Policy', 'same-origin').type('html').send(page(`<h1>Assistant access</h1><p>${escape(session.accountLabel)}</p>`
      + (state.active ? '<p>Read-only access is approved for this account.</p>'
        + '<h2>Next: connect or reconnect your assistant</h2>'
        + '<p>Return to your assistant and connect this service in its connector settings. If the connector already exists, reconnect it there.</p>'
        + '<p>If there is no reconnect action, disconnect and connect again in your assistant’s settings.</p>'
        + '<p>Finish the sign-in steps, then start a new chat and ask for fresh data.</p>'
        + '<p>This page confirms your account permission. It cannot confirm whether your assistant is connected.</p>'
        + `<form method="post" action="${base}/disconnect">`
        + fields('disconnect', state.authorizationId) + hidden('authorizationId', state.authorizationId)
        + '<button type="submit">Disconnect</button></form>'
        : '<p>No active approval.</p><p>Your assistant cannot access this account, even if its connector still says Connected.</p>')
      + (blocked ? '<p>An earlier provider operation needs administrator review before reconnecting.</p>'
        : pending ? '<p>An approval is already in progress. Finish it in the original tab, or reload after five minutes.</p>'
        : (state.active ? '<details><summary>Replace this approval</summary>'
            + '<p>Only replace this approval to start over. This stops existing assistant access. After approving again, reconnect your assistant in its connector settings.</p>'
            : '<p>First approve access below. Then connect or reconnect this service in your assistant’s connector settings and start a new chat.</p>')
          + `<p>Approve ${escape(scopes.join(', '))} until ${escape(new Date(deadline).toISOString())}.</p>`
          + `<form method="post" action="${base}/start">${fields('start')}<button type="submit">`
          + `${state.active ? 'Replace approval' : 'Approve access'}</button></form>`
          + (state.active ? '</details>' : ''))
      + `<p>Assistant MCP address: <code>${escape(resource)}</code></p>`
      + `<p>OAuth client ID: <code>${escape(clientId)}</code></p>`));
  }));
  const post = (req, res, next) => {
    if (req.headers.origin !== publicUrl || !req.is('application/x-www-form-urlencoded') || query(req).size) {
      failPage(res, 403); return;
    }
    next();
  };
  controls.post('/start', post, express.urlencoded({ extended: false, limit: '2kb', parameterLimit: 4 }),
    guarded(async (req, res, session, account, context) => {
      const deadline = Number(req.body?.approvedExpiresAt);
      if (Object.keys(req.body ?? {}).sort().join(',') !== 'approvedExpiresAt,csrf,revision'
        || !validCsrf(req.body.csrf, session, account, 'start', req.body.revision, deadline)) { failPage(res, 403); return; }
      const state = randomBytes(32).toString('base64url');
      const verifier = randomBytes(32).toString('base64url');
      const attemptExpiresAt = Math.min(Date.now() + ATTEMPT_MS, session.expiresAt, deadline);
      const ticket = await store.begin({ ...target(session, account, deadline), ...binding(session),
        expectedRevision: req.body.revision, stateHash: hash(state), attemptExpiresAt }, context);
      try {
        requireBeforeCutoff();
        await provider.resetAuthorization(account.providerSubject, { signal: context.signal,
          beforeDelete: async () => {
            await requireCurrentAuthority(req, session, account, context);
            if (!await store.claimReset(ticket, context)) throw new AccessError('FORBIDDEN');
            context.signal.throwIfAborted();
          } });
        await requireCurrentAuthority(req, session, account, context);
        if (!await store.completeReset(ticket, context)) throw new AccessError('FORBIDDEN');
        const destination = provider.authorizationUrl({ state, codeChallenge: hashBase64(verifier) });
        const envelope = await new EncryptJWT({ state, verifier, operationId: ticket.operationId, approvedExpiresAt: deadline })
          .setProtectedHeader({ alg: 'dir', enc: 'A256GCM', typ: 'gateivo-reference+jwt' })
          .setIssuer(publicUrl).setAudience(callback).setIssuedAt()
          .setExpirationTime(Math.floor(attemptExpiresAt / 1000)).encrypt(key);
        requireBeforeCutoff();
        context.signal.throwIfAborted();
        res.cookie(cookieName, envelope, { ...cookieOptions, maxAge: Math.max(0, attemptExpiresAt - Date.now()) });
        res.redirect(303, destination);
      } catch (cause) { await fail(ticket); throw cause; }
    }));
  controls.post('/disconnect', post, express.urlencoded({ extended: false, limit: '2kb', parameterLimit: 4 }),
    guarded(async (req, res, session, account, context) => {
      const deadline = Number(req.body?.approvedExpiresAt);
      if (Object.keys(req.body ?? {}).sort().join(',') !== 'approvedExpiresAt,authorizationId,csrf,revision'
        || !opaque(req.body.authorizationId, 128) || !validCsrf(req.body.csrf, session, account, 'disconnect',
          req.body.revision, deadline, req.body.authorizationId)) { failPage(res, 403); return; }
      if (!await store.revoke({ appSubject: session.appSubject, authorizationId: req.body.authorizationId,
        expectedRevision: req.body.revision }, context)) { failPage(res, 403); return; }
      requireBeforeCutoff();
      res.redirect(303, base);
    }));
  controls.get('/callback', guarded(async (req, res, session, account, context) => {
    const params = query(req);
    const state = params.get('state'); const code = params.get('code'); const denied = params.get('error');
    const keys = [...params.keys()];
    if (!secretText(state) || new Set(keys).size !== keys.length
      || (denied ? code !== null || keys.some((value) => !['state', 'error', 'error_description'].includes(value))
        : keys.length !== 2 || !opaque(code, 2048))) { failPage(res, 400); return; }
    const cookies = (req.headers.cookie ?? '').split(';').map((part) => part.trim()).filter((part) => part.startsWith(`${cookieName}=`));
    if (cookies.length !== 1 || cookies[0].length > 4096 || (req.headers.cookie?.length ?? 0) > 8192) { failPage(res, 400); return; }
    let attempt;
    try {
      const verified = await jwtDecrypt(cookies[0].slice(cookieName.length + 1), key, { issuer: publicUrl, audience: callback,
        maxTokenAge: '5m', keyManagementAlgorithms: ['dir'], contentEncryptionAlgorithms: ['A256GCM'] });
      attempt = verified.payload;
      if (verified.protectedHeader.typ !== 'gateivo-reference+jwt' || !secretText(attempt.state)
        || !secretText(attempt.verifier) || !opaque(attempt.operationId, 128)
        || !Number.isSafeInteger(attempt.approvedExpiresAt) || attempt.approvedExpiresAt <= Date.now()
        || attempt.approvedExpiresAt > accessExpiresAt
        || !timingSafeEqual(Buffer.from(state), Buffer.from(attempt.state))) throw new Error();
    } catch { failPage(res, 400); return; }
    const callbackIdentity = { ...target(session, account, attempt.approvedExpiresAt), ...binding(session),
      operationId: attempt.operationId, stateHash: hash(state) };
    if (denied) {
      // No token exchange was started. A verified denial can safely be retried.
      if (!await store.cancel(callbackIdentity, context)) { failPage(res, 400); return; }
      res.clearCookie(cookieName, cookieOptions);
      res.status(403).type('html').send(page(`<h1>Access was not approved</h1><a href="${base}">Try again</a>`));
      return;
    }
    const ticket = await store.consume(callbackIdentity, context);
    if (!ticket) { failPage(res, 400); return; }
    res.clearCookie(cookieName, cookieOptions);
    let phase = 'token_exchange';
    try {
      requireBeforeCutoff();
      const identity = await provider.exchangeCode({ code, codeVerifier: attempt.verifier,
        expectedUserId: account.providerSubject }, context);
      phase = 'authority_recheck';
      await requireCurrentAuthority(req, session, account, context);
      phase = 'store_complete';
      await store.complete(ticket, identity, context);
      requireBeforeCutoff();
      context.signal.throwIfAborted(); res.redirect(303, base);
    } catch (cause) { await fail(ticket); consentDiagnostic(phase, cause); throw cause; }
  }));
  controls.use((_req, res) => failPage(res, 404));
  controls.use((_error, _req, res, _next) => {
    if (!res.headersSent && !res.locals.context?.signal.aborted) failPage(res, 400);
  });
  return Object.freeze({ router, verifyToken, isAuthorized: active, registry, oauth, provider });
}

function hashBase64(value) { return createHash('sha256').update(value).digest('base64url'); }
