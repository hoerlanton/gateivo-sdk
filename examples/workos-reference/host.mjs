#!/usr/bin/env node
/** Fictional app host. Importing this module never reads configuration or starts a server. */
import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createServer as createHttpServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { z } from 'zod/v4';
import { AccessError, defineAction } from '@gateivo/sdk';
import { createWorkOSReference } from './index.mjs';
import { createWorkOSReferenceStore } from './store.mjs';
import { accountVersion, configurationIdentity, readHostConfig, readPrivateFile,
  validateHostConfig, validateTestApiKey, verifyPassword } from './host-config.mjs';

const APP_COOKIE = '__Host-gateivo-reference-app';
const LOGIN_COOKIE = '__Host-gateivo-reference-login';
const SESSION_MS = 60 * 60_000;
const FORM_MS = 5 * 60_000;
const MAX_SESSIONS = 200;
const opaque = value => typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value);
const escape = value => String(value).replace(/[&<>"']/g,
  character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));
const hash = value => createHash('sha256').update(value).digest('hex');
const cookieOptions = Object.freeze({ secure: true, httpOnly: true, sameSite: 'lax', path: '/' });
const same = (left, right) => typeof left === 'string' && typeof right === 'string'
  && Buffer.byteLength(left) === Buffer.byteLength(right) && timingSafeEqual(Buffer.from(left), Buffer.from(right));
const hidden = (name, value) => `<input type="hidden" name="${escape(name)}" value="${escape(value)}">`;
const page = (title, body) => `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>${escape(title)} · Gateivo reference</title>
<style>body{margin:0;background:#fffaf2;color:#2c2521;font:17px/1.6 system-ui,sans-serif}main{max-width:650px;margin:60px auto;padding:0 24px}header{display:flex;justify-content:space-between;gap:20px;border-bottom:1px solid #e7d7cb;padding-bottom:24px}strong.brand{font-size:28px;letter-spacing:-1px}strong.brand span{color:#e86145}.notice{background:#f7ebe2;border:1px solid #edc7b7;border-radius:12px;padding:16px;margin:32px 0}h1{font-size:36px;line-height:1.15}form{display:grid;gap:12px}label{display:grid;gap:5px}input{font:inherit;padding:12px;border:1px solid #c9b8aa;border-radius:8px;background:#fff}button{justify-self:start;background:#e86145;color:#fff;font:inherit;font-weight:650;padding:12px 20px;border:0;border-radius:8px;cursor:pointer}a{color:#a73d28}code{overflow-wrap:anywhere}small,footer{color:#75675f}footer{margin:36px 0;border-top:1px solid #e7d7cb;padding-top:18px;font-size:14px}.error{color:#9c281b}</style></head><body><main>
<header><strong class="brand">gateivo<span>.</span></strong><small>Fictional app reference</small></header>
<p class="notice">Development only · Fictional workouts · Real delegated authentication when configured.</p>
${body}<footer>This reference demonstrates the application hooks. Publishers keep their own sign-in, accounts and business services.</footer>
</main></body></html>`;

function cookie(request, name) {
  const header = request.headers.cookie;
  if (typeof header !== 'string' || header.length > 4096) return null;
  const matches = header.split(';').map(part => part.trim()).filter(part => part.startsWith(`${name}=`));
  return matches.length === 1 ? matches[0].slice(name.length + 1) : null;
}

function nativeLoopback(address) {
  return ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(address);
}

function workoutActions(isAuthorized) {
  // Application-owned services. The query condition always includes the canonical owner.
  const rows = Object.freeze([
    Object.freeze({ id: 'workout-alice-1', ownerId: 'alice', title: 'Morning trail ride',
      activity: 'cycling', startedAt: '2026-10-20T07:30:00.000Z', durationMinutes: 55,
      internalNote: 'FICTIONAL_PRIVATE_ALICE_NOTE' }),
    Object.freeze({ id: 'workout-bob-1', ownerId: 'bob', title: 'Pool session',
      activity: 'swimming', startedAt: '2026-10-21T08:00:00.000Z', durationMinutes: 40,
      internalNote: 'FICTIONAL_PRIVATE_BOB_NOTE' }),
  ]);
  const idSchema = z.string().regex(/^workout-[a-z0-9-]{1,80}$/);
  const output = z.object({ id: idSchema, title: z.string().max(120),
    activity: z.enum(['cycling', 'running', 'swimming']), startedAt: z.iso.datetime(),
    durationMinutes: z.number().int().min(1).max(1440) }).strict();
  const project = row => ({ id: row.id, title: row.title, activity: row.activity,
    startedAt: row.startedAt, durationMinutes: row.durationMinutes });
  const assertActive = async context => {
    context.signal.throwIfAborted();
    if (!await isAuthorized(context.principal, context)) throw new AccessError('FORBIDDEN');
    context.signal.throwIfAborted();
  };
  return [defineAction({
    name: 'workouts_list', title: 'List my workouts',
    description: 'Read up to 20 fictional workouts owned by the connected account.',
    requiredScopes: ['workouts:read'],
    inputSchema: z.object({ limit: z.number().int().min(1).max(20).default(10) }).strict(),
    outputSchema: z.object({ workouts: z.array(output).max(20) }).strict(),
    async execute({ limit }, context) {
      await assertActive(context);
      const result = rows.filter(row => row.ownerId === context.principal.subject).slice(0, limit).map(project);
      await assertActive(context);
      return { workouts: result };
    },
  }), defineAction({
    name: 'workouts_get', title: 'Read my workout',
    description: 'Read one fictional workout owned by the connected account.',
    requiredScopes: ['workouts:read'], inputSchema: z.object({ workoutId: idSchema }).strict(),
    outputSchema: z.object({ workout: output }).strict(),
    async execute({ workoutId }, context) {
      await assertActive(context);
      const row = rows.find(record => record.id === workoutId && record.ownerId === context.principal.subject);
      if (!row) throw new AccessError('NOT_FOUND');
      await assertActive(context);
      return { workout: project(row) };
    },
  })];
}

/**
 * loadConfig and referenceFactory are trusted composition/test seams. They are
 * never selected from an HTTP request. CLI startup always loads a private file.
 */
export async function createReferenceHost(options, dependencies = {}) {
  const config = validateHostConfig(options.config);
  const apiKey = validateTestApiKey(options.apiKey);
  const appId = 'workouts-example';
  const createActions = dependencies.createActions ?? (({ isAuthorized }) => workoutActions(isAuthorized));
  if (typeof createActions !== 'function') throw new TypeError('Invalid trusted action factory.');
  const clock = dependencies.now ?? Date.now;
  const loadConfig = dependencies.loadConfig ?? (async () => config);
  const referenceFactory = dependencies.referenceFactory ?? createWorkOSReference;
  const identity = configurationIdentity(config);
  const secret = Buffer.from(config.secret, 'base64url');
  const origin = new URL(config.publicUrl);
  const sessions = new Map();
  const ownedStore = !dependencies.store;
  const store = dependencies.store ?? createWorkOSReferenceStore({ path: config.databasePath });
  let closed = false;
  let loginInFlight = 0;
  let rateWindow = clock();
  let attempts = 0;
  const sign = value => createHmac('sha256', secret).update(value).digest('base64url');
  const dummy = { salt: secret.subarray(0, 16).toString('base64url'),
    digest: Buffer.alloc(64).toString('base64url') };
  const currentAccounts = async () => {
    if (closed) return null;
    try {
      const current = validateHostConfig(await loadConfig());
      return configurationIdentity(current) === identity ? current.accounts : null;
    } catch { return null; }
  };
  const account = async id => (await currentAccounts())?.find(value => value.id === id) ?? null;
  const authenticateSession = async (request, { signal } = {}) => {
    if (closed || signal?.aborted) return null;
    const token = cookie(request, APP_COOKIE);
    if (!opaque(token)) return null;
    const key = hash(token);
    const session = sessions.get(key);
    if (!session || session.expiresAt <= clock()) { sessions.delete(key); return null; }
    const current = await account(session.appSubject);
    if (signal?.aborted || !current?.enabled || session.authVersion !== accountVersion(current)) {
      sessions.delete(key); return null;
    }
    return Object.freeze({ ...session, accountLabel: current.label });
  };
  const resolveAccount = async ({ issuer, appSubject }, { signal } = {}) => {
    if (closed || signal?.aborted || issuer !== config.issuer) return null;
    const current = await account(appSubject);
    return !signal?.aborted && current?.enabled
      ? Object.freeze({ providerSubject: current.providerSubject, enabled: true }) : null;
  };
  // Source-example composition hook. It receives the SDK's verified principal,
  // never browser/tool arguments, and exposes only the current canonical binding.
  // Delegated reads do not require an active browser session or its cookie.
  const resolveApplicationAccount = async (principal, { signal } = {}) => {
    if (closed || signal?.aborted || principal?.appId !== appId
      || typeof principal.subject !== 'string') return null;
    const current = await account(principal.subject);
    if (closed || signal?.aborted || !current?.enabled) return null;
    return Object.freeze({ appId, subject: current.id, issuer: config.issuer,
      providerSubject: current.providerSubject, authVersion: accountVersion(current) });
  };

  let assistantAccess;
  try {
    const actions = createActions(Object.freeze({ appId,
      isAuthorized: (principal, context) => assistantAccess?.isAuthorized(principal, context) ?? false,
      resolveApplicationAccount,
    }));
    assistantAccess = referenceFactory({ appId, publicUrl: config.publicUrl,
      issuer: config.issuer, clientId: config.clientId, applicationId: config.applicationId,
      apiKey, accessTokenType: config.accessTokenType, requiredScopes: ['workouts:read'],
      secret, store, authenticateSession, resolveAccount,
      trustProxyHttps: config.transport === 'loopback-proxy',
      actions,
    }, dependencies.provider ?? {});
  } catch (error) {
    if (ownedStore) await store.close();
    throw error;
  }

  const app = express();
  app.disable('x-powered-by');
  app.set('query parser', 'simple');
  app.use((request, response, next) => {
    response.set({ 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer', 'Strict-Transport-Security': 'max-age=31536000',
      'X-Frame-Options': 'DENY',
      'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'" });
    const secure = config.transport === 'tls' ? request.socket.encrypted === true
      : nativeLoopback(request.socket.remoteAddress) && request.headers['x-forwarded-proto'] === 'https';
    if (closed) { response.status(503).json({ error: 'UNAVAILABLE' }); return; }
    if (!secure || request.headers.host !== origin.host
      || request.originalUrl.length > 8192) { response.status(403).json({ error: 'FORBIDDEN' }); return; }
    next();
  });
  const asyncRoute = work => (request, response, next) => {
    Promise.resolve(work(request, response, next)).catch(next);
  };
  const reject = (response, status = 403) => response.status(status).type('html').send(page('Unable to continue',
    '<h1>Unable to continue</h1><p>This request could not be completed.</p><a href="/sign-in">Return to sign-in</a>'));
  const browserPost = request => request.headers.origin === config.publicUrl
    && (!request.headers['sec-fetch-site'] || ['same-origin', 'none'].includes(request.headers['sec-fetch-site']))
    && request.is('application/x-www-form-urlencoded') && !request.originalUrl.includes('?');
  const strictBody = (request, keys) => request.body && typeof request.body === 'object'
    && Object.keys(request.body).length === keys.length
    && keys.every(key => typeof request.body[key] === 'string');
  const body = express.urlencoded({ extended: false, limit: '4kb', parameterLimit: 4 });
  const bootstrap = () => {
    const value = `${clock() + FORM_MS}.${randomBytes(32).toString('base64url')}`;
    return `${value}.${sign(`login:${config.publicUrl}:${value}`)}`;
  };
  const validBootstrap = (request, value) => {
    if (typeof value !== 'string' || !/^\d{13}\.[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}$/.test(value)
      || !same(cookie(request, LOGIN_COOKIE), value)) return false;
    const [expires, nonce, signature] = value.split('.');
    return Number(expires) > clock() && Number(expires) <= clock() + FORM_MS
      && same(signature, sign(`login:${config.publicUrl}:${expires}.${nonce}`));
  };
  const logoutCsrf = session => sign(`logout:${config.publicUrl}:${session.sessionId}:${session.authVersion}:${session.expiresAt}`);
  const signInPage = (response, error = false) => {
    const csrf = bootstrap();
    response.cookie(LOGIN_COOKIE, csrf, { ...cookieOptions, maxAge: FORM_MS });
    return response.status(error ? 401 : 200).type('html').send(page('Sign in', `<h1>Sign in to fictional workouts</h1>
<p>Use the Alice or Bob app password created by the setup command. WorkOS approval happens separately after sign-in.</p>
${error ? '<p class="error" role="alert">Sign-in was not accepted. Check the fictional account credentials.</p>' : ''}
<form method="post" action="/sign-in">${hidden('csrf', csrf)}
<label>Email<input type="email" name="email" autocomplete="username" maxlength="254" required></label>
<label>Password<input type="password" name="password" autocomplete="current-password" maxlength="128" required></label>
<button type="submit">Sign in</button></form>
<p><small>Fictional accounts: alice@gateivo.example and bob@gateivo.example. No signup or password reset is provided by this example.</small></p>`));
  };

  app.get('/healthz', (_request, response) => response.json({ status: 'ok', example: 'fictional-workouts' }));
  app.get('/sign-in', asyncRoute(async (request, response) => {
    if (request.originalUrl.includes('?') || request.headers.origin && request.headers.origin !== config.publicUrl) {
      reject(response); return;
    }
    if (await authenticateSession(request)) { response.redirect(303, '/'); return; }
    signInPage(response);
  }));
  app.post('/sign-in', body, asyncRoute(async (request, response) => {
    if (!browserPost(request) || !strictBody(request, ['email', 'password', 'csrf'])
      || !validBootstrap(request, request.body.csrf)) { reject(response); return; }
    response.clearCookie(LOGIN_COOKIE, cookieOptions);
    if (clock() - rateWindow >= 60_000) { rateWindow = clock(); attempts = 0; }
    if (attempts >= 12 || loginInFlight >= 2) { reject(response, 429); return; }
    attempts++; loginInFlight++;
    try {
      const email = request.body.email.trim().toLowerCase();
      const selected = email.length <= 254
        ? (await currentAccounts())?.find(value => value.email === email) : null;
      const accepted = await verifyPassword(request.body.password, selected?.password ?? dummy);
      const fresh = selected ? await account(selected.id) : null;
      if (!accepted || !selected?.enabled || !fresh?.enabled
        || accountVersion(selected) !== accountVersion(fresh)) { signInPage(response, true); return; }
      for (const [key, session] of sessions) if (session.expiresAt <= clock()) sessions.delete(key);
      if (sessions.size >= MAX_SESSIONS) { reject(response, 503); return; }
      const previous = cookie(request, APP_COOKIE);
      if (opaque(previous)) sessions.delete(hash(previous));
      const token = randomBytes(32).toString('base64url');
      sessions.set(hash(token), Object.freeze({ sessionId: randomUUID(), authVersion: accountVersion(fresh),
        appSubject: fresh.id, expiresAt: clock() + SESSION_MS }));
      response.cookie(APP_COOKIE, token, { ...cookieOptions, maxAge: SESSION_MS });
      response.redirect(303, '/account/assistant');
    } finally { loginInFlight--; }
  }));
  app.get('/', asyncRoute(async (request, response) => {
    if (request.originalUrl.includes('?')) { reject(response); return; }
    const session = await authenticateSession(request);
    if (!session) { response.redirect(303, '/sign-in'); return; }
    response.type('html').send(page('Your account', `<h1>Your fictional workout account</h1>
<p>Signed in as <strong>${escape(session.accountLabel)}</strong>.</p>
<p><a href="/account/assistant">Manage assistant access</a></p>
<p>MCP endpoint: <code>${escape(config.publicUrl)}/agent/mcp</code></p>
<p>Signing out ends this browser session. Use <strong>Disconnect</strong> in assistant access to revoke delegated permission.</p>
<form method="post" action="/sign-out">${hidden('csrf', logoutCsrf(session))}<button type="submit">Sign out</button></form>`));
  }));
  app.post('/sign-out', body, asyncRoute(async (request, response) => {
    const session = await authenticateSession(request);
    if (!browserPost(request) || !session || !strictBody(request, ['csrf'])
      || !same(request.body.csrf, logoutCsrf(session))) { reject(response); return; }
    sessions.delete(hash(cookie(request, APP_COOKIE)));
    response.clearCookie(APP_COOKIE, cookieOptions);
    response.clearCookie(LOGIN_COOKIE, cookieOptions);
    response.redirect(303, '/sign-in');
  }));
  app.get('/account/assistant', asyncRoute(async (request, response, next) => {
    if (!await authenticateSession(request)) { response.redirect(303, '/sign-in'); return; }
    // Leave the reference's own host, CSRF, session and consent checks in place.
    next();
  }));
  app.use(assistantAccess.router);
  app.use((_request, response) => response.status(404).type('html').send(page('Not found', '<h1>Page not found</h1>')));
  app.use((_error, _request, response, _next) => {
    if (!response.headersSent) reject(response, 400);
    else response.destroy();
  });
  return Object.freeze({ app, reference: assistantAccess,
    async close() { closed = true; sessions.clear(); if (ownedStore) await store.close(); } });
}

export async function runReferenceHost(environment = process.env) {
  if (Number(process.versions.node.split('.')[0]) !== 24) {
    throw new TypeError('The authenticated reference host requires Node.js 24.');
  }
  const filename = environment.GATEIVO_REFERENCE_CONFIG;
  const config = await readHostConfig(filename);
  const apiKey = validateTestApiKey(environment.WORKOS_API_KEY);
  let tls;
  if (config.transport === 'tls') {
    const certFile = environment.GATEIVO_REFERENCE_TLS_CERT_FILE;
    const keyFile = environment.GATEIVO_REFERENCE_TLS_KEY_FILE;
    if (typeof certFile !== 'string' || !path.isAbsolute(certFile)
      || typeof keyFile !== 'string' || !path.isAbsolute(keyFile)) {
      throw new TypeError('Direct TLS requires explicit certificate and private key files.');
    }
    tls = { cert: await readFile(certFile), key: await readPrivateFile(keyFile, 1024 * 1024),
      minVersion: 'TLSv1.2' };
  } else if (environment.GATEIVO_REFERENCE_TLS_CERT_FILE || environment.GATEIVO_REFERENCE_TLS_KEY_FILE) {
    throw new TypeError('Direct TLS files do not apply to loopback-proxy mode.');
  }
  const host = await createReferenceHost({ config, apiKey }, { loadConfig: () => readHostConfig(filename) });
  const server = tls ? createHttpsServer(tls, host.app) : createHttpServer(host.app);
  server.requestTimeout = 15_000;
  server.headersTimeout = 10_000;
  server.keepAliveTimeout = 5_000;
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(config.port, '127.0.0.1', () => { server.off('error', reject); resolve(); });
    });
  } catch (error) { await host.close(); throw error; }
  server.on('error', () => { console.error('Reference HTTP server unavailable.'); });
  const stop = () => {
    const deadline = setTimeout(() => server.closeAllConnections(), 5000);
    deadline.unref();
    server.close(() => { clearTimeout(deadline); host.close().catch(() => {
      console.error('Reference storage could not close cleanly.'); process.exitCode = 1;
    }); });
  };
  process.once('SIGINT', stop); process.once('SIGTERM', stop);
  console.log(`Fictional reference host listening on 127.0.0.1:${config.port}.`);
  console.log('Open the configured HTTPS public URL. This example uses no customer data.');
  return Object.freeze({ server, host });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runReferenceHost().catch(() => {
    console.error('Reference host could not start. Check private configuration and development provider settings.');
    process.exitCode = 1;
  });
}
