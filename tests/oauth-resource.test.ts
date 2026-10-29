import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { test, type TestContext } from 'node:test';
import express from 'express';
import { z } from 'zod/v4';
import { createActionRegistry } from '../src/core.js';
import { createAgentRouter } from '../src/http.js';
import { createOAuthResource } from '../src/oauth-resource.js';
import type { Principal } from '../src/types.js';

const ISSUER = 'https://issuer.example/tenant';
const ALLOWED_ORIGIN = 'https://assistant.example';
const RESOURCE = 'https://api.example/agent/mcp';
const config = () => ({
  resource: RESOURCE,
  authorizationServers: [ISSUER],
  scopesSupported: ['workouts:read', 'maintenance:write'],
  requiredScopes: ['workouts:read'],
});

function challenge(response: Response): Record<string, string> {
  const value = response.headers.get('www-authenticate');
  assert.ok(value, 'expected a WWW-Authenticate header');
  assert.ok(value.startsWith('Bearer '), 'expected a Bearer challenge');
  return Object.fromEntries([...value.matchAll(/([a-z_]+)="([^"\\]*)"/g)]
    .map((match) => [match[1]!, match[2]!]));
}

async function harness(t: TestContext, resourcePath = '/agent/mcp') {
  const app = express();
  app.disable('x-powered-by');
  const server = createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Missing local server address');
  const origin = `http://127.0.0.1:${address.port}`;
  const resource = `${origin}${resourcePath}`;
  const oauth = createOAuthResource({ ...config(), resource });
  const counts = { verifier: 0, action: 0 };
  const actor: Principal = {
    appId: 'example-app', subject: 'alice', scopes: ['workouts:read'], expiresAt: Date.now() + 60_000,
  };
  const tokens: Record<string, Principal> = {
    alice: actor,
    expired: { ...actor, expiresAt: Date.now() - 1 },
    noscope: { ...actor, scopes: [] },
    otherapp: { ...actor, appId: 'another-app' },
  };
  const registry = createActionRegistry({ appId: 'example-app', actions: [{
    name: 'read_setup', title: 'Read setup', description: 'Read an owned setup.',
    requiredScopes: ['workouts:read'],
    inputSchema: z.strictObject({}), outputSchema: z.strictObject({ name: z.string() }),
    execute: async (_input, context) => {
      counts.action++;
      return { name: `${context.principal.subject}'s setup` };
    },
  }] });
  app.use(oauth.router);
  app.use(resourcePath, createAgentRouter({
    registry, resource, oauth, allowedOrigins: [ALLOWED_ORIGIN],
    verifyToken: async (token, context) => {
      counts.verifier++;
      assert.equal(context.audience, resource);
      return tokens[token] ?? null;
    },
  }));
  const post = (token?: string, query = '', extraHeaders: Record<string, string> = {}) => fetch(`${resource}${query}`, {
    method: 'POST', headers: {
      'content-type': 'application/json', accept: 'application/json, text/event-stream',
      ...(token ? { authorization: `Bearer ${token}` } : {}), ...extraHeaders,
    }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
  });
  const raw = (path: string, headers: Record<string, string>) => new Promise<{
    status: number | undefined; body: string;
  }>((resolve, reject) => {
    const req = request(new URL(path, origin), { headers }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (chunk: string) => { body += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('error', reject);
    req.end();
  });
  return { origin, resource, oauth, counts, post, raw };
}

test('protected resource metadata is public at the resource-specific well-known path', async (t) => {
  const h = await harness(t);
  assert.equal(h.oauth.metadataPath, '/.well-known/oauth-protected-resource/agent/mcp');
  assert.equal(h.oauth.metadataUrl, `${h.origin}${h.oauth.metadataPath}`);
  const response = await fetch(h.oauth.metadataUrl);
  assert.equal(response.status, 200);
  assert.match(response.headers.get('content-type') ?? '', /application\/json/);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.deepEqual(await response.json(), {
    resource: h.resource, authorization_servers: [ISSUER],
    scopes_supported: ['workouts:read', 'maintenance:write'], bearer_methods_supported: ['header'],
  });
  const head = await fetch(h.oauth.metadataUrl, { method: 'HEAD' });
  assert.equal(head.status, 200);
  assert.equal(await head.text(), '');
  assert.equal((await fetch(`${h.origin}/.well-known/oauth-protected-resource`)).status, 404);
  assert.equal((await fetch(`${h.resource}/.well-known/oauth-protected-resource`)).status, 401);
  assert.deepEqual(h.counts, { verifier: 0, action: 0 });
});

test('trailing-slash resource discovery serves both paths without changing resource identity', async (t) => {
  const h = await harness(t, '/agent/mcp/');
  assert.equal(h.oauth.resource, `${h.origin}/agent/mcp/`);
  assert.equal(h.oauth.metadataPath, '/.well-known/oauth-protected-resource/agent/mcp/');
  assert.equal(h.oauth.metadataUrl, `${h.origin}${h.oauth.metadataPath}`);
  for (const path of [h.oauth.metadataPath, h.oauth.metadataPath.slice(0, -1)]) {
    const response = await fetch(`${h.origin}${path}`);
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), h.oauth.metadata);
    assert.equal(h.oauth.metadata.resource, h.resource);
    assert.deepEqual(h.oauth.metadata.authorization_servers, [ISSUER]);
  }
  const unauthorized = await h.post();
  assert.equal(unauthorized.status, 401);
  assert.equal(challenge(unauthorized).resource_metadata, h.oauth.metadataUrl);
  assert.deepEqual(h.counts, { verifier: 0, action: 0 });
});

test('metadata and challenges cannot be rewritten by query or proxy headers', async (t) => {
  const h = await harness(t);
  const headers = {
    forwarded: 'host=attacker.invalid;proto=https',
    'x-forwarded-host': 'attacker.invalid', 'x-forwarded-proto': 'https',
  };
  const response = await fetch(`${h.oauth.metadataUrl}?resource=https://attacker.invalid&issuer=https://attacker.invalid`, { headers });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), h.oauth.metadata);
  const unauthorized = await h.post(undefined, '?resource_metadata=https://attacker.invalid', headers);
  assert.equal(unauthorized.status, 401);
  assert.equal(challenge(unauthorized).resource_metadata, h.oauth.metadataUrl);
  const hostile = await h.raw(h.oauth.metadataPath, { host: 'attacker.invalid' });
  assert.equal(hostile.status, 403);
  assert.doesNotMatch(hostile.body, /authorization_servers|issuer\.example/);
  assert.deepEqual(h.counts, { verifier: 0, action: 0 });
});

test('missing and invalid tokens advertise discovery without leaking credentials', async (t) => {
  const h = await harness(t);
  const missing = await h.post();
  assert.equal(missing.status, 401);
  assert.deepEqual(challenge(missing), {
    resource_metadata: h.oauth.metadataUrl, scope: 'workouts:read',
  });
  for (const token of ['canary-invalid-token', 'expired']) {
    const response = await h.post(token);
    assert.equal(response.status, 401);
    assert.deepEqual(challenge(response), {
      resource_metadata: h.oauth.metadataUrl, scope: 'workouts:read', error: 'invalid_token',
    });
    assert.doesNotMatch(await response.text(), /canary|alice|issuer|signature/);
  }
  assert.equal(h.counts.action, 0);
});

test('only insufficient scopes trigger a scope-upgrade challenge', async (t) => {
  const h = await harness(t);
  const denied = await h.post('noscope');
  assert.equal(denied.status, 403);
  assert.deepEqual(challenge(denied), {
    resource_metadata: h.oauth.metadataUrl, scope: 'workouts:read', error: 'insufficient_scope',
  });
  const wrongApp = await h.post('otherapp');
  assert.equal(wrongApp.status, 403);
  assert.doesNotMatch(wrongApp.headers.get('www-authenticate') ?? '', /insufficient_scope|scope=/);
  assert.equal(h.counts.action, 0);
});

test('query bearer credentials are rejected even alongside a valid header', async (t) => {
  const h = await harness(t);
  for (const token of [undefined, 'alice']) {
    const response = await h.post(token, '?access_token=canary-query-token');
    assert.equal(response.status, 400);
    assert.doesNotMatch(await response.text(), /canary-query-token/);
  }
  assert.deepEqual(h.counts, { verifier: 0, action: 0 });
});

test('public metadata supports cross-origin discovery while MCP origins stay restricted', async (t) => {
  const h = await harness(t);
  const metadata = await fetch(h.oauth.metadataUrl, { headers: { origin: 'https://unregistered.example' } });
  assert.equal(metadata.status, 200);
  assert.equal(metadata.headers.get('access-control-allow-origin'), '*');
  assert.notEqual(metadata.headers.get('access-control-allow-credentials'), 'true');
  const unauthorized = await h.post(undefined, '', { origin: ALLOWED_ORIGIN });
  assert.equal(unauthorized.status, 401);
  assert.equal(unauthorized.headers.get('access-control-allow-origin'), ALLOWED_ORIGIN);
  assert.match(unauthorized.headers.get('access-control-expose-headers') ?? '', /www-authenticate/i);
  const forbidden = await h.post('alice', '', { origin: 'https://attacker.invalid' });
  assert.equal(forbidden.status, 403);
  assert.equal(forbidden.headers.get('access-control-allow-origin'), null);
  assert.equal(h.counts.verifier, 0);
});

test('approved browser preflight is public and a forbidden origin cannot preflight MCP', async (t) => {
  const h = await harness(t);
  const headers = {
    origin: ALLOWED_ORIGIN, 'access-control-request-method': 'POST',
    // The official client adds mcp-method to modern discovery and mcp-name to tools/call.
    'access-control-request-headers': 'authorization,content-type,mcp-protocol-version,mcp-method,mcp-name',
  };
  const approved = await fetch(h.resource, { method: 'OPTIONS', headers });
  assert.ok(approved.status >= 200 && approved.status < 300);
  assert.equal(approved.headers.get('access-control-allow-origin'), ALLOWED_ORIGIN);
  assert.match(approved.headers.get('access-control-allow-methods') ?? '', /\bPOST\b/);
  for (const name of ['authorization', 'content-type', 'mcp-protocol-version', 'mcp-method', 'mcp-name']) {
    assert.ok((approved.headers.get('access-control-allow-headers') ?? '').toLowerCase()
      .split(',').map((item) => item.trim()).includes(name), `${name} must be allowed`);
  }
  const forbidden = await fetch(h.resource, {
    method: 'OPTIONS', headers: { ...headers, origin: 'https://attacker.invalid' },
  });
  assert.equal(forbidden.status, 403);
  assert.equal(forbidden.headers.get('access-control-allow-origin'), null);
  assert.deepEqual(h.counts, { verifier: 0, action: 0 });
});

test('OAuth resource configuration is a frozen snapshot, including nested scope arrays', () => {
  const options = config();
  const oauth = createOAuthResource(options);
  options.authorizationServers.push('https://attacker.invalid');
  options.scopesSupported.push('admin');
  options.requiredScopes[0] = 'admin';
  options.resource = 'https://attacker.invalid/mcp';
  assert.equal(oauth.resource, RESOURCE);
  assert.deepEqual(oauth.metadata.authorization_servers, [ISSUER]);
  assert.deepEqual(oauth.metadata.scopes_supported, ['workouts:read', 'maintenance:write']);
  assert.deepEqual(oauth.requiredScopes, ['workouts:read']);
  for (const value of [oauth, oauth.metadata, oauth.metadata.authorization_servers,
    oauth.metadata.scopes_supported, oauth.metadata.bearer_methods_supported, oauth.requiredScopes]) {
    assert.equal(Object.isFrozen(value), true);
  }
});

test('unsafe resource URLs, issuer URLs and OAuth scope values fail at startup', () => {
  const unsafeUrls = [
    'http://public.example/mcp', 'https://user:password@api.example/mcp',
    'https://api.example/mcp?x=1', 'https://api.example/mcp#fragment',
    'https://api.example/mcp\n', 'https://api.example/"mcp', 'https://api.example/\\mcp',
  ];
  for (const resource of unsafeUrls) {
    assert.throws(() => createOAuthResource({ ...config(), resource }), `unsafe resource: ${JSON.stringify(resource)}`);
  }
  for (const issuer of unsafeUrls) {
    assert.throws(() => createOAuthResource({ ...config(), authorizationServers: [issuer] }),
      `unsafe issuer: ${JSON.stringify(issuer)}`);
  }
  assert.throws(() => createOAuthResource({ ...config(), authorizationServers: [] }));
  assert.equal(createOAuthResource({ ...config(), resource: 'https://API.example/agent/mcp' }).resource, RESOURCE);
  for (const scope of ['', 'two scopes', 'read"admin', 'read\\admin', 'read\nadmin', 'é', 'x'.repeat(129)]) {
    assert.throws(() => createOAuthResource({ ...config(), scopesSupported: [scope] }), `unsafe scope: ${JSON.stringify(scope)}`);
    assert.throws(() => createOAuthResource({ ...config(), requiredScopes: [scope] }), `unsafe required scope: ${JSON.stringify(scope)}`);
  }
  assert.throws(() => createOAuthResource({ ...config(), scopesSupported: Array.from({ length: 257 }, (_, i) => `scope:${i}`) }));
  assert.throws(() => createOAuthResource({ ...config(), requiredScopes: ['undeclared:scope'] }));
});

test('the metadata resource and router audience must identify the same service', () => {
  const oauth = createOAuthResource(config());
  const registry = createActionRegistry({ appId: 'example-app', actions: [] });
  assert.throws(() => createAgentRouter({
    registry, oauth, resource: 'https://api.example/different/mcp', verifyToken: async () => null,
  }));
});
