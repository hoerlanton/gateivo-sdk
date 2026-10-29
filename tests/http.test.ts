import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { test, type TestContext } from 'node:test';
import express from 'express';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { z } from 'zod/v4';
import { createAgentRouter, type AgentRouterOptions } from '../src/http.js';
import { createActionRegistry } from '../src/core.js';
import { AccessError, type Principal, type AppAction } from '../src/types.js';

const principal = (subject = 'alice', overrides: Partial<Principal> = {}): Principal => ({
  appId: 'example-app', subject, scopes: ['workouts:read'], expiresAt: Date.now() + 60_000, ...overrides,
});

async function harness(t: TestContext, overrides: Partial<AgentRouterOptions> = {}) {
  let calls = 0;
  const audit: unknown[] = [];
  const action: AppAction = {
    name: 'read_setup', title: 'Read setup', description: 'Read one customer-owned setup.',
    requiredScopes: ['workouts:read'],
    inputSchema: z.strictObject({ setupId: z.enum(['alice-bike', 'bob-bike']) }),
    outputSchema: z.strictObject({ name: z.string() }),
    execute: async (input, context) => {
      calls++;
      await new Promise((resolve) => setTimeout(resolve, context.principal.subject === 'alice' ? 12 : 2));
      if (input.setupId !== `${context.principal.subject}-bike`) throw new AccessError('NOT_FOUND');
      return { name: `${context.principal.subject}'s bike` };
    },
  };
  const registry = createActionRegistry({ appId: 'example-app', actions: [action], audit: (event) => { audit.push(event); } });
  const app = express();
  app.disable('x-powered-by');
  const server = createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Missing server address');
  const url = new URL(`http://127.0.0.1:${address.port}/mcp`);
  const tokens: Record<string, Principal> = {
    alice: principal(), bob: principal('bob'),
    expired: principal('alice', { expiresAt: Date.now() - 1 }),
    otherapp: principal('alice', { appId: 'different-app' }),
    noscope: principal('alice', { scopes: [] }),
  };
  app.use('/mcp', createAgentRouter({ registry, resource: url.href,
    verifyToken: async (token, context) => {
      assert.equal(context.audience, url.href);
      return tokens[token] ?? null;
    }, ...overrides,
  }));
  const post = (token?: string, body: unknown = { jsonrpc: '2.0', id: 1, method: 'tools/list' }, extra: Record<string, string> = {}) => fetch(url, {
    method: 'POST', headers: {
      'content-type': 'application/json', accept: 'application/json, text/event-stream',
      ...(token ? { authorization: `Bearer ${token}` } : {}), ...extra,
    }, body: JSON.stringify(body),
  });
  async function client(token: string, modern = false, extra: Record<string, string> = {}) {
    const instance = new Client({ name: 'sdk-test', version: '1.0.0' }, {
      versionNegotiation: { mode: modern ? 'auto' : 'legacy' },
    });
    t.after(() => instance.close());
    await instance.connect(new StreamableHTTPClientTransport(url, {
      requestInit: { headers: { authorization: `Bearer ${token}`, ...extra } },
    }));
    return instance;
  }
  return { url, post, client, calls: () => calls, audit, tokens };
}

test('HTTP rejects missing, invalid and expired credentials before any app read', async (t) => {
  const h = await harness(t);
  for (const token of [undefined, 'invalid', 'expired']) {
    const result = await h.post(token);
    assert.equal(result.status, 401);
    assert.equal(result.headers.get('cache-control'), 'no-store');
    assert.deepEqual(await result.json(), { error: { code: 'UNAUTHENTICATED' } });
  }
  assert.equal(h.calls(), 0);
});

test('HTTP checks app and scope before discovery or invocation', async (t) => {
  const h = await harness(t);
  for (const token of ['otherapp', 'noscope']) {
    const result = await h.post(token);
    assert.equal(result.status, 403);
    assert.deepEqual(await result.json(), { error: { code: 'FORBIDDEN' } });
  }
  assert.equal(h.calls(), 0);
});

for (const modern of [false, true]) {
  test(`official MCP client discovers and reads a setup (${modern ? 'modern' : 'legacy'})`, async (t) => {
    const h = await harness(t);
    const client = await h.client('alice', modern);
    const tools = await client.listTools();
    assert.equal(tools.tools.length, 1);
    assert.equal(tools.tools[0]?.annotations?.readOnlyHint, true);
    const result = await client.callTool({ name: 'read_setup', arguments: { setupId: 'alice-bike' } });
    assert.deepEqual(result.structuredContent, { name: "alice's bike" });
    assert.equal(result.isError, undefined);
    assert.equal(h.calls(), 1);
  });
}

test('concurrent clients cannot cross accounts; a session header cannot substitute identity', async (t) => {
  const h = await harness(t);
  const [alice, bob] = await Promise.all([
    h.client('alice'), h.client('bob', false, { 'mcp-session-id': 'claimed-alice-session' }),
  ]);
  const results = await Promise.all([
    alice.callTool({ name: 'read_setup', arguments: { setupId: 'alice-bike' } }),
    bob.callTool({ name: 'read_setup', arguments: { setupId: 'bob-bike' } }),
    alice.callTool({ name: 'read_setup', arguments: { setupId: 'bob-bike' } }),
    bob.callTool({ name: 'read_setup', arguments: { setupId: 'alice-bike' } }),
  ]);
  assert.deepEqual(results[0]?.structuredContent, { name: "alice's bike" });
  assert.deepEqual(results[1]?.structuredContent, { name: "bob's bike" });
  for (const result of results.slice(2)) {
    assert.equal(result.isError, true);
    assert.match(JSON.stringify(result), /NOT_FOUND/);
    assert.doesNotMatch(JSON.stringify(result), /'s bike/);
  }
  assert.equal(h.audit.length, 4);
  assert.doesNotMatch(JSON.stringify(h.audit), /alice|bob|Bearer|setupId/);
});

test('authentication is rechecked after an established client loses access', async (t) => {
  const h = await harness(t);
  const client = await h.client('alice');
  delete h.tokens.alice;
  await assert.rejects(client.callTool({ name: 'read_setup', arguments: { setupId: 'alice-bike' } }));
  assert.equal(h.calls(), 0);
});

test('extra identity arguments are rejected before adapter execution', async (t) => {
  const h = await harness(t);
  const client = await h.client('alice');
  const result = await client.callTool({ name: 'read_setup', arguments: {
    setupId: 'alice-bike', subject: 'bob', userId: 'bob', appId: 'other', token: 'canary-token',
  } });
  assert.equal(result.isError, true);
  assert.equal(h.calls(), 0);
});

test('host, browser origin, payload size, malformed JSON and methods are bounded', async (t) => {
  const h = await harness(t);
  // Node fetch normalizes Host; send this adversarial header on a raw HTTP request.
  const hostileHostStatus = await new Promise<number | undefined>((resolve, reject) => {
    const req = request(h.url, { method: 'POST', headers: { host: 'attacker.invalid' } }, (res) => {
      res.resume();
      res.on('end', () => resolve(res.statusCode));
    });
    req.on('error', reject);
    req.end();
  });
  assert.equal(hostileHostStatus, 403);
  assert.equal((await h.post('alice', {}, { origin: 'https://attacker.invalid' })).status, 403);
  assert.equal((await h.post('alice', { huge: 'x'.repeat(17_000) })).status, 413);
  const malformed = await fetch(h.url, {
    method: 'POST', headers: { authorization: 'Bearer alice', 'content-type': 'application/json' }, body: '{',
  });
  assert.equal(malformed.status, 400);
  assert.deepEqual(await malformed.json(), { error: { code: 'INVALID_REQUEST' } });
  for (const method of ['GET', 'DELETE']) {
    assert.equal((await fetch(h.url, { method })).status, 401);
    assert.equal((await fetch(h.url, { method, headers: { authorization: 'Bearer alice' } })).status, 405);
  }
  assert.equal(h.calls(), 0);
});

test('token verifier failure and timeout cannot leak upstream details or reach an adapter', async (t) => {
  const broken = await harness(t, { verifyToken: async () => { throw new Error('secret-token upstream-body'); } });
  const response = await broken.post('alice');
  assert.equal(response.status, 401);
  assert.doesNotMatch(await response.text(), /secret|upstream/);
  const slow = await harness(t, { authTimeoutMs: 15, verifyToken: async () => new Promise(() => {}) });
  const timeout = await slow.post('alice');
  assert.equal(timeout.status, 503);
  assert.equal(slow.calls(), 0);
});

test('startup requires an explicit verifier and a secure resource URL', () => {
  assert.throws(() => createAgentRouter({ resource: 'http://127.0.0.1/mcp' } as AgentRouterOptions), /verifier/);
  assert.throws(() => createAgentRouter({ resource: 'http://public.example/mcp', verifyToken: async () => null } as unknown as AgentRouterOptions), /HTTPS/);
});
