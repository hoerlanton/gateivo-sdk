import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { APP_ID, READ_SCOPE } from './actions.mjs';
import { createHttpBackendClient, createHttpBackendExample } from './index.mjs';
import { startHttpBackendFixture } from './fixture.mjs';

const privateMarkers = /PRIVATE_UPSTREAM_|internalNote|billingReference|privateEnvelope/;
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Real MCP and HTTP requests, fictional identities and existing-credential map. */
export async function runHttpBackendExercise() {
  const fixture = await startHttpBackendFixture();
  const server = createServer();
  const clients = [];
  const results = [];
  const events = [];
  const checks = [];
  let aliceApproved = true;
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject); server.listen(0, '127.0.0.1', resolve);
    });
    const resource = `http://127.0.0.1:${server.address().port}/mcp`;
    const backend = createHttpBackendClient({
      baseUrl: fixture.origin, resolveCredential: fixture.resolveCredential,
      allowLoopbackHttp: true, timeoutMs: 350, maxResponseBytes: 512,
    });
    const example = createHttpBackendExample({
      resource, backend, audit: (event) => { events.push(event); },
      async verifyToken(token, { audience, signal }) {
        // FIXTURE ONLY: a production verifier must validate issuer, signature,
        // audience, expiry, scopes and live consent. These are random demo tokens.
        if (signal.aborted || audience !== resource) return null;
        if (token === 'fictional-approval-without-read-scope') return {
          ...fixture.accounts.alice.principal, scopes: [],
        };
        return Object.values(fixture.accounts).find((account) =>
          account.assistantToken === token && account.principal.expiresAt > Date.now())?.principal ?? null;
      },
      async authorize(_name, { principal }) {
        return (principal.subject !== 'alice' || aliceApproved)
          && principal.appId === APP_ID && fixture.accounts[principal.subject]
          ?.principal.authorizationId === principal.authorizationId;
      },
    });
    server.on('request', example.app);
    for (const [token, status] of [
      [undefined, 401], ['fictional-invalid-assistant-token', 401],
      ['fictional-approval-without-read-scope', 403],
    ]) {
      const response = await fetch(resource, {
        method: 'POST', redirect: 'error', signal: AbortSignal.timeout(5000),
        headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream',
          ...(token ? { authorization: `Bearer ${token}` } : {}) },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
      });
      await response.body?.cancel();
      assert.equal(response.status, status);
    }
    assert.equal(fixture.lookups.length, 0);
    assert.equal(fixture.requests.length, 0);
    checks.push('Missing/invalid assistant credentials and missing scopes fail before any upstream lookup.');
    async function connect(account) {
      const client = new Client({ name: 'gateivo-http-backend-demo', version: '0.1.0' }, {
        versionNegotiation: { mode: 'auto' },
      });
      clients.push(client);
      await client.connect(new StreamableHTTPClientTransport(new URL(resource), {
        requestInit: { headers: { authorization: `Bearer ${account.assistantToken}` }, redirect: 'error' },
        redirectPolicy: 'same-origin',
      }), { timeout: 5000 });
      return client;
    }
    const alice = await connect(fixture.accounts.alice);
    const bob = await connect(fixture.accounts.bob);
    const call = async (client, args) => {
      const result = await client.callTool({ name: 'workouts_get', arguments: args }, { timeout: 5000 });
      results.push(result);
      assert.ok(!privateMarkers.test(JSON.stringify(result)), 'No upstream private data may reach MCP.');
      return result;
    };
    const denied = (result, code) => {
      assert.equal(result.isError, true, 'Expected a tool error.');
      if (code) assert.ok(JSON.stringify(result).includes(code), 'Expected a stable sanitized error code.');
      assert.ok(!JSON.stringify(result).includes('Morning trail ride'), 'Errors may not contain record bodies.');
    };
    const { tools } = await alice.listTools(undefined, { timeout: 5000 });
    assert.deepEqual(tools.map((tool) => tool.name), ['workouts_get']);
    assert.equal(tools[0].annotations.readOnlyHint, true);
    assert.deepEqual(Object.keys(tools[0].inputSchema.properties), ['workoutId']);
    checks.push('The official MCP client discovers one typed read-only tool.');

    const result = await call(alice, { workoutId: 'workout-alice-1' });
    assert.notEqual(result.isError, true);
    assert.deepEqual(result.structuredContent, { workout: { id: 'workout-alice-1', title: 'Morning trail ride' } });
    const bobResult = await call(bob, { workoutId: 'workout-bob-1' });
    assert.deepEqual(bobResult.structuredContent, { workout: { id: 'workout-bob-1', title: 'Evening run' } });
    checks.push('Verified Alice and Bob resolve separate existing upstream user credentials.');
    checks.push('Only id and title cross the explicit public projection.');

    denied(await call(alice, { workoutId: 'workout-bob-1' }), 'NOT_FOUND');
    denied(await call(bob, { workoutId: 'workout-alice-1' }), 'NOT_FOUND');
    checks.push('The upstream user-scoped endpoint refuses another account’s record with NOT_FOUND.');

    const lookupCount = fixture.lookups.length;
    for (const args of [
      { workoutId: 'workout-alice-1', ownerId: 'bob' },
      { workoutId: 'workout-alice-1', credential: 'model-supplied' },
      { workoutId: 'workout-alice-1', url: fixture.origin },
      { workoutId: '../workout-alice-1' },
    ]) denied(await call(alice, args));
    assert.equal(fixture.lookups.length, lookupCount);
    checks.push('Owner, credential, URL overrides and malformed IDs fail before a credential lookup.');

    for (const [id, code] of [
      ['workout-server-error', 'UNAVAILABLE'], ['workout-invalid-json', 'UNAVAILABLE'],
      ['workout-wrong-type', 'UNAVAILABLE'], ['workout-wrong-id', 'UNAVAILABLE'],
      ['workout-redirect', 'UNAVAILABLE'], ['workout-declared-large', 'OUTPUT_LIMIT'],
      ['workout-streamed-large', 'OUTPUT_LIMIT'], ['workout-slow', 'TIMEOUT'],
    ]) denied(await call(alice, { workoutId: id }), code);
    assert.equal(fixture.credentialCaptureRequests, 0);
    checks.push('Upstream errors, malformed responses, record mismatches and redirects fail closed.');
    checks.push('Declared and streamed response bytes and operation time are bounded.');

    // Exercise cancellation through the SDK context, then observe actual HTTP close.
    const countBefore = fixture.requests.length;
    const controller = new AbortController();
    const cancelled = example.registry.execute('workouts_get', { workoutId: 'workout-slow' },
      fixture.accounts.alice.principal, { signal: controller.signal });
    for (let i = 0; i < 100 && fixture.requests.length === countBefore; i++) await delay(5);
    assert.ok(fixture.requests.length > countBefore, 'Expected an actual upstream request before cancellation.');
    controller.abort();
    await assert.rejects(cancelled, (error) => error.code === 'TIMEOUT');
    for (let i = 0; i < 100 && fixture.cancelledRequests < 2; i++) await delay(5);
    assert.ok(fixture.cancelledRequests >= 2, 'Both timeout and cancellation must stop upstream HTTP requests.');
    checks.push('Caller cancellation propagates through the SDK to the upstream HTTP request.');

    const context = { principal: fixture.accounts.alice.principal, signal: new AbortController().signal };
    const beforeRejectedHooks = fixture.requests.length;
    for (const [resolveCredential, expected] of [
      [async () => null, 'FORBIDDEN'],
      [async () => 'injected\r\nheader', 'FORBIDDEN'],
      [async () => { throw new Error('PRIVATE_UPSTREAM_BODY'); }, 'UNAVAILABLE'],
    ]) {
      const deniedBackend = createHttpBackendClient({ baseUrl: fixture.origin, allowLoopbackHttp: true,
        resolveCredential });
      await assert.rejects(deniedBackend.getMyWorkout('workout-alice-1', context), (error) =>
        error.code === expected && error.message === expected && !error.cause);
    }
    assert.equal(fixture.requests.length, beforeRejectedHooks);
    const rejectedToken = createHttpBackendClient({ baseUrl: fixture.origin, allowLoopbackHttp: true,
      resolveCredential: async () => 'fictional-rejected-upstream-token' });
    await assert.rejects(rejectedToken.getMyWorkout('workout-alice-1', context),
      (error) => error.code === 'FORBIDDEN' && error.message === 'FORBIDDEN');
    checks.push('Missing, invalid, rejected and failing user-credential hooks expose only safe errors.');

    const beforeDelayed = fixture.requests.length;
    const pendingRead = call(alice, { workoutId: 'workout-delayed' });
    for (let i = 0; i < 100 && fixture.requests.length === beforeDelayed; i++) await delay(5);
    assert.ok(fixture.requests.length > beforeDelayed, 'Expected an upstream read before revocation.');
    aliceApproved = false;
    fixture.releaseDelayedResponse();
    denied(await pendingRead, 'FORBIDDEN');
    // Revocation is terminal for this fictional approval. Reconnect requires a
    // distinct grant in the actual connection module, not toggling this to true.
    const lookupsAfterRevocation = fixture.lookups.length;
    denied(await call(alice, { workoutId: 'workout-alice-1' }), 'FORBIDDEN');
    assert.equal(fixture.lookups.length, lookupsAfterRevocation);
    checks.push('The final trusted consent check suppresses a read revoked while HTTP was pending.');

    assert.ok(fixture.lookups.every((principal) => principal.appId === APP_ID
      && principal.scopes.includes(READ_SCOPE)
      && !Object.hasOwn(principal, 'token') && !Object.hasOwn(principal, 'credential')));
    assert.ok(fixture.requests.every((request) => request.usedAssistantCredential === false));
    assert.ok(fixture.requests.filter((request) => request.subject !== null)
      .every((request) => request.usedUpstreamCredential));
    const rendered = JSON.stringify({ results, events, lookups: fixture.lookups, requests: fixture.requests });
    assert.ok(Object.values(fixture.accounts).every((account) =>
      !rendered.includes(account.assistantToken) && !rendered.includes(account.upstreamToken)),
    'No credential may appear in MCP results, audit hooks or diagnostic metadata.');
    assert.ok(events.some((event) => event.outcome === 'success')
      && events.some((event) => event.code === 'NOT_FOUND'));
    assert.ok(!privateMarkers.test(JSON.stringify(events)), 'Audits must contain metadata only.');
    checks.push('Assistant credentials are never forwarded upstream; results and audit metadata contain no credentials.');

    return Object.freeze({ workout: result.structuredContent.workout, checks: Object.freeze(checks) });
  } finally {
    await Promise.allSettled(clients.map((client) => client.close()));
    server.closeAllConnections();
    if (server.listening) await new Promise((resolve) => server.close(resolve));
    await fixture.close();
  }
}
