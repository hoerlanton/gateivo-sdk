import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { createWorkoutExample } from './index.mjs';

const publicFields = ['activity', 'durationMinutes', 'id', 'startedAt', 'title'];
const privateFields = /ownerId|internalNote|billingReference|PRIVATE_(?:ALICE|BOB)_(?:NOTE|BILLING)/;

function successful(result) {
  assert.notEqual(result.isError, true, 'Expected a successful MCP tool call');
  assert.ok(result.structuredContent && typeof result.structuredContent === 'object');
  assert.doesNotMatch(JSON.stringify(result), privateFields);
  return result.structuredContent;
}

function denied(result, code) {
  assert.equal(result.isError, true, 'Expected this tool call to be denied');
  const text = JSON.stringify(result);
  if (code) assert.match(text, new RegExp(code));
  // Schema errors may name a rejected ownerId argument; they must not return
  // private records or their hidden fields.
  assert.doesNotMatch(text, /internalNote|billingReference|PRIVATE_(?:ALICE|BOB)_(?:NOTE|BILLING)/);
  assert.doesNotMatch(text, /durationMinutes/);
}

/**
 * Starts a temporary loopback server and exercises it with the official MCP
 * client. Tokens are created in memory and are never returned or printed.
 * Fictional approvals demonstrate the app/SDK boundary, not production OAuth.
 */
export async function runWorkoutExercise() {
  const server = createServer();
  const clients = [];
  const checks = [];
  const events = [];
  const pass = (message) => { checks.push(message); };
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const address = server.address();
    assert.ok(address && typeof address === 'object');
    const url = new URL(`http://127.0.0.1:${address.port}/mcp`);
    const example = createWorkoutExample({
      demo: true, resource: url.href, audit: (event) => { events.push(event); },
    });
    server.on('request', example.app);
    const alice = example.approvals.approve({ subject: 'alice' });
    const bob = example.approvals.approve({ subject: 'bob' });
    const noScope = example.approvals.approve({ subject: 'alice', scopes: [] });

    async function request(token) {
      const response = await fetch(url, {
        method: 'POST', redirect: 'error', signal: AbortSignal.timeout(5000),
        headers: {
          'content-type': 'application/json', accept: 'application/json, text/event-stream',
          ...(token ? { authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
      });
      await response.body?.cancel();
      return response.status;
    }

    async function connect(token) {
      const client = new Client({ name: 'gateivo-workouts-demo', version: '0.1.0' }, {
        versionNegotiation: { mode: 'auto' },
      });
      clients.push(client);
      await client.connect(new StreamableHTTPClientTransport(url, {
        requestInit: { headers: { authorization: `Bearer ${token}` }, redirect: 'error' },
        redirectPolicy: 'same-origin',
      }), { timeout: 5000 });
      return client;
    }

    const call = (client, name, arguments_) => client.callTool({
      name, arguments: arguments_,
    }, { timeout: 5000 });

    assert.equal(await request(), 401);
    assert.equal(await request('not-an-issued-credential'), 401);
    assert.equal(await request(noScope.token), 403);
    pass('Missing credentials and missing permissions are refused.');

    const aliceClient = await connect(alice.token);
    const bobClient = await connect(bob.token);
    const { tools } = await aliceClient.listTools(undefined, { timeout: 5000 });
    assert.deepEqual(tools.map((tool) => tool.name).sort(), ['workouts_get', 'workouts_list']);
    assert.ok(tools.every((tool) => tool.annotations?.readOnlyHint === true));
    pass('The official MCP client discovers two read-only tools.');

    const list = successful(await call(aliceClient, 'workouts_list', {}));
    assert.deepEqual(list.workouts.map((workout) => workout.id).sort(), [
      'workout-alice-1', 'workout-alice-2',
    ]);
    for (const workout of list.workouts) {
      assert.deepEqual(Object.keys(workout).sort(), publicFields);
    }
    const owned = successful(await call(aliceClient, 'workouts_get', {
      workoutId: 'workout-alice-1',
    })).workout;
    assert.equal(owned.id, 'workout-alice-1');
    assert.deepEqual(Object.keys(owned).sort(), publicFields);
    const bobList = successful(await call(bobClient, 'workouts_list', {}));
    assert.deepEqual(bobList.workouts.map((workout) => workout.id), ['workout-bob-1']);
    pass('Each account receives only its own projected public workout fields.');

    denied(await call(aliceClient, 'workouts_get', { workoutId: 'workout-bob-1' }), 'NOT_FOUND');
    denied(await call(bobClient, 'workouts_get', { workoutId: 'workout-alice-1' }), 'NOT_FOUND');
    pass('Reading another account’s workout is refused.');

    // MCP can reject schema-invalid arguments before the action registry runs.
    // Assert refusal and non-disclosure without prescribing that layer's code.
    denied(await call(aliceClient, 'workouts_get', {
      workoutId: 'workout-alice-1', ownerId: 'bob',
    }));
    denied(await call(aliceClient, 'workouts_list', { limit: 0 }));
    pass('Invalid inputs and assistant-supplied owner overrides are refused.');

    example.approvals.revoke(alice.authorizationId);
    assert.equal(await request(alice.token), 401);
    const fresh = example.approvals.reconnect(alice.authorizationId);
    assert.notEqual(fresh.authorizationId, alice.authorizationId);
    assert.notEqual(fresh.token, alice.token);
    assert.equal(await request(alice.token), 401);
    const replacementClient = await connect(fresh.token);
    assert.equal(successful(await call(replacementClient, 'workouts_get', {
      workoutId: 'workout-alice-1',
    })).workout.id, 'workout-alice-1');
    successful(await call(bobClient, 'workouts_list', {}));
    pass('Local reconnect creates a fresh approval and keeps the old credential blocked.');

    assert.ok(events.some((event) => event.action === 'workouts_get' && event.outcome === 'success'));
    assert.ok(events.some((event) => event.code === 'NOT_FOUND'));
    const audit = JSON.stringify(events);
    assert.doesNotMatch(audit, privateFields);
    for (const grant of [alice, bob, noScope, fresh]) assert.ok(!audit.includes(grant.token));
    pass('Audit hooks report outcomes without tool payloads or credentials.');

    return Object.freeze({
      tools: tools.map((tool) => tool.name), workout: owned, checks: Object.freeze(checks),
    });
  } finally {
    await Promise.allSettled(clients.map((client) => client.close()));
    server.closeAllConnections();
    if (server.listening) await new Promise((resolve) => server.close(resolve));
  }
}
