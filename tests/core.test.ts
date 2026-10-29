import assert from 'node:assert/strict';
import { test } from 'node:test';
import { z } from 'zod/v4';
import { createActionRegistry } from '../src/core.js';
import { AccessError, type ActionContext, type AppAction, type AuditEvent, type Principal } from '../src/types.js';

const identity = (overrides: Partial<Principal> = {}): Principal => ({
  appId: 'example-app', subject: 'alice', scopes: ['items:read'], expiresAt: Date.now() + 60_000, ...overrides,
});
const action = (overrides: Partial<AppAction> = {}): AppAction => ({
  name: 'get_bike', title: 'Read bike', description: 'Read an owned bike', requiredScopes: ['items:read'],
  inputSchema: z.object({ bikeId: z.string().min(1).max(32) }),
  outputSchema: z.object({ name: z.string() }),
  execute: async () => ({ name: 'Trail bike' }),
  ...overrides,
});
const rejectsWith = async (promise: Promise<unknown>, code: AccessError['code']) => {
  await assert.rejects(promise, (error: unknown) => {
    assert.ok(error instanceof AccessError);
    assert.equal(error.code, code);
    assert.equal(error.message, code);
    return true;
  });
};
const pause = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

test('unauthenticated, expired, wrong-app and unscoped callers never reach the adapter', async () => {
  let calls = 0;
  const registry = createActionRegistry({ appId: 'example-app', actions: [action({ execute: async () => { calls++; return { name: 'no' }; } })] });
  const invalid: Principal[] = [
    null as unknown as Principal, identity({ subject: '' }), identity({ subject: ' ' }),
    identity({ subject: 'a\nb' }), identity({ subject: 'a'.repeat(513) }),
    identity({ expiresAt: Date.now() - 1 }), identity({ expiresAt: Infinity }),
    identity({ expiresAt: NaN }), identity({ scopes: ['items:read\n'] }),
    identity({ scopes: 'items:read' as unknown as string[] }),
  ];
  for (const principal of invalid) {
    await rejectsWith(registry.execute('get_bike', { bikeId: 'bike-1' }, principal), 'UNAUTHENTICATED');
    assert.throws(() => registry.list(principal), (error: unknown) => error instanceof AccessError && error.code === 'UNAUTHENTICATED');
  }
  await rejectsWith(registry.execute('get_bike', { bikeId: 'bike-1' }, identity({ appId: 'other-app' })), 'FORBIDDEN');
  await rejectsWith(registry.execute('get_bike', { bikeId: 'bike-1' }, identity({ scopes: [] })), 'FORBIDDEN');
  assert.equal(calls, 0);
  assert.deepEqual(registry.list(identity({ scopes: [] })), []);
});

test('strict arguments reject missing, malformed and extra identity fields before policy or adapter', async () => {
  let calls = 0;
  const registry = createActionRegistry({ appId: 'example-app', actions: [action()], authorize: async () => { calls++; return true; } });
  for (const input of [undefined, null, [], {}, { bikeId: 42 }, { bikeId: 'b', userId: 'bob' }, { bikeId: 'b', token: 'secret' }]) {
    await rejectsWith(registry.execute('get_bike', input, identity()), 'INVALID_ARGUMENT');
  }
  assert.equal(calls, 0);
  const nested = createActionRegistry({ appId: 'example-app', actions: [action({ inputSchema: z.object({ filter: z.object({ bikeId: z.string() }) }) })] });
  await rejectsWith(nested.execute('get_bike', { filter: { bikeId: 'b', userId: 'bob' } }, identity()), 'INVALID_ARGUMENT');
});

test('unknown names are generic and untrusted names do not enter the audit record', async () => {
  const events: AuditEvent[] = [];
  const registry = createActionRegistry({ appId: 'example-app', actions: [action()], audit: (event) => { events.push(event); } });
  await rejectsWith(registry.execute('unknown-with-secret', { token: 'secret' }, identity()), 'NOT_FOUND');
  assert.equal(events[0]?.action, 'unknown');
  assert.ok(!JSON.stringify(events).includes('secret'));
});

test('caller mutation and concurrent users cannot change the immutable principal or scopes', async () => {
  let release!: () => void;
  const ready = new Promise<void>((resolve) => { release = resolve; });
  const seen: ActionContext[] = [];
  const registry = createActionRegistry({
    appId: 'example-app', actions: [action({ execute: async (_input, context) => {
      await ready;
      seen.push(context);
      assert.ok(Object.isFrozen(context));
      assert.ok(Object.isFrozen(context.principal));
      assert.ok(Object.isFrozen(context.principal.scopes));
      return { name: `${context.principal.appId}/${context.principal.subject}` };
    } })],
  });
  const alice = identity();
  const first = registry.execute('get_bike', { bikeId: 'a' }, alice);
  const second = registry.execute('get_bike', { bikeId: 'b' }, identity({ subject: 'bob' }));
  alice.subject = 'mallory';
  (alice.scopes as string[]).push('admin');
  release();
  assert.deepEqual(await Promise.all([first, second]), [{ name: 'example-app/alice' }, { name: 'example-app/bob' }]);
  assert.equal(seen.find((context) => context.principal.subject === 'alice')?.principal.scopes.includes('admin'), false);
});

test('registry snapshots the trusted authorization generation and rejects malformed metadata', async () => {
  const caller = identity({ authorizationId: 'original-approval' });
  const registry = createActionRegistry({ appId: 'example-app', actions: [action({ execute: async (_input, context) => {
    assert.ok(Object.isFrozen(context.principal));
    return { name: context.principal.authorizationId! };
  } })] });
  const result = registry.execute('get_bike', { bikeId: 'a' }, caller);
  caller.authorizationId = 'replacement-approval';
  assert.deepEqual(await result, { name: 'original-approval' });
  await rejectsWith(registry.execute('get_bike', { bikeId: 'a' }, identity({ authorizationId: '' })), 'UNAUTHENTICATED');
  await rejectsWith(registry.execute('get_bike', { bikeId: 'a' }, identity({ authorizationId: 'bad\nvalue' })), 'UNAUTHENTICATED');
});

test('action configuration and returned lists cannot broaden registered scopes', async () => {
  const configured = action();
  const registry = createActionRegistry({ appId: 'example-app', actions: [configured] });
  (configured.requiredScopes as string[]).length = 0;
  configured.execute = async () => ({ name: 'replaced' });
  assert.deepEqual(registry.list(identity({ scopes: [] })), []);
  assert.ok(Object.isFrozen(registry.list(identity())[0]));
  assert.deepEqual(await registry.execute('get_bike', { bikeId: 'b' }, identity()), { name: 'Trail bike' });
});

test('policy false denies and all thrown policy/adapter errors are redacted', async () => {
  let executed = 0;
  const read = action({ execute: async () => { executed++; return { name: 'okay' }; } });
  const denied = createActionRegistry({ appId: 'example-app', actions: [read], authorize: async () => false });
  await rejectsWith(denied.execute('get_bike', { bikeId: 'b' }, identity()), 'FORBIDDEN');
  const failed = createActionRegistry({ appId: 'example-app', actions: [read], authorize: async () => { throw new Error('SECRET policy credential'); } });
  await rejectsWith(failed.execute('get_bike', { bikeId: 'b' }, identity()), 'UNAVAILABLE');
  assert.equal(executed, 0);
  const adapter = createActionRegistry({ appId: 'example-app', actions: [action({ execute: async () => { throw new Error('SECRET upstream body'); } })] });
  await rejectsWith(adapter.execute('get_bike', { bikeId: 'b' }, identity()), 'UNAVAILABLE');
});

test('adapter receives trusted owner identity and can deny access without disclosing another owner', async () => {
  const bikes = new Map([['alice-bike', { owner: 'alice', name: 'Alice bike' }], ['bob-bike', { owner: 'bob', name: 'Bob secret' }]]);
  const registry = createActionRegistry({ appId: 'example-app', actions: [action({ execute: async (input, context) => {
    const bike = bikes.get(input.bikeId);
    if (!bike || bike.owner !== context.principal.subject) throw new AccessError('NOT_FOUND');
    return bike;
  } })] });
  assert.deepEqual(await registry.execute('get_bike', { bikeId: 'alice-bike' }, identity()), { name: 'Alice bike' });
  await rejectsWith(registry.execute('get_bike', { bikeId: 'bob-bike' }, identity()), 'NOT_FOUND');
  await rejectsWith(registry.execute('get_bike', { bikeId: 'nonexistent' }, identity()), 'NOT_FOUND');
});

test('intentional adapter codes survive while custom messages, causes and unknown codes do not', async () => {
  for (const code of ['NOT_FOUND', 'FORBIDDEN', 'OUTPUT_LIMIT'] as const) {
    const original = new AccessError(code);
    original.message = 'SECRET upstream response';
    original.cause = new Error('SECRET credential');
    const registry = createActionRegistry({ appId: 'example-app', actions: [action({ execute: async () => { throw original; } })] });
    await assert.rejects(registry.execute('get_bike', { bikeId: 'b' }, identity()), (error: unknown) => {
      assert.ok(error instanceof AccessError);
      assert.notEqual(error, original);
      assert.equal(error.code, code);
      assert.equal(error.message, code);
      assert.equal(error.cause, undefined);
      return true;
    });
  }
  const registry = createActionRegistry({ appId: 'example-app', actions: [action({ execute: async () => { throw new AccessError('SECRET' as never); } })] });
  await rejectsWith(registry.execute('get_bike', { bikeId: 'b' }, identity()), 'UNAVAILABLE');
});

test('output schema projects away sensitive adapter fields and rejects malformed results', async () => {
  const events: AuditEvent[] = [];
  const registry = createActionRegistry({ appId: 'example-app', actions: [action({ execute: async () => ({ name: 'Allowed', email: 'secret@example.com', token: 'SECRET' }) })], audit: (event) => { events.push(event); } });
  assert.deepEqual(await registry.execute('get_bike', { bikeId: 'secret-id' }, identity({ subject: 'private-subject' })), { name: 'Allowed' });
  const logged = JSON.stringify(events);
  for (const secret of ['secret@example.com', 'SECRET', 'secret-id', 'private-subject', 'Allowed']) assert.ok(!logged.includes(secret));
  assert.deepEqual(Object.keys(events[0]!).sort(), ['action', 'appId', 'durationMs', 'outcome', 'requestId']);
  const bad = createActionRegistry({ appId: 'example-app', actions: [action({ execute: async () => ({ unexpected: 'SECRET' }) })] });
  await rejectsWith(bad.execute('get_bike', { bikeId: 'b' }, identity()), 'UNAVAILABLE');
});

test('output limit counts UTF-8 bytes of the actual projected JSON', async () => {
  const registry = createActionRegistry({ appId: 'example-app', actions: [action({ execute: async () => ({ name: '🚲🚲' }) })], maxOutputBytes: 16 });
  await rejectsWith(registry.execute('get_bike', { bikeId: 'b' }, identity()), 'OUTPUT_LIMIT');
  const boundary = createActionRegistry({ appId: 'example-app', actions: [action({ execute: async () => ({ name: '🚲🚲' }) })], maxOutputBytes: Buffer.byteLength(JSON.stringify({ name: '🚲🚲' })) });
  assert.deepEqual(await boundary.execute('get_bike', { bikeId: 'b' }, identity()), { name: '🚲🚲' });
  const defaultLimit = createActionRegistry({ appId: 'example-app', actions: [action({ execute: async () => ({ name: 'x'.repeat(32 * 1024) }) })] });
  await rejectsWith(defaultLimit.execute('get_bike', { bikeId: 'b' }, identity()), 'OUTPUT_LIMIT');
});

test('a hung policy times out before adapter execution', async () => {
  let called = false;
  let observed: AbortSignal | undefined;
  const registry = createActionRegistry({ appId: 'example-app', timeoutMs: 30,
    actions: [action({ execute: async () => { called = true; return { name: 'bad' }; } })],
    authorize: async (_name, context) => { observed = context.signal; return new Promise<boolean>(() => {}); },
  });
  await rejectsWith(registry.execute('get_bike', { bikeId: 'b' }, identity()), 'TIMEOUT');
  assert.equal(called, false);
  assert.equal(observed?.aborted, true);
});

test('one deadline covers policy plus adapter, and a late adapter rejection is handled', async () => {
  let signal: AbortSignal | undefined;
  const registry = createActionRegistry({ appId: 'example-app', timeoutMs: 60,
    authorize: async () => { await pause(35); return true; },
    actions: [action({ execute: async (_input, context) => { signal = context.signal; await pause(40); throw new Error('late secret'); } })],
  });
  await rejectsWith(registry.execute('get_bike', { bikeId: 'b' }, identity()), 'TIMEOUT');
  assert.equal(signal?.aborted, true);
  await pause(50);
});

test('caller cancellation stops work and already-cancelled requests never call adapter', async () => {
  let called = false;
  const controller = new AbortController();
  controller.abort();
  const registry = createActionRegistry({ appId: 'example-app', actions: [action({ execute: async () => { called = true; return { name: 'no' }; } })] });
  await rejectsWith(registry.execute('get_bike', { bikeId: 'b' }, identity(), { signal: controller.signal }), 'TIMEOUT');
  assert.equal(called, false);
});

test('cancellation during an adapter read propagates the abort signal and returns promptly', async () => {
  const controller = new AbortController();
  let signal: AbortSignal | undefined;
  let entered!: () => void;
  const started = new Promise<void>((resolve) => { entered = resolve; });
  const registry = createActionRegistry({ appId: 'example-app', actions: [action({ execute: async (_input, context) => {
    signal = context.signal;
    entered();
    return new Promise<Record<string, unknown>>(() => {});
  } })] });
  const pending = registry.execute('get_bike', { bikeId: 'b' }, identity(), { signal: controller.signal });
  await started;
  controller.abort();
  await rejectsWith(pending, 'TIMEOUT');
  assert.equal(signal?.aborted, true);
});

test('async output validation shares the request deadline', async () => {
  const registry = createActionRegistry({ appId: 'example-app', timeoutMs: 25, actions: [action({
    outputSchema: z.object({ name: z.string() }).refine(async () => new Promise<boolean>(() => {})),
  })] });
  await rejectsWith(registry.execute('get_bike', { bikeId: 'b' }, identity()), 'TIMEOUT');
});

test('expiration during authorization prevents an otherwise permitted adapter read', async () => {
  let called = false;
  const registry = createActionRegistry({ appId: 'example-app', timeoutMs: 500,
    authorize: async () => { await pause(40); return true; },
    actions: [action({ execute: async () => { called = true; return { name: 'no' }; } })],
  });
  await rejectsWith(registry.execute('get_bike', { bikeId: 'b' }, identity({ expiresAt: Date.now() + 20 })), 'UNAUTHENTICATED');
  assert.equal(called, false);
});

test('throwing or hung audit hooks cannot leak errors or indefinitely block a successful read', async () => {
  for (const audit of [async () => { throw new Error('logging SECRET'); }, async () => new Promise<void>(() => {})]) {
    const registry = createActionRegistry({ appId: 'example-app', actions: [action()], timeoutMs: 100, audit });
    assert.deepEqual(await registry.execute('get_bike', { bikeId: 'b' }, identity()), { name: 'Trail bike' });
  }
});
