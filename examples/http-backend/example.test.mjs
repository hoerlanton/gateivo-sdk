import assert from 'node:assert/strict';
import { test } from 'node:test';
import { APP_ID } from './actions.mjs';
import { createHttpBackendClient } from './client.mjs';
import { runHttpBackendExercise } from './exercise.mjs';

test('real local MCP/HTTP exercise preserves upstream ownership and credential boundaries', {
  timeout: 15_000,
}, async () => { await runHttpBackendExercise(); });

test('backend origin is exact trusted configuration; HTTP is explicitly loopback-only', () => {
  const resolveCredential = async () => null;
  for (const baseUrl of [
    'http://backend.example', 'https://user:password@backend.example',
    'https://backend.example/api', 'https://backend.example?owner=bob',
    'https://backend.example#fragment', 'https://backend.example/',
    'http://localhost:3000', 'http://127.0.0.1:3000',
  ]) assert.throws(() => createHttpBackendClient({ baseUrl, resolveCredential }), TypeError);
  assert.throws(() => createHttpBackendClient({ baseUrl: 'http://backend.example',
    resolveCredential, allowLoopbackHttp: true }), TypeError);
  assert.ok(createHttpBackendClient({ baseUrl: 'https://backend.example', resolveCredential }));
  assert.ok(createHttpBackendClient({ baseUrl: 'http://127.0.0.1:3000',
    resolveCredential, allowLoopbackHttp: true }));
});

test('uncooperative credential hook is bounded; pre-cancel and invalid identity never call it', async () => {
  let calls = 0;
  const backend = createHttpBackendClient({ baseUrl: 'https://backend.example', timeoutMs: 25,
    resolveCredential: async () => { calls++; return new Promise(() => undefined); } });
  const principal = { appId: APP_ID, subject: 'alice', scopes: ['workouts:read'], expiresAt: Date.now() + 5000 };
  const context = { principal, signal: new AbortController().signal, requestId: 'test' };
  await assert.rejects(backend.getMyWorkout('workout-alice-1', context), (error) => error.code === 'TIMEOUT');
  assert.equal(calls, 1);
  await assert.rejects(backend.getMyWorkout('workout-alice-1', {
    ...context, signal: AbortSignal.abort(),
  }), (error) => error.code === 'TIMEOUT');
  await assert.rejects(backend.getMyWorkout('workout-alice-1', {
    ...context, principal: { ...principal, appId: 'another-app' },
  }), (error) => error.code === 'FORBIDDEN');
  await assert.rejects(backend.getMyWorkout('../alice', context), (error) => error.code === 'INVALID_ARGUMENT');
  assert.equal(calls, 1);
});
