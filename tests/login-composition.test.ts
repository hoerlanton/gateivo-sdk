import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import test from 'node:test';
import {z} from 'zod/v4';
import {defineAction} from '../src/action.js';
import {createWorkOSPasswordConnection, type WorkOSPasswordConnectionOptions} from '../src/workos-password.js';

function fixture() {
  const calls = {checkout: 0, poolClose: 0, provider: 0, credentials: 0, account: 0, action: 0};
  const pool = {
    async connect(): Promise<never> {calls.checkout++; throw new Error('Unexpected fixture database checkout.');},
    async end() {calls.poolClose++;},
  };
  const options: WorkOSPasswordConnectionOptions = {
    appId: 'fictional-publisher', publicUrl: 'https://publisher.example',
    issuer: 'https://fictional-login-staging.authkit.app',
    clientId: 'client_fictionalcomposition1234', applicationId: 'connect_app_fictionalcomposition1234',
    apiKey: 'sk_test_FICTIONAL_COMPOSITION_ONLY', accessTokenType: 'JWT',
    secret: randomBytes(32), requiredScopes: ['setups:read'], trustProxyHttps: true,
    pool, schemaPrefix: 'fictional_assistant', accountName: 'Fictional app',
    async verifyCredentials() {calls.credentials++; return null;},
    async resolveLoginAccount() {calls.account++; return null;},
    actions: [defineAction({
      name: 'setup_summary', title: 'Fictional setup summary', description: 'Read one fictional summary.',
      requiredScopes: ['setups:read'], inputSchema: z.strictObject({id: z.string()}),
      outputSchema: z.strictObject({id: z.string()}),
      async execute({id}) {calls.action++; return {id};},
    })],
  };
  const dependencies = {async fetch(): Promise<never> {calls.provider++; throw new Error('Unexpected fixture provider request.');}};
  return {options, dependencies, calls};
}

test('high-level password composition uses real SDK modules without checkout, API calls or implicit migrations', async () => {
  const f = fixture();
  const assistant = createWorkOSPasswordConnection(f.options, f.dependencies);
  assert.equal(typeof assistant.router, 'function');
  assert.equal(typeof assistant.ready, 'function');
  assert.equal(typeof assistant.migrate, 'function');
  assert.equal(typeof assistant.close, 'function');
  assert.ok(Object.isFrozen(assistant));
  // Explicit fictional claims inspect the registered action only. No verified
  // browser session, provider token, consent or hosted assistant is simulated.
  assert.deepEqual(assistant.registry?.list({appId: f.options.appId, subject: 'fictional-alice',
    scopes: ['setups:read'], expiresAt: Date.now() + 60_000}).map(action => action.name), ['setup_summary']);
  assert.deepEqual(f.calls, {checkout: 0, poolClose: 0, provider: 0, credentials: 0, account: 0, action: 0});
  await assistant.close();
  await assistant.close();
  assert.deepEqual(f.calls, {checkout: 0, poolClose: 0, provider: 0, credentials: 0, account: 0, action: 0});
  await assert.rejects(assistant.ready());
  await assert.rejects(assistant.migrate());
  assert.equal(f.calls.checkout, 0);
  assert.equal(f.calls.poolClose, 0);
});

test('composition requires both publisher hooks, a pool and at least one action', () => {
  for (const changed of [
    {verifyCredentials: undefined}, {resolveLoginAccount: undefined},
    {pool: undefined}, {pool: {}}, {actions: undefined}, {actions: []},
  ]) {
    const f = fixture();
    assert.throws(() => createWorkOSPasswordConnection({...f.options, ...changed} as WorkOSPasswordConnectionOptions, f.dependencies));
    assert.deepEqual(f.calls, {checkout: 0, poolClose: 0, provider: 0, credentials: 0, account: 0, action: 0});
  }
  assert.throws(() => createWorkOSPasswordConnection(undefined as unknown as WorkOSPasswordConnectionOptions), TypeError);
});

test('invalid settings fail before any application or provider operations', () => {
  for (const changed of [
    {publicUrl: 'http://publisher.example'}, {publicUrl: 'https://publisher.example/elsewhere'},
    {issuer: 'https://other.example'}, {clientId: 'invalid'}, {applicationId: 'invalid'},
    {apiKey: 'sk_live_NOT_A_TEST_KEY'}, {secret: randomBytes(16)}, {accessTokenType: undefined},
    {schemaPrefix: 'pg_forbidden'}, {schemaPrefix: 'contains-dash'},
    {resource: 'https://different.example/agent/mcp'}, {requiredScopes: []},
  ]) {
    const f = fixture();
    assert.throws(() => createWorkOSPasswordConnection({...f.options, ...changed} as WorkOSPasswordConnectionOptions, f.dependencies));
    assert.deepEqual(f.calls, {checkout: 0, poolClose: 0, provider: 0, credentials: 0, account: 0, action: 0});
  }
});
