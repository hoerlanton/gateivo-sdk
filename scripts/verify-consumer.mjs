#!/usr/bin/env node
/**
 * Exercise the distributable exactly as an unrelated app would consume it.
 * Only the packed SDK and copied workouts example enter the temporary project;
 * no source aliases, symlinks, NODE_PATH, or checkout node_modules are used.
 */
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cp, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execute = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const sdkDirectory = root;
const exampleDirectory = path.join(root, 'examples/workouts');
const [nodeMajor, nodeMinor] = process.versions.node.split('.').map(Number);
const reportPath = path.join(root, nodeMajor === 22
  ? 'artifacts/consumer-node22-verification.json'
  : 'artifacts/consumer-verification.json');
const exampleFiles = ['actions.mjs', 'client.mjs', 'constants.mjs',
  'demo-approvals.mjs', 'index.mjs', 'repository.mjs', 'server.mjs', 'exercise.mjs'];
const checks = [];
const report = { status: 'running', checkedAt: new Date().toISOString(), node: process.version, checks };
const childEnv = { ...process.env };
// Never let inherited module loaders resolve imports from the checkout.
for (const name of ['NODE_PATH', 'NODE_OPTIONS', 'TS_NODE_PROJECT', 'TSX_TSCONFIG_PATH']) delete childEnv[name];
childEnv.npm_config_audit = 'false';
childEnv.npm_config_fund = 'false';
childEnv.npm_config_ignore_scripts = 'true';

function inside(parent, child) {
  const relative = path.relative(parent, child);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

async function run(program, arguments_, cwd, label) {
  try {
    return await execute(program, arguments_, {
      cwd, env: childEnv, timeout: 300_000, maxBuffer: 4 * 1024 * 1024,
    });
  } catch (error) {
    // Test fixtures are generated in the child. Never dump process output, which
    // could otherwise include credentials in an assertion or npm diagnostic.
    const code = error && typeof error === 'object' && 'code' in error ? String(error.code) : 'unknown';
    throw new Error(`${label} failed (exit ${code}). No child output was logged.`, { cause: error });
  }
}

async function npm(arguments_, cwd, label) {
  return process.env.npm_execpath
    ? run(process.execPath, [process.env.npm_execpath, ...arguments_], cwd, label)
    : run('npm', arguments_, cwd, label);
}

const typesFixture = `import { defineAction, createActionRegistry, type Principal } from '@gateivo/sdk';
import { AccessError } from '@gateivo/sdk/core';
import { createAgentRouter, type AgentRouterOptions } from '@gateivo/sdk/express';
import { createOAuthResource } from '@gateivo/sdk/oauth';
import { createWorkOSConnection } from '@gateivo/sdk/workos-connect/express';
import { createWorkOSPostgresStore } from '@gateivo/sdk/workos-connect/postgres';
import { createPasswordLogin } from '@gateivo/sdk/login/express';
import { createLoginPostgresStore } from '@gateivo/sdk/login/postgres';
import { createWorkOSStandaloneLogin } from '@gateivo/sdk/workos-connect/standalone';
import { createWorkOSPasswordConnection } from '@gateivo/sdk/workos-connect/password';
import { z } from 'zod/v4';

const action = defineAction({
  name: 'typed_workout', title: 'Typed workout', description: 'Consumer declaration contract.',
  requiredScopes: ['workouts:read'],
  inputSchema: z.strictObject({ title: z.string(), limit: z.number().int().default(3) }),
  outputSchema: z.object({ title: z.string(), count: z.number() }),
  execute: async (input, context) => {
    const title: string = input.title;
    const count: number = input.limit;
    const user: string = context.principal.subject;
    // @ts-expect-error Inferred input must not degrade to any.
    const wrongType: number = input.title;
    // @ts-expect-error Identity is not a caller-supplied action argument.
    input.subject;
    // @ts-expect-error Verified principal is read-only in action handlers.
    context.principal.subject = user;
    void wrongType;
    return { title, count };
  },
});

defineAction({
  name: 'bad_output', title: 'Bad output', description: 'Type error is intentional.',
  requiredScopes: ['workouts:read'], inputSchema: z.strictObject({}),
  outputSchema: z.object({ title: z.string() }),
  // @ts-expect-error Handler output must match its inferred output schema.
  execute: async () => ({ title: 42 }),
});

const principal: Principal = { appId: 'workouts', subject: 'test-user', scopes: ['workouts:read'], expiresAt: Date.now() + 1000 };
const registry = createActionRegistry({ appId: 'workouts', actions: [action] });
const options: AgentRouterOptions = {
  registry, resource: 'http://127.0.0.1:5196/mcp', verifyToken: async () => principal,
};
createAgentRouter(options);
createOAuthResource({ resource: options.resource, authorizationServers: ['https://issuer.example'], scopesSupported: ['workouts:read'] });
void new AccessError('FORBIDDEN');

// These contracts must be usable from an independently installed archive with
// no copied composition source, provider SDK, pg declarations or permissive any.
type PasswordOptions = Parameters<typeof createWorkOSPasswordConnection>[0];
type LoginOptions = Parameters<typeof createPasswordLogin>[0];
type StandaloneOptions = Parameters<typeof createWorkOSStandaloneLogin>[0];
declare const loginPool: Parameters<typeof createLoginPostgresStore>[0]['pool'];
createLoginPostgresStore({ pool: loginPool, appId: 'workouts' });
type LoginIsAny<T> = 0 extends (1 & T) ? true : false;
const passwordOptionsAreTyped: LoginIsAny<PasswordOptions> = false;
const loginOptionsAreTyped: LoginIsAny<LoginOptions> = false;
const standaloneOptionsAreTyped: LoginIsAny<StandaloneOptions> = false;
// @ts-expect-error Publisher credential verification is required.
createWorkOSPasswordConnection({});
void passwordOptionsAreTyped; void loginOptionsAreTyped; void standaloneOptionsAreTyped;
type ConnectionOptions = Parameters<typeof createWorkOSConnection>[0];
type IsAny<Value> = 0 extends (1 & Value) ? true : false;
const connectionOptionsAreTyped: IsAny<ConnectionOptions> = false;
const sessionRequestIsTyped: IsAny<Parameters<ConnectionOptions['authenticateSession']>[0]> = false;
const sessionResultIsTyped: IsAny<Awaited<ReturnType<ConnectionOptions['authenticateSession']>>> = false;
const accountResultIsTyped: IsAny<Awaited<ReturnType<ConnectionOptions['resolveAccount']>>> = false;
const lifecycleStoreIsTyped: IsAny<ConnectionOptions['store']> = false;
declare const pool: Parameters<typeof createWorkOSPostgresStore>[0]['pool'];
const connectionStore = createWorkOSPostgresStore({ pool, schema: 'gateivo_consumer' });
const connectionOptions: ConnectionOptions = {
  appId: 'workouts', publicUrl: 'https://publisher.example', issuer: 'https://issuer.example',
  clientId: 'client_reference123456', applicationId: 'connect_app_reference123456',
  apiKey: 'synthetic-provider-key', accessTokenType: null, requiredScopes: ['workouts:read'],
  secret: new Uint8Array(32), store: connectionStore, mountMcp: false,
  authenticateSession: async (request, context) => {
    const method: string = request.method;
    context.signal.throwIfAborted();
    return { sessionId: 'opaque-session', authVersion: '1', appSubject: 'local-account',
      accountLabel: method, expiresAt: Date.now() + 1000 };
  },
  resolveAccount: async (account, context) => {
    const subject: string = account.appSubject;
    const issuer: string = account.issuer;
    context.signal.throwIfAborted();
    void subject; void issuer;
    return { providerSubject: 'user_reference123456', enabled: true };
  },
};
const connection = createWorkOSConnection(connectionOptions);
const linkedPrincipal: Promise<Principal | null> = connection.verifyToken('token', {
  audience: 'https://publisher.example/agent/mcp', signal: AbortSignal.timeout(1000),
});
connection.isAuthorized({ appId: 'workouts', subject: 'local-account', scopes: ['workouts:read'],
  expiresAt: Date.now() + 1000 }, { signal: AbortSignal.timeout(1000) });
connectionStore.migrate(); connectionStore.checkReady(); connectionStore.close();
const { authenticateSession: omittedSession, ...withoutSession } = connectionOptions;
// @ts-expect-error Existing application authentication is mandatory.
createWorkOSConnection(withoutSession);
const { resolveAccount: omittedAccount, ...withoutAccount } = connectionOptions;
// @ts-expect-error A trusted, existing account binding is mandatory.
createWorkOSConnection(withoutAccount);
// @ts-expect-error A partial store cannot silently omit durable lifecycle methods.
createWorkOSConnection({ ...connectionOptions, store: {} });
// @ts-expect-error Session expiry must be numeric Unix milliseconds.
const wrongSession: ConnectionOptions['authenticateSession'] = async () => ({ sessionId: 's', authVersion: '1', appSubject: 'a', accountLabel: 'A', expiresAt: 'tomorrow' });
// @ts-expect-error Account enabled status must be boolean.
const wrongAccount: ConnectionOptions['resolveAccount'] = async () => ({ providerSubject: 'user_reference123456', enabled: 'yes' });
// @ts-expect-error Lifecycle access checks require a cancellation context.
connection.isAuthorized({ appId: 'workouts', subject: 'a', scopes: [], expiresAt: 1 });
// @ts-expect-error Pool checkout must return a typed query/release client.
createWorkOSPostgresStore({ pool: { connect: async () => ({}) } });
void connectionOptionsAreTyped; void sessionRequestIsTyped; void sessionResultIsTyped;
void accountResultIsTyped; void lifecycleStoreIsTyped; void linkedPrincipal;
void omittedSession; void omittedAccount; void wrongSession; void wrongAccount;
`;

// A real CommonJS host loads the package's ESM graph before mounting routes.
// Keep this on Node 24 as well so adding Node 22 does not replace existing checks.
const bootstrapFixture = String.raw`const assert = require('node:assert/strict');
(async () => {
  const sdk = await import('@gateivo/sdk');
  const core = await import('@gateivo/sdk/core');
  const expressEntry = await import('@gateivo/sdk/express');
  const oauth = await import('@gateivo/sdk/oauth');
  const workos = await import('@gateivo/sdk/workos-connect');
  const connection = await import('@gateivo/sdk/workos-connect/express');
  const postgres = await import('@gateivo/sdk/workos-connect/postgres');
  const login = await import('@gateivo/sdk/login/express');
  const loginStore = await import('@gateivo/sdk/login/postgres');
  const standalone = await import('@gateivo/sdk/workos-connect/standalone');
  const password = await import('@gateivo/sdk/workos-connect/password');
  assert.equal(typeof login.createPasswordLogin, 'function');
  assert.equal(typeof loginStore.createLoginPostgresStore, 'function');
  assert.equal(typeof standalone.createWorkOSStandaloneLogin, 'function');
  assert.equal(typeof password.createWorkOSPasswordConnection, 'function');
  const example = await import('./index.mjs');
  assert.equal(sdk.AccessError, core.AccessError);
  assert.equal(sdk.createAgentRouter, expressEntry.createAgentRouter);
  assert.equal(sdk.createOAuthResource, oauth.createOAuthResource);
  assert.equal(typeof workos.createWorkOSConnectVerifier, 'function');
  assert.equal(typeof workos.createWorkOSConnectProvider, 'function');
  assert.deepEqual(Object.keys(connection), ['createWorkOSConnection']);
  assert.deepEqual(Object.keys(postgres), ['createWorkOSPostgresStore']);
  assert.equal(typeof example.createWorkoutExample, 'function');
  const commonCore = require('@gateivo/sdk/core');
  const commonExpress = require('@gateivo/sdk/express');
  const commonPostgres = require('@gateivo/sdk/workos-connect/postgres');
  assert.deepEqual(Object.keys(commonCore).sort(), Object.keys(core).sort());
  assert.deepEqual(Object.keys(commonExpress).sort(), Object.keys(expressEntry).sort());
  assert.deepEqual(Object.keys(commonPostgres).sort(), Object.keys(postgres).sort());
  assert.ok(new commonCore.AccessError('NOT_FOUND') instanceof commonCore.AccessError);
  if (process.versions.node.split('.')[0] === '24') {
    const common = require('@gateivo/sdk');
    assert.equal(common.AccessError, commonCore.AccessError);
    assert.equal(common.createAgentRouter, commonExpress.createAgentRouter);
    assert.equal(common.createOAuthResource, require('@gateivo/sdk/oauth').createOAuthResource);
    assert.deepEqual(Object.keys(common).sort(), Object.keys(sdk).sort());
    assert.deepEqual(Object.keys(require('@gateivo/sdk/workos-connect')).sort(), Object.keys(workos).sort());
    assert.deepEqual(Object.keys(require('@gateivo/sdk/workos-connect/express')).sort(), Object.keys(connection).sort());
    assert.deepEqual(Object.keys(require('@gateivo/sdk/workos-connect/postgres')).sort(), Object.keys(postgres).sort());
  }
  await import('./verify-runtime.mjs');
})().catch((error) => {
  // Never log assertion values or generated example credentials.
  console.error('CommonJS bootstrap failed (' + (error?.constructor?.name ?? 'Error') + ').');
  process.exitCode = 1;
});
`;

const runtimeFixture = String.raw`import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { realpath, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import * as sdk from '@gateivo/sdk';
import * as core from '@gateivo/sdk/core';
import * as expressEntry from '@gateivo/sdk/express';
import * as oauth from '@gateivo/sdk/oauth';
import { createWorkoutExample, createWorkoutRepository } from './index.mjs';

const directory = await realpath(path.dirname(fileURLToPath(import.meta.url)));
const require = createRequire(import.meta.url);
const evidence = [];
const clients = [];
let server;
let phase = 'package imports';

function pass(check) { evidence.push(check); }
function below(parent, child) {
  const relative = path.relative(parent, child);
  return relative !== '' && !relative.startsWith('../') && relative !== '..' && !path.isAbsolute(relative);
}

async function connect(url, token, modern = false) {
  const client = new Client({ name: 'gateivo-independent-consumer', version: '0.1.0' }, {
    versionNegotiation: { mode: modern ? 'auto' : 'legacy' },
  });
  clients.push(client);
  await client.connect(new StreamableHTTPClientTransport(url, {
    requestInit: { headers: { authorization: 'Bearer ' + token }, redirect: 'error' },
    redirectPolicy: 'same-origin',
  }));
  return client;
}

function visibleWorkout(workout, expectedId) {
  assert.equal(workout.id, expectedId);
  assert.deepEqual(Object.keys(workout).sort(), ['activity', 'durationMinutes', 'id', 'startedAt', 'title']);
  assert.equal(typeof workout.title, 'string');
  assert.equal(typeof workout.durationMinutes, 'number');
}

async function assertCliExit() {
  // Reserve then release an ephemeral port; the actual CLI must choose its own
  // configured nonzero port. Keep stdin open after writing exit so this catches
  // a leaked/resumed input handle rather than hiding it with parent-side EOF.
  const reservation = createServer();
  await new Promise((resolve, reject) => {
    reservation.once('error', reject);
    reservation.listen(0, '127.0.0.1', resolve);
  });
  const address = reservation.address();
  assert.ok(address && typeof address === 'object');
  await new Promise((resolve) => reservation.close(resolve));
  const cli = spawn(process.execPath, ['server.mjs', '--demo'], {
    cwd: directory, env: { ...process.env, PORT: String(address.port) },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  let timer;
  let output = '';
  let exitSent = false;
  try {
    await new Promise((resolve, reject) => {
      const fail = () => reject(new Error('Standalone CLI did not exit cleanly after its exit command'));
      timer = setTimeout(fail, 10_000);
      cli.once('error', reject);
      cli.stdout.on('data', (chunk) => {
        output = (output + chunk.toString()).slice(-4096);
        // Generated demo credentials may follow this line. They stay captured
        // here and are neither printed nor added to verification evidence.
        if (!exitSent && output.includes('Gateivo workouts example:')) {
          exitSent = true;
          clearTimeout(timer);
          timer = setTimeout(fail, 10_000);
          cli.stdin.write('exit\n');
        }
      });
      cli.stderr.resume();
      cli.stdin.on('error', reject);
      cli.once('close', (code, signal) => {
        if (exitSent && code === 0 && signal === null) resolve();
        else fail();
      });
    });
  } finally {
    clearTimeout(timer);
    output = '';
    if (cli.exitCode === null && cli.signalCode === null) {
      cli.kill('SIGKILL');
      await new Promise((resolve) => cli.once('close', resolve));
    }
    cli.stdin.destroy();
    cli.stdout.destroy();
    cli.stderr.destroy();
  }
}

try {
  for (const subpath of ['', '/core', '/express', '/oauth', '/workos-connect', '/workos-connect/express', '/workos-connect/postgres']) {
    const resolved = await realpath(require.resolve('@gateivo/sdk' + subpath));
    assert.ok(below(path.join(directory, 'node_modules/@gateivo/sdk'), resolved), 'Package resolves inside isolated installed SDK');
  }
  assert.equal(sdk.AccessError, core.AccessError);
  assert.equal(sdk.createAgentRouter, expressEntry.createAgentRouter);
  assert.equal(sdk.createOAuthResource, oauth.createOAuthResource);
  assert.ok(new core.AccessError('NOT_FOUND') instanceof sdk.AccessError);
  assert.deepEqual(Object.keys(sdk).sort(), ['AccessError', 'createActionRegistry', 'createAgentRouter', 'createOAuthJwtVerifier', 'createOAuthResource', 'defineAction']);
  pass('CommonJS bootstrap dynamically imports every public SDK entry, including optional Express connection and PostgreSQL factories, without a database driver or SQLite; ESM error identity is preserved');
  if (process.versions.node.split('.')[0] === '24') {
    pass('Node 24 synchronous CommonJS root, OAuth and WorkOS exports retain their public API and shared error identity');
  }

  phase = 'example startup';
  server = createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  const url = new URL('http://127.0.0.1:' + address.port + '/mcp');
  const repository = createWorkoutRepository();
  const privateRow = await repository.getForOwner('alice', 'workout-alice-1', { signal: new AbortController().signal });
  assert.equal(privateRow.internalNote, 'PRIVATE_ALICE_NOTE');
  assert.equal(privateRow.billingReference, 'PRIVATE_ALICE_BILLING');
  assert.equal(privateRow.ownerId, 'alice');
  const audit = [];
  const example = createWorkoutExample({ demo: true, resource: url.href, repository, audit: (event) => { audit.push(event); } });
  server.on('request', example.app);
  const alice = example.approvals.approve({ subject: 'alice' });
  const bob = example.approvals.approve({ subject: 'bob' });
  const noScope = example.approvals.approve({ subject: 'alice', scopes: [] });

  const raw = (token, method = 'tools/list', params = {}) => fetch(url, {
    method: 'POST', headers: {
      'content-type': 'application/json', accept: 'application/json, text/event-stream',
      ...(token ? { authorization: 'Bearer ' + token } : {}),
    }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });

  phase = 'authentication and scope';
  for (const token of [undefined, 'not-an-issued-credential']) {
    const response = await raw(token);
    assert.equal(response.status, 401);
    assert.deepEqual(await response.json(), { error: { code: 'UNAUTHENTICATED' } });
  }
  const forbidden = await raw(noScope.token);
  assert.equal(forbidden.status, 403);
  assert.deepEqual(await forbidden.json(), { error: { code: 'FORBIDDEN' } });
  pass('Missing/invalid credentials rejected with 401; missing required scope rejected with 403');

  phase = 'MCP discovery and owned reads';
  const aliceClient = await connect(url, alice.token);
  const bobClient = await connect(url, bob.token);
  const modernClient = await connect(url, alice.token, true);
  for (const client of [aliceClient, modernClient]) {
    const discovery = await client.listTools();
    assert.deepEqual(discovery.tools.map((tool) => tool.name).sort(), ['workouts_get', 'workouts_list']);
    assert.ok(discovery.tools.every((tool) => tool.annotations?.readOnlyHint === true));
    const listed = await client.callTool({ name: 'workouts_list', arguments: {} });
    assert.notEqual(listed.isError, true);
    assert.deepEqual(listed.structuredContent.workouts.map((workout) => workout.id).sort(), ['workout-alice-1', 'workout-alice-2']);
    for (const workout of listed.structuredContent.workouts) visibleWorkout(workout, workout.id);
    const single = await client.callTool({ name: 'workouts_get', arguments: { workoutId: 'workout-alice-1' } });
    assert.notEqual(single.isError, true);
    visibleWorkout(single.structuredContent.workout, 'workout-alice-1');
    assert.doesNotMatch(JSON.stringify([listed, single]), /internalNote|billingReference|ownerId|PRIVATE_(?:ALICE|BOB)_(?:NOTE|BILLING)/);
  }
  const bobList = await bobClient.callTool({ name: 'workouts_list', arguments: {} });
  assert.deepEqual(bobList.structuredContent.workouts.map((workout) => workout.id), ['workout-bob-1']);
  const bobGet = await bobClient.callTool({ name: 'workouts_get', arguments: { workoutId: 'workout-bob-1' } });
  assert.notEqual(bobGet.isError, true);
  visibleWorkout(bobGet.structuredContent.workout, 'workout-bob-1');
  pass('Official MCP clients discover and read the standalone example over real HTTP in legacy and modern negotiation modes');
  pass('Alice and Bob receive only their own projected public workout fields');

  phase = 'standalone quickstart client';
  const quickstart = await promisify(execFile)(process.execPath, ['client.mjs'], {
    cwd: directory, timeout: 20_000, maxBuffer: 64 * 1024,
    env: { ...process.env, GATEIVO_DEMO_TOKEN: alice.token, GATEIVO_DEMO_URL: url.href },
  });
  assert.match(quickstart.stdout, /workouts_list/);
  assert.match(quickstart.stdout, /workout-alice-1/);
  assert.ok(!quickstart.stdout.includes(alice.token), 'Quickstart output must omit credentials');
  assert.doesNotMatch(quickstart.stdout, /PRIVATE_(?:ALICE|BOB)_(?:NOTE|BILLING)|internalNote|billingReference/);
  pass('Copied quickstart client executes successfully against the isolated example and prints only public results');

  phase = 'ownership and input denial';
  for (const [client, id] of [[aliceClient, 'workout-bob-1'], [bobClient, 'workout-alice-1']]) {
    const denied = await client.callTool({ name: 'workouts_get', arguments: { workoutId: id } });
    assert.equal(denied.isError, true);
    assert.match(JSON.stringify(denied), /NOT_FOUND/);
    assert.doesNotMatch(JSON.stringify(denied), /PRIVATE_(?:ALICE|BOB)_(?:NOTE|BILLING)|internalNote|billingReference|durationMinutes/);
  }
  for (const [name, arguments_] of [
    ['workouts_list', { limit: 0 }],
    ['workouts_list', { subject: 'bob' }],
    ['workouts_get', { workoutId: 'workout-alice-1', ownerId: 'bob' }],
    ['workouts_get', { workoutId: 7 }],
  ]) {
    const invalid = await aliceClient.callTool({ name, arguments: arguments_ });
    assert.equal(invalid.isError, true);
    assert.doesNotMatch(JSON.stringify(invalid), /PRIVATE_(?:ALICE|BOB)_(?:NOTE|BILLING)|internalNote|billingReference|durationMinutes/);
  }
  pass('Cross-account reads and invalid/spoofed identity arguments are denied');

  phase = 'revoke and reconnect';
  assert.equal(example.approvals.revoke(alice.authorizationId), true);
  const revoked = await raw(alice.token);
  assert.equal(revoked.status, 401);
  await revoked.body?.cancel();
  await assert.rejects(aliceClient.callTool({ name: 'workouts_list', arguments: {} }));
  const replacement = example.approvals.reconnect(alice.authorizationId);
  assert.ok(replacement.authorizationId !== alice.authorizationId, 'Reconnect creates a new approval generation');
  assert.ok(replacement.token !== alice.token, 'Reconnect creates a new credential');
  const stillRevoked = await raw(alice.token);
  assert.equal(stillRevoked.status, 401);
  await stillRevoked.body?.cancel();
  await assert.rejects(modernClient.callTool({ name: 'workouts_list', arguments: {} }));
  const replacementClient = await connect(url, replacement.token);
  const fresh = await replacementClient.callTool({ name: 'workouts_get', arguments: { workoutId: 'workout-alice-1' } });
  assert.notEqual(fresh.isError, true);
  visibleWorkout(fresh.structuredContent.workout, 'workout-alice-1');
  const unaffected = await bobClient.callTool({ name: 'workouts_list', arguments: {} });
  assert.notEqual(unaffected.isError, true);
  pass('Revocation blocks an established client; reconnect uses fresh credentials and never restores old credentials; Bob remains authorized');

  phase = 'audit evidence';
  assert.ok(audit.length > 0, 'The example must actually emit audit events');
  assert.ok(audit.some((event) => event.action === 'workouts_list' && event.outcome === 'success'), 'Successful list emits an audit event');
  assert.ok(audit.some((event) => event.action === 'workouts_get' && event.outcome === 'success'), 'Successful detail emits an audit event');
  assert.ok(audit.some((event) => event.action === 'workouts_get' && event.outcome === 'failed' && event.code === 'NOT_FOUND'), 'Cross-account denial emits the expected failed action event');
  const auditJson = JSON.stringify(audit);
  for (const issued of [alice, bob, noScope, replacement]) assert.ok(!auditJson.includes(issued.token), 'Audit must omit credentials');
  assert.doesNotMatch(auditJson, /PRIVATE_(?:ALICE|BOB)_(?:NOTE|BILLING)|internalNote|billingReference/);
  pass('Successful and failed action audit events are emitted and omit credentials and private repository fields');
  phase = 'standalone CLI shutdown';
  await assertCliExit();
  pass('Standalone CLI exits with code 0 after its exit command while parent stdin remains open');
  await writeFile('./consumer-result.json', JSON.stringify({ status: 'passed', checks: evidence }, null, 2));
} catch (error) {
  // Deliberately retain only fixed phase and error class; never assertion values
  // or generated demo credentials. This is enough to localize a failing check.
  await writeFile('./consumer-result.json', JSON.stringify({ status: 'failed', phase, errorType: error?.constructor?.name ?? 'Error', checks: evidence }, null, 2));
  process.exitCode = 1;
} finally {
  await Promise.allSettled(clients.map((client) => client.close()));
  if (server?.listening) {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
}
`;

let temporary;
try {
  assert.ok(nodeMajor === 24 || (nodeMajor === 22 && nodeMinor >= 6),
    'Developer preview verification requires Node 22.6+ within 22.x, or Node 24.x');
  await mkdir(path.dirname(reportPath), { recursive: true });
  await writeFile(reportPath, JSON.stringify(report, null, 2) + '\n');
  const [manifest, rootManifest] = await Promise.all([
    readFile(path.join(sdkDirectory, 'package.json'), 'utf8').then(JSON.parse),
    readFile(path.join(root, 'package.json'), 'utf8').then(JSON.parse),
  ]);
  await readFile(path.join(sdkDirectory, 'dist/index.js')).catch(() => {
    throw new Error('SDK build is missing. Run npm run build before this script.');
  });
  assert.equal(manifest.name, '@gateivo/sdk');
  assert.match(manifest.version, /^\d+\.\d+\.\d+-(?:preview|alpha)\.\d+$/);
  assert.equal(manifest.private, true, 'Registry publishing remains disabled; this check must not enable it');
  assert.equal(manifest.engines.node, '>=22.6.0 <23 || 24.x');
  const permittedDependencies = new Set([
    '@modelcontextprotocol/express', '@modelcontextprotocol/node', '@modelcontextprotocol/server',
    '@types/express', '@types/express-serve-static-core', 'express', 'jose', 'zod',
  ]);
  for (const [name, version] of Object.entries(manifest.dependencies)) {
    assert.ok(permittedDependencies.has(name), `Unexpected SDK dependency: ${name}`);
    assert.match(version, /^\d+\.\d+\.\d+$/, `SDK dependency must be pinned: ${name}`);
  }

  temporary = await realpath(await mkdtemp(path.join(tmpdir(), 'gateivo-preview-consumer-')));
  assert.ok(!inside(await realpath(root), temporary), 'Consumer must be outside the SDK checkout');
  childEnv.npm_config_cache = path.join(temporary, 'npm-cache');
  const { stdout } = await npm(['pack', '--json', '--ignore-scripts', '--pack-destination', temporary], sdkDirectory, 'Packing SDK');
  const packed = JSON.parse(stdout);
  assert.equal(packed.length, 1);
  const pack = packed[0];
  assert.equal(pack.name, manifest.name);
  assert.equal(pack.version, manifest.version);
  const packedFiles = pack.files.map((file) => file.path).sort();
  for (const file of packedFiles) {
    assert.ok(['package.json', 'README.md', 'LICENSE', 'NOTICE', 'SECURITY.md', 'docs/authentication.md', 'docs/workos-connection.md', 'docs/workos-reference.md', 'docs/password-login.md'].includes(file) || /^dist\/[A-Za-z0-9_-]+(?:\.d\.(?:ts|cts)|\.(?:js|cjs))$/.test(file), `Unexpected tarball file: ${file}`);
    assert.doesNotMatch(file, /sagly|pilot|\.env|secret|service/i);
  }
  assert.ok(packedFiles.includes('README.md'), 'Tarball must contain developer documentation');
  for (const entry of ['index', 'core', 'express', 'oauth', 'workos-connect', 'workos-connect-express', 'workos-connect-postgres']) {
    for (const extension of ['js', 'cjs', 'd.ts', 'd.cts']) assert.ok(packedFiles.includes(`dist/${entry}.${extension}`));
  }
  report.package = { name: pack.name, version: pack.version, integrity: pack.integrity, fileCount: packedFiles.length, files: packedFiles };
  checks.push('Actual npm tarball contains only public entry points, runtime chunks, declarations, manifest and allowlisted documentation/license files');
  checks.push('Registry publishing remains disabled; SDK has no SAGLY, WorkOS vendor-SDK or PostgreSQL dependencies');

  const consumer = path.join(temporary, 'consumer');
  await mkdir(consumer);
  for (const file of exampleFiles) {
    await cp(path.join(exampleDirectory, file), path.join(consumer, file));
  }
  // Bind evidence to the distribution's original example, before npm rewrites
  // package.json to point at the installed local tarball.
  report.example = { files: Object.fromEntries(await Promise.all(exampleFiles.map(async (file) => [
    file, createHash('sha256').update(await readFile(path.join(consumer, file))).digest('hex'),
  ]))) };
  const consumerManifest = {
    name: 'gateivo-independent-consumer', version: '0.0.0', private: true, type: 'module',
    dependencies: {
      '@gateivo/sdk': `file:${path.join(temporary, pack.filename)}`,
      express: manifest.dependencies.express,
      zod: manifest.dependencies.zod,
    },
  };
  consumerManifest.devDependencies = {
    ...consumerManifest.devDependencies,
    '@modelcontextprotocol/client': rootManifest.devDependencies['@modelcontextprotocol/client'],
    '@types/node': rootManifest.devDependencies['@types/node'],
    typescript: rootManifest.devDependencies.typescript,
  };
  await writeFile(path.join(consumer, 'package.json'), JSON.stringify(consumerManifest, null, 2) + '\n');
  await npm(['install', '--ignore-scripts', '--no-audit', '--no-fund'], consumer, 'Installing independent consumer');
  const installedLock = JSON.parse(await readFile(path.join(consumer, 'package-lock.json'), 'utf8'));
  assert.ok(!Object.keys(installedLock.packages).some((name) => /(?:^|\/)node_modules\/(?:pg|@workos-inc\/node)$/.test(name)), 'Installed dependency graph must not include pilot database or provider SDK');
  const installedSdk = await realpath(path.join(consumer, 'node_modules/@gateivo/sdk'));
  assert.ok(inside(consumer, installedSdk), 'SDK must be an unpacked tarball, not a checkout symlink');
  for (const file of packedFiles.filter((file) => /^dist\/.*\.(?:js|cjs)$/.test(file))) {
    const code = await readFile(path.join(installedSdk, file), 'utf8');
    assert.doesNotMatch(code, /(?:from\s*|import\s*\(|require\s*\()\s*['"](?:node:sqlite|pg)['"]/, 'Runtime archive must not import an optional host database implementation');
  }
  report.isolatedInstallation = true;
  checks.push('Copied standalone example installs the tarball outside the checkout with no source aliases or NODE_PATH');

  await Promise.all(['mts', 'cts'].map((extension) => writeFile(path.join(consumer, `consumer-types.${extension}`), typesFixture)));
  await run(process.execPath, [
    'node_modules/typescript/bin/tsc', '--noEmit', '--strict', '--module', 'NodeNext',
    '--moduleResolution', 'NodeNext', '--target', 'ES2022', '--types', 'node', '--esModuleInterop',
    'consumer-types.mts', 'consumer-types.cts',
  ], consumer, 'Strict NodeNext ESM/CommonJS consumer declarations');
  checks.push('Strict NodeNext ESM/CommonJS consumers preserve action inference and typed connection/store contracts; missing authentication/binding hooks, wrong session/account types and partial stores are rejected');
  await writeFile(path.join(consumer, 'verify-runtime.mjs'), runtimeFixture);
  await writeFile(path.join(consumer, 'verify-bootstrap.cjs'), bootstrapFixture);
  try {
    await run(process.execPath, ['verify-bootstrap.cjs'], consumer, 'Independent CommonJS bootstrap and MCP consumer');
  } catch (error) {
    const result = await readFile(path.join(consumer, 'consumer-result.json'), 'utf8').then(JSON.parse).catch(() => null);
    if (result?.status === 'failed') throw new Error(`Independent MCP consumer failed during ${result.phase} (${result.errorType}).`);
    throw error;
  }
  const runtime = JSON.parse(await readFile(path.join(consumer, 'consumer-result.json'), 'utf8'));
  assert.equal(runtime.status, 'passed');
  checks.push(...runtime.checks);
  for (const [file, testedHash] of Object.entries(report.example.files)) {
    const sourceHash = createHash('sha256').update(await readFile(path.join(exampleDirectory, file))).digest('hex');
    assert.equal(sourceHash, testedHash, 'Example changed during verification: ' + file + '; rerun verification.');
  }
  checks.push('Verification records the exact standalone example file hashes and confirms source stayed unchanged during the test');
  report.status = 'passed';
  report.scope = 'Local package consumer and synthetic authorization lifecycle; not hosted OAuth or Claude acceptance.';
  console.log(`SDK consumer verified on ${process.version}: ${checks.length} checks passed using an isolated installed tarball.`);
} catch (error) {
  report.status = 'failed';
  report.failure = error instanceof Error ? error.message : 'Unknown verification failure';
  console.error(report.failure);
  process.exitCode = 1;
} finally {
  if (temporary) await rm(temporary, { recursive: true, force: true });
  await mkdir(path.dirname(reportPath), { recursive: true });
  await writeFile(reportPath, JSON.stringify(report, null, 2) + '\n');
}
