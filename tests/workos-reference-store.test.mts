import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, statSync, writeFileSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test, type TestContext } from 'node:test';

// The shipped reference is plain JavaScript and is tested without repository SDK imports.
const moduleUrl = new URL('../examples/workos-reference/store.mjs', import.meta.url).href;
const { createWorkOSReferenceStore } = await import(moduleUrl);
const NOW = Date.UTC(2030, 0, 1);
const OWNER = { sessionId: 'verified-browser-session', authVersion: 'login-generation-1' };
const BASE = {
  issuer: 'https://example-staging.authkit.app', clientId: 'client_example0001',
  resource: 'https://publisher.example/agent/mcp', providerSubject: 'user_example0001',
  appSubject: 'account-alice', scopes: ['workouts:read'], approvedExpiresAt: NOW + 3_600_000,
};
const identity = (consentId = 'app_consent_first0001', extra: Record<string, unknown> = {}) => ({
  issuer: BASE.issuer, subject: BASE.providerSubject, clientId: BASE.clientId,
  audience: BASE.resource, consentId, tokenId: 'first-token-id',
  scopes: ['openid', 'workouts:read', 'offline_access'], expiresAt: NOW + 600_000, ...extra,
});

function harness(t: TestContext) {
  const directory = mkdtempSync(join(tmpdir(), 'gateivo-consent-store-'));
  const path = join(directory, 'connections.sqlite');
  let time = NOW;
  let store = createWorkOSReferenceStore({ path, now: () => time });
  const additional: any[] = [];
  t.after(() => { for (const item of additional) item.close(); store.close(); rmSync(directory, { recursive: true, force: true }); });
  return {
    path, directory, get store() { return store; },
    advance(ms: number) { time += ms; },
    restart() { store.close(); store = createWorkOSReferenceStore({ path, now: () => time }); },
    second() { const other = createWorkOSReferenceStore({ path, now: () => time }); additional.push(other); return other; },
    begin(extra: Record<string, unknown> = {}, onStore = store) {
      const selected = { ...BASE, ...extra };
      const { revision } = onStore.getState(selected);
      return onStore.begin({ ...selected, ...OWNER, expectedRevision: revision,
        stateHash: 'a'.repeat(64), attemptExpiresAt: time + 120_000 });
    },
    approve(consentId = 'app_consent_first0001') {
      const pending = this.begin();
      assert.equal(store.completeReset(pending), true);
      const consumed = store.consume(pending);
      assert.ok(consumed);
      return store.complete(consumed, identity(consentId));
    },
  };
}

test('standalone consent store persists active grants and original bindings across restart', t => {
  const h = harness(t);
  const grant = h.approve();
  assert.equal(statSync(h.path).mode & 0o777, 0o600);
  assert.equal(grant.subject, BASE.appSubject);
  assert.deepEqual(grant.scopes, BASE.scopes);
  assert.equal(grant.expiresAt, BASE.approvedExpiresAt);
  assert.equal(h.store.isActive(grant), true);
  h.restart();
  const resolved = h.store.resolveConsent(identity());
  assert.equal(resolved.authorizationId, grant.authorizationId);
  assert.equal(resolved.expiresAt, identity().expiresAt);
  assert.equal(h.store.getState(BASE).active, true);
  assert.ok(Object.isFrozen(resolved)); assert.ok(Object.isFrozen(resolved.scopes));
});

test('unknown consent and changed token identity never create or remap a grant', t => {
  const h = harness(t); const grant = h.approve();
  assert.equal(h.store.resolveConsent(identity('app_consent_unknown')), null);
  for (const changed of [
    { issuer: 'https://another.authkit.app' }, { subject: 'user_other0001' },
    { clientId: 'client_other0001' }, { audience: 'https://publisher.example/another' },
    { scopes: ['openid'] }, { scopes: ['workouts:read', 'workouts:read'] }, { expiresAt: NOW },
  ]) assert.equal(h.store.resolveConsent(identity(undefined, changed)), null);
  assert.equal(h.store.resolveConsent(identity(undefined, { tokenId: 'fresh-refreshed-jti' })).authorizationId, grant.authorizationId);
  assert.equal(h.store.getState(BASE).authorizationId, grant.authorizationId);
});

test('disconnect is owner-scoped, permanent, and survives reconnect with a fresh consent', t => {
  const h = harness(t); const old = h.approve();
  assert.equal(h.store.revoke({ appSubject: 'account-bob', authorizationId: old.authorizationId }), false);
  assert.equal(h.store.isActive(old), true);
  assert.equal(h.store.revoke({ appSubject: BASE.appSubject, authorizationId: old.authorizationId }), true);
  assert.equal(h.store.revoke({ appSubject: BASE.appSubject, authorizationId: old.authorizationId }), false);
  h.restart();
  const replacement = h.approve('app_consent_replacement0001');
  assert.notEqual(replacement.authorizationId, old.authorizationId);
  assert.equal(h.store.isActive(old), false);
  assert.equal(h.store.resolveConsent(identity()), null);
  assert.equal(h.store.resolveConsent(identity(undefined, { tokenId: 'fresh-old-family-jti' })), null);
  assert.equal(h.store.resolveConsent(identity('app_consent_replacement0001')).authorizationId, replacement.authorizationId);
});

test('the same historical provider consent can never be approved again', t => {
  const h = harness(t); const old = h.approve();
  h.store.revoke({ appSubject: BASE.appSubject, authorizationId: old.authorizationId });
  const next = h.begin(); assert.equal(h.store.completeReset(next), true);
  const consumed = h.store.consume(next);
  assert.throws(() => h.store.complete(consumed, identity()), /could not be verified/);
  h.store.fail(consumed); h.restart();
  assert.equal(h.store.getState(BASE).phase, 'blocked');
  assert.equal(h.store.getState(BASE).active, false);
  assert.equal(h.store.resolveConsent(identity()), null);
});

test('begin revokes existing access atomically and stale form revisions cannot reset it twice', t => {
  const h = harness(t); const original = h.approve();
  const second = h.second(); const revision = second.getState(BASE).revision;
  h.begin();
  assert.equal(h.store.isActive(original), false);
  assert.equal(second.resolveConsent(identity()), null);
  assert.throws(() => second.begin({ ...BASE, ...OWNER, expectedRevision: revision,
    stateHash: 'b'.repeat(64), attemptExpiresAt: NOW + 120_000 }), /could not be verified/);
  assert.throws(() => h.begin(), /could not be verified/);
});

test('disconnect compares its revision atomically against concurrent reconnect forms', t => {
  const h = harness(t); const original = h.approve();
  const { revision } = h.store.getState(BASE);
  assert.equal(h.store.revoke({ appSubject: BASE.appSubject, authorizationId: original.authorizationId,
    expectedRevision: '00000000-0000-4000-8000-000000000000' }), false);
  assert.equal(h.store.isActive(original), true);
  assert.equal(h.store.revoke({ appSubject: BASE.appSubject, authorizationId: original.authorizationId,
    expectedRevision: revision }), true);
  assert.throws(() => h.store.begin({ ...BASE, ...OWNER, expectedRevision: revision,
    stateHash: 'a'.repeat(64), attemptExpiresAt: NOW + 120_000 }), /could not be verified/);
  const pending = h.begin();
  assert.equal(h.store.revoke({ appSubject: BASE.appSubject, authorizationId: original.authorizationId,
    expectedRevision: revision }), false);
  assert.equal(h.store.getState(BASE).phase, 'reset_pending');
  assert.equal(h.store.claimReset(pending), true);
});

test('callback state, authenticated session, target and operation must match before one-use consumption', t => {
  const h = harness(t); const pending = h.begin(); h.store.completeReset(pending);
  for (const changed of [
    { stateHash: 'b'.repeat(64) }, { sessionId: 'another-session' }, { authVersion: 'another-login' },
    { approvedExpiresAt: BASE.approvedExpiresAt - 1 }, { operationId: '00000000-0000-4000-8000-000000000000' },
  ]) assert.equal(h.store.consume({ ...pending, ...changed }), null);
  assert.throws(() => h.store.consume({ ...pending, appSubject: 'account-bob' }), /could not be verified/);
  const consumed = h.store.consume(pending); assert.ok(consumed);
  assert.equal(h.store.consume(pending), null);
  assert.throws(() => h.store.complete({ ...consumed, sessionId: 'another-session' }, identity()), /could not be verified/);
  assert.throws(() => h.store.complete(consumed, identity(undefined, { subject: 'user_other0001' })), /could not be verified/);
  assert.throws(() => h.store.complete(consumed, identity(undefined, { scopes: ['openid'] })), /could not be verified/);
  h.store.complete(consumed, identity());
  assert.throws(() => h.store.complete(consumed, identity()), /could not be verified/);
});

test('dispatch claim is durable before provider deletion and uncertainty remains fenced after restart', t => {
  const h = harness(t); const pending = h.begin();
  assert.equal(h.store.claimReset(pending), true);
  assert.equal(h.second().getState(BASE).phase, 'reset_dispatched');
  assert.equal(h.store.claimReset(pending), false);
  h.restart(); h.advance(6 * 60_000);
  assert.throws(() => h.begin(), /could not be verified/);
  assert.equal(h.store.completeReset(pending), false);
  h.store.fail(pending); h.restart();
  assert.equal(h.store.getState(BASE).phase, 'blocked');
  assert.throws(() => h.begin(), /could not be verified/);
});

test('an interrupted exchange cannot reopen after timeout or process restart', t => {
  const h = harness(t); const pending = h.begin(); h.store.completeReset(pending);
  const consumed = h.store.consume(pending);
  h.restart(); h.advance(6 * 60_000);
  assert.equal(h.store.getState(BASE).phase, 'exchanging');
  assert.throws(() => h.begin(), /could not be verified/);
  assert.throws(() => h.store.complete(consumed, identity()), /could not be verified/);
  h.store.fail(consumed);
  assert.equal(h.store.getState(BASE).phase, 'blocked');
});

test('verified consent denial consumes the callback once and permits a fresh approval attempt', t => {
  const h = harness(t); const pending = h.begin();
  assert.equal(h.store.cancel(pending), false); // Reset is not yet definitively complete.
  h.store.completeReset(pending);
  for (const changed of [
    { stateHash: 'b'.repeat(64) }, { sessionId: 'another-session' }, { authVersion: 'another-login' },
    { approvedExpiresAt: BASE.approvedExpiresAt - 1 },
  ]) assert.equal(h.store.cancel({ ...pending, ...changed }), false);
  assert.equal(h.store.getState(BASE).phase, 'awaiting_consent');
  assert.equal(h.store.cancel(pending), true);
  assert.equal(h.store.cancel(pending), false);
  assert.equal(h.store.consume(pending), null);
  assert.equal(h.store.getState(BASE).phase, 'failed');
  h.restart();
  const fresh = h.begin(); assert.notEqual(fresh.operationId, pending.operationId);
  h.store.completeReset(fresh); const consumed = h.store.consume(fresh);
  assert.equal(h.store.cancel(consumed), false); // No cancellation of an uncertain exchange.
  h.store.fail(consumed);
  assert.equal(h.store.getState(BASE).phase, 'blocked');
});

test('an expired awaiting-consent flow can restart without making its old callback usable', t => {
  const h = harness(t); const pending = h.begin(); h.store.completeReset(pending);
  h.advance(121_000);
  assert.equal(h.store.cancel(pending), false);
  const replacement = h.begin();
  assert.equal(h.store.consume(pending), null);
  assert.equal(h.store.cancel(pending), false);
  assert.equal(h.store.getState(BASE).phase, 'reset_pending');
  assert.equal(h.store.completeReset(replacement), true);
});

test('a stale reset with no dispatched mutation can be replaced but the old ticket stays invalid', t => {
  const h = harness(t); const pending = h.begin();
  h.advance(121_000); h.restart();
  const replacement = h.begin();
  assert.notEqual(replacement.operationId, pending.operationId);
  assert.equal(h.store.claimReset(pending), false);
  assert.equal(h.store.completeReset(pending), false);
  h.store.fail(pending);
  assert.equal(h.store.getState(BASE).phase, 'reset_pending');
  assert.equal(h.store.claimReset(replacement), true);
  assert.equal(h.store.completeReset(replacement), true);
});

test('a provider user/client scope cannot move to a new resource, app owner or permission set', t => {
  const h = harness(t); h.begin();
  for (const changed of [
    { resource: 'https://publisher.example/another-resource' }, { appSubject: 'account-bob' },
    { scopes: ['workouts:read', 'workouts:write'] },
  ]) assert.throws(() => h.store.getState({ ...BASE, ...changed }), /could not be verified/);
  // Another registered OAuth client is an independent reset scope, even on the same resource.
  const independent = h.begin({ clientId: 'client_independent0001' });
  assert.equal(h.store.claimReset(independent), true);
  assert.equal(h.store.getState(BASE).phase, 'reset_pending');
});

test('a consent generation is globally unique within its issuer, including across clients', t => {
  const h = harness(t); h.approve();
  const independent = h.begin({ clientId: 'client_independent0001' });
  h.store.completeReset(independent); const consumed = h.store.consume(independent);
  assert.throws(() => h.store.complete(consumed, identity(undefined, { clientId: independent.clientId })), /could not be verified/);
  assert.equal(h.store.resolveConsent(identity()).subject, BASE.appSubject);
});

test('expiry, permission changes, abort and forged principals are denied', t => {
  const h = harness(t); const grant = h.approve();
  assert.equal(h.store.isActive({ ...grant, subject: 'account-bob' }), false);
  assert.equal(h.store.isActive({ ...grant, scopes: ['workouts:write'] }), false);
  assert.equal(h.store.isActive({ ...grant, expiresAt: NOW }), false);
  const controller = new AbortController(); controller.abort();
  assert.equal(h.store.resolveConsent(identity(), { signal: controller.signal }), null);
  assert.equal(h.store.isActive(grant, { signal: controller.signal }), false);
  assert.throws(() => h.store.revoke({ appSubject: BASE.appSubject, authorizationId: grant.authorizationId },
    { signal: controller.signal }), /could not be verified/);
  h.advance(3_600_001);
  assert.equal(h.store.isActive(grant), false);
  assert.equal(h.store.resolveConsent(identity(undefined, { expiresAt: NOW + 4_000_000 })), null);
});

test('live account mapping is checked against the grant identity again around business reads', t => {
  const h = harness(t); const grant = h.approve();
  const binding = { issuer: BASE.issuer, providerSubject: BASE.providerSubject, clientId: BASE.clientId, resource: BASE.resource };
  assert.equal(h.store.isActive(grant, binding), true);
  for (const changed of [
    { issuer: 'https://another.authkit.app' }, { providerSubject: 'user_reassigned0001' },
    { clientId: 'client_another0001' }, { resource: 'https://publisher.example/other' },
  ]) assert.equal(h.store.isActive(grant, { ...binding, ...changed }), false);
});

test('approval and attempt bounds, duplicate scopes and noncanonical URLs reject before mutation', t => {
  const h = harness(t); const state = h.store.getState(BASE);
  const input = { ...BASE, ...OWNER, expectedRevision: state.revision, stateHash: 'a'.repeat(64), attemptExpiresAt: NOW + 120_000 };
  for (const changed of [
    { approvedExpiresAt: NOW + 7 * 86_400_000 + 1 }, { approvedExpiresAt: NOW },
    { attemptExpiresAt: NOW + 300_001 }, { attemptExpiresAt: NOW }, { stateHash: 'not-a-hash' },
    { issuer: `${BASE.issuer}/` }, { resource: 'http://publisher.example/agent/mcp' },
    { scopes: ['workouts:read', 'workouts:read'] }, { scopes: ['invalid scope'] },
  ]) assert.throws(() => h.store.begin({ ...input, ...changed }), /could not be verified/);
  assert.deepEqual(h.store.getState(BASE), state);
});

test('reference database refuses relative paths, shared permissions, symlinks and unrelated files', t => {
  const h = harness(t);
  assert.throws(() => createWorkOSReferenceStore({ path: 'relative.sqlite' }));
  const publicFile = join(h.directory, 'public.sqlite'); writeFileSync(publicFile, '', { mode: 0o644 });
  assert.throws(() => createWorkOSReferenceStore({ path: publicFile }), /private/);
  const alias = join(h.directory, 'alias.sqlite'); symlinkSync(h.path, alias);
  assert.throws(() => createWorkOSReferenceStore({ path: alias }), /private/);
  const unrelated = join(h.directory, 'unrelated.sqlite'); writeFileSync(unrelated, '', { mode: 0o600 });
  assert.throws(() => createWorkOSReferenceStore({ path: unrelated }), /schema/);
});
