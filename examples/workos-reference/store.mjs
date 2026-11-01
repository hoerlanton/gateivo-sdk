// Generic Gateivo reference implementation. See the repository MIT licence.
import { randomUUID } from 'node:crypto';
import { closeSync, constants, lstatSync, openSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const APPLICATION_ID = 0x47415445;
const ATTEMPT_MS = 5 * 60_000;
const APPROVAL_MS = 7 * 24 * 60 * 60_000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HASH = /^[0-9a-f]{64}$/;
const MAX_TIME = 8_640_000_000_000_000;
const opaque = (value, max = 512) => typeof value === 'string' && value.length > 0
  && value.length <= max && /^[\x21-\x7e]+$/.test(value);
const millis = value => Number.isSafeInteger(value) && value > 0 && value <= MAX_TIME;
const reject = () => { throw new Error('Connection state could not be verified.'); };
const canonicalUrl = (value, originOnly = false) => {
  try {
    if (!opaque(value, 2048)) return false;
    const url = new URL(value);
    return url.protocol === 'https:' && !url.username && !url.password && !url.search && !url.hash
      && (originOnly ? url.origin === value : url.href === value);
  } catch { return false; }
};
const canonicalScopes = input => {
  if (!Array.isArray(input) || input.length < 1 || input.length > 32
    || input.some(scope => typeof scope !== 'string' || !/^[\x21\x23-\x5b\x5d-\x7e]{1,128}$/.test(scope))
    || new Set(input).size !== input.length) reject();
  return [...input].sort();
};
const target = value => {
  if (!value || !canonicalUrl(value.issuer, true) || !canonicalUrl(value.resource)
    || !opaque(value.clientId, 128) || !opaque(value.providerSubject, 128)
    || !opaque(value.appSubject) || !millis(value.approvedExpiresAt)) reject();
  return { issuer: value.issuer, clientId: value.clientId, resource: value.resource,
    providerSubject: value.providerSubject, appSubject: value.appSubject,
    scopes: canonicalScopes(value.scopes), approvedExpiresAt: value.approvedExpiresAt };
};
const binding = value => {
  if (!value || !opaque(value.sessionId, 256) || !opaque(value.authVersion, 256)) reject();
  return { sessionId: value.sessionId, authVersion: value.authVersion };
};
const ticket = value => {
  if (!value || !UUID.test(value.operationId) || !HASH.test(value.stateHash) || !millis(value.attemptExpiresAt)) reject();
  return { ...target(value), ...binding(value), operationId: value.operationId,
    stateHash: value.stateHash, attemptExpiresAt: value.attemptExpiresAt };
};
const scopeKey = value => JSON.stringify([value.issuer, value.providerSubject, value.clientId]);
const freeze = value => Object.freeze({ ...value, scopes: Object.freeze([...value.scopes]) });
const stopped = context => { if (context?.signal?.aborted) reject(); };

/**
 * Single-host reference persistence. Keep this file on a persistent private disk.
 * It is not suitable for Heroku's ephemeral filesystem, shared network filesystems, or
 * multiple app hosts. The host must authenticate sessions and check live account state.
 * No access/refresh tokens, API keys, authorization codes or PKCE verifiers are stored.
 */
export function createWorkOSReferenceStore({ path, now = Date.now } = {}) {
  if (typeof path !== 'string' || !isAbsolute(path) || typeof now !== 'function') reject();
  let created = false;
  try {
    const fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    closeSync(fd); created = true;
  } catch (error) { if (error?.code !== 'EEXIST') throw new Error('Private connection database could not be opened.'); }
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0
    || (typeof process.getuid === 'function' && stat.uid !== process.getuid())) {
    throw new Error('Connection database must be a private, owner-controlled regular file.');
  }
  const db = new DatabaseSync(path);
  let closed = false;
  const clock = () => { const value = now(); if (!millis(value)) reject(); return value; };
  const transaction = work => {
    if (closed) reject();
    db.exec('BEGIN IMMEDIATE');
    try { const result = work(); db.exec('COMMIT'); return result; }
    catch (error) { db.exec('ROLLBACK'); throw error; }
  };
  try {
    db.exec('PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 2000; PRAGMA synchronous = FULL;');
    const marker = db.prepare('PRAGMA application_id').get().application_id;
    const version = db.prepare('PRAGMA user_version').get().user_version;
    if (!created && (marker !== APPLICATION_ID || version !== 1)) reject();
    if (created) transaction(() => {
      db.exec(`
        CREATE TABLE connection_scope (
          scope_key TEXT PRIMARY KEY, issuer TEXT NOT NULL, provider_subject TEXT NOT NULL,
          client_id TEXT NOT NULL, resource TEXT NOT NULL, app_subject TEXT NOT NULL,
          scopes TEXT NOT NULL, revision TEXT NOT NULL,
          UNIQUE(issuer, provider_subject, client_id)
        ) STRICT;
        CREATE TABLE connection_flow (
          scope_key TEXT PRIMARY KEY REFERENCES connection_scope(scope_key),
          operation_id TEXT NOT NULL UNIQUE, ticket TEXT NOT NULL,
          phase TEXT NOT NULL CHECK (phase IN ('reset_pending','reset_dispatched','awaiting_consent','exchanging','completed','failed','blocked'))
        ) STRICT;
        CREATE TABLE connection_grant (
          id TEXT PRIMARY KEY, scope_key TEXT NOT NULL REFERENCES connection_scope(scope_key),
          issuer TEXT NOT NULL, consent_id TEXT NOT NULL, app_subject TEXT NOT NULL,
          scopes TEXT NOT NULL, expires_at INTEGER NOT NULL, revoked_at INTEGER,
          UNIQUE(issuer, consent_id)
        ) STRICT;
        CREATE INDEX grant_scope ON connection_grant(scope_key);
        PRAGMA application_id = ${APPLICATION_ID}; PRAGMA user_version = 1;
      `);
    });
  } catch {
    db.close(); throw new Error('Connection database schema could not be verified.');
  }
  const scope = (value, create = false) => {
    const key = scopeKey(value);
    let row = db.prepare('SELECT * FROM connection_scope WHERE scope_key = ?').get(key);
    if (!row && create) {
      db.prepare('INSERT INTO connection_scope VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
        .run(key, value.issuer, value.providerSubject, value.clientId, value.resource,
          value.appSubject, JSON.stringify(value.scopes), randomUUID());
      row = db.prepare('SELECT * FROM connection_scope WHERE scope_key = ?').get(key);
    }
    if (row && (row.issuer !== value.issuer || row.provider_subject !== value.providerSubject
      || row.client_id !== value.clientId || row.resource !== value.resource || row.app_subject !== value.appSubject
      || row.scopes !== JSON.stringify(value.scopes))) reject();
    return row;
  };
  const flow = key => db.prepare('SELECT * FROM connection_flow WHERE scope_key = ?').get(key);
  const touch = key => db.prepare('UPDATE connection_scope SET revision = ? WHERE scope_key = ?').run(randomUUID(), key);
  const transition = (key, phase) => {
    db.prepare('UPDATE connection_flow SET phase = ? WHERE scope_key = ?').run(phase, key); touch(key);
  };
  const matches = (row, value) => !!row && row.operation_id === value.operationId
    && JSON.stringify(ticket(JSON.parse(row.ticket))) === JSON.stringify(value);
  const activeGrant = (key, time) => db.prepare(`SELECT * FROM connection_grant
    WHERE scope_key = ? AND revoked_at IS NULL AND expires_at > ?`).get(key, time);
  const grantValue = (row, expiresAt = row.expires_at) => freeze({
    authorizationId: row.id, subject: row.app_subject, scopes: JSON.parse(row.scopes), expiresAt,
  });
  const usable = (row, time) => !!row && row.revoked_at === null && row.expires_at > time;

  return Object.freeze({
    getState(input, context) {
      stopped(context); const selected = target(input);
      return transaction(() => {
        const row = scope(selected, true); const current = flow(row.scope_key);
        const grant = activeGrant(row.scope_key, clock());
        return Object.freeze({ revision: row.revision, phase: current?.phase ?? null,
          attemptExpiresAt: current ? ticket(JSON.parse(current.ticket)).attemptExpiresAt : null, active: !!grant,
          ...(grant ? { authorizationId: grant.id } : {}) });
      });
    },
    begin(input, context) {
      stopped(context); const selected = target(input); const owner = binding(input); const time = clock();
      if (!UUID.test(input.expectedRevision) || !HASH.test(input.stateHash)
        || !millis(input.attemptExpiresAt) || input.attemptExpiresAt <= time || input.attemptExpiresAt > time + ATTEMPT_MS
        || selected.approvedExpiresAt <= time || selected.approvedExpiresAt > time + APPROVAL_MS
        || input.attemptExpiresAt > selected.approvedExpiresAt) reject();
      return transaction(() => {
        const row = scope(selected); if (!row || row.revision !== input.expectedRevision) reject();
        if (input.attemptExpiresAt <= clock() || selected.approvedExpiresAt <= clock()) reject();
        const current = flow(row.scope_key);
        if (current && !['completed', 'failed'].includes(current.phase)) {
          const previous = ticket(JSON.parse(current.ticket));
          // A stale pending reset never dispatched DELETE. Awaiting consent means reset
          // definitively completed and no exchange began. Replacing either invalidates
          // the previous operation ID; uncertain dispatched/exchanging phases stay fenced.
          if (!['reset_pending', 'awaiting_consent'].includes(current.phase) || previous.attemptExpiresAt > time) reject();
        }
        const next = { ...selected, ...owner, operationId: randomUUID(), stateHash: input.stateHash,
          attemptExpiresAt: input.attemptExpiresAt };
        db.prepare('UPDATE connection_grant SET revoked_at = ? WHERE scope_key = ? AND revoked_at IS NULL').run(time, row.scope_key);
        db.prepare(`INSERT INTO connection_flow VALUES (?, ?, ?, 'reset_pending') ON CONFLICT(scope_key)
          DO UPDATE SET operation_id = excluded.operation_id, ticket = excluded.ticket, phase = excluded.phase`)
          .run(row.scope_key, next.operationId, JSON.stringify(next));
        touch(row.scope_key); return freeze(next);
      });
    },
    claimReset(input, context) {
      stopped(context); const saved = ticket(input);
      return transaction(() => {
        const row = scope(saved); const current = row && flow(row.scope_key);
        if (!matches(current, saved) || current.phase !== 'reset_pending'
          || saved.attemptExpiresAt <= clock() || saved.approvedExpiresAt <= clock()) return false;
        transition(row.scope_key, 'reset_dispatched'); return true;
      });
    },
    completeReset(input, context) {
      stopped(context); const saved = ticket(input);
      return transaction(() => {
        const row = scope(saved); const current = row && flow(row.scope_key);
        if (!matches(current, saved) || !['reset_pending', 'reset_dispatched'].includes(current.phase)
          || saved.attemptExpiresAt <= clock() || saved.approvedExpiresAt <= clock()) return false;
        transition(row.scope_key, 'awaiting_consent'); return true;
      });
    },
    fail(input, context) {
      stopped(context); const saved = ticket(input);
      return transaction(() => {
        const row = scope(saved); const current = row && flow(row.scope_key);
        if (!matches(current, saved) || ['blocked', 'completed', 'failed'].includes(current.phase)) return;
        transition(row.scope_key, ['reset_dispatched', 'exchanging'].includes(current.phase) ? 'blocked' : 'failed');
      });
    },
    consume(input, context) {
      stopped(context); const selected = target(input); const owner = binding(input);
      if (!UUID.test(input.operationId) || !HASH.test(input.stateHash)) return null;
      return transaction(() => {
        const row = scope(selected); const current = row && flow(row.scope_key);
        if (!current || current.operation_id !== input.operationId || current.phase !== 'awaiting_consent') return null;
        const saved = ticket(JSON.parse(current.ticket));
        if (saved.stateHash !== input.stateHash || saved.sessionId !== owner.sessionId || saved.authVersion !== owner.authVersion
          || JSON.stringify(target(saved)) !== JSON.stringify(selected)
          || saved.attemptExpiresAt <= clock() || saved.approvedExpiresAt <= clock()) return null;
        transition(row.scope_key, 'exchanging'); return freeze(saved);
      });
    },
    /** A verified provider denial consumes only an awaiting callback; no exchange was started. */
    cancel(input, context) {
      stopped(context); const selected = target(input); const owner = binding(input);
      if (!UUID.test(input.operationId) || !HASH.test(input.stateHash)) return false;
      return transaction(() => {
        const row = scope(selected); const current = row && flow(row.scope_key);
        if (!current || current.operation_id !== input.operationId || current.phase !== 'awaiting_consent') return false;
        const saved = ticket(JSON.parse(current.ticket));
        if (saved.stateHash !== input.stateHash || saved.sessionId !== owner.sessionId || saved.authVersion !== owner.authVersion
          || JSON.stringify(target(saved)) !== JSON.stringify(selected)
          || saved.attemptExpiresAt <= clock() || saved.approvedExpiresAt <= clock()) return false;
        transition(row.scope_key, 'failed'); return true;
      });
    },
    complete(input, identity, context) {
      stopped(context); const saved = ticket(input); const time = clock();
      if (!identity || identity.issuer !== saved.issuer || identity.subject !== saved.providerSubject
        || identity.clientId !== saved.clientId || identity.audience !== saved.resource
        || !opaque(identity.consentId, 128) || !millis(identity.expiresAt) || identity.expiresAt <= time
        || !saved.scopes.every(scope => canonicalScopes(identity.scopes).includes(scope))) reject();
      return transaction(() => {
        const row = scope(saved); const current = row && flow(row.scope_key);
        if (!matches(current, saved) || current.phase !== 'exchanging'
          || saved.attemptExpiresAt <= clock() || saved.approvedExpiresAt <= clock() || identity.expiresAt <= clock()) reject();
        // Never revive or reassign a known generation, even if the same user reconnects.
        if (db.prepare('SELECT 1 FROM connection_grant WHERE issuer = ? AND consent_id = ?')
          .get(saved.issuer, identity.consentId)) reject();
        const id = randomUUID();
        db.prepare('INSERT INTO connection_grant VALUES (?, ?, ?, ?, ?, ?, ?, NULL)')
          .run(id, row.scope_key, saved.issuer, identity.consentId, saved.appSubject,
            JSON.stringify(saved.scopes), saved.approvedExpiresAt);
        transition(row.scope_key, 'completed');
        return grantValue(db.prepare('SELECT * FROM connection_grant WHERE id = ?').get(id));
      });
    },
    resolveConsent(identity, context) {
      if (closed || context?.signal?.aborted) return null;
      try {
        if (!identity || !canonicalUrl(identity.issuer, true) || !opaque(identity.consentId, 128)
          || !opaque(identity.subject, 128) || !opaque(identity.clientId, 128) || !canonicalUrl(identity.audience)
          || !millis(identity.expiresAt) || identity.expiresAt <= clock()) return null;
        const scopes = canonicalScopes(identity.scopes);
        const row = db.prepare(`SELECT g.*, s.provider_subject, s.client_id, s.resource
          FROM connection_grant g JOIN connection_scope s ON s.scope_key = g.scope_key
          WHERE g.issuer = ? AND g.consent_id = ?`).get(identity.issuer, identity.consentId);
        if (!usable(row, clock()) || row.provider_subject !== identity.subject || row.client_id !== identity.clientId
          || row.resource !== identity.audience || !JSON.parse(row.scopes).every(scope => scopes.includes(scope))) return null;
        return grantValue(row, Math.min(row.expires_at, identity.expiresAt));
      } catch { return null; }
    },
    revoke({ appSubject, authorizationId, expectedRevision } = {}, context) {
      stopped(context); if (!opaque(appSubject) || !UUID.test(authorizationId)
        || (expectedRevision !== undefined && !UUID.test(expectedRevision))) return false;
      return transaction(() => {
        const row = db.prepare('SELECT * FROM connection_grant WHERE id = ? AND app_subject = ?').get(authorizationId, appSubject);
        if (!row || row.revoked_at !== null) return false;
        const state = db.prepare('SELECT revision FROM connection_scope WHERE scope_key = ?').get(row.scope_key);
        if (!state || (expectedRevision !== undefined && state.revision !== expectedRevision)) return false;
        db.prepare('UPDATE connection_grant SET revoked_at = ? WHERE id = ?').run(clock(), authorizationId);
        touch(row.scope_key); return true;
      });
    },
    isActive(principal, context) {
      if (closed || context?.signal?.aborted) return false;
      try {
        if (!principal || !UUID.test(principal.authorizationId) || !opaque(principal.subject)
          || !millis(principal.expiresAt) || principal.expiresAt <= clock()) return false;
        const scopes = canonicalScopes(principal.scopes);
        const row = db.prepare(`SELECT g.*, s.provider_subject, s.client_id, s.resource
          FROM connection_grant g JOIN connection_scope s ON s.scope_key = g.scope_key
          WHERE g.id = ? AND g.app_subject = ?`)
          .get(principal.authorizationId, principal.subject);
        return usable(row, clock()) && scopes.every(scope => JSON.parse(row.scopes).includes(scope))
          && (context?.issuer === undefined || context.issuer === row.issuer)
          && (context?.providerSubject === undefined || context.providerSubject === row.provider_subject)
          && (context?.clientId === undefined || context.clientId === row.client_id)
          && (context?.resource === undefined || context.resource === row.resource);
      } catch { return false; }
    },
    close() { if (!closed) { db.close(); closed = true; } },
  });
}
