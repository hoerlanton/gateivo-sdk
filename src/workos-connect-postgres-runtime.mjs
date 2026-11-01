// Shared WorkOS PostgreSQL connection store. See the repository MIT licence.
// Schema markers and advisory-lock identities intentionally retain their original values.
import { createHash, randomUUID } from 'node:crypto';

const APPLICATION = 'gateivo-workos-reference';
const VERSION = 1;
const ATTEMPT_MS = 5 * 60_000;
const APPROVAL_MS = 7 * 24 * 60 * 60_000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HASH = /^[0-9a-f]{64}$/;
const MAX_TIME = 8_640_000_000_000_000;
const opaque = (value, max = 512) => typeof value === 'string' && value.length > 0
  && value.length <= max && /^[\x21-\x7e]+$/.test(value);
const millis = value => Number.isSafeInteger(value) && value > 0 && value <= MAX_TIME;
const failure = () => new Error('Connection state could not be verified.');
const reject = () => { throw failure(); };
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
const storedTime = value => {
  // pg returns int8 as strings unless the host configured a custom type parser.
  if (typeof value !== 'number' && (typeof value !== 'string' || !/^[1-9][0-9]{0,15}$/.test(value))) reject();
  const time = Number(value); if (!millis(time)) reject(); return time;
};
const storedScopes = value => canonicalScopes(JSON.parse(value));
const lockKey = value => {
  const digest = createHash('sha256').update(value).digest();
  return [digest.readInt32BE(0), digest.readInt32BE(4)];
};

/**
 * PostgreSQL reference persistence for multiple app processes/hosts. The caller
 * owns the Pool, its TLS configuration, capacity and idle-error handling. Never
 * point this reference at an unrelated schema. Call migrate() in an explicit
 * deployment/release step, then checkReady() before accepting traffic.
 *
 * No API keys, access/refresh tokens, authorization codes or PKCE verifiers are
 * persisted. Every mutation is serialized by issuer/provider user/OAuth client;
 * granting a fresh consent never edits or revives a historical authorization.
 */
export function createWorkOSPostgresStoreRuntime({ pool, schema = 'gateivo_reference', now = Date.now, timeoutMs = 3000 } = {}) {
  if (!pool || typeof pool.connect !== 'function' || typeof now !== 'function'
    || typeof schema !== 'string' || !/^[a-z][a-z0-9_]{0,62}$/.test(schema)
    || schema === 'public' || schema === 'information_schema' || schema.startsWith('pg_')
    || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30_000) reject();
  const namespace = `"${schema}"`;
  const table = name => `${namespace}."${name}"`;
  const markerTable = table('reference_schema');
  const scopeTable = table('connection_scope');
  const flowTable = table('connection_flow');
  const grantTable = table('connection_grant');
  let closed = false;
  const operations = new Set();
  const clock = () => { const value = now(); if (!millis(value)) reject(); return value; };

  // A single deadline bounds pool checkout, lock waits, SQL, work and COMMIT.
  // Any ambiguous outcome destroys the checked-out client. No transaction or
  // provider reset is retried automatically. A late pool checkout is destroyed,
  // too, rather than leaking a connection after the caller has timed out.
  const transaction = async (readonly, context, work, verify = true) => {
    const signal = context?.signal;
    if (closed || signal?.aborted || (signal !== undefined
      && (typeof signal.addEventListener !== 'function' || typeof signal.removeEventListener !== 'function'))) reject();
    const deadline = performance.now() + timeoutMs;
    let client; let released = false; let cancelled = false; let failed = false;
    let rejectCancellation = () => {};
    const release = destroy => {
      if (!client || released) return;
      released = true;
      client.removeListener?.('error', connectionError);
      try { client.release(destroy); } catch { /* Never expose driver cleanup details. */ }
    };
    const cancel = () => {
      cancelled = true; release(true); rejectCancellation(failure());
    };
    const connectionError = () => {
      failed = true; release(true); rejectCancellation(failure());
    };
    const assertActive = () => {
      if (closed || cancelled || signal?.aborted || performance.now() >= deadline) { cancel(); reject(); }
      if (failed) reject();
    };
    const cancellation = new Promise((_, rejectPromise) => { rejectCancellation = rejectPromise; });
    signal?.addEventListener('abort', cancel, { once: true });
    operations.add(cancel);
    const timer = setTimeout(cancel, timeoutMs);
    const run = async () => {
      try {
        assertActive();
        client = await pool.connect();
        client.on?.('error', connectionError);
        assertActive();
        const query = async (sql, values = []) => {
          assertActive();
          const result = await client.query(sql, values);
          assertActive();
          return result;
        };
        await query(`BEGIN TRANSACTION ISOLATION LEVEL READ COMMITTED, READ ${readonly ? 'ONLY' : 'WRITE'}`);
        const remaining = `${Math.max(1, Math.floor(deadline - performance.now()))}ms`;
        await query(`SELECT pg_catalog.set_config('statement_timeout', $1, true),
          pg_catalog.set_config('lock_timeout', $1, true),
          pg_catalog.set_config('idle_in_transaction_session_timeout', $1, true)`, [remaining]);
        if (verify) await verifyMarker(query);
        const result = await work(query);
        assertActive(); await query('COMMIT'); release(false); return result;
      } catch { release(true); throw failure(); }
    };
    try { return await Promise.race([run(), cancellation]); }
    finally {
      clearTimeout(timer); signal?.removeEventListener('abort', cancel); operations.delete(cancel);
    }
  };

  const verifyMarker = async query => {
    const { rows } = await query(`SELECT singleton, application, version FROM ${markerTable}`);
    if (rows.length !== 1 || rows[0].singleton !== true || rows[0].application !== APPLICATION
      || rows[0].version !== VERSION) reject();
  };
  const expectedRelations = [
    ['reference_schema', 'r'], ['reference_schema_pkey', 'i'],
    ['connection_scope', 'r'], ['connection_scope_pkey', 'i'], ['connection_scope_identity', 'i'],
    ['connection_flow', 'r'], ['connection_flow_pkey', 'i'], ['connection_flow_operation', 'i'],
    ['connection_grant', 'r'], ['connection_grant_pkey', 'i'], ['connection_grant_generation', 'i'],
    ['grant_scope', 'i'], ['grant_active_scope', 'i'],
  ].sort(([a], [b]) => a.localeCompare(b));
  const relations = async query => (await query(`SELECT c.relname, c.relkind
    FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = $1 ORDER BY c.relname`, [schema])).rows;
  const columnSpecs = {
    reference_schema: [['singleton', 'bool'], ['application', 'text'], ['version', 'int4']],
    connection_scope: [['scope_key', 'text'], ['issuer', 'text'], ['provider_subject', 'text'],
      ['client_id', 'text'], ['resource', 'text'], ['app_subject', 'text'], ['scopes', 'text'], ['revision', 'uuid']],
    connection_flow: [['scope_key', 'text'], ['operation_id', 'uuid'], ['ticket', 'text'], ['phase', 'text']],
    connection_grant: [['id', 'uuid'], ['scope_key', 'text'], ['issuer', 'text'], ['consent_id', 'text'],
      ['app_subject', 'text'], ['scopes', 'text'], ['expires_at', 'int8'], ['revoked_at', 'int8', false]],
  };
  const indexSpecs = {
    reference_schema_pkey: ['reference_schema', ['singleton'], true, true, null],
    connection_scope_pkey: ['connection_scope', ['scope_key'], true, true, null],
    connection_scope_identity: ['connection_scope', ['issuer', 'provider_subject', 'client_id'], true, false, null],
    connection_flow_pkey: ['connection_flow', ['scope_key'], true, true, null],
    connection_flow_operation: ['connection_flow', ['operation_id'], true, false, null],
    connection_grant_pkey: ['connection_grant', ['id'], true, true, null],
    connection_grant_generation: ['connection_grant', ['issuer', 'consent_id'], true, false, null],
    grant_scope: ['connection_grant', ['scope_key'], false, false, null],
    grant_active_scope: ['connection_grant', ['scope_key'], true, false, '(revoked_at IS NULL)'],
  };
  const verifyShape = async query => {
    const actual = (await relations(query)).map(row => [row.relname, row.relkind])
      .sort(([a], [b]) => a.localeCompare(b));
    if (JSON.stringify(actual) !== JSON.stringify(expectedRelations)) reject();
    await verifyMarker(query);
    // A marker or matching index name alone is insufficient: losing consent
    // uniqueness, changing its key or dropping the active-grant predicate would
    // undermine the synchronization contract. Verify those physical invariants.
    const columns = (await query(`SELECT c.relname, a.attname, t.typname, a.attnotnull,
      a.attidentity, a.attgenerated, a.atthasdef, tn.nspname AS type_schema,
      c.relpersistence, c.relrowsecurity, c.relforcerowsecurity
      FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
      JOIN pg_catalog.pg_type t ON t.oid = a.atttypid
      JOIN pg_catalog.pg_namespace tn ON tn.oid = t.typnamespace
      WHERE n.nspname = $1 AND c.relkind = 'r' AND a.attnum > 0 AND NOT a.attisdropped
      ORDER BY c.relname, a.attnum`, [schema])).rows;
    const expectedColumns = Object.entries(columnSpecs).sort(([a], [b]) => a.localeCompare(b))
      .flatMap(([relation, entries]) => entries.map(([name, type, notnull = true]) => [relation, name, type, notnull]));
    const actualColumns = columns.map(row => {
      if (row.attidentity !== '' || row.attgenerated !== '' || row.atthasdef || row.type_schema !== 'pg_catalog'
        || row.relpersistence !== 'p' || row.relrowsecurity || row.relforcerowsecurity) reject();
      return [row.relname, row.attname, row.typname, row.attnotnull];
    });
    if (JSON.stringify(actualColumns) !== JSON.stringify(expectedColumns)) reject();
    const indexes = (await query(`SELECT i.relname, t.relname AS table_name, x.indisunique, x.indisprimary,
      x.indisvalid, x.indisready, x.indimmediate, am.amname,
      pg_catalog.pg_get_expr(x.indpred, x.indrelid) AS predicate,
      x.indexprs IS NULL AS plain_columns, x.indnatts = x.indnkeyatts AS keys_only,
      ARRAY(SELECT a.attname::text FROM pg_catalog.unnest(x.indkey) WITH ORDINALITY AS k(attnum, position)
        JOIN pg_catalog.pg_attribute a ON a.attrelid = x.indrelid AND a.attnum = k.attnum
        ORDER BY k.position) AS columns
      FROM pg_catalog.pg_index x JOIN pg_catalog.pg_class i ON i.oid = x.indexrelid
      JOIN pg_catalog.pg_class t ON t.oid = x.indrelid JOIN pg_catalog.pg_namespace n ON n.oid = t.relnamespace
      JOIN pg_catalog.pg_am am ON am.oid = i.relam WHERE n.nspname = $1`, [schema])).rows;
    if (indexes.length !== Object.keys(indexSpecs).length) reject();
    for (const row of indexes) {
      const expected = indexSpecs[row.relname];
      if (!expected || !row.indisvalid || !row.indisready || !row.indimmediate || row.amname !== 'btree'
        || !row.plain_columns || !row.keys_only || JSON.stringify([row.table_name, row.columns,
          row.indisunique, row.indisprimary, row.predicate]) !== JSON.stringify(expected)) reject();
    }
    const references = (await query(`SELECT c.conname, t.relname AS table_name, r.relname AS target_name,
      rn.nspname AS target_schema, c.convalidated, c.condeferrable, c.condeferred,
      c.confupdtype, c.confdeltype, c.confmatchtype,
      ARRAY(SELECT a.attname::text FROM pg_catalog.unnest(c.conkey) WITH ORDINALITY AS k(attnum, position)
        JOIN pg_catalog.pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum ORDER BY k.position) AS columns,
      ARRAY(SELECT a.attname::text FROM pg_catalog.unnest(c.confkey) WITH ORDINALITY AS k(attnum, position)
        JOIN pg_catalog.pg_attribute a ON a.attrelid = c.confrelid AND a.attnum = k.attnum ORDER BY k.position) AS target_columns
      FROM pg_catalog.pg_constraint c JOIN pg_catalog.pg_class t ON t.oid = c.conrelid
      JOIN pg_catalog.pg_namespace n ON n.oid = t.relnamespace
      JOIN pg_catalog.pg_class r ON r.oid = c.confrelid JOIN pg_catalog.pg_namespace rn ON rn.oid = r.relnamespace
      WHERE n.nspname = $1 AND c.contype = 'f'`, [schema])).rows;
    if (references.length !== 2 || new Set(references.map(row => row.table_name)).size !== 2) reject();
    for (const row of references) {
      if (!['connection_flow', 'connection_grant'].includes(row.table_name) || row.target_name !== 'connection_scope'
        || row.target_schema !== schema || !row.convalidated || row.condeferrable || row.condeferred
        || row.confupdtype !== 'a' || row.confdeltype !== 'a' || row.confmatchtype !== 's'
        || JSON.stringify(row.columns) !== '["scope_key"]' || JSON.stringify(row.target_columns) !== '["scope_key"]') reject();
    }
    const triggers = await query(`SELECT 1 FROM pg_catalog.pg_trigger g JOIN pg_catalog.pg_class t ON t.oid = g.tgrelid
      JOIN pg_catalog.pg_namespace n ON n.oid = t.relnamespace WHERE n.nspname = $1 AND NOT g.tgisinternal LIMIT 1`, [schema]);
    if (triggers.rows.length) reject();
  };
  const lock = (query, key) => query('SELECT pg_catalog.pg_advisory_xact_lock($1::integer, $2::integer)',
    lockKey(`${APPLICATION}:scope:${schema}:${key}`));
  const scope = async (query, value, create = false) => {
    const key = scopeKey(value);
    await lock(query, key);
    let row = (await query(`SELECT * FROM ${scopeTable} WHERE scope_key = $1 FOR UPDATE`, [key])).rows[0];
    if (!row && create) {
      row = (await query(`INSERT INTO ${scopeTable}
        (scope_key, issuer, provider_subject, client_id, resource, app_subject, scopes, revision)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`, [key, value.issuer, value.providerSubject,
        value.clientId, value.resource, value.appSubject, JSON.stringify(value.scopes), randomUUID()])).rows[0];
    }
    if (row && (row.issuer !== value.issuer || row.provider_subject !== value.providerSubject
      || row.client_id !== value.clientId || row.resource !== value.resource || row.app_subject !== value.appSubject
      || row.scopes !== JSON.stringify(value.scopes))) reject();
    return row;
  };
  const flow = async (query, key) => (await query(`SELECT * FROM ${flowTable} WHERE scope_key = $1`, [key])).rows[0];
  const touch = (query, key) => query(`UPDATE ${scopeTable} SET revision = $1 WHERE scope_key = $2`, [randomUUID(), key]);
  const transition = async (query, key, phase) => {
    await query(`UPDATE ${flowTable} SET phase = $1 WHERE scope_key = $2`, [phase, key]); await touch(query, key);
  };
  const matches = (row, value) => !!row && row.operation_id === value.operationId
    && JSON.stringify(ticket(JSON.parse(row.ticket))) === JSON.stringify(value);
  const activeGrant = async (query, key, time) => (await query(`SELECT * FROM ${grantTable}
    WHERE scope_key = $1 AND revoked_at IS NULL AND expires_at > $2`, [key, time])).rows[0];
  const grantValue = (row, expiresAt = storedTime(row.expires_at)) => freeze({
    authorizationId: row.id, subject: row.app_subject, scopes: storedScopes(row.scopes), expiresAt,
  });
  const usable = (row, time) => !!row && row.revoked_at === null && storedTime(row.expires_at) > time;
  const stopped = context => { if (closed || context?.signal?.aborted) reject(); };

  return Object.freeze({
    async migrate(context) {
      try {
        return await transaction(false, context, async query => {
          await query('SELECT pg_catalog.pg_advisory_xact_lock($1::integer, $2::integer)',
            lockKey(`${APPLICATION}:migration:${schema}`));
          const existing = await relations(query);
          if (existing.length) { await verifyShape(query); return true; }
          // Refuse an unrelated namespace containing functions or user-defined
          // types even if it has no tables. A dedicated empty schema is safe.
          const { rows } = await query(`SELECT EXISTS (
            SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = $1
            UNION ALL SELECT 1 FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname = $1
          ) AS occupied`, [schema]);
          if (rows[0]?.occupied !== false) reject();
          await query(`CREATE SCHEMA IF NOT EXISTS ${namespace}`);
          await query(`CREATE TABLE ${markerTable} (
            singleton BOOLEAN PRIMARY KEY CHECK (singleton), application TEXT NOT NULL, version INTEGER NOT NULL
          );
          CREATE TABLE ${scopeTable} (
            scope_key TEXT PRIMARY KEY, issuer TEXT NOT NULL, provider_subject TEXT NOT NULL,
            client_id TEXT NOT NULL, resource TEXT NOT NULL, app_subject TEXT NOT NULL,
            scopes TEXT NOT NULL, revision UUID NOT NULL,
            CONSTRAINT connection_scope_identity UNIQUE (issuer, provider_subject, client_id)
          );
          CREATE TABLE ${flowTable} (
            scope_key TEXT PRIMARY KEY REFERENCES ${scopeTable}(scope_key), operation_id UUID NOT NULL,
            ticket TEXT NOT NULL, phase TEXT NOT NULL CHECK (phase IN
              ('reset_pending','reset_dispatched','awaiting_consent','exchanging','completed','failed','blocked')),
            CONSTRAINT connection_flow_operation UNIQUE (operation_id)
          );
          CREATE TABLE ${grantTable} (
            id UUID PRIMARY KEY, scope_key TEXT NOT NULL REFERENCES ${scopeTable}(scope_key),
            issuer TEXT NOT NULL, consent_id TEXT NOT NULL, app_subject TEXT NOT NULL,
            scopes TEXT NOT NULL, expires_at BIGINT NOT NULL CHECK (expires_at > 0 AND expires_at <= ${MAX_TIME}),
            revoked_at BIGINT CHECK (revoked_at > 0 AND revoked_at <= ${MAX_TIME}),
            CONSTRAINT connection_grant_generation UNIQUE (issuer, consent_id)
          );
          CREATE INDEX grant_scope ON ${grantTable}(scope_key);
          CREATE UNIQUE INDEX grant_active_scope ON ${grantTable}(scope_key) WHERE revoked_at IS NULL`);
          await query(`INSERT INTO ${markerTable} (singleton, application, version) VALUES (true, $1, $2)`, [APPLICATION, VERSION]);
          await verifyShape(query); return true;
        }, false);
      } catch { throw new Error('Connection database schema could not be verified.'); }
    },
    async checkReady(context) {
      try { return await transaction(true, context, async query => { await verifyShape(query); return true; }); }
      catch { throw new Error('Connection database schema could not be verified.'); }
    },
    async getState(input, context) {
      stopped(context); const selected = target(input);
      return transaction(false, context, async query => {
        const row = await scope(query, selected, true); const current = await flow(query, row.scope_key);
        const grant = await activeGrant(query, row.scope_key, clock());
        return Object.freeze({ revision: row.revision, phase: current?.phase ?? null,
          attemptExpiresAt: current ? ticket(JSON.parse(current.ticket)).attemptExpiresAt : null, active: !!grant,
          ...(grant ? { authorizationId: grant.id } : {}) });
      });
    },
    async begin(input, context) {
      stopped(context); const selected = target(input); const owner = binding(input); const time = clock();
      if (!UUID.test(input.expectedRevision) || !HASH.test(input.stateHash)
        || !millis(input.attemptExpiresAt) || input.attemptExpiresAt <= time || input.attemptExpiresAt > time + ATTEMPT_MS
        || selected.approvedExpiresAt <= time || selected.approvedExpiresAt > time + APPROVAL_MS
        || input.attemptExpiresAt > selected.approvedExpiresAt) reject();
      return transaction(false, context, async query => {
        const row = await scope(query, selected); if (!row || row.revision !== input.expectedRevision) reject();
        if (input.attemptExpiresAt <= clock() || selected.approvedExpiresAt <= clock()) reject();
        const current = await flow(query, row.scope_key);
        if (current && !['completed', 'failed'].includes(current.phase)) {
          const previous = ticket(JSON.parse(current.ticket));
          if (!['reset_pending', 'awaiting_consent'].includes(current.phase) || previous.attemptExpiresAt > time) reject();
        }
        const next = { ...selected, ...owner, operationId: randomUUID(), stateHash: input.stateHash,
          attemptExpiresAt: input.attemptExpiresAt };
        await query(`UPDATE ${grantTable} SET revoked_at = $1 WHERE scope_key = $2 AND revoked_at IS NULL`, [time, row.scope_key]);
        await query(`INSERT INTO ${flowTable} (scope_key, operation_id, ticket, phase) VALUES ($1, $2, $3, 'reset_pending')
          ON CONFLICT (scope_key) DO UPDATE SET operation_id = EXCLUDED.operation_id, ticket = EXCLUDED.ticket, phase = EXCLUDED.phase`,
        [row.scope_key, next.operationId, JSON.stringify(next)]);
        await touch(query, row.scope_key); return freeze(next);
      });
    },
    async claimReset(input, context) {
      stopped(context); const saved = ticket(input);
      return transaction(false, context, async query => {
        const row = await scope(query, saved); const current = row && await flow(query, row.scope_key);
        if (!matches(current, saved) || current.phase !== 'reset_pending'
          || saved.attemptExpiresAt <= clock() || saved.approvedExpiresAt <= clock()) return false;
        await transition(query, row.scope_key, 'reset_dispatched'); return true;
      });
    },
    async completeReset(input, context) {
      stopped(context); const saved = ticket(input);
      return transaction(false, context, async query => {
        const row = await scope(query, saved); const current = row && await flow(query, row.scope_key);
        if (!matches(current, saved) || !['reset_pending', 'reset_dispatched'].includes(current.phase)
          || saved.attemptExpiresAt <= clock() || saved.approvedExpiresAt <= clock()) return false;
        await transition(query, row.scope_key, 'awaiting_consent'); return true;
      });
    },
    async fail(input, context) {
      stopped(context); const saved = ticket(input);
      return transaction(false, context, async query => {
        const row = await scope(query, saved); const current = row && await flow(query, row.scope_key);
        if (!matches(current, saved) || ['blocked', 'completed', 'failed'].includes(current.phase)) return;
        await transition(query, row.scope_key, ['reset_dispatched', 'exchanging'].includes(current.phase) ? 'blocked' : 'failed');
      });
    },
    async consume(input, context) {
      stopped(context); const selected = target(input); const owner = binding(input);
      if (!UUID.test(input.operationId) || !HASH.test(input.stateHash)) return null;
      return transaction(false, context, async query => {
        const row = await scope(query, selected); const current = row && await flow(query, row.scope_key);
        if (!current || current.operation_id !== input.operationId || current.phase !== 'awaiting_consent') return null;
        const saved = ticket(JSON.parse(current.ticket));
        if (saved.stateHash !== input.stateHash || saved.sessionId !== owner.sessionId || saved.authVersion !== owner.authVersion
          || JSON.stringify(target(saved)) !== JSON.stringify(selected)
          || saved.attemptExpiresAt <= clock() || saved.approvedExpiresAt <= clock()) return null;
        await transition(query, row.scope_key, 'exchanging'); return freeze(saved);
      });
    },
    async cancel(input, context) {
      stopped(context); const selected = target(input); const owner = binding(input);
      if (!UUID.test(input.operationId) || !HASH.test(input.stateHash)) return false;
      return transaction(false, context, async query => {
        const row = await scope(query, selected); const current = row && await flow(query, row.scope_key);
        if (!current || current.operation_id !== input.operationId || current.phase !== 'awaiting_consent') return false;
        const saved = ticket(JSON.parse(current.ticket));
        if (saved.stateHash !== input.stateHash || saved.sessionId !== owner.sessionId || saved.authVersion !== owner.authVersion
          || JSON.stringify(target(saved)) !== JSON.stringify(selected)
          || saved.attemptExpiresAt <= clock() || saved.approvedExpiresAt <= clock()) return false;
        await transition(query, row.scope_key, 'failed'); return true;
      });
    },
    async complete(input, identity, context) {
      stopped(context); const saved = ticket(input); const time = clock();
      if (!identity || identity.issuer !== saved.issuer || identity.subject !== saved.providerSubject
        || identity.clientId !== saved.clientId || identity.audience !== saved.resource
        || !opaque(identity.consentId, 128) || !millis(identity.expiresAt) || identity.expiresAt <= time
        || !saved.scopes.every(scope => canonicalScopes(identity.scopes).includes(scope))) reject();
      return transaction(false, context, async query => {
        const row = await scope(query, saved); const current = row && await flow(query, row.scope_key);
        if (!matches(current, saved) || current.phase !== 'exchanging'
          || saved.attemptExpiresAt <= clock() || saved.approvedExpiresAt <= clock() || identity.expiresAt <= clock()) reject();
        // The permanent unique constraint also closes races across different
        // provider-user/client scopes attempting to claim the same consent ID.
        const id = randomUUID();
        const result = await query(`INSERT INTO ${grantTable}
          (id, scope_key, issuer, consent_id, app_subject, scopes, expires_at, revoked_at)
          VALUES ($1, $2, $3, $4, $5, $6, $7, NULL) RETURNING *`,
        [id, row.scope_key, saved.issuer, identity.consentId, saved.appSubject,
          JSON.stringify(saved.scopes), saved.approvedExpiresAt]);
        await transition(query, row.scope_key, 'completed'); return grantValue(result.rows[0]);
      });
    },
    async resolveConsent(identity, context) {
      if (closed || context?.signal?.aborted) return null;
      try {
        if (!identity || !canonicalUrl(identity.issuer, true) || !opaque(identity.consentId, 128)
          || !opaque(identity.subject, 128) || !opaque(identity.clientId, 128) || !canonicalUrl(identity.audience)
          || !millis(identity.expiresAt) || identity.expiresAt <= clock()) return null;
        const scopes = canonicalScopes(identity.scopes);
        return await transaction(true, context, async query => {
          const row = (await query(`SELECT g.*, s.provider_subject, s.client_id, s.resource
            FROM ${grantTable} g JOIN ${scopeTable} s ON s.scope_key = g.scope_key
            WHERE g.issuer = $1 AND g.consent_id = $2`, [identity.issuer, identity.consentId])).rows[0];
          if (!usable(row, clock()) || identity.expiresAt <= clock() || row.provider_subject !== identity.subject
            || row.client_id !== identity.clientId || row.resource !== identity.audience
            || !storedScopes(row.scopes).every(scope => scopes.includes(scope))) return null;
          return grantValue(row, Math.min(storedTime(row.expires_at), identity.expiresAt));
        });
      } catch { return null; }
    },
    async revoke({ appSubject, authorizationId, expectedRevision } = {}, context) {
      stopped(context); if (!opaque(appSubject) || !UUID.test(authorizationId)
        || (expectedRevision !== undefined && !UUID.test(expectedRevision))) return false;
      return transaction(false, context, async query => {
        const found = (await query(`SELECT scope_key FROM ${grantTable} WHERE id = $1 AND app_subject = $2`,
          [authorizationId, appSubject])).rows[0];
        if (!found) return false;
        await lock(query, found.scope_key);
        const row = (await query(`SELECT * FROM ${grantTable} WHERE id = $1 AND app_subject = $2`,
          [authorizationId, appSubject])).rows[0];
        if (!row || row.revoked_at !== null) return false;
        const state = (await query(`SELECT revision FROM ${scopeTable} WHERE scope_key = $1 FOR UPDATE`, [row.scope_key])).rows[0];
        if (!state || (expectedRevision !== undefined && state.revision !== expectedRevision)) return false;
        await query(`UPDATE ${grantTable} SET revoked_at = $1 WHERE id = $2`, [clock(), authorizationId]);
        await touch(query, row.scope_key); return true;
      });
    },
    async isActive(principal, context) {
      if (closed || context?.signal?.aborted) return false;
      try {
        if (!principal || !UUID.test(principal.authorizationId) || !opaque(principal.subject)
          || !millis(principal.expiresAt) || principal.expiresAt <= clock()) return false;
        const scopes = canonicalScopes(principal.scopes);
        return await transaction(true, context, async query => {
          const row = (await query(`SELECT g.*, s.provider_subject, s.client_id, s.resource
            FROM ${grantTable} g JOIN ${scopeTable} s ON s.scope_key = g.scope_key
            WHERE g.id = $1 AND g.app_subject = $2`, [principal.authorizationId, principal.subject])).rows[0];
          return usable(row, clock()) && principal.expiresAt > clock() && scopes.every(scope => storedScopes(row.scopes).includes(scope))
            && (context?.issuer === undefined || context.issuer === row.issuer)
            && (context?.providerSubject === undefined || context.providerSubject === row.provider_subject)
            && (context?.clientId === undefined || context.clientId === row.client_id)
            && (context?.resource === undefined || context.resource === row.resource);
        });
      } catch { return false; }
    },
    async close() { if (!closed) { closed = true; for (const cancel of operations) cancel(); } },
  });
}
