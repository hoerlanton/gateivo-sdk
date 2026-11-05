import { createHash } from 'node:crypto';

const APPLICATION = 'gateivo-login';
const VERSION = 1;
const ATTEMPT_MS = 300_000;
const SESSION_MS = 60 * 60_000;
const MAX_TIME = 8_640_000_000_000_000;
const HASH = /^[a-f0-9]{64}$/;
const hashed = value => typeof value === 'string' && HASH.test(value);
const EXTERNAL = /^gateivo:[a-f0-9]{64}$/;
const PROVIDER = /^user_[A-Za-z0-9]{8,64}$/;
const opaque = (value, maximum = 512) => typeof value === 'string' && value.length > 0
  && value.length <= maximum && /^[\x21-\x7e]+$/.test(value);
const millis = value => Number.isSafeInteger(value) && value > 0 && value <= MAX_TIME;
const failure = () => new Error('Login state could not be verified.');
const reject = () => {throw failure();};
const exact = (input, keys) => input && typeof input === 'object' && !Array.isArray(input)
  && Object.keys(input).length === keys.length && keys.every(key => Object.hasOwn(input, key));
const issuerValid = value => {
  try {return opaque(value, 2048) && new URL(value).protocol === 'https:' && new URL(value).origin === value;}
  catch {return false;}
};
const storedTime = value => {
  if (typeof value !== 'number' && (typeof value !== 'string' || !/^[1-9][0-9]{0,15}$/.test(value))) reject();
  const time = Number(value); if (!millis(time)) reject(); return time;
};
const accountFields = ['appSubject', 'accountKey', 'authVersion'];
const validAccount = value => opaque(value?.appSubject) && opaque(value?.accountKey, 256)
  && opaque(value?.authVersion, 256);
const sessionValue = row => {
  const value = {sessionId: row.session_id, appSubject: row.app_subject, accountKey: row.account_key,
    authVersion: row.auth_version, expiresAt: storedTime(row.expires_at)};
  if (!opaque(value.sessionId, 256) || !validAccount(value)) reject();
  return Object.freeze(value);
};
const bindingFields = ['issuer', 'appSubject', 'accountKey', 'externalId', 'providerSubject'];
const validBinding = value => issuerValid(value?.issuer) && opaque(value?.appSubject)
  && opaque(value?.accountKey, 256) && typeof value?.externalId === 'string' && EXTERNAL.test(value.externalId)
  && typeof value?.providerSubject === 'string' && PROVIDER.test(value.providerSubject);
const bindingValue = row => {
  const value = {issuer: row.issuer, appSubject: row.app_subject, accountKey: row.account_key,
    externalId: row.external_id, providerSubject: row.provider_subject};
  if (!validBinding(value)) reject(); return Object.freeze(value);
};
const lockKey = value => {
  const bytes = createHash('sha256').update(value).digest();
  return [bytes.readInt32BE(0), bytes.readInt32BE(4)];
};

/**
 * Private app-namespaced login/session/identity storage. No passwords, provider
 * API keys or OAuth credentials enter this interface. Session/form hashes may be
 * pruned after expiry in bounded batches; handoff IDs and immutable identity
 * bindings are retained forever so expiry, logout and recreation cannot revive
 * an external authorization request or move a provider identity to another user.
 */
export function createLoginPostgresStoreRuntime({pool, appId, schema = 'gateivo_login',
  timeoutMs = 3000, now = Date.now} = {}) {
  if (!pool || typeof pool.connect !== 'function' || !opaque(appId, 128) || typeof now !== 'function'
    || typeof schema !== 'string' || !/^[a-z][a-z0-9_]{0,62}$/.test(schema)
    || schema === 'public' || schema === 'information_schema' || schema.startsWith('pg_')
    || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30_000) reject();
  const namespace = `"${schema}"`;
  const table = name => `${namespace}."${name}"`;
  const marker = table('schema_marker');
  const forms = table('login_attempt');
  const sessions = table('browser_session');
  const bindings = table('account_binding');
  const handoffs = table('authorization_handoff');
  let closed = false;
  const operations = new Set();
  const clock = () => {const time = now(); if (!millis(time)) reject(); return time;};
  const lock = (query, key = appId) => query('SELECT pg_catalog.pg_advisory_xact_lock($1::integer,$2::integer)',
    lockKey(`${APPLICATION}:${schema}:${key}`));

  // One deadline covers checkout, locks, SQL and COMMIT. Late checkout and any
  // uncertain transaction outcome destroy the client; the caller's pool stays open.
  const transaction = async (readonly, context, work, verify = true) => {
    const signal = context?.signal;
    if (closed || signal?.aborted || (signal !== undefined && (typeof signal.addEventListener !== 'function'
      || typeof signal.removeEventListener !== 'function'))) reject();
    const deadline = performance.now() + timeoutMs;
    let client, released = false, cancelled = false, connectionFailed = false, rejectCancellation = () => {};
    const release = destroy => {
      if (!client || released) return;
      released = true; client.removeListener?.('error', connectionError);
      try {client.release(destroy);} catch { /* No driver details escape. */ }
    };
    const cancel = () => {cancelled = true; release(true); rejectCancellation(failure());};
    const connectionError = () => {connectionFailed = true; release(true); rejectCancellation(failure());};
    const active = () => {
      if (closed || cancelled || signal?.aborted || performance.now() >= deadline) {cancel(); reject();}
      if (connectionFailed) reject();
    };
    const cancellation = new Promise((_, fail) => {rejectCancellation = fail;});
    signal?.addEventListener('abort', cancel, {once: true});
    operations.add(cancel);
    const timer = setTimeout(cancel, timeoutMs);
    const run = async () => {
      try {
        active(); client = await pool.connect(); client.on?.('error', connectionError); active();
        const query = async (sql, values = []) => {
          active(); const result = await client.query(sql, values); active(); return result;
        };
        await query(`BEGIN TRANSACTION ISOLATION LEVEL READ COMMITTED, READ ${readonly ? 'ONLY' : 'WRITE'}`);
        const remaining = `${Math.max(1, Math.floor(deadline - performance.now()))}ms`;
        await query(`SELECT pg_catalog.set_config('statement_timeout',$1,true),
          pg_catalog.set_config('lock_timeout',$1,true),
          pg_catalog.set_config('idle_in_transaction_session_timeout',$1,true),
          pg_catalog.set_config('search_path','pg_catalog',true)`, [remaining]);
        if (verify) await verifyMarker(query);
        const result = await work(query);
        active(); await query('COMMIT'); release(false); return result;
      } catch {release(true); throw failure();}
    };
    try {return await Promise.race([run(), cancellation]);}
    finally {clearTimeout(timer); signal?.removeEventListener('abort', cancel); operations.delete(cancel);}
  };

  const verifyMarker = async query => {
    const {rows} = await query(`SELECT singleton,application,version FROM ${marker}`);
    if (rows.length !== 1 || rows[0].singleton !== true || rows[0].application !== APPLICATION
      || rows[0].version !== VERSION) reject();
  };
  const columnSpecs = {
    account_binding: [['app_id','text'],['issuer','text'],['app_subject','text'],['account_key','text'],
      ['external_id','text'],['provider_subject','text']],
    authorization_handoff: [['app_id','text'],['external_auth_id_hash','text'],['browser_nonce_hash','text'],
      ['created_at','int8'],['expires_at','int8'],['consumed_at','int8',false],['session_id','text',false],
      ['app_subject','text',false],['account_key','text',false],['auth_version','text',false]],
    browser_session: [['app_id','text'],['session_hash','text'],['session_id','text'],['app_subject','text'],
      ['account_key','text'],['auth_version','text'],['created_at','int8'],['expires_at','int8'],['revoked_at','int8',false]],
    login_attempt: [['app_id','text'],['state_hash','text'],['created_at','int8'],['expires_at','int8'],['consumed_at','int8',false]],
    schema_marker: [['singleton','bool'],['application','text'],['version','int4']],
  };
  const indexSpecs = {
    account_binding_pkey: ['account_binding',['app_id','issuer','app_subject','account_key'],true,true],
    binding_external: ['account_binding',['app_id','issuer','external_id'],true,false],
    binding_provider: ['account_binding',['app_id','issuer','provider_subject'],true,false],
    authorization_handoff_pkey: ['authorization_handoff',['app_id','external_auth_id_hash'],true,true],
    handoff_browser: ['authorization_handoff',['app_id','browser_nonce_hash'],true,false],
    handoff_expiry: ['authorization_handoff',['app_id','expires_at'],false,false],
    browser_session_pkey: ['browser_session',['app_id','session_hash'],true,true],
    session_identity: ['browser_session',['app_id','session_id'],true,false],
    session_expiry: ['browser_session',['app_id','expires_at'],false,false],
    login_attempt_pkey: ['login_attempt',['app_id','state_hash'],true,true],
    login_expiry: ['login_attempt',['app_id','expires_at'],false,false],
    schema_marker_pkey: ['schema_marker',['singleton'],true,true],
  };
  const relations = async query => (await query(`SELECT c.relname,c.relkind FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 ORDER BY c.relname`, [schema])).rows;
  const verifyShape = async query => {
    const expectedRelations = [...Object.keys(columnSpecs).map(name => [name,'r']),
      ...Object.keys(indexSpecs).map(name => [name,'i'])].sort(([a],[b]) => a.localeCompare(b));
    const actualRelations = (await relations(query)).map(row => [row.relname,row.relkind])
      .sort(([a],[b]) => a.localeCompare(b));
    if (JSON.stringify(actualRelations) !== JSON.stringify(expectedRelations)) reject();
    await verifyMarker(query);
    const columns = (await query(`SELECT c.relname,a.attname,t.typname,a.attnotnull,a.atthasdef,a.attidentity,a.attgenerated,
      tn.nspname AS type_schema,c.relpersistence,c.relrowsecurity,c.relforcerowsecurity
      FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid
      JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_type t ON t.oid=a.atttypid
      JOIN pg_catalog.pg_namespace tn ON tn.oid=t.typnamespace WHERE n.nspname=$1 AND c.relkind='r'
      AND a.attnum>0 AND NOT a.attisdropped ORDER BY c.relname,a.attnum`, [schema])).rows;
    const expectedColumns = Object.entries(columnSpecs).flatMap(([relation, entries]) =>
      entries.map(([name,type,notnull = true]) => [relation,name,type,notnull]));
    if (columns.length !== expectedColumns.length || columns.some((row,index) => row.atthasdef || row.attidentity !== ''
      || row.attgenerated !== '' || row.type_schema !== 'pg_catalog' || row.relpersistence !== 'p' || row.relrowsecurity
      || row.relforcerowsecurity || JSON.stringify([row.relname,row.attname,row.typname,row.attnotnull])
      !== JSON.stringify(expectedColumns[index]))) reject();
    const indexes = (await query(`SELECT i.relname,t.relname AS table_name,x.indisunique,x.indisprimary,
      x.indisvalid,x.indisready,x.indimmediate,am.amname,x.indpred IS NULL AS no_predicate,
      x.indexprs IS NULL AS no_expression,x.indnatts=x.indnkeyatts AS keys_only,
      ARRAY(SELECT a.attname::text FROM pg_catalog.unnest(x.indkey) WITH ORDINALITY k(attnum,position)
        JOIN pg_catalog.pg_attribute a ON a.attrelid=x.indrelid AND a.attnum=k.attnum ORDER BY k.position) AS columns
      FROM pg_catalog.pg_index x JOIN pg_catalog.pg_class i ON i.oid=x.indexrelid
      JOIN pg_catalog.pg_class t ON t.oid=x.indrelid JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace
      JOIN pg_catalog.pg_am am ON am.oid=i.relam WHERE n.nspname=$1`, [schema])).rows;
    if (indexes.length !== Object.keys(indexSpecs).length || indexes.some(row => !row.indisvalid || !row.indisready
      || !row.indimmediate || row.amname !== 'btree' || !row.no_predicate || !row.no_expression || !row.keys_only
      || JSON.stringify([row.table_name,row.columns,row.indisunique,row.indisprimary])
      !== JSON.stringify(indexSpecs[row.relname]))) reject();
    const constraints = (await query(`SELECT c.conname,c.contype,c.convalidated,c.condeferrable,t.relname AS table_name,
      COALESCE((pg_catalog.to_jsonb(c)->>'conenforced')::boolean,true) AS enforced,
      pg_catalog.pg_get_constraintdef(c.oid,true) AS definition
      FROM pg_catalog.pg_constraint c JOIN pg_catalog.pg_namespace n ON n.oid=c.connamespace
      JOIN pg_catalog.pg_class t ON t.oid=c.conrelid WHERE n.nspname=$1`, [schema])).rows;
    const checks = {
      schema_marker_singleton_check: ['schema_marker','CHECK (singleton)'],
      login_window: ['login_attempt','CHECK (created_at > 0 AND expires_at > created_at AND (expires_at - created_at) <= 300000)'],
      session_window: ['browser_session','CHECK (created_at > 0 AND expires_at > created_at AND (expires_at - created_at) <= 3600000)'],
      handoff_window: ['authorization_handoff','CHECK (created_at > 0 AND expires_at > created_at AND (expires_at - created_at) <= 300000)'],
      handoff_claim: ['authorization_handoff','CHECK (num_nonnulls(consumed_at, session_id, app_subject, account_key, auth_version) = 0 OR num_nonnulls(consumed_at, session_id, app_subject, account_key, auth_version) = 5)'],
    };
    const structural = constraints.filter(row => row.contype !== 'n');
    if (structural.length !== 14 || structural.some(row => !row.convalidated || row.condeferrable || !row.enforced
      || !['p','u','c'].includes(row.contype)) || Object.entries(checks).some(([name,expected]) =>
      !structural.some(row => row.conname===name && row.contype==='c'
        && JSON.stringify([row.table_name,row.definition])===JSON.stringify(expected)))) reject();
    const triggers = (await query(`SELECT 1 FROM pg_catalog.pg_trigger g JOIN pg_catalog.pg_class c ON c.oid=g.tgrelid
      JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND NOT g.tgisinternal LIMIT 1`, [schema])).rows;
    if (triggers.length) reject();
    const publicPrivileges = (await query(`SELECT 1 FROM pg_catalog.pg_namespace n
      CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) p
      WHERE n.nspname=$1 AND p.grantee=0 UNION ALL SELECT 1 FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(c.relacl,pg_catalog.acldefault('r',c.relowner))) p
      WHERE n.nspname=$1 AND c.relkind='r' AND p.grantee=0 LIMIT 1`,[schema])).rows;
    if (publicPrivileges.length) reject();
  };
  const cleanExpired = async (query, selected, key, time) => query(`DELETE FROM ${selected}
    WHERE app_id=$1 AND ${key} IN (SELECT ${key} FROM ${selected}
      WHERE app_id=$1 AND expires_at<=$2 ORDER BY expires_at LIMIT 256)`, [appId,time]);
  const copyBinding = input => {
    if (!exact(input,bindingFields) || !validBinding(input)) reject();
    return Object.freeze(Object.fromEntries(bindingFields.map(key => [key,input[key]])));
  };

  return Object.freeze({
    async migrate(context) {
      return transaction(false,context,async query => {
        await lock(query,'migration');
        if ((await relations(query)).length) {await verifyShape(query); return true;}
        const {rows} = await query(`SELECT EXISTS (
          SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=$1
          UNION ALL SELECT 1 FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname=$1
        ) AS occupied`, [schema]);
        if (rows[0]?.occupied !== false) reject();
        await query(`CREATE SCHEMA IF NOT EXISTS ${namespace}`);
        await query(`CREATE TABLE ${marker} (singleton boolean PRIMARY KEY CHECK(singleton),application text NOT NULL,version integer NOT NULL);
          CREATE TABLE ${forms} (app_id text NOT NULL,state_hash text NOT NULL,created_at bigint NOT NULL,
            expires_at bigint NOT NULL,consumed_at bigint,PRIMARY KEY(app_id,state_hash),
            CONSTRAINT login_window CHECK(created_at>0 AND expires_at>created_at AND expires_at-created_at<=${ATTEMPT_MS}));
          CREATE INDEX login_expiry ON ${forms}(app_id,expires_at);
          CREATE TABLE ${sessions} (app_id text NOT NULL,session_hash text NOT NULL,session_id text NOT NULL,
            app_subject text NOT NULL,account_key text NOT NULL,auth_version text NOT NULL,
            created_at bigint NOT NULL,expires_at bigint NOT NULL,revoked_at bigint,PRIMARY KEY(app_id,session_hash),
            CONSTRAINT session_identity UNIQUE(app_id,session_id),
            CONSTRAINT session_window CHECK(created_at>0 AND expires_at>created_at AND expires_at-created_at<=${SESSION_MS}));
          CREATE INDEX session_expiry ON ${sessions}(app_id,expires_at);
          CREATE TABLE ${bindings} (app_id text NOT NULL,issuer text NOT NULL,app_subject text NOT NULL,
            account_key text NOT NULL,external_id text NOT NULL,provider_subject text NOT NULL,
            PRIMARY KEY(app_id,issuer,app_subject,account_key),
            CONSTRAINT binding_external UNIQUE(app_id,issuer,external_id),
            CONSTRAINT binding_provider UNIQUE(app_id,issuer,provider_subject));
          CREATE TABLE ${handoffs} (app_id text NOT NULL,external_auth_id_hash text NOT NULL,browser_nonce_hash text NOT NULL,
            created_at bigint NOT NULL,expires_at bigint NOT NULL,consumed_at bigint,session_id text,
            app_subject text,account_key text,auth_version text,PRIMARY KEY(app_id,external_auth_id_hash),
            CONSTRAINT handoff_browser UNIQUE(app_id,browser_nonce_hash),
            CONSTRAINT handoff_window CHECK(created_at>0 AND expires_at>created_at AND expires_at-created_at<=${ATTEMPT_MS}),
            CONSTRAINT handoff_claim CHECK(pg_catalog.num_nonnulls(consumed_at,session_id,app_subject,account_key,auth_version)=0
              OR pg_catalog.num_nonnulls(consumed_at,session_id,app_subject,account_key,auth_version)=5));
          CREATE INDEX handoff_expiry ON ${handoffs}(app_id,expires_at)`);
        await query(`INSERT INTO ${marker} VALUES(true,$1,$2)`,[APPLICATION,VERSION]);
        await query(`REVOKE ALL ON SCHEMA ${namespace} FROM PUBLIC`);
        await query(`REVOKE ALL ON ALL TABLES IN SCHEMA ${namespace} FROM PUBLIC`);
        await verifyShape(query); return true;
      },false);
    },
    async checkReady(context) {return transaction(true,context,async query => {await verifyShape(query); return true;});},
    async beginLogin(input,context) {
      if (!exact(input,['stateHash','expiresAt']) || !hashed(input.stateHash) || !millis(input.expiresAt)) reject();
      const {stateHash,expiresAt} = input;
      const time = clock(); if (expiresAt<=time || expiresAt>time+ATTEMPT_MS) return false;
      return transaction(false,context,async query => {
        await lock(query); await cleanExpired(query,forms,'state_hash',clock());
        if (expiresAt<=clock()) return false;
        const count = (await query(`SELECT count(*)::integer AS count FROM ${forms}
          WHERE app_id=$1 AND consumed_at IS NULL AND expires_at>$2`,[appId,clock()])).rows[0]?.count;
        if (!Number.isSafeInteger(count) || count>=1000) return false;
        const inserted = await query(`INSERT INTO ${forms}(app_id,state_hash,created_at,expires_at)
          VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING RETURNING expires_at`,[appId,stateHash,time,expiresAt]);
        return inserted.rows.length===1 && expiresAt>clock();
      });
    },
    async consumeLogin(stateHash,context) {
      if (typeof stateHash!=='string' || !HASH.test(stateHash)) reject();
      return transaction(false,context,async query => {
        const time = clock();
        const result = await query(`UPDATE ${forms} SET consumed_at=$3
          WHERE app_id=$1 AND state_hash=$2 AND consumed_at IS NULL AND created_at<=$3 AND expires_at>$3
          RETURNING expires_at`,[appId,stateHash,time]);
        return result.rows.length===1 && storedTime(result.rows[0].expires_at)>clock();
      });
    },
    async createSession(input,context) {
      if (!exact(input,['sessionHash','sessionId',...accountFields,'expiresAt']) || !hashed(input.sessionHash)
        || !opaque(input.sessionId,256) || !validAccount(input) || !millis(input.expiresAt)) reject();
      const value = Object.freeze({...input});
      const time = clock(); if (value.expiresAt<=time || value.expiresAt>time+SESSION_MS) reject();
      return transaction(false,context,async query => {
        await lock(query); await cleanExpired(query,sessions,'session_hash',clock());
        if (value.expiresAt<=clock()) reject();
        const count = (await query(`SELECT count(*)::integer AS count FROM ${sessions}
          WHERE app_id=$1 AND revoked_at IS NULL AND expires_at>$2`,[appId,clock()])).rows[0]?.count;
        if (!Number.isSafeInteger(count) || count>=10000) reject();
        await query(`INSERT INTO ${sessions}(app_id,session_hash,session_id,app_subject,account_key,auth_version,created_at,expires_at)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,[appId,value.sessionHash,value.sessionId,value.appSubject,
          value.accountKey,value.authVersion,time,value.expiresAt]);
        if (value.expiresAt<=clock()) reject();
      });
    },
    async resolveSession(sessionHash,context) {
      if (typeof sessionHash!=='string' || !HASH.test(sessionHash)) reject();
      return transaction(true,context,async query => {
        const row = (await query(`SELECT * FROM ${sessions}
          WHERE app_id=$1 AND session_hash=$2 AND revoked_at IS NULL AND expires_at>$3`,[appId,sessionHash,clock()])).rows[0];
        if (!row) return null;
        const value = sessionValue(row); return value.expiresAt>clock() ? value : null;
      });
    },
    async revokeSession(sessionHash,context) {
      if (typeof sessionHash!=='string' || !HASH.test(sessionHash)) reject();
      return transaction(false,context,async query => {
        await lock(query);
        const result = await query(`UPDATE ${sessions} SET revoked_at=$3
          WHERE app_id=$1 AND session_hash=$2 AND revoked_at IS NULL AND expires_at>$3 RETURNING session_hash`,
        [appId,sessionHash,clock()]);
        return result.rows.length===1;
      });
    },
    async getBinding(input,context) {
      if (!exact(input,['issuer','appSubject','accountKey']) || !issuerValid(input.issuer)
        || !opaque(input.appSubject) || !opaque(input.accountKey,256)) reject();
      const {issuer,appSubject,accountKey} = input;
      return transaction(true,context,async query => {
        const row = (await query(`SELECT * FROM ${bindings} WHERE app_id=$1 AND issuer=$2
          AND app_subject=$3 AND account_key=$4`,[appId,issuer,appSubject,accountKey])).rows[0];
        return row ? bindingValue(row) : null;
      });
    },
    async bindAccount(input,context) {
      const value = copyBinding(input);
      return transaction(false,context,async query => {
        await lock(query);
        const existing = (await query(`SELECT * FROM ${bindings} WHERE app_id=$1 AND issuer=$2
          AND app_subject=$3 AND account_key=$4`,[appId,value.issuer,value.appSubject,value.accountKey])).rows[0];
        if (existing) {
          const found = bindingValue(existing);
          if (bindingFields.some(key => found[key]!==value[key])) reject();
          return found;
        }
        const row = (await query(`INSERT INTO ${bindings}(app_id,issuer,app_subject,account_key,external_id,provider_subject)
          VALUES($1,$2,$3,$4,$5,$6) RETURNING *`,[appId,value.issuer,value.appSubject,value.accountKey,
          value.externalId,value.providerSubject])).rows[0];
        return bindingValue(row);
      });
    },
    async findBinding(input,context) {
      if (!exact(input,['issuer','subject']) || !issuerValid(input.issuer)
        || typeof input.subject!=='string' || !EXTERNAL.test(input.subject)) reject();
      const {issuer,subject} = input;
      return transaction(true,context,async query => {
        const row = (await query(`SELECT * FROM ${bindings} WHERE app_id=$1 AND issuer=$2 AND external_id=$3`,
          [appId,issuer,subject])).rows[0];
        return row ? bindingValue(row) : null;
      });
    },
    async beginHandoff(input,context) {
      if (!exact(input,['externalAuthIdHash','browserNonceHash','expiresAt']) || !hashed(input.externalAuthIdHash)
        || !hashed(input.browserNonceHash) || !millis(input.expiresAt)) reject();
      const value = Object.freeze({...input});
      const time = clock(); if (value.expiresAt<=time || value.expiresAt>time+ATTEMPT_MS) return false;
      return transaction(false,context,async query => {
        await lock(query);
        const count = (await query(`SELECT count(*)::integer AS count FROM ${handoffs}
          WHERE app_id=$1 AND consumed_at IS NULL AND expires_at>$2`,[appId,clock()])).rows[0]?.count;
        if (!Number.isSafeInteger(count) || count>=1000 || value.expiresAt<=clock()) return false;
        // Never delete or overwrite handoff rows, even when expired or consumed.
        const result = await query(`INSERT INTO ${handoffs}(app_id,external_auth_id_hash,browser_nonce_hash,created_at,expires_at)
          VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING RETURNING expires_at`,
        [appId,value.externalAuthIdHash,value.browserNonceHash,time,value.expiresAt]);
        return result.rows.length===1 && value.expiresAt>clock();
      });
    },
    async consumeHandoff(input,context) {
      if (!exact(input,['externalAuthIdHash','browserNonceHash','expiresAt','sessionId',...accountFields])
        || !hashed(input.externalAuthIdHash) || !hashed(input.browserNonceHash)
        || !millis(input.expiresAt) || !opaque(input.sessionId,256) || !validAccount(input)) reject();
      const value = Object.freeze({...input});
      return transaction(false,context,async query => {
        await lock(query);
        const time = clock(); if (value.expiresAt<=time) return false;
        const result = await query(`UPDATE ${handoffs} h SET consumed_at=$4,session_id=$5,
          app_subject=$6,account_key=$7,auth_version=$8 WHERE h.app_id=$1 AND h.external_auth_id_hash=$2
          AND h.browser_nonce_hash=$3 AND h.consumed_at IS NULL AND h.created_at<=$4 AND h.expires_at>$4
          AND h.expires_at=$9 AND EXISTS(SELECT 1 FROM ${sessions} s WHERE s.app_id=$1 AND s.session_id=$5
            AND s.app_subject=$6 AND s.account_key=$7 AND s.auth_version=$8 AND s.revoked_at IS NULL AND s.expires_at>$4)
          RETURNING h.expires_at`,[appId,value.externalAuthIdHash,value.browserNonceHash,time,value.sessionId,
          value.appSubject,value.accountKey,value.authVersion,value.expiresAt]);
        return result.rows.length===1 && storedTime(result.rows[0].expires_at)>clock();
      });
    },
    async close() {if (!closed) {closed=true; for (const cancel of operations) cancel();}},
  });
}
