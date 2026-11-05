import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import test from 'node:test';
import { createLoginPostgresStoreRuntime as createStore } from '../src/login-postgres-runtime.mjs';

const connectionString = process.env.GATEIVO_LOGIN_TEST_DATABASE_URL;
if (connectionString) {
  const target = new URL(connectionString);
  assert.ok(['postgres:','postgresql:'].includes(target.protocol)
    && ['127.0.0.1','localhost','[::1]'].includes(target.hostname)
    && target.pathname === '/gateivo_login_test' && !target.search && !target.hash,
  'Use an explicit loopback gateivo_login_test database without URL options.');
}
const digest = () => randomBytes(32).toString('hex');
const context = () => ({signal:new AbortController().signal});
const issuer = 'https://issuer.example';
const session = (time,changes = {}) => ({sessionHash:digest(),sessionId:`session-${digest()}`,appSubject:'alice',
  accountKey:'alice-created-1',authVersion:'alice-auth-1',expiresAt:time+60_000,...changes});
const binding = (changes = {}) => ({issuer,appSubject:'alice',accountKey:'alice-created-1',
  externalId:`gateivo:${digest()}`,providerSubject:`user_${randomBytes(12).toString('hex')}`,...changes});

test('PostgreSQL login persistence, isolation and lifecycle acceptance', {
  skip:!connectionString, timeout:60_000,
},async t => {
  const {Pool} = await import('pg');
  const pool = new Pool({connectionString,max:8,connectionTimeoutMillis:1500,ssl:false});
  const stores = [], schemas = [];
  t.after(async () => {
    for (const store of stores) await store.close();
    for (const schema of schemas.reverse()) await pool.query(`DROP SCHEMA "${schema}" CASCADE`);
    await pool.end();
  });
  const make = async (appId = 'app-a',options = {}) => {
    const schema = options.schema ?? `gateivo_login_test_${randomBytes(10).toString('hex')}`;
    if (!options.schema) {
      assert.equal((await pool.query('SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname=$1',[schema])).rows.length,0);
      schemas.push(schema);
    }
    const store = createStore({pool,appId,schema,...options}); stores.push(store);
    await store.migrate(context());
    return {store,schema};
  };

  await t.test('migration is explicit, repeatable and shared across application namespaces',async () => {
    const schema = `gateivo_login_test_${randomBytes(10).toString('hex')}`;
    const store = createStore({pool,appId:'app-a',schema}); stores.push(store);
    await assert.rejects(store.checkReady(context()),/Login state could not be verified/);
    assert.equal((await pool.query('SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname=$1',[schema])).rows.length,0);
    schemas.push(schema);
    assert.equal(await store.migrate(context()),true);
    assert.equal(await store.migrate(context()),true);
    assert.equal(await store.checkReady(context()),true);
    assert.equal(await (await make('app-b',{schema})).store.checkReady(context()),true);
    const publicAcl = await pool.query(`SELECT p.grantee FROM pg_catalog.pg_namespace n
      CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) p
      WHERE n.nspname=$1 AND p.grantee=0`,[schema]);
    assert.equal(publicAcl.rows.length,0);
  });

  await t.test('login state consumes once across concurrent stores and remains app-specific',async () => {
    let now = Date.now();
    const {store,schema} = await make('app-a',{now:() => now});
    const second = (await make('app-a',{schema,now:() => now})).store;
    const other = (await make('app-b',{schema,now:() => now})).store;
    const value = {stateHash:digest(),expiresAt:now+1000};
    assert.equal(await store.beginLogin(value,context()),true);
    assert.equal(await second.beginLogin(value,context()),false);
    assert.equal(await other.beginLogin(value,context()),true);
    const claimed = await Promise.all([store.consumeLogin(value.stateHash,context()),second.consumeLogin(value.stateHash,context())]);
    assert.deepEqual(claimed.sort(),[false,true]);
    assert.equal(await other.consumeLogin(value.stateHash,context()),true);
    assert.equal(await store.consumeLogin(value.stateHash,context()),false);
    const expired = {stateHash:digest(),expiresAt:now+1000};
    assert.equal(await store.beginLogin(expired,context()),true);
    now+=1001;
    assert.equal(await store.consumeLogin(expired.stateHash,context()),false);
  });

  await t.test('sessions persist across store reopen, reject duplicates, isolate apps and revoke durably',async () => {
    let now = Date.now();
    const {store,schema} = await make('app-a',{now:() => now});
    const alice = session(now);
    await store.createSession(alice,context());
    const resolved = await store.resolveSession(alice.sessionHash,context());
    const {sessionHash,...expected} = alice;
    assert.deepEqual(resolved,expected);
    assert.equal(Object.isFrozen(resolved),true);
    await assert.rejects(store.createSession({...alice,authVersion:'changed'},context()),/Login state could not be verified/);
    await assert.rejects(store.createSession({...alice,sessionHash:digest()},context()),/Login state could not be verified/);
    const other = (await make('app-b',{schema,now:() => now})).store;
    assert.equal(await other.resolveSession(sessionHash,context()),null);
    await other.createSession(alice,context());
    assert.deepEqual(await other.resolveSession(sessionHash,context()),expected);
    await store.close();
    const reopened = (await make('app-a',{schema,now:() => now})).store;
    assert.deepEqual(await reopened.resolveSession(sessionHash,context()),expected);
    assert.equal(await reopened.revokeSession(sessionHash,context()),true);
    assert.equal(await reopened.revokeSession(sessionHash,context()),false);
    assert.equal(await reopened.resolveSession(sessionHash,context()),null);
    assert.deepEqual(await other.resolveSession(sessionHash,context()),expected);
    now=alice.expiresAt;
    assert.equal(await other.resolveSession(sessionHash,context()),null);
  });

  await t.test('identity bindings are immutable, canonical and unique for each app and issuer',async () => {
    const {store,schema} = await make();
    const alice = binding();
    const result = await store.bindAccount(alice,context());
    assert.deepEqual(result,alice);
    assert.equal(Object.isFrozen(result),true);
    assert.deepEqual(await store.bindAccount(alice,context()),alice);
    assert.deepEqual(await store.getBinding({issuer,appSubject:alice.appSubject,accountKey:alice.accountKey},context()),alice);
    assert.equal(await store.getBinding({issuer,appSubject:'alice',accountKey:'deleted-and-recreated'},context()),null);
    assert.deepEqual(await store.findBinding({issuer,subject:alice.externalId},context()),alice);
    assert.equal(await store.findBinding({issuer:'https://other.example',subject:alice.externalId},context()),null);
    await assert.rejects(store.findBinding({issuer,subject:alice.providerSubject},context()),/Login state could not be verified/);
    for (const replacement of [
      {...alice,externalId:`gateivo:${digest()}`},
      {...alice,providerSubject:'user_replacement1234'},
      {...alice,accountKey:'new-incarnation'},
      {...alice,appSubject:'bob',accountKey:'bob-created-1',externalId:`gateivo:${digest()}`},
      {...alice,appSubject:'bob',accountKey:'bob-created-1',providerSubject:'user_other12345678'},
    ]) await assert.rejects(store.bindAccount(replacement,context()),/Login state could not be verified/);
    const other = (await make('app-b',{schema})).store;
    assert.equal(await other.findBinding({issuer,subject:alice.externalId},context()),null);
    assert.deepEqual(await other.bindAccount(alice,context()),alice);
    await store.close();
    const reopened = (await make('app-a',{schema})).store;
    assert.deepEqual(await reopened.findBinding({issuer,subject:alice.externalId},context()),alice);
  });

  await t.test('handoff consumes once only for an exact live browser session; replay remains denied after reopen',async () => {
    const now = Date.now();
    const {store,schema} = await make('app-a',{now:() => now});
    const second = (await make('app-a',{schema,now:() => now})).store;
    const alice = session(now), bob = session(now,{appSubject:'bob',accountKey:'bob-created-1',authVersion:'bob-auth-1'});
    await store.createSession(alice,context()); await store.createSession(bob,context());
    const handoff = {externalAuthIdHash:digest(),browserNonceHash:digest(),expiresAt:now+5000};
    assert.equal(await store.beginHandoff(handoff,context()),true);
    assert.equal(await second.beginHandoff({...handoff,browserNonceHash:digest()},context()),false);
    const claim = {...handoff,sessionId:alice.sessionId,appSubject:'alice',accountKey:alice.accountKey,authVersion:alice.authVersion};
    for (const change of [{sessionId:'missing'}, {appSubject:'bob'}, {accountKey:'recreated'}, {authVersion:'new-password'},
      {browserNonceHash:digest()}, {expiresAt:handoff.expiresAt+1}]) {
      assert.equal(await store.consumeHandoff({...claim,...change},context()),false);
    }
    const bobClaim = {...handoff,sessionId:bob.sessionId,appSubject:'bob',accountKey:bob.accountKey,authVersion:bob.authVersion};
    const results = await Promise.all([store.consumeHandoff(claim,context()),second.consumeHandoff(bobClaim,context())]);
    assert.deepEqual(results.sort(),[false,true]);
    const row = (await pool.query(`SELECT * FROM "${schema}".authorization_handoff
      WHERE app_id=$1 AND external_auth_id_hash=$2`,['app-a',handoff.externalAuthIdHash])).rows[0];
    assert.ok([alice.sessionId,bob.sessionId].includes(row.session_id));
    const winner = row.session_id===alice.sessionId ? claim : bobClaim;
    assert.equal(row.app_subject,winner.appSubject);
    assert.equal(row.account_key,winner.accountKey);
    assert.equal(row.auth_version,winner.authVersion);
    await store.close(); await second.close();
    const reopened = (await make('app-a',{schema,now:() => now})).store;
    assert.equal(await reopened.consumeHandoff(winner,context()),false);
    assert.equal(await reopened.beginHandoff({...handoff,browserNonceHash:digest()},context()),false);
    assert.equal(await reopened.beginHandoff({...handoff,externalAuthIdHash:digest()},context()),false);
  });

  await t.test('expired handoff IDs remain reserved forever, and revoked sessions cannot claim new handoffs',async () => {
    let now = Date.now();
    const {store,schema} = await make('app-a',{now:() => now});
    const alice = session(now);
    await store.createSession(alice,context());
    const expired = {externalAuthIdHash:digest(),browserNonceHash:digest(),expiresAt:now+1000};
    assert.equal(await store.beginHandoff(expired,context()),true);
    now+=1001;
    assert.equal(await store.consumeHandoff({...expired,sessionId:alice.sessionId,appSubject:'alice',
      accountKey:alice.accountKey,authVersion:alice.authVersion},context()),false);
    assert.equal(await store.beginHandoff({...expired,browserNonceHash:digest(),expiresAt:now+1000},context()),false);
    const fresh = {externalAuthIdHash:digest(),browserNonceHash:digest(),expiresAt:now+1000};
    assert.equal(await store.beginHandoff(fresh,context()),true);
    await store.revokeSession(alice.sessionHash,context());
    assert.equal(await store.consumeHandoff({...fresh,sessionId:alice.sessionId,appSubject:'alice',
      accountKey:alice.accountKey,authVersion:alice.authVersion},context()),false);
    const other = (await make('app-b',{schema,now:() => now})).store;
    assert.equal(await other.beginHandoff({...expired,expiresAt:now+1000},context()),true);
  });

  await t.test('capacity limits apply only to active app rows and expiry cleanup is bounded',async () => {
    const now = Date.now();
    const {store,schema} = await make('app-a',{now:() => now});
    await pool.query(`INSERT INTO "${schema}".login_attempt(app_id,state_hash,created_at,expires_at)
      SELECT 'app-a',md5(i::text)||md5(i::text),$1,$2 FROM generate_series(1,1000) i`,[now,now+60_000]);
    assert.equal(await store.beginLogin({stateHash:digest(),expiresAt:now+1000},context()),false);
    const other = (await make('app-b',{schema,now:() => now})).store;
    assert.equal(await other.beginLogin({stateHash:digest(),expiresAt:now+1000},context()),true);
    await pool.query(`INSERT INTO "${schema}".browser_session
      (app_id,session_hash,session_id,app_subject,account_key,auth_version,created_at,expires_at)
      SELECT 'app-a',md5(i::text)||md5(i::text),'s-'||i,'alice','one','v1',$1,$2
      FROM generate_series(1,10000) i`,[now,now+60_000]);
    await assert.rejects(store.createSession(session(now),context()),/Login state could not be verified/);
    await pool.query(`INSERT INTO "${schema}".login_attempt(app_id,state_hash,created_at,expires_at)
      SELECT 'app-b',md5(('old-'||i)::text)||md5(('old-'||i)::text),$1,$2
      FROM generate_series(1,300) i`,[now-2000,now-1000]);
    assert.equal(await other.beginLogin({stateHash:digest(),expiresAt:now+1000},context()),true);
    assert.equal((await pool.query(`SELECT count(*)::integer AS count FROM "${schema}".login_attempt
      WHERE app_id='app-b' AND expires_at<=$1`,[now])).rows[0].count,44);
  });

  await t.test('schema marker and physical identity uniqueness tampering are refused',async () => {
    const {store,schema} = await make();
    await pool.query(`ALTER TABLE "${schema}".account_binding DROP CONSTRAINT binding_provider`);
    await assert.rejects(store.checkReady(context()),/Login state could not be verified/);
    await assert.rejects(store.migrate(context()),/Login state could not be verified/);
    const unrelated = `gateivo_login_test_${randomBytes(10).toString('hex')}`;
    schemas.push(unrelated);
    await pool.query(`CREATE SCHEMA "${unrelated}";CREATE TABLE "${unrelated}".unrelated(id integer)`);
    const foreign = createStore({pool,appId:'app-a',schema:unrelated}); stores.push(foreign);
    await assert.rejects(foreign.migrate(context()),/Login state could not be verified/);
    assert.equal((await pool.query(`SELECT * FROM "${unrelated}".unrelated`)).rows.length,0);
    const {store:marked,schema:markedSchema} = await make();
    await pool.query(`UPDATE "${markedSchema}".schema_marker SET application='other-application'`);
    await assert.rejects(marked.checkReady(context()),/Login state could not be verified/);
    await assert.rejects(marked.resolveSession(digest(),context()),/Login state could not be verified/);
  });

  await t.test('weakened claim checks and public schema/table grants are refused',async () => {
    for (const change of ['claim','schema-public','table-public']) {
      const {store,schema} = await make();
      if (change==='claim') {
        await pool.query(`ALTER TABLE "${schema}".authorization_handoff DROP CONSTRAINT handoff_claim;
          ALTER TABLE "${schema}".authorization_handoff ADD CONSTRAINT handoff_claim CHECK(consumed_at IS NULL OR true)`);
      } else if (change==='schema-public') {
        await pool.query(`GRANT USAGE ON SCHEMA "${schema}" TO PUBLIC`);
      } else {
        await pool.query(`GRANT SELECT ON "${schema}".browser_session TO PUBLIC`);
      }
      await assert.rejects(store.checkReady(context()),/Login state could not be verified/);
      await assert.rejects(store.migrate(context()),/Login state could not be verified/);
    }
  });
});
