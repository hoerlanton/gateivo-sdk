import assert from 'node:assert/strict';
import test from 'node:test';
import { createLoginPostgresStoreRuntime as createStore } from '../src/login-postgres-runtime.mjs';

const hash = 'a'.repeat(64);
const context = () => ({signal: new AbortController().signal});

test('login PostgreSQL store rejects unsafe configuration before touching the pool', () => {
  const pool = {connect() {throw new Error('Pool must not be reached.');}};
  for (const change of [{pool:null},{appId:''},{appId:'a\nb'},{schema:'public'}, {schema:'pg_temp'},
    {schema:'a";drop schema public'}, {timeoutMs:0}, {timeoutMs:30_001}, {now:null}]) {
    assert.throws(() => createStore({pool,appId:'example',...change}), /Login state could not be verified/);
  }
});

test('invalid hashes, claims and external identities never request a connection', async () => {
  let checkouts = 0;
  const store = createStore({appId:'example',pool:{connect() {checkouts++; throw new Error('Unexpected checkout.');}}});
  const current = context();
  const invalid = [
    () => store.beginLogin({stateHash:hash,expiresAt:Date.now()+1000,owner:'forged'},current),
    () => store.consumeLogin('invalid',current),
    () => store.resolveSession('A'.repeat(64),current),
    () => store.revokeSession('invalid',current),
    () => store.createSession({sessionHash:hash,sessionId:'session',appSubject:'alice',
      accountKey:'creation',authVersion:'v1',expiresAt:Date.now()+3_660_000},current),
    () => store.getBinding({issuer:'http://unsafe.example',appSubject:'alice',accountKey:'one'},current),
    () => store.bindAccount({issuer:'https://issuer.example',appSubject:'alice',accountKey:'one',
      externalId:'user_abcdefgh1234',providerSubject:'user_abcdefgh1234'},current),
    () => store.findBinding({issuer:'https://issuer.example',subject:'user_abcdefgh1234'},current),
    () => store.beginHandoff({externalAuthIdHash:'bad',browserNonceHash:hash,expiresAt:Date.now()+1000},current),
    () => store.consumeHandoff({externalAuthIdHash:hash,browserNonceHash:hash,expiresAt:Date.now()+1000,
      sessionId:'session',appSubject:'alice',accountKey:'one',authVersion:'v1',credential:'forged'},current),
  ];
  for (const run of invalid) await assert.rejects(run(), /Login state could not be verified/);
  assert.equal(checkouts,0);
  await store.close();
});

test('timeout destroys a late checkout and never executes SQL or closes the owned pool', async () => {
  let finish, released = [], queries = 0, ended = 0;
  const pool = {connect:() => new Promise(resolve => {finish=resolve;}),end() {ended++;}};
  const store = createStore({pool,appId:'example',timeoutMs:20});
  await assert.rejects(store.resolveSession(hash,context()), /Login state could not be verified/);
  finish({query() {queries++; return Promise.resolve({rows:[]});},release(destroy) {released.push(destroy);}});
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(released,[true]);
  assert.equal(queries,0);
  await store.close();
  assert.equal(ended,0);
});

test('abort or close during checkout cancels the operation and destroys the eventual client', async () => {
  for (const mode of ['abort','close']) {
    const controller = new AbortController();
    let finish, destroyed = 0;
    const store = createStore({appId:'example',pool:{connect:() => new Promise(resolve => {finish=resolve;})}});
    const pending = store.resolveSession(hash,{signal:controller.signal});
    const denied = assert.rejects(pending,/Login state could not be verified/);
    if (mode==='abort') controller.abort(); else await store.close();
    await denied;
    finish({query() {throw new Error('Unexpected SQL.');},release(destroy) {if (destroy) destroyed++;}});
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(destroyed,1);
    await store.close();
  }
});

test('abort during an uncancellable SQL query releases once and never commits', async () => {
  const controller = new AbortController();
  let finish;
  const queries = [], releases = [];
  const store = createStore({appId:'example',pool:{async connect() {return {
    query(sql) {queries.push(sql); return new Promise(resolve => {finish=resolve;});},
    release(destroy) {releases.push(destroy);},
  };}}});
  const pending = store.resolveSession(hash,{signal:controller.signal});
  const denied = assert.rejects(pending,/Login state could not be verified/);
  await new Promise(resolve => setImmediate(resolve));
  controller.abort();
  await denied;
  finish({rows:[]});
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(releases,[true]);
  assert.equal(queries.length,1);
  assert.equal(queries.includes('COMMIT'),false);
  await store.close();
});
