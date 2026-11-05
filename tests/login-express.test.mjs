import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {createServer, request as httpRequest} from 'node:http';
import test from 'node:test';
import express from 'express';
import {createPasswordLoginRuntime as createPasswordLogin} from '../src/login-express-runtime.mjs';

const ORIGIN='https://publisher.example';
const LOGIN='/account/assistant/login';
const LOGOUT='/account/assistant/logout';
const SESSION='__Host-gateivo-login-session';
const ATTEMPT='__Host-gateivo-login-attempt';
const csrf=html=>/name="csrf" value="([^"]+)"/.exec(html)?.[1];
const selectedCookie=(response,name)=>(response.headers['set-cookie']??[]).find(value=>value.startsWith(name+'='))?.split(';')[0];
const tick=()=>new Promise(resolve=>setImmediate(resolve));

// This fixture supplies publisher services and an atomic in-memory LoginStore.
// HTTP/session/CSRF behavior is real; no hosted login, database or OAuth is tested.
async function fixture(t, customize=()=>{}) {
    const accounts=new Map([['alice',{appSubject:'alice',accountKey:'alice-created-once',authVersion:'revision-1',
        accountLabel:'Alice <fictional>',email:'alice@example.test',emailVerified:true,enabled:true}]]);
    const attempts=new Map(),sessions=new Map(),writes=[],revocations=[];
    let verifies=0, resolves=0, onVerify, onResolve, onCreate;
    const store={
        async beginLogin(input,{signal}){signal.throwIfAborted();attempts.set(input.stateHash,input.expiresAt);return true;},
        async consumeLogin(stateHash,{signal}){signal.throwIfAborted();const expires=attempts.get(stateHash);attempts.delete(stateHash);return expires>Date.now();},
        async createSession(input,context){if(onCreate)await onCreate(input,context);else context.signal.throwIfAborted();
            writes.push({...input});sessions.set(input.sessionHash,{...input});},
        async resolveSession(sessionHash,{signal}){signal.throwIfAborted();return sessions.get(sessionHash)??null;},
        async revokeSession(sessionHash,{signal}){signal.throwIfAborted();revocations.push(sessionHash);return sessions.delete(sessionHash);},
    };
    const options={appId:'fictional-app',publicUrl:ORIGIN,accountName:'Fictional app',secret:randomBytes(32),store,
        trustProxyHttps:true,
        async verifyCredentials(input,context){verifies++;if(onVerify)return onVerify(input,context);
            context.signal.throwIfAborted();return input.email==='alice@example.test'&&input.password==='fixture-password'
                ?accounts.get('alice'):null;},
        async resolveAccount(subject,context){resolves++;if(onResolve)return onResolve(subject,context);
            context.signal.throwIfAborted();return accounts.get(subject)??null;},
    };
    customize(options);
    let login=createPasswordLogin(options);
    const app=express();
    app.use((req,res,next)=>login.router(req,res,next));
    app.get('/account/assistant',async(req,res)=>{
        const session=await login.authenticateSession(req,{signal:AbortSignal.timeout(1000)});
        if(!session){res.status(401).json({error:'unauthorized'});return;}
        res.json(session);
    });
    const server=createServer(app);
    await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
    t.after(async()=>{await login.close();server.closeAllConnections();await new Promise(resolve=>server.close(resolve));});
    const request=(method,path,{headers={},body='',rawHeaders,onRequest}={})=>new Promise((resolve,reject)=>{
        const payload=typeof body==='string'?body:new URLSearchParams(body).toString();
        const allHeaders={host:new URL(ORIGIN).host,'x-forwarded-proto':'https',
            ...(payload?{'content-type':'application/x-www-form-urlencoded','content-length':Buffer.byteLength(payload)}:{}),...headers};
        const req=httpRequest({host:'127.0.0.1',port:server.address().port,method,path,
            headers:rawHeaders??allHeaders},response=>{
            let text='';response.setEncoding('utf8');response.on('data',chunk=>{text+=chunk;});
            response.once('end',()=>resolve({status:response.statusCode,headers:response.headers,text}));
        });
        req.once('error',reject);onRequest?.(req);req.end(payload);
    });
    const form=async()=>{const response=await request('GET',LOGIN);return {...response,csrf:csrf(response.text),cookie:selectedCookie(response,ATTEMPT)};};
    const postLogin=(opened,fields={},extra={})=>request('POST',LOGIN,{...extra,
        headers:{origin:ORIGIN,cookie:opened.cookie,...extra.headers},
        body:{email:'alice@example.test',password:'fixture-password',csrf:opened.csrf,...fields}});
    const signIn=async()=>postLogin(await form());
    return {options,request,form,postLogin,signIn,store,accounts,attempts,sessions,writes,revocations,
        get verifies(){return verifies;},get resolves(){return resolves;},
        setVerify(value){onVerify=value;},setResolve(value){onResolve=value;},setCreate(value){onCreate=value;},
        async restart(){await login.close();login=createPasswordLogin(options);},
        async close(){await login.close();},
    };
}

test('password login persists only session hashes and returns a reusable canonical browser session',async t=>{
    const f=await fixture(t);const opened=await f.form();
    assert.equal(opened.status,200);assert.match(opened.text,/autocomplete="current-password"/);
    assert.equal(f.attempts.size,1);assert.match([...f.attempts.keys()][0],/^[a-f0-9]{64}$/);
    const response=await f.postLogin(opened);
    assert.equal(response.status,303);assert.equal(response.headers.location,'/account/assistant');
    const rawCookie=selectedCookie(response,SESSION);
    assert.ok(rawCookie);assert.match(response.headers['set-cookie'].find(value=>value.startsWith(SESSION+'=')),/HttpOnly; Secure; SameSite=Lax/);
    assert.equal(f.writes.length,1);assert.match(f.writes[0].sessionHash,/^[a-f0-9]{64}$/);
    assert.ok(!JSON.stringify(f.writes).includes(rawCookie.split('=')[1]));
    assert.ok(!JSON.stringify(f.writes).includes('fixture-password'));
    const account=await f.request('GET','/account/assistant',{headers:{cookie:rawCookie}});
    assert.equal(account.status,200);assert.deepEqual(Object.keys(JSON.parse(account.text)).sort(),
        ['accountKey','accountLabel','appSubject','authVersion','expiresAt','sessionId']);
    assert.equal(JSON.parse(account.text).appSubject,'alice');
    const again=await f.request('GET',LOGIN,{headers:{cookie:rawCookie}});
    assert.equal(again.status,303);assert.equal(again.headers.location,'/account/assistant');
    assert.equal(f.verifies,1);
    await f.restart();
    assert.equal((await f.request('GET','/account/assistant',{headers:{cookie:rawCookie}})).status,200);
});

test('absent or wrong credentials fail without sessions; a consumed form cannot be replayed',async t=>{
    const f=await fixture(t);
    const missing=await f.postLogin(await f.form(),{password:''});assert.equal(missing.status,400);assert.equal(f.verifies,0);
    const opened=await f.form();const denied=await f.postLogin(opened,{password:'incorrect'});
    assert.equal(denied.status,401);assert.match(denied.text,/Sign-in was not accepted/);
    assert.equal(f.sessions.size,0);assert.equal((await f.postLogin(opened)).status,400);assert.equal(f.verifies,1);
    const fresh={csrf:csrf(denied.text),cookie:selectedCookie(denied,ATTEMPT)};
    assert.equal((await f.postLogin(fresh)).status,303);
});

test('CSRF, origin, exact fields and cookie integrity are checked before publisher verification',async t=>{
    const f=await fixture(t);const opened=await f.form();
    for(const [fields,extra,expected] of [
        [{csrf:'forged'},{},400],
        [{},{headers:{origin:'https://attacker.example'}},403],
        [{appSubject:'bob'},{},413],
        [{},{headers:{cookie:opened.cookie+'; '+opened.cookie}},400],
        [{},{headers:{cookie:opened.cookie.slice(0,-1)+'!'}},400],
    ]) {
        const response=await f.postLogin(opened,fields,extra);
        // Parameter-count overflow is an Express parse error, sanitized by the module.
        assert.equal(response.status,expected);
    }
    assert.equal(f.verifies,0);assert.equal(f.sessions.size,0);
});

test('password or account incarnation changes durably invalidate the old browser session',async t=>{
    const f=await fixture(t);const rawCookie=selectedCookie(await f.signIn(),SESSION);
    const original={...f.accounts.get('alice')};
    f.accounts.set('alice',{...original,authVersion:'revision-2'});
    assert.equal((await f.request('GET','/account/assistant',{headers:{cookie:rawCookie}})).status,401);
    assert.equal(f.sessions.size,0);
    f.accounts.set('alice',original);
    assert.equal((await f.request('GET','/account/assistant',{headers:{cookie:rawCookie}})).status,401);
    const second=selectedCookie(await f.signIn(),SESSION);
    f.accounts.set('alice',{...original,accountKey:'new-account-created-later'});
    assert.equal((await f.request('GET','/account/assistant',{headers:{cookie:second}})).status,401);
    assert.equal(f.sessions.size,0);
});

test('disabled and unverified accounts cannot sign in or retain a session',async t=>{
    const f=await fixture(t);const original={...f.accounts.get('alice')};
    const rawCookie=selectedCookie(await f.signIn(),SESSION);
    f.accounts.set('alice',{...original,enabled:false});
    assert.equal((await f.request('GET','/account/assistant',{headers:{cookie:rawCookie}})).status,401);
    assert.equal(f.sessions.size,0);assert.equal((await f.signIn()).status,401);
    f.accounts.set('alice',{...original,emailVerified:false});
    assert.equal((await f.signIn()).status,401);
});

test('publisher account contract rejects blank labels, undotted domains and non-ASCII email',async t=>{
    const f=await fixture(t);const original={...f.accounts.get('alice')};
    for(const changed of [{accountLabel:''},{accountLabel:'   '},{email:'a@b'},{email:'álîce@example.test'}]) {
        f.accounts.set('alice',{...original,...changed});
        const response=await f.signIn();
        assert.equal(response.status,401);
        assert.equal(selectedCookie(response,SESSION),undefined);
        assert.equal(f.sessions.size,0);
    }
});

test('expiry, bearer credentials, HTTPS and duplicate headers cannot authenticate browser controls',async t=>{
    const f=await fixture(t);const rawCookie=selectedCookie(await f.signIn(),SESSION);
    assert.equal((await f.request('GET','/account/assistant',{headers:{cookie:rawCookie,authorization:'Bearer mobile-token'}})).status,401);
    assert.equal((await f.request('GET',LOGIN,{headers:{authorization:'Bearer mobile-token'}})).status,403);
    assert.equal((await f.request('GET',LOGIN,{headers:{'x-forwarded-proto':'http'}})).status,403);
    assert.equal((await f.request('GET',LOGIN,{headers:{host:'attacker.example'}})).status,403);
    assert.equal((await f.request('GET',LOGIN,{rawHeaders:['Host','publisher.example','Host','attacker.example','X-Forwarded-Proto','https']})).status,403);
    const key=[...f.sessions.keys()][0];f.sessions.set(key,{...f.sessions.get(key),expiresAt:Date.now()-1});
    assert.equal((await f.request('GET','/account/assistant',{headers:{cookie:rawCookie}})).status,401);
    assert.equal((await f.request('GET',LOGIN+'?returnTo=https://attacker.example')).status,400);
    assert.equal((await f.request('GET',LOGIN+'/extra')).status,400);
    assert.equal((await f.request('POST','/agent/mcp',{headers:{cookie:rawCookie}})).status,404);
});

test('logout requires same-origin CSRF and revokes the persistent session',async t=>{
    const f=await fixture(t);const rawCookie=selectedCookie(await f.signIn(),SESSION);
    const opened=await f.request('GET',LOGOUT,{headers:{cookie:rawCookie}});
    assert.equal(opened.status,200);assert.match(opened.text,/separate approval|disconnect control/);
    assert.equal((await f.request('POST',LOGOUT,{headers:{cookie:rawCookie,origin:ORIGIN},body:{csrf:'forged'}})).status,403);
    assert.equal(f.sessions.size,1);
    const logout=await f.request('POST',LOGOUT,{headers:{cookie:rawCookie,origin:ORIGIN},body:{csrf:csrf(opened.text)}});
    assert.equal(logout.status,303);assert.equal(logout.headers.location,LOGIN);assert.equal(f.sessions.size,0);
    await f.restart();
    assert.equal((await f.request('GET','/account/assistant',{headers:{cookie:rawCookie}})).status,401);
});

test('logout during a current-account lookup prevents an already-started session read',async t=>{
    const f=await fixture(t);const rawCookie=selectedCookie(await f.signIn(),SESSION);
    const original={...f.accounts.get('alice')};
    let entered,release;const started=new Promise(resolve=>{entered=resolve;});
    const held=new Promise(resolve=>{release=resolve;});
    f.setResolve(async()=>{entered();await held;return original;});
    const pending=f.request('GET','/account/assistant',{headers:{cookie:rawCookie}});
    await started;
    for(const key of f.sessions.keys())await f.store.revokeSession(key,{signal:AbortSignal.timeout(1000)});
    release();assert.equal((await pending).status,401);
});

test('canonical account changes before and after session creation stop sign-in',async t=>{
    const f=await fixture(t);const original={...f.accounts.get('alice')};
    f.setVerify(async()=>({...original,accountKey:'wrong-incarnation'}));
    assert.equal((await f.signIn()).status,401);assert.equal(f.writes.length,0);
    f.setVerify(null);
    f.setCreate(async()=>{f.accounts.set('alice',{...original,authVersion:'rotated-during-create'});});
    const response=await f.signIn();assert.equal(response.status,401);
    assert.equal(f.writes.length,1);assert.equal(f.sessions.size,0);assert.equal(selectedCookie(response,SESSION),undefined);
});

test('a cancelled in-flight session write is cleaned up when its uncancellable store returns',async t=>{
    const f=await fixture(t);const opened=await f.form();
    let started,release;const entered=new Promise(resolve=>{started=resolve;});
    const held=new Promise(resolve=>{release=resolve;});
    f.setCreate(async()=>{started();await held;});
    let pendingRequest;
    const pending=f.postLogin(opened,{}, {onRequest:request=>{pendingRequest=request;}}).catch(()=>null);
    await entered;pendingRequest.destroy();await pending;
    // Wait for the HTTP close to reach the module before releasing the fake write.
    await tick();await tick();release();
    for(let i=0;i<20&&f.revocations.length===0;i++)await tick();
    assert.equal(f.writes.length,1);assert.equal(f.sessions.size,0);assert.equal(f.revocations.length,1);
});

test('private publisher errors are sanitized and close invalidates module access',async t=>{
    const f=await fixture(t);f.setVerify(async()=>{throw new Error('PRIVATE_PASSWORD_OR_DATABASE_ERROR');});
    const response=await f.signIn();assert.equal(response.status,503);
    assert.doesNotMatch(response.text,/PRIVATE_PASSWORD|DATABASE_ERROR|fixture-password/);
    assert.match(response.headers['content-security-policy'],/style-src 'sha256-/);
    assert.equal(response.headers['cache-control'],'no-store');
    await f.close();assert.equal((await f.request('GET',LOGIN)).status,503);
});

test('configuration validates exact origins, key sizes, lifetime and used store methods',()=>{
    const store=Object.fromEntries(['beginLogin','consumeLogin','createSession','resolveSession','revokeSession'].map(name=>[name,async()=>null]));
    const options={appId:'example',publicUrl:ORIGIN,secret:randomBytes(32),store,
        verifyCredentials:async()=>null,resolveAccount:async()=>null};
    for(const changed of [{publicUrl:'http://publisher.example'},{publicUrl:ORIGIN+'/path'},
        {secret:randomBytes(16)},{sessionLifetimeMs:3_600_001},{trustProxyHttps:'yes'},
        {store:{...store,consumeLogin:undefined}},{verifyCredentials:undefined},{resolveAccount:undefined}]) {
        assert.throws(()=>createPasswordLogin({...options,...changed}),TypeError);
    }
});
