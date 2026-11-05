import {createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, randomUUID, timingSafeEqual} from 'node:crypto';
import express from 'express';

const LOGIN = '/account/assistant/login';
const LOGOUT = '/account/assistant/logout';
const DESTINATION = '/account/assistant';
const SESSION_COOKIE = '__Host-gateivo-login-session';
const ATTEMPT_COOKIE = '__Host-gateivo-login-attempt';
const FORM_MS = 5 * 60_000;
const SESSION_MS = 60 * 60_000;
const REQUEST_MS = 5_000;
const TOKEN = /^[A-Za-z0-9_-]{43}$/;
const safe = (value, max = 512) => typeof value === 'string' && value.length > 0 && value.length <= max && /^[\x21-\x7e]+$/.test(value);
const email = value => safe(value,254) && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
const exact = (value, names) => !!value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === names.length && names.every(name => Object.hasOwn(value, name));
const token = value => typeof value === 'string' && TOKEN.test(value)
    && Buffer.from(value, 'base64url').toString('base64url') === value;
const hash = value => createHash('sha256').update(value).digest('hex');
const random = () => randomBytes(32).toString('base64url');
const equal = (left, right) => typeof left === 'string' && typeof right === 'string'
    && Buffer.byteLength(left) === Buffer.byteLength(right) && timingSafeEqual(Buffer.from(left), Buffer.from(right));
const escape = value => String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const COOKIE_OPTIONS = Object.freeze({secure:true, httpOnly:true, sameSite:'lax', path:'/'});
const STYLE = 'body{margin:0;background:#fffaf4;color:#30251f;font:17px/1.6 system-ui,sans-serif}main{box-sizing:border-box;max-width:600px;margin:7vh auto;padding:28px}header{font-size:14px;color:#75665c;border-bottom:1px solid #dfcfc2;padding-bottom:18px}h1{font-size:clamp(28px,6vw,38px);line-height:1.2;letter-spacing:-1px}form,label{display:grid;gap:10px}form{gap:22px;margin:28px 0}input{box-sizing:border-box;width:100%;min-height:48px;padding:12px;border:1px solid #cdb9a9;border-radius:9px;background:#fff;font:inherit;font-size:16px}button{min-height:48px;padding:12px 20px;border:0;border-radius:9px;background:#d85b37;color:#fff;font:inherit;font-weight:650;cursor:pointer}a{color:#a43b21}input:focus-visible,button:focus-visible,a:focus-visible{outline:3px solid #d85b37;outline-offset:3px}[role=alert]{padding:14px;border:1px solid #e7b6a5;border-radius:9px;background:#fff0e9}small,footer{color:#75665c}footer{border-top:1px solid #dfcfc2;margin-top:30px;padding-top:18px;font-size:13px}';
const STYLE_HASH = createHash('sha256').update(STYLE).digest('base64');
class Failure extends Error {constructor(status) {super('Login request could not be completed.'); this.status = status;}}
const reject = status => {throw new Failure(status);};

function cookie(request, name) {
    const raw = request.headers.cookie;
    if (typeof raw !== 'string' || raw.length > 8192) return null;
    const matches = raw.split(';').map(value => value.trim()).filter(value => value.startsWith(name+'='));
    return matches.length === 1 ? matches[0].slice(name.length+1) : null;
}
function account(value) {
    if (!value || !safe(value.appSubject) || !safe(value.accountKey,256) || !safe(value.authVersion,256)
        || typeof value.accountLabel !== 'string' || !value.accountLabel.trim() || value.accountLabel.length > 200
        || /[\u0000-\u001f\u007f-\u009f]/u.test(value.accountLabel) || !email(value.email)
        || value.emailVerified !== true || value.enabled !== true) return null;
    return Object.freeze({appSubject:value.appSubject,accountKey:value.accountKey,authVersion:value.authVersion,
        accountLabel:value.accountLabel,email:value.email,emailVerified:true,enabled:true});
}
const sameAccount = (left,right) => !!left && !!right && ['appSubject','accountKey','authVersion','email']
    .every(field => left[field] === right[field]);

/** Browser sessions are distinct from assistant access tokens and never authenticate MCP. */
export function createPasswordLoginRuntime(options) {
    if (!options || !safe(options.appId,128) || !(options.secret instanceof Uint8Array) || options.secret.length !== 32
        || typeof options.verifyCredentials !== 'function' || typeof options.resolveAccount !== 'function'
        || !options.store || !['beginLogin','consumeLogin','createSession','resolveSession','revokeSession']
            .every(method => typeof options.store[method] === 'function')) throw new TypeError('Invalid password login configuration.');
    let origin;
    try {origin = new URL(options.publicUrl);} catch {throw new TypeError('Configure an exact HTTPS application origin.');}
    if (origin.protocol !== 'https:' || origin.origin !== options.publicUrl || origin.username || origin.password
        || (options.trustProxyHttps !== undefined && typeof options.trustProxyHttps !== 'boolean')) {
        throw new TypeError('Configure an exact HTTPS application origin and proxy trust.');
    }
    const lifetime = options.sessionLifetimeMs ?? SESSION_MS;
    const cutoff = options.accessExpiresAt ?? Infinity;
    const accountName = options.accountName ?? 'your app';
    if (!Number.isSafeInteger(lifetime) || lifetime < 1 || lifetime > SESSION_MS
        || (options.accessExpiresAt !== undefined && (!Number.isSafeInteger(cutoff) || cutoff < 0 || cutoff > 8_640_000_000_000_000))
        || typeof accountName !== 'string' || !accountName.trim() || accountName.length > 100
        || /[\u0000-\u001f\u007f]/u.test(accountName)) throw new TypeError('Invalid password login lifetime or account name.');
    const publicUrl = origin.origin;
    const trustProxyHttps = options.trustProxyHttps === true;
    const {store,verifyCredentials,resolveAccount} = options;
    const domain = `${options.appId}:${publicUrl}`;
    const key = createHmac('sha256',options.secret).update(`gateivo-login-envelope-v1:${domain}`).digest();
    const csrfKey = createHmac('sha256',options.secret).update(`gateivo-login-csrf-v1:${domain}`).digest();
    const aad = Buffer.from(`${domain}:${LOGIN}`);
    const closedSignal = new AbortController();
    let closed = false;
    const trusted = request => {
        const raw = request.rawHeaders;
        if (!Array.isArray(raw)) return false;
        const copies = name => raw.filter((value,index) => index%2===0 && value.toLowerCase()===name).length;
        return copies('host') === 1 && request.headers.host === origin.host
            && ['cookie','origin','authorization','x-forwarded-proto'].every(name => copies(name) <= 1)
            && request.headers.authorization === undefined
            && (request.socket?.encrypted === true || (trustProxyHttps && request.headers['x-forwarded-proto'] === 'https'));
    };
    const bounded = async (operation,context,onLate) => {
        context.signal.throwIfAborted();
        let stop;
        const cancelled = new Promise((_,fail) => {stop=()=>fail(new Failure(503)); context.signal.addEventListener('abort',stop,{once:true});});
        const work = Promise.resolve().then(() => {context.signal.throwIfAborted();return operation();});
        if (onLate) void work.then(value => {if(context.signal.aborted)return onLate(value);}).catch(()=>{});
        try {return await Promise.race([work,cancelled]);}
        finally {context.signal.removeEventListener('abort',stop);}
    };
    const revokeIndependent = async sessionHash => {
        const controller = new AbortController();
        const timer = setTimeout(()=>controller.abort(),REQUEST_MS);
        try {await bounded(()=>store.revokeSession(sessionHash,{signal:controller.signal}),{signal:controller.signal});}
        catch { /* A never-exposed late session token cannot grant browser access. */ }
        finally {clearTimeout(timer);controller.abort();}
    };
    const authenticateSession = async (request,context) => {
        if (closed || !context?.signal || context.signal.aborted || Date.now() >= cutoff || !trusted(request)) return null;
        const raw = cookie(request,SESSION_COOKIE);
        if (!token(raw)) return null;
        const deadline = new AbortController();
        const signal = AbortSignal.any([context.signal,closedSignal.signal,deadline.signal]);
        const selected = {signal};
        const timer = setTimeout(()=>deadline.abort(),REQUEST_MS);
        const sessionHash = hash(raw);
        try {
            const found = await bounded(()=>store.resolveSession(sessionHash,selected),selected);
            if (!found || !safe(found.sessionId,256) || !safe(found.appSubject) || !safe(found.accountKey,256)
                || !safe(found.authVersion,256) || !Number.isSafeInteger(found.expiresAt)
                || found.expiresAt <= Date.now() || found.expiresAt > Math.min(Date.now()+lifetime,cutoff)) return null;
            const session = Object.freeze({sessionId:found.sessionId,appSubject:found.appSubject,
                accountKey:found.accountKey,authVersion:found.authVersion,expiresAt:found.expiresAt});
            const current = account(await bounded(()=>resolveAccount(session.appSubject,selected),selected));
            signal.throwIfAborted();
            if (!current || !sameAccount({...session,email:current.email},current)) {
                await bounded(()=>store.revokeSession(sessionHash,selected),selected);
                return null;
            }
            const fresh=await bounded(()=>store.resolveSession(sessionHash,selected),selected);
            signal.throwIfAborted();
            if(!fresh||!['sessionId','appSubject','accountKey','authVersion','expiresAt'].every(field=>fresh[field]===session[field]))return null;
            if (closed || Date.now() >= Math.min(session.expiresAt,cutoff)) return null;
            return Object.freeze({...session,accountLabel:current.accountLabel});
        } catch {return null;}
        finally {clearTimeout(timer);deadline.abort();}
    };
    const page = (title,content) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escape(title)}</title><style>${STYLE}</style></head><body><main><header>${escape(accountName)} · Assistant connections</header>${content}<footer>Signing in proves your app account. Assistant access requires a separate approval.</footer></main></body></html>`;
    const notice = (response,status) => response.status(status).type('html').send(page('Unable to continue',
        '<h1>Unable to continue</h1><p>This request could not be completed. Return to sign in and try again.</p><a href="'+LOGIN+'">Back to sign in</a>'));
    const encrypt = value => {
        const iv = randomBytes(12); const cipher = createCipheriv('aes-256-gcm',key,iv); cipher.setAAD(aad);
        const ciphertext=Buffer.concat([cipher.update(JSON.stringify(value)),cipher.final()]);
        return Buffer.concat([iv,cipher.getAuthTag(),ciphertext]).toString('base64url');
    };
    const decryptAttempt = request => {
        const raw = cookie(request,ATTEMPT_COOKIE);
        if (typeof raw !== 'string' || !/^[A-Za-z0-9_-]{64,2048}$/.test(raw)
            || Buffer.from(raw,'base64url').toString('base64url') !== raw) reject(400);
        let value;
        try {
            const bytes=Buffer.from(raw,'base64url'); const cipher=createDecipheriv('aes-256-gcm',key,bytes.subarray(0,12));
            cipher.setAAD(aad);cipher.setAuthTag(bytes.subarray(12,28));
            value=JSON.parse(Buffer.concat([cipher.update(bytes.subarray(28)),cipher.final()]).toString('utf8'));
        } catch {reject(400);}
        if (!exact(value,['nonce','csrf','expiresAt']) || !token(value.nonce) || !token(value.csrf)
            || !Number.isSafeInteger(value.expiresAt) || value.expiresAt <= Date.now()
            || value.expiresAt > Math.min(Date.now()+FORM_MS,cutoff)) reject(400);
        return value;
    };
    const signInForm = async (request,response,failed=false) => {
        const context = request[REQUEST];
        const attempt={nonce:random(),csrf:random(),expiresAt:Math.min(Date.now()+FORM_MS,cutoff)};
        if (!await bounded(()=>store.beginLogin({stateHash:hash(attempt.nonce),expiresAt:attempt.expiresAt},context),context)) reject(503);
        live(request,response);
        response.cookie(ATTEMPT_COOKIE,encrypt(attempt),{...COOKIE_OPTIONS,maxAge:attempt.expiresAt-Date.now()});
        response.set('Referrer-Policy','same-origin').status(failed?401:200).type('html').send(page('Sign in',
            `<h1>Sign in to ${escape(accountName)}</h1><p>Use your existing app account to continue.</p>`
            +(failed?'<p role="alert">Sign-in was not accepted. Check your credentials and try again.</p>':'')
            +`<form method="post" action="${LOGIN}"><input type="hidden" name="csrf" value="${attempt.csrf}">`
            +'<label>Email address<input type="email" name="email" autocomplete="username" inputmode="email" autocapitalize="none" spellcheck="false" maxlength="254" required></label>'
            +'<label>Password<input type="password" name="password" autocomplete="current-password" maxlength="1024" required></label>'
            +'<button type="submit">Sign in and continue</button></form>'));
    };
    const signature = (session,expires,nonce) => createHmac('sha256',csrfKey)
        .update(JSON.stringify([session.sessionId,session.appSubject,session.accountKey,session.authVersion,expires,nonce])).digest('base64url');
    const logoutCsrf = session => {
        const expires=Math.min(Date.now()+FORM_MS,session.expiresAt,cutoff);const nonce=random();
        return `${expires}.${nonce}.${signature(session,expires,nonce)}`;
    };
    const validLogoutCsrf = (value,session) => {
        if (typeof value !== 'string' || !/^\d{1,16}\.[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}$/.test(value)) return false;
        const [time,nonce,signed]=value.split('.');const expires=Number(time);
        return Number.isSafeInteger(expires) && expires>Date.now() && expires<=Math.min(Date.now()+FORM_MS,session.expiresAt,cutoff)
            && equal(signed,signature(session,expires,nonce));
    };
    const REQUEST=Symbol('gateivoLoginRequest');
    const live=(request,response)=>{request[REQUEST].signal.throwIfAborted();if(closed||response.destroyed||response.headersSent||Date.now()>=cutoff)reject(503);};
    const router=express.Router({caseSensitive:true,strict:true});
    const owns=path=>{try{path=decodeURIComponent(path);}catch{}return[LOGIN,LOGOUT].some(prefix=>path.toLowerCase()===prefix||path.toLowerCase().startsWith(prefix+'/'));};
    let requests=0, resetsAt=0, inFlight=0;
    router.use((request,response,next)=>{
        if(!owns(request.path)){next();return;}
        response.set({'Cache-Control':'no-store',Pragma:'no-cache','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer',
            'X-Frame-Options':'DENY','Content-Security-Policy':`default-src 'none'; style-src 'sha256-${STYLE_HASH}'; style-src-attr 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`});
        if(!trusted(request)){notice(response,403);return;}
        if(closed){notice(response,503);return;}
        if(Date.now()>=cutoff){notice(response,410);return;}
        if(request.originalUrl.includes('?')||![LOGIN,LOGOUT].includes(request.path)){notice(response,400);return;}
        if(Date.now()>=resetsAt){requests=0;resetsAt=Date.now()+60_000;}
        if(++requests>60||inFlight>=4){response.set('Retry-After','60');notice(response,429);return;}
        const controller=new AbortController();const signal=AbortSignal.any([controller.signal,closedSignal.signal]);
        request[REQUEST]={signal};inFlight++;
        let finished=false;
        const stop=()=>{if(!finished){finished=true;clearTimeout(timer);inFlight--;controller.abort();}};
        const timer=setTimeout(()=>{if(!response.headersSent)notice(response,503);stop();},REQUEST_MS);
        request.once('aborted',stop);response.once('finish',stop);response.once('close',stop);
        next();
    });
    const guarded=work=>(request,response,next)=>{Promise.resolve().then(()=>work(request,response)).catch(next);};
    const post=(request,response,next)=>{
        if(request.headers.origin!==publicUrl||(request.headers['sec-fetch-site']!==undefined&&request.headers['sec-fetch-site']!=='same-origin')){notice(response,403);return;}
        if(!request.is('application/x-www-form-urlencoded')){notice(response,415);return;}next();
    };
    const parse=()=>{
        const parser=express.urlencoded({extended:false,inflate:false,limit:'8kb',parameterLimit:3});
        return(request,response,next)=>parser(request,response,error=>next(error?new Failure(error.status===413?413:400):undefined));
    };
    const bodyless=request=>request.headers['transfer-encoding']===undefined
        &&(request.headers['content-length']===undefined||request.headers['content-length']==='0');
    router.get(LOGIN,guarded(async(request,response)=>{
        if(!bodyless(request)||(request.headers.origin!==undefined&&request.headers.origin!==publicUrl))reject(400);
        const session=await authenticateSession(request,request[REQUEST]);live(request,response);
        if(session){response.redirect(303,DESTINATION);return;}
        await signInForm(request,response);
    }));
    router.post(LOGIN,post,parse(),guarded(async(request,response)=>{
        const started=decryptAttempt(request);const context=request[REQUEST];
        if(!exact(request.body,['email','password','csrf'])||!token(request.body.csrf)||!equal(request.body.csrf,started.csrf)
            ||!email(request.body.email)
            ||typeof request.body.password!=='string'||!request.body.password.length||Buffer.byteLength(request.body.password)>1024
            ||request.body.password.includes('\0'))reject(400);
        if(!await bounded(()=>store.consumeLogin(hash(started.nonce),context),context))reject(400);
        live(request,response);
        const verified=account(await bounded(()=>verifyCredentials({email:request.body.email,password:request.body.password},context),context));
        live(request,response);
        if(!verified){await signInForm(request,response,true);return;}
        const current=account(await bounded(()=>resolveAccount(verified.appSubject,context),context));
        live(request,response);
        if(!sameAccount(verified,current)){await signInForm(request,response,true);return;}
        response.clearCookie(ATTEMPT_COOKIE,COOKIE_OPTIONS);
        const raw=random();const sessionHash=hash(raw);const expiresAt=Math.min(Date.now()+lifetime,cutoff);
        const session={sessionHash,sessionId:randomUUID(),appSubject:current.appSubject,accountKey:current.accountKey,
            authVersion:current.authVersion,expiresAt};
        let created=false;
        try {
            await bounded(()=>store.createSession(session,context),context,()=>revokeIndependent(sessionHash));created=true;
            live(request,response);
            const after=account(await bounded(()=>resolveAccount(current.appSubject,context),context));
            live(request,response);if(!sameAccount(current,after))reject(401);
            const previous=cookie(request,SESSION_COOKIE);
            if(token(previous))await bounded(()=>store.revokeSession(hash(previous),context),context);
            live(request,response);
            response.cookie(SESSION_COOKIE,raw,{...COOKIE_OPTIONS,maxAge:expiresAt-Date.now()});
            response.redirect(303,DESTINATION);
        } catch(error) {if(created)await revokeIndependent(sessionHash);throw error;}
    }));
    router.get(LOGOUT,guarded(async(request,response)=>{
        if(!bodyless(request)||(request.headers.origin!==undefined&&request.headers.origin!==publicUrl))reject(400);
        const session=await authenticateSession(request,request[REQUEST]);live(request,response);
        if(!session){response.redirect(303,LOGIN);return;}
        response.set('Referrer-Policy','same-origin').type('html').send(page('Sign out','<h1>Sign out</h1><p>End your app browser session. Existing assistant approvals have their own disconnect control.</p>'
            +`<form method="post" action="${LOGOUT}"><input type="hidden" name="csrf" value="${logoutCsrf(session)}"><button type="submit">Sign out</button></form>`));
    }));
    router.post(LOGOUT,post,parse(),guarded(async(request,response)=>{
        const context=request[REQUEST];const session=await authenticateSession(request,context);live(request,response);
        if(!session||!exact(request.body,['csrf'])||!validLogoutCsrf(request.body.csrf,session))reject(403);
        const raw=cookie(request,SESSION_COOKIE);
        if(!await bounded(()=>store.revokeSession(hash(raw),context),context))reject(401);
        live(request,response);response.clearCookie(SESSION_COOKIE,COOKIE_OPTIONS);response.clearCookie(ATTEMPT_COOKIE,COOKIE_OPTIONS);
        response.redirect(303,LOGIN);
    }));
    router.use((request,response,next)=>{if(owns(request.path))notice(response,404);else next();});
    router.use((error,request,response,next)=>{
        if(!owns(request.path)){next(error);return;}
        if(!response.headersSent)notice(response,error instanceof Failure?error.status:503);else response.destroy();
    });
    return Object.freeze({router,authenticateSession,async close(){closed=true;closedSignal.abort();}});
}
