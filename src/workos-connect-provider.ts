import { AccessError } from './types.js';
import { configuredOAuthUrl, oauthScopes } from './oauth-resource.js';
import { createWorkOSConnectVerifier, type VerifiedWorkOSConnectIdentity,
  type WorkOSConnectTokenSubjectResolver } from './workos-connect.js';

export interface WorkOSConnectProviderOptions {
  apiKey: string;
  issuer: string;
  clientId: string;
  applicationId: string;
  resource: string;
  redirectUri: string;
  accessTokenType: 'JWT' | 'at+jwt' | null;
  /** Same trusted signed-subject mapping used by the resource verifier. No approval is created. */
  resolveTokenSubject?: WorkOSConnectTokenSubjectResolver;
  /** App-specific minimum scopes. OpenID/offline_access are added for the Connect flow. */
  requiredScopes: readonly string[];
}

export interface WorkOSConnectProvider {
  authorizationUrl(input: { state: string; codeChallenge: string }): string;
  resetAuthorization(providerSubject: string, context: {
    signal: AbortSignal;
    /** Durably claim this reset before the one provider mutation. Failure prevents DELETE. */
    beforeDelete: () => Promise<void>;
  }): Promise<void>;
  exchangeCode(input: { code: string; codeVerifier: string; expectedUserId: string },
    context: { signal: AbortSignal }): Promise<VerifiedWorkOSConnectIdentity>;
}

const API_ORIGIN = 'https://api.workos.com';
const OPERATION_TIMEOUT_MS = 8_000;
const MAX_RESPONSE_BYTES = 128 * 1024;
const PAGE_SIZE = 100;
const MAX_PAGES = 5;
const USER_ID = /^user_[A-Za-z0-9]{8,64}$/;
const CLIENT_ID = /^client_[A-Za-z0-9]{8,64}$/;
const APPLICATION_ID = /^connect_app_[A-Za-z0-9]{8,64}$/;
const opaque = (value: unknown, min: number, max: number): value is string => typeof value === 'string'
  && value.length >= min && value.length <= max && /^[\x21-\x7e]+$/.test(value);
const record = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);

function validateOptions(options: WorkOSConnectProviderOptions): void {
  try {
    if (!options || !opaque(options.apiKey, 16, 512)
      || !CLIENT_ID.test(options.clientId) || !APPLICATION_ID.test(options.applicationId)
      || (options.resolveTokenSubject !== undefined && typeof options.resolveTokenSubject !== 'function')
      || ![null, 'JWT', 'at+jwt'].includes(options.accessTokenType)) throw new Error();
    const issuer = configuredOAuthUrl(options.issuer);
    if (issuer.protocol !== 'https:' || issuer.origin !== options.issuer) throw new Error();
    if (oauthScopes(options.requiredScopes).length === 0) throw new Error();
    const resource = configuredOAuthUrl(options.resource);
    const callback = configuredOAuthUrl(options.redirectUri);
    for (const [url, original] of [[resource, options.resource], [callback, options.redirectUri]] as const) {
      if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash
        || url.href !== original) throw new Error();
    }
    if (resource.origin !== callback.origin) throw new Error();
  } catch { throw new Error('Invalid WorkOS Connect provider configuration.'); }
}

/**
 * WorkOS Connect consent onboarding. Browser AuthKit sessions use a different provider.
 * The only test seam is transport; endpoints, identity checks and deadlines cannot be
 * changed by an HTTP request. Credentials never leave their respective pinned origin.
 *
 * DELETE is scoped to a user and application, not a consent generation. The caller
 * must serialize reset/reconsent durably, and must not retry an uncertain deletion
 * after a replacement has been approved. This adapter performs no automatic retries.
 * https://workos.com/docs/reference/authkit/user
 */
export function createWorkOSConnectProvider(options: WorkOSConnectProviderOptions,
  dependencies: { fetch?: typeof fetch } = {}): WorkOSConnectProvider {
  validateOptions(options);
  if (dependencies.fetch !== undefined && typeof dependencies.fetch !== 'function') {
    throw new Error('Invalid WorkOS Connect provider configuration.');
  }
  // Copy configuration so later caller mutation cannot change a credential destination.
  const { apiKey, issuer, clientId, applicationId, resource, redirectUri, accessTokenType, resolveTokenSubject } = options;
  const requiredScopes = oauthScopes(options.requiredScopes);
  const requestedScopes = oauthScopes(['openid', 'offline_access', ...requiredScopes]);
  const transport = dependencies.fetch ?? globalThis.fetch;

  async function operation<T>(caller: AbortSignal, run: (signal: AbortSignal) => Promise<T>): Promise<T> {
    if (caller.aborted) throw new AccessError('TIMEOUT');
    const controller = new AbortController();
    const abort = () => controller.abort();
    caller.addEventListener('abort', abort, { once: true });
    const timer = setTimeout(abort, OPERATION_TIMEOUT_MS);
    let removeAbort = () => {};
    const interrupted = new Promise<never>((_, reject) => {
      const stop = () => reject(new AccessError('TIMEOUT'));
      controller.signal.addEventListener('abort', stop, { once: true });
      removeAbort = () => controller.signal.removeEventListener('abort', stop);
    });
    if (caller.aborted) abort();
    try {
      return await Promise.race([run(controller.signal), interrupted]);
    } catch (error) {
      if (controller.signal.aborted) throw new AccessError('TIMEOUT');
      if (error instanceof AccessError) throw new AccessError(error.code);
      // WorkOS bodies, codes, tokens, credentials and callback details are never exposed.
      throw new AccessError('UNAVAILABLE');
    } finally {
      clearTimeout(timer); caller.removeEventListener('abort', abort); removeAbort(); controller.abort();
    }
  }

  async function boundedFetch(url: URL, init: RequestInit, signal: AbortSignal): Promise<Response> {
    signal.throwIfAborted();
    const response = await transport(url, { ...init, signal, redirect: 'error', credentials: 'omit' });
    if (signal.aborted) void response.body?.cancel().catch(() => undefined);
    signal.throwIfAborted();
    if (!response.body) return response;
    const reader = response.body.getReader();
    const cancel = () => { void reader.cancel().catch(() => undefined); };
    signal.addEventListener('abort', cancel, { once: true });
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
      while (true) {
        signal.throwIfAborted();
        const next = await reader.read();
        signal.throwIfAborted();
        if (next.done) break;
        size += next.value.byteLength;
        if (size > MAX_RESPONSE_BYTES) throw new AccessError('UNAVAILABLE');
        chunks.push(next.value);
      }
      return new Response(Buffer.concat(chunks), { status: response.status, headers: response.headers });
    } finally {
      signal.removeEventListener('abort', cancel); cancel(); reader.releaseLock();
    }
  }

  async function management(path: string, signal: AbortSignal, method: 'GET' | 'DELETE' = 'GET',
    after?: string): Promise<unknown> {
    const url = new URL(path, API_ORIGIN);
    if (url.origin !== API_ORIGIN || url.username || url.password || url.search || url.hash) throw new AccessError('UNAVAILABLE');
    if (method === 'GET' && path.endsWith('/authorized_applications')) {
      url.searchParams.set('limit', String(PAGE_SIZE));
      if (after !== undefined) url.searchParams.set('after', after);
    }
    const response = await boundedFetch(url, {
      method, headers: { Authorization: `Bearer ${apiKey}`, Accept: 'application/json' },
    }, signal);
    // A 202 is not definitive deletion; 404 and provider failures remain uncertain.
    if (method === 'DELETE') {
      if (response.status !== 200 && response.status !== 204) throw new AccessError('UNAVAILABLE');
      return;
    }
    if (response.status !== 200) throw new AccessError('UNAVAILABLE');
    return response.json();
  }

  async function hasAuthorization(subject: string, signal: AbortSignal): Promise<boolean> {
    const path = `/user_management/users/${subject}/authorized_applications`;
    let after: string | undefined;
    let matching = 0;
    const cursors = new Set<string>();
    const entries = new Set<string>();
    for (let page = 0; page < MAX_PAGES; page++) {
      const result = await management(path, signal, 'GET', after);
      if (!record(result) || !Array.isArray(result.data)
        || result.data.length > PAGE_SIZE || !record(result.list_metadata)) throw new AccessError('UNAVAILABLE');
      const next = result.list_metadata.after;
      if (next !== null && !opaque(next, 1, 256)) throw new AccessError('UNAVAILABLE');
      for (const entry of result.data) {
        if (!record(entry) || !opaque(entry.id, 1, 256)
          || entries.has(entry.id) || !record(entry.application)
          || !opaque(entry.application.id, 1, 128)
          || typeof entry.application.client_id !== 'string' || !CLIENT_ID.test(entry.application.client_id)) {
          throw new AccessError('UNAVAILABLE');
        }
        entries.add(entry.id);
        const idMatch = entry.application.id === applicationId;
        const clientMatch = entry.application.client_id === clientId;
        if (idMatch !== clientMatch) throw new AccessError('UNAVAILABLE');
        if (idMatch && ++matching > 1) throw new AccessError('UNAVAILABLE');
      }
      if (result.data.length === 0 && next !== null) throw new AccessError('UNAVAILABLE');
      if (next === null) return matching === 1;
      if (cursors.has(next)) throw new AccessError('UNAVAILABLE');
      cursors.add(next); after = next;
    }
    throw new AccessError('UNAVAILABLE');
  }

  return Object.freeze<WorkOSConnectProvider>({
    authorizationUrl({ state, codeChallenge }) {
      if (typeof state !== 'string' || !/^[A-Za-z0-9_-]{32,128}$/.test(state)
        || typeof codeChallenge !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(codeChallenge)) {
        throw new AccessError('INVALID_ARGUMENT');
      }
      const url = new URL('/oauth2/authorize', issuer);
      url.search = new URLSearchParams({ client_id: clientId, redirect_uri: redirectUri, response_type: 'code',
        scope: requestedScopes.join(' '), resource, state, code_challenge: codeChallenge,
        code_challenge_method: 'S256' }).toString();
      return url.href;
    },

    async resetAuthorization(providerSubject, { signal, beforeDelete }) {
      if (typeof providerSubject !== 'string' || !USER_ID.test(providerSubject) || typeof beforeDelete !== 'function') {
        throw new AccessError('INVALID_ARGUMENT');
      }
      await operation(signal, async (activeSignal) => {
        const app = await management(`/connect/applications/${clientId}`, activeSignal);
        if (!record(app) || app.id !== applicationId
          || app.client_id !== clientId) throw new AccessError('UNAVAILABLE');
        if (!await hasAuthorization(providerSubject, activeSignal)) return;
        activeSignal.throwIfAborted();
        await beforeDelete();
        // A slow durable claim must never cause a delayed DELETE after this operation expired.
        activeSignal.throwIfAborted();
        await management(`/user_management/users/${providerSubject}/authorized_applications/${applicationId}`, activeSignal, 'DELETE');
        activeSignal.throwIfAborted();
        if (await hasAuthorization(providerSubject, activeSignal)) throw new AccessError('UNAVAILABLE');
      });
    },

    async exchangeCode({ code, codeVerifier, expectedUserId }, { signal }) {
      if (!opaque(code, 8, 4096) || typeof codeVerifier !== 'string' || !/^[A-Za-z0-9._~-]{43,128}$/.test(codeVerifier)
        || typeof expectedUserId !== 'string' || !USER_ID.test(expectedUserId)) throw new AccessError('INVALID_ARGUMENT');
      return operation(signal, async (activeSignal) => {
        const response = await boundedFetch(new URL('/oauth2/token', issuer), {
          method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
          body: new URLSearchParams({ grant_type: 'authorization_code', client_id: clientId, code,
            code_verifier: codeVerifier, redirect_uri: redirectUri, resource }),
        }, activeSignal);
        if (response.status !== 200) throw new AccessError([400, 401, 403].includes(response.status) ? 'UNAUTHENTICATED' : 'UNAVAILABLE');
        let tokens: unknown = await response.json();
        try {
          if (!record(tokens) || !opaque(tokens.access_token, 32, 8192)
            || typeof tokens.token_type !== 'string' || tokens.token_type.toLowerCase() !== 'bearer') {
            throw new AccessError('UNAUTHENTICATED');
          }
          let identity: VerifiedWorkOSConnectIdentity | undefined;
          const verify = createWorkOSConnectVerifier({
            appId: 'gateivo-connect-onboarding', issuer, clientId, resource, accessTokenType,
            resolveTokenSubject,
            timeoutMs: OPERATION_TIMEOUT_MS,
            // Capture is reached only after the existing verifier checks signature and claims.
            // It cannot resolve or approve a grant, and no unverified identity is returned.
            resolveConsent: async (verified) => { identity = verified; return null; },
          }, { fetch: async (input, init) => {
            const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
            if (url.href !== `${issuer}/oauth2/jwks`) throw new AccessError('UNAVAILABLE');
            return boundedFetch(url, { method: 'GET', headers: { Accept: 'application/json' } },
              init?.signal ? AbortSignal.any([activeSignal, init.signal]) : activeSignal);
          } });
          await verify(tokens.access_token, { audience: resource, signal: activeSignal });
          activeSignal.throwIfAborted();
          if (!identity || identity.subject !== expectedUserId || identity.expiresAt <= Date.now()
            || requiredScopes.some(scope => !identity!.scopes.includes(scope))) {
            throw new AccessError('UNAUTHENTICATED');
          }
          return identity;
        } finally {
          // No access, refresh or ID token is stored, returned, logged or sent to management APIs.
          tokens = undefined;
        }
      });
    },
  });
}
