import { createRemoteJWKSet, customFetch, jwtVerify } from 'jose';
import type { TokenVerifierContext } from './http.js';
import type { ActiveOAuthGrant } from './oauth-jwt.js';
import { configuredOAuthUrl, oauthScopes } from './oauth-resource.js';
import { AccessError, type Principal } from './types.js';

/** Verified access-token identity with a canonical WorkOS user_ subject. */
export interface VerifiedWorkOSConnectIdentity {
  readonly issuer: string;
  readonly subject: string;
  readonly clientId: string;
  readonly audience: string;
  readonly scopes: readonly string[];
  /** Unix milliseconds. */
  readonly expiresAt: number;
  /** Immutable WorkOS authorization generation. Revoked IDs must stay denied forever. */
  readonly consentId: string;
  readonly tokenId: string;
}

/** Signed subject and pinned context, after access-token verification; not local approval. */
export interface VerifiedWorkOSConnectTokenSubject {
  readonly issuer: string;
  readonly clientId: string;
  readonly audience: string;
  /** Original signed sub, bounded to 512 printable ASCII characters. */
  readonly subject: string;
}

/** Resolve an existing immutable binding only; never create identities or consent here. */
export type WorkOSConnectTokenSubjectResolver = (
  identity: VerifiedWorkOSConnectTokenSubject,
  context: { signal: AbortSignal },
) => Promise<string | null>;

export interface WorkOSConnectVerifierOptions {
  appId: string;
  /** Exact configured AuthKit HTTPS origin, without a trailing slash. Not the browser-session issuer. */
  issuer: string;
  /** One statically registered, third-party OAuth client. */
  clientId: string;
  resource: string;
  /** Required inspected profile: null means the protected header must omit typ. No fallback. */
  accessTokenType: 'JWT' | 'at+jwt' | null;
  /**
   * Explicit application mapping of EVERY verified signed sub to a known canonical
   * WorkOS user_ ID. Return null for unknown, disabled or mismatched bindings. Called
   * only after signature and token-profile checks, within the verification deadline.
   * Without this callback, only native user_ subjects are accepted. Never use this
   * callback to decode tokens, infer identity from email, or create local approval.
   */
  resolveTokenSubject?: WorkOSConnectTokenSubjectResolver;
  maxTokenLifetimeSeconds?: number;
  timeoutMs?: number;
  jwksCooldownMs?: number;
  jwksCacheMaxAgeMs?: number;
  /**
   * Required on every request. Resolve ONLY the exact, previously approved provider
   * consent generation, checking account status and durable revocation. Unknown consent
   * IDs must remain denied; never create approval or select the latest active grant here.
   */
  resolveConsent: (identity: VerifiedWorkOSConnectIdentity, context: { signal: AbortSignal }) => Promise<ActiveOAuthGrant | null>;
}

const USER_ID = /^user_[A-Za-z0-9]{8,64}$/;
const CLIENT_ID = /^client_[A-Za-z0-9]{8,64}$/;
const CONSENT_ID = /^app_consent_[A-Za-z0-9]{8,64}$/;
const identifier = (value: unknown, max = 128): value is string => typeof value === 'string'
  && value.length > 0 && value.length <= max && /^[\x21-\x7e]+$/.test(value);

function limit(value: number, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError('Invalid WorkOS Connect limit.');
  }
  return value;
}

/**
 * Explicit WorkOS Connect user-access-token profile, separate from both the RFC 9068
 * verifier and AuthKit browser authentication. This opt-in factory does not issue tokens.
 * https://workos.com/docs/authkit/connect/token-claims
 * Verify issuance, refresh and reconnect against your configured provider before rollout.
 * The optional fetch transport is a code-level test seam, never request configuration.
 */
export function createWorkOSConnectVerifier(
  options: WorkOSConnectVerifierOptions,
  dependencies: { fetch?: typeof fetch } = {},
) {
  const { appId, issuer, clientId, resource, accessTokenType, resolveTokenSubject, resolveConsent } = options;
  const issuerUrl = configuredOAuthUrl(issuer);
  const resourceUrl = configuredOAuthUrl(resource);
  if (!identifier(appId) || !CLIENT_ID.test(clientId) || typeof resolveConsent !== 'function'
    || (resolveTokenSubject !== undefined && typeof resolveTokenSubject !== 'function')
    || ![null, 'JWT', 'at+jwt'].includes(accessTokenType)
    || issuerUrl.protocol !== 'https:' || issuerUrl.origin !== issuer
    || resourceUrl.protocol !== 'https:' || resourceUrl.href !== resource) {
    throw new TypeError('Invalid WorkOS Connect configuration.');
  }
  const timeout = limit(options.timeoutMs ?? 2500, 1, 30000);
  const lifetime = limit(options.maxTokenLifetimeSeconds ?? 3600, 1, 86400);
  const cooldown = limit(options.jwksCooldownMs ?? 30000, 0, 300000);
  const cacheAge = limit(options.jwksCacheMaxAgeMs ?? 300000, 1, 3600000);
  const transport = dependencies.fetch ?? globalThis.fetch;
  const jwksUrl = new URL('/oauth2/jwks', issuerUrl);
  const keys = createRemoteJWKSet(jwksUrl, {
    timeoutDuration: timeout, cooldownDuration: cooldown, cacheMaxAge: cacheAge,
    [customFetch]: async (url, init) => {
      if (url !== jwksUrl.href) throw new Error('Unexpected signing key destination.');
      // This public-key fetch never receives the assistant bearer, API key or app cookies.
      const response = await transport(url, {
        method: 'GET', headers: { accept: 'application/json' },
        signal: init.signal, redirect: 'manual', credentials: 'omit',
      });
      if (response.status !== 200 || !response.body) {
        void response.body?.cancel().catch(() => undefined);
        throw new Error('Signing keys unavailable.');
      }
      const reader = response.body.getReader();
      const chunks: Uint8Array[] = [];
      let size = 0;
      const cancelRead = () => { void reader.cancel().catch(() => undefined); };
      init.signal?.addEventListener('abort', cancelRead, { once: true });
      try {
        while (true) {
          init.signal?.throwIfAborted();
          const next = await reader.read();
          init.signal?.throwIfAborted();
          if (next.done) break;
          size += next.value.byteLength;
          if (size > 128 * 1024) throw new Error('Signing key response exceeds limit.');
          chunks.push(next.value);
        }
        const body = Buffer.concat(chunks);
        const parsed: unknown = JSON.parse(body.toString('utf8'));
        if (!parsed || typeof parsed !== 'object' || !('keys' in parsed)
          || !Array.isArray(parsed.keys) || parsed.keys.length < 1 || parsed.keys.length > 32) {
          throw new Error('Invalid signing key set.');
        }
        return new Response(body, { status: 200, headers: { 'content-type': 'application/json' } });
      } finally {
        init.signal?.removeEventListener('abort', cancelRead);
        cancelRead();
        reader.releaseLock();
      }
    },
  });

  return async (token: string, context: TokenVerifierContext): Promise<Principal | null> => {
    if (context.signal.aborted) throw new AccessError('TIMEOUT');
    if (context.audience !== resource || typeof token !== 'string' || token.length > 8192
      || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)) return null;
    const controller = new AbortController();
    const stop = () => controller.abort();
    context.signal.addEventListener('abort', stop, { once: true });
    let removeAbort = () => {};
    const cancelled = new Promise<never>((_, reject) => {
      const aborted = () => reject(new AccessError('TIMEOUT'));
      controller.signal.addEventListener('abort', aborted, { once: true });
      removeAbort = () => controller.signal.removeEventListener('abort', aborted);
    });
    const timer = setTimeout(stop, timeout);
    if (context.signal.aborted) stop();
    const work = async (): Promise<Principal | null> => {
      const { payload, protectedHeader } = await jwtVerify(token, keys, {
        issuer, audience: resource, algorithms: ['RS256'], clockTolerance: 0,
        requiredClaims: ['iss', 'aud', 'sub', 'client_id', 'sid', 'jti', 'iat', 'exp', 'scope'],
      });
      if (controller.signal.aborted) throw new AccessError('TIMEOUT');
      const nowSeconds = Math.floor(Date.now() / 1000);
      if (protectedHeader.typ !== (accessTokenType ?? undefined) || !identifier(protectedHeader.kid)
        || payload.aud !== resource || payload.client_id !== clientId
        || !identifier(payload.sub, 512) || (!resolveTokenSubject && !USER_ID.test(payload.sub))
        || typeof payload.sid !== 'string' || !CONSENT_ID.test(payload.sid)
        || !identifier(payload.jti) || payload.act !== undefined || payload.impersonator !== undefined
        || !Number.isSafeInteger(payload.iat) || !Number.isSafeInteger(payload.exp)
        || payload.iat! < 0 || payload.iat! > nowSeconds || payload.exp! <= payload.iat!
        || payload.exp! - payload.iat! > lifetime || !Number.isSafeInteger(payload.exp! * 1000)
        || typeof payload.scope !== 'string' || !payload.scope.length || payload.scope.length > 32768) return null;
      const scopes = oauthScopes(payload.scope.split(' '));
      // Mapping is an explicit application policy over an already verified signed
      // subject. It never replaces signature/profile checks or consent resolution.
      const subject = resolveTokenSubject ? await resolveTokenSubject(Object.freeze({
        issuer, clientId, audience: resource, subject: payload.sub,
      }), { signal: controller.signal }) : payload.sub;
      if (controller.signal.aborted) throw new AccessError('TIMEOUT');
      if (typeof subject !== 'string' || !USER_ID.test(subject) || payload.exp! * 1000 <= Date.now()) return null;
      const identity: VerifiedWorkOSConnectIdentity = Object.freeze({
        issuer, subject, clientId, audience: resource,
        consentId: payload.sid, tokenId: payload.jti, scopes, expiresAt: payload.exp! * 1000,
      });
      const grant = await resolveConsent(identity, { signal: controller.signal });
      if (controller.signal.aborted) throw new AccessError('TIMEOUT');
      if (!grant || !identifier(grant.subject, 512) || !Number.isSafeInteger(grant.expiresAt)
        || (grant.authorizationId !== undefined && !identifier(grant.authorizationId))) return null;
      const consentScopes = oauthScopes(grant.scopes);
      if (!consentScopes.length || consentScopes.some((scope) => !scopes.includes(scope))) return null;
      const expiresAt = Math.min(identity.expiresAt, grant.expiresAt);
      if (expiresAt <= Date.now()) return null;
      return Object.freeze({ appId, subject: grant.subject, scopes: consentScopes, expiresAt,
        ...(grant.authorizationId !== undefined ? { authorizationId: grant.authorizationId } : {}) });
    };
    try {
      return await Promise.race([work(), cancelled]);
    } catch {
      if (controller.signal.aborted) throw new AccessError('TIMEOUT');
      // No token, claims, provider response or resolver exception is exposed to callers.
      return null;
    } finally {
      clearTimeout(timer);
      context.signal.removeEventListener('abort', stop);
      removeAbort();
      controller.abort();
    }
  };
}

// WorkOS is an explicit optional entry point; generic SDK entry points do not export it.
export { createWorkOSConnectProvider } from './workos-connect-provider.js';
export type { WorkOSConnectProvider, WorkOSConnectProviderOptions } from './workos-connect-provider.js';
