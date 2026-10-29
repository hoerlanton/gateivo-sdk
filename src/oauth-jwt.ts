import { createRemoteJWKSet, customFetch, jwtVerify } from 'jose';
import { AccessError, type Principal } from './types.js';
import type { TokenVerifierContext } from './http.js';
import { configuredOAuthUrl, oauthScopes } from './oauth-resource.js';

export interface VerifiedOAuthIdentity {
  readonly issuer: string;
  readonly subject: string;
  readonly clientId: string;
  readonly tokenId: string;
  readonly audience: string;
  readonly scopes: readonly string[];
  readonly expiresAt: number;
}

export interface ActiveOAuthGrant {
  /** Host-owned immutable approval generation for data-source routing and revalidation. */
  authorizationId?: string;
  /** Canonical existing app account ID, resolved from a trusted link, never an email or tool argument. */
  subject: string;
  /** Current consent scopes. These may narrow, but never widen, the access token's scopes. */
  scopes: readonly string[];
  /** Current consent/link expiry as Unix milliseconds. */
  expiresAt: number;
}

export interface OAuthJwtVerifierOptions {
  appId: string;
  issuer: string;
  resource: string;
  jwksUri: string;
  algorithms?: readonly ('RS256' | 'ES256' | 'EdDSA')[];
  maxTokenLifetimeSeconds?: number;
  timeoutMs?: number;
  jwksCooldownMs?: number;
  jwksCacheMaxAgeMs?: number;
  /**
   * Required on EVERY verified request: check active user consent, revocation and account status.
   * Null denies access. Use (issuer, subject, clientId) and tokenId where applicable. Never grant
   * a client-credentials token a rider identity. Honor signal; failures and timeouts fail closed.
   */
  resolveGrant: (identity: VerifiedOAuthIdentity, context: { signal: AbortSignal }) => Promise<ActiveOAuthGrant | null>;
}

const identifier = (value: unknown, max = 512): value is string => typeof value === 'string'
  && value.length > 0 && value.length <= max && value.trim().length > 0 && !/[\u0000-\u001f\u007f-\u009f]/u.test(value);

function boundedInteger(value: number, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new TypeError('Invalid OAuth limit.');
  return value;
}

/**
 * Verifies RFC 9068 JWT access tokens. This is a resource-server verifier, NOT an OAuth issuer.
 * Providers using opaque or other token profiles can supply createAgentRouter.verifyToken instead.
 */
export function createOAuthJwtVerifier(options: OAuthJwtVerifierOptions) {
  const { appId, issuer, resolveGrant } = options;
  if (!identifier(appId, 128) || typeof resolveGrant !== 'function') throw new TypeError('App and grant resolver required.');
  configuredOAuthUrl(issuer);
  const audience = configuredOAuthUrl(options.resource).href;
  const jwksUrl = configuredOAuthUrl(options.jwksUri);
  const algorithms = [...new Set(options.algorithms ?? ['RS256', 'ES256'])];
  if (!algorithms.length || algorithms.some((alg) => !['RS256', 'ES256', 'EdDSA'].includes(alg))) {
    throw new TypeError('Only configured asymmetric signing algorithms are supported.');
  }
  const lifetime = boundedInteger(options.maxTokenLifetimeSeconds ?? 3600, 1, 86400);
  const timeout = boundedInteger(options.timeoutMs ?? 2500, 1, 30000);
  const cooldown = boundedInteger(options.jwksCooldownMs ?? 30000, 0, 300000);
  const cacheAge = boundedInteger(options.jwksCacheMaxAgeMs ?? 300000, 1, 3600000);
  const keys = createRemoteJWKSet(jwksUrl, {
    timeoutDuration: timeout, cooldownDuration: cooldown, cacheMaxAge: cacheAge,
    [customFetch]: async (url, init) => {
      if (url !== jwksUrl.href) throw new Error('Unexpected key destination.');
      // No bearer token, app session or cookies ever reach the signing-key endpoint.
      const response = await fetch(url, { ...init, redirect: 'manual', credentials: 'omit' });
      if (response.status !== 200 || !response.body) {
        await response.body?.cancel();
        throw new Error('Signing keys unavailable.');
      }
      const reader = response.body.getReader();
      const chunks: Uint8Array[] = [];
      let size = 0;
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          size += value.byteLength;
          if (size > 128 * 1024) throw new Error('Signing key response exceeds limit.');
          chunks.push(value);
        }
      } finally {
        await reader.cancel().catch(() => undefined);
        reader.releaseLock();
      }
      const body = Buffer.concat(chunks);
      const parsed: unknown = JSON.parse(body.toString('utf8'));
      if (!parsed || typeof parsed !== 'object' || !('keys' in parsed) ||
          !Array.isArray(parsed.keys) || parsed.keys.length < 1 || parsed.keys.length > 32) {
        throw new Error('Invalid signing key set.');
      }
      return new Response(body, { status: 200, headers: { 'content-type': 'application/json' } });
    },
  });

  return async (token: string, context: TokenVerifierContext): Promise<Principal | null> => {
    if (context.signal.aborted) throw new AccessError('TIMEOUT');
    if (context.audience !== audience || typeof token !== 'string' || token.length > 8192 ||
        !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)) return null;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const stopped = () => controller.abort();
    context.signal.addEventListener('abort', stopped, { once: true });
    const timeoutError = () => new AccessError('TIMEOUT');
    const cancelled = new Promise<never>((_, reject) => {
      controller.signal.addEventListener('abort', () => reject(timeoutError()), { once: true });
      timer = setTimeout(stopped, timeout);
      if (context.signal.aborted) stopped();
    });
    const work = async (): Promise<Principal | null> => {
      const { payload } = await jwtVerify(token, keys, {
        issuer, audience, algorithms, typ: 'at+jwt', clockTolerance: 0,
        requiredClaims: ['iss', 'sub', 'aud', 'exp', 'iat', 'jti', 'client_id'],
      });
      if (controller.signal.aborted) throw timeoutError();
      const now = Date.now();
      if (!identifier(payload.sub) || !identifier(payload.jti) || !identifier(payload.client_id) ||
          !Number.isSafeInteger(payload.exp) || !Number.isSafeInteger(payload.iat) ||
          payload.iat! > Math.floor(now / 1000) || payload.exp! <= payload.iat! ||
          payload.exp! - payload.iat! > lifetime || !Number.isSafeInteger(payload.exp! * 1000)) return null;
      if (typeof payload.scope !== 'string' || payload.scope.length > 32768) return null;
      const scopes = oauthScopes(payload.scope === '' ? [] : payload.scope.split(' '));
      const identity: VerifiedOAuthIdentity = Object.freeze({
        issuer, subject: payload.sub, clientId: payload.client_id, tokenId: payload.jti,
        audience, scopes, expiresAt: payload.exp! * 1000,
      });
      // This lookup must enforce that the token corresponds to a live human-approved app connection.
      const grant = await resolveGrant(identity, { signal: controller.signal });
      if (controller.signal.aborted) throw timeoutError();
      if (!grant || !identifier(grant.subject) || !Number.isSafeInteger(grant.expiresAt)
        || (grant.authorizationId !== undefined && !identifier(grant.authorizationId, 128))) return null;
      const consentScopes = oauthScopes(grant.scopes);
      if (consentScopes.some((scope) => !scopes.includes(scope))) return null;
      const expiresAt = Math.min(identity.expiresAt, grant.expiresAt);
      if (expiresAt <= Date.now()) return null;
      return Object.freeze({ appId, subject: grant.subject, scopes: consentScopes, expiresAt,
        ...(grant.authorizationId !== undefined ? { authorizationId: grant.authorizationId } : {}) });
    };
    try {
      return await Promise.race([work(), cancelled]);
    } catch {
      if (controller.signal.aborted) throw timeoutError();
      // Never expose a token, claim, provider body, key URL or grant lookup error.
      return null;
    } finally {
      clearTimeout(timer);
      context.signal.removeEventListener('abort', stopped);
    }
  };
}
