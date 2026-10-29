import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { APP_ID, READ_SCOPE } from './constants.mjs';

const MAX_TTL_MS = 15 * 60 * 1000;
const digest = (token) => createHash('sha256').update(token).digest('hex');

export function loopbackResource(value) {
  const resource = new URL(value);
  if (resource.protocol !== 'http:' || resource.hostname !== '127.0.0.1'
    || resource.pathname !== '/mcp' || resource.username || resource.password
    || resource.search || resource.hash) {
    throw new Error('This local demo requires http://127.0.0.1:<port>/mcp.');
  }
  return resource.href;
}

/**
 * LOCAL DEMO ONLY. An operator supplies fictional identities and approvals.
 * This is not OAuth, signup, account linking, or a production consent service.
 * State disappears on restart; all tokens from that process become invalid.
 */
export function createDemoApprovals({ audience, now = Date.now }) {
  const resource = loopbackResource(audience);
  const grants = new Map();
  const tokenGrants = new Map();

  function approve({ subject, scopes = [READ_SCOPE], ttlMs = MAX_TTL_MS }) {
    if (!['alice', 'bob'].includes(subject)) throw new Error('Use a fictional alice or bob account.');
    if (!Array.isArray(scopes) || scopes.length > 1 || scopes.some((scope) => scope !== READ_SCOPE)) {
      throw new Error('Unsupported demo scopes.');
    }
    if (!Number.isSafeInteger(ttlMs) || ttlMs < 1 || ttlMs > MAX_TTL_MS) {
      throw new Error('Demo credentials must expire within 15 minutes.');
    }
    const token = randomBytes(32).toString('base64url');
    const identity = Object.freeze({
      appId: APP_ID, subject, scopes: Object.freeze([...scopes]),
      authorizationId: randomUUID(), expiresAt: now() + ttlMs,
    });
    grants.set(identity.authorizationId, { identity, revoked: false });
    tokenGrants.set(digest(token), identity.authorizationId);
    return Object.freeze({ token, ...identity });
  }

  function revoke(authorizationId) {
    const grant = grants.get(authorizationId);
    if (!grant) return false;
    // This flag can only move from false to true. Reconnect creates a new grant.
    grant.revoked = true;
    return true;
  }

  function isActive(principal) {
    const grant = grants.get(principal?.authorizationId);
    if (!grant || grant.revoked || grant.identity.expiresAt <= now()) return false;
    const identity = grant.identity;
    return principal.appId === identity.appId && principal.subject === identity.subject
      && principal.expiresAt === identity.expiresAt
      && Array.isArray(principal.scopes) && principal.scopes.length === identity.scopes.length
      && principal.scopes.every((scope, index) => scope === identity.scopes[index]);
  }

  return Object.freeze({
    approve,
    revoke,
    reconnect(authorizationId) {
      const previous = grants.get(authorizationId);
      if (!previous) throw new Error('Unknown demo approval.');
      revoke(authorizationId);
      return approve({ subject: previous.identity.subject, scopes: [...previous.identity.scopes] });
    },
    isActive,
    async verifyToken(token, { audience: requestedAudience, signal }) {
      if (signal.aborted || requestedAudience !== resource
        || typeof token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(token)) return null;
      const grant = grants.get(tokenGrants.get(digest(token)));
      return grant && isActive(grant.identity) ? grant.identity : null;
    },
  });
}
