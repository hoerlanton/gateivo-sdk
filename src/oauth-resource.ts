import express from 'express';
import { hostHeaderValidation } from '@modelcontextprotocol/express';

const SCOPE = /^[\x21\x23-\x5b\x5d-\x7e]{1,128}$/;

/** Configuration only: never call this with a URL from a token or HTTP headers. */
export function configuredOAuthUrl(value: string): URL {
  if (typeof value !== 'string' || value.length > 2048 || /[\s\u0000-\u001f\u007f"\\]/u.test(value)) {
    throw new TypeError('Invalid OAuth URL configuration.');
  }
  const url = new URL(value);
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if ((url.protocol !== 'https:' && !(local && url.protocol === 'http:')) ||
      url.username || url.password || url.search || url.hash) {
    throw new TypeError('OAuth URLs require HTTPS (or local HTTP) without credentials, query or fragment.');
  }
  return url;
}

export function oauthScopes(value: unknown): readonly string[] {
  if (!Array.isArray(value) || value.length > 256 ||
      !value.every((scope) => typeof scope === 'string' && SCOPE.test(scope))) {
    throw new TypeError('Invalid OAuth scopes.');
  }
  return Object.freeze([...new Set(value as string[])]);
}

export interface OAuthResourceOptions {
  resource: string;
  authorizationServers: readonly string[];
  scopesSupported: readonly string[];
  /** Scopes needed for this endpoint's basic functionality; do not request every future scope. */
  requiredScopes?: readonly string[];
}

/** Public resource metadata. The authorization server still owns sign-in, consent and issuance. */
export function createOAuthResource(options: OAuthResourceOptions) {
  const url = configuredOAuthUrl(options.resource);
  const resource = url.href;
  if (!Array.isArray(options.authorizationServers) || !options.authorizationServers.length ||
      options.authorizationServers.length > 8) throw new TypeError('An authorization server is required.');
  const authorizationServers = Object.freeze([...new Set(options.authorizationServers.map((issuer) => {
    configuredOAuthUrl(issuer);
    // Issuer identifiers use exact string comparison, including trailing slashes.
    return issuer;
  }))]);
  const scopesSupported = oauthScopes(options.scopesSupported);
  const requiredScopes = oauthScopes(options.requiredScopes ?? []);
  if (requiredScopes.some((scope) => !scopesSupported.includes(scope))) {
    throw new TypeError('Required scopes must be supported.');
  }
  const metadataPath = `/.well-known/oauth-protected-resource${url.pathname === '/' ? '' : url.pathname}`;
  // Official MCP clients remove one trailing slash when constructing discovery URLs.
  // Serve that alias without changing the configured resource or advertised metadata URL.
  const discoveryAlias = metadataPath.endsWith('/') ? metadataPath.slice(0, -1) : metadataPath;
  const metadataUrl = `${url.origin}${metadataPath}`;
  const metadata = Object.freeze({
    resource, authorization_servers: authorizationServers, scopes_supported: scopesSupported,
    bearer_methods_supported: Object.freeze(['header']),
  });
  const router = express.Router();
  // Match literally: Express path patterns must not reinterpret configured path punctuation.
  router.use((req, res, next) => {
    if (req.path !== metadataPath && req.path !== discoveryAlias) return next();
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Access-Control-Allow-Origin', '*');
    if (req.method !== 'GET' && req.method !== 'HEAD' && req.method !== 'OPTIONS') {
      res.setHeader('Allow', 'GET, HEAD, OPTIONS');
      res.status(405).end();
      return;
    }
    hostHeaderValidation([url.hostname])(req, res, () => {
      if (req.method === 'OPTIONS') {
        res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
        res.status(204).end();
      } else res.json(metadata);
    });
  });
  return Object.freeze({ resource, metadataPath, metadataUrl, metadata, requiredScopes, router });
}

export type OAuthResource = ReturnType<typeof createOAuthResource>;

export function oauthChallenge(resource: OAuthResource, error?: 'invalid_token' | 'insufficient_scope'): string {
  const fields = [`resource_metadata="${resource.metadataUrl}"`];
  if (resource.requiredScopes.length) fields.push(`scope="${resource.requiredScopes.join(' ')}"`);
  if (error) fields.push(`error="${error}"`);
  return `Bearer ${fields.join(', ')}`;
}
