import { randomUUID } from 'node:crypto';
import express, { type ErrorRequestHandler } from 'express';
import { hostHeaderValidation } from '@modelcontextprotocol/express';
import { toNodeHandler } from '@modelcontextprotocol/node';
import { createMcpHandler, McpServer } from '@modelcontextprotocol/server';
import { createActionRegistry } from './core.js';
import { AccessError, type Principal } from './types.js';
import { configuredOAuthUrl, createOAuthResource, oauthChallenge, type OAuthResource } from './oauth-resource.js';

export interface TokenVerifierContext {
  /** The configured MCP resource URL; the verifier MUST validate token audience. */
  audience: string;
  signal: AbortSignal;
}

export interface AgentRouterOptions {
  registry: ReturnType<typeof createActionRegistry>;
  /** Required. Verify signature, issuer, audience, expiry, revocation and consent. */
  verifyToken: (token: string, context: TokenVerifierContext) => Promise<Principal | null>;
  resource: string;
  /** Mount oauth.router at the application root for public protected-resource discovery. */
  oauth?: OAuthResource;
  allowedHosts?: string[];
  /** Exact browser origins, including scheme and port. Native clients omit Origin. */
  allowedOrigins?: string[];
  authTimeoutMs?: number;
  maxConcurrentRequests?: number;
}

const BODY_LIMIT = 16 * 1024;
const safeError = (code: string) => ({ error: { code } });

/** Stateless HTTP transport. Every request authenticates; session headers grant no authority. */
export function createAgentRouter(options: AgentRouterOptions) {
  if (typeof options.verifyToken !== 'function') throw new Error('A token verifier is required.');
  const resource = configuredOAuthUrl(options.resource);
  // Rebuild from validated configuration rather than trusting a mutable challenge string.
  const oauth = options.oauth ? createOAuthResource({
    resource: options.oauth.resource,
    authorizationServers: options.oauth.metadata.authorization_servers,
    scopesSupported: options.oauth.metadata.scopes_supported,
    requiredScopes: options.oauth.requiredScopes,
  }) : undefined;
  if (oauth && oauth.resource !== resource.href) throw new TypeError('OAuth resource does not match the MCP resource.');
  const allowedOrigins = Object.freeze([...(options.allowedOrigins ?? [])].map((origin) => {
    const parsed = configuredOAuthUrl(origin);
    if (parsed.origin !== origin) throw new TypeError('Allowed origins must be exact origins without paths.');
    return origin;
  }));
  const challenge = (error?: 'invalid_token' | 'insufficient_scope') => oauth ? oauthChallenge(oauth, error) : 'Bearer';
  const authTimeoutMs = options.authTimeoutMs ?? 3000;
  const maxConcurrent = options.maxConcurrentRequests ?? 16;
  if (!Number.isSafeInteger(authTimeoutMs) || authTimeoutMs < 1 || authTimeoutMs > 30_000 ||
      !Number.isSafeInteger(maxConcurrent) || maxConcurrent < 1 || maxConcurrent > 1000) {
    throw new Error('Invalid HTTP limits.');
  }
  const router = express.Router();
  let active = 0;

  router.use(hostHeaderValidation(options.allowedHosts ?? [resource.hostname]));
  router.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    const origin = req.headers.origin;
    if (origin && !allowedOrigins.includes(origin)) {
      res.status(403).json(safeError('FORBIDDEN'));
      return;
    }
    if (origin) {
      res.vary('Origin');
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Expose-Headers', 'WWW-Authenticate, X-Request-ID, MCP-Session-ID');
    }
    if (req.method === 'OPTIONS') {
      const requestedMethod = req.headers['access-control-request-method'];
      const allowedHeaders = ['authorization', 'content-type', 'accept', 'mcp-protocol-version', 'mcp-method', 'mcp-name', 'mcp-session-id', 'last-event-id'];
      const requestedHeaders = req.headers['access-control-request-headers'];
      if (!origin || requestedMethod !== 'POST' ||
          (requestedHeaders && (typeof requestedHeaders !== 'string' ||
            requestedHeaders.toLowerCase().split(',').some((header) => !allowedHeaders.includes(header.trim()))))) {
        res.status(403).json(safeError('FORBIDDEN'));
        return;
      }
      res.setHeader('Access-Control-Allow-Methods', 'POST');
      res.setHeader('Access-Control-Allow-Headers', allowedHeaders.join(', '));
      res.vary('Access-Control-Request-Method');
      res.vary('Access-Control-Request-Headers');
      res.status(204).end();
      return;
    }
    if (new URL(req.originalUrl, resource.origin).searchParams.has('access_token')) {
      res.status(400).json(safeError('INVALID_REQUEST'));
      return;
    }
    if (active >= maxConcurrent) {
      res.setHeader('Retry-After', '1');
      res.status(429).json(safeError('BUSY'));
      return;
    }
    active++;
    let released = false;
    const release = () => { if (!released) { active--; released = true; } };
    res.once('finish', release);
    res.once('close', release);
    next();
  });

  router.use((req, res, next) => {
    const requestId = randomUUID();
    res.setHeader('X-Request-ID', requestId);
    const authorization = req.headers.authorization;
    const match = typeof authorization === 'string' && authorization.length <= 8192
      ? /^Bearer ([A-Za-z0-9\-._~+/]+=*)$/i.exec(authorization) : null;
    if (!match?.[1]) {
      res.setHeader('WWW-Authenticate', challenge(authorization ? 'invalid_token' : undefined));
      res.status(401).json(safeError('UNAUTHENTICATED'));
      return;
    }
    const controller = new AbortController();
    let insufficientScope = false;
    const disconnected = () => controller.abort();
    res.once('close', disconnected);
    let timer: ReturnType<typeof setTimeout>;
    const deadline = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new AccessError('TIMEOUT'));
      }, authTimeoutMs);
    });
    void Promise.race([
      Promise.resolve().then(() => options.verifyToken(match[1]!, {
        audience: resource.href, signal: controller.signal,
      })),
      deadline,
    ]).then((verified) => {
      if (!verified) throw new AccessError('UNAUTHENTICATED');
      // Copy immediately; no mutable principal is shared between HTTP requests.
      const principal = Object.freeze({
        appId: verified.appId, subject: verified.subject,
        scopes: Object.freeze([...verified.scopes]), expiresAt: verified.expiresAt,
        ...(verified.authorizationId !== undefined ? { authorizationId: verified.authorizationId } : {}),
      });
      const actions = options.registry.list(principal);
      if (actions.length === 0) {
        insufficientScope = true;
        throw new AccessError('FORBIDDEN');
      }
      res.locals.agent = { principal, actions, requestId, signal: controller.signal };
      if (!res.destroyed) next();
    }).catch((error: unknown) => {
      if (res.destroyed || res.headersSent) return;
      const forbidden = error instanceof AccessError && error.code === 'FORBIDDEN';
      const timeout = error instanceof AccessError && error.code === 'TIMEOUT';
      if (!forbidden && !timeout) res.setHeader('WWW-Authenticate', challenge('invalid_token'));
      else if (forbidden && insufficientScope && oauth) {
        res.setHeader('WWW-Authenticate', challenge('insufficient_scope'));
      }
      res.status(forbidden ? 403 : timeout ? 503 : 401)
        .json(safeError(forbidden ? 'FORBIDDEN' : timeout ? 'UNAVAILABLE' : 'UNAUTHENTICATED'));
    }).finally(() => clearTimeout(timer));
  });

  router.use(express.json({ limit: BODY_LIMIT, strict: true }));
  router.all('/', (req, res) => {
    if (req.method !== 'POST') {
      res.setHeader('Allow', 'POST');
      res.status(405).json(safeError('METHOD_NOT_ALLOWED'));
      return;
    }
    // Also enforce the output of an earlier parent JSON parser, if mounted after one.
    if (Buffer.byteLength(JSON.stringify(req.body) ?? '', 'utf8') > BODY_LIMIT) {
      res.status(413).json(safeError('REQUEST_TOO_LARGE'));
      return;
    }
    const { principal, actions, requestId, signal } = res.locals.agent as {
      principal: Principal;
      actions: ReturnType<AgentRouterOptions['registry']['list']>;
      requestId: string;
      signal: AbortSignal;
    };
    const handler = createMcpHandler(() => {
      const server = new McpServer({ name: 'mobigent-agent-access', version: '0.1.0' });
      for (const action of actions) {
        server.registerTool(action.name, {
          title: action.title,
          description: action.description,
          inputSchema: action.inputSchema,
          outputSchema: action.outputSchema,
          annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
        }, async (args, context) => {
          try {
            const result = await options.registry.execute(action.name, args, principal, {
              requestId, signal: AbortSignal.any([signal, context.mcpReq.signal]),
            });
            return { content: [{ type: 'text' as const, text: JSON.stringify(result) }], structuredContent: result };
          } catch (error) {
            const code = error instanceof AccessError ? error.code : 'UNAVAILABLE';
            return { isError: true, content: [{ type: 'text' as const, text: JSON.stringify(safeError(code)) }] };
          }
        });
      }
      return server;
    }, { responseMode: 'auto', maxRequestBodySize: BODY_LIMIT, maxSubscriptions: 0 });
    void toNodeHandler(handler, { maxRequestBodySize: BODY_LIMIT })(req, res, req.body)
      .catch(() => {
        if (!res.headersSent && !res.destroyed) res.status(500).json(safeError('UNAVAILABLE'));
        else if (!res.destroyed) res.end();
      })
      .finally(() => handler.close());
  });
  const errorHandler: ErrorRequestHandler = (error, _req, res, _next) => {
    if (res.headersSent) return;
    const tooLarge = error?.type === 'entity.too.large';
    res.status(tooLarge ? 413 : 400).json(safeError(tooLarge ? 'REQUEST_TOO_LARGE' : 'INVALID_REQUEST'));
  };
  router.use(errorHandler);
  return router;
}
