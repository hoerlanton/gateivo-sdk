import type { Request, Router } from 'express';
import type { createActionRegistry } from './core.js';
import type { TokenVerifierContext } from './http.js';
import type { ActiveOAuthGrant } from './oauth-jwt.js';
import type { OAuthResource } from './oauth-resource.js';
import type { AppAction, AuditEvent, ErrorCode, Principal } from './types.js';
import type { VerifiedWorkOSConnectIdentity, WorkOSConnectTokenSubjectResolver } from './workos-connect.js';
import type { WorkOSConnectProvider } from './workos-connect-provider.js';
import { createWorkOSConnectionRuntime } from './workos-connect-express-runtime.mjs';

export type WorkOSConnectionResult<T> = T | Promise<T>;

/** Trusted, current application session. Neither ID is the browser cookie. */
export interface WorkOSAppSession {
  /** Opaque stable session ID, maximum 256 printable ASCII characters. */
  sessionId: string;
  /** Opaque authentication revision, maximum 256 printable ASCII characters. */
  authVersion: string;
  appSubject: string;
  accountLabel: string;
  /** Unix milliseconds. */
  expiresAt: number;
}

export interface WorkOSAccountBinding {
  /** Existing immutable native WorkOS user_ ID; never infer it from email. */
  providerSubject: string;
  enabled: boolean;
}

export interface WorkOSConnectionContext { signal: AbortSignal }

export interface WorkOSConnectionStoreContext {
  signal?: AbortSignal;
  issuer?: string;
  providerSubject?: string;
  clientId?: string;
  resource?: string;
}

export interface WorkOSConnectionTarget {
  issuer: string;
  clientId: string;
  resource: string;
  providerSubject: string;
  appSubject: string;
  scopes: readonly string[];
  approvedExpiresAt: number;
}

export interface WorkOSConnectionSessionBinding { sessionId: string; authVersion: string }

export interface WorkOSConnectionTicket extends WorkOSConnectionTarget, WorkOSConnectionSessionBinding {
  operationId: string;
  stateHash: string;
  attemptExpiresAt: number;
}

export interface WorkOSConnectionBegin extends WorkOSConnectionTarget, WorkOSConnectionSessionBinding {
  expectedRevision: string;
  stateHash: string;
  attemptExpiresAt: number;
}

export interface WorkOSConnectionCallback extends WorkOSConnectionTarget, WorkOSConnectionSessionBinding {
  operationId: string;
  stateHash: string;
}

export type WorkOSConnectionPhase = 'reset_pending' | 'reset_dispatched' | 'awaiting_consent'
  | 'exchanging' | 'completed' | 'failed' | 'blocked';

export interface WorkOSConnectionState {
  revision: string;
  phase: WorkOSConnectionPhase | null;
  attemptExpiresAt: number | null;
  active: boolean;
  authorizationId?: string;
}

/** Durable lifecycle contract. Every implementation must preserve old revoked generations. */
export interface WorkOSConnectionStore {
  getState(target: WorkOSConnectionTarget, context?: WorkOSConnectionStoreContext): WorkOSConnectionResult<WorkOSConnectionState>;
  begin(input: WorkOSConnectionBegin, context?: WorkOSConnectionStoreContext): WorkOSConnectionResult<WorkOSConnectionTicket>;
  claimReset(ticket: WorkOSConnectionTicket, context?: WorkOSConnectionStoreContext): WorkOSConnectionResult<boolean>;
  completeReset(ticket: WorkOSConnectionTicket, context?: WorkOSConnectionStoreContext): WorkOSConnectionResult<boolean>;
  fail(ticket: WorkOSConnectionTicket, context?: WorkOSConnectionStoreContext): WorkOSConnectionResult<void>;
  consume(input: WorkOSConnectionCallback, context?: WorkOSConnectionStoreContext): WorkOSConnectionResult<WorkOSConnectionTicket | null>;
  cancel(input: WorkOSConnectionCallback, context?: WorkOSConnectionStoreContext): WorkOSConnectionResult<boolean>;
  complete(ticket: WorkOSConnectionTicket, identity: VerifiedWorkOSConnectIdentity,
    context?: WorkOSConnectionStoreContext): WorkOSConnectionResult<ActiveOAuthGrant>;
  resolveConsent(identity: VerifiedWorkOSConnectIdentity,
    context?: WorkOSConnectionStoreContext): WorkOSConnectionResult<ActiveOAuthGrant | null>;
  revoke(input: { appSubject: string; authorizationId: string; expectedRevision?: string },
    context?: WorkOSConnectionStoreContext): WorkOSConnectionResult<boolean>;
  isActive(principal: Readonly<Principal>, context?: WorkOSConnectionStoreContext): WorkOSConnectionResult<boolean>;
}

export interface WorkOSConnectionBaseOptions {
  appId: string;
  publicUrl: string;
  issuer: string;
  clientId: string;
  applicationId: string;
  apiKey: string;
  accessTokenType: 'JWT' | 'at+jwt' | null;
  requiredScopes: readonly string[];
  /** Stable private 32-byte key. Changing it invalidates in-progress browser attempts. */
  secret: Uint8Array;
  store: WorkOSConnectionStore;
  authenticateSession(request: Request, context: WorkOSConnectionContext): WorkOSConnectionResult<WorkOSAppSession | null>;
  resolveAccount(identity: { issuer: string; appSubject: string },
    context: WorkOSConnectionContext): WorkOSConnectionResult<WorkOSAccountBinding | null>;
  resolveTokenSubject?: WorkOSConnectTokenSubjectResolver;
  /** Fixed to publicUrl + /agent/mcp when supplied. */
  resource?: string;
  /** One minute to seven days; defaults to one day. */
  approvalLifetimeMs?: number;
  /** Optional fixed cutoff as Unix milliseconds. Existing expired grants are never extended. */
  accessExpiresAt?: number;
  /** Enable only behind the application's explicitly trusted HTTPS reverse proxy. */
  trustProxyHttps?: boolean;
  audit?: (event: AuditEvent) => void | Promise<void>;
}

export type WorkOSConnectionOptions = WorkOSConnectionBaseOptions & (
  | { mountMcp?: true; actions: AppAction[] }
  | { mountMcp: false; actions?: AppAction[] }
);

export interface WorkOSConnection {
  readonly router: Router;
  readonly verifyToken: (token: string, context: TokenVerifierContext) => Promise<Principal | null>;
  readonly isAuthorized: (principal: Readonly<Principal>, context: WorkOSConnectionContext) => Promise<boolean>;
  readonly registry: ReturnType<typeof createActionRegistry> | undefined;
  readonly oauth: OAuthResource;
  readonly provider: WorkOSConnectProvider;
}

/** Fixed callback failure categories; deliberately excludes identity, tokens and errors. */
export interface WorkOSConsentDiagnostic {
  readonly operation: 'consent_callback';
  readonly phase: 'token_exchange' | 'authority_recheck' | 'store_complete';
  readonly reason: ErrorCode | 'internal_error';
}

export interface WorkOSConnectionDependencies {
  fetch?: typeof fetch;
  /** Best-effort observer. Throws/rejections do not change the authentication outcome. */
  onConsentDiagnostic?: (event: WorkOSConsentDiagnostic) => void | Promise<void>;
}

/** Optional Express composition; the application supplies its existing login, binding and store. */
export function createWorkOSConnection(options: WorkOSConnectionOptions,
  dependencies: WorkOSConnectionDependencies = {}): WorkOSConnection {
  return createWorkOSConnectionRuntime(options, dependencies);
}
