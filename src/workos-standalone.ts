import type { Router } from 'express';
import type { AuthenticateLoginSession, LoginStore, ResolveLoginAccount } from './login-contract.js';
import type { WorkOSAccountBinding } from './workos-connect-express.js';
import type { WorkOSConnectTokenSubjectResolver } from './workos-connect.js';
import { createWorkOSStandaloneLoginRuntime } from './workos-standalone-runtime.mjs';

/** Experimental WorkOS Standalone Connect handoff around the publisher's login. */
export interface WorkOSStandaloneLoginOptions {
  appId: string;
  publicUrl: string;
  issuer: string;
  /** Development API key only in this preview. */
  apiKey: string;
  clientId: string;
  /** Fixed to publicUrl + /agent/mcp. */
  resource?: string;
  /** Exactly 32 bytes. Also derives stable external identities: preserve this key. */
  secret: Uint8Array;
  /** The default PostgreSQL store consumes handoffs only for sessions persisted
   * by this same LoginStore. Existing external sessions need a compatible store
   * implementation; returning an unrecorded session from the hook is insufficient. */
  store: LoginStore;
  authenticateSession: AuthenticateLoginSession;
  resolveLoginAccount: ResolveLoginAccount;
  trustProxyHttps?: boolean;
  /** Optional fixed pilot cutoff, Unix milliseconds. */
  accessExpiresAt?: number;
}
export interface WorkOSStandaloneLogin {
  /** Mount after application login routes and before createWorkOSConnection.router. */
  readonly router: Router;
  readonly resolveAccount: (identity: { issuer: string; appSubject: string },
    context: { signal: AbortSignal }) => Promise<WorkOSAccountBinding | null>;
  readonly resolveTokenSubject: WorkOSConnectTokenSubjectResolver;
}
export interface WorkOSStandaloneLoginDependencies {
  /** Trusted server-side transport seam; never configured by a browser request. */
  fetch?: typeof fetch;
}

/** This establishes identity only. Explicit assistant consent remains separate. */
export function createWorkOSStandaloneLogin(options: WorkOSStandaloneLoginOptions,
  dependencies: WorkOSStandaloneLoginDependencies = {}): WorkOSStandaloneLogin {
  return createWorkOSStandaloneLoginRuntime(options, dependencies);
}
