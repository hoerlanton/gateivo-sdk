import type { Router } from 'express';
import type { AuthenticateLoginSession, LoginAccount, LoginContext, LoginStore, ResolveLoginAccount } from './login-contract.js';
import { createPasswordLoginRuntime } from './login-express-runtime.mjs';

export interface PasswordLoginOptions {
  appId: string;
  publicUrl: string;
  /** Stable, private 32-byte key; distinct domains derive the cookie and CSRF keys. */
  secret: Uint8Array;
  store: LoginStore;
  /** Publisher-owned password verification. Return the verified current account, never the form's account ID.
   * This preview requires a nonblank account label and verified ASCII email with a dotted domain. */
  verifyCredentials(credentials: {email: string; password: string}, context: LoginContext): Promise<LoginAccount | null>;
  resolveAccount: ResolveLoginAccount;
  /** Enable only behind the application's explicitly trusted HTTPS proxy. */
  trustProxyHttps?: boolean;
  /** At most one hour; Unix milliseconds are used for expiry values. */
  sessionLifetimeMs?: number;
  accessExpiresAt?: number;
  accountName?: string;
}

export interface PasswordLogin {
  readonly router: Router;
  readonly authenticateSession: AuthenticateLoginSession;
  /** Stops this module; the caller retains ownership of its store and database pool. */
  close(): Promise<void>;
}

/** Reusable browser login; app password verification remains a trusted publisher service. */
export function createPasswordLogin(options: PasswordLoginOptions): PasswordLogin {
  return createPasswordLoginRuntime(options);
}

export type { AuthenticateLoginSession, LoginAccount, LoginContext, LoginStore, ResolveLoginAccount,
  LoginSession, LoginSessionRecord, LoginBinding, LoginHandoff, LoginHandoffClaim, VerifiedLoginSession } from './login-contract.js';
