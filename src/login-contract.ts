import type { Request } from 'express';

/** Trusted account state returned by the publisher, never by a browser form. */
export interface LoginAccount {
  appSubject: string;
  /** Immutable account creation/incarnation key; changes after deletion/recreation. */
  accountKey: string;
  /** Opaque current authentication revision; never a password or password hash. */
  authVersion: string;
  accountLabel: string;
  email: string;
  emailVerified: true;
  enabled: true;
}
export interface LoginContext { signal: AbortSignal }
export interface LoginSession {
  sessionId: string;
  appSubject: string;
  accountKey: string;
  authVersion: string;
  expiresAt: number;
}
export interface LoginSessionRecord extends LoginSession { sessionHash: string }
export interface VerifiedLoginSession extends LoginSession { accountLabel: string }
export interface LoginBinding {
  issuer: string;
  appSubject: string;
  accountKey: string;
  externalId: string;
  providerSubject: string;
}
export interface LoginHandoff {
  externalAuthIdHash: string;
  browserNonceHash: string;
  expiresAt: number;
}
export interface LoginHandoffClaim extends LoginHandoff {
  sessionId: string;
  appSubject: string;
  accountKey: string;
  authVersion: string;
}
/** Durable, app-namespaced records. Implementations never receive passwords or OAuth tokens. */
export interface LoginStore {
  beginLogin(input: {stateHash: string; expiresAt: number}, context: LoginContext): Promise<boolean>;
  consumeLogin(stateHash: string, context: LoginContext): Promise<boolean>;
  createSession(input: LoginSessionRecord, context: LoginContext): Promise<void>;
  resolveSession(sessionHash: string, context: LoginContext): Promise<LoginSession | null>;
  revokeSession(sessionHash: string, context: LoginContext): Promise<boolean>;
  getBinding(input: {issuer: string; appSubject: string; accountKey: string}, context: LoginContext): Promise<LoginBinding | null>;
  bindAccount(input: LoginBinding, context: LoginContext): Promise<LoginBinding>;
  findBinding(input: {issuer: string; subject: string}, context: LoginContext): Promise<LoginBinding | null>;
  beginHandoff(input: LoginHandoff, context: LoginContext): Promise<boolean>;
  consumeHandoff(input: LoginHandoffClaim, context: LoginContext): Promise<boolean>;
}
export type ResolveLoginAccount = (appSubject: string, context: LoginContext) => Promise<LoginAccount | null>;
export type AuthenticateLoginSession = (request: Request, context: LoginContext) => Promise<VerifiedLoginSession | null>;
