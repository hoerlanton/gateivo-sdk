import type { LoginContext, LoginStore } from './login-contract.js';
import { createLoginPostgresStoreRuntime } from './login-postgres-runtime.mjs';

/** The publisher owns the pg-compatible driver, pool and verified TLS settings. */
export interface LoginPostgresClient {
  query(sql: string, values?: unknown[]): Promise<{rows: Record<string, unknown>[]} >;
  release(destroy?: boolean): void;
  on?(event: 'error', listener: (error: Error) => void): unknown;
  removeListener?(event: 'error', listener: (error: Error) => void): unknown;
}
export interface LoginPostgresPool { connect(): Promise<LoginPostgresClient> }
export interface LoginPostgresStoreOptions {
  pool: LoginPostgresPool;
  appId: string;
  /** Dedicated SDK-owned schema. Tables are additionally namespaced by appId. */
  schema?: string;
  timeoutMs?: number;
  now?: () => number;
}
export interface LoginPostgresStore extends LoginStore {
  /** Explicit release task; never invoked by a request or application startup. */
  migrate(context?: LoginContext): Promise<boolean>;
  checkReady(context?: LoginContext): Promise<boolean>;
  /** Cancels this adapter's work without closing the application-owned pool. */
  close(): Promise<void>;
}
export function createLoginPostgresStore(options: LoginPostgresStoreOptions): LoginPostgresStore {
  return createLoginPostgresStoreRuntime(options);
}
