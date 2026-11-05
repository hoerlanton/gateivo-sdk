import type { WorkOSConnectionStore, WorkOSConnectionStoreContext } from './workos-connect-express.js';
import { createWorkOSPostgresStoreRuntime } from './workos-connect-postgres-runtime.mjs';

/** Structural pg-compatible client: the SDK does not install or own the driver. */
export interface WorkOSPostgresClient {
  query(sql: string, values?: unknown[]): Promise<{ rows: Record<string, unknown>[] }>;
  release(destroy?: boolean): void;
  on?(event: 'error', listener: (error: Error) => void): unknown;
  removeListener?(event: 'error', listener: (error: Error) => void): unknown;
}

export interface WorkOSPostgresPool { connect(): Promise<WorkOSPostgresClient> }

export interface WorkOSPostgresStoreOptions {
  pool: WorkOSPostgresPool;
  /** Dedicated private schema. Existing default is preserved for reference compatibility. */
  schema?: string;
  now?: () => number;
  timeoutMs?: number;
}

export interface WorkOSPostgresStore extends WorkOSConnectionStore {
  /** Explicit deployment step; never called automatically by the Express composition. */
  migrate(context?: WorkOSConnectionStoreContext): Promise<boolean>;
  checkReady(context?: WorkOSConnectionStoreContext): Promise<boolean>;
  /** Stops this adapter's operations; does not close the caller-owned pool. */
  close(): Promise<void>;
}

export function createWorkOSPostgresStore(options: WorkOSPostgresStoreOptions): WorkOSPostgresStore {
  return createWorkOSPostgresStoreRuntime(options);
}
