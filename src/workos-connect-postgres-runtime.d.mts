import type { WorkOSPostgresStore, WorkOSPostgresStoreOptions } from './workos-connect-postgres.js';

/** Internal implementation boundary; the driver remains structurally injected. */
export function createWorkOSPostgresStoreRuntime(options: WorkOSPostgresStoreOptions): WorkOSPostgresStore;
