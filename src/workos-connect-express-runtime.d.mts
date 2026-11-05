import type { WorkOSConnection, WorkOSConnectionDependencies, WorkOSConnectionOptions } from './workos-connect-express.js';

/** Internal implementation boundary; public options and returns remain fully typed. */
export function createWorkOSConnectionRuntime(options: WorkOSConnectionOptions,
  dependencies?: WorkOSConnectionDependencies): WorkOSConnection;
