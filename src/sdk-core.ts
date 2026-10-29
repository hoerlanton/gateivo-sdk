/** Provider-independent action contracts for publisher integrations. */
export { createActionRegistry, type ActionRegistryOptions } from './core.js';
export { defineAction } from './action.js';
export { AccessError } from './types.js';
export type { Principal, AppAction, ActionContext, AuditEvent, ErrorCode } from './types.js';
