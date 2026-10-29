import type { z } from 'zod/v4';

/** Created only by a verified credential, never from agent-provided arguments. */
export interface Principal {
  appId: string;
  subject: string;
  scopes: readonly string[];
  /** Expiration as Unix milliseconds. */
  expiresAt: number;
  /** Opaque approval generation returned by the trusted grant resolver, never a tool argument. */
  authorizationId?: string;
}

export interface ActionContext {
  principal: Readonly<Principal>;
  signal: AbortSignal;
  requestId: string;
}

/**
 * Milestone one deliberately supports reads only.
 * The defaults keep heterogeneous action collections compatible. Use
 * defineAction when authoring an action to infer handler types from schemas.
 */
export interface AppAction<I = any, O extends Record<string, unknown> = any> {
  name: string;
  title: string;
  description: string;
  requiredScopes: readonly string[];
  inputSchema: z.ZodType<I>;
  outputSchema: z.ZodType<O>;
  execute: (input: I, context: ActionContext) => Promise<O>;
}

export type ErrorCode =
  | 'UNAUTHENTICATED' | 'FORBIDDEN' | 'INVALID_ARGUMENT'
  | 'NOT_FOUND' | 'UNAVAILABLE' | 'TIMEOUT' | 'OUTPUT_LIMIT';

export class AccessError extends Error {
  constructor(public readonly code: ErrorCode) {
    super(code);
    this.name = 'AccessError';
  }
}

export interface AuditEvent {
  requestId: string;
  appId: string;
  action: string;
  outcome: 'success' | 'denied' | 'failed';
  code?: ErrorCode;
  durationMs: number;
}
