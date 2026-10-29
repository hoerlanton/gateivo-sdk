import { randomUUID } from 'node:crypto';
import { z } from 'zod/v4';
import { AccessError, type ActionContext, type AppAction, type AuditEvent, type Principal } from './types.js';

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_OUTPUT_BYTES = 32 * 1024;
const MAX_AUDIT_WAIT_MS = 25;
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f-\u009f]/u;
const SCOPE = /^[\x21\x23-\x5b\x5d-\x7e]{1,128}$/;
const ACTION_NAME = /^[A-Za-z][A-Za-z0-9_.:-]{0,127}$/;
const REQUEST_ID = /^[A-Za-z0-9_-]{1,128}$/;
const ADAPTER_ERROR_CODES = new Set<AccessError['code']>([
  'FORBIDDEN', 'INVALID_ARGUMENT', 'NOT_FOUND', 'UNAVAILABLE', 'TIMEOUT', 'OUTPUT_LIMIT',
]);

export interface ActionRegistryOptions {
  appId: string;
  actions: AppAction[];
  authorize?: (actionName: string, context: ActionContext) => Promise<boolean>;
  audit?: (event: AuditEvent) => void | Promise<void>;
  timeoutMs?: number;
  maxOutputBytes?: number;
}

function opaqueIdentifier(value: unknown, maxLength: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= maxLength
    && value.trim().length > 0 && !CONTROL_CHARACTERS.test(value);
}

function validScopes(value: unknown): value is string[] {
  return Array.isArray(value) && value.length <= 256
    && value.every((scope: unknown) => typeof scope === 'string' && SCOPE.test(scope));
}

function authenticatedPrincipal(value: Principal, appId: string): Readonly<Principal> {
  // Copy the verified credential's claims: never retain a caller-mutable identity.
  let principal: Principal;
  try {
    if (!value || typeof value !== 'object') throw new Error();
    const { appId: claimedAppId, subject, expiresAt, scopes, authorizationId } = value;
    if (!opaqueIdentifier(claimedAppId, 128) || !opaqueIdentifier(subject, 512)
      || typeof expiresAt !== 'number' || !Number.isFinite(expiresAt)
      || expiresAt <= Date.now() || !validScopes(scopes)
      || (authorizationId !== undefined && !opaqueIdentifier(authorizationId, 128))) throw new Error();
    principal = Object.freeze({
      appId: claimedAppId, subject, expiresAt,
      scopes: Object.freeze([...new Set(scopes)]),
      ...(authorizationId !== undefined ? { authorizationId } : {}),
    });
  } catch {
    throw new AccessError('UNAUTHENTICATED');
  }
  if (principal.appId !== appId) throw new AccessError('FORBIDDEN');
  return principal;
}

function assertFresh(principal: Readonly<Principal>): void {
  if (principal.expiresAt <= Date.now()) throw new AccessError('UNAUTHENTICATED');
}

function hasScopes(action: AppAction, principal: Readonly<Principal>): boolean {
  return action.requiredScopes.every((scope) => principal.scopes.includes(scope));
}

/** Reject keys silently removed by nested object schemas, as well as at the root. */
function assertNoDiscardedInputKeys(input: unknown, parsed: unknown): void {
  if (Array.isArray(input)) {
    if (Array.isArray(parsed)) {
      input.forEach((item, index) => assertNoDiscardedInputKeys(item, parsed[index]));
    }
    return;
  }
  if (input === null || typeof input !== 'object' || parsed === null || typeof parsed !== 'object') return;
  for (const key of Object.keys(input)) {
    if (!Object.hasOwn(parsed, key)) throw new AccessError('INVALID_ARGUMENT');
    assertNoDiscardedInputKeys((input as Record<string, unknown>)[key], (parsed as Record<string, unknown>)[key]);
  }
}

async function boundedAudit(
  audit: ActionRegistryOptions['audit'], event: AuditEvent, deadline: number,
): Promise<void> {
  if (!audit) return;
  // Logging is best effort. A rejected/hung hook cannot deny a successful read.
  const completed = Promise.resolve().then(() => audit(Object.freeze(event))).catch(() => undefined);
  const remaining = Math.min(MAX_AUDIT_WAIT_MS, Math.max(0, deadline - performance.now()));
  if (remaining === 0) return;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([completed, new Promise<void>((resolve) => { timer = setTimeout(resolve, remaining); })]);
  } finally {
    clearTimeout(timer);
  }
}

export function createActionRegistry(options: ActionRegistryOptions) {
  const {
    appId, authorize, audit,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    maxOutputBytes = DEFAULT_MAX_OUTPUT_BYTES,
  } = options;
  if (!opaqueIdentifier(appId, 128)) throw new TypeError('Invalid registry appId');
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 2_147_483_647) {
    throw new TypeError('Invalid registry timeoutMs');
  }
  if (!Number.isSafeInteger(maxOutputBytes) || maxOutputBytes <= 0) {
    throw new TypeError('Invalid registry maxOutputBytes');
  }
  const actions = new Map<string, AppAction>();
  for (const action of options.actions) {
    if (!ACTION_NAME.test(action.name) || actions.has(action.name) || !validScopes(action.requiredScopes)) {
      throw new TypeError('Invalid or duplicate action');
    }
    actions.set(action.name, Object.freeze({
      ...action,
      requiredScopes: Object.freeze([...new Set(action.requiredScopes)]),
      inputSchema: action.inputSchema instanceof z.ZodObject ? action.inputSchema.strict() : action.inputSchema,
    }));
  }

  return {
    list(principal: Principal): AppAction[] {
      const identity = authenticatedPrincipal(principal, appId);
      return [...actions.values()].filter((action) => hasScopes(action, identity));
    },

    async execute(
      name: string,
      input: unknown,
      principal: Principal,
      executionOptions: { signal?: AbortSignal; requestId?: string } = {},
    ): Promise<Record<string, unknown>> {
      const started = performance.now();
      const deadline = started + timeoutMs;
      const requestId = typeof executionOptions.requestId === 'string' && REQUEST_ID.test(executionOptions.requestId)
        ? executionOptions.requestId : randomUUID();
      const controller = new AbortController();
      let timer: ReturnType<typeof setTimeout> | undefined;
      let cancel: (() => void) | undefined;
      let actionName = 'unknown';
      let code: AccessError['code'] | undefined;
      const assertActive = () => {
        if (controller.signal.aborted || performance.now() >= deadline) {
          controller.abort();
          throw new AccessError('TIMEOUT');
        }
      };

      try {
        const identity = authenticatedPrincipal(principal, appId);
        const action = actions.get(name);
        if (!action) throw new AccessError('NOT_FOUND');
        actionName = action.name;
        if (!hasScopes(action, identity)) throw new AccessError('FORBIDDEN');
        const context: ActionContext = Object.freeze({ principal: identity, signal: controller.signal, requestId });
        const interrupted = new Promise<never>((_, reject) => {
          cancel = () => { controller.abort(); reject(new AccessError('TIMEOUT')); };
          timer = setTimeout(cancel, Math.max(0, deadline - performance.now()));
          executionOptions.signal?.addEventListener('abort', cancel, { once: true });
          if (executionOptions.signal?.aborted) cancel();
        });
        const work = async (): Promise<Record<string, unknown>> => {
          assertActive();
          let validatedInput: unknown;
          try {
            const result = await action.inputSchema.safeParseAsync(input);
            if (!result.success) throw new AccessError('INVALID_ARGUMENT');
            assertNoDiscardedInputKeys(input, result.data);
            validatedInput = result.data;
          } catch {
            throw new AccessError('INVALID_ARGUMENT');
          }
          assertActive();
          assertFresh(identity);
          if (authorize) {
            let permitted: boolean;
            try { permitted = await authorize(action.name, context); }
            catch { throw new AccessError('UNAVAILABLE'); }
            assertActive();
            if (permitted !== true) throw new AccessError('FORBIDDEN');
          }
          assertFresh(identity);
          let rawOutput: unknown;
          try { rawOutput = await action.execute(validatedInput, context); }
          catch (error) {
            // Preserve intentional domain failures, never an adapter's message/cause.
            throw new AccessError(error instanceof AccessError && ADAPTER_ERROR_CODES.has(error.code)
              ? error.code : 'UNAVAILABLE');
          }
          assertActive();
          assertFresh(identity);
          let serialized: string;
          try {
            const output = await action.outputSchema.safeParseAsync(rawOutput);
            if (!output.success || !output.data || typeof output.data !== 'object' || Array.isArray(output.data)) {
              throw new Error();
            }
            serialized = JSON.stringify(output.data);
            if (typeof serialized !== 'string') throw new Error();
          } catch { throw new AccessError('UNAVAILABLE'); }
          assertActive();
          assertFresh(identity);
          if (Buffer.byteLength(serialized, 'utf8') > maxOutputBytes) throw new AccessError('OUTPUT_LIMIT');
          const output: unknown = JSON.parse(serialized);
          if (!output || typeof output !== 'object' || Array.isArray(output)) throw new AccessError('UNAVAILABLE');
          return output as Record<string, unknown>;
        };
        return await Promise.race([interrupted, work()]);
      } catch (error) {
        const safe = error instanceof AccessError ? error : new AccessError('UNAVAILABLE');
        code = safe.code;
        throw safe;
      } finally {
        clearTimeout(timer);
        if (cancel) executionOptions.signal?.removeEventListener('abort', cancel);
        // Stop cooperative background work even after success or a validation failure.
        controller.abort();
        const denied = code === 'UNAUTHENTICATED' || code === 'FORBIDDEN';
        await boundedAudit(audit, {
          requestId, appId, action: actionName,
          outcome: code ? (denied ? 'denied' : 'failed') : 'success',
          ...(code ? { code } : {}), durationMs: Math.max(0, Math.round(performance.now() - started)),
        }, deadline);
      }
    },
  };
}
