import { AccessError } from '@gateivo/sdk';
import { createReferenceHost } from '../workos-reference/host.mjs';
import { createHttpBackendAction } from './actions.mjs';
import { createHttpBackendClient } from './client.mjs';

const bindingFields = Object.freeze(['appId', 'subject', 'issuer', 'providerSubject', 'authVersion']);
const recordFields = Object.freeze([...bindingFields, 'credential', 'expiresAt']);
const matches = (left, right) => !!left && !!right
  && bindingFields.every(field => typeof left[field] === 'string' && left[field] === right[field]);
const denied = () => { throw new AccessError('FORBIDDEN'); };

function credentialRecord(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)
    || Object.keys(input).length !== recordFields.length
    || !recordFields.every(field => Object.hasOwn(input, field))) denied();
  // Copy once: a hook cannot mutate the selected record while the API is reading.
  const selected = Object.freeze(Object.fromEntries(recordFields.map(field => [field, input[field]])));
  if (!Number.isSafeInteger(selected.expiresAt) || selected.expiresAt <= Date.now()
    || typeof selected.credential !== 'string' || !/^[\x21-\x7e]{1,4096}$/.test(selected.credential)) denied();
  return selected;
}

/**
 * SOURCE EXAMPLE: password/session login and durable delegated consent compose
 * with an existing account-authenticated API. No credential is issued here.
 *
 * resolveBackendCredential is a trusted publisher lookup. It receives the current
 * canonical app binding, and must return an already authorized, account-bound,
 * expiring credential record with that exact binding. It must never copy binding
 * fields onto a shared admin credential or use the assistant's token/cookie.
 *
 * Auth-version changes invalidate stale credential records; reprovisioning a new
 * record is separate publisher work. Only explicit disconnect revokes a grant.
 */
export async function createAuthenticatedHttpBackendHost({
  config, apiKey, backend, resolveBackendCredential,
}, dependencies = {}) {
  if (!backend || typeof backend !== 'object' || Array.isArray(backend)
    || typeof resolveBackendCredential !== 'function') {
    throw new TypeError('Configure a trusted backend and account-bound credential lookup.');
  }
  const transport = Object.freeze({ baseUrl: backend.baseUrl, timeoutMs: backend.timeoutMs,
    maxResponseBytes: backend.maxResponseBytes, allowLoopbackHttp: backend.allowLoopbackHttp });
  // Validate the fixed transport at startup. This creates no connection or token.
  createHttpBackendClient({ ...transport, appId: 'workouts-example', resolveCredential: async () => null });

  return createReferenceHost({ config, apiKey }, { ...dependencies,
    createActions({ appId, isAuthorized, resolveApplicationAccount }) {
      const currentAccount = async (principal, signal) => {
        signal.throwIfAborted();
        if (!await isAuthorized(principal, { signal })) denied();
        const account = await resolveApplicationAccount(principal, { signal });
        signal.throwIfAborted();
        if (!account || account.appId !== appId || account.subject !== principal.subject
          || !await isAuthorized(principal, { signal })) denied();
        signal.throwIfAborted();
        return account;
      };
      const authenticatedBackend = Object.freeze({
        async getMyWorkout(id, context) {
          let expectedAccount;
          let selected;
          // Keep request-specific bindings and credentials on this call's stack.
          const client = createHttpBackendClient({ ...transport, appId,
            async resolveCredential(principal, { signal }) {
              const before = await currentAccount(principal, signal);
              const record = credentialRecord(await resolveBackendCredential(before, { signal }));
              signal.throwIfAborted();
              const after = await currentAccount(principal, signal);
              if (!matches(before, after) || !matches(record, before) || record.expiresAt <= Date.now()) denied();
              expectedAccount = before;
              selected = record;
              return record.credential;
            },
          });
          try {
            const result = await client.getMyWorkout(id, context);
            const current = await currentAccount(context.principal, context.signal);
            if (!matches(expectedAccount, current) || !matches(selected, current)
              || selected.expiresAt <= Date.now()) denied();
            context.signal.throwIfAborted();
            return result;
          } catch (error) {
            if (context.signal.aborted) throw new AccessError('TIMEOUT');
            if (error instanceof AccessError) throw new AccessError(error.code);
            throw new AccessError('UNAVAILABLE');
          }
        },
      });
      return [createHttpBackendAction({ backend: authenticatedBackend })];
    },
  });
}
