import express from 'express';
import { AccessError, createActionRegistry, createAgentRouter } from '@gateivo/sdk';
import { APP_ID, createHttpBackendAction } from './actions.mjs';

export { createHttpBackendAction } from './actions.mjs';
export { createHttpBackendClient } from './client.mjs';

/**
 * Compose with the publisher's real verifier and active-consent check. This
 * example does not create login, consent, OAuth discovery, or a deployable host.
 */
export function createHttpBackendExample({ resource, verifyToken, authorize, backend, audit }) {
  if (typeof authorize !== 'function') throw new TypeError('Supply an active-consent check.');
  const action = createHttpBackendAction({ backend });
  const registry = createActionRegistry({
    appId: APP_ID, actions: [{ ...action, async execute(input, context) {
      const result = await action.execute(input, context);
      context.signal.throwIfAborted();
      // The registry checks consent before execute. Suppress a response if that
      // same trusted check observes revocation while the upstream read was open.
      let active;
      try { active = await authorize(action.name, context); }
      catch { throw new AccessError('UNAVAILABLE'); }
      context.signal.throwIfAborted();
      if (active !== true) throw new AccessError('FORBIDDEN');
      return result;
    } }],
    authorize, audit, timeoutMs: 2500, maxOutputBytes: 8 * 1024,
  });
  const app = express();
  app.disable('x-powered-by');
  app.use('/mcp', createAgentRouter({ registry, verifyToken, resource, allowedOrigins: [] }));
  return Object.freeze({ app, registry });
}
