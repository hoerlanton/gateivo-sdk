import express from 'express';
import { createActionRegistry, createAgentRouter } from '@gateivo/sdk';
import { APP_ID } from './constants.mjs';
import { createDemoApprovals, loopbackResource } from './demo-approvals.mjs';
import { createWorkoutActions } from './actions.mjs';
import { createWorkoutRepository } from './repository.mjs';

export { createDemoApprovals } from './demo-approvals.mjs';
export { createWorkoutRepository } from './repository.mjs';
export { createWorkoutActions } from './actions.mjs';

/** Returns an unbound Express app; the CLI below binds it only to 127.0.0.1. */
export function createWorkoutExample({ demo, resource, repository, approvals, audit } = {}) {
  if (demo !== true) throw new Error('Explicit demo: true is required for the local example.');
  const audience = loopbackResource(resource);
  const ownedRepository = repository ?? createWorkoutRepository();
  const demoApprovals = approvals ?? createDemoApprovals({ audience });
  const registry = createActionRegistry({
    appId: APP_ID,
    actions: createWorkoutActions({ repository: ownedRepository, isActive: demoApprovals.isActive }),
    authorize: async (_action, { principal }) => demoApprovals.isActive(principal),
    audit,
    timeoutMs: 3000,
    maxOutputBytes: 16 * 1024,
  });
  const app = express();
  app.disable('x-powered-by');
  app.use((req, res, next) => {
    // Do not turn this operator-controlled toy authentication into a public service.
    if (!['127.0.0.1', '::ffff:127.0.0.1'].includes(req.socket.remoteAddress)) {
      res.status(403).end();
      return;
    }
    next();
  });
  app.use('/mcp', createAgentRouter({
    registry, verifyToken: demoApprovals.verifyToken,
    resource: audience, allowedHosts: ['127.0.0.1'], allowedOrigins: [],
  }));
  // There are deliberately no HTTP endpoints for creating or revoking approvals.
  return Object.freeze({ app, registry, repository: ownedRepository, approvals: demoApprovals });
}
