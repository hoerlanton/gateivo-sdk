import assert from 'node:assert/strict';
import { test } from 'node:test';
import { z } from 'zod/v4';
import { defineAction } from '../src/action.js';
import { createActionRegistry } from '../src/core.js';

test('schema-inferred actions receive parsed defaults through the registry', async () => {
  const action = defineAction({
    name: 'list_items', title: 'List items', description: 'List owned items', requiredScopes: ['items:read'],
    inputSchema: z.object({ limit: z.number().default(10) }),
    outputSchema: z.object({ count: z.number(), subject: z.string() }),
    execute: async ({ limit }, { principal }) => ({ count: limit, subject: principal.subject }),
  });
  assert.equal(defineAction(action), action);
  const registry = createActionRegistry({ appId: 'items', actions: [action] });
  const result = await registry.execute('list_items', {}, {
    appId: 'items', subject: 'alice', scopes: ['items:read'], expiresAt: Date.now() + 60_000,
  });
  assert.deepEqual(result, { count: 10, subject: 'alice' });
});
