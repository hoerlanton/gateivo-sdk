import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { loopbackResource } from './demo-approvals.mjs';

function structuredResult(result) {
  if (result.isError || !result.structuredContent || typeof result.structuredContent !== 'object') {
    throw new Error('The local demo tool did not return a successful result.');
  }
  return result.structuredContent;
}

async function main() {
  const resource = loopbackResource(process.env.GATEIVO_DEMO_URL ?? 'http://127.0.0.1:5196/mcp');
  const token = process.env.GATEIVO_DEMO_TOKEN;
  if (!token || !/^[A-Za-z0-9_-]{43}$/.test(token)) {
    throw new Error('Set GATEIVO_DEMO_TOKEN to the short-lived token printed by the local server.');
  }
  const client = new Client({ name: 'gateivo-workouts-local-client', version: '0.1.0' });
  const transport = new StreamableHTTPClientTransport(new URL(resource), {
    authProvider: { token: async () => token },
    requestInit: { redirect: 'error' },
    redirectPolicy: 'same-origin',
  });
  try {
    await client.connect(transport, { timeout: 5000 });
    const { tools } = await client.listTools(undefined, { timeout: 5000 });
    console.log('Available read-only tools:', tools.map(({ name }) => name).join(', '));
    const list = structuredResult(await client.callTool({
      name: 'workouts_list', arguments: { limit: 10 },
    }, { timeout: 5000 }));
    console.log(JSON.stringify(list, null, 2));
    const first = Array.isArray(list.workouts) ? list.workouts[0] : undefined;
    if (typeof first?.id === 'string') {
      const detail = structuredResult(await client.callTool({
        name: 'workouts_get', arguments: { workoutId: first.id },
      }, { timeout: 5000 }));
      console.log(JSON.stringify(detail, null, 2));
    }
  } finally {
    await client.close();
  }
}

void main().catch((error) => {
  // Transport errors can contain headers. Never print them or the bearer token.
  const known = error instanceof Error && /^(Set GATEIVO_DEMO_TOKEN|This local demo|The local demo tool)/.test(error.message);
  console.error(known ? error.message : 'Local test failed. Check the server, URL, approval and token expiry.');
  process.exitCode = 1;
});
