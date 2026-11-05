import { randomBytes, randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { APP_ID, READ_SCOPE } from './actions.mjs';

/**
 * Local fictional HTTP simulation only. This is NOT a Laravel server, OAuth,
 * login, consent, token issuance for a real backend, or a deployable bridge.
 */
export async function startHttpBackendFixture() {
  const requests = [];
  const lookups = [];
  const accounts = Object.fromEntries(['alice', 'bob'].map((subject, index) => [subject, {
    assistantToken: randomBytes(32).toString('base64url'),
    upstreamToken: `${index + 17}|${randomBytes(32).toString('base64url')}`,
    principal: Object.freeze({
      appId: APP_ID, subject, scopes: Object.freeze([READ_SCOPE]),
      authorizationId: randomUUID(), expiresAt: Date.now() + 5 * 60 * 1000,
    }),
  }]));
  const records = [
    { id: 'workout-alice-1', title: 'Morning trail ride', ownerId: 'alice' },
    { id: 'workout-bob-1', title: 'Evening run', ownerId: 'bob' },
  ];
  let cancelledRequests = 0;
  let credentialCaptureRequests = 0;
  let delayedResponse;
  const server = createServer((req, res) => {
    if (!['127.0.0.1', '::ffff:127.0.0.1'].includes(req.socket.remoteAddress)) {
      res.writeHead(403).end(); return;
    }
    if (req.url === '/credential-capture') credentialCaptureRequests++;
    const account = Object.values(accounts).find((candidate) =>
      req.headers.authorization === `Bearer ${candidate.upstreamToken}`);
    requests.push({ path: req.url, subject: account?.principal.subject ?? null,
      usedUpstreamCredential: Boolean(account),
      usedAssistantCredential: Object.values(accounts).some((candidate) =>
        req.headers.authorization === `Bearer ${candidate.assistantToken}`) });
    res.setHeader('content-type', 'application/json');
    if (!account) { res.writeHead(401).end('{"privateError":"PRIVATE_UPSTREAM_BODY"}'); return; }
    const match = /^\/api\/me\/workouts\/(workout-[a-z0-9-]{1,80})$/.exec(req.url ?? '');
    if (req.method !== 'GET' || !match) { res.writeHead(404).end('{}'); return; }
    const id = match[1];
    if (id === 'workout-server-error') {
      res.writeHead(503).end(JSON.stringify({ privateError: 'PRIVATE_UPSTREAM_BODY',
        credential: account.upstreamToken })); return;
    }
    if (id === 'workout-redirect') {
      res.writeHead(302, { location: '/credential-capture' }).end(); return;
    }
    if (id === 'workout-slow') {
      // The client must cancel the actual upstream request, not only its caller.
      const timer = setTimeout(() => res.end('{}'), 5000);
      res.once('close', () => { clearTimeout(timer); if (!res.writableEnded) cancelledRequests++; });
      return;
    }
    if (id === 'workout-delayed') { delayedResponse = res; return; }
    if (id === 'workout-declared-large') {
      res.writeHead(200, { 'content-length': 4096 }).end('x'.repeat(4096)); return;
    }
    if (id === 'workout-streamed-large') {
      res.writeHead(200); res.write('{"private":"'); res.end('x'.repeat(4096) + '"}'); return;
    }
    if (id === 'workout-invalid-json') { res.end('PRIVATE_UPSTREAM_BODY'); return; }
    if (id === 'workout-wrong-id') {
      res.end(JSON.stringify({ workout: { id: 'workout-bob-1', title: 'Wrong record' } })); return;
    }
    if (id === 'workout-wrong-type') {
      res.setHeader('content-type', 'text/plain'); res.end('PRIVATE_UPSTREAM_BODY'); return;
    }
    // Authentication and this ownership decision are upstream, not model input.
    const row = records.find((record) => record.id === id && record.ownerId === account.principal.subject);
    if (!row) { res.writeHead(404).end('{"privateError":"PRIVATE_UPSTREAM_BODY"}'); return; }
    res.end(JSON.stringify({ workout: { ...row, internalNote: 'PRIVATE_UPSTREAM_NOTE',
      billingReference: 'PRIVATE_UPSTREAM_BILLING' }, privateEnvelope: 'PRIVATE_UPSTREAM_ENVELOPE' }));
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject); server.listen(0, '127.0.0.1', resolve);
  });
  return Object.freeze({
    origin: `http://127.0.0.1:${server.address().port}`, accounts, requests, lookups,
    get cancelledRequests() { return cancelledRequests; },
    get credentialCaptureRequests() { return credentialCaptureRequests; },
    releaseDelayedResponse() {
      if (!delayedResponse) throw new Error('No delayed fixture response is pending.');
      delayedResponse.end(JSON.stringify({ workout: { id: 'workout-delayed', title: 'Delayed owned read' } }));
      delayedResponse = undefined;
    },
    async resolveCredential(principal, { signal }) {
      signal.throwIfAborted();
      lookups.push({ ...principal });
      const account = accounts[principal.subject];
      return principal.appId === APP_ID && account?.principal.authorizationId === principal.authorizationId
        ? account.upstreamToken : null;
    },
    async close() {
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
    },
  });
}
