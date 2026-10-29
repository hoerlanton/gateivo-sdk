import { createInterface } from 'node:readline';
import { createWorkoutExample } from './index.mjs';

const args = process.argv.slice(2);
if (args.length !== 1 || args[0] !== '--demo') {
  console.error('Run: npm run demo:server\nLocal fictional-data example; not a production login service.');
  process.exit(1);
}
const portText = process.env.PORT ?? '5196';
if (!/^[0-9]{1,5}$/.test(portText) || Number(portText) < 1024 || Number(portText) > 65535) {
  console.error('PORT must be an integer from 1024 to 65535.');
  process.exit(1);
}
const port = Number(portText);
const resource = `http://127.0.0.1:${port}/mcp`;
const { app, approvals } = createWorkoutExample({ demo: true, resource });
const latest = new Map();

function show(approval) {
  latest.set(approval.subject, approval.authorizationId);
  console.log(`\n${approval.subject}: local demo approval ${approval.authorizationId}`);
  console.log(`Expires: ${new Date(approval.expiresAt).toISOString()}`);
  console.log(`Bearer token (local test only): ${approval.token}`);
}

const server = app.listen(port, '127.0.0.1', () => {
  console.log(`Gateivo workouts example: ${resource}`);
  console.log('Fictional data; in-memory operator approvals; NOT OAuth or account signup.');
  console.log('Tokens expire after 15 minutes and stop working when this process exits.');
  show(approvals.approve({ subject: 'alice' }));
  console.log('\nLocal operator commands: approve bob | revoke alice | reconnect alice | exit');
});
let stopping = false;
function shutdown() {
  if (stopping) return;
  stopping = true;
  input.close();
  process.stdin.destroy();
  server.close();
  // A local client may leave a streamed response open. Exit also ends that access.
  server.closeAllConnections();
}
server.on('error', (error) => {
  console.error(error.code === 'EADDRINUSE' ? `Port ${port} is already in use.` : 'Unable to start local example.');
  process.exitCode = 1;
  shutdown();
});
const input = createInterface({ input: process.stdin });
input.on('line', (line) => {
  const [command, subject, extra] = line.trim().split(/\s+/);
  if (command === 'exit' && !subject) { shutdown(); return; }
  if (extra || !['alice', 'bob'].includes(subject)) {
    console.log('Use: approve alice|bob, revoke alice|bob, reconnect alice|bob, or exit.');
    return;
  }
  const previous = latest.get(subject);
  if (command === 'approve' && !previous) show(approvals.approve({ subject }));
  else if (command === 'revoke' && previous) {
    approvals.revoke(previous);
    console.log(`${subject}: revoked. The old token will not be restored.`);
  } else if (command === 'reconnect' && previous) show(approvals.reconnect(previous));
  else console.log(previous ? 'Use revoke or reconnect for an existing approval.' : 'Approve this fictional account first.');
});
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.once(signal, shutdown);
}
