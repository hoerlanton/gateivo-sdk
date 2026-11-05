import { runHttpBackendExercise } from './exercise.mjs';

console.log('Gateivo HTTP backend example — local fictional simulation');
console.log('Real MCP and loopback HTTP calls; simulated accounts and existing-credential lookup.');
console.log('Not Laravel validation, real OAuth, login/session handoff or a deployment.\n');
try {
  const { workout, checks } = await runHttpBackendExercise();
  console.log('Public workout:', JSON.stringify(workout));
  for (const check of checks) console.log(`- ${check}`);
  console.log('\nBoth temporary servers are closed.');
} catch (error) {
  // Never print transport errors, request headers, raw upstream bodies or tokens.
  console.error(`Example failed (${error instanceof Error ? error.name : 'Error'}).`);
  process.exitCode = 1;
}
