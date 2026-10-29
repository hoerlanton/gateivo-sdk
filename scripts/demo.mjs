#!/usr/bin/env node
import { runWorkoutExercise } from '../examples/workouts/exercise.mjs';

console.log('Gateivo SDK local demo');
console.log('Fictional data, temporary loopback server and simulated approvals.');
console.log('This is not OAuth, a hosted service or a live Claude connection.\n');
try {
  const result = await runWorkoutExercise();
  console.log('Tools:', result.tools.join(', '));
  console.log('\nOwned workout returned over MCP:');
  console.log(JSON.stringify(result.workout, null, 2));
  console.log('\nChecks completed:');
  for (const check of result.checks) console.log(`- ${check}`);
  console.log('\nThe temporary server is closed. Next: https://gateivo.com');
} catch (error) {
  // Raw transport errors can include request headers. Keep demo credentials out
  // of diagnostic output, including when a developer breaks the example.
  console.error(`Local demo failed (${error?.constructor?.name ?? 'Error'}). Run npm run verify:consumer for detailed phase checks.`);
  process.exitCode = 1;
}
