import test from 'node:test';
import { runLoginHttpBackendExercise } from '../examples/http-backend/login-exercise.mjs';

test('real password/session → signed consent → current account credential → scoped HTTP API, including revocation and races', {
  timeout: 30_000,
}, async () => {
  await runLoginHttpBackendExercise();
});
