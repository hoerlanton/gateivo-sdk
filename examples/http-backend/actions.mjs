import { defineAction } from '@gateivo/sdk';
import { z } from 'zod/v4';

export const APP_ID = 'http-backend-example';
export const READ_SCOPE = 'workouts:read';
export const workoutId = z.string().regex(/^workout-[a-z0-9-]{1,80}$/);
const workout = z.object({
  id: workoutId,
  title: z.string().min(1).max(120),
}).strict();

/** Project explicitly: upstream records may contain private or newly added fields. */
export function publicWorkout(row) {
  return workout.parse({
    id: row?.id, title: row?.title,
  });
}

/**
 * The same action can call an existing PHP/Laravel, Python, or other HTTP backend.
 * Only this fictional HTTP fixture is tested; no Laravel integration is claimed.
 */
export function createHttpBackendAction({ backend }) {
  return defineAction({
    name: 'workouts_get', title: 'Get my saved workout',
    description: 'Read one saved workout belonging to the connected account.',
    requiredScopes: [READ_SCOPE],
    inputSchema: z.object({ workoutId }).strict(),
    outputSchema: z.object({ workout }).strict(),
    async execute({ workoutId: id }, context) {
      // Identity comes from the verified SDK context, never a model-chosen owner.
      return { workout: await backend.getMyWorkout(id, context) };
    },
  });
}
