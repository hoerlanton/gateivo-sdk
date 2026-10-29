import { AccessError, defineAction } from '@gateivo/sdk';
import { z } from 'zod/v4';
import { READ_SCOPE } from './constants.mjs';

const workoutId = z.string().regex(/^workout-[a-z0-9-]{1,80}$/);
const workout = z.object({
  id: workoutId,
  title: z.string().min(1).max(120),
  activity: z.enum(['cycling', 'running', 'swimming']),
  startedAt: z.iso.datetime(),
  durationMinutes: z.number().int().min(1).max(1440),
}).strict();

// Explicitly select publishable fields, even if the application's records grow.
function publicWorkout(row) {
  return {
    id: row.id, title: row.title, activity: row.activity,
    startedAt: row.startedAt, durationMinutes: row.durationMinutes,
  };
}

/** The publisher's adapter: existing business functions become scoped tools. */
export function createWorkoutActions({ repository, isActive }) {
  async function assertActive({ principal, signal }) {
    signal.throwIfAborted();
    if (await isActive(principal) !== true) throw new AccessError('FORBIDDEN');
    signal.throwIfAborted();
  }

  return [
    defineAction({
      name: 'workouts_list', title: 'List my workouts',
      description: 'Read up to 20 saved workouts belonging to the connected account.',
      requiredScopes: [READ_SCOPE],
      inputSchema: z.object({ limit: z.number().int().min(1).max(20).default(10) }).strict(),
      outputSchema: z.object({ workouts: z.array(workout).max(20) }).strict(),
      async execute({ limit }, context) {
        await assertActive(context);
        const rows = await repository.listForOwner(context.principal.subject, {
          limit, signal: context.signal,
        });
        // Suppress data if approval was revoked while the application was reading.
        await assertActive(context);
        return { workouts: rows.map(publicWorkout) };
      },
    }),
    defineAction({
      name: 'workouts_get', title: 'Get one of my workouts',
      description: 'Read one saved workout belonging to the connected account.',
      requiredScopes: [READ_SCOPE],
      inputSchema: z.object({ workoutId }).strict(),
      outputSchema: z.object({ workout }).strict(),
      async execute({ workoutId: id }, context) {
        await assertActive(context);
        const row = await repository.getForOwner(context.principal.subject, id, {
          signal: context.signal,
        });
        await assertActive(context);
        if (!row) throw new AccessError('NOT_FOUND');
        return { workout: publicWorkout(row) };
      },
    }),
  ];
}
