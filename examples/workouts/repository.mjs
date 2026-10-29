/** Existing application business logic. This module has no Gateivo dependency. */
export function createWorkoutRepository() {
  const workouts = [
    {
      id: 'workout-alice-1', ownerId: 'alice', title: 'Morning trail ride', activity: 'cycling',
      startedAt: '2026-10-20T07:30:00.000Z', durationMinutes: 55,
      internalNote: 'PRIVATE_ALICE_NOTE', billingReference: 'PRIVATE_ALICE_BILLING',
    },
    {
      id: 'workout-alice-2', ownerId: 'alice', title: 'Evening run', activity: 'running',
      startedAt: '2026-10-21T17:00:00.000Z', durationMinutes: 30,
      internalNote: 'PRIVATE_ALICE_NOTE', billingReference: 'PRIVATE_ALICE_BILLING',
    },
    {
      id: 'workout-bob-1', ownerId: 'bob', title: 'Pool session', activity: 'swimming',
      startedAt: '2026-10-21T08:00:00.000Z', durationMinutes: 40,
      internalNote: 'PRIVATE_BOB_NOTE', billingReference: 'PRIVATE_BOB_BILLING',
    },
  ].map(Object.freeze);

  return Object.freeze({
    async listForOwner(ownerId, { limit, signal }) {
      signal.throwIfAborted();
      if (!Number.isSafeInteger(limit) || limit < 1 || limit > 20) {
        throw new RangeError('Invalid workout limit.');
      }
      // A database implementation must put this ownership check in its query.
      return workouts.filter((workout) => workout.ownerId === ownerId)
        .slice(0, limit).map((workout) => ({ ...workout }));
    },
    async getForOwner(ownerId, workoutId, { signal }) {
      signal.throwIfAborted();
      const workout = workouts.find((row) => row.ownerId === ownerId && row.id === workoutId);
      // Missing and another user's records are indistinguishable to the caller.
      return workout ? { ...workout } : null;
    },
  });
}
