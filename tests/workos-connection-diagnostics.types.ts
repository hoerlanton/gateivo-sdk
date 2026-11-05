import type { ErrorCode } from '../src/types.js';
import type { WorkOSConnectionDependencies, WorkOSConsentDiagnostic } from '../src/workos-connect-express.js';

type IsAny<Value> = 0 extends (1 & Value) ? true : false;
type Observer = NonNullable<WorkOSConnectionDependencies['onConsentDiagnostic']>;
type Event = Parameters<Observer>[0];
const eventIsTyped: IsAny<Event> = false;

const observer: Observer = event => {
  const operation: 'consent_callback' = event.operation;
  const phase: 'token_exchange' | 'authority_recheck' | 'store_complete' = event.phase;
  const reason: ErrorCode | 'internal_error' = event.reason;
  // @ts-expect-error Observers receive immutable diagnostic categories.
  event.reason = 'internal_error';
  // @ts-expect-error Tokens are never included in diagnostic events.
  event.accessToken;
  // @ts-expect-error Raw exceptions and their private properties are not exposed.
  event.error;
  // @ts-expect-error Diagnostic events contain no application account identity.
  event.subject;
  void operation; void phase; void reason;
};

// @ts-expect-error A diagnostic observer must be a function.
const invalidObserver: WorkOSConnectionDependencies = { onConsentDiagnostic: 'private' };
// @ts-expect-error Arbitrary private messages cannot become an event reason.
const invalidReason: WorkOSConsentDiagnostic['reason'] = 'PRIVATE_PROVIDER_RESPONSE';
void eventIsTyped; void observer; void invalidObserver; void invalidReason;
