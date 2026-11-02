import { AccessError } from '@gateivo/sdk';
import { APP_ID, publicWorkout, workoutId } from './actions.mjs';

/**
 * SOURCE EXAMPLE, not a new SDK API. The publisher supplies an existing credential
 * for the verified app account. Token issuance, storage, rotation, session handoff,
 * and obtaining that user's permission for this bridge remain publisher work.
 * Never substitute an admin token, a tool argument, or the assistant's OAuth token.
 *
 * @param {{ baseUrl: string,
 *   resolveCredential: (principal: Readonly<import('@gateivo/sdk').Principal>,
 *     context: {signal: AbortSignal}) => Promise<string|null>,
 *   timeoutMs?: number, maxResponseBytes?: number, allowLoopbackHttp?: boolean }} options
 */
export function createHttpBackendClient({
  baseUrl, resolveCredential, timeoutMs = 1500, maxResponseBytes = 16 * 1024,
  allowLoopbackHttp = false,
}) {
  const base = new URL(baseUrl);
  // A trusted, exact origin is configuration, never an action argument. HTTPS in
  // real deployments; the explicit HTTP exception is only for the loopback demo.
  if (base.origin !== baseUrl || base.username || base.password || base.search || base.hash
    || !(base.protocol === 'https:' || (allowLoopbackHttp === true
      && base.protocol === 'http:' && base.hostname === '127.0.0.1'))) {
    throw new TypeError('Configure one trusted HTTPS backend origin.');
  }
  if (typeof resolveCredential !== 'function'
    || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 10_000
    || !Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 1
    || maxResponseBytes > 1024 * 1024) throw new TypeError('Invalid HTTP backend limits or hook.');

  return Object.freeze({
    /** @param {string} id @param {import('@gateivo/sdk').ActionContext} context */
    async getMyWorkout(id, { principal, signal }) {
      if (!workoutId.safeParse(id).success) throw new AccessError('INVALID_ARGUMENT');
      if (principal?.appId !== APP_ID) throw new AccessError('FORBIDDEN');
      const controller = new AbortController();
      const active = AbortSignal.any([signal, controller.signal]);
      let timer;
      let stop;
      let reader;
      let response;
      const interrupted = new Promise((_, reject) => {
        stop = () => reject(new AccessError('TIMEOUT'));
        active.addEventListener('abort', stop, { once: true });
        if (active.aborted) stop();
        timer = setTimeout(() => controller.abort(), timeoutMs);
      });
      void interrupted.catch(() => undefined);
      const bounded = async (operation, lateResult) => {
        active.throwIfAborted();
        const work = Promise.resolve().then(operation);
        // A late/uncancellable transport must not leave a response body open.
        if (lateResult) void work.then((result) => {
          if (active.aborted) lateResult(result);
        }).catch(() => undefined);
        const value = await Promise.race([work, interrupted]);
        active.throwIfAborted();
        return value;
      };
      try {
        const credential = await bounded(() => resolveCredential(principal, { signal: active }));
        // Existing systems can use visible separators, e.g. an opaque "id|token".
        // Bound the header and reject whitespace/control characters and injection.
        if (typeof credential !== 'string' || !/^[\x21-\x7e]{1,4096}$/.test(credential)) {
          throw new AccessError('FORBIDDEN');
        }
        // /me selects identity using existing backend authentication; the backend
        // enforces ownership. A server-to-server credential is not enough unless
        // the backend already securely binds it to this exact end-user account.
        const url = new URL(`/api/me/workouts/${encodeURIComponent(id)}`, base);
        response = await bounded(() => fetch(url, {
          method: 'GET', signal: active, redirect: 'error', credentials: 'omit', cache: 'no-store',
          headers: { accept: 'application/json', authorization: `Bearer ${credential}` },
        }), (late) => { void late.body?.cancel().catch(() => undefined); });
        if (response.status === 404) throw new AccessError('NOT_FOUND');
        if (response.status === 401 || response.status === 403) throw new AccessError('FORBIDDEN');
        // Never read or forward error bodies, headers, URLs, or exception causes.
        if (response.status !== 200 || !/^application\/json(?:\s*;|$)/i.test(
          response.headers.get('content-type') ?? '')) throw new AccessError('UNAVAILABLE');
        const length = response.headers.get('content-length');
        if (length !== null && (!/^\d+$/.test(length) || Number(length) > maxResponseBytes)) {
          throw new AccessError('OUTPUT_LIMIT');
        }
        if (!response.body) throw new AccessError('UNAVAILABLE');
        reader = response.body.getReader();
        const chunks = [];
        let bytes = 0;
        for (;;) {
          const { value, done } = await bounded(() => reader.read());
          if (done) break;
          bytes += value.byteLength;
          if (bytes > maxResponseBytes) throw new AccessError('OUTPUT_LIMIT');
          chunks.push(value);
        }
        const payload = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
        const projected = publicWorkout(payload?.workout);
        if (projected.id !== id) throw new AccessError('UNAVAILABLE');
        active.throwIfAborted();
        return projected;
      } catch (error) {
        if (active.aborted) throw new AccessError('TIMEOUT');
        if (error instanceof AccessError) throw new AccessError(error.code);
        throw new AccessError('UNAVAILABLE');
      } finally {
        clearTimeout(timer);
        active.removeEventListener('abort', stop);
        controller.abort();
        if (reader) {
          void reader.cancel().catch(() => undefined);
          try { reader.releaseLock(); } catch { /* A cancelled read may still be settling. */ }
        } else void response?.body?.cancel().catch(() => undefined);
      }
    },
  });
}
