/**
 * The pieces of a cancellable attempt that the token sites and the device
 * poll share: the failure an aborted attempt ends with, a race
 * that settles at the abort itself, and the server's poll interval as an
 * abortable wait. No timer of this package's choosing: the only `setTimeout`
 * here is the interval the server asked for.
 */

import { AuthProviderFailure, authError } from '@mcp-abap-adt/auth-errors';

/** `Promise.prototype.then`, bound: the engine's, never a value's own. */
const engineThen = Function.prototype.call.bind(Promise.prototype.then) as <T>(
  promise: Promise<T>,
  onFulfilled: ((value: T) => void) | undefined,
  onRejected: (error: unknown) => void,
) => Promise<void>;

/**
 * Runs `handler` with the rejection of a collaborator's answer that nobody
 * awaits (a detached persistence report, a presentation's answer). The answer
 * is the consumer's own code: it is adopted as `await` adopts it, through a
 * fresh native promise (`new Promise((resolve) => resolve(answer))`, never
 * `Promise.resolve`, so a native promise with its own `then` is adopted
 * through that `then`). A `then` that throws, a `then` getter or Proxy trap
 * that throws, and a rejection are all a rejection. A handler that throws is
 * contained, so nothing here can raise `unhandledRejection`. Never throws.
 */
export function whenRejected(
  answer: unknown,
  handler: (error: unknown) => void,
): void {
  const adopted = new Promise<unknown>((resolve) => resolve(answer));
  engineThen(adopted, undefined, (error) => {
    try {
      handler(error);
    } catch {
      // The handler's own failure is contained: nobody awaits it.
    }
  });
}

/** `interactive-login` `aborted`: what an aborted attempt's work ends with. */
export function abortedFailure(): AuthProviderFailure {
  return new AuthProviderFailure(
    authError['interactive-login']({ outcome: 'aborted' }),
  );
}

/** Throws `abortedFailure()` when `signal` has aborted. */
export function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw abortedFailure();
}

/**
 * `work`, settled at the abort itself when `signal` aborts first: the
 * caller stops waiting for it — a request still on the wire, a presenter
 * that hangs — and `work`'s own later rejection is handled here, never left
 * unhandled. Without a signal, `work` itself.
 */
export function untilAborted<T>(
  work: T | PromiseLike<T>,
  signal: AbortSignal | undefined,
): Promise<T> {
  // Every value is adopted once, through a fresh native promise, as `await`
  // adopts it; then subscribed only through the engine's `then`.
  const plain = new Promise<T>((resolve) => resolve(work));
  if (!signal) return plain;
  engineThen(
    plain,
    () => undefined,
    () => undefined,
  );
  if (signal.aborted) return Promise.reject(abortedFailure());
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(abortedFailure());
    signal.addEventListener('abort', onAbort, { once: true });
    engineThen(
      plain,
      (value) => {
        signal.removeEventListener('abort', onAbort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener('abort', onAbort);
        reject(error);
      },
    );
  });
}

/**
 * The server's poll interval (RFC 8628 §3.5), ended early by the abort:
 * the timer is cleared and the wait rejects `aborted`.
 */
export function intervalWait(
  ms: number,
  signal: AbortSignal | undefined,
): Promise<void> {
  if (signal?.aborted) return Promise.reject(abortedFailure());
  return new Promise<void>((resolve, reject) => {
    const onAbort = () => {
      clearTimeout(timer);
      reject(abortedFailure());
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}
