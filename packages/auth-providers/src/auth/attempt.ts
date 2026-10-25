/**
 * The pieces of a cancellable attempt that the token sites and the device
 * poll share: the failure an aborted attempt ends with, a race
 * that settles at the abort itself, and the server's poll interval as an
 * abortable wait. No timer of this package's choosing: the only `setTimeout`
 * here is the interval the server asked for.
 */

import { AuthProviderFailure, authError } from '@mcp-abap-adt/auth-errors';
import { isPlainPromise } from './handled';

/** `Promise.prototype.then`, bound: the engine's, never a value's own. */
const engineThen = Function.prototype.call.bind(Promise.prototype.then) as <T>(
  promise: Promise<T>,
  onFulfilled: (value: T) => void,
  onRejected: (error: unknown) => void,
) => Promise<void>;

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
  work: Promise<T>,
  signal: AbortSignal | undefined,
): Promise<T> {
  // Subscribed only through the engine's `then`, on a plain native promise:
  // anything else is first adopted, once, as `await` would adopt it.
  const plain: Promise<T> = isPlainPromise(work)
    ? work
    : new Promise<T>((resolve) => resolve(work));
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
