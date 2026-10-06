/**
 * TRANSITION (Decision D6 table; replaced in Task 27 by interfaces-auth
 * 6.0.0's `AuthorizationRequest`, which carries the field): the 4.x
 * `AuthorizationRequest` plus the attempt's `signal` (spec §6b). A token
 * provider builds it for every login it hands a strategy; the shipped
 * strategies combine it with their own option signal, so either one ends
 * the login. A consumer's strategy must honour it too, and settle its
 * `authorize` only once it has released what it holds (a socket, a reader):
 * the next login waits for that.
 */

import type { AuthorizationRequest } from '@mcp-abap-adt/interfaces-auth';
import { readSafely } from './knownCodes';

export type SignalledAuthorizationRequest = AuthorizationRequest & {
  /** Aborts when every waiter of the login has gone (spec §6b). */
  readonly signal?: AbortSignal | undefined;
};

/**
 * The request's signal when it is a native `AbortSignal`, read once and
 * safely; anything else — absent, a getter that throws, another object —
 * is no signal.
 */
export function signalOf(request: unknown): AbortSignal | undefined {
  const signal = readSafely(request, 'signal');
  return signal instanceof AbortSignal ? signal : undefined;
}
