/**
 * The attempt's signal on an `AuthorizationRequest` (interfaces-auth 6.0.0,
 * spec §6b): a token provider sets it for every login it hands a strategy;
 * the shipped strategies combine it with their own option signal, so either
 * one ends the login. A consumer's strategy must honour it too, and settle
 * its `authorize` only once it has released what it holds (a socket, a
 * reader): the next login waits for that.
 */

import { readSafely } from './knownCodes';

/**
 * The request's signal when it is a native `AbortSignal`, read once and
 * safely; anything else — absent, a getter that throws, another object —
 * is no signal.
 */
export function signalOf(request: unknown): AbortSignal | undefined {
  const signal = readSafely(request, 'signal');
  return signal instanceof AbortSignal ? signal : undefined;
}
