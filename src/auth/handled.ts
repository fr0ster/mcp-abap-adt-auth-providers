/**
 * Marking a promise this package holds — but may never await — handled,
 * without running a consumer's code (spec §8.3, rule 1; controller additions
 * after Tasks 22 and 23). A consumer's method may answer a rejecting promise
 * where none is expected: an async logger, a request target's `header` or
 * `cookies`, a callback server's `waitForResult()` the strategy never reaches
 * its `await` for. Left alone, it raises `unhandledRejection`.
 */

import { isPromise, isProxy } from 'node:util/types';

const NativePromise = Promise;
const PROMISE_PROTOTYPE = Promise.prototype;
const SPECIES_GETTER = Reflect.getOwnPropertyDescriptor(
  Promise,
  Symbol.species,
)?.get;
const promiseThen = Function.prototype.call.bind(Promise.prototype.then) as (
  promise: Promise<unknown>,
  onFulfilled: undefined,
  onRejected: () => void,
) => Promise<unknown>;
const ignoreRejection = (): void => undefined;

/**
 * Whether calling `then` on `value` runs no code but the engine's: a plain
 * native promise — no Proxy, `Promise.prototype` its prototype, no own
 * `constructor`, the built-in `constructor` and `Symbol.species` still in
 * place (auth-errors' `relayOutcome` applies the same test). Never throws.
 */
export function isPlainPromise(value: unknown): value is Promise<unknown> {
  try {
    if (!isPromise(value) || isProxy(value)) return false;
    if (Object.getPrototypeOf(value) !== PROMISE_PROTOTYPE) return false;
    if (Object.hasOwn(value, 'constructor')) return false;
    const ctor = Reflect.getOwnPropertyDescriptor(
      PROMISE_PROTOTYPE,
      'constructor',
    );
    if (ctor === undefined || ctor.value !== NativePromise) return false;
    const species = Reflect.getOwnPropertyDescriptor(
      NativePromise,
      Symbol.species,
    );
    return species !== undefined && species.get === SPECIES_GETTER;
  } catch {
    return false;
  }
}

/**
 * Marks `value` handled when it is a plain native promise, so that a
 * rejection of a promise this package holds but may never await (a
 * consumer's callback server's `waitForResult()`, say) raises no
 * `unhandledRejection`. A foreign thenable, a Promise subclass or a Proxy is
 * left alone — handling it would run its code. Never throws.
 */
export function markHandled(value: unknown): void {
  if (isPlainPromise(value)) promiseThen(value, undefined, ignoreRejection);
}
