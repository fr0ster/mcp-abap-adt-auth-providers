/**
 * Marking a promise this package holds — but may never await — handled
 * (rule 1). A
 * consumer's method may answer a rejecting promise where none is expected:
 * an async logger, a request target's `header` or `cookies`, a callback
 * server's `waitForResult()` the strategy never reaches its `await` for.
 * Left alone, it raises `unhandledRejection`.
 *
 * Where a value crosses a trust boundary (a target's answer, a value being
 * classified) a foreign `then` is never called: `markHandled` touches plain
 * native promises only. A collaborator's answer that this package awaits is
 * awaited normally: the consumer's own
 * code, Bluebird or Q included, inside the guarded boundary.
 */

import { isPromise, isProxy } from 'node:util/types';

const NativePromise = Promise;
const PROMISE_PROTOTYPE = Promise.prototype;
const PROMISE_THEN = Reflect.getOwnPropertyDescriptor(
  Promise.prototype,
  'then',
)?.value;
const SPECIES_GETTER = Reflect.getOwnPropertyDescriptor(
  Promise,
  Symbol.species,
)?.get;
const promiseThen = Function.prototype.call.bind(Promise.prototype.then) as (
  promise: Promise<unknown>,
  onFulfilled: undefined,
  onRejected: (error: unknown) => void,
) => Promise<unknown>;
const ignoreRejection = (): void => undefined;

/**
 * Whether calling `then` on `value` runs no code but the engine's: a plain
 * native promise — no Proxy, `Promise.prototype` its prototype, no own
 * `constructor`, `then` or `catch`, the built-in `then`, `constructor` and
 * `Symbol.species` still in place (auth-errors' `relayOutcome` applies the
 * same test). Never throws.
 */
export function isPlainPromise(value: unknown): value is Promise<unknown> {
  try {
    if (!isPromise(value) || isProxy(value)) return false;
    if (Object.getPrototypeOf(value) !== PROMISE_PROTOTYPE) return false;
    if (Object.hasOwn(value, 'constructor')) return false;
    if (Object.hasOwn(value, 'then') || Object.hasOwn(value, 'catch')) {
      return false;
    }
    const then = Reflect.getOwnPropertyDescriptor(PROMISE_PROTOTYPE, 'then');
    if (then === undefined || then.value !== PROMISE_THEN) return false;
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
 * logon target's answer, or a renewal strategy's `aborted()`, say) raises no
 * `unhandledRejection`. A foreign thenable, a Promise subclass or a Proxy is
 * left alone — handling it would run its code. Never throws.
 */
export function markHandled(value: unknown): void {
  if (isPlainPromise(value)) promiseThen(value, undefined, ignoreRejection);
}

/**
 * Runs `handler` with the rejection of a collaborator's answer that this
 * package does not await (the browser launcher's): the answer is the
 * consumer's own code, so it is adopted as any `await` would adopt it — a
 * native promise, a Promise subclass or any Promises/A+ thenable (Bluebird,
 * Q) — through a native promise this module creates: its `then` is read
 * here and called in a later job. A `then` that throws, or a `then`
 * getter or Proxy trap that throws, is a rejection like any other. A handler
 * that throws is contained, and the derived promise is marked handled:
 * nothing here can raise `unhandledRejection`. Never throws.
 */
export function onAnswerRejection(
  value: unknown,
  handler: (error: unknown) => void,
): void {
  const adopted = new NativePromise<unknown>((resolve) => resolve(value));
  const derived = promiseThen(adopted, undefined, (error) => {
    try {
      handler(error);
    } catch {
      // The handler's own failure is contained: nobody awaits it.
    }
  });
  markHandled(derived);
}
