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
  onRejected: (error: unknown) => void,
) => Promise<unknown>;
const ignoreRejection = (): void => undefined;
const promiseThen2 = Function.prototype.call.bind(Promise.prototype.then) as <
  R,
>(
  promise: Promise<unknown>,
  onFulfilled: (value: unknown) => R,
) => Promise<R>;

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

/**
 * Runs `handler` with the rejection of `value` when — and only when — it is a
 * plain native promise, through the `then` captured at load; anything else
 * (a foreign thenable, a subclass, a Proxy, a non-promise) is left alone and
 * its code never runs. A handler that throws is contained, and the derived
 * promise is marked handled: nothing here can raise `unhandledRejection`.
 * Never throws.
 */
export function onNativeRejection(
  value: unknown,
  handler: (error: unknown) => void,
): void {
  if (!isPlainPromise(value)) return;
  const derived = promiseThen(value, undefined, (error) => {
    try {
      handler(error);
    } catch {
      // The handler's own failure is contained: nobody awaits it.
    }
  });
  markHandled(derived);
}

/**
 * A collaborator's answer, boxed: the box is a plain object with no
 * prototype, so resolving with it never reads a `then`.
 */
export interface Answered<T> {
  readonly value: T;
}

/**
 * What a refused answer rejects with: no `Error` and no words of its own —
 * whoever catches it classifies it with its own operation (`unknown`).
 */
const FOREIGN_THENABLE = Object.freeze({ answer: 'foreign-thenable' });

function box<T>(value: T): Answered<T> {
  const answered = Object.create(null) as { value: T };
  answered.value = value;
  return answered;
}

/**
 * Whether reading or awaiting `value` could run a consumer's code as a
 * thenable: a Proxy (its traps run on any read), or an object or function
 * with a `then` — a getter or a function — anywhere on its prototype chain,
 * read by descriptor so no getter runs. Never throws (a throwing read is
 * "yes": fail closed).
 */
function looksThenable(value: unknown): boolean {
  try {
    if (
      (typeof value !== 'object' && typeof value !== 'function') ||
      value === null
    ) {
      return false;
    }
    if (isProxy(value)) return true;
    for (
      let at: object | null = value;
      at !== null;
      at = Object.getPrototypeOf(at) as object | null
    ) {
      if (isProxy(at)) return true;
      const then = Reflect.getOwnPropertyDescriptor(at, 'then');
      if (then !== undefined) {
        return then.get !== undefined || typeof then.value === 'function';
      }
    }
    return false;
  } catch {
    return true;
  }
}

/**
 * What a collaborator answered — a value or a promise of one — as a native
 * promise of a box (Task 29 review): a plain native promise is followed
 * through the `then` captured at load; any other thenable is refused with
 * fixed words, its `then` never called; a plain value is boxed as it is.
 * Awaiting the result runs no consumer code. A collaborator that throws
 * synchronously is the caller's to catch, as before.
 */
export function answered<T>(value: T | PromiseLike<T>): Promise<Answered<T>> {
  if (isPlainPromise(value)) {
    return promiseThen2(value, (fulfilled) => box(fulfilled as T));
  }
  if (looksThenable(value)) return NativePromise.reject(FOREIGN_THENABLE);
  return NativePromise.resolve(box(value as T));
}
