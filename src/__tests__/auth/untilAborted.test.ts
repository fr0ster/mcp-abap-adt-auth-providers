/**
 * `untilAborted` subscribes only through the engine's `then`:
 * a plain native promise is never asked for its own `then`, and anything
 * else is adopted once, as `await` adopts it — never subscribed twice.
 */

import { describe, expect, it } from '@jest/globals';
import { untilAborted } from '../../auth/attempt';
import { isPlainPromise } from '../../auth/handled';

function ownThen<T>(value: T) {
  const counter = { calls: 0 };
  const promise = Promise.resolve(value);
  Object.defineProperty(promise, 'then', {
    value(...args: unknown[]) {
      counter.calls += 1;
      return Promise.prototype.then.apply(promise, args as never);
    },
  });
  return { promise, counter };
}

describe('isPlainPromise', () => {
  it('refuses a native promise with an own then or catch', () => {
    expect(isPlainPromise(Promise.resolve(1))).toBe(true);
    expect(isPlainPromise(ownThen(1).promise)).toBe(false);
    const withCatch = Promise.resolve(1);
    Object.defineProperty(withCatch, 'catch', { value: () => withCatch });
    expect(isPlainPromise(withCatch)).toBe(false);
  });
});

describe('untilAborted', () => {
  it('a non-plain promise is adopted once, with or without a signal', async () => {
    for (const signal of [undefined, new AbortController().signal]) {
      const { promise, counter } = ownThen('value');
      await expect(untilAborted(promise, signal)).resolves.toBe('value');
      expect(counter.calls).toBe(1);
    }
  });
});
