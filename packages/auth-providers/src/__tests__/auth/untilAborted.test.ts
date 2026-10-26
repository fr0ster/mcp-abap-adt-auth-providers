/**
 * `untilAborted` adopts every value once, through a fresh native promise, as
 * `await` adopts it — a native promise with its own `then` included — and
 * never subscribes twice. `whenRejected` hands a detached answer's rejection
 * to a handler, whatever the answer is.
 */

import { describe, expect, it } from '@jest/globals';
import { untilAborted, whenRejected } from '../../auth/attempt';
import { APlusPromise } from '../helpers/aplusPromise';

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

describe('untilAborted', () => {
  it('a native promise with its own then is adopted through that then, once, with or without a signal', async () => {
    for (const signal of [undefined, new AbortController().signal]) {
      const { promise, counter } = ownThen('value');
      await expect(untilAborted(promise, signal)).resolves.toBe('value');
      expect(counter.calls).toBe(1);
    }
  });
});

describe('whenRejected', () => {
  it('a native and a Promises/A+ rejection reach the handler; a resolving answer does not', async () => {
    const reasons: unknown[] = [];
    whenRejected(Promise.reject('native'), (e) => reasons.push(e));
    whenRejected(APlusPromise.reject('aplus'), (e) => reasons.push(e));
    whenRejected(APlusPromise.resolve('fine'), (e) => reasons.push(e));
    whenRejected('a plain value', (e) => reasons.push(e));
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(reasons.sort()).toEqual(['aplus', 'native']);
  });

  it('a throwing then getter, then and Proxy trap are rejections; a throwing handler is contained; never throws', async () => {
    const reasons: unknown[] = [];
    const record = (e: unknown) => reasons.push(e);
    expect(() => {
      whenRejected(
        {
          // biome-ignore lint/suspicious/noThenProperty: the hostile answer under test
          get then(): never {
            throw 'getter threw';
          },
        },
        record,
      );
      whenRejected(
        {
          // biome-ignore lint/suspicious/noThenProperty: the hostile answer under test
          then() {
            throw 'then threw';
          },
        },
        record,
      );
      whenRejected(
        new Proxy(
          {},
          {
            get: () => {
              throw 'trap threw';
            },
          },
        ),
        record,
      );
      whenRejected(Promise.reject('x'), () => {
        throw new Error('handler threw');
      });
    }).not.toThrow();
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(reasons.sort()).toEqual([
      'getter threw',
      'then threw',
      'trap threw',
    ]);
  });
});
