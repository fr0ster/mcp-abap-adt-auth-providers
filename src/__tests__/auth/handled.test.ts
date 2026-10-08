/**
 * `markHandled` and `onAnswerRejection` (src/auth/handled.ts).
 *
 * `markHandled` crosses a trust boundary (a target's answer, a value being
 * classified): a plain native promise gets a native handler; a foreign
 * thenable, a Promise subclass or a Proxy is never touched — its `then` is
 * never called.
 *
 * `onAnswerRejection` reads a collaborator's answer — the consumer's own
 * code: it is adopted as `await` would
 * adopt it, so a Promises/A+ thenable's rejection, or its `then` throwing,
 * reaches the handler like a native rejection.
 */

import { describe, expect, it } from '@jest/globals';
import { markHandled, onAnswerRejection } from '../../auth/handled';
import { APlusPromise } from '../helpers/aplusPromise';

function foreign(): { value: unknown[]; calls: () => number } {
  let calls = 0;
  const record = () => {
    calls += 1;
  };
  class Sub extends Promise<unknown> {}
  return {
    value: [
      // biome-ignore lint/suspicious/noThenProperty: a foreign thenable is the input under test
      { then: record, catch: record },
      new Proxy(Promise.resolve('proxied'), {
        get: (target, key) => {
          if (key === 'then' || key === 'catch') record();
          return Reflect.get(target, key);
        },
      }),
      (() => {
        const p = Sub.resolve('sub');
        Object.defineProperty(p, 'then', { value: record });
        return p;
      })(),
    ],
    calls: () => calls,
  };
}

/** Collects `unhandledRejection` while `body` runs and a little after. */
async function unhandledDuring(body: () => void): Promise<unknown[]> {
  const seen: unknown[] = [];
  const listener = (reason: unknown) => seen.push(reason);
  process.on('unhandledRejection', listener);
  try {
    body();
    await new Promise((resolve) => setTimeout(resolve, 20));
  } finally {
    process.off('unhandledRejection', listener);
  }
  return seen;
}

describe('markHandled: native promises only', () => {
  it('a foreign thenable, a Proxy and a subclass: then never called', () => {
    const { value, calls } = foreign();
    for (const v of value) markHandled(v);
    expect(calls()).toBe(0);
  });

  it('a rejecting native promise raises no unhandledRejection', async () => {
    expect(
      await unhandledDuring(() => markHandled(Promise.reject(new Error('c')))),
    ).toEqual([]);
  });
});

describe('onAnswerRejection: a collaborator’s answer, adopted', () => {
  it('a native rejection and a Promises/A+ rejection reach the handler; a resolving one does not', async () => {
    const reasons: unknown[] = [];
    const record = (error: unknown) => reasons.push(error);
    const seen = await unhandledDuring(() => {
      onAnswerRejection(Promise.reject('native'), record);
      onAnswerRejection(APlusPromise.reject('aplus'), record);
      onAnswerRejection(APlusPromise.resolve('fine'), record);
      onAnswerRejection('a plain value', record);
    });
    expect(reasons.sort()).toEqual(['aplus', 'native']);
    expect(seen).toEqual([]);
  });

  it('a then that throws, a then getter that throws, a hostile Proxy: each a rejection', async () => {
    const reasons: unknown[] = [];
    const record = (error: unknown) => reasons.push(error);
    const seen = await unhandledDuring(() => {
      onAnswerRejection(
        {
          // biome-ignore lint/suspicious/noThenProperty: the thenable under test
          then() {
            throw 'then threw';
          },
        },
        record,
      );
      onAnswerRejection(
        {
          // biome-ignore lint/suspicious/noThenProperty: the thenable under test
          get then() {
            throw 'getter threw';
          },
        },
        record,
      );
      onAnswerRejection(
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
    });
    expect(reasons.sort()).toEqual([
      'getter threw',
      'then threw',
      'trap threw',
    ]);
    expect(seen).toEqual([]);
  });

  it('a handler that throws is contained', async () => {
    const seen = await unhandledDuring(() => {
      onAnswerRejection(Promise.reject(new Error('b')), () => {
        throw new Error('handler threw');
      });
      onAnswerRejection(APlusPromise.reject(new Error('b')), () => {
        throw new Error('handler threw');
      });
    });
    expect(seen).toEqual([]);
  });

  it('never throws synchronously', () => {
    expect(() =>
      onAnswerRejection(
        {
          // biome-ignore lint/suspicious/noThenProperty: the thenable under test
          get then() {
            throw new Error('sync');
          },
        },
        () => undefined,
      ),
    ).not.toThrow();
  });
});
