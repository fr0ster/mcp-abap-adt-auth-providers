/**
 * `markHandled` and `onNativeRejection` (src/auth/handled.ts): a plain
 * native promise gets a native handler; a foreign thenable, a Promise
 * subclass or a Proxy is never touched — its `then` is never called.
 */

import { describe, expect, it } from '@jest/globals';
import { markHandled, onNativeRejection } from '../../auth/handled';

function foreign(): { value: unknown; calls: () => number } {
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

describe('handled: native promises only', () => {
  it('a foreign thenable, a Proxy and a subclass: then never called by either helper', () => {
    const { value, calls } = foreign();
    for (const v of value as unknown[]) {
      markHandled(v);
      onNativeRejection(v, () => undefined);
    }
    expect(calls()).toBe(0);
  });

  it('a rejecting native promise: the handler runs, a throwing handler is contained', async () => {
    const seen: unknown[] = [];
    const listener = (reason: unknown) => seen.push(reason);
    process.on('unhandledRejection', listener);
    try {
      const reasons: unknown[] = [];
      onNativeRejection(Promise.reject(new Error('a')), (e) => reasons.push(e));
      onNativeRejection(Promise.reject(new Error('b')), () => {
        throw new Error('handler threw');
      });
      markHandled(Promise.reject(new Error('c')));
      await new Promise((resolve) => setTimeout(resolve, 20));
      expect(reasons).toHaveLength(1);
    } finally {
      process.off('unhandledRejection', listener);
    }
    expect(seen).toEqual([]);
  });
});
