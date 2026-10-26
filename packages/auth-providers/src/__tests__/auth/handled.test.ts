/**
 * `markHandled` (src/auth/handled.ts). `onAnswerRejection`'s cases are tested
 * through the paths that detach an answer: `providers/raceScenarios`,
 * `authorization/presentationAnswers`, `authorization/openInBrowser`, and the
 * logger paths (`noTokensInLogs`).
 *
 * `markHandled` crosses a trust boundary (a target's answer, a value being
 * classified): a plain native promise gets a native handler; a foreign
 * thenable, a Promise subclass or a Proxy is never touched — its `then` is
 * never called.
 */

import { describe, expect, it } from '@jest/globals';
import { markHandled } from '../../auth/handled';

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
