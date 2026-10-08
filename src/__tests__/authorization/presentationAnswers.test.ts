/**
 * What a presentation answers is the consumer's own code: adopted as `await`
 * would adopt it, so a native promise or any Promises/A+ thenable that
 * rejects (or whose `then` throws) is a presentation failure, and one that
 * never settles is a presentation that succeeded. A failure ends nothing:
 * the login waits for its answer (here the transport's, after 200 ms), and
 * nothing raises `unhandledRejection`. Also: a transport whose `answer()` rejects at once, the
 * presentation throwing synchronously, leaves no unhandled rejection. Run
 * under plain node in a child process, bounded by the test.
 */

import { describe, expect, it } from '@jest/globals';
import { runPlainNode } from '../helpers/plainNode';

/** A transport whose answer arrives through the judge after 200 ms. */
const scenario = (present: string) => `
const { composeAuthorization, oauthCode } = lib;
const seen = { thenCalls: 0, lines: 0 };
const transport = {
  label: 'consumer',
  async open(_options, use) {
    return use({
      redirectUri: 'http://127.0.0.1:1/callback',
      arm(judge) {
        const answer = new Promise((resolve) => {
          setTimeout(() => {
            judge({ via: 'consumer', text: 'code' });
            resolve();
          }, 200);
        });
        return { answer: () => answer };
      },
    });
  },
};
const logger = {
  debug() {}, info() {}, warn() {},
  error() { seen.lines += 1; },
};
const strategy = composeAuthorization({
  presentation: { present: ${present} },
  transport,
  protocol: oauthCode(),
  endpoint: '/callback',
});
let outcome;
try {
  const answered = await strategy.authorize({
    buildAuthorizationUrl: async (uri) => 'https://idp.example/a?state=S&r=' + uri,
    logger,
  });
  outcome = 'payload:' + answered.payload;
} catch (error) {
  outcome = errors.readFailure(error, 'unfamiliar-error').facts.outcome;
}
await new Promise((resolve) => setTimeout(resolve, 300));
report({ outcome, ...seen });
`;

const REJECTING = `async () => { throw new Error('present: SECRET'); }`;
const NEVER = `() => ({ then() { seen.thenCalls += 1; } })`;
const APLUS_REJECTING = `() => ({ then(_resolve, reject) { seen.thenCalls += 1; queueMicrotask(() => reject(new Error('present: SECRET'))); } })`;
const THEN_THROWS = `() => ({ then() { seen.thenCalls += 1; throw new Error('then: SECRET'); } })`;

describe('a presentation’s answer is adopted, whatever promise it is', () => {
  it.each([
    [
      'a rejecting presentation',
      REJECTING,
      { outcome: 'payload:code', thenCalls: 0, lines: 1 },
    ],
    [
      'a presentation answering a thenable that never settles',
      NEVER,
      { outcome: 'payload:code', thenCalls: 1, lines: 0 },
    ],
    [
      'a presentation answering a rejecting Promises/A+ thenable',
      APLUS_REJECTING,
      { outcome: 'payload:code', thenCalls: 1, lines: 1 },
    ],
    [
      'a presentation answering a thenable whose then throws',
      THEN_THROWS,
      { outcome: 'payload:code', thenCalls: 1, lines: 1 },
    ],
    [
      'a presentation throwing synchronously',
      `() => { throw new Error('sync: SECRET'); }`,
      { outcome: 'payload:code', thenCalls: 0, lines: 1 },
    ],
  ] as const)(
    '%s: no unhandled rejection, one failure line at most, the login waits for its answer',
    (_name, present, expected) => {
      const run = runPlainNode<Record<string, unknown>>(scenario(present), {
        boundMs: 30_000,
      });
      expect(run.timedOut).toBe(false);
      expect(run.result).toEqual(expected);
      expect(run.unhandled).toEqual([]);
      expect(run.stderr).not.toContain('SECRET');
    },
    60_000,
  );
});

const early = `
const { composeAuthorization, oauthCode } = lib;
const transport = {
  label: 'consumer',
  async open(_options, use) {
    return use({
      redirectUri: 'http://127.0.0.1:1/callback',
      arm() {
        const answer = Promise.reject(new Error('early: SECRET'));
        return { answer: () => answer };
      },
    });
  },
};
const strategy = composeAuthorization({
  presentation: { present() { throw new Error('sync'); } },
  transport,
  protocol: oauthCode(),
  endpoint: '/callback',
});
let kind;
try {
  await strategy.authorize({
    buildAuthorizationUrl: async (uri) => 'https://idp.example/a?state=S&r=' + uri,
  });
  kind = 'resolved';
} catch (error) {
  kind = errors.readFailure(error, 'unfamiliar-error').kind;
}
report({ kind });
`;

describe('a transport whose answer rejects early', () => {
  it('a presentation throwing synchronously: no unhandled rejection, nothing printed, the login failed', () => {
    const run = runPlainNode<{ kind: string }>(early);
    expect(run.result).toEqual({ kind: 'interactive-login' });
    expect(run.unhandled).toEqual([]);
    expect(run.stderr).toBe('');
  });
});
