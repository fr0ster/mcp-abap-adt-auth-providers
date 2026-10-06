/**
 * Task 29 review, item 1: what the launcher (`openUrl`) answers is never
 * handled through a foreign `then` / `catch`; only a plain native promise
 * gets a native rejection handler, and the consumer server's `fail()` runs
 * inside a try, so a `fail()` that throws raises no `unhandledRejection`.
 * Run under plain node in a child process, bounded by the test.
 */

import { describe, expect, it } from '@jest/globals';
import { runPlainNode } from '../helpers/plainNode';

const scenario = (openUrl: string, failThrows: boolean) => `
const { BrowserCallbackStrategy } = lib;
const seen = { thenCalls: 0, failCalls: 0 };
const factory = async (_options, use) => {
  let settle;
  const result = new Promise((resolve, reject) => { settle = { resolve, reject }; });
  setTimeout(() => settle.resolve('code'), 200);
  return use({
    port: 1,
    redirectUri: 'http://127.0.0.1:1/callback',
    waitForResult: () => result,
    fail: (error) => {
      seen.failCalls += 1;
      settle.reject(error);
      if (${failThrows}) throw new Error('fail threw: SECRET');
    },
  });
};
const strategy = new BrowserCallbackStrategy({ port: 0, callbackServer: factory, openUrl: ${openUrl} });
let outcome;
try {
  const answered = await strategy.authorize({
    buildAuthorizationUrl: async (uri) => 'https://idp.example/a?r=' + uri,
  });
  outcome = 'payload:' + answered.payload;
} catch (error) {
  outcome = errors.readFailure(error, 'unfamiliar-error').facts.outcome;
}
await new Promise((resolve) => setTimeout(resolve, 300));
report({ outcome, ...seen });
`;

const REJECTING = `async () => { throw new Error('launch: SECRET'); }`;
const THENABLE = `() => ({ then() { seen.thenCalls += 1; }, catch() { seen.thenCalls += 1; } })`;

describe('the launcher’s answer is handled natively, or not at all', () => {
  it.each([
    [
      'a rejecting launcher, fail() throws',
      REJECTING,
      true,
      { outcome: 'browser-launch-failed', thenCalls: 0, failCalls: 1 },
    ],
    [
      'a rejecting launcher',
      REJECTING,
      false,
      { outcome: 'browser-launch-failed', thenCalls: 0, failCalls: 1 },
    ],
    [
      'a launcher answering a foreign thenable',
      THENABLE,
      false,
      { outcome: 'payload:code', thenCalls: 0, failCalls: 0 },
    ],
    [
      'a launcher throwing synchronously, fail() throws',
      `() => { throw new Error('sync: SECRET'); }`,
      true,
      { outcome: 'browser-launch-failed', thenCalls: 0, failCalls: 1 },
    ],
  ] as const)(
    '%s: no unhandled rejection, the login ends as it should',
    (_name, openUrl, failThrows, expected) => {
      const run = runPlainNode<Record<string, unknown>>(
        scenario(openUrl, failThrows),
        { boundMs: 30_000 },
      );
      expect(run.timedOut).toBe(false);
      expect(run.result).toEqual(expected);
      expect(run.unhandled).toEqual([]);
    },
    60_000,
  );
});
