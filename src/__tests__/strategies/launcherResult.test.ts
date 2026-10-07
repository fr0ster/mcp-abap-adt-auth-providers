/**
 * Task 29 review, item 1, as the user decided on 2026-10-07: what the
 * launcher (`openUrl`) answers is the consumer's own code — adopted as
 * `await` would adopt it, so a native promise or any Promises/A+ thenable
 * that rejects (or whose `then` throws) is a launch failure, and one that
 * never settles is a launcher that succeeded. Since Task 30h a launch failure
 * ends nothing: the server's `fail()` is never called, the login waits for
 * its result (here the server's own, after 200 ms), and the failure raises no
 * `unhandledRejection`. Run under plain node in a child process, bounded by
 * the test.
 */

import { describe, expect, it } from '@jest/globals';
import { runPlainNode } from '../helpers/plainNode';

const scenario = (openUrl: string) => `
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
    },
  });
};
const strategy = new BrowserCallbackStrategy({ port: 0, stateGate: false, callbackServer: factory, openUrl: ${openUrl} });
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
const NEVER = `() => ({ then() { seen.thenCalls += 1; } })`;
const APLUS_REJECTING = `() => ({ then(_resolve, reject) { seen.thenCalls += 1; queueMicrotask(() => reject(new Error('launch: SECRET'))); } })`;
const THEN_THROWS = `() => ({ then() { seen.thenCalls += 1; throw new Error('then: SECRET'); } })`;

describe('the launcher’s answer is adopted, whatever promise it is', () => {
  it.each([
    [
      'a rejecting launcher',
      REJECTING,
      { outcome: 'payload:code', thenCalls: 0, failCalls: 0 },
    ],
    [
      'a launcher answering a thenable that never settles',
      NEVER,
      { outcome: 'payload:code', thenCalls: 1, failCalls: 0 },
    ],
    [
      'a launcher answering a rejecting Promises/A+ thenable',
      APLUS_REJECTING,
      { outcome: 'payload:code', thenCalls: 1, failCalls: 0 },
    ],
    [
      'a launcher answering a thenable whose then throws',
      THEN_THROWS,
      { outcome: 'payload:code', thenCalls: 1, failCalls: 0 },
    ],
    [
      'a launcher throwing synchronously',
      `() => { throw new Error('sync: SECRET'); }`,
      { outcome: 'payload:code', thenCalls: 0, failCalls: 0 },
    ],
  ] as const)(
    '%s: no unhandled rejection, fail() never called, the login waits for its result',
    (_name, openUrl, expected) => {
      const run = runPlainNode<Record<string, unknown>>(scenario(openUrl), {
        boundMs: 30_000,
      });
      expect(run.timedOut).toBe(false);
      expect(run.result).toEqual(expected);
      expect(run.unhandled).toEqual([]);
    },
    60_000,
  );
});
