/**
 * Controller addition after Task 23: a consumer's callback-server factory
 * whose `waitForResult()` answers a promise that rejects at once — and that
 * the factory did not mark handled, against the contract's advice — must not
 * raise `unhandledRejection` when the strategy never reaches its `await` (a
 * launcher that throws synchronously, or answers something that is not a
 * promise). The strategy marks the promise it holds handled — a plain native
 * promise only: a foreign thenable's code is never run. Run under plain node
 * in a child process, where an unhandled rejection is recorded rather than
 * hidden by Jest.
 */

import { describe, expect, it } from '@jest/globals';
import { runPlainNode } from '../helpers/plainNode';

const scenario = (openUrl: string, result: string) => `
const { BrowserCallbackStrategy } = lib;
const seen = { thenRan: false };
const factory = async (_options, use) =>
  use({
    port: 1,
    redirectUri: 'http://127.0.0.1:1/callback',
    waitForResult: () => ${result},
    fail: () => undefined,
  });
const strategy = new BrowserCallbackStrategy({
  port: 0,
  callbackServer: factory,
  openUrl: ${openUrl},
});
let kind;
try {
  await strategy.authorize({
    buildAuthorizationUrl: async (uri) => 'https://idp.example/a?r=' + uri,
  });
  kind = 'resolved';
} catch (error) {
  kind = errors.readFailure(error, 'unfamiliar-error').kind;
}
report({ kind, thenRan: seen.thenRan });
`;

const REJECTING = `Promise.reject(new Error('early: SECRET'))`;

describe('a callback server whose result rejects early, never awaited', () => {
  it.each([
    [
      'a launcher that throws synchronously',
      `() => { throw new Error('sync'); }`,
    ],
    ['a launcher that answers no promise', `() => undefined`],
  ])('%s: no unhandled rejection', (_name, openUrl) => {
    const run = runPlainNode<{ kind: string; thenRan: boolean }>(
      scenario(openUrl, REJECTING),
    );
    expect(run.stderr).toBe('');
    expect(run.result).toEqual({ kind: 'interactive-login', thenRan: false });
    expect(run.unhandled).toEqual([]);
  });

  it('a foreign thenable as the result: its then is never run by the marking', () => {
    const run = runPlainNode<{ kind: string; thenRan: boolean }>(
      scenario(
        `() => { throw new Error('sync'); }`,
        `({ then() { seen.thenRan = true; } })`,
      ),
    );
    expect(run.stderr).toBe('');
    expect(run.result).toEqual({ kind: 'interactive-login', thenRan: false });
    expect(run.unhandled).toEqual([]);
  });
});
