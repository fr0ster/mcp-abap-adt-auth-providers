/**
 * Drain handoff with a manual strategy: with the old reader's close
 * deliberately held, every waiter of a login aborts and a new attempt arrives
 * at once — the new attempt's reader opens only after the old one is closed.
 * Never two readers on stdin, asserted on stdin's listener count.
 */

import assert from 'node:assert/strict';

import readline = require('node:readline');

import { afterEach, describe, it, mock } from 'node:test';
import { readFailure } from '@mcp-abap-adt/auth-errors';
import { refreshThenLogin } from '../../renewal';
import { matchObject } from '../helpers/expectations';
import { type FakeTerminal, fakeTerminal } from '../helpers/fakeTerminal';

const turn = () => new Promise<void>((resolve) => setImmediate(resolve));

async function turns(n: number): Promise<void> {
  for (let i = 0; i < n; i++) await turn();
}

describe('drain handoff: a manual strategy', () => {
  let terminal: FakeTerminal | undefined;

  afterEach(() => {
    terminal?.restore();
    // The fake readline and the quiet stderr.
    mock.restoreAll();
  });

  it('the next attempt opens its reader only after the aborted one has closed', async () => {
    const base = process.stdin.listenerCount('end');
    terminal = fakeTerminal();
    // terminalPaste reads `createInterface` off the module object at each
    // call, so the fake replaces it with no fresh module registry.
    mock.method(readline, 'createInterface', terminal.module.createInterface);
    mock.method(process.stderr, 'write', () => true);
    const { UaaPasscodeProvider } = await import(
      '../../providers/UaaPasscodeProvider'
    );
    const { manualPasscodeStrategy } = await import(
      '../../strategies/manualStrategies'
    );
    const provider = new UaaPasscodeProvider({
      renewal: refreshThenLogin(),
      uaaUrl: 'https://uaa.example',
      clientId: 'cf',
      clientSecret: '',
      authorization: manualPasscodeStrategy(),
    });

    const first = new AbortController();
    const firstCall = provider
      .getTokens({ signal: first.signal })
      .catch((e: unknown) => e);
    while (terminal.readers.length < 1) await turn();
    assert.equal(process.stdin.listenerCount('end'), base + 1);

    // The old reader's close is held; every waiter aborts; a new attempt
    // arrives at once.
    terminal.holdClose = true;
    first.abort();
    const second = new AbortController();
    const secondCall = provider
      .getTokens({ signal: second.signal })
      .catch((e: unknown) => e);
    matchObject(readFailure(await firstCall, 'unfamiliar-error').facts, {
      outcome: 'aborted',
    });
    await turns(20);
    // Waiting for the drain: no second reader while the first holds stdin.
    assert.equal(terminal.readers.length, 1);
    assert.equal(terminal.readers[0]?.closeCalled, true);

    terminal.holdClose = false;
    terminal.releaseClose();
    while (terminal.readers.length < 2) await turn();
    // The second reader opened on a stdin the first had already left.
    assert.deepEqual(terminal.listenersAtOpen, [base, base]);
    assert.equal(process.stdin.listenerCount('end'), base + 1);

    second.abort();
    matchObject(readFailure(await secondCall, 'unfamiliar-error').facts, {
      outcome: 'aborted',
    });
    while (!terminal.readers[1]?.closed) await turn();
    assert.equal(process.stdin.listenerCount('end'), base);
  });
});
