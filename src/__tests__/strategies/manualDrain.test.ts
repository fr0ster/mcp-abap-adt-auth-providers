/**
 * Drain handoff with a manual strategy (spec §6b; plan Task 23, moved from
 * Task 22a, C7): with the old reader's close deliberately held, every waiter
 * of a login aborts and a new attempt arrives at once — the new attempt's
 * reader opens only after the old one is closed. Never two readers on stdin,
 * asserted on stdin's listener count.
 */

import { afterEach, describe, expect, it, jest } from '@jest/globals';
import { readFailure } from '@mcp-abap-adt/auth-errors';
import { refreshThenLogin } from '../../renewal';
import { type FakeTerminal, fakeTerminal } from '../helpers/fakeTerminal';

const turn = () => new Promise<void>((resolve) => setImmediate(resolve));

async function turns(n: number): Promise<void> {
  for (let i = 0; i < n; i++) await turn();
}

describe('drain handoff: a manual strategy', () => {
  let terminal: FakeTerminal | undefined;
  let stderr: { mockRestore(): void } | undefined;

  afterEach(() => {
    terminal?.restore();
    stderr?.mockRestore();
    jest.dontMock('node:readline');
  });

  it('the next attempt opens its reader only after the aborted one has closed', async () => {
    const base = process.stdin.listenerCount('end');
    terminal = fakeTerminal();
    const mocked = terminal.module;
    jest.resetModules();
    jest.doMock('node:readline', () => mocked);
    stderr = jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
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
    expect(process.stdin.listenerCount('end')).toBe(base + 1);

    // The old reader's close is held; every waiter aborts; a new attempt
    // arrives at once.
    terminal.holdClose = true;
    first.abort();
    const second = new AbortController();
    const secondCall = provider
      .getTokens({ signal: second.signal })
      .catch((e: unknown) => e);
    expect(
      readFailure(await firstCall, 'unfamiliar-error').facts,
    ).toMatchObject({ outcome: 'aborted' });
    await turns(20);
    // Waiting for the drain: no second reader while the first holds stdin.
    expect(terminal.readers).toHaveLength(1);
    expect(terminal.readers[0]?.closeCalled).toBe(true);

    terminal.holdClose = false;
    terminal.releaseClose();
    while (terminal.readers.length < 2) await turn();
    // The second reader opened on a stdin the first had already left.
    expect(terminal.listenersAtOpen).toEqual([base, base]);
    expect(process.stdin.listenerCount('end')).toBe(base + 1);

    second.abort();
    expect(
      readFailure(await secondCall, 'unfamiliar-error').facts,
    ).toMatchObject({ outcome: 'aborted' });
    while (!terminal.readers[1]?.closed) await turn();
    expect(process.stdin.listenerCount('end')).toBe(base);
  });
});
