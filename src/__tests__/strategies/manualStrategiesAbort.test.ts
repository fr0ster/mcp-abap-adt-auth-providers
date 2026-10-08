/**
 * The manual strategies have no deadline of their own (spec §6a): a read ends
 * on its answer, the consumer's or the attempt's abort, or `dispose()` — and
 * the strategy settles only once the reader has released stdin (§6b, the
 * drain handoff). The words are the K12–K16 rows.
 */

import { afterEach, describe, expect, it, jest } from '@jest/globals';
import { readFailure } from '@mcp-abap-adt/auth-errors';
import type { AuthorizationRequest } from '@mcp-abap-adt/interfaces-auth';
import { manualPasscodeStrategy } from '../../strategies/manualStrategies';
import { type FakeTerminal, fakeTerminal } from '../helpers/fakeTerminal';

const request = {
  buildAuthorizationUrl: async () => 'https://uaa/passcode',
} as unknown as AuthorizationRequest;

const factsOf = (error: unknown) => readFailure(error, 'browser-login').facts;

/** Settles on the next turn of the event loop, never earlier. */
const turn = () => new Promise<void>((resolve) => setImmediate(resolve));

describe('manual strategies end on an abort, never on a clock', () => {
  it('K4: a reader that never answers ends `aborted` (manual) when the consumer aborts', async () => {
    let seen: AbortSignal | undefined;
    const consumer = new AbortController();
    const strategy = manualPasscodeStrategy({
      signal: consumer.signal,
      read: (_prompt, signal) => {
        seen = signal;
        return new Promise<string>((_resolve, reject) => {
          signal.addEventListener('abort', () => reject(new Error('gone')));
        });
      },
    });
    const authorizing = strategy.authorize(request);
    const rejected = expect(authorizing).rejects.toThrow(
      'the manual login was aborted',
    );
    await turn();
    consumer.abort();
    await rejected;
    expect(factsOf(await authorizing.catch((e) => e))).toEqual({
      outcome: 'aborted',
      strategy: 'manual',
    });
    expect(seen?.aborted).toBe(true);
  });

  it('K15: dispose() resolves only once the pending authorize has already settled', async () => {
    let settled = false;
    const strategy = manualPasscodeStrategy({
      read: (_prompt, signal) =>
        new Promise<string>((_resolve, reject) => {
          signal.addEventListener('abort', () => reject(new Error('gone')));
        }),
    });
    const authorizing = strategy.authorize(request);
    authorizing.then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      },
    );
    await turn();
    expect(settled).toBe(false);

    await strategy.dispose?.();

    expect(settled).toBe(true);
    await expect(authorizing).rejects.toThrow(
      'the manual strategy was disposed',
    );
  });

  it('K15: a concurrent authorize is busy (one reader on stdin); dispose() ends the one in flight', async () => {
    const signals: AbortSignal[] = [];
    const strategy = manualPasscodeStrategy({
      read: (_prompt, signal) => {
        signals.push(signal);
        return new Promise<string>((_resolve, reject) => {
          signal.addEventListener('abort', () => reject(new Error('gone')));
        });
      },
    });
    let settled = false;
    const first = strategy.authorize(request);
    first.then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      },
    );
    const second = strategy.authorize(request).catch((e: unknown) => e);
    await turn(); // the first read begins
    expect(signals).toHaveLength(1);
    expect(factsOf(await second)).toEqual({ outcome: 'busy' });

    await strategy.dispose?.();

    expect(signals.map((s) => s.aborted)).toEqual([true]);
    expect(settled).toBe(true);
    expect(factsOf(await first.catch((e) => e))).toEqual({
      outcome: 'disposed',
      strategy: 'manual',
    });
  });

  it('K15: a disposed strategy refuses the next authorize', async () => {
    const strategy = manualPasscodeStrategy({ read: async () => 'code' });
    await strategy.dispose?.();
    await expect(strategy.authorize(request)).rejects.toThrow(
      'the manual strategy was disposed',
    );
  });

  it('without a signal there is no deadline — an answer still arrives', async () => {
    const strategy = manualPasscodeStrategy({ read: async () => ' 123456 ' });
    await expect(strategy.authorize(request)).resolves.toMatchObject({
      payload: '123456',
    });
  });

  it('settles only once a slow reader has released, never at the abort alone', async () => {
    let release!: () => void;
    let released = false;
    const consumer = new AbortController();
    const strategy = manualPasscodeStrategy({
      signal: consumer.signal,
      read: (_prompt, signal) =>
        new Promise<string>((_resolve, reject) => {
          signal.addEventListener('abort', () => {
            release = () => {
              released = true;
              reject(new Error('closed'));
            };
          });
        }),
    });
    let settledAt: boolean | undefined;
    const authorizing = strategy.authorize(request).catch((error) => {
      settledAt = released;
      return error;
    });
    await turn();
    consumer.abort();
    await turn();
    await turn();
    expect(settledAt).toBeUndefined();
    release();
    expect(factsOf(await authorizing)).toEqual({
      outcome: 'aborted',
      strategy: 'manual',
    });
    expect(settledAt).toBe(true);
  });
});

describe('the terminal reader', () => {
  let terminal: FakeTerminal | undefined;
  let stderr: { mockRestore(): void } | undefined;

  async function freshStrategies(): Promise<
    typeof import('../../strategies/manualStrategies')
  > {
    terminal = fakeTerminal();
    const mocked = terminal.module;
    jest.resetModules();
    jest.doMock('node:readline', () => mocked);
    stderr = jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
    return await import('../../strategies/manualStrategies');
  }

  afterEach(() => {
    terminal?.restore();
    stderr?.mockRestore();
    jest.dontMock('node:readline');
    terminal = undefined;
  });

  it('closes its readline when aborted, and leaves no listener on stdin', async () => {
    const base = process.stdin.listenerCount('end');
    const { manualPasscodeStrategy: fresh } = await freshStrategies();
    const consumer = new AbortController();
    const authorizing = fresh({ signal: consumer.signal }).authorize(request);
    const rejected = expect(authorizing).rejects.toThrow(
      'the manual login was aborted',
    );
    await turn();
    expect(process.stdin.listenerCount('end')).toBe(base + 1);
    consumer.abort();
    await rejected;
    expect(terminal?.readers[0]?.closed).toBe(true);
    expect(process.stdin.listenerCount('end')).toBe(base);
  });

  it('settle after release: a held close holds the rejection exactly that long', async () => {
    const base = process.stdin.listenerCount('end');
    const { manualPasscodeStrategy: fresh } = await freshStrategies();
    const fake = terminal as FakeTerminal;
    fake.holdClose = true;
    const consumer = new AbortController();
    let listenersAtSettle: number | undefined;
    const authorizing = fresh({ signal: consumer.signal })
      .authorize(request)
      .catch((error: unknown) => {
        listenersAtSettle = process.stdin.listenerCount('end');
        return error;
      });
    await turn();
    consumer.abort();
    for (let i = 0; i < 5; i++) await turn();
    expect(fake.readers[0]?.closeCalled).toBe(true);
    expect(listenersAtSettle).toBeUndefined();
    fake.releaseClose();
    expect(factsOf(await authorizing)).toEqual({
      outcome: 'aborted',
      strategy: 'manual',
    });
    expect(listenersAtSettle).toBe(base);
  });

  it('given an already-aborted signal opens no readline', async () => {
    const { manualPasscodeStrategy: fresh } = await freshStrategies();
    const consumer = new AbortController();
    // The abort lands while the URL is still being built.
    let built: () => void = () => {};
    const slow = {
      buildAuthorizationUrl: () =>
        new Promise<string>((resolve) => {
          built = () => resolve('https://uaa/passcode');
        }),
    } as unknown as AuthorizationRequest;
    const authorizing = fresh({ signal: consumer.signal }).authorize(slow);
    await turn();
    consumer.abort();
    built();
    expect(factsOf(await authorizing.catch((e) => e))).toEqual({
      outcome: 'aborted',
      strategy: 'manual',
    });
    expect(terminal?.readers).toHaveLength(0);
  });

  it('K12: the reader itself, given an aborted signal, says the input was abandoned', async () => {
    const { readFromTerminal } = await freshStrategies();
    await expect(
      readFromTerminal('prompt', AbortSignal.abort()),
    ).rejects.toThrow('the manual input was abandoned before it began');
    expect(terminal?.readers).toHaveLength(0);
  });

  it('K14: stdin ending without a line is no input', async () => {
    const { manualPasscodeStrategy: fresh } = await freshStrategies();
    const authorizing = fresh().authorize(request);
    const rejected = expect(authorizing).rejects.toThrow(
      'no input was received',
    );
    await turn();
    // The terminal closes (Ctrl+D): the interface ends with no line.
    terminal?.readers[0]?.end();
    await rejected;
  });

  it('answers the line typed, trimmed', async () => {
    const { manualPasscodeStrategy: fresh } = await freshStrategies();
    const authorizing = fresh().authorize(request);
    await turn();
    terminal?.readers[0]?.type('  654321  ');
    await expect(authorizing).resolves.toMatchObject({ payload: '654321' });
    expect(terminal?.readers[0]?.closed).toBe(true);
  });
});
