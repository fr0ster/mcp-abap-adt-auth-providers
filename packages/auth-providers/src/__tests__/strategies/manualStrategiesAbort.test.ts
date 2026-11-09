/**
 * The manual strategies have no deadline of their own: a read ends
 * on its answer, the consumer's or the attempt's abort, or `dispose()` — and
 * the strategy settles only once the reader has released stdin (the
 * drain handoff).
 */

import assert from 'node:assert/strict';

import readline = require('node:readline');

import { afterEach, describe, it, mock } from 'node:test';
import { readFailure } from '@mcp-abap-adt/auth-errors';
import type { AuthorizationRequest } from '@mcp-abap-adt/interfaces-auth';
import { manualPasscodeStrategy } from '../../strategies/manualStrategies';
import { matchObject, thrown } from '../helpers/expectations';
import { type FakeTerminal, fakeTerminal } from '../helpers/fakeTerminal';

const request = {
  buildAuthorizationUrl: async () => 'https://uaa/passcode',
} as unknown as AuthorizationRequest;

const factsOf = (error: unknown) => readFailure(error, 'browser-login').facts;

/** Settles on the next turn of the event loop, never earlier. */
const turn = () => new Promise<void>((resolve) => setImmediate(resolve));

describe('manual strategies end on an abort, never on a clock', () => {
  it('a reader that never answers ends `aborted` (manual) when the consumer aborts', async () => {
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
    const rejected = assert.rejects(
      authorizing,
      thrown('the manual login was aborted'),
    );
    await turn();
    consumer.abort();
    await rejected;
    assert.deepEqual(factsOf(await authorizing.catch((e) => e)), {
      outcome: 'aborted',
      strategy: 'manual',
    });
    assert.equal(seen?.aborted, true);
  });

  it('dispose() resolves only once the pending authorize has already settled', async () => {
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
    assert.equal(settled, false);

    await strategy.dispose?.();

    assert.equal(settled, true);
    await assert.rejects(
      authorizing,
      thrown('the manual strategy was disposed'),
    );
  });

  it('a concurrent authorize is busy (one reader on stdin); dispose() ends the one in flight', async () => {
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
    assert.equal(signals.length, 1);
    assert.deepEqual(factsOf(await second), { outcome: 'busy' });

    await strategy.dispose?.();

    assert.deepEqual(
      signals.map((s) => s.aborted),
      [true],
    );
    assert.equal(settled, true);
    assert.deepEqual(factsOf(await first.catch((e) => e)), {
      outcome: 'disposed',
      strategy: 'manual',
    });
  });

  it('a disposed strategy refuses the next authorize', async () => {
    const strategy = manualPasscodeStrategy({ read: async () => 'code' });
    await strategy.dispose?.();
    await assert.rejects(
      strategy.authorize(request),
      thrown('the manual strategy was disposed'),
    );
  });

  it('without a signal there is no deadline — an answer still arrives', async () => {
    const strategy = manualPasscodeStrategy({ read: async () => ' 123456 ' });
    matchObject(await strategy.authorize(request), {
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
    assert.equal(settledAt, undefined);
    release();
    assert.deepEqual(factsOf(await authorizing), {
      outcome: 'aborted',
      strategy: 'manual',
    });
    assert.equal(settledAt, true);
  });
});

describe('the terminal reader', () => {
  let terminal: FakeTerminal | undefined;

  /**
   * The strategies over the fake terminal. terminalPaste reads
   * `createInterface` off the module object at each call, so the fake
   * replaces it with no fresh module registry.
   */
  async function freshStrategies(): Promise<
    typeof import('../../strategies/manualStrategies')
  > {
    terminal = fakeTerminal();
    mock.method(readline, 'createInterface', terminal.module.createInterface);
    mock.method(process.stderr, 'write', () => true);
    return await import('../../strategies/manualStrategies');
  }

  afterEach(() => {
    terminal?.restore();
    // The fake readline and the quiet stderr.
    mock.restoreAll();
    terminal = undefined;
  });

  it('closes its readline when aborted, and leaves no listener on stdin', async () => {
    const base = process.stdin.listenerCount('end');
    const { manualPasscodeStrategy: fresh } = await freshStrategies();
    const consumer = new AbortController();
    const authorizing = fresh({ signal: consumer.signal }).authorize(request);
    const rejected = assert.rejects(
      authorizing,
      thrown('the manual login was aborted'),
    );
    await turn();
    assert.equal(process.stdin.listenerCount('end'), base + 1);
    consumer.abort();
    await rejected;
    assert.equal(terminal?.readers[0]?.closed, true);
    assert.equal(process.stdin.listenerCount('end'), base);
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
    assert.equal(fake.readers[0]?.closeCalled, true);
    assert.equal(listenersAtSettle, undefined);
    fake.releaseClose();
    assert.deepEqual(factsOf(await authorizing), {
      outcome: 'aborted',
      strategy: 'manual',
    });
    assert.equal(listenersAtSettle, base);
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
    assert.deepEqual(factsOf(await authorizing.catch((e) => e)), {
      outcome: 'aborted',
      strategy: 'manual',
    });
    assert.equal(terminal?.readers.length, 0);
  });

  it('the reader itself, given an aborted signal, says the input was abandoned', async () => {
    const { readFromTerminal } = await freshStrategies();
    await assert.rejects(
      readFromTerminal('prompt', AbortSignal.abort()),
      thrown('the manual input was abandoned before it began'),
    );
    assert.equal(terminal?.readers.length, 0);
  });

  it('stdin ending without a line is no input', async () => {
    const { manualPasscodeStrategy: fresh } = await freshStrategies();
    const authorizing = fresh().authorize(request);
    const rejected = assert.rejects(
      authorizing,
      thrown('no input was received'),
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
    matchObject(await authorizing, { payload: '654321' });
    assert.equal(terminal?.readers[0]?.closed, true);
  });
});
