/**
 * A prompt must not vanish (CLAUDE.md "Nothing writes to process.stdout"):
 * `announcer` writes to the logger's `info`, and to stderr — never stdout —
 * when there is no logger, when `info` throws, or when `info` answers a native
 * promise that rejects. A logger that took the prompt gets no stderr copy, and
 * a foreign thenable's code is never run. That nothing in src writes to
 * stdout is checked statically (`noStdoutSources.test.ts`).
 */

import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it, mock } from 'node:test';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { announcer } from '../../auth/announce';

const PROMPT = 'Enter code: UC-42';

let stderr: string[];
let restore: Array<() => void>;

beforeEach(() => {
  stderr = [];
  const e = mock.method(process.stderr, 'write', (c: unknown) => {
    stderr.push(String(c));
    return true;
  });
  restore = [() => e.mock.restore()];
});

afterEach(() => {
  for (const undo of restore) undo();
});

const turn = () => new Promise<void>((resolve) => setImmediate(resolve));

const loggerWith = (info: (msg: string) => unknown): ILogger =>
  ({
    debug: () => undefined,
    info,
    warn: () => undefined,
    error: () => undefined,
  }) as unknown as ILogger;

describe('announcer', () => {
  it('without a logger: stderr', () => {
    announcer()(PROMPT);
    assert.deepEqual(stderr, [`${PROMPT}\n`]);
  });

  it('a logger that takes it: no stderr copy', async () => {
    const seen: string[] = [];
    announcer(loggerWith((m) => seen.push(m)))(PROMPT);
    announcer(loggerWith(async (m) => seen.push(m)))(PROMPT);
    await turn();
    assert.deepEqual(seen, [PROMPT, PROMPT]);
    assert.deepEqual(stderr, []);
  });

  it('a logger whose info throws: stderr', () => {
    announcer(
      loggerWith(() => {
        throw new Error('info threw');
      }),
    )(PROMPT);
    assert.deepEqual(stderr, [`${PROMPT}\n`]);
  });
});
