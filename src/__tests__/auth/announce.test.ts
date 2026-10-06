/**
 * A prompt must not vanish (CLAUDE.md "Nothing writes to process.stdout";
 * Task 23 fix round 1, item 8): `announcer` writes to the logger's `info`,
 * and to stderr — never stdout — when there is no logger, when `info`
 * throws, or when `info` answers a native promise that rejects. A logger
 * that took the prompt gets no stderr copy, and a foreign thenable's code
 * is never run.
 */

import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  jest,
} from '@jest/globals';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { announcer } from '../../auth/announce';

const PROMPT = 'Enter code: UC-42';

let stderr: string[];
let stdout: string[];
let restore: Array<() => void>;

beforeEach(() => {
  stderr = [];
  stdout = [];
  const e = jest
    .spyOn(process.stderr, 'write')
    .mockImplementation((c: unknown) => {
      stderr.push(String(c));
      return true;
    });
  const o = jest
    .spyOn(process.stdout, 'write')
    .mockImplementation((c: unknown) => {
      stdout.push(String(c));
      return true;
    });
  restore = [() => e.mockRestore(), () => o.mockRestore()];
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
    expect(stderr).toEqual([`${PROMPT}\n`]);
    expect(stdout).toEqual([]);
  });

  it('a logger that takes it: no stderr copy', async () => {
    const seen: string[] = [];
    announcer(loggerWith((m) => seen.push(m)))(PROMPT);
    announcer(loggerWith(async (m) => seen.push(m)))(PROMPT);
    await turn();
    expect(seen).toEqual([PROMPT, PROMPT]);
    expect(stderr).toEqual([]);
  });

  it('a logger whose info throws: stderr', () => {
    announcer(
      loggerWith(() => {
        throw new Error('info threw');
      }),
    )(PROMPT);
    expect(stderr).toEqual([`${PROMPT}\n`]);
  });

  it('an async logger whose info rejects: stderr once the rejection arrives', async () => {
    announcer(
      loggerWith(async () => {
        throw new Error('async info');
      }),
    )(PROMPT);
    await turn();
    expect(stderr).toEqual([`${PROMPT}\n`]);
    expect(stdout).toEqual([]);
  });

  it('a foreign thenable: its then never runs, nothing on stderr', async () => {
    const then = jest.fn();
    announcer(loggerWith(() => ({ then })))(PROMPT);
    await turn();
    expect(then).not.toHaveBeenCalled();
    expect(stderr).toEqual([]);
  });
});
