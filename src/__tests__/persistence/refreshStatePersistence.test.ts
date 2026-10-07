/**
 * `refreshStatePersistence(write, options)` alone (spec §6c.8, §6c.10
 * "`refreshStatePersistence`, alone"): the logical refresh state, pending
 * delivery of a failed new refresh token, `onWriteFailure`, and one write at
 * a time in report order — detached reports included. Reports are built by
 * hand; no provider runs here.
 */

import { describe, expect, it } from '@jest/globals';
import { readFailure } from '@mcp-abap-adt/auth-errors';
import type {
  PersistenceReport,
  ReportedCredential,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import {
  type PersistedTokens,
  refreshStatePersistence,
} from '../../persistence';
import { deferred, quiet, rejectionOf } from '../helpers/attemptHarness';

const credential = (access: string): ReportedCredential => ({
  authorizationToken: access,
  tokenType: 'jwt',
  authType: 'authorization_code',
  expiresAt: 1_900_000_000_000,
});

const fresh = (
  access: string,
  value: string,
  awaited = true,
): PersistenceReport => ({
  event: 'credential',
  credential: credential(access),
  refreshToken: { change: 'new', value },
  awaited,
});

const none = (access: string, awaited = true): PersistenceReport => ({
  event: 'credential',
  credential: credential(access),
  refreshToken: { change: 'none' },
  awaited,
});

const discarded = (access: string, awaited = true): PersistenceReport => ({
  event: 'refresh-token-discarded',
  credential: credential(access),
  awaited,
});

/** A store: every write, the stored refresh token as a fallback store keeps it. */
function store(fail: (tokens: PersistedTokens) => boolean = () => false) {
  const writes: PersistedTokens[] = [];
  const stored: { refreshToken?: string | undefined } = {};
  const write = async (tokens: PersistedTokens) => {
    writes.push(tokens);
    if (fail(tokens)) throw new Error('disk full: SECRET-WRITE-TEXT');
    if (tokens.refreshToken === null) stored.refreshToken = undefined;
    else if (tokens.refreshToken !== undefined) {
      stored.refreshToken = tokens.refreshToken;
    }
  };
  return { writes, stored, write };
}

const refreshOf = (writes: readonly PersistedTokens[]) =>
  writes.map((w) => w.refreshToken);

function recordingLogger() {
  const lines: { level: string; message: string; meta: unknown }[] = [];
  const at =
    (level: string) =>
    (message: string, meta?: unknown): void => {
      lines.push({ level, message, meta });
    };
  const logger: ILogger = {
    debug: at('debug'),
    info: at('info'),
    warn: at('warn'),
    error: at('error'),
  };
  return { lines, logger };
}

describe('refreshStatePersistence — the logical state', () => {
  it('new writes the token; none writes undefined while held and null after a discard', async () => {
    const s = store();
    const p = refreshStatePersistence(s.write, { onWriteFailure: 'fail' });
    await p.report(fresh('T1', 'R1'));
    await p.report(none('T2'));
    await p.report(discarded('T2'));
    await p.report(none('T3'));
    expect(refreshOf(s.writes)).toEqual(['R1', undefined, null, null]);
    // A store falling back to its stored refresh token never restores R1.
    expect(s.stored.refreshToken).toBeUndefined();
    // A new refresh token moves the state back to held.
    await p.report(fresh('T4', 'R4'));
    await p.report(none('T5'));
    expect(refreshOf(s.writes).slice(4)).toEqual(['R4', undefined]);
  });

  it('writes the reported credential with the refresh token decided', async () => {
    const s = store();
    const p = refreshStatePersistence(s.write, { onWriteFailure: 'fail' });
    await p.report(fresh('T1', 'R1'));
    expect(s.writes).toEqual([
      {
        authorizationToken: 'T1',
        tokenType: 'jwt',
        authType: 'authorization_code',
        expiresAt: 1_900_000_000_000,
        refreshToken: 'R1',
      },
    ]);
  });

  it('a discard before any credential report: the reported credential with null, nothing erased; a failed login after it leaves the refresh token cleared', async () => {
    const s = store();
    s.stored.refreshToken = 'SEEDED';
    const p = refreshStatePersistence(s.write, { onWriteFailure: 'fail' });
    await p.report(discarded(''));
    expect(s.writes).toEqual([
      {
        authorizationToken: '',
        tokenType: 'jwt',
        authType: 'authorization_code',
        expiresAt: 1_900_000_000_000,
        refreshToken: null,
      },
    ]);
    // The login that follows fails: no credential report — the stored
    // refresh token stays cleared.
    expect(s.stored.refreshToken).toBeUndefined();
  });
});

describe('refreshStatePersistence — pending delivery', () => {
  it('a failed null is written as null by the next report', async () => {
    let failNext = true;
    const s = store((t) => {
      const fail = failNext && t.refreshToken === null;
      failNext = false;
      return fail;
    });
    const p = refreshStatePersistence(s.write, { onWriteFailure: 'continue' });
    await p.report(discarded('T1'));
    await p.report(none('T2'));
    expect(refreshOf(s.writes)).toEqual([null, null]);
  });

  it('a failed new token is written again with that token by the next none report', async () => {
    let failures = 1;
    const s = store(() => failures-- > 0);
    const p = refreshStatePersistence(s.write, { onWriteFailure: 'continue' });
    await p.report(fresh('T1', 'R1'));
    await p.report(none('T2'));
    await p.report(none('T3'));
    // Delivered by the second report; the third has nothing pending.
    expect(refreshOf(s.writes)).toEqual(['R1', 'R1', undefined]);
    expect(s.stored.refreshToken).toBe('R1');
  });

  it('stays pending until one write succeeds', async () => {
    let failures = 2;
    const s = store(() => failures-- > 0);
    const p = refreshStatePersistence(s.write, { onWriteFailure: 'continue' });
    await p.report(fresh('T1', 'R1'));
    await p.report(none('T2'));
    await p.report(none('T3'));
    await p.report(none('T4'));
    expect(refreshOf(s.writes)).toEqual(['R1', 'R1', 'R1', undefined]);
  });

  it('a newer new supersedes a pending one', async () => {
    let failures = 1;
    const s = store(() => failures-- > 0);
    const p = refreshStatePersistence(s.write, { onWriteFailure: 'continue' });
    await p.report(fresh('T1', 'R1'));
    await p.report(fresh('T2', 'R2'));
    await p.report(none('T3'));
    expect(refreshOf(s.writes)).toEqual(['R1', 'R2', undefined]);
  });

  it('a discard supersedes a pending one', async () => {
    let failures = 1;
    const s = store(() => failures-- > 0);
    const p = refreshStatePersistence(s.write, { onWriteFailure: 'continue' });
    await p.report(fresh('T1', 'R1'));
    await p.report(discarded('T1'));
    await p.report(none('T2'));
    expect(refreshOf(s.writes)).toEqual(['R1', null, null]);
  });
});

describe('refreshStatePersistence — onWriteFailure', () => {
  it("'fail': an awaited report rethrows the write's failure, after recording it pending", async () => {
    let failures = 1;
    const s = store(() => failures-- > 0);
    const p = refreshStatePersistence(s.write, { onWriteFailure: 'fail' });
    const thrown = await rejectionOf(
      Promise.resolve(p.report(fresh('T1', 'R1'))),
    );
    expect(thrown).toBeInstanceOf(Error);
    expect((thrown as Error).message).toBe('disk full: SECRET-WRITE-TEXT');
    await p.report(none('T2'));
    expect(refreshOf(s.writes)).toEqual(['R1', 'R1']);
  });

  it("'fail': a detached report never throws, and its write is pending", async () => {
    let failures = 1;
    const s = store(() => failures-- > 0);
    const p = refreshStatePersistence(s.write, { onWriteFailure: 'fail' });
    await expect(
      Promise.resolve(p.report(fresh('T1', 'R1', false))),
    ).resolves.toBeUndefined();
    await p.report(none('T2'));
    expect(refreshOf(s.writes)).toEqual(['R1', 'R1']);
  });

  it("'continue': an awaited report never throws, and its write is pending", async () => {
    let failures = 1;
    const s = store(() => failures-- > 0);
    const p = refreshStatePersistence(s.write, { onWriteFailure: 'continue' });
    await expect(
      Promise.resolve(p.report(fresh('T1', 'R1'))),
    ).resolves.toBeUndefined();
    await p.report(none('T2'));
    expect(refreshOf(s.writes)).toEqual(['R1', 'R1']);
  });

  it('a write that throws synchronously is a failed write like any other', async () => {
    const write = (_tokens: PersistedTokens): Promise<void> => {
      throw new Error('sync: SECRET');
    };
    const p = refreshStatePersistence(write, { onWriteFailure: 'fail' });
    const thrown = await rejectionOf(
      Promise.resolve(p.report(fresh('T1', 'R1'))),
    );
    expect((thrown as Error).message).toBe('sync: SECRET');
  });

  it('a failed write is logged once in fixed words — no token, no message', async () => {
    const s = store(() => true);
    const { lines, logger } = recordingLogger();
    const p = refreshStatePersistence(s.write, {
      onWriteFailure: 'continue',
      logger,
    });
    await p.report(fresh('ACCESS-TOKEN-VALUE', 'REFRESH-TOKEN-VALUE'));
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatchObject({
      level: 'warn',
      message: '[refreshStatePersistence] Writing the tokens failed',
      meta: {
        error: 'persisting the tokens failed (unknown error)',
        kind: 'unknown',
      },
    });
    const text = JSON.stringify(lines);
    for (const secret of [
      'ACCESS-TOKEN-VALUE',
      'REFRESH-TOKEN-VALUE',
      'SECRET-WRITE-TEXT',
    ]) {
      expect(text).not.toContain(secret);
    }
  });

  it('a logger that throws changes nothing', async () => {
    let failures = 1;
    const s = store(() => failures-- > 0);
    const throwing: ILogger = {
      debug: () => undefined,
      info: () => undefined,
      warn: () => {
        throw new Error('logger: SECRET');
      },
      error: () => undefined,
    };
    const p = refreshStatePersistence(s.write, {
      onWriteFailure: 'fail',
      logger: throwing,
    });
    const thrown = await rejectionOf(
      Promise.resolve(p.report(fresh('T1', 'R1'))),
    );
    expect((thrown as Error).message).toBe('disk full: SECRET-WRITE-TEXT');
  });
});

describe('refreshStatePersistence — one write at a time, in report order', () => {
  it('a detached discard whose write is held open, then a newer credential report: the newer write starts after the held one settles', async () => {
    const held = deferred();
    const started: (string | null | undefined)[] = [];
    let active = 0;
    let most = 0;
    const stored: { refreshToken?: string | null | undefined } = {};
    const write = async (tokens: PersistedTokens) => {
      started.push(tokens.refreshToken);
      active += 1;
      most = Math.max(most, active);
      try {
        if (tokens.refreshToken === null) await held.promise;
        stored.refreshToken = tokens.refreshToken ?? stored.refreshToken;
      } finally {
        active -= 1;
      }
    };
    const p = refreshStatePersistence(write, { onWriteFailure: 'fail' });
    // Detached: the provider does not await it.
    void p.report(discarded('T1', false));
    const newer = Promise.resolve(p.report(fresh('T2', 'R2')));
    let newerSettled = false;
    void newer.then(() => {
      newerSettled = true;
    });
    await quiet();
    expect(started).toEqual([null]);
    expect(newerSettled).toBe(false);
    held.resolve();
    await newer;
    expect(started).toEqual([null, 'R2']);
    expect(most).toBe(1);
    expect(stored.refreshToken).toBe('R2');
    // The newer report's state: held, nothing pending — a none report
    // writes undefined, not null.
    await p.report(none('T3'));
    expect(started).toEqual([null, 'R2', undefined]);
  });

  it('a held failing write, then a none report: the none report sees the failure as pending', async () => {
    const held = deferred();
    const started: (string | null | undefined)[] = [];
    const write = async (tokens: PersistedTokens) => {
      started.push(tokens.refreshToken);
      if (started.length === 1) {
        await held.promise;
        throw new Error('late failure');
      }
    };
    const p = refreshStatePersistence(write, { onWriteFailure: 'continue' });
    void p.report(fresh('T1', 'R1', false));
    const second = Promise.resolve(p.report(none('T2')));
    await quiet();
    expect(started).toEqual(['R1']);
    held.resolve();
    await second;
    expect(started).toEqual(['R1', 'R1']);
  });

  it('an awaited report settles when its own turn ends, not before', async () => {
    const first = deferred();
    const second = deferred();
    const gates = [first, second];
    const write = async (_tokens: PersistedTokens) => {
      await gates.shift()?.promise;
    };
    const p = refreshStatePersistence(write, { onWriteFailure: 'fail' });
    const a = Promise.resolve(p.report(fresh('T1', 'R1')));
    const b = Promise.resolve(p.report(none('T2')));
    const done: string[] = [];
    void a.then(() => done.push('a'));
    void b.then(() => done.push('b'));
    first.resolve();
    await a;
    await quiet();
    expect(done).toEqual(['a']);
    second.resolve();
    await b;
    expect(done).toEqual(['a', 'b']);
  });
});

describe('refreshStatePersistence — construction', () => {
  const write = async (_tokens: PersistedTokens) => undefined;

  const expectInvalid = (build: () => unknown) => {
    let thrown: unknown;
    try {
      build();
    } catch (error) {
      thrown = error;
    }
    const error = readFailure(thrown, 'unfamiliar-error');
    expect(error.kind).toBe('configuration');
    expect(error.facts).toEqual({
      case: 'invalid-value',
      fields: ['persistence'],
    });
  };

  it('onWriteFailure is required, with no default', () => {
    expectInvalid(() =>
      refreshStatePersistence(write, {} as never as { onWriteFailure: 'fail' }),
    );
    expectInvalid(() => refreshStatePersistence(write, undefined as never));
    expectInvalid(() =>
      refreshStatePersistence(write, {
        onWriteFailure: 'retry',
      } as never),
    );
  });

  it('write must be a function', () => {
    expectInvalid(() =>
      refreshStatePersistence('nope' as never, { onWriteFailure: 'fail' }),
    );
  });

  it('an accessor on the options is never run', () => {
    let ran = false;
    const options = {};
    Object.defineProperty(options, 'onWriteFailure', {
      get() {
        ran = true;
        return 'fail';
      },
      enumerable: true,
    });
    expectInvalid(() => refreshStatePersistence(write, options as never));
    expect(ran).toBe(false);
  });
});
