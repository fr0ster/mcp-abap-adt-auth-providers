/**
 * Spec §8.1: the base owns the four moments, each inside auth-errors'
 * `guard`. Whatever a subclass controls — `grant()`, `getAuthType()`, a
 * `moments` getter, the operations it hands the constructor — is read inside
 * the boundary or validated once at construction, so every moment answers an
 * outcome (a minted refusal on failure) and never rejects.
 */
import { describe, expect, it } from '@jest/globals';
import { isMinted, OK } from '@mcp-abap-adt/auth-errors';
import type {
  AuthOutcome,
  IAuthProvider,
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces-auth';
import {
  AuthProviderBase,
  type MomentOperations,
} from '../../auth/AuthProviderBase';
import { BaseTokenProvider } from '../../index';
import { refreshThenLogin } from '../../renewal';
import { recordingTargets } from '../helpers/targets';

const MARKER = 'SECRET-MARKER';
const boom = () => {
  throw new Error(MARKER);
};

const OPERATIONS: MomentOperations = {
  prepare: 'loading-certificate',
  establish: 'presenting-certificate',
  authorize: 'writing-authorization-header',
  rejected: 'reading-rejection',
};

/** A provider whose every moment throws a foreign error. */
class Throwing extends AuthProviderBase {
  readonly kind = 'test';
  constructor(moments: MomentOperations = OPERATIONS) {
    super(moments);
  }
  protected onPrepare(): AuthOutcome {
    return boom();
  }
  protected onEstablish(): AuthOutcome {
    return boom();
  }
  protected onAuthorize(): AuthOutcome {
    return boom();
  }
  protected onRejected(): AuthOutcome {
    return boom();
  }
}

/** Every moment of a provider, with throwaway arguments. */
async function everyMoment(p: IAuthProvider) {
  const t = recordingTargets();
  return {
    prepare: await p.prepare(),
    establish: await p.establish(t.logonTarget),
    authorize: await p.authorize(t.requestTarget),
    rejected: await p.rejected({ at: 'request', status: 401, error: {} }),
  };
}

/** The refusal's facts, after checking it is minted and leaks nothing. */
function factsOf(outcome: AuthOutcome) {
  expect(outcome.ok).toBe(false);
  if (outcome.ok) throw new Error('unreachable');
  expect(isMinted(outcome.refusal)).toBe(true);
  expect(JSON.stringify(outcome)).not.toContain(MARKER);
  return (outcome.refusal as unknown as { kind: string; facts: object }).facts;
}

describe('AuthProviderBase (spec §8.1)', () => {
  it('a body that throws → unknown with the moment its operation names', async () => {
    const got = await everyMoment(new Throwing());
    expect(factsOf(got.prepare)).toEqual({ operation: 'loading-certificate' });
    expect(factsOf(got.establish)).toEqual({
      operation: 'presenting-certificate',
    });
    expect(factsOf(got.authorize)).toEqual({
      operation: 'writing-authorization-header',
    });
    expect(factsOf(got.rejected)).toEqual({ operation: 'reading-rejection' });
  });

  it('a throwing grant() → a minted refusal without a grant, every moment, never a rejection', async () => {
    class ThrowingGrant extends Throwing {
      protected override grant(): OAuth2GrantType | undefined {
        return boom();
      }
    }
    const got = await everyMoment(new ThrowingGrant());
    for (const outcome of Object.values(got)) {
      expect(factsOf(outcome)).not.toHaveProperty('grant');
    }
    expect(factsOf(got.prepare)).toEqual({ operation: 'loading-certificate' });
  });

  it('a grant() that answers is named in the refusal', async () => {
    class Granted extends Throwing {
      protected override grant(): OAuth2GrantType | undefined {
        return 'password';
      }
    }
    const got = await everyMoment(new Granted());
    expect(factsOf(got.prepare)).toEqual({
      operation: 'loading-certificate',
      grant: 'password',
    });
  });

  it('a throwing getAuthType() (BaseTokenProvider) → a minted refusal without a grant, never a rejection', async () => {
    class ThrowingAuthType extends BaseTokenProvider {
      protected performLogin(): Promise<ITokenResult> {
        return boom();
      }
      protected performRefresh(): Promise<ITokenResult> {
        return boom();
      }
      protected getAuthType(): OAuth2GrantType {
        return boom();
      }
    }
    const got = await everyMoment(
      new ThrowingAuthType({ renewal: refreshThenLogin() }),
    );
    for (const outcome of [got.prepare, got.authorize, got.rejected]) {
      expect(factsOf(outcome)).toEqual({ operation: 'token-request' });
    }
  });

  it('a subclass `moments` getter that throws changes nothing the base reads', async () => {
    class Shadowing extends Throwing {
      get moments(): MomentOperations {
        return boom();
      }
    }
    const got = await everyMoment(new Shadowing());
    expect(factsOf(got.prepare)).toEqual({ operation: 'loading-certificate' });
    expect(factsOf(got.rejected)).toEqual({ operation: 'reading-rejection' });
  });

  it('a moments object whose establish getter throws → establishing, the rest kept', async () => {
    const moments = {
      prepare: 'loading-certificate',
      get establish(): never {
        return boom();
      },
      authorize: 'writing-authorization-header',
      rejected: 'reading-rejection',
    } as MomentOperations;
    const got = await everyMoment(new Throwing(moments));
    expect(factsOf(got.establish)).toEqual({ operation: 'establishing' });
    expect(factsOf(got.prepare)).toEqual({ operation: 'loading-certificate' });
  });

  it('an operation off the list → the fallback of its moment', async () => {
    const moments = {
      prepare: 'not-an-operation',
      establish: 'presenting-certificate',
      authorize: 'writing-authorization-header',
      rejected: 'reading-rejection',
    } as unknown as MomentOperations;
    const got = await everyMoment(new Throwing(moments));
    expect(factsOf(got.prepare)).toEqual({ operation: 'preparing' });
  });

  it('a moments object that is not one, or whose every read throws → all four fallbacks', async () => {
    const hostile = new Proxy({}, { get: boom, has: boom, ownKeys: boom });
    for (const moments of [null, hostile, 'x']) {
      const got = await everyMoment(
        new Throwing(moments as unknown as MomentOperations),
      );
      expect(factsOf(got.prepare)).toEqual({ operation: 'preparing' });
      expect(factsOf(got.establish)).toEqual({ operation: 'establishing' });
      expect(factsOf(got.authorize)).toEqual({ operation: 'authorizing' });
      expect(factsOf(got.rejected)).toEqual({ operation: 'reading-rejection' });
    }
  });

  it('the operations are captured at construction: changing the object later changes nothing', async () => {
    const moments = { ...OPERATIONS };
    const p = new Throwing(moments);
    moments.prepare = 'refresh';
    expect(factsOf(await p.prepare())).toEqual({
      operation: 'loading-certificate',
    });
  });

  it('an answering body passes through: Ok is Ok', async () => {
    class Fine extends Throwing {
      protected override onPrepare(): AuthOutcome {
        return OK;
      }
    }
    await expect(new Fine().prepare()).resolves.toEqual({ ok: true });
  });
});

describe('the grant is read once per moment, inside the boundary', () => {
  /** Unhandled rejections seen while `run` settles, and a tick after. */
  async function unhandledDuring(run: () => Promise<unknown>) {
    const seen: unknown[] = [];
    const listener = (reason: unknown) => seen.push(reason);
    process.on('unhandledRejection', listener);
    try {
      await run();
      await new Promise((resolve) => setTimeout(resolve, 50));
    } finally {
      process.off('unhandledRejection', listener);
    }
    return seen;
  }

  const grantAnswers: Array<[string, () => unknown]> = [
    ['a rejecting promise', () => Promise.reject(new Error(MARKER))],
    [
      'a throw',
      () => {
        throw new Error(MARKER);
      },
    ],
  ];
  it.each(
    grantAnswers.flatMap(([name, answer]) =>
      (['throws', 'answers Ok'] as const).map(
        (body) => [name, body, answer] as const,
      ),
    ),
  )(
    'grant() answering %s, a body that %s: no unhandled rejection, one call per moment',
    async (_name, body, answer) => {
      let calls = 0;
      class Granting extends Throwing {
        protected override grant(): OAuth2GrantType | undefined {
          calls += 1;
          return answer() as never;
        }
        protected override onPrepare(): AuthOutcome {
          return body === 'throws' ? boom() : OK;
        }
        protected override onEstablish(): AuthOutcome {
          return body === 'throws' ? boom() : OK;
        }
        protected override onAuthorize(): AuthOutcome {
          return body === 'throws' ? boom() : OK;
        }
        protected override onRejected(): AuthOutcome {
          return body === 'throws' ? boom() : OK;
        }
      }
      const p = new Granting();
      const outcomes: AuthOutcome[] = [];
      const seen = await unhandledDuring(async () => {
        const t = recordingTargets();
        outcomes.push(await p.prepare());
        outcomes.push(await p.establish(t.logonTarget));
        outcomes.push(await p.authorize(t.requestTarget));
        outcomes.push(
          await p.rejected({ at: 'request', status: 401, error: {} }),
        );
      });
      expect(seen).toEqual([]);
      expect(calls).toBe(4);
      for (const outcome of outcomes) {
        // A throwing grant() refuses the moment; a rejecting promise is no
        // grant, and the body decides.
        if (body === 'throws' || answer === grantAnswers[1]?.[1]) {
          expect(factsOf(outcome)).not.toHaveProperty('grant');
        } else {
          expect(outcome).toEqual({ ok: true });
        }
      }
    },
  );

  // Task 27: the ladder is gone; auth-errors' guard reads the grant once and
  // classify names it beside the thrown value's allowlisted facts.
  it('a foreign throw by the body names the grant read once', async () => {
    let calls = 0;
    class Ladder extends Throwing {
      protected override grant(): OAuth2GrantType | undefined {
        calls += 1;
        return 'password';
      }
      protected override onPrepare(): AuthOutcome {
        throw Object.assign(new Error(MARKER), { code: 'ECONNRESET' });
      }
    }
    expect(factsOf(await new Ladder().prepare())).toEqual({
      operation: 'loading-certificate',
      grant: 'password',
      code: 'ECONNRESET',
    });
    expect(calls).toBe(1);
  });

  it('getAuthType() answering a rejecting promise (BaseTokenProvider): no unhandled rejection, one call per moment', async () => {
    let calls = 0;
    class Rejecting extends BaseTokenProvider {
      protected performLogin(): Promise<ITokenResult> {
        return boom();
      }
      protected performRefresh(): Promise<ITokenResult> {
        return boom();
      }
      protected getAuthType(): OAuth2GrantType {
        calls += 1;
        return Promise.reject(new Error(MARKER)) as never;
      }
    }
    const p = new Rejecting({ renewal: refreshThenLogin() });
    let outcome: AuthOutcome | undefined;
    const seen = await unhandledDuring(async () => {
      outcome = await p.prepare();
    });
    expect(seen).toEqual([]);
    expect(calls).toBe(1);
    if (!outcome) throw new Error('unreachable');
    expect(factsOf(outcome)).toEqual({ operation: 'token-request' });
  });
});
