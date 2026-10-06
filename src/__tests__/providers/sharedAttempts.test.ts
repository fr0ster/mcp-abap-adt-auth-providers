/**
 * Waiters, not owners (spec §6b): a renewal is a shared attempt; each caller
 * of `getTokens({ signal })` / `refreshTokens({ signal })` is a waiter with
 * its own signal, and a login a moment starts waits on the provider's
 * attached parties. One waiter's abort releases only that waiter; the
 * attempt is aborted when every waiter has. Run on a real token endpoint
 * (loopback) and a strategy that waits until answered or aborted; the
 * callback port, where one is bound, is asserted by binding it afterwards.
 */

import { getEventListeners } from 'node:events';
import * as net from 'node:net';
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  jest,
} from '@jest/globals';
import { readFailure } from '@mcp-abap-adt/auth-errors';
import type {
  AuthorizationOutcome,
  AuthorizationRequest,
  IAuthorizationStrategy,
  ICertificateMaterial,
  IClientAuthentication,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { AuthorizationCodeProvider } from '../../providers/AuthorizationCodeProvider';
import { browserCallbackStrategy } from '../../strategies';
import {
  deferred,
  jwt,
  rejectionOf,
  settle,
  startTokenServer,
  type TokenServer,
  waitingStrategy,
} from '../helpers/attemptHarness';
import { certificate } from '../helpers/certificates';
import { getAvailablePort } from '../helpers/netHelpers';

const silent: ILogger = {
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
};

const refused = { at: 'request' as const, status: 401, error: {} };

/** `interactive-login` `aborted`, read from a thrown failure or a refusal. */
function isAborted(error: unknown): boolean {
  const read = readFailure(error, 'unfamiliar-error');
  return (
    read.kind === 'interactive-login' &&
    (read.facts as { outcome?: string }).outcome === 'aborted'
  );
}

let server: TokenServer;
let logins = 0;

beforeEach(async () => {
  logins = 0;
  server = await startTokenServer((request) => {
    logins += 1;
    request.answer(200, {
      access_token: jwt(`login-${logins}`),
      refresh_token: `R-${logins}`,
    });
  });
});
afterEach(async () => {
  await server.close();
});

function provider(
  authorization: IAuthorizationStrategy<string>,
  extra: { signal?: AbortSignal } = {},
): AuthorizationCodeProvider {
  return new AuthorizationCodeProvider({
    uaaUrl: server.url,
    clientId: 'cid',
    clientSecret: 'sec',
    authorization,
    logger: silent,
    ...extra,
  });
}

/** A browser strategy on a fixed port, its every authorize observed. */
async function browserOnPort() {
  const port = await getAvailablePort();
  const inner = browserCallbackStrategy({
    port,
    browser: 'none',
    openUrl: async () => undefined,
  });
  const settledCalls: Promise<void>[] = [];
  const signals: (AbortSignal | undefined)[] = [];
  const bound = deferred<void>();
  const strategy: IAuthorizationStrategy<string> = {
    authorize(request: AuthorizationRequest) {
      signals.push((request as { signal?: AbortSignal }).signal);
      const observed: AuthorizationRequest = {
        ...request,
        buildAuthorizationUrl: async (redirectUri) => {
          bound.resolve();
          return request.buildAuthorizationUrl(redirectUri);
        },
      };
      const outcome = inner.authorize({
        ...observed,
        ...{ signal: (request as { signal?: AbortSignal }).signal },
      } as AuthorizationRequest);
      settledCalls.push(
        outcome.then(
          () => undefined,
          () => undefined,
        ),
      );
      return outcome as Promise<AuthorizationOutcome<string>>;
    },
  };
  return { port, strategy, settledCalls, signals, bound: bound.promise };
}

/** True when the test can bind `port` itself: the login released it. */
function canBind(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const probe = net.createServer();
    probe.once('error', () => resolve(false));
    probe.listen(port, '127.0.0.1', () => probe.close(() => resolve(true)));
  });
}

describe('two getTokens callers with separate signals share one login', () => {
  it('the first aborts: it alone rejects aborted; the second gets the token of the same login', async () => {
    const strategy = waitingStrategy();
    const p = provider(strategy);
    const first = new AbortController();
    const second = new AbortController();
    const one = rejectionOf(p.getTokens({ signal: first.signal }));
    const two = p.getTokens({ signal: second.signal });
    const call = await strategy.nth(1);

    first.abort();
    expect(isAborted(await one)).toBe(true);
    expect(call.signal?.aborted).toBe(false);

    call.answer('code-1');
    const tokens = await two;
    expect(tokens.refreshToken).toBe('R-1');
    expect(strategy.calls).toHaveLength(1);
    expect(server.requests).toHaveLength(1);
    expect(server.requests[0]?.params.get('code')).toBe('code-1');
    expect(call.signal?.aborted).toBe(false);
  });

  it('the same through refreshTokens', async () => {
    const strategy = waitingStrategy();
    const p = provider(strategy);
    const first = new AbortController();
    const one = rejectionOf(p.refreshTokens({ signal: first.signal }));
    const two = p.refreshTokens({ signal: new AbortController().signal });
    const call = await strategy.nth(1);
    first.abort();
    expect(isAborted(await one)).toBe(true);
    call.answer('code-1');
    await expect(two).resolves.toMatchObject({ refreshToken: 'R-1' });
    expect(strategy.calls).toHaveLength(1);
  });

  it('both abort: the strategy signal aborts and the callback port is free afterwards', async () => {
    const { port, strategy, settledCalls, signals, bound } =
      await browserOnPort();
    const p = provider(strategy);
    const first = new AbortController();
    const second = new AbortController();
    const one = rejectionOf(p.getTokens({ signal: first.signal }));
    const two = rejectionOf(p.getTokens({ signal: second.signal }));
    await bound;
    expect(await canBind(port)).toBe(false);

    first.abort();
    expect(isAborted(await one)).toBe(true);
    expect(signals[0]?.aborted).toBe(false);
    second.abort();
    expect(isAborted(await two)).toBe(true);
    expect(signals[0]?.aborted).toBe(true);
    await settledCalls[0];
    expect(await canBind(port)).toBe(true);
    expect(server.requests).toHaveLength(0);
  });

  it('an aborted attempt is not reused: the next getTokens starts a new login', async () => {
    const strategy = waitingStrategy();
    const p = provider(strategy);
    const only = new AbortController();
    const aborted = rejectionOf(p.getTokens({ signal: only.signal }));
    const first = await strategy.nth(1);
    only.abort();
    expect(isAborted(await aborted)).toBe(true);
    expect(first.signal?.aborted).toBe(true);

    const next = p.getTokens();
    const second = await strategy.nth(2);
    expect(second.signal?.aborted).toBe(false);
    second.answer('code-2');
    await expect(next).resolves.toMatchObject({ refreshToken: 'R-1' });
    expect(server.requests.map((r) => r.params.get('code'))).toEqual([
      'code-2',
    ]);
  });

  it('a caller without a signal beside one that aborts: the login continues', async () => {
    const strategy = waitingStrategy();
    const p = provider(strategy);
    const signalled = new AbortController();
    const one = rejectionOf(p.getTokens({ signal: signalled.signal }));
    const unsignalled = p.getTokens();
    const call = await strategy.nth(1);
    signalled.abort();
    expect(isAborted(await one)).toBe(true);
    expect(call.signal?.aborted).toBe(false);
    call.answer('code-1');
    await expect(unsignalled).resolves.toMatchObject({ refreshToken: 'R-1' });
  });
});

describe('a login a moment starts waits on the attached parties', () => {
  it('rejected() running when the config signal aborts: Oops aborted, the port free', async () => {
    const { port, strategy, settledCalls, signals, bound } =
      await browserOnPort();
    const session = new AbortController();
    const p = provider(strategy, { signal: session.signal });
    const outcome = p.rejected(refused);
    await bound;
    session.abort();
    const answered = await outcome;
    expect(answered.ok).toBe(false);
    expect(isAborted(answered.ok ? undefined : answered.refusal)).toBe(true);
    expect(signals[0]?.aborted).toBe(true);
    await settledCalls[0];
    expect(await canBind(port)).toBe(true);
  });

  it('two attached parties: one aborts, the login continues; then the other, it is aborted', async () => {
    const strategy = waitingStrategy();
    const a = new AbortController();
    const b = new AbortController();
    const p = provider(strategy);
    p.attach(a.signal);
    p.attach(b.signal);
    const outcome = p.rejected(refused);
    const call = await strategy.nth(1);
    a.abort();
    await settle();
    expect(call.signal?.aborted).toBe(false);
    b.abort();
    const answered = await outcome;
    expect(answered.ok).toBe(false);
    expect(isAborted(answered.ok ? undefined : answered.refusal)).toBe(true);
    expect(call.signal?.aborted).toBe(true);
  });

  it('two attached parties, one aborts: the login runs to its token', async () => {
    const strategy = waitingStrategy();
    const a = new AbortController();
    const b = new AbortController();
    const p = provider(strategy);
    p.attach(a.signal);
    p.attach(b.signal);
    const outcome = p.rejected(refused);
    const call = await strategy.nth(1);
    a.abort();
    await settle();
    call.answer('code-1');
    await expect(outcome).resolves.toEqual({ ok: true });
    expect(call.signal?.aborted).toBe(false);
  });

  it('a party attached with an already-aborted signal is not added: the login runs unbounded', async () => {
    const strategy = waitingStrategy();
    const p = provider(strategy, { signal: AbortSignal.abort() });
    p.attach(AbortSignal.abort());
    const outcome = p.rejected(refused);
    const call = await strategy.nth(1);
    await settle();
    expect(call.signal?.aborted).toBe(false);
    call.answer('code-1');
    await expect(outcome).resolves.toEqual({ ok: true });
  });

  it('after every attached party has been released, a later rejected() login runs unbounded and gets a token', async () => {
    const strategy = waitingStrategy();
    const a = new AbortController();
    const b = new AbortController();
    const p = provider(strategy, { signal: a.signal });
    const detach = p.attach(b.signal);
    a.abort();
    detach();
    const outcome = p.rejected(refused);
    const call = await strategy.nth(1);
    await settle();
    expect(call.signal?.aborted).toBe(false);
    call.answer('code-1');
    await expect(outcome).resolves.toEqual({ ok: true });
    expect(call.signal?.aborted).toBe(false);
  });

  it('a never-attached provider: its rejected() login runs as today', async () => {
    const strategy = waitingStrategy();
    const p = provider(strategy);
    const outcome = p.rejected(refused);
    const call = await strategy.nth(1);
    expect(call.signal?.aborted).toBe(false);
    call.answer('code-1');
    await expect(outcome).resolves.toEqual({ ok: true });
  });

  describe('mixed consumers: a signalled party and an unsignalled consumer', () => {
    it('the signalled one closes with no login running: the unsignalled renewal gets a token', async () => {
      const strategy = waitingStrategy();
      const session = new AbortController();
      const p = provider(strategy);
      p.attach(session.signal);
      session.abort();
      const outcome = p.rejected(refused);
      const call = await strategy.nth(1);
      await settle();
      expect(call.signal?.aborted).toBe(false);
      call.answer('code-1');
      await expect(outcome).resolves.toEqual({ ok: true });
    });

    it('it closes while a login it bounds runs: that login aborts; the next moment logs in afresh and gets a token', async () => {
      const strategy = waitingStrategy();
      const session = new AbortController();
      const p = provider(strategy);
      p.attach(session.signal);
      const bounded = p.rejected(refused);
      const first = await strategy.nth(1);
      session.abort();
      const answered = await bounded;
      expect(isAborted(answered.ok ? undefined : answered.refusal)).toBe(true);
      expect(first.signal?.aborted).toBe(true);

      const next = p.rejected(refused);
      const second = await strategy.nth(2);
      await settle();
      expect(second.signal?.aborted).toBe(false);
      second.answer('code-2');
      await expect(next).resolves.toEqual({ ok: true });
    });
  });

  it('detach() and an aborted signal each remove the party, and its listener', async () => {
    const strategy = waitingStrategy();
    const detached = new AbortController();
    const aborting = new AbortController();
    const removedFromDetached = jest.spyOn(
      detached.signal,
      'removeEventListener',
    );
    const removedFromAborting = jest.spyOn(
      aborting.signal,
      'removeEventListener',
    );
    const p = provider(strategy);
    const detach = p.attach(detached.signal);
    p.attach(aborting.signal);
    expect(getEventListeners(detached.signal, 'abort')).toHaveLength(1);
    expect(getEventListeners(aborting.signal, 'abort')).toHaveLength(1);

    detach();
    aborting.abort();
    expect(removedFromDetached).toHaveBeenCalledWith(
      'abort',
      expect.any(Function),
    );
    expect(removedFromAborting).toHaveBeenCalledWith(
      'abort',
      expect.any(Function),
    );
    expect(getEventListeners(detached.signal, 'abort')).toHaveLength(0);
    expect(getEventListeners(aborting.signal, 'abort')).toHaveLength(0);

    // Neither bounds a later moment: its login runs unbounded.
    const outcome = p.rejected(refused);
    const call = await strategy.nth(1);
    await settle();
    expect(call.signal?.aborted).toBe(false);
    call.answer('code-1');
    await expect(outcome).resolves.toEqual({ ok: true });
  });

  it("a detached party no longer holds a moment open: the remaining party's abort aborts it", async () => {
    const strategy = waitingStrategy();
    const a = new AbortController();
    const b = new AbortController();
    const p = provider(strategy);
    const detach = p.attach(a.signal);
    p.attach(b.signal);
    detach();
    const outcome = p.rejected(refused);
    const call = await strategy.nth(1);
    b.abort();
    const answered = await outcome;
    expect(isAborted(answered.ok ? undefined : answered.refusal)).toBe(true);
    expect(call.signal?.aborted).toBe(true);
  });

  it('attach of an aborted signal adds no listener', () => {
    const p = provider(waitingStrategy());
    const aborted = AbortSignal.abort();
    const added = jest.spyOn(aborted, 'addEventListener');
    p.attach(aborted);
    expect(getEventListeners(aborted, 'abort')).toHaveLength(0);
    added.mockRestore();
  });

  it("the parties' listener count returns to its baseline after every moment", async () => {
    const strategy = waitingStrategy();
    const party = new AbortController();
    const p = provider(strategy);
    p.attach(party.signal);
    const baseline = getEventListeners(party.signal, 'abort').length;
    expect(baseline).toBe(1);
    const outcome = p.rejected(refused);
    const call = await strategy.nth(1);
    call.answer('code-1');
    await expect(outcome).resolves.toEqual({ ok: true });
    await expect(p.prepare()).resolves.toEqual({ ok: true });
    expect(getEventListeners(party.signal, 'abort')).toHaveLength(baseline);
  });

  it('RF6: a rejected() login of parties A and B, joined by getTokens({ signal: C })', async () => {
    const { port, strategy, settledCalls, signals, bound } =
      await browserOnPort();
    const a = new AbortController();
    const b = new AbortController();
    const c = new AbortController();
    const p = provider(strategy);
    p.attach(a.signal);
    p.attach(b.signal);
    const moment = p.rejected(refused);
    await bound;
    const caller = rejectionOf(p.getTokens({ signal: c.signal }));

    a.abort();
    await settle();
    expect(signals[0]?.aborted).toBe(false);
    c.abort();
    expect(isAborted(await caller)).toBe(true);
    expect(signals[0]?.aborted).toBe(false);
    b.abort();
    const answered = await moment;
    expect(isAborted(answered.ok ? undefined : answered.refusal)).toBe(true);
    expect(signals[0]?.aborted).toBe(true);
    await settledCalls[0];
    expect(await canBind(port)).toBe(true);
    expect(signals).toHaveLength(1);
  });
});

describe('the pin attempt is shared the same way', () => {
  it('two callers, one aborts: only it rejects; the other gets the pinned material', async () => {
    const material = deferred<ICertificateMaterial>();
    const reads = jest.fn(() => material.promise);
    const clientAuthentication: IClientAuthentication = {
      authenticate: async () => ({}),
      tlsMaterial: reads,
    };
    const p = new AuthorizationCodeProvider({
      uaaUrl: server.url,
      clientId: 'cid',
      authorization: waitingStrategy(),
      clientAuthentication,
    });
    const pin = (signal?: AbortSignal) =>
      (
        p as unknown as {
          pin(signal?: AbortSignal): Promise<unknown>;
        }
      ).pin(signal);
    const leaving = new AbortController();
    const one = rejectionOf(pin(leaving.signal));
    const two = pin(new AbortController().signal);
    await settle();
    leaving.abort();
    expect(isAborted(await one)).toBe(true);
    material.resolve(certificate());
    await expect(two).resolves.toMatchObject({
      thumbprint: expect.any(String),
    });
    expect(reads).toHaveBeenCalledTimes(1);
  });
});
