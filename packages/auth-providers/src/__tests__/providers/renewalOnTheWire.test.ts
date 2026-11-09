/**
 * The renewal strategy where the point is what reached the server: real sockets
 * through real axios, a local token endpoint that holds or answers each
 * request, and every claim about a refresh token asserted on what the server
 * received.
 */

import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { readFailure } from '@mcp-abap-adt/auth-errors';
import type {
  IRenewalStrategy,
  ITokenPersistence,
  RenewalAbortObservation,
  RenewalSituation,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { AuthorizationCodeProvider } from '../../providers/AuthorizationCodeProvider';
import { OidcPasswordProvider } from '../../providers/OidcPasswordProvider';
import { refreshOnly, refreshThenLogin } from '../../renewal';
import {
  Arrivals,
  type HeldRequest,
  jwt,
  quiet,
  rejectionOf,
  startTokenServer,
  type TokenServer,
  waitingStrategy,
} from '../helpers/attemptHarness';
import {
  deepEqualWith,
  matchObject,
  objectContaining,
} from '../helpers/expectations';
import { stateRecorder } from '../helpers/persistence';

const silent: ILogger = {
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
};

function expectAborted(thrown: unknown): void {
  const error = readFailure(thrown, 'unfamiliar-error');
  assert.equal(error.kind, 'interactive-login');
  matchObject(error.facts, { outcome: 'aborted' });
}

/** `inner`'s decisions, with every observation recorded. */
function observing(inner: IRenewalStrategy) {
  const observed: RenewalAbortObservation[] = [];
  const strategy: IRenewalStrategy = {
    next: (situation) => inner.next(situation),
    aborted: (observation) => {
      observed.push(observation);
    },
  };
  return { strategy, observed };
}

const expired = (subject: string) => jwt(subject, -3600);

let server: TokenServer;
afterEach(async () => {
  await server.close();
});

/** The refresh tokens the server received, in order. */
const submitted = () =>
  server.requests
    .filter((r) => r.params.get('grant_type') === 'refresh_token')
    .map((r) => r.params.get('refresh_token'));

describe('a refresh cut before dispatch (OIDC, discovery held open)', () => {
  let discoveries: Arrivals<HeldRequest>;
  beforeEach(async () => {
    discoveries = new Arrivals<HeldRequest>();
    server = await startTokenServer((request) => {
      if (request.path.includes('/.well-known/')) {
        discoveries.push(request);
        return;
      }
      request.answer(200, {
        access_token: jwt('refreshed'),
        refresh_token: 'R2',
      });
    });
  });

  it('nothing reached the token endpoint, R is not discarded, and the next renewal sends R', async () => {
    const { seen, persistence } = stateRecorder();
    const { strategy, observed } = observing(refreshThenLogin());
    const provider = new OidcPasswordProvider({
      renewal: strategy,
      issuerUrl: server.url,
      clientId: 'cid',
      username: 'user',
      password: 'pw',
      accessToken: expired('held'),
      refreshToken: 'R',
      logger: silent,
      persistence,
    });
    const only = new AbortController();
    const cut = rejectionOf(provider.getTokens({ signal: only.signal }));
    await discoveries.nth(1);
    only.abort();
    expectAborted(await cut);
    await quiet();
    // No token request, no clearing notification, R untouched.
    assert.equal(server.requests.filter((r) => r.path === '/token').length, 0);
    assert.deepEqual(seen, []);
    assert.deepEqual(observed, [
      {
        cause: { trigger: 'expired' },
        moment: 'get-tokens',
        step: 'refresh',
        sent: false,
      },
    ]);

    const next = provider.getTokens();
    (await discoveries.nth(2)).answer(200, {
      issuer: server.url,
      token_endpoint: `${server.url}/token`,
    });
    matchObject(await next, { refreshToken: 'R2' });
    assert.deepEqual(submitted(), ['R']);
    assert.equal(
      server.requests.filter((r) => r.params.get('grant_type') === 'password')
        .length,
      0,
    );
  });
});

describe('the server answers the token endpoint', () => {
  let refreshes: Arrivals<HeldRequest>;
  /** How each refresh is answered; undefined holds it. */
  let refreshAnswer: ((request: HeldRequest) => void) | undefined;
  /** What each code exchange answers. */
  let codeAnswer: object;
  /** Code exchanges held, when `holdCode` is set. */
  let codes: Arrivals<HeldRequest>;
  let holdCode: boolean;
  beforeEach(async () => {
    codes = new Arrivals<HeldRequest>();
    holdCode = false;
    refreshes = new Arrivals<HeldRequest>();
    refreshAnswer = undefined;
    codeAnswer = { access_token: jwt('login'), refresh_token: 'S' };
    server = await startTokenServer((request) => {
      if (request.params.get('grant_type') === 'refresh_token') {
        refreshes.push(request);
        refreshAnswer?.(request);
        return;
      }
      if (holdCode) {
        codes.push(request);
        return;
      }
      request.answer(200, codeAnswer);
    });
  });

  function codeProvider(
    renewal: IRenewalStrategy,
    extra: { persistence?: ITokenPersistence } = {},
    strategy = waitingStrategy(),
  ) {
    const p = new AuthorizationCodeProvider({
      renewal,
      uaaUrl: server.url,
      clientId: 'cid',
      clientSecret: 'sec',
      authorization: strategy,
      logger: silent,
      accessToken: expired('held'),
      refreshToken: 'R',
      ...extra,
    });
    return { p, strategy };
  }

  it('a refresh cut after dispatch with ifCut keep: the replacement sends R again, and a late R2 still commits', async () => {
    const { seen, persistence } = stateRecorder();
    const keep: IRenewalStrategy = {
      next: (situation: RenewalSituation) =>
        situation.steps.length === 0 && situation.canRefresh
          ? { next: 'refresh', ifCut: 'keep' }
          : situation.steps.length === 0
            ? { next: 'stop' }
            : { next: 'stop', sentRefreshToken: 'keep' },
    };
    const { strategy, observed } = observing(keep);
    const { p } = codeProvider(strategy, { persistence });
    const only = new AbortController();
    const cut = rejectionOf(p.getTokens({ signal: only.signal }));
    const late = await refreshes.nth(1);
    only.abort();
    expectAborted(await cut);
    await quiet();
    deepEqualWith(observed, [
      objectContaining({
        step: 'refresh',
        sent: true,
        refreshToken: 'kept',
      }),
    ]);

    const replacement = p.getTokens();
    const second = await refreshes.nth(2);
    assert.deepEqual(submitted(), ['R', 'R']);
    // The late answer of the cut refresh: nothing newer committed yet.
    const T2 = jwt('late');
    late.answer(200, { access_token: T2, refresh_token: 'R2' });
    await quiet();
    assert.deepEqual(seen, [[T2, 'R2', 'replace']]);
    const T3 = jwt('replacement');
    second.answer(200, { access_token: T3, refresh_token: 'R3' });
    matchObject(await replacement, {
      authorizationToken: T3,
      refreshToken: 'R3',
    });
  });

  describe('keep through login', () => {
    it('a sent refresh fails, the login keeps R and returns none: R still held, told without one, and the next refresh sends R', async () => {
      refreshAnswer = (request) =>
        submitted().length === 1
          ? request.answer(400, { error: 'invalid_grant' })
          : request.answer(200, { access_token: jwt('again') });
      const LOGIN = expired('login');
      codeAnswer = { access_token: LOGIN };
      const { seen, persistence } = stateRecorder();
      const keepThenLogin: IRenewalStrategy = {
        next: (situation) => {
          const last = situation.steps.at(-1);
          if (last === undefined) return { next: 'refresh', ifCut: 'discard' };
          if (last.step === 'refresh' && last.outcome === 'failed') {
            return { next: 'login', sentRefreshToken: 'keep' };
          }
          return { next: 'stop' };
        },
      };
      const { p, strategy } = codeProvider(keepThenLogin, { persistence });
      const first = p.getTokens();
      (await strategy.nth(1)).answer('code-1');
      matchObject(await first, { refreshToken: 'R' });
      assert.deepEqual(seen, [[LOGIN, undefined, 'keep']]);

      // The login's token is expired: the next renewal refreshes R again.
      await p.getTokens();
      assert.deepEqual(submitted(), ['R', 'R']);
      assert.equal(strategy.calls.length, 1);
    });

    it('a strategy that logs in directly while R is held: R still held after a login without one, and the next refresh sends R', async () => {
      refreshAnswer = (request) =>
        request.answer(200, { access_token: jwt('refreshed') });
      codeAnswer = { access_token: expired('login') };
      const loginFirst: IRenewalStrategy = {
        next: (situation) =>
          situation.steps.length > 0
            ? { next: 'stop' }
            : situation.cause.trigger === 'explicit'
              ? { next: 'login' }
              : { next: 'refresh', ifCut: 'discard' },
      };
      const { p, strategy } = codeProvider(loginFirst);
      const loggedIn = p.refreshTokens();
      (await strategy.nth(1)).answer('code-1');
      matchObject(await loggedIn, { refreshToken: 'R' });
      assert.deepEqual(submitted(), []);
      await p.getTokens();
      assert.deepEqual(submitted(), ['R']);
    });
  });

  it('refreshOnly() never calls the authorization strategy: a refused refresh stops', async () => {
    refreshAnswer = (request) =>
      request.answer(400, { error: 'invalid_grant' });
    const { p, strategy } = codeProvider(refreshOnly());
    const thrown = await rejectionOf(p.getTokens());
    matchObject(readFailure(thrown, 'unfamiliar-error'), {
      kind: 'request-failed',
      facts: { status: 400, oauthError: 'invalid_grant' },
    });
    await quiet();
    assert.equal(strategy.calls.length, 0);
    assert.deepEqual(submitted(), ['R']);
  });

  describe('rule 5 as a reading', () => {
    it('a 403 with refreshThenLogin(): system-refused, no token request', async () => {
      const { p, strategy } = codeProvider(refreshThenLogin());
      const outcome = await p.rejected({
        at: 'request',
        status: 403,
        error: undefined,
      });
      matchObject(outcome, {
        ok: false,
        refusal: { kind: 'system-refused', facts: { status: 403 } },
      });
      assert.equal(server.requests.length, 0);
      assert.equal(strategy.calls.length, 0);
    });

    it('a strategy that renews on not-credential: one refresh sent', async () => {
      refreshAnswer = (request) =>
        request.answer(200, { access_token: jwt('new'), refresh_token: 'R2' });
      const renewOn403: IRenewalStrategy = {
        next: (situation) =>
          situation.steps.length === 0
            ? { next: 'refresh', ifCut: 'discard' }
            : { next: 'stop' },
      };
      const { p } = codeProvider(renewOn403);
      assert.deepEqual(
        await p.rejected({ at: 'request', status: 403, error: undefined }),
        { ok: true },
      );
      assert.deepEqual(submitted(), ['R']);
    });
  });

  describe("a login step's sent, as its sites told it", () => {
    function loginOnly() {
      const situations: RenewalSituation[] = [];
      const { strategy, observed } = observing({
        next: (situation) => {
          situations.push(situation);
          return refreshThenLogin().next(situation);
        },
      });
      const authorization = waitingStrategy();
      const p = new AuthorizationCodeProvider({
        renewal: strategy,
        uaaUrl: server.url,
        clientId: 'cid',
        clientSecret: 'sec',
        authorization,
        logger: silent,
      });
      return { p, authorization, observed, situations };
    }

    it('an abort after the code exchange was dispatched: sent true', async () => {
      holdCode = true;
      const { p, authorization, observed } = loginOnly();
      const only = new AbortController();
      const cut = rejectionOf(p.getTokens({ signal: only.signal }));
      (await authorization.nth(1)).answer('code-1');
      await codes.nth(1);
      only.abort();
      expectAborted(await cut);
      await quiet();
      assert.deepEqual(observed, [
        {
          cause: { trigger: 'no-token' },
          moment: 'get-tokens',
          step: 'login',
          sent: true,
        },
      ]);
    });

    it('a login refused after its code exchange was sent: failed, sent true', async () => {
      holdCode = true;
      const { p, authorization, situations } = loginOnly();
      const thrown = rejectionOf(p.getTokens());
      (await authorization.nth(1)).answer('code-1');
      (await codes.nth(1)).answer(400, { error: 'invalid_grant' });
      await thrown;
      deepEqualWith(situations[1]?.steps, [
        objectContaining({
          step: 'login',
          outcome: 'failed',
          sent: true,
        }),
      ]);
    });
  });
});
