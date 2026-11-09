import assert from 'node:assert/strict';
import { describe, it, mock } from 'node:test';
import { AuthProviderFailure, authError } from '@mcp-abap-adt/auth-errors';
import type {
  ITokenResult,
  OAuth2GrantType,
  PersistenceReport,
} from '@mcp-abap-adt/interfaces-auth';
import { refreshStatePersistence } from '../../persistence';
import {
  BaseTokenProvider,
  refreshTokenRefused,
  type TokenProviderHooks,
} from '../../providers/BaseTokenProvider';
import { Saml2PureProvider } from '../../providers/Saml2PureProvider';
import { refreshThenLogin } from '../../renewal';
import { matchObject } from '../helpers/expectations';
import { wordsOf } from '../helpers/minted';
import { recordingTargets } from '../helpers/targets';

const inAnHour = () => Date.now() + 3600_000;
// As a provider builds it: `refreshToken: undefined` present when there is none.
const result = (token: string, refresh?: string): ITokenResult =>
  ({
    authorizationToken: token,
    refreshToken: refresh,
    authType: 'client_credentials',
    tokenType: 'opaque',
    expiresAt: inAnHour(),
  }) as ITokenResult;

class TestProvider extends BaseTokenProvider {
  login = mock.fn(async () => result('T1', 'R1'));
  refresh = mock.fn(async () => result('T2', 'R2'));
  constructor(hooks: TokenProviderHooks = { renewal: refreshThenLogin() }) {
    super(hooks);
  }
  protected performLogin() {
    return this.login();
  }
  protected performRefresh(
    _refreshToken: string,
    _signal: AbortSignal,
    dispatched: () => void,
  ) {
    // The request leaves: the site would call this right before it.
    dispatched();
    return this.refresh();
  }
  protected getAuthType(): OAuth2GrantType {
    return 'client_credentials';
  }
  expire() {
    this.expiresAt = Date.now() - 1;
  }
}
const refused = { at: 'request' as const, status: 401, error: {} };

describe('BaseTokenProvider as IAuthProvider', () => {
  it('kind is the grant type', () => {
    assert.equal(new TestProvider().kind, 'client_credentials');
  });

  it('prepare logs in and answers Ok', async () => {
    const p = new TestProvider();
    assert.deepEqual(await p.prepare(), { ok: true });
    assert.equal(p.login.mock.callCount(), 1);
  });

  it('establish writes nothing, answers Ok, and obtains no token', async () => {
    const t = recordingTargets();
    const p = new TestProvider();
    assert.deepEqual(await p.establish(t.logonTarget), {
      ok: true,
    });
    assert.deepEqual(t.logon, { tls: [], params: [] });
    assert.equal(p.login.mock.callCount(), 0);
  });

  it('establish on an expired token neither refreshes nor logs in', async () => {
    const p = new TestProvider();
    await p.prepare();
    p.expire();
    assert.deepEqual(await p.establish(recordingTargets().logonTarget), {
      ok: true,
    });
    assert.equal(p.login.mock.callCount(), 1);
    assert.equal(p.refresh.mock.callCount(), 0);
  });

  it('authorize writes the bearer header', async () => {
    const t = recordingTargets();
    assert.deepEqual(await new TestProvider().authorize(t.requestTarget), {
      ok: true,
    });
    assert.deepEqual(t.request.headers, { Authorization: 'Bearer T1' });
  });

  it('authorize renews an expired token in that call', async () => {
    const p = new TestProvider();
    await p.prepare();
    p.expire();
    const t = recordingTargets();
    await p.authorize(t.requestTarget);
    assert.equal(t.request.headers.Authorization, 'Bearer T2');
    assert.equal(p.refresh.mock.callCount(), 1);
  });

  it('a throwing target is an Oops, not a rejected promise', async () => {
    const p = new TestProvider();
    const outcome = await p.authorize(
      recordingTargets({ throws: true }).requestTarget,
    );
    assert.deepEqual(wordsOf(outcome), {
      ok: false,
      refusal: { reason: 'presenting the token failed (unknown error)' },
    });
    assert.doesNotMatch(JSON.stringify(outcome), /SECRET-IN-TARGET/);
  });

  it('rejected refreshes once and answers Ok when the token changed', async () => {
    const p = new TestProvider();
    await p.authorize(recordingTargets().requestTarget); // presents T1
    assert.deepEqual(await p.rejected(refused), { ok: true });
    assert.equal(p.refresh.mock.callCount(), 1);
  });

  it('rejected is Oops when the renewal returns the token that was refused', async () => {
    const p = new TestProvider();
    p.refresh.mock.mockImplementation(async () => result('T1', 'R2'));
    await p.authorize(recordingTargets().requestTarget); // presents T1
    matchObject(await p.rejected(refused), {
      ok: false,
      refusal: {
        reason: 'the renewal returned the credential that was refused',
      },
    });
  });

  it('rejected before any authorize takes the held token as the refused one', async () => {
    const p = new TestProvider();
    p.refresh.mock.mockImplementation(async () => result('T1', 'R2'));
    await p.prepare(); // holds T1, presents nothing
    matchObject(await p.rejected(refused), {
      ok: false,
      refusal: {
        reason: 'the renewal returned the credential that was refused',
      },
    });
    assert.equal(p.refresh.mock.callCount(), 1);
  });

  it('rejected before any authorize renews the held token → Ok', async () => {
    const p = new TestProvider();
    await p.prepare(); // holds T1, presents nothing
    assert.deepEqual(await p.rejected(refused), { ok: true });
    assert.equal(p.refresh.mock.callCount(), 1);
  });

  it('rejected with nothing held obtains a token → Ok', async () => {
    const p = new TestProvider();
    assert.deepEqual(await p.rejected(refused), { ok: true });
    assert.equal(p.login.mock.callCount(), 1);
  });

  it('refresh refused → exactly one login → Ok', async () => {
    const p = new TestProvider();
    // Calls 0 and 1 answer T1, then T3 (each `Once` names its call).
    p.login.mock.mockImplementationOnce(async () => result('T1', 'R1'), 0);
    p.login.mock.mockImplementationOnce(async () => result('T3', 'R3'), 1);
    p.refresh.mock.mockImplementation(async () => {
      throw refreshTokenRefused();
    });
    await p.authorize(recordingTargets().requestTarget); // login #1, presents T1
    assert.deepEqual(await p.rejected(refused), { ok: true });
    assert.equal(p.refresh.mock.callCount(), 1);
    assert.equal(p.login.mock.callCount(), 2);
  });

  it('login refused → Oops, no second refresh or login', async () => {
    const p = new TestProvider();
    await p.authorize(recordingTargets().requestTarget); // login #1, presents T1
    p.refresh.mock.mockImplementation(async () => {
      throw refreshTokenRefused();
    });
    p.login.mock.mockImplementation(async () => {
      throw new AuthProviderFailure(
        authError['interactive-login']({ outcome: 'failed' }),
      );
    });
    const outcome = await p.rejected(refused);
    matchObject(wordsOf(outcome), {
      ok: false,
      refusal: { reason: 'the browser login failed (unknown error)' },
    });
    assert.doesNotMatch(JSON.stringify(outcome), /SECRET/);
    assert.equal(p.refresh.mock.callCount(), 1);
    assert.equal(p.login.mock.callCount(), 2);
  });

  it('a failure is an Oops, never a throw, and nothing is retried', async () => {
    const p = new TestProvider();
    p.login.mock.mockImplementation(async () => {
      throw refreshTokenRefused();
    });
    matchObject(await p.prepare(), { ok: false });
    assert.equal(p.login.mock.callCount(), 1);
  });

  it('a foreign error from the login keeps its secret out of the refusal', async () => {
    const p = new TestProvider();
    p.login.mock.mockImplementation(async () => {
      throw new Error('invalid_grant for SECRET-CLIENT-SECRET');
    });
    const outcome = await p.prepare();
    assert.deepEqual(wordsOf(outcome), {
      ok: false,
      refusal: {
        reason: 'client_credentials token request failed (unknown error)',
      },
    });
  });

  it('a report after a login and after a refresh, never on a cache hit', async () => {
    const report = mock.fn(async (_: PersistenceReport) => {});
    const p = new TestProvider({
      renewal: refreshThenLogin(),
      persistence: { report },
    });
    await p.prepare();
    await p.authorize(recordingTargets().requestTarget); // cache hit
    await p.rejected(refused);
    assert.deepEqual(
      report.mock.calls
        .map((call) => call.arguments)
        .map(([r]) => r.credential.authorizationToken),
      ['T1', 'T2'],
    );
  });

  it('a failing awaited report fails the moment with persisting-tokens, and logs no message', async () => {
    const warn = mock.fn();
    const p = new TestProvider({
      renewal: refreshThenLogin(),
      persistence: {
        report: async () => {
          throw new Error('store down: SECRET-T1');
        },
      },
    });
    (p as unknown as { logger: unknown }).logger = {
      warn,
      debug: mock.fn(),
      info: mock.fn(),
      error: mock.fn(),
    };
    const outcome = await p.prepare();
    matchObject(outcome, {
      ok: false,
      refusal: { kind: 'unknown', facts: { operation: 'persisting-tokens' } },
    });
    assert.doesNotMatch(JSON.stringify(outcome), /SECRET/);
    assert.doesNotMatch(
      JSON.stringify(warn.mock.calls.map((call) => call.arguments)),
      /SECRET/,
    );
  });

  it("a failing write under refreshStatePersistence 'continue' does not fail authentication, and logs no message", async () => {
    const warn = mock.fn();
    const logger = {
      warn,
      debug: mock.fn(),
      info: mock.fn(),
      error: mock.fn(),
    };
    const p = new TestProvider({
      renewal: refreshThenLogin(),
      persistence: refreshStatePersistence(
        async () => {
          throw new Error('store down: SECRET-T1');
        },
        { onWriteFailure: 'continue', logger },
      ),
    });
    (p as unknown as { logger: unknown }).logger = logger;
    assert.deepEqual(await p.prepare(), { ok: true });
    assert.ok(warn.mock.callCount() > 0);
    assert.doesNotMatch(
      JSON.stringify(warn.mock.calls.map((call) => call.arguments)),
      /SECRET/,
    );
  });

  it('Saml2PureProvider writes cookies, not a header', () => {
    const p = Object.create(Saml2PureProvider.prototype) as Saml2PureProvider;
    const t = recordingTargets();
    (
      p as unknown as { applyToken: (r: unknown, x: ITokenResult) => void }
    ).applyToken(t.requestTarget, result('SAP_SESSIONID=x'));
    assert.deepEqual(t.request.cookies, ['SAP_SESSIONID=x']);
    assert.deepEqual(t.request.headers, {});
  });
});
