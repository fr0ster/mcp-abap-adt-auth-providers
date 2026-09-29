import { describe, expect, it, jest } from '@jest/globals';
import type {
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces-auth';
import {
  BrowserAuthError,
  RefreshError,
} from '../../errors/TokenProviderErrors';
import {
  BaseTokenProvider,
  type TokenProviderHooks,
} from '../../providers/BaseTokenProvider';
import { Saml2PureProvider } from '../../providers/Saml2PureProvider';
import { recordingTargets } from '../helpers/targets';

const inAnHour = () => Date.now() + 3600_000;
const result = (token: string, refresh?: string): ITokenResult => ({
  authorizationToken: token,
  refreshToken: refresh,
  authType: 'client_credentials',
  tokenType: 'opaque',
  expiresAt: inAnHour(),
});

class TestProvider extends BaseTokenProvider {
  login = jest.fn(async () => result('T1', 'R1'));
  refresh = jest.fn(async () => result('T2', 'R2'));
  constructor(hooks: TokenProviderHooks = {}) {
    super(hooks);
  }
  protected performLogin() {
    return this.login();
  }
  protected performRefresh() {
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
    expect(new TestProvider().kind).toBe('client_credentials');
  });

  it('prepare logs in and answers Ok', async () => {
    const p = new TestProvider();
    await expect(p.prepare()).resolves.toEqual({ ok: true });
    expect(p.login).toHaveBeenCalledTimes(1);
  });

  it('establish writes nothing and answers Ok', async () => {
    const t = recordingTargets();
    await expect(new TestProvider().establish(t.logonTarget)).resolves.toEqual({
      ok: true,
    });
    expect(t.logon).toEqual({ tls: [], params: [] });
  });

  it('authorize writes the bearer header', async () => {
    const t = recordingTargets();
    await expect(
      new TestProvider().authorize(t.requestTarget),
    ).resolves.toEqual({ ok: true });
    expect(t.request.headers).toEqual({ Authorization: 'Bearer T1' });
  });

  it('authorize renews an expired token in that call', async () => {
    const p = new TestProvider();
    await p.prepare();
    p.expire();
    const t = recordingTargets();
    await p.authorize(t.requestTarget);
    expect(t.request.headers.Authorization).toBe('Bearer T2');
    expect(p.refresh).toHaveBeenCalledTimes(1);
  });

  it('a throwing target is an Oops, not a rejected promise', async () => {
    const p = new TestProvider();
    const outcome = await p.authorize(
      recordingTargets({ throws: true }).requestTarget,
    );
    expect(outcome).toMatchObject({ ok: false });
    expect(JSON.stringify(outcome)).not.toMatch(/SECRET-IN-TARGET/);
  });

  it('rejected refreshes once and answers Ok when the token changed', async () => {
    const p = new TestProvider();
    await p.authorize(recordingTargets().requestTarget); // presents T1
    await expect(p.rejected(refused)).resolves.toEqual({ ok: true });
    expect(p.refresh).toHaveBeenCalledTimes(1);
  });

  it('rejected is Oops when the renewal returns the token that was refused', async () => {
    const p = new TestProvider();
    p.refresh.mockResolvedValue(result('T1', 'R2'));
    await p.authorize(recordingTargets().requestTarget); // presents T1
    await expect(p.rejected(refused)).resolves.toMatchObject({
      ok: false,
      refusal: {
        reason: 'the renewal returned the credential that was refused',
      },
    });
  });

  it('refresh refused → exactly one login → Ok', async () => {
    const p = new TestProvider();
    p.login
      .mockResolvedValueOnce(result('T1', 'R1'))
      .mockResolvedValueOnce(result('T3', 'R3'));
    p.refresh.mockRejectedValue(new RefreshError('refused'));
    await p.authorize(recordingTargets().requestTarget); // login #1, presents T1
    await expect(p.rejected(refused)).resolves.toEqual({ ok: true });
    expect(p.refresh).toHaveBeenCalledTimes(1);
    expect(p.login).toHaveBeenCalledTimes(2);
  });

  it('login refused → Oops, no second refresh or login', async () => {
    const p = new TestProvider();
    await p.authorize(recordingTargets().requestTarget); // login #1, presents T1
    p.refresh.mockRejectedValue(new RefreshError('refused'));
    p.login.mockRejectedValue(new BrowserAuthError('SECRET-IDP-TEXT'));
    const outcome = await p.rejected(refused);
    expect(outcome).toMatchObject({
      ok: false,
      refusal: { reason: 'the interactive login did not complete' },
    });
    expect(JSON.stringify(outcome)).not.toMatch(/SECRET/);
    expect(p.refresh).toHaveBeenCalledTimes(1);
    expect(p.login).toHaveBeenCalledTimes(2);
  });

  it('a failure is an Oops, never a throw, and nothing is retried', async () => {
    const p = new TestProvider();
    p.login.mockRejectedValue(new RefreshError('refused'));
    await expect(p.prepare()).resolves.toMatchObject({ ok: false });
    expect(p.login).toHaveBeenCalledTimes(1);
  });

  it('a foreign error from the login keeps its secret out of the refusal', async () => {
    const p = new TestProvider();
    p.login.mockRejectedValue(
      new Error('invalid_grant for SECRET-CLIENT-SECRET'),
    );
    const outcome = await p.prepare();
    expect(outcome).toEqual({
      ok: false,
      refusal: {
        reason: 'client_credentials token request failed (unknown error)',
      },
    });
  });

  it('onTokens after a login and after a refresh, never on a cache hit', async () => {
    const onTokens = jest.fn(async (_: ITokenResult) => {});
    const p = new TestProvider({ onTokens });
    await p.prepare();
    await p.authorize(recordingTargets().requestTarget); // cache hit
    await p.rejected(refused);
    expect(onTokens.mock.calls.map(([r]) => r.authorizationToken)).toEqual([
      'T1',
      'T2',
    ]);
  });

  it('a failing onTokens does not fail authentication and logs no message', async () => {
    const warn = jest.fn();
    const p = new TestProvider({
      onTokens: async () => {
        throw new Error('store down: SECRET-T1');
      },
    });
    (p as unknown as { logger: unknown }).logger = {
      warn,
      debug: jest.fn(),
      info: jest.fn(),
      error: jest.fn(),
    };
    await expect(p.prepare()).resolves.toEqual({ ok: true });
    expect(JSON.stringify(warn.mock.calls)).not.toMatch(/SECRET/);
  });

  it('Saml2PureProvider writes cookies, not a header', () => {
    const p = Object.create(Saml2PureProvider.prototype) as Saml2PureProvider;
    const t = recordingTargets();
    (
      p as unknown as { applyToken: (r: unknown, x: ITokenResult) => void }
    ).applyToken(t.requestTarget, result('SAP_SESSIONID=x'));
    expect(t.request.cookies).toEqual(['SAP_SESSIONID=x']);
    expect(t.request.headers).toEqual({});
  });
});
