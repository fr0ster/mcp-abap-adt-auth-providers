/**
 * Rule 5 on the real providers: one renewal is at most one refresh, then —
 * only if the refresh is refused or there is none — one login. A provider's
 * own `performRefresh` never logs in; the base decides the single login.
 * Concurrent renewals share one flight.
 */

import { describe, expect, it, jest } from '@jest/globals';
import { AuthProviderFailure, authError } from '@mcp-abap-adt/auth-errors';
import type {
  IAuthorizationStrategy,
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces-auth';
import { AuthorizationCodeProvider } from '../../providers/AuthorizationCodeProvider';
import { BaseTokenProvider } from '../../providers/BaseTokenProvider';
import { OidcTokenExchangeProvider } from '../../providers/OidcTokenExchangeProvider';
import { recordingTargets } from '../helpers/targets';

jest.mock('../../auth/tokenRefresher', () => ({
  refreshJwtToken: jest.fn(async () => {
    throw new Error('invalid_grant');
  }),
}));

jest.mock('../../auth/oidcToken', () => ({
  tokenExchange: jest.fn(async () => {
    throw new Error('exchange refused');
  }),
}));

import { tokenExchange } from '../../auth/oidcToken';
import { refreshThenLogin } from '../../renewal';
import { wordsOf } from '../helpers/minted';

const refused = { at: 'request' as const, status: 401, error: {} };

describe('AuthorizationCodeProvider: one renewal, one login', () => {
  it('a refused refresh and a failed login call the strategy exactly once', async () => {
    const authorize = jest.fn(async () => {
      // What a shipped strategy throws when the login fails.
      throw new AuthProviderFailure(
        authError['interactive-login']({ outcome: 'failed' }),
      );
    });
    const strategy = { authorize } as unknown as IAuthorizationStrategy<string>;
    const provider = new AuthorizationCodeProvider({
      renewal: refreshThenLogin(),
      uaaUrl: 'https://uaa.example',
      clientId: 'client',
      clientSecret: 'secret',
      accessToken: 'T1',
      refreshToken: 'R1',
      authorization: strategy,
    });

    const outcome = await provider.rejected(refused);

    expect(wordsOf(outcome)).toMatchObject({
      ok: false,
      refusal: { reason: 'the browser login failed (unknown error)' },
    });
    expect(authorize).toHaveBeenCalledTimes(1);
  });
});

describe('a provider with no refresh grant', () => {
  it('one rejected() is exactly one login, even holding a refresh token', async () => {
    const exchange = tokenExchange as jest.MockedFunction<typeof tokenExchange>;
    exchange.mockClear();
    const provider = new OidcTokenExchangeProvider({
      renewal: refreshThenLogin(),
      tokenEndpoint: 'https://issuer.example/token',
      clientId: 'client',
      subjectToken: 'subject',
      subjectTokenType: 'urn:ietf:params:oauth:token-type:jwt',
      accessToken: 'T1',
      refreshToken: 'R1',
    });

    const outcome = await provider.rejected(refused);

    expect(outcome).toMatchObject({ ok: false });
    expect(exchange).toHaveBeenCalledTimes(1);
  });
});

const inAnHour = () => Date.now() + 3600_000;

/** A refresh token that rotates: each one works once, like UAA's. */
class RotatingProvider extends BaseTokenProvider {
  logins = 0;
  refreshes = 0;
  private spent = new Set<string>();

  constructor() {
    super({ renewal: refreshThenLogin() });
    this.authorizationToken = 'T1';
    this.refreshToken = 'R1';
    this.expiresAt = inAnHour();
    this.tokenType = 'opaque';
  }

  get storedRefreshToken() {
    return this.refreshToken;
  }

  protected getAuthType(): OAuth2GrantType {
    return 'authorization_code';
  }

  protected async performLogin(): Promise<ITokenResult> {
    this.logins += 1;
    return {
      authorizationToken: `L${this.logins}`,
      refreshToken: `RL${this.logins}`,
      authType: 'authorization_code',
      tokenType: 'opaque',
      expiresAt: inAnHour(),
    };
  }

  protected async performRefresh(
    _refreshToken: string,
    _signal: AbortSignal,
    dispatched: () => void,
  ): Promise<ITokenResult> {
    // The request leaves: the site would call this right before it.
    dispatched();
    this.refreshes += 1;
    const presented = this.refreshToken as string;
    await new Promise((resolve) => setTimeout(resolve, 5));
    if (this.spent.has(presented)) throw new Error('invalid_grant');
    this.spent.add(presented);
    const n = this.refreshes + 1;
    return {
      authorizationToken: `T${n}`,
      refreshToken: `R${n}`,
      authType: 'authorization_code',
      tokenType: 'opaque',
      expiresAt: inAnHour(),
    };
  }
}

describe('concurrent renewals share one flight', () => {
  it('two concurrent rejected(): one refresh, no login, both Ok, the new refresh token kept', async () => {
    const p = new RotatingProvider();
    await p.authorize(recordingTargets().requestTarget); // presents T1

    const [a, b] = await Promise.all([
      p.rejected(refused),
      p.rejected(refused),
    ]);

    expect(a).toEqual({ ok: true });
    expect(b).toEqual({ ok: true });
    expect(p.refreshes).toBe(1);
    expect(p.logins).toBe(0);
    expect(p.storedRefreshToken).toBe('R2');
  });

  it('a rejected() whose token is already superseded answers Ok without renewing', async () => {
    const p = new RotatingProvider();
    await p.authorize(recordingTargets().requestTarget); // presents T1
    await expect(p.rejected(refused)).resolves.toEqual({ ok: true });
    // A second request that carried T1 comes back 401 after the renewal.
    await expect(p.rejected(refused)).resolves.toEqual({ ok: true });
    expect(p.refreshes).toBe(1);
    expect(p.logins).toBe(0);
  });

  it('after the new token is presented and refused, the next rejected() renews again', async () => {
    const p = new RotatingProvider();
    await p.authorize(recordingTargets().requestTarget); // presents T1
    await p.rejected(refused);
    const t = recordingTargets();
    await p.authorize(t.requestTarget); // presents T2
    expect(t.request.headers.Authorization).toBe('Bearer T2');
    await expect(p.rejected(refused)).resolves.toEqual({ ok: true });
    expect(p.refreshes).toBe(2);
  });

  it('an authorize() during a renewal waits for it and presents the new token', async () => {
    const p = new RotatingProvider();
    await p.authorize(recordingTargets().requestTarget); // presents T1
    const renewing = p.rejected(refused);
    const t = recordingTargets();
    await p.authorize(t.requestTarget);
    await renewing;
    expect(t.request.headers.Authorization).toBe('Bearer T2');
    expect(p.refreshes).toBe(1);
  });

  it('concurrent expired authorize() calls share one refresh', async () => {
    const p = new RotatingProvider();
    (p as unknown as { expiresAt: number }).expiresAt = Date.now() - 1;
    const [x, y] = [recordingTargets(), recordingTargets()];
    await Promise.all([
      p.authorize(x.requestTarget),
      p.authorize(y.requestTarget),
    ]);
    expect(p.refreshes).toBe(1);
    expect(p.logins).toBe(0);
    expect(x.request.headers.Authorization).toBe('Bearer T2');
    expect(y.request.headers.Authorization).toBe('Bearer T2');
  });
});
