/**
 * `refreshTokens()`: a new token, never the cached one.
 *
 * `getTokens()` answers the cache while the token looks valid, and that is
 * exactly when a caller holding a 401 needs another token. These tests run
 * the base class's lifecycle on a provider whose login and refresh only count
 * their calls, so what is asserted is the order of the steps, not a flow.
 */
import type {
  IRefreshableTokenProvider,
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces-auth';
import { BaseTokenProvider } from '../../providers/BaseTokenProvider';

/** A JWT whose `exp` is `secondsFromNow` away: what `isTokenValid` reads. */
function jwt(label: string, secondsFromNow: number): string {
  const encode = (value: object) =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  const exp = Math.floor(Date.now() / 1000) + secondsFromNow;
  return `${encode({ alg: 'none' })}.${encode({ exp, label })}.sig`;
}

class CountingProvider extends BaseTokenProvider {
  logins = 0;
  refreshes = 0;
  refuseRefresh = false;

  constructor(seed?: { token?: string; refreshToken?: string }) {
    super();
    this.authorizationToken = seed?.token;
    this.refreshToken = seed?.refreshToken;
    // What `isTokenValid` reads: the seeded token's own `exp`.
    if (seed?.token) this.expiresAt = this.parseExpirationFromJWT(seed.token);
  }

  protected getAuthType(): OAuth2GrantType {
    return 'authorization_code';
  }

  protected async performLogin(): Promise<ITokenResult> {
    this.logins += 1;
    return {
      authorizationToken: jwt(`login-${this.logins}`, 3600),
      refreshToken: `refresh-from-login-${this.logins}`,
      authType: 'authorization_code',
    };
  }

  protected async performRefresh(): Promise<ITokenResult> {
    this.refreshes += 1;
    if (this.refuseRefresh) throw new Error('invalid_grant');
    return {
      authorizationToken: jwt(`refresh-${this.refreshes}`, 3600),
      refreshToken: `refresh-from-refresh-${this.refreshes}`,
      authType: 'authorization_code',
    };
  }
}

describe('refreshTokens', () => {
  it('is what a base provider offers: the refreshable contract', () => {
    const provider: IRefreshableTokenProvider = new CountingProvider();
    expect(typeof provider.refreshTokens).toBe('function');
  });

  it('refreshes even while the cached token is still valid', async () => {
    const cached = jwt('cached', 3600);
    const provider = new CountingProvider({
      token: cached,
      refreshToken: 'held',
    });

    // The cache answers getTokens: nothing is requested.
    expect((await provider.getTokens()).authorizationToken).toBe(cached);
    expect(provider.refreshes + provider.logins).toBe(0);

    const fresh = await provider.refreshTokens();

    expect(provider.refreshes).toBe(1);
    expect(provider.logins).toBe(0);
    expect(fresh.authorizationToken).not.toBe(cached);
  });

  it('replaces the cache with what it obtained', async () => {
    const provider = new CountingProvider({
      token: jwt('cached', 3600),
      refreshToken: 'held',
    });

    const fresh = await provider.refreshTokens();
    const after = await provider.getTokens();

    expect(after.authorizationToken).toBe(fresh.authorizationToken);
    expect(after.refreshToken).toBe('refresh-from-refresh-1');
    expect(provider.refreshes).toBe(1);
  });

  it('logs in when there is no refresh token', async () => {
    const provider = new CountingProvider({ token: jwt('cached', 3600) });

    await provider.refreshTokens();

    expect(provider.refreshes).toBe(0);
    expect(provider.logins).toBe(1);
  });

  it('logs in when the refresh is refused, and drops the spent refresh token', async () => {
    const provider = new CountingProvider({
      token: jwt('cached', 3600),
      refreshToken: 'revoked',
    });
    provider.refuseRefresh = true;

    const fresh = await provider.refreshTokens();

    expect(provider.refreshes).toBe(1);
    expect(provider.logins).toBe(1);
    expect(fresh.refreshToken).toBe('refresh-from-login-1');
  });
});

describe('getTokens, unchanged', () => {
  it('answers the cache while the token is valid', async () => {
    const provider = new CountingProvider({
      token: jwt('cached', 3600),
      refreshToken: 'held',
    });
    await provider.getTokens();
    expect(provider.refreshes + provider.logins).toBe(0);
  });

  it('refreshes an expired token, then logs in only if that is refused', async () => {
    const provider = new CountingProvider({
      token: jwt('expired', -60),
      refreshToken: 'held',
    });

    await provider.getTokens();
    expect([provider.refreshes, provider.logins]).toEqual([1, 0]);
  });
});
