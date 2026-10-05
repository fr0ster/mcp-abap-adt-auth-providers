/**
 * A provider seeded with a stored credential reuses it until it expires, and
 * logs in only after. A JWT states its own expiry (`exp`); cookies and an
 * opaque token do not, so the consumer states it beside them (`expiresAt`).
 */

import { describe, expect, it, jest } from '@jest/globals';
import type {
  IAssertionValidator,
  IAuthorizationStrategy,
  IAuthRejection,
  ITokenResult,
} from '@mcp-abap-adt/interfaces-auth';
import { AuthorizationCodeProvider } from '../../providers/AuthorizationCodeProvider';
import type { BaseTokenProvider } from '../../providers/BaseTokenProvider';
import { OidcBrowserProvider } from '../../providers/OidcBrowserProvider';
import { OidcDeviceFlowProvider } from '../../providers/OidcDeviceFlowProvider';
import { OidcPasswordProvider } from '../../providers/OidcPasswordProvider';
import { OidcTokenExchangeProvider } from '../../providers/OidcTokenExchangeProvider';
import { Saml2BearerProvider } from '../../providers/Saml2BearerProvider';
import { Saml2PureProvider } from '../../providers/Saml2PureProvider';
import { UaaPasscodeProvider } from '../../providers/UaaPasscodeProvider';
import { recordingTargets } from '../helpers/targets';

const HOUR = 3600_000;
const b64url = (value: object) =>
  Buffer.from(JSON.stringify(value)).toString('base64url');
const jwt = (expMs: number) =>
  `${b64url({ alg: 'none', typ: 'JWT' })}.${b64url({
    exp: Math.floor(expMs / 1000),
    sub: 'user',
  })}.signature`;
/** No `exp`: three parts, but no expiry inside. */
const OPAQUE = 'opaque-access-token-without-any-expiry';

// ---- Saml2PureProvider: the stored cookies are its token.

const STORED_COOKIES = 'SAP_SESSIONID_ABC_100=stored; sap-usercontext=x';
const NEW_COOKIES = 'SAP_SESSIONID_ABC_100=fresh';

const R401: IAuthRejection = { at: 'request', status: 401, error: {} };

function samlPure(
  seed: { accessToken?: string; expiresAt?: number },
  loginCookies = NEW_COOKIES,
) {
  const authorize = jest.fn<IAuthorizationStrategy<string>['authorize']>(
    async () => ({
      payload: 'PHNhbWxwOlJlc3BvbnNlLz4=',
      redirectUri: 'https://sp/acs',
    }),
  );
  const loginExpiresAt = Date.now() + 2 * HOUR;
  const validate = jest.fn(async () => ({
    expiresAt: new Date(loginExpiresAt),
  }));
  const cookieProvider = jest.fn(async () => loginCookies);
  const onTokens = jest.fn(async (_result: ITokenResult) => {});
  const provider = new Saml2PureProvider({
    idpSsoUrl: 'https://idp/sso',
    spEntityId: 'sp',
    idpInitiated: true,
    authorization: { authorize },
    assertionValidator: { validate } as unknown as IAssertionValidator,
    cookieProvider,
    onTokens,
    ...seed,
  });
  return { provider, authorize, cookieProvider, onTokens, loginExpiresAt };
}

describe('Saml2PureProvider seeded with stored cookies', () => {
  it('before expiresAt: answers the stored cookies and never logs in', async () => {
    const expiresAt = Date.now() + HOUR;
    const { provider, authorize, cookieProvider } = samlPure({
      accessToken: STORED_COOKIES,
      expiresAt,
    });

    const tokens = await provider.getTokens();
    expect(tokens).toMatchObject({
      authorizationToken: STORED_COOKIES,
      tokenType: 'saml',
      expiresAt,
    });

    const t = recordingTargets();
    await expect(provider.authorize(t.requestTarget)).resolves.toEqual({
      ok: true,
    });
    expect(t.request.cookies).toEqual([STORED_COOKIES]);
    expect(t.request.headers).toEqual({});
    expect(authorize).not.toHaveBeenCalled();
    expect(cookieProvider).not.toHaveBeenCalled();
  });

  it('a 401 on the stored cookies before expiresAt: rejected() logs in once and the new cookies are presented', async () => {
    const { provider, authorize } = samlPure({
      accessToken: STORED_COOKIES,
      expiresAt: Date.now() + HOUR,
    });
    const first = recordingTargets();
    await provider.authorize(first.requestTarget);
    expect(first.request.cookies).toEqual([STORED_COOKIES]);

    await expect(provider.rejected(R401)).resolves.toEqual({ ok: true });
    expect(authorize).toHaveBeenCalledTimes(1);
    const second = recordingTargets();
    await provider.authorize(second.requestTarget);
    expect(second.request.cookies).toEqual([NEW_COOKIES]);
  });

  it('a 401 on the stored cookies, and a login that yields them again: rejected() refuses', async () => {
    const { provider } = samlPure(
      { accessToken: STORED_COOKIES, expiresAt: Date.now() + HOUR },
      STORED_COOKIES,
    );
    await provider.authorize(recordingTargets().requestTarget);
    const outcome = await provider.rejected(R401);
    expect(outcome.ok).toBe(false);
    expect(outcome.ok === false && outcome.refusal.reason).toBe(
      'the renewal returned the credential that was refused',
    );
  });

  it.each([
    ['Infinity', Number.POSITIVE_INFINITY],
    ['NaN', Number.NaN],
    ['a numeric string', '9999999999999' as unknown as number],
  ])('expiresAt as %s is not an expiry: it logs in', async (_l, expiresAt) => {
    const { provider, authorize } = samlPure({
      accessToken: STORED_COOKIES,
      expiresAt,
    });
    const t = recordingTargets();
    await provider.authorize(t.requestTarget);
    expect(authorize).toHaveBeenCalledTimes(1);
    expect(t.request.cookies).toEqual([NEW_COOKIES]);
  });

  it('past expiresAt: logs in once through the strategy and presents the new cookies', async () => {
    const { provider, authorize } = samlPure({
      accessToken: STORED_COOKIES,
      expiresAt: Date.now() - 1,
    });
    const t = recordingTargets();
    await expect(provider.authorize(t.requestTarget)).resolves.toEqual({
      ok: true,
    });
    expect(authorize).toHaveBeenCalledTimes(1);
    expect(t.request.cookies).toEqual([NEW_COOKIES]);
  });

  it('within the one-minute buffer before expiresAt: logs in', async () => {
    const { provider, authorize } = samlPure({
      accessToken: STORED_COOKIES,
      expiresAt: Date.now() + 30_000,
    });
    await provider.getTokens();
    expect(authorize).toHaveBeenCalledTimes(1);
  });

  it('without expiresAt: the stored cookies are taken as expired, and it logs in', async () => {
    const { provider, authorize } = samlPure({ accessToken: STORED_COOKIES });
    const tokens = await provider.getTokens();
    expect(authorize).toHaveBeenCalledTimes(1);
    expect(tokens.authorizationToken).toBe(NEW_COOKIES);
  });

  it('onTokens after the login carries the new cookies and their expiresAt', async () => {
    const { provider, onTokens, loginExpiresAt } = samlPure({
      accessToken: STORED_COOKIES,
      expiresAt: Date.now() - 1,
    });
    await provider.getTokens();
    expect(onTokens).toHaveBeenCalledTimes(1);
    expect(onTokens.mock.calls[0]![0]).toMatchObject({
      authorizationToken: NEW_COOKIES,
      tokenType: 'saml',
      expiresAt: loginExpiresAt,
    });
  });

  it('a seed is not new: onTokens is not called while the stored cookies are reused', async () => {
    const { provider, onTokens } = samlPure({
      accessToken: STORED_COOKIES,
      expiresAt: Date.now() + HOUR,
    });
    await provider.getTokens();
    expect(onTokens).not.toHaveBeenCalled();
  });
});

// ---- The JWT providers: `exp` first, `expiresAt` only for a token without one.

interface Seed {
  accessToken?: string;
  refreshToken?: string;
  expiresAt?: number;
}

const neverCalled = {
  authorize: async () => {
    throw new Error('the strategy must not be called in this test');
  },
};
const saml = {
  idpSsoUrl: 'https://idp/sso',
  spEntityId: 'sp',
  idpInitiated: true,
  authorization: neverCalled,
  assertionValidator: {
    validate: async () => {
      throw new Error('unused');
    },
  } as unknown as IAssertionValidator,
};

const jwtProviders: Array<[string, (seed: Seed) => BaseTokenProvider]> = [
  [
    'AuthorizationCodeProvider',
    (seed) =>
      new AuthorizationCodeProvider({
        uaaUrl: 'https://uaa',
        clientId: 'c',
        clientSecret: 's',
        authorization: neverCalled,
        ...seed,
      }),
  ],
  [
    'UaaPasscodeProvider',
    (seed) =>
      new UaaPasscodeProvider({
        uaaUrl: 'https://uaa',
        clientId: 'c',
        authorization: neverCalled,
        ...seed,
      }),
  ],
  [
    'OidcBrowserProvider',
    (seed) =>
      new OidcBrowserProvider({
        clientId: 'c',
        tokenEndpoint: 'https://idp/token',
        authorizationEndpoint: 'https://idp/auth',
        authorization: neverCalled as never,
        ...seed,
      }),
  ],
  [
    'OidcDeviceFlowProvider',
    (seed) =>
      new OidcDeviceFlowProvider({
        clientId: 'c',
        tokenEndpoint: 'https://idp/token',
        deviceAuthorizationEndpoint: 'https://idp/device',
        presenter: {
          present: async () => {
            throw new Error('unused');
          },
        } as never,
        ...seed,
      }),
  ],
  [
    'OidcPasswordProvider',
    (seed) =>
      new OidcPasswordProvider({
        clientId: 'c',
        tokenEndpoint: 'https://idp/token',
        username: 'u',
        password: 'p',
        ...seed,
      }),
  ],
  [
    'OidcTokenExchangeProvider',
    (seed) =>
      new OidcTokenExchangeProvider({
        clientId: 'c',
        tokenEndpoint: 'https://idp/token',
        subjectToken: 'subject',
        subjectTokenType: 'urn:ietf:params:oauth:token-type:access_token',
        ...seed,
      }),
  ],
  [
    'Saml2BearerProvider',
    (seed) =>
      new Saml2BearerProvider({
        ...saml,
        tokenUrl: 'https://uaa/oauth/token',
        clientId: 'c',
        clientSecret: 's',
        ...seed,
      }),
  ],
];

const RENEWED = 'renewed-token';

/** The provider with its login and refresh replaced, so nothing reaches a network. */
function seeded(make: (seed: Seed) => BaseTokenProvider, seed: Seed) {
  const provider = make(seed);
  const renewed: ITokenResult = {
    authorizationToken: RENEWED,
    authType: 'password',
    tokenType: 'jwt',
    expiresAt: Date.now() + HOUR,
  };
  const internals = provider as unknown as {
    performLogin: () => Promise<ITokenResult>;
    performRefresh: () => Promise<ITokenResult>;
  };
  const login = jest
    .spyOn(internals, 'performLogin')
    .mockResolvedValue(renewed);
  const refresh = jest
    .spyOn(internals, 'performRefresh')
    .mockResolvedValue(renewed);
  return { provider, login, refresh };
}

describe.each(jwtProviders)('%s seeded with a stored token', (_name, make) => {
  it('a token with no exp and a future expiresAt is reused until it', async () => {
    const expiresAt = Date.now() + HOUR;
    const { provider, login, refresh } = seeded(make, {
      accessToken: OPAQUE,
      expiresAt,
    });
    const tokens = await provider.getTokens();
    expect(tokens.authorizationToken).toBe(OPAQUE);
    expect(tokens.expiresAt).toBe(expiresAt);
    expect(login).not.toHaveBeenCalled();
    expect(refresh).not.toHaveBeenCalled();
  });

  it('a token with no exp and a past expiresAt is renewed', async () => {
    const { provider, login } = seeded(make, {
      accessToken: OPAQUE,
      expiresAt: Date.now() - 1,
    });
    const tokens = await provider.getTokens();
    expect(tokens.authorizationToken).toBe(RENEWED);
    expect(login).toHaveBeenCalledTimes(1);
  });

  it("a JWT's own exp wins over a later expiresAt: expired by exp, it is renewed", async () => {
    const { provider, login } = seeded(make, {
      accessToken: jwt(Date.now() - HOUR),
      expiresAt: Date.now() + HOUR,
    });
    const tokens = await provider.getTokens();
    expect(tokens.authorizationToken).toBe(RENEWED);
    expect(login).toHaveBeenCalledTimes(1);
  });

  it("a JWT's own exp wins over an earlier expiresAt: valid by exp, it is reused", async () => {
    const exp = Date.now() + HOUR;
    const token = jwt(exp);
    const { provider, login } = seeded(make, {
      accessToken: token,
      expiresAt: Date.now() - HOUR,
    });
    const tokens = await provider.getTokens();
    expect(tokens.authorizationToken).toBe(token);
    expect(tokens.expiresAt).toBe(Math.floor(exp / 1000) * 1000);
    expect(login).not.toHaveBeenCalled();
  });

  it('a JWT whose exp is 0 is expired by it, whatever expiresAt says', async () => {
    const { provider, login } = seeded(make, {
      accessToken: jwt(0),
      expiresAt: Date.now() + HOUR,
    });
    const tokens = await provider.getTokens();
    expect(tokens.authorizationToken).toBe(RENEWED);
    expect(login).toHaveBeenCalledTimes(1);
  });

  it.each([
    ['Infinity', Number.POSITIVE_INFINITY],
    ['NaN', Number.NaN],
    ['a numeric string', '9999999999999' as unknown as number],
  ])(
    'expiresAt as %s is not an expiry: the opaque token is renewed',
    async (_l, expiresAt) => {
      const { provider } = seeded(make, { accessToken: OPAQUE, expiresAt });
      const tokens = await provider.getTokens();
      expect(tokens.authorizationToken).toBe(RENEWED);
    },
  );

  it('a token with neither exp nor expiresAt is renewed', async () => {
    const { provider, login } = seeded(make, { accessToken: OPAQUE });
    const tokens = await provider.getTokens();
    expect(tokens.authorizationToken).toBe(RENEWED);
    expect(login).toHaveBeenCalledTimes(1);
  });

  it('expiresAt without a token seeds nothing', async () => {
    const { provider, login } = seeded(make, {
      expiresAt: Date.now() + HOUR,
    });
    const tokens = await provider.getTokens();
    expect(tokens.authorizationToken).toBe(RENEWED);
    expect(login).toHaveBeenCalledTimes(1);
  });
});
