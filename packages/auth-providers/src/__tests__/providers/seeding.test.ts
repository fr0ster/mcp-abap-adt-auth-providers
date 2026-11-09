/**
 * A provider seeded with a stored credential reuses it until it expires, and
 * logs in only after. A JWT states its own expiry (`exp`); cookies and an
 * opaque token do not, so the consumer states it beside them (`expiresAt`).
 */

import assert from 'node:assert/strict';
import { describe, it, mock } from 'node:test';
import type {
  IAssertionValidator,
  IAuthorizationStrategy,
  IAuthRejection,
  ITokenResult,
  PersistenceReport,
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
import { refreshThenLogin } from '../../renewal';
import { cases, caseTitle, matchObject } from '../helpers/expectations';
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
  const authorize = mock.fn<IAuthorizationStrategy<string>['authorize']>(
    async () => ({
      payload: 'PHNhbWxwOlJlc3BvbnNlLz4=',
      redirectUri: 'https://sp/acs',
    }),
  );
  const loginExpiresAt = Date.now() + 2 * HOUR;
  const validate = mock.fn(async () => ({
    expiresAt: new Date(loginExpiresAt),
  }));
  const cookieProvider = mock.fn(async () => loginCookies);
  const report = mock.fn(async (_report: PersistenceReport) => {});
  const provider = new Saml2PureProvider({
    renewal: refreshThenLogin(),
    idpSsoUrl: 'https://idp/sso',
    spEntityId: 'sp',
    idpInitiated: true,
    authorization: { authorize },
    assertionValidator: { validate } as unknown as IAssertionValidator,
    cookieProvider,
    persistence: { report },
    ...seed,
  });
  return { provider, authorize, cookieProvider, report, loginExpiresAt };
}

describe('Saml2PureProvider seeded with stored cookies', () => {
  it('before expiresAt: answers the stored cookies and never logs in', async () => {
    const expiresAt = Date.now() + HOUR;
    const { provider, authorize, cookieProvider } = samlPure({
      accessToken: STORED_COOKIES,
      expiresAt,
    });

    const tokens = await provider.getTokens();
    matchObject(tokens, {
      authorizationToken: STORED_COOKIES,
      tokenType: 'saml',
      expiresAt,
    });

    const t = recordingTargets();
    assert.deepEqual(await provider.authorize(t.requestTarget), {
      ok: true,
    });
    assert.deepEqual(t.request.cookies, [STORED_COOKIES]);
    assert.deepEqual(t.request.headers, {});
    assert.equal(authorize.mock.callCount(), 0);
    assert.equal(cookieProvider.mock.callCount(), 0);
  });

  it('a 401 on the stored cookies before expiresAt: rejected() logs in once and the new cookies are presented', async () => {
    const { provider, authorize } = samlPure({
      accessToken: STORED_COOKIES,
      expiresAt: Date.now() + HOUR,
    });
    const first = recordingTargets();
    await provider.authorize(first.requestTarget);
    assert.deepEqual(first.request.cookies, [STORED_COOKIES]);

    assert.deepEqual(await provider.rejected(R401), { ok: true });
    assert.equal(authorize.mock.callCount(), 1);
    const second = recordingTargets();
    await provider.authorize(second.requestTarget);
    assert.deepEqual(second.request.cookies, [NEW_COOKIES]);
  });

  it('a 401 on the stored cookies, and a login that yields them again: rejected() refuses', async () => {
    const { provider } = samlPure(
      { accessToken: STORED_COOKIES, expiresAt: Date.now() + HOUR },
      STORED_COOKIES,
    );
    await provider.authorize(recordingTargets().requestTarget);
    const outcome = await provider.rejected(R401);
    assert.equal(outcome.ok, false);
    assert.equal(
      outcome.ok === false && outcome.refusal.reason,
      'the renewal returned the credential that was refused',
    );
  });

  for (const [caseIndex, caseRow] of cases([
    ['Infinity', Number.POSITIVE_INFINITY],
    ['NaN', Number.NaN],
    ['a numeric string', '9999999999999' as unknown as number],
  ]).entries()) {
    const [_l, expiresAt] = caseRow;
    it(
      caseTitle(
        'expiresAt as %s is not an expiry: it logs in',
        caseRow,
        caseIndex,
      ),
      async () => {
        const { provider, authorize } = samlPure({
          accessToken: STORED_COOKIES,
          expiresAt,
        });
        const t = recordingTargets();
        await provider.authorize(t.requestTarget);
        assert.equal(authorize.mock.callCount(), 1);
        assert.deepEqual(t.request.cookies, [NEW_COOKIES]);
      },
    );
  }

  it('past expiresAt: logs in once through the strategy and presents the new cookies', async () => {
    const { provider, authorize } = samlPure({
      accessToken: STORED_COOKIES,
      expiresAt: Date.now() - 1,
    });
    const t = recordingTargets();
    assert.deepEqual(await provider.authorize(t.requestTarget), {
      ok: true,
    });
    assert.equal(authorize.mock.callCount(), 1);
    assert.deepEqual(t.request.cookies, [NEW_COOKIES]);
  });

  it('within the one-minute buffer before expiresAt: logs in', async () => {
    const { provider, authorize } = samlPure({
      accessToken: STORED_COOKIES,
      expiresAt: Date.now() + 30_000,
    });
    await provider.getTokens();
    assert.equal(authorize.mock.callCount(), 1);
  });

  it('without expiresAt: the stored cookies are taken as expired, and it logs in', async () => {
    const { provider, authorize } = samlPure({ accessToken: STORED_COOKIES });
    const tokens = await provider.getTokens();
    assert.equal(authorize.mock.callCount(), 1);
    assert.equal(tokens.authorizationToken, NEW_COOKIES);
  });

  it('the report after the login carries the new cookies and their expiresAt', async () => {
    const { provider, report, loginExpiresAt } = samlPure({
      accessToken: STORED_COOKIES,
      expiresAt: Date.now() - 1,
    });
    await provider.getTokens();
    assert.equal(report.mock.callCount(), 1);
    matchObject(report.mock.calls.map((call) => call.arguments)[0]![0], {
      event: 'credential',
      credential: {
        authorizationToken: NEW_COOKIES,
        tokenType: 'saml',
        expiresAt: loginExpiresAt,
      },
      awaited: true,
    });
  });

  it('a seed is not new: nothing is reported while the stored cookies are reused', async () => {
    const { provider, report } = samlPure({
      accessToken: STORED_COOKIES,
      expiresAt: Date.now() + HOUR,
    });
    await provider.getTokens();
    assert.equal(report.mock.callCount(), 0);
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
        renewal: refreshThenLogin(),
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
        renewal: refreshThenLogin(),
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
        renewal: refreshThenLogin(),
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
        renewal: refreshThenLogin(),
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
        renewal: refreshThenLogin(),
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
        renewal: refreshThenLogin(),
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
        renewal: refreshThenLogin(),
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
  const login = mock.method(internals, 'performLogin', async () => renewed);
  const refresh = mock.method(internals, 'performRefresh', async () => renewed);
  return { provider, login, refresh };
}

for (const [caseIndex, caseRow] of jwtProviders.entries()) {
  const [_name, make] = caseRow;
  describe(
    caseTitle('%s seeded with a stored token', caseRow, caseIndex),
    () => {
      it('a token with no exp and a future expiresAt is reused until it', async () => {
        const expiresAt = Date.now() + HOUR;
        const { provider, login, refresh } = seeded(make, {
          accessToken: OPAQUE,
          expiresAt,
        });
        const tokens = await provider.getTokens();
        assert.equal(tokens.authorizationToken, OPAQUE);
        assert.equal(tokens.expiresAt, expiresAt);
        assert.equal(login.mock.callCount(), 0);
        assert.equal(refresh.mock.callCount(), 0);
      });

      it('a token with no exp and a past expiresAt is renewed', async () => {
        const { provider, login } = seeded(make, {
          accessToken: OPAQUE,
          expiresAt: Date.now() - 1,
        });
        const tokens = await provider.getTokens();
        assert.equal(tokens.authorizationToken, RENEWED);
        assert.equal(login.mock.callCount(), 1);
      });

      it("a JWT's own exp wins over a later expiresAt: expired by exp, it is renewed", async () => {
        const { provider, login } = seeded(make, {
          accessToken: jwt(Date.now() - HOUR),
          expiresAt: Date.now() + HOUR,
        });
        const tokens = await provider.getTokens();
        assert.equal(tokens.authorizationToken, RENEWED);
        assert.equal(login.mock.callCount(), 1);
      });

      it("a JWT's own exp wins over an earlier expiresAt: valid by exp, it is reused", async () => {
        const exp = Date.now() + HOUR;
        const token = jwt(exp);
        const { provider, login } = seeded(make, {
          accessToken: token,
          expiresAt: Date.now() - HOUR,
        });
        const tokens = await provider.getTokens();
        assert.equal(tokens.authorizationToken, token);
        assert.equal(tokens.expiresAt, Math.floor(exp / 1000) * 1000);
        assert.equal(login.mock.callCount(), 0);
      });

      it('a JWT whose exp is 0 is expired by it, whatever expiresAt says', async () => {
        const { provider, login } = seeded(make, {
          accessToken: jwt(0),
          expiresAt: Date.now() + HOUR,
        });
        const tokens = await provider.getTokens();
        assert.equal(tokens.authorizationToken, RENEWED);
        assert.equal(login.mock.callCount(), 1);
      });

      for (const [caseIndex, caseRow] of cases([
        ['Infinity', Number.POSITIVE_INFINITY],
        ['NaN', Number.NaN],
        ['a numeric string', '9999999999999' as unknown as number],
      ]).entries()) {
        const [_l, expiresAt] = caseRow;
        it(
          caseTitle(
            'expiresAt as %s is not an expiry: the opaque token is renewed',
            caseRow,
            caseIndex,
          ),
          async () => {
            const { provider } = seeded(make, {
              accessToken: OPAQUE,
              expiresAt,
            });
            const tokens = await provider.getTokens();
            assert.equal(tokens.authorizationToken, RENEWED);
          },
        );
      }

      it('a token with neither exp nor expiresAt is renewed', async () => {
        const { provider, login } = seeded(make, { accessToken: OPAQUE });
        const tokens = await provider.getTokens();
        assert.equal(tokens.authorizationToken, RENEWED);
        assert.equal(login.mock.callCount(), 1);
      });

      it('expiresAt without a token seeds nothing', async () => {
        const { provider, login } = seeded(make, {
          expiresAt: Date.now() + HOUR,
        });
        const tokens = await provider.getTokens();
        assert.equal(tokens.authorizationToken, RENEWED);
        assert.equal(login.mock.callCount(), 1);
      });
    },
  );
}
