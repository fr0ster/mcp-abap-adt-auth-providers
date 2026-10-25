/**
 * `authDebug` reaches the token sites through a real provider, constructed with
 * `authDebug: true` and with it absent, one site per provider. With it, the
 * site's one line is `[<operation>] token endpoint said` with `sent`; without
 * it, the safe-facts line. The provider's grant reaches the failure's facts the
 * same way.
 *
 * axios is mocked at the module boundary, so every real site runs; the token
 * endpoint answers `400 invalid_grant`.
 */

import { beforeEach, describe, expect, it, jest } from '@jest/globals';
import { readFailure } from '@mcp-abap-adt/auth-errors';
import type {
  IAssertionValidator,
  IAuthorizationStrategy,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import axios from 'axios';
import { prepareSecret } from '../../auth/tokenRequest';
import { AuthorizationCodeProvider } from '../../providers/AuthorizationCodeProvider';
import type { BaseTokenProvider } from '../../providers/BaseTokenProvider';
import { ClientCredentialsProvider } from '../../providers/ClientCredentialsProvider';
import { OidcBrowserProvider } from '../../providers/OidcBrowserProvider';
import { OidcDeviceFlowProvider } from '../../providers/OidcDeviceFlowProvider';
import { OidcPasswordProvider } from '../../providers/OidcPasswordProvider';
import { OidcTokenExchangeProvider } from '../../providers/OidcTokenExchangeProvider';
import { Saml2BearerProvider } from '../../providers/Saml2BearerProvider';
import { UaaPasscodeProvider } from '../../providers/UaaPasscodeProvider';
import { refreshThenLogin } from '../../renewal';
import { phrase } from '../helpers/tokenRequestSites';

jest.mock('axios', () => {
  const mocked = jest.createMockFromModule<Record<string, unknown>>('axios');
  mocked.AxiosError =
    jest.requireActual<Record<string, unknown>>('axios').AxiosError;
  return mocked;
});
type Mock = jest.Mock<(...args: any[]) => Promise<unknown>>;
const mockedAxios = axios as unknown as Mock & { post: Mock };

const SECRET = 'client-secret-0123456789';

const refused = () => ({
  isAxiosError: true,
  response: { status: 400, data: { error: 'invalid_grant' } },
});

beforeEach(() => {
  jest.resetAllMocks();
  mockedAxios.mockImplementation(async () => {
    throw refused();
  });
  mockedAxios.post.mockImplementation(async () => {
    throw refused();
  });
});

const codeStrategy = <T>(payload: T): IAuthorizationStrategy<T> => ({
  authorize: async () => ({
    payload,
    redirectUri: 'http://localhost:61001/callback',
  }),
});

/**
 * Builds the URL first, as a browser strategy does: the provider then holds
 * this attempt's PKCE verifier and sends it (a code no URL was
 * built for is exchanged without one).
 */
const buildingCodeStrategy = <T>(payload: T): IAuthorizationStrategy<T> => ({
  authorize: async (request) => {
    await request.buildAuthorizationUrl('http://localhost:61001/callback');
    return { payload, redirectUri: 'http://localhost:61001/callback' };
  },
});

const acceptingSamlValidator = (): IAssertionValidator => ({
  async validate(payload) {
    return {
      expiresAt: new Date(Date.now() + 3600_000),
      assertionId: '_stub',
      issuer: 'urn:stub:idp',
      raw: payload,
      signedXml: payload,
    };
  },
});

const samlPayload = (): string => {
  const assertion =
    '<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a"><saml2:Issuer>idp</saml2:Issuer></saml2:Assertion>';
  const response = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>${assertion}</samlp:Response>`;
  return Buffer.from(response, 'utf8').toString('base64');
};

type Make = (extra: {
  logger: ILogger;
  authDebug?: boolean;
}) => BaseTokenProvider;

/**
 * One provider per row: its first site's operation, the grant its failures
 * name, and one secret that site carries by name.
 */
const PROVIDERS: [string, Make, string, string, string][] = [
  [
    'ClientCredentialsProvider',
    (extra) =>
      new ClientCredentialsProvider({
        renewal: refreshThenLogin(),
        uaaUrl: 'https://uaa',
        clientId: 'cid',
        clientSecret: SECRET,
        ...extra,
      }),
    'client-credentials',
    'client_credentials',
    'client_secret',
  ],
  [
    'AuthorizationCodeProvider',
    (extra) =>
      new AuthorizationCodeProvider({
        renewal: refreshThenLogin(),
        uaaUrl: 'https://uaa',
        clientId: 'cid',
        clientSecret: SECRET,
        authorization: codeStrategy('the-authorization-code'),
        ...extra,
      }),
    'code-exchange',
    'authorization_code',
    'code',
  ],
  [
    'UaaPasscodeProvider',
    (extra) =>
      new UaaPasscodeProvider({
        renewal: refreshThenLogin(),
        uaaUrl: 'https://uaa',
        clientId: 'cf',
        clientSecret: SECRET,
        authorization: codeStrategy('passcode-0123456789'),
        ...extra,
      }),
    'passcode-exchange',
    'password',
    'passcode',
  ],
  [
    'Saml2BearerProvider',
    (extra) =>
      new Saml2BearerProvider({
        renewal: refreshThenLogin(),
        idpSsoUrl: 'https://idp/sso',
        spEntityId: 'sp-entity',
        uaaUrl: 'https://uaa',
        clientId: 'cid',
        clientSecret: SECRET,
        idpInitiated: true,
        authorization: codeStrategy(samlPayload()),
        assertionValidator: acceptingSamlValidator(),
        ...extra,
      }),
    'saml-token-exchange',
    'saml2_bearer',
    'assertion',
  ],
  [
    'OidcBrowserProvider',
    (extra) =>
      new OidcBrowserProvider({
        renewal: refreshThenLogin(),
        clientId: 'cid',
        clientSecret: SECRET,
        tokenEndpoint: 'https://idp/token',
        authorizationEndpoint: 'https://idp/auth',
        authorization: buildingCodeStrategy({
          code: 'the-authorization-code',
        }),
        ...extra,
      }),
    'oidc-token-request',
    'authorization_code_pkce',
    'code_verifier',
  ],
  [
    'OidcDeviceFlowProvider',
    (extra) =>
      new OidcDeviceFlowProvider({
        renewal: refreshThenLogin(),
        clientId: 'cid',
        clientSecret: SECRET,
        tokenEndpoint: 'https://idp/token',
        deviceAuthorizationEndpoint: 'https://idp/device',
        presenter: { present: async () => {} },
        ...extra,
      }),
    'device-authorization',
    'authorization_code',
    // The device initiation carries no secret of its own: `sent` is empty.
    '',
  ],
  [
    'OidcPasswordProvider',
    (extra) =>
      new OidcPasswordProvider({
        renewal: refreshThenLogin(),
        clientId: 'cid',
        clientSecret: SECRET,
        tokenEndpoint: 'https://idp/token',
        username: 'user',
        password: 'pass-word-0123456789',
        ...extra,
      }),
    'password-grant',
    'password',
    'password',
  ],
  [
    'OidcTokenExchangeProvider',
    (extra) =>
      new OidcTokenExchangeProvider({
        renewal: refreshThenLogin(),
        clientId: 'cid',
        clientSecret: SECRET,
        tokenEndpoint: 'https://idp/token',
        subjectToken: 'subject-token-0123456789',
        subjectTokenType: 'urn:ietf:params:oauth:token-type:access_token',
        ...extra,
      }),
    'oidc-token-request',
    'user_token',
    'subject_token',
  ],
];

/** A logger keeping its debug lines. */
function debugLines(): {
  logger: ILogger;
  lines: { message: string; meta: unknown }[];
} {
  const lines: { message: string; meta: unknown }[] = [];
  return {
    logger: {
      debug: (message: string, meta?: unknown) => lines.push({ message, meta }),
      info: () => {},
      warn: () => {},
      error: () => {},
    },
    lines,
  };
}

describe.each(PROVIDERS)(
  '%s threads authDebug and its grant to its site',
  (_name, make, operation, grant, secretName) => {
    it.each([
      ['absent', undefined],
      ['true', true],
    ])('authDebug %s', async (_mode, authDebug) => {
      const { logger, lines } = debugLines();
      const provider = make({
        logger,
        ...(authDebug === undefined ? {} : { authDebug }),
      });
      const thrown = await provider.getTokens().catch((e: unknown) => e);
      // The grant reaches the failure (`getTokens()` passes it through).
      expect(readFailure(thrown, 'unfamiliar-error').facts).toEqual({
        operation,
        grant,
        problem: 'refused',
        status: 400,
        oauthError: 'invalid_grant',
      });
      // The site's own line; the provider's other debug lines aside.
      const siteLines = lines.filter(({ message }) =>
        message.includes('token endpoint'),
      );
      expect(siteLines).toHaveLength(1);
      const line = siteLines[0];
      if (authDebug === true) {
        expect(line?.message).toBe(`[${operation}] token endpoint said`);
        const sent =
          (line?.meta as { sent: Record<string, string> } | undefined)?.sent ??
          {};
        if (secretName !== '') {
          expect(Object.keys(sent)).toContain(secretName);
        }
        if (operation !== 'device-authorization') {
          expect(sent.client_secret).toBe(prepareSecret(SECRET, true));
        }
      } else {
        expect(line).toEqual({
          message: `${phrase(operation as never)}: the token endpoint refused the request`,
          meta: { status: 400, error: 'invalid_grant' },
        });
      }
    });
  },
);
