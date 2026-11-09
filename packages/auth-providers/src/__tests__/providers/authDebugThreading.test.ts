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

import '../helpers/axiosModuleMock';
import assert from 'node:assert/strict';
import { beforeEach, describe, it } from 'node:test';
import { readFailure } from '@mcp-abap-adt/auth-errors';
import type {
  IAssertionValidator,
  IAuthorizationStrategy,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
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
import { mockedAxios, resetAxiosMock } from '../helpers/axiosModuleMock';
import { cases, caseTitle, contains } from '../helpers/expectations';
import { phrase } from '../helpers/tokenRequestSites';

const SECRET = 'client-secret-0123456789';

const refused = () => ({
  isAxiosError: true,
  response: { status: 400, data: { error: 'invalid_grant' } },
});

beforeEach(() => {
  resetAxiosMock();
  mockedAxios.mock.mockImplementation(async () => {
    throw refused();
  });
  mockedAxios.post.mock.mockImplementation(async () => {
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

for (const [caseIndex, caseRow] of PROVIDERS.entries()) {
  const [_name, make, operation, grant, secretName] = caseRow;
  describe(
    caseTitle(
      '%s threads authDebug and its grant to its site',
      caseRow,
      caseIndex,
    ),
    () => {
      for (const [caseIndex, caseRow] of cases([
        ['absent', undefined],
        ['true', true],
      ]).entries()) {
        const [_mode, authDebug] = caseRow;
        it(caseTitle('authDebug %s', caseRow, caseIndex), async () => {
          const { logger, lines } = debugLines();
          const provider = make({
            logger,
            ...(authDebug === undefined ? {} : { authDebug }),
          });
          const thrown = await provider.getTokens().catch((e: unknown) => e);
          // The grant reaches the failure (`getTokens()` passes it through).
          assert.deepEqual(readFailure(thrown, 'unfamiliar-error').facts, {
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
          assert.equal(siteLines.length, 1);
          const line = siteLines[0];
          if (authDebug === true) {
            assert.equal(line?.message, `[${operation}] token endpoint said`);
            const sent =
              (line?.meta as { sent: Record<string, string> } | undefined)
                ?.sent ?? {};
            if (secretName !== '') {
              contains(Object.keys(sent), secretName);
            }
            if (operation !== 'device-authorization') {
              assert.equal(sent.client_secret, prepareSecret(SECRET, true));
            }
          } else {
            assert.deepEqual(line, {
              message: `${phrase(operation as never)}: the token endpoint refused the request`,
              meta: { status: 400, error: 'invalid_grant' },
            });
          }
        });
      }
    },
  );
}
