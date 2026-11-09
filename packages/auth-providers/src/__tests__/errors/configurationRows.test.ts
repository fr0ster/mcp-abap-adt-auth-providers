/**
 * Configuration throws: every one is an `AuthProviderFailure` of kind
 * `configuration`, its `case` and `fields` as the row says, the words rendered
 * by auth-errors 1.0.0, `allowed` where the row sets it, and — for the redirect
 * mismatch only — the two URIs as diagnostics, never in `reason` or `hint`. A
 * configured value never reaches the words.
 *
 * A constructor may throw it (a constructor is not a moment of the contract);
 * a token provider's `getTokens()` throws it as a failure
 * holding the same error.
 */

import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeEach, describe, it, mock } from 'node:test';
import {
  isAuthProviderFailure,
  isMinted,
  readFailure,
} from '@mcp-abap-adt/auth-errors';
import type {
  AuthorizationOutcome,
  IAuthorizationStrategy,
  IAuthProviderError,
} from '@mcp-abap-adt/interfaces-auth';
import { getJwtAuthorizationUrl } from '../../auth/browserAuth';
import { exchangeSamlAssertion } from '../../auth/saml2TokenExchange';
import { loopback } from '../../authorization/transport';
import { noClientAuthentication } from '../../clientAuthentication/noClientAuthentication';
import { FileCertificateMaterialLoader } from '../../credentials/FileCertificateMaterialLoader';
import { AuthorizationCodeProvider } from '../../providers/AuthorizationCodeProvider';
import { ClientCredentialsProvider } from '../../providers/ClientCredentialsProvider';
import { OidcBrowserProvider } from '../../providers/OidcBrowserProvider';
import { OidcDeviceFlowProvider } from '../../providers/OidcDeviceFlowProvider';
import { OidcPasswordProvider } from '../../providers/OidcPasswordProvider';
import { OidcTokenExchangeProvider } from '../../providers/OidcTokenExchangeProvider';
import { Saml2PureProvider } from '../../providers/Saml2PureProvider';
import {
  checkAssertionValidator,
  getSamlAssertion,
  resolveTokenUrl,
  type Saml2CommonConfig,
  validateSamlConfig,
} from '../../providers/saml2Utils';
import { refreshThenLogin } from '../../renewal';
import { browserCallbackStrategy } from '../../strategies';
import { staticCodeStrategy } from '../../strategies/codeStrategies';
import { createSignedResponseValidator } from '../../validation/assertionValidator';
import { createInMemoryReplayStore } from '../../validation/inMemoryReplayStore';
import { toPem } from '../../validation/signedNode';
import {
  cases,
  caseTitle,
  matchObject,
  notContains,
} from '../helpers/expectations';
import { getAvailablePort } from '../helpers/netHelpers';
import { CERTIFICATES } from '../helpers/packagePaths';

import oidcDiscovery = require('../../auth/oidcDiscovery');

/**
 * discoverOidc replaced on its module object for each test (what was a
 * jest.mock of the module, its mtlsAlias kept real): the providers read it
 * off the module at each call. It answers `undefined` unless a test says
 * otherwise, as the automock did.
 */
let mockedDiscovery = mock.method(
  oidcDiscovery,
  'discoverOidc',
  async () => undefined,
);

const CERT = readFileSync(join(CERTIFICATES, 'client.crt'), 'utf8');
const CHECK = 'check the provider configuration';
const MARKER = 'CONFIGURED-VALUE-MARKER';

/** What `run` throws, synchronously or as a rejection; fails when nothing. */
async function thrownBy(run: () => unknown): Promise<unknown> {
  try {
    await run();
  } catch (error) {
    return error;
  }
  throw new Error('expected a throw');
}

interface Row {
  readonly case: string;
  readonly fields: readonly string[];
  readonly reason: string;
  /** `null`: the case has no hint; absent: the shared configuration hint. */
  readonly hint?: string | null;
  readonly allowed?: string;
  readonly diagnostics?: Readonly<Record<string, string>>;
}

/**
 * The thrown value is an `AuthProviderFailure` of this copy holding a minted
 * `configuration` error of the row: case (and variant), fields, words,
 * `allowed` only where set, diagnostics only where set — and nothing of a
 * diagnostic or of the configured marker in the words.
 */
function expectRow(thrown: unknown, row: Row): IAuthProviderError {
  assert.equal(isAuthProviderFailure(thrown), true);
  const error = readFailure(thrown, 'unfamiliar-error');
  assert.equal(isMinted(error), true);
  assert.equal(error.kind, 'configuration');
  assert.equal(error.variant, row.case);
  assert.deepEqual(error.facts, {
    case: row.case,
    fields: row.fields,
    ...(row.allowed === undefined ? {} : { allowed: row.allowed }),
  });
  assert.equal(error.reason, row.reason);
  assert.equal(error.hint, row.hint === null ? undefined : (row.hint ?? CHECK));
  if (row.diagnostics === undefined) {
    assert.equal(error.diagnostics, undefined);
  } else {
    assert.deepEqual(error.diagnostics, row.diagnostics);
    for (const value of Object.values(row.diagnostics)) {
      notContains(error.reason, value);
      notContains(error.hint ?? '', value);
    }
  }
  const words = `${error.reason} ${error.hint ?? ''}`;
  notContains(words, MARKER);
  // The thrown failure's own text is the words, never a configured value.
  notContains(String((thrown as Error).message), MARKER);
  return error;
}

/** A strategy that asks for the URL with `redirectUri`, then answers. */
function asking<T>(
  redirectUri: string,
  payload: T,
): IAuthorizationStrategy<T> & { calls: number } {
  const strategy = {
    calls: 0,
    async authorize(request: {
      buildAuthorizationUrl(uri: string): Promise<string>;
    }): Promise<AuthorizationOutcome<T>> {
      strategy.calls += 1;
      await request.buildAuthorizationUrl(redirectUri);
      return { payload, redirectUri };
    },
  };
  return strategy as IAuthorizationStrategy<T> & { calls: number };
}

/** A strategy that never asks for the URL, answering `redirectUri`. */
function holding<T>(
  redirectUri: string,
  payload: T,
): IAuthorizationStrategy<T> {
  return {
    async authorize(): Promise<AuthorizationOutcome<T>> {
      return { payload, redirectUri };
    },
  };
}

function samlConfig(
  extra: Partial<Saml2CommonConfig>,
): Saml2CommonConfig & { renewal: ReturnType<typeof refreshThenLogin> } {
  return {
    renewal: refreshThenLogin(),
    idpSsoUrl: 'https://idp.example/sso',
    spEntityId: 'sp',
    authorization: holding('http://localhost:61001/callback', 'PAYLOAD'),
    assertionValidator: { validate: async () => ({}) } as never,
    ...extra,
  };
}

beforeEach(() => {
  mockedDiscovery.mock.restore();
  mockedDiscovery = mock.method(
    oidcDiscovery,
    'discoverOidc',
    async () => undefined,
  );
});

describe('required fields missing (ClientCredentials, AuthorizationCode)', () => {
  it('ClientCredentialsProvider names each missing field', async () => {
    const thrown = await thrownBy(
      () =>
        new ClientCredentialsProvider({
          renewal: refreshThenLogin(),
          uaaUrl: '',
          clientId: '',
        }),
    );
    expectRow(thrown, {
      case: 'required-fields-missing',
      fields: ['uaaUrl', 'clientId', 'clientSecret'],
      reason:
        'required configuration is missing: uaaUrl, clientId, clientSecret',
    });
  });

  it('AuthorizationCodeProvider names only what is missing', async () => {
    const thrown = await thrownBy(
      () =>
        new AuthorizationCodeProvider({
          renewal: refreshThenLogin(),
          uaaUrl: '',
          clientId: MARKER,
          clientSecret: MARKER,
          authorization: holding('http://localhost:61001/callback', 'code'),
        }),
    );
    expectRow(thrown, {
      case: 'required-fields-missing',
      fields: ['uaaUrl'],
      reason: 'required configuration is missing: uaaUrl',
    });
  });
});

describe('clientSecret beside clientAuthentication', () => {
  it('the base constructor refuses both, naming clientSecret', async () => {
    const thrown = await thrownBy(
      () =>
        new ClientCredentialsProvider({
          renewal: refreshThenLogin(),
          uaaUrl: 'https://uaa.example',
          clientId: 'client',
          // '' counts: decided on presence.
          clientSecret: '',
          clientAuthentication: noClientAuthentication(),
        }),
    );
    expectRow(thrown, {
      case: 'client-secret-beside-client-authentication',
      fields: ['clientSecret'],
      reason: 'clientSecret cannot be given beside clientAuthentication',
      hint: 'give the secret to the clientAuthentication strategy, or drop the strategy',
    });
  });
});

describe('SAML configuration', () => {
  it('acsUrl is required with a pre-built authorizationUrl', async () => {
    const thrown = await thrownBy(() =>
      validateSamlConfig(
        samlConfig({ authorizationUrl: `https://idp.example/${MARKER}` }),
      ),
    );
    expectRow(thrown, {
      case: 'saml-acs-required-with-authorization-url',
      fields: ['acsUrl'],
      reason:
        'acsUrl is required when authorizationUrl is set: the ACS inside a pre-built SAML request cannot be read, so it must be declared',
    });
  });

  it('idpInitiated with a declared authnRequestId, at construction', async () => {
    const thrown = await thrownBy(
      () =>
        new Saml2PureProvider({
          ...samlConfig({ idpInitiated: true, authnRequestId: MARKER }),
          cookieProvider: async () => ({ cookies: '' }),
        } as never),
    );
    expectRow(thrown, {
      case: 'saml-idp-initiated-with-request-id',
      fields: ['idpInitiated', 'authnRequestId'],
      reason:
        'SAML idpInitiated is true, but a request ID was also configured or minted: an IdP-initiated login sends no request',
      hint: 'remove one of them',
    });
  });

  it('a shipped validator supplied without idpEntityId', async () => {
    const thrown = await thrownBy(() =>
      checkAssertionValidator(
        samlConfig({
          assertionValidator: createSignedResponseValidator({
            idpCertificates: [CERT],
            replayStore: createInMemoryReplayStore(),
          }),
        }),
      ),
    );
    expectRow(thrown, {
      case: 'saml-shipped-validator-without-issuer',
      fields: ['idpEntityId'],
      reason:
        'the supplied assertionValidator is a shipped one, which refuses every assertion without an expected issuer: idpEntityId is missing',
    });
  });

  it('the SAML bearer exchange without tokenUrl or uaaUrl', async () => {
    const thrown = await thrownBy(() => resolveTokenUrl({}));
    expectRow(thrown, {
      case: 'saml-token-endpoint-missing',
      fields: ['tokenUrl', 'uaaUrl'],
      reason: 'the SAML bearer exchange needs tokenUrl or uaaUrl',
    });
  });

  // Trailing slashes dropped in plain code, linear on a long run.
  it('resolveTokenUrl drops trailing slashes of uaaUrl, linearly', () => {
    assert.equal(
      resolveTokenUrl({ uaaUrl: 'https://uaa.example///' }),
      'https://uaa.example/oauth/token',
    );
    const long = `https://uaa.example${'/'.repeat(100_000)}x`;
    const started = Date.now();
    assert.equal(resolveTokenUrl({ uaaUrl: long }), `${long}/oauth/token`);
    assert.ok(Date.now() - started < 500, `${Date.now() - started} < ${500}`);
  });

  it('idpInitiated without authorizationUrl, and a strategy asking for a URL', async () => {
    const strategy = asking('http://localhost:61001/callback', 'PAYLOAD');
    const thrown = await thrownBy(() =>
      getSamlAssertion(
        samlConfig({ idpInitiated: true, authorization: strategy }),
      ),
    );
    expectRow(thrown, {
      case: 'saml-idp-initiated-without-authorization-url',
      fields: ['idpInitiated', 'authorizationUrl'],
      reason:
        'SAML idpInitiated is true and no authorizationUrl is configured, but the authorization strategy asked for an authorization URL',
      hint: 'configure the IdP-initiated SSO URL as authorizationUrl, or use a strategy that does not call buildAuthorizationUrl',
    });
  });

  const ACS = 'https://sp.example/acs';
  const LISTENING = 'http://localhost:61001/callback';
  const E8 = {
    case: 'saml-acs-mismatch',
    fields: ['acsUrl'],
    reason:
      'SAML acsUrl and the address the authorization strategy used do not match',
    hint: 'they must match',
    diagnostics: { configuredUri: ACS, strategyUri: LISTENING },
  } as const;

  it('the strategy listens elsewhere than acsUrl (inside the builder)', async () => {
    const thrown = await thrownBy(() =>
      getSamlAssertion(
        samlConfig({ acsUrl: ACS, authorization: asking(LISTENING, 'P') }),
      ),
    );
    expectRow(thrown, E8);
  });

  it('the strategy used another address than acsUrl (after it returned)', async () => {
    const thrown = await thrownBy(() =>
      getSamlAssertion(
        samlConfig({
          acsUrl: ACS,
          authnRequestId: 'id',
          authorization: holding(LISTENING, 'P'),
        }),
      ),
    );
    expectRow(thrown, E8);
  });

  it('a URI with a query keeps only its origin and path as a diagnostic', async () => {
    const thrown = await thrownBy(() =>
      getSamlAssertion(
        samlConfig({
          acsUrl: `${ACS}?token=${MARKER}`,
          authnRequestId: 'id',
          authorization: holding(LISTENING, 'P'),
        }),
      ),
    );
    const error = expectRow(thrown, E8);
    notContains(JSON.stringify(error), MARKER);
  });

  it('idpInitiated, and a request ID declared (a direct caller)', async () => {
    const thrown = await thrownBy(() =>
      getSamlAssertion(
        samlConfig({ idpInitiated: true, authnRequestId: MARKER }),
      ),
    );
    expectRow(thrown, {
      case: 'saml-idp-initiated-with-request-id',
      fields: ['idpInitiated'],
      reason:
        'SAML idpInitiated is true, but a request ID was also configured or minted: an IdP-initiated login sends no request',
      hint: 'remove one of them',
    });
  });

  it('no request ID minted, declared or declared absent', async () => {
    const thrown = await thrownBy(() => getSamlAssertion(samlConfig({})));
    expectRow(thrown, {
      case: 'saml-in-response-to-undeclared',
      fields: ['authnRequestId', 'idpInitiated'],
      reason:
        'cannot validate InResponseTo: this login did not build its own AuthnRequest',
      hint: 'configure authnRequestId, or idpInitiated: true if the identity provider starts this login itself',
    });
  });
});

describe('clientId with a client authentication', () => {
  it('the SAML exchange with a strategy and no clientId sends nothing', async () => {
    const thrown = await thrownBy(() =>
      exchangeSamlAssertion(
        'assertion',
        'https://uaa.example/oauth/token',
        undefined,
        undefined,
        undefined,
        {
          strategy: noClientAuthentication(),
        } as never,
      ),
    );
    expectRow(thrown, {
      case: 'client-id-required-with-client-authentication',
      fields: ['clientId'],
      reason: 'clientId is required with a client authentication',
    });
  });
});

describe('redirect mismatch', () => {
  const DECLARED = 'http://localhost:61001/callback';
  const USED = 'http://localhost:61002/callback';
  const PREBUILT = `https://uaa.example/oauth/authorize?client_id=c&redirect_uri=${encodeURIComponent(DECLARED)}&response_type=code`;
  const E12 = {
    case: 'redirect-mismatch',
    fields: ['authorizationUrl'],
    reason:
      'the pre-built authorizationUrl declares a redirect_uri the authorization strategy did not use',
    hint: 'an ephemeral port cannot be used with a pre-built URL',
    diagnostics: { configuredUri: DECLARED, strategyUri: USED },
  } as const;

  for (const [caseIndex, caseRow] of cases([
    ['inside the builder', () => asking(USED, 'code')],
    ['after the strategy returned', () => holding(USED, 'code')],
  ]).entries()) {
    const [_name, strategy] = caseRow;
    it(caseTitle('%s, through getTokens()', caseRow, caseIndex), async () => {
      const provider = new AuthorizationCodeProvider({
        renewal: refreshThenLogin(),
        uaaUrl: 'http://127.0.0.1:9',
        clientId: 'client',
        clientSecret: 'secret',
        authorizationUrl: PREBUILT,
        authorization: strategy(),
      });
      expectRow(await thrownBy(() => provider.getTokens()), E12);
    });
  }

  it('a configuration failure inside a moment is the moment’s refusal, its case, fields and words kept', async () => {
    const provider = new AuthorizationCodeProvider({
      renewal: refreshThenLogin(),
      uaaUrl: 'http://127.0.0.1:9',
      clientId: 'client',
      clientSecret: 'secret',
      authorizationUrl: PREBUILT,
      authorization: holding(USED, 'code'),
    });
    const outcome = await provider.authorize({
      header: () => undefined,
      cookies: () => undefined,
    });
    assert.equal(outcome.ok, false);
    if (outcome.ok) return;
    assert.equal(isMinted(outcome.refusal), true);
    matchObject(outcome.refusal, {
      kind: 'configuration',
      facts: { case: E12.case, fields: E12.fields },
      reason: E12.reason,
      hint: E12.hint,
      diagnostics: E12.diagnostics,
    });
  });
});

describe('an unparseable authorizationUrl', () => {
  // A configuration error naming the field, never the value: case
  // `invalid-value` (interfaces-auth 7.0.0), at construction and at login.
  const row = {
    case: 'invalid-value',
    fields: ['authorizationUrl'],
    reason: 'a configured value cannot be used: authorizationUrl',
    hint: null,
  };

  it('is refused at construction', async () => {
    const thrown = await thrownBy(
      () =>
        new AuthorizationCodeProvider({
          renewal: refreshThenLogin(),
          uaaUrl: 'https://uaa.example',
          clientId: 'client',
          clientSecret: 'secret',
          authorizationUrl: `not a url ${MARKER}`,
          authorization: holding('http://localhost:61001/callback', 'code'),
        }),
    );
    expectRow(thrown, row);
  });

  it('is refused at login when it changed after construction', async () => {
    const provider = new AuthorizationCodeProvider({
      renewal: refreshThenLogin(),
      uaaUrl: 'https://uaa.example',
      clientId: 'client',
      clientSecret: 'secret',
      authorization: holding('http://localhost:61001/callback', 'code'),
    });
    (
      provider as unknown as { config: { authorizationUrl: string } }
    ).config.authorizationUrl = `not a url ${MARKER}`;
    expectRow(await thrownBy(() => provider.getTokens()), row);
  });
});

describe('OIDC endpoints', () => {
  const E13 = {
    case: 'oidc-discovery-needs-issuer',
    fields: ['issuerUrl'],
    reason: 'OIDC issuerUrl is required when discovery is used',
  } as const;
  const endpoint = (field: string) => ({
    case: 'oidc-endpoint-missing',
    fields: [field],
    reason: `OIDC ${field} is required (configure it, or use discovery)`,
  });
  const password = (extra: object = {}) =>
    new OidcPasswordProvider({
      renewal: refreshThenLogin(),
      clientId: 'client',
      username: 'user',
      password: MARKER,
      ...extra,
    });
  const exchange = (extra: object = {}) =>
    new OidcTokenExchangeProvider({
      renewal: refreshThenLogin(),
      clientId: 'client',
      subjectToken: MARKER,
      subjectTokenType: 'urn:ietf:params:oauth:token-type:access_token',
      ...extra,
    });
  const device = (extra: object = {}) =>
    new OidcDeviceFlowProvider({
      renewal: refreshThenLogin(),
      clientId: 'client',
      presenter: { present: async () => undefined } as never,
      ...extra,
    });
  const browser = (extra: object = {}) =>
    new OidcBrowserProvider({
      renewal: refreshThenLogin(),
      clientId: 'client',
      authorization: asking('http://localhost:61001/callback', {
        code: 'code',
      }) as never,
      ...extra,
    });

  for (const [caseIndex, caseRow] of cases([
    ['OidcPasswordProvider', () => password()],
    ['OidcTokenExchangeProvider', () => exchange()],
    ['OidcDeviceFlowProvider', () => device()],
    ['OidcBrowserProvider', () => browser()],
  ]).entries()) {
    const [_name, make] = caseRow;
    it(
      caseTitle('%s login without issuerUrl or endpoints', caseRow, caseIndex),
      async () => {
        expectRow(await thrownBy(() => make().getTokens()), E13);
        assert.equal(mockedDiscovery.mock.callCount(), 0);
      },
    );
  }

  for (const [caseIndex, caseRow] of cases([
    ['OidcPasswordProvider', () => password({ refreshToken: 'r' })],
    ['OidcTokenExchangeProvider', () => exchange({ refreshToken: 'r' })],
    ['OidcDeviceFlowProvider', () => device({ refreshToken: 'r' })],
    ['OidcBrowserProvider', () => browser({ refreshToken: 'r' })],
  ]).entries()) {
    const [_name, make] = caseRow;
    it(
      caseTitle(
        '%s refresh without issuerUrl or tokenEndpoint',
        caseRow,
        caseIndex,
      ),
      async () => {
        const provider = make();
        expectRow(await thrownBy(() => provider.refreshTokens()), E13);
      },
    );
  }

  it('no authorization endpoint configured or discovered', async () => {
    mockedDiscovery.mock.mockImplementation(async () => ({
      token_endpoint: 'https://t',
    }));
    const provider = browser({ issuerUrl: 'https://issuer.example' });
    expectRow(
      await thrownBy(() => provider.getTokens()),
      endpoint('authorizationEndpoint'),
    );
  });

  for (const [caseIndex, caseRow] of cases([
    ['OidcPasswordProvider', () => password({ issuerUrl: 'https://i' })],
    ['OidcTokenExchangeProvider', () => exchange({ issuerUrl: 'https://i' })],
    [
      'OidcDeviceFlowProvider',
      () =>
        device({
          issuerUrl: 'https://i',
          deviceAuthorizationEndpoint: 'https://d',
        }),
    ],
    [
      'OidcBrowserProvider',
      () =>
        browser({ issuerUrl: 'https://i', authorizationEndpoint: 'https://a' }),
    ],
  ]).entries()) {
    const [_name, make] = caseRow;
    it(
      caseTitle(
        '%s without a token endpoint configured or discovered',
        caseRow,
        caseIndex,
      ),
      async () => {
        // A parsed document without the field: data from outside the types.
        mockedDiscovery.mock.mockImplementation(async () => JSON.parse('{}'));
        expectRow(
          await thrownBy(() => make().getTokens()),
          endpoint('tokenEndpoint'),
        );
      },
    );
  }

  it('no device authorization endpoint configured or discovered', async () => {
    mockedDiscovery.mock.mockImplementation(async () => ({
      token_endpoint: 'https://t',
    }));
    const provider = device({ issuerUrl: 'https://issuer.example' });
    expectRow(
      await thrownBy(() => provider.getTokens()),
      endpoint('deviceAuthorizationEndpoint'),
    );
  });
});

describe('certificate files', () => {
  it('PEM and PFX both given', async () => {
    const thrown = await thrownBy(() =>
      new FileCertificateMaterialLoader().load({
        certPath: `/${MARKER}.crt`,
        certPfxPath: `/${MARKER}.pfx`,
      } as never),
    );
    expectRow(thrown, {
      case: 'certificate-pem-and-pfx',
      fields: ['certPath', 'certPfxPath'],
      reason:
        'certificate auth: provide either PEM (certPath + certKeyPath) or certPfxPath, not both',
    });
  });

  it('neither a PFX nor a whole PEM pair', async () => {
    const thrown = await thrownBy(() =>
      new FileCertificateMaterialLoader().load({
        certPath: `/${MARKER}.crt`,
      } as never),
    );
    expectRow(thrown, {
      case: 'certificate-files-missing',
      fields: ['certPfxPath', 'certPath', 'certKeyPath'],
      reason:
        'certificate auth requires certPfxPath, or certPath and certKeyPath',
    });
  });
});

describe('UAA authorization URL', () => {
  for (const [caseIndex, caseRow] of cases([
    ['uaaUrl', { uaaUrl: '', uaaClientId: 'c' }, ['uaaUrl']],
    ['clientId', { uaaUrl: 'https://u', uaaClientId: '' }, ['clientId']],
    ['both', { uaaUrl: '', uaaClientId: '' }, ['uaaUrl', 'clientId']],
  ]).entries()) {
    const [_name, config, fields] = caseRow;
    it(caseTitle('without %s', caseRow, caseIndex), async () => {
      const thrown = await thrownBy(() =>
        getJwtAuthorizationUrl(
          config as never,
          'http://localhost:61001/callback',
        ),
      );
      expectRow(thrown, {
        case: 'required-fields-missing',
        fields,
        reason: `required configuration is missing: ${fields.join(', ')}`,
      });
    });
  }
});

describe('shipped validator construction', () => {
  const store = () => createInMemoryReplayStore();

  for (const [caseIndex, caseRow] of cases([
    [-1],
    [1.5],
    [Number.NaN],
    [Number.POSITIVE_INFINITY],
  ]).entries()) {
    const [clockSkewMs] = caseRow;
    it(
      caseTitle(
        'clockSkewMs %p, the value never in the words',
        caseRow,
        caseIndex,
      ),
      async () => {
        const thrown = await thrownBy(() =>
          createSignedResponseValidator({
            idpCertificates: [CERT],
            clockSkewMs,
            replayStore: store(),
          }),
        );
        const error = expectRow(thrown, {
          case: 'validator-clock-skew-invalid',
          fields: ['clockSkewMs'],
          reason: 'clockSkewMs must be a finite non-negative integer',
        });
        notContains(error.reason, String(clockSkewMs));
      },
    );
  }

  it('no certificate to verify against', async () => {
    const thrown = await thrownBy(() =>
      createSignedResponseValidator({
        idpCertificates: [],
        replayStore: store(),
      }),
    );
    expectRow(thrown, {
      case: 'validator-no-certificates',
      fields: ['idpCertificates'],
      reason: 'idpCertificates must not be empty: nothing could be verified',
    });
  });

  for (const [caseIndex, caseRow] of cases([
    ['neither PEM nor base64 DER', `${MARKER}!!`],
    ['base64 that is no certificate', 'AAAA'],
  ]).entries()) {
    const [_name, value] = caseRow;
    it(
      caseTitle(
        '%s (toPem, and the validator built on it)',
        caseRow,
        caseIndex,
      ),
      async () => {
        const row = {
          case: 'idp-certificate-invalid',
          fields: ['idpCertificates'],
          reason:
            'a configured IdP certificate is not a valid X.509 certificate in PEM or base64 DER',
        };
        expectRow(await thrownBy(() => toPem(value)), row);
        expectRow(
          await thrownBy(() =>
            createSignedResponseValidator({
              idpCertificates: [CERT, value],
              replayStore: store(),
            }),
          ),
          row,
        );
      },
    );
  }
});

describe('staticCodeStrategy', () => {
  it('no payload', async () => {
    const thrown = await thrownBy(() => staticCodeStrategy({ payload: '' }));
    expectRow(thrown, {
      case: 'static-code-without-payload',
      fields: ['payload'],
      reason: 'staticCodeStrategy requires a payload',
    });
  });
});

describe('callback server port', () => {
  const K6 = {
    case: 'callback-port-invalid',
    fields: ['port'],
    reason: 'invalid callback server port: it must be an integer in 0..65535',
  };

  for (const [caseIndex, caseRow] of cases([
    [70000],
    [-1],
    [1.5],
    [Number.NaN],
    ['k6sock'],
    ['61001'],
  ]).entries()) {
    const [port] = caseRow;
    it(
      caseTitle(
        'browserCallbackStrategy({ port: %p }) refuses at construction',
        caseRow,
        caseIndex,
      ),
      async () => {
        expectRow(
          await thrownBy(() => browserCallbackStrategy({ port } as never)),
          K6,
        );
      },
    );
  }

  for (const [caseIndex, caseRow] of cases([
    [70000],
    [-1],
    [1.5],
    [Number.NaN],
    ['k6sock'],
  ]).entries()) {
    const [port] = caseRow;
    it(
      caseTitle(
        'a port changed after construction (%p) changes nothing — the options were read once; no socket file',
        caseRow,
        caseIndex,
      ),
      async () => {
        const free = await getAvailablePort();
        const options: { port?: unknown } = { port: free };
        const strategy = browserCallbackStrategy(options as never);
        options.port = port;
        const redirects: string[] = [];
        const login = strategy
          .authorize({
            buildAuthorizationUrl: async (redirectUri: string) => {
              redirects.push(redirectUri);
              return 'https://idp.example/a?state=S';
            },
          } as never)
          .catch(() => undefined);
        while (redirects.length === 0) {
          await new Promise((resolve) => setTimeout(resolve, 5));
        }
        assert.deepEqual(redirects, [`http://localhost:${free}/callback`]);
        await strategy.dispose();
        await login;
        assert.equal(existsSync(join(process.cwd(), 'k6sock')), false);
      },
    );
  }

  for (const [caseIndex, caseRow] of cases([
    [-1],
    [65536],
    [1.5],
    ['61001'],
    [Number.NaN],
  ]).entries()) {
    const [port] = caseRow;
    it(
      caseTitle('port %p, the value never in the words', caseRow, caseIndex),
      async () => {
        const thrown = await thrownBy(() => loopback({ port } as never));
        const error = expectRow(thrown, {
          case: 'callback-port-invalid',
          fields: ['port'],
          reason:
            'invalid callback server port: it must be an integer in 0..65535',
        });
        notContains(error.reason, String(port));
      },
    );
  }
});
