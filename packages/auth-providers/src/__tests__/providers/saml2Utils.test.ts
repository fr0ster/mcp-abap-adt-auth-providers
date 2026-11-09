/**
 * The AuthnRequest ID surviving from URL building to `getSamlAssertion`.
 *
 * `buildSamlAuthorizationUrl` is exercised here rather than in its own file
 * because the rule this task adds — where the expected request ID comes from —
 * spans both functions: the ID `buildSamlAuthorizationUrl` mints is exactly
 * what `getSamlAssertion` must thread through, or refuse to proceed without.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { generateKeyMaterial } from '@mcp-abap-adt/auth-mocks';
import type {
  AuthorizationOutcome,
  AuthorizationRequest,
  IAssertionValidator,
  IAuthorizationStrategy,
} from '@mcp-abap-adt/interfaces-auth';
import { buildSamlAuthorizationUrl } from '../../auth/saml2Auth';
import { Saml2BearerProvider } from '../../providers/Saml2BearerProvider';
import { Saml2PureProvider } from '../../providers/Saml2PureProvider';
import {
  getSamlAssertion,
  type Saml2CommonConfig,
} from '../../providers/saml2Utils';
import { refreshThenLogin } from '../../renewal';
import {
  createSignedAssertionValidator,
  createSignedResponseValidator,
} from '../../validation/assertionValidator';
import { createInMemoryReplayStore } from '../../validation/inMemoryReplayStore';
import {
  caseTitle,
  contains,
  matchObject,
  matchText,
} from '../helpers/expectations';
import { configurationOf, thrownFrom } from '../helpers/minted';

/** Never used at runtime by these tests: only here to satisfy the required field. */
const unusedValidator: IAssertionValidator = {
  async validate() {
    throw new Error('never called');
  },
};

/** Never used at runtime by these tests: only here to satisfy the required field. */
const unreachableAuthorization: IAuthorizationStrategy<string> = {
  async authorize() {
    throw new Error('the strategy must never be reached');
  },
};

describe('buildSamlAuthorizationUrl', () => {
  it('mints a request ID and reports it', () => {
    const built = buildSamlAuthorizationUrl({
      idpSsoUrl: 'https://idp.example/sso',
      spEntityId: 'urn:sp',
      acsUrl: 'http://localhost:61001/acs',
    });
    matchText(built.requestId, /^_/);
    contains(built.url, 'SAMLRequest=');
  });

  it('puts the ID it reports into the request it builds', () => {
    const built = buildSamlAuthorizationUrl({
      idpSsoUrl: 'https://idp.example/sso',
      spEntityId: 'urn:sp',
      acsUrl: 'http://localhost:61001/acs',
    });
    const encoded = new URL(built.url).searchParams.get('SAMLRequest') ?? '';
    const xml = require('node:zlib')
      .inflateRawSync(Buffer.from(encoded, 'base64'))
      .toString('utf8');
    contains(xml, `ID="${built.requestId}"`);
  });

  it('mints nothing for a pre-built authorization URL', () => {
    const built = buildSamlAuthorizationUrl({
      idpSsoUrl: 'https://idp.example/sso',
      spEntityId: 'urn:sp',
      acsUrl: 'http://localhost:61001/acs',
      authorizationUrl: 'https://idp.example/preauthorized?SAMLRequest=xyz',
    });
    assert.equal(
      built.url,
      'https://idp.example/preauthorized?SAMLRequest=xyz',
    );
    assert.equal(built.requestId, undefined);
  });
});

describe('getSamlAssertion — where the expected request ID comes from', () => {
  const baseConfig = {
    idpSsoUrl: 'https://idp.example/sso',
    spEntityId: 'urn:sp',
    assertionValidator: unusedValidator,
  };

  /** Calls the builder — the strategy that asks for a URL, as a real browser flow does. */
  function callsBuilder(
    redirectUri: string,
    payload = 'PHNhbWw+',
  ): IAuthorizationStrategy<string> {
    return {
      async authorize(
        request: AuthorizationRequest,
      ): Promise<AuthorizationOutcome<string>> {
        await request.buildAuthorizationUrl(redirectUri);
        return { payload, redirectUri };
      },
    };
  }

  /** Never calls the builder — a strategy that already holds the payload. */
  function neverCallsBuilder(
    redirectUri: string,
    payload = 'PHNhbWw+',
  ): IAuthorizationStrategy<string> {
    return {
      async authorize(): Promise<AuthorizationOutcome<string>> {
        return { payload, redirectUri };
      },
    };
  }

  it('reports the ID it minted while building the request', async () => {
    const config: Saml2CommonConfig = {
      ...baseConfig,
      authorization: callsBuilder('http://localhost:61001/callback'),
    };

    const result = await getSamlAssertion(config);

    matchText(result.requestId, /^_/);
    assert.equal(result.payload, 'PHNhbWw+');
  });

  it('reports outcome.redirectUri as acsUrl, not config.acsUrl', async () => {
    const config: Saml2CommonConfig = {
      ...baseConfig,
      authorization: callsBuilder('http://localhost:61001/callback'),
    };

    const result = await getSamlAssertion(config);

    assert.equal(result.acsUrl, 'http://localhost:61001/callback');
  });

  it('uses the declared authnRequestId when the builder was never called', async () => {
    const config: Saml2CommonConfig = {
      ...baseConfig,
      authnRequestId: '_declared-id',
      authorization: neverCallsBuilder('http://localhost:61001/callback'),
    };

    const result = await getSamlAssertion(config);

    assert.equal(result.requestId, '_declared-id');
  });

  // Minted beats declared: the ID the package just put in the request is
  // the one the answer must carry, whatever the configuration also says.
  it('prefers the ID it minted over a declared authnRequestId', async () => {
    const config: Saml2CommonConfig = {
      ...baseConfig,
      authnRequestId: '_declared-id',
      authorization: callsBuilder('http://localhost:61001/callback'),
    };

    const result = await getSamlAssertion(config);

    matchText(result.requestId, /^_[0-9a-f-]{36}$/);
    assert.notEqual(result.requestId, '_declared-id');
  });

  it('yields requestId undefined when idpInitiated is declared and the builder was never called', async () => {
    const config: Saml2CommonConfig = {
      ...baseConfig,
      idpInitiated: true,
      authorization: neverCallsBuilder('http://localhost:61001/callback'),
    };

    const result = await getSamlAssertion(config);

    assert.equal(result.requestId, undefined);
  });

  it('throws a configuration failure naming authnRequestId when no ID can be established', async () => {
    const config: Saml2CommonConfig = {
      ...baseConfig,
      authorization: neverCallsBuilder('http://localhost:61001/callback'),
    };

    matchObject(
      configurationOf(await thrownFrom(() => getSamlAssertion(config))),
      {
        case: 'saml-in-response-to-undeclared',
        fields: ['authnRequestId', 'idpInitiated'],
      },
    );
  });

  it('never infers idpInitiated from a strategy that simply did not call the builder', async () => {
    // Same shape as the previous case, restated: omitting the declaration is
    // not read as "no request was sent" — that must be said explicitly.
    const config: Saml2CommonConfig = {
      ...baseConfig,
      authorization: neverCallsBuilder('http://localhost:61001/callback'),
    };

    // The case, not 5.4.2's sentence.
    assert.equal(
      configurationOf(await thrownFrom(() => getSamlAssertion(config))).case,
      'saml-in-response-to-undeclared',
    );
  });

  // The builder refuses before any URL exists: an IdP-initiated login with no
  // pre-built authorizationUrl could only get a URL carrying a freshly minted
  // AuthnRequest. Found at the builder, the mistake surfaces before a browser
  // opens rather than after the user has logged in.
  it('refuses inside the builder when idpInitiated has no authorizationUrl', async () => {
    const produced: string[] = [];
    const strategy: IAuthorizationStrategy<string> = {
      async authorize(request) {
        produced.push(
          await request.buildAuthorizationUrl(
            'http://localhost:61001/callback',
          ),
        );
        return {
          payload: 'PHNhbWw+',
          redirectUri: 'http://localhost:61001/callback',
        };
      },
    };
    const config: Saml2CommonConfig = {
      ...baseConfig,
      idpInitiated: true,
      authorization: strategy,
    };

    matchObject(
      configurationOf(await thrownFrom(() => getSamlAssertion(config))),
      {
        case: 'saml-idp-initiated-without-authorization-url',
        fields: ['idpInitiated', 'authorizationUrl'],
      },
    );
    assert.deepEqual(produced, []);
  });

  // The other half: with a pre-built URL — the IdP-initiated SSO URL — the
  // builder mints nothing and hands it over.
  it('lets a strategy open a pre-built authorizationUrl when idpInitiated', async () => {
    const config: Saml2CommonConfig = {
      ...baseConfig,
      idpInitiated: true,
      acsUrl: 'http://localhost:61001/callback',
      authorizationUrl: 'https://idp.example/idp-initiated',
      authorization: callsBuilder('http://localhost:61001/callback'),
    };

    const result = await getSamlAssertion(config);

    assert.equal(result.requestId, undefined);
  });

  it('throws a configuration failure when idpInitiated is combined with a declared authnRequestId', async () => {
    const config: Saml2CommonConfig = {
      ...baseConfig,
      idpInitiated: true,
      authnRequestId: '_declared-id',
      authorization: neverCallsBuilder('http://localhost:61001/callback'),
    };

    matchObject(
      configurationOf(await thrownFrom(() => getSamlAssertion(config))),
      {
        case: 'saml-idp-initiated-with-request-id',
        fields: ['idpInitiated'],
      },
    );
  });
});

describe('checkAssertionValidator — a shipped validator still needs idpEntityId', () => {
  const certificate = generateKeyMaterial().certificatePem;
  const common = {
    idpSsoUrl: 'https://idp.example/sso',
    spEntityId: 'urn:sp',
    idpInitiated: true,
  };
  const shipped = {
    createSignedResponseValidator,
    createSignedAssertionValidator,
  };

  for (const [caseIndex, caseRow] of (
    Object.keys(shipped) as (keyof typeof shipped)[]
  ).entries()) {
    const factory = caseRow;
    describe(
      caseTitle('%s supplied as assertionValidator', caseRow, caseIndex),
      () => {
        const assertionValidator = () =>
          shipped[factory]({
            idpCertificates: [certificate],
            replayStore: createInMemoryReplayStore(),
          });

        it('refuses Saml2BearerProvider at construction without idpEntityId', () => {
          let thrown: unknown;
          try {
            new Saml2BearerProvider({
              renewal: refreshThenLogin(),
              ...common,
              uaaUrl: 'https://uaa.example',
              authorization: unreachableAuthorization,
              assertionValidator: assertionValidator(),
            });
          } catch (error) {
            thrown = error;
          }
          matchObject(configurationOf(thrown), {
            case: 'saml-shipped-validator-without-issuer',
            fields: ['idpEntityId'],
          });
        });

        it('refuses Saml2PureProvider at construction without idpEntityId', () => {
          let thrown: unknown;
          try {
            new Saml2PureProvider({
              renewal: refreshThenLogin(),
              ...common,
              cookieProvider: async () => 'cookie',
              authorization: unreachableAuthorization,
              assertionValidator: assertionValidator(),
            });
          } catch (error) {
            thrown = error;
          }
          matchObject(configurationOf(thrown), {
            case: 'saml-shipped-validator-without-issuer',
            fields: ['idpEntityId'],
          });
        });

        it('constructs with idpEntityId', () => {
          assert.doesNotThrow(
            () =>
              new Saml2PureProvider({
                renewal: refreshThenLogin(),
                ...common,
                idpEntityId: 'urn:idp',
                cookieProvider: async () => 'cookie',
                authorization: unreachableAuthorization,
                assertionValidator: assertionValidator(),
              }),
          );
        });
      },
    );
  }

  it('constructs both providers with a custom validator and no idpEntityId', () => {
    const custom: IAssertionValidator = {
      async validate() {
        throw new Error('never called');
      },
    };
    assert.doesNotThrow(
      () =>
        new Saml2BearerProvider({
          renewal: refreshThenLogin(),
          ...common,
          uaaUrl: 'https://uaa.example',
          authorization: unreachableAuthorization,
          assertionValidator: custom,
        }),
    );
    assert.doesNotThrow(
      () =>
        new Saml2PureProvider({
          renewal: refreshThenLogin(),
          ...common,
          cookieProvider: async () => 'cookie',
          authorization: unreachableAuthorization,
          assertionValidator: custom,
        }),
    );
  });

  // The brand is not part of what a consumer sees: not enumerable, so it
  // does not show up in keys, spreads or serialisation.
  it('hides the brand from enumeration', () => {
    const validator = createSignedResponseValidator({
      idpCertificates: [certificate],
      replayStore: createInMemoryReplayStore(),
    });
    assert.deepEqual(Object.keys(validator), ['validate']);
    assert.equal(Object.getOwnPropertySymbols({ ...validator }).length, 0);
  });
});

// Both declarations describe different logins. Found at construction, the
// mistake costs nothing; found after authorize(), it costs a browser login.
describe('idpInitiated with authnRequestId is refused at construction', () => {
  const both = {
    idpSsoUrl: 'https://idp.example/sso',
    spEntityId: 'urn:sp',
    idpEntityId: 'urn:idp',
    assertionValidator: unusedValidator,
    idpInitiated: true,
    authnRequestId: '_declared-id',
  };
  const unreachable: IAuthorizationStrategy<string> = {
    async authorize() {
      throw new Error('the strategy must never be reached');
    },
  };
  const construct = {
    Saml2BearerProvider: () =>
      new Saml2BearerProvider({
        renewal: refreshThenLogin(),
        ...both,
        uaaUrl: 'https://uaa.example',
        authorization: unreachable,
      }),
    Saml2PureProvider: () =>
      new Saml2PureProvider({
        renewal: refreshThenLogin(),
        ...both,
        cookieProvider: async () => 'cookie',
        authorization: unreachable,
      }),
  };

  for (const [caseIndex, caseRow] of (
    Object.keys(construct) as (keyof typeof construct)[]
  ).entries()) {
    const provider = caseRow;
    it(caseTitle('refuses %s', caseRow, caseIndex), () => {
      let thrown: unknown;
      try {
        construct[provider]();
      } catch (error) {
        thrown = error;
      }
      matchObject(configurationOf(thrown), {
        case: 'saml-idp-initiated-with-request-id',
        fields: ['idpInitiated', 'authnRequestId'],
      });
    });
  }
});
