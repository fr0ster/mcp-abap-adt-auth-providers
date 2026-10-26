/**
 * A constructor or factory does not read a collaborator: a collaborator is
 * read and called only inside a moment, whose boundary classifies its throw.
 * So a collaborator that throws on every trap (a strategy, a validator, a
 * signal, a logger, a hook) never makes a constructor throw: it returns, or
 * refuses with its own `configuration` failure holding nothing of the thrown
 * text. The one exception is stated where it is excluded below. The shipped
 * validators' brand is read guarded, so a throwing Proxy is not a shipped one.
 */

import { inspect } from 'node:util';
import { describe, expect, it } from '@jest/globals';
import { isAuthProviderFailure } from '@mcp-abap-adt/auth-errors';
import { composeAuthorization } from '../../authorization/compose';
import {
  consumerPresentation,
  showUrl,
} from '../../authorization/presentation';
import { oauthCode } from '../../authorization/protocol';
import {
  consumerAnswer,
  consumerHandoff,
  loopback4,
  terminalPaste,
} from '../../authorization/transport';
import { AuthorizationCodeProvider } from '../../providers/AuthorizationCodeProvider';
import { ClientCredentialsProvider } from '../../providers/ClientCredentialsProvider';
import { OidcBrowserProvider } from '../../providers/OidcBrowserProvider';
import { OidcDeviceFlowProvider } from '../../providers/OidcDeviceFlowProvider';
import { OidcPasswordProvider } from '../../providers/OidcPasswordProvider';
import { OidcTokenExchangeProvider } from '../../providers/OidcTokenExchangeProvider';
import { Saml2BearerProvider } from '../../providers/Saml2BearerProvider';
import { Saml2PureProvider } from '../../providers/Saml2PureProvider';
import { UaaPasscodeProvider } from '../../providers/UaaPasscodeProvider';
import { SncLogonProvider } from '../../snc/SncLogonProvider';
import { SpnegoAuthProvider } from '../../spnego/SpnegoAuthProvider';
import { browserCallbackStrategy } from '../../strategies/callbackStrategies';
import { externalCodeStrategy } from '../../strategies/codeStrategies';
import { manualPasteStrategy } from '../../strategies/manualStrategies';

const SECRET = 'HOSTILE-OPTION-SECRET-41';
const boom = () => {
  throw new Error(SECRET);
};

type Make = (hostile: unknown) => unknown;
const h = (value: unknown): never => value as never;

/** What a call threw, or `undefined` when it returned. */
function thrownBy(make: () => unknown): unknown {
  try {
    make();
    return undefined;
  } catch (error) {
    return error ?? new Error('threw a nullish value');
  }
}

function expectConfigurationOrNothing(thrown: unknown): void {
  if (thrown === undefined) return;
  expect(isAuthProviderFailure(thrown)).toBe(true);
  expect((thrown as { error: { kind: string } }).error.kind).toBe(
    'configuration',
  );
  expect(inspect(thrown, { showHidden: true, depth: 8 })).not.toContain(SECRET);
}

/**
 * A complete configuration whose collaborators are hostile: each field that
 * holds an object or a function (a strategy, a validator, a signal, a
 * logger, a hook) is a Proxy that throws on every trap. A constructor
 * does not read it; it is read and called inside a moment's boundary.
 */
describe('a constructor does not read a collaborator, so a hostile one never makes it throw', () => {
  const hostile = () =>
    new Proxy(() => undefined, {
      get: boom,
      has: boom,
      ownKeys: boom,
      getOwnPropertyDescriptor: boom,
      getPrototypeOf: boom,
      apply: boom,
    });
  const collaborators = [
    'authorization',
    'clientAuthentication',
    'assertionValidator',
    'presenter',
    'logger',
    'replayStore',
    'persistence',
    'signal',
    'cookieProvider',
    'locator',
    'probes',
    'presentation',
    'transport',
    'protocol',
    'show',
    'onFailure',
    'receive',
    'provide',
    'read',
    'remoteHint',
    'tokenSource',
  ] as const;
  const base = {
    uaaUrl: 'https://uaa.example',
    issuerUrl: 'https://idp.example',
    tokenEndpoint: 'https://idp.example/token',
    clientId: 'c',
    username: 'u',
    password: 'p',
    subjectToken: 's',
    subjectTokenType: 'urn:ietf:params:oauth:token-type:access_token',
    idpSsoUrl: 'https://idp.example/sso',
    spEntityId: 'sp',
    idpEntityId: 'idp',
    acsUrl: 'http://localhost:61001/callback',
    partnerName: 'p:CN=SAP',
    servicePrincipal: 'HTTP@sap.example.com',
  };
  const complete: Record<string, Make> = {
    ClientCredentialsProvider: (x) => new ClientCredentialsProvider(h(x)),
    AuthorizationCodeProvider: (x) => new AuthorizationCodeProvider(h(x)),
    OidcBrowserProvider: (x) => new OidcBrowserProvider(h(x)),
    OidcDeviceFlowProvider: (x) => new OidcDeviceFlowProvider(h(x)),
    OidcPasswordProvider: (x) => new OidcPasswordProvider(h(x)),
    OidcTokenExchangeProvider: (x) => new OidcTokenExchangeProvider(h(x)),
    Saml2BearerProvider: (x) => new Saml2BearerProvider(h(x)),
    Saml2PureProvider: (x) => new Saml2PureProvider(h(x)),
    UaaPasscodeProvider: (x) => new UaaPasscodeProvider(h(x)),
    SncLogonProvider: (x) => new SncLogonProvider(h(x)),
    // A usable source unless the field under test replaces it.
    SpnegoAuthProvider: (x) =>
      new SpnegoAuthProvider(
        h({
          tokenSource: {
            token: async () => ({ ok: false, problem: 'no-credential' }),
          },
          ...(x as object),
        }),
      ),
    composeAuthorization: (x) =>
      composeAuthorization(
        h({
          presentation: showUrl(),
          transport: loopback4({ port: 0 }),
          protocol: oauthCode(),
          endpoint: '/callback',
          ...(x as object),
        }),
      ),
    consumerPresentation: (x) => consumerPresentation(h(x)),
    consumerHandoff: (x) => consumerHandoff(h(x)),
    consumerAnswer: (x) => consumerAnswer(h(x)),
    terminalPaste: (x) => terminalPaste(h(x)),
    browserCallbackStrategy: (x) => browserCallbackStrategy(h(x)),
    manualPasteStrategy: (x) => manualPasteStrategy(h(x)),
    externalCodeStrategy: (x) => externalCodeStrategy(h(x)),
  };
  /**
   * `composeAuthorization` reads the transport's `label` and the protocol's
   * descriptor (`redirect`, `callbackMethods`, `paste`) once, at composition,
   * as typed data: those two parts are composed, not deferred collaborators.
   */
  const readAtComposition = new Set([
    'composeAuthorization — transport',
    'composeAuthorization — protocol',
  ]);
  for (const [name, make] of Object.entries(complete)) {
    for (const field of collaborators) {
      if (readAtComposition.has(`${name} — ${field}`)) continue;
      it(`${name} — ${field} hostile`, () => {
        expectConfigurationOrNothing(
          thrownBy(() => make({ ...base, [field]: hostile() })),
        );
      });
    }
  }
});

describe('a hostile validator is not a shipped one', () => {
  it('a validator that is a throwing object Proxy is not a shipped one', () => {
    const validator = new Proxy(
      {},
      { get: boom, getOwnPropertyDescriptor: boom, has: boom },
    );
    expectConfigurationOrNothing(
      thrownBy(
        () =>
          new Saml2PureProvider(
            h({
              idpSsoUrl: 'https://idp.example/sso',
              spEntityId: 'sp',
              cookieProvider: async () => ({}),
              authorization: {},
              assertionValidator: validator,
            }),
          ),
      ),
    );
  });
});
