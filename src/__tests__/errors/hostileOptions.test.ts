/**
 * Every exported constructor and factory reads its options through a guarded
 * own-data read: an options object that is a throwing Proxy, one whose every
 * field is a throwing getter, a primitive or nothing at all never makes it
 * throw what the object threw. It returns, or throws an `AuthProviderFailure`
 * of kind `configuration` — and nothing of the thrown text survives.
 *
 * A strategy or factory result called directly by the consumer, outside a
 * moment, may still reject with what the consumer's own collaborator threw
 * (README, "Errors outside the moments"); that is not this suite's subject.
 */

import { inspect } from 'node:util';
import { describe, expect, it } from '@jest/globals';
import { isAuthProviderFailure } from '@mcp-abap-adt/auth-errors';
import { CONFIG_FIELDS } from '@mcp-abap-adt/interfaces-auth';
import { withBrowserCallbackServer } from '../../auth/callbackServer';
import { withOidcCallbackServer } from '../../auth/oidcBrowserAuth';
import { withSamlCallbackServer } from '../../auth/saml2Auth';
import {
  clientSecretBasic,
  clientSecretPost,
} from '../../clientAuthentication/clientSecret';
import { privateKeyJwt } from '../../clientAuthentication/privateKeyJwt';
import { tlsClientCertificate } from '../../clientAuthentication/tlsClientCertificate';
import { BasicAuthProvider } from '../../credentials/BasicAuthProvider';
import { CertificateAuthProvider } from '../../credentials/CertificateAuthProvider';
import { SamlAuthProvider } from '../../credentials/SamlAuthProvider';
import { TokenAuthProvider } from '../../credentials/TokenAuthProvider';
import { consoleDeviceCodePresenter } from '../../deviceCode/DeviceCodePresenter';
import { AuthorizationCodeProvider } from '../../providers/AuthorizationCodeProvider';
import { ClientCredentialsProvider } from '../../providers/ClientCredentialsProvider';
import { OidcBrowserProvider } from '../../providers/OidcBrowserProvider';
import { OidcDeviceFlowProvider } from '../../providers/OidcDeviceFlowProvider';
import { OidcPasswordProvider } from '../../providers/OidcPasswordProvider';
import { OidcTokenExchangeProvider } from '../../providers/OidcTokenExchangeProvider';
import { Saml2BearerProvider } from '../../providers/Saml2BearerProvider';
import { Saml2PureProvider } from '../../providers/Saml2PureProvider';
import { UaaPasscodeProvider } from '../../providers/UaaPasscodeProvider';
import { refreshThenLogin } from '../../renewal';
import { DefaultSncLibraryLocator } from '../../snc/DefaultSncLibraryLocator';
import { SecureLoginClientProbe } from '../../snc/SecureLoginClientProbe';
import { SncLogonProvider } from '../../snc/SncLogonProvider';
import { SsoProviderFactory } from '../../sso/SsoProviderFactory';
import { asOidcResult } from '../../strategies/asOidcResult';
import {
  BrowserCallbackStrategy,
  browserCallbackStrategy,
  oidcCallbackStrategy,
  samlCallbackStrategy,
} from '../../strategies/BrowserCallbackStrategy';
import {
  externalCodeStrategy,
  staticCodeStrategy,
} from '../../strategies/codeStrategies';
import {
  manualPasscodeStrategy,
  manualPasteStrategy,
  manualSamlResponseStrategy,
} from '../../strategies/manualStrategies';
import {
  createSignedAssertionValidator,
  createSignedResponseValidator,
} from '../../validation/assertionValidator';
import { certificate } from '../helpers/certificates';

const SECRET = 'HOSTILE-OPTION-SECRET-41';
const boom = () => {
  throw new Error(SECRET);
};

/** Field names an options object of this package may carry. */
const FIELDS = [
  ...CONFIG_FIELDS,
  'authDebug',
  'signal',
  'browser',
  'openUrl',
  'callbackServer',
  'redirectUri',
  'remoteHint',
  'material',
  'key',
  'algorithm',
  'kid',
  'endpoint',
  'expectedIssuer',
  'expectedAudience',
  'expectedDestination',
  'expectedAcsUrl',
  'clientAuthentication',
  'expiresAt',
  'cookies',
  'sessionCookies',
  'buildUrl',
  'getCode',
  'flow',
  'protocol',
  'saml',
  'oidc',
  'xsuaa',
  'system',
];

function hostileVariants(): Array<[string, unknown]> {
  const throwingProxy = new Proxy(
    {},
    {
      get: boom,
      has: boom,
      ownKeys: boom,
      getOwnPropertyDescriptor: boom,
      getPrototypeOf: boom,
    },
  );
  const getters: Record<string, unknown> = {};
  for (const field of FIELDS) {
    Object.defineProperty(getters, field, {
      get: boom,
      enumerable: true,
    });
  }
  const { proxy: revoked, revoke } = Proxy.revocable({}, {});
  revoke();
  return [
    ['a throwing Proxy', throwingProxy],
    ['throwing getters', getters],
    ['a revoked Proxy', revoked],
    ['an empty object', {}],
    ['null', null],
    ['undefined', undefined],
    ['a string', SECRET],
    ['a number', 42],
  ];
}

type Make = (hostile: unknown) => unknown;
const h = (value: unknown): never => value as never;

const makers: Record<string, Make> = {
  'new ClientCredentialsProvider': (x) => new ClientCredentialsProvider(h(x)),
  'new AuthorizationCodeProvider': (x) => new AuthorizationCodeProvider(h(x)),
  'AuthorizationCodeProvider.inBrowser': (x) =>
    AuthorizationCodeProvider.inBrowser(h(x)),
  'AuthorizationCodeProvider.inBrowser options': (x) =>
    AuthorizationCodeProvider.inBrowser(
      {
        renewal: refreshThenLogin(),
        uaaUrl: 'https://uaa',
        clientId: 'c',
        clientSecret: 's',
      },
      h(x),
    ),
  'new OidcBrowserProvider': (x) => new OidcBrowserProvider(h(x)),
  'OidcBrowserProvider.inBrowser': (x) => OidcBrowserProvider.inBrowser(h(x)),
  'new OidcDeviceFlowProvider': (x) => new OidcDeviceFlowProvider(h(x)),
  'OidcDeviceFlowProvider.toConsole': (x) =>
    OidcDeviceFlowProvider.toConsole(h(x)),
  'new OidcPasswordProvider': (x) => new OidcPasswordProvider(h(x)),
  'new OidcTokenExchangeProvider': (x) => new OidcTokenExchangeProvider(h(x)),
  'new Saml2BearerProvider': (x) => new Saml2BearerProvider(h(x)),
  'Saml2BearerProvider.inBrowser': (x) =>
    Saml2BearerProvider.inBrowser(h(x), h(x)),
  'new Saml2PureProvider': (x) => new Saml2PureProvider(h(x)),
  'Saml2PureProvider.inBrowser': (x) => Saml2PureProvider.inBrowser(h(x), h(x)),
  'new UaaPasscodeProvider': (x) => new UaaPasscodeProvider(h(x)),
  'UaaPasscodeProvider.fromTerminal': (x) =>
    UaaPasscodeProvider.fromTerminal(h(x)),
  'new BasicAuthProvider (user)': (x) => new BasicAuthProvider(h(x), 'p'),
  'new BasicAuthProvider (password)': (x) => new BasicAuthProvider('u', h(x)),
  'new CertificateAuthProvider': (x) => new CertificateAuthProvider(h(x), h(x)),
  'CertificateAuthProvider.fromFiles': (x) =>
    CertificateAuthProvider.fromFiles(h(x)),
  'new SamlAuthProvider': (x) => new SamlAuthProvider(h(x)),
  'TokenAuthProvider.fixed': (x) => TokenAuthProvider.fixed(h(x)),
  'TokenAuthProvider.from': (x) => TokenAuthProvider.from(h(x)),
  'new SncLogonProvider': (x) => new SncLogonProvider(h(x)),
  'SncLogonProvider.forSecureLoginClient': (x) =>
    SncLogonProvider.forSecureLoginClient(h(x)),
  'new DefaultSncLibraryLocator': (x) => new DefaultSncLibraryLocator(h(x)),
  'new SecureLoginClientProbe': (x) => new SecureLoginClientProbe(h(x)),
  'SsoProviderFactory.create': (x) => SsoProviderFactory.create(h(x)),
  'clientSecretBasic (secret)': (x) =>
    clientSecretBasic(h(x), { encoding: 'raw' }),
  'clientSecretBasic (options)': (x) => clientSecretBasic('s', h(x)),
  clientSecretPost: (x) => clientSecretPost(h(x)),
  tlsClientCertificate: (x) => tlsClientCertificate(h(x)),
  privateKeyJwt: (x) => privateKeyJwt(h(x)),
  'new BrowserCallbackStrategy': (x) => new BrowserCallbackStrategy(h(x)),
  browserCallbackStrategy: (x) => browserCallbackStrategy(h(x)),
  oidcCallbackStrategy: (x) => oidcCallbackStrategy(h(x)),
  samlCallbackStrategy: (x) => samlCallbackStrategy(h(x)),
  manualPasteStrategy: (x) => manualPasteStrategy(h(x)),
  manualSamlResponseStrategy: (x) => manualSamlResponseStrategy(h(x)),
  manualPasscodeStrategy: (x) => manualPasscodeStrategy(h(x)),
  externalCodeStrategy: (x) => externalCodeStrategy(h(x)),
  staticCodeStrategy: (x) => staticCodeStrategy(h(x)),
  asOidcResult: (x) => asOidcResult(h(x)),
  createSignedResponseValidator: (x) => createSignedResponseValidator(h(x)),
  createSignedAssertionValidator: (x) => createSignedAssertionValidator(h(x)),
  consoleDeviceCodePresenter: (x) => consoleDeviceCodePresenter(h(x)),
};

/** The callback-server factories: they answer a promise. */
const servers: Record<string, Make> = {
  withBrowserCallbackServer: (x) =>
    withBrowserCallbackServer(h(x), async () => 'done'),
  withOidcCallbackServer: (x) =>
    withOidcCallbackServer(h(x), async () => 'done'),
  withSamlCallbackServer: (x) =>
    withSamlCallbackServer(h(x), async () => 'done'),
};

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

describe('hostile options never make a constructor or factory throw them', () => {
  for (const [name, make] of Object.entries(makers)) {
    for (const [label, hostile] of hostileVariants()) {
      it(`${name} — ${label}`, () => {
        expectConfigurationOrNothing(thrownBy(() => make(hostile)));
      });
    }
  }

  for (const [name, make] of Object.entries(servers)) {
    for (const [label, hostile] of hostileVariants()) {
      // Only the hostile objects: `undefined` and `{}` are a valid scope on
      // the default port, which this suite does not bind.
      if (label === 'undefined' || label === 'an empty object') continue;
      it(`${name} — ${label}`, async () => {
        let thrown: unknown;
        try {
          await make(hostile);
        } catch (error) {
          thrown = error ?? new Error('threw a nullish value');
        }
        expectConfigurationOrNothing(thrown);
      });
    }
  }
});

/**
 * A complete configuration whose collaborators are hostile: each field that
 * holds an object or a function (a strategy, a validator, a signal, a
 * logger, a hook) is a Proxy that throws on every trap. A constructor
 * reads a collaborator only guarded, or not at all — it is called inside a
 * moment's boundary.
 */
describe('hostile collaborators never make a constructor throw them', () => {
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
    BrowserCallbackStrategy: (x) => new BrowserCallbackStrategy(h(x)),
    browserCallbackStrategy: (x) => browserCallbackStrategy(h(x)),
    manualPasteStrategy: (x) => manualPasteStrategy(h(x)),
    externalCodeStrategy: (x) => externalCodeStrategy(h(x)),
    asOidcResult: () => asOidcResult(hostile() as never),
  };
  for (const [name, make] of Object.entries(complete)) {
    for (const field of collaborators) {
      it(`${name} — ${field} hostile`, () => {
        expectConfigurationOrNothing(
          thrownBy(() => make({ ...base, [field]: hostile() })),
        );
      });
    }
  }
});

describe('the shipped validators refuse what a JavaScript caller passes', () => {
  const store = { recordIfUnseen: async () => true };
  const caseOf = (make: () => unknown) =>
    (thrownBy(make) as { error?: { facts?: { case?: string } } } | undefined)
      ?.error?.facts?.case;

  for (const factory of [
    createSignedResponseValidator,
    createSignedAssertionValidator,
  ]) {
    it(`${factory.name}: no certificates, a non-array, a non-string entry, no store`, () => {
      expect(caseOf(() => factory(h({})))).toBe('validator-no-certificates');
      expect(
        caseOf(() =>
          factory(h({ idpCertificates: 'MIIB', replayStore: store })),
        ),
      ).toBe('validator-no-certificates');
      expect(
        caseOf(() => factory(h({ idpCertificates: [42], replayStore: store }))),
      ).toBe('idp-certificate-invalid');
      expect(
        caseOf(() =>
          factory(
            h({
              idpCertificates: new Proxy([], { get: boom, ownKeys: boom }),
              replayStore: store,
            }),
          ),
        ),
      ).toBe('validator-no-certificates');
      // A usable certificate, and no replay store: required, by name.
      const pem = String(certificate().cert);
      const thrown = thrownBy(() => factory(h({ idpCertificates: [pem] })));
      expect(caseOf(() => factory(h({ idpCertificates: [pem] })))).toBe(
        'required-fields-missing',
      );
      expect(
        (thrown as { error: { facts: { fields: string[] } } }).error.facts
          .fields,
      ).toEqual(['replayStore']);
    });
  }

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
