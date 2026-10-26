/**
 * An empty options object: every exported constructor and factory answers
 * with its own `configuration` failure (a required field it finds missing)
 * or returns. One row per maker, so a refusal removed later is pruned row by
 * row.
 */
import { inspect } from 'node:util';
import { describe, expect, it } from '@jest/globals';
import { isAuthProviderFailure } from '@mcp-abap-adt/auth-errors';
import { composeAuthorization } from '../../authorization/compose';
import {
  consumerPresentation,
  openInBrowser,
} from '../../authorization/presentation';
import {
  consumerAnswer,
  consumerHandoff,
  loopback,
  loopback4,
  loopback6,
  terminalPaste,
} from '../../authorization/transport';
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
import { SpnegoAuthProvider } from '../../spnego/SpnegoAuthProvider';
import { SsoProviderFactory } from '../../sso/SsoProviderFactory';
import { asOidcResult } from '../../strategies/asOidcResult';
import {
  browserCallbackStrategy,
  oidcCallbackStrategy,
  samlCallbackStrategy,
} from '../../strategies/callbackStrategies';
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

const SECRET = 'HOSTILE-OPTION-SECRET-41';

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
  'new SpnegoAuthProvider': (x) => new SpnegoAuthProvider(h(x)),
  'new SecureLoginClientProbe': (x) => new SecureLoginClientProbe(h(x)),
  'SsoProviderFactory.create': (x) => SsoProviderFactory.create(h(x)),
  'clientSecretBasic (secret)': (x) =>
    clientSecretBasic(h(x), { encoding: 'raw' }),
  'clientSecretBasic (options)': (x) => clientSecretBasic('s', h(x)),
  clientSecretPost: (x) => clientSecretPost(h(x)),
  tlsClientCertificate: (x) => tlsClientCertificate(h(x)),
  privateKeyJwt: (x) => privateKeyJwt(h(x)),
  composeAuthorization: (x) => composeAuthorization(h(x)),
  openInBrowser: (x) => openInBrowser(h(x)),
  consumerPresentation: (x) => consumerPresentation(h(x)),
  loopback: (x) => loopback(h(x)),
  loopback4: (x) => loopback4(h(x)),
  loopback6: (x) => loopback6(h(x)),
  terminalPaste: (x) => terminalPaste(h(x)),
  consumerAnswer: (x) => consumerAnswer(h(x)),
  consumerHandoff: (x) => consumerHandoff(h(x)),
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

/** A transport's `open`, given hostile options: it answers a promise. */
const opens: Record<string, Make> = {
  'loopback4 open': (x) =>
    loopback4({ port: 0 }).open(h(x), async () => 'done'),
  'terminalPaste open': (x) =>
    terminalPaste({ read: async () => 'x' }).open(h(x), async () => 'done'),
  'consumerAnswer open': (x) =>
    consumerAnswer({ receive: async () => 'x' }).open(h(x), async () => 'done'),
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

describe('an empty options object is a configuration failure or nothing', () => {
  for (const [name, make] of Object.entries(makers)) {
    it(`${name} — an empty object`, () => {
      expectConfigurationOrNothing(thrownBy(() => make({})));
    });
  }

  for (const [name, make] of Object.entries(opens)) {
    it(`${name} — an empty object`, async () => {
      let thrown: unknown;
      try {
        await make({});
      } catch (error) {
        thrown = error ?? new Error('threw a nullish value');
      }
      expectConfigurationOrNothing(thrown);
    });
  }
});
