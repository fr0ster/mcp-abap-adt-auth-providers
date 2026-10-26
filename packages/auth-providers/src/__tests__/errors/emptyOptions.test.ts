/**
 * An empty options object: a constructor or factory answers with its own
 * `configuration` failure (a value rule or an optional field the
 * configuration needs) or returns. One row per maker, so a refusal removed
 * later is pruned row by row. A maker whose only refusal of `{}` was for a
 * field its type requires has no row: what it does with a value that breaks
 * its type is not stated.
 */
import { inspect } from 'node:util';
import { describe, expect, it } from '@jest/globals';
import { isAuthProviderFailure } from '@mcp-abap-adt/auth-errors';
import { composeAuthorization } from '../../authorization/compose';
import {
  consumerAnswer,
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
import { refreshThenLogin } from '../../renewal';
import { DefaultSncLibraryLocator } from '../../snc/DefaultSncLibraryLocator';
import { SecureLoginClientProbe } from '../../snc/SecureLoginClientProbe';
import { asOidcResult } from '../../strategies/asOidcResult';
import {
  browserCallbackStrategy,
  oidcCallbackStrategy,
  samlCallbackStrategy,
} from '../../strategies/callbackStrategies';
import { staticCodeStrategy } from '../../strategies/codeStrategies';
import { manualPasscodeStrategy } from '../../strategies/manualStrategies';

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
  'new BasicAuthProvider (user)': (x) => new BasicAuthProvider(h(x), 'p'),
  'new BasicAuthProvider (password)': (x) => new BasicAuthProvider('u', h(x)),
  'new CertificateAuthProvider': (x) => new CertificateAuthProvider(h(x), h(x)),
  'CertificateAuthProvider.fromFiles': (x) =>
    CertificateAuthProvider.fromFiles(h(x)),
  'new SamlAuthProvider': (x) => new SamlAuthProvider(h(x)),
  'TokenAuthProvider.fixed': (x) => TokenAuthProvider.fixed(h(x)),
  'TokenAuthProvider.from': (x) => TokenAuthProvider.from(h(x)),
  'new DefaultSncLibraryLocator': (x) => new DefaultSncLibraryLocator(h(x)),
  'new SecureLoginClientProbe': (x) => new SecureLoginClientProbe(h(x)),
  'clientSecretBasic (secret)': (x) =>
    clientSecretBasic(h(x), { encoding: 'raw' }),
  clientSecretPost: (x) => clientSecretPost(h(x)),
  tlsClientCertificate: (x) => tlsClientCertificate(h(x)),
  privateKeyJwt: (x) => privateKeyJwt(h(x)),
  composeAuthorization: (x) => composeAuthorization(h(x)),
  loopback: (x) => loopback(h(x)),
  loopback4: (x) => loopback4(h(x)),
  loopback6: (x) => loopback6(h(x)),
  terminalPaste: (x) => terminalPaste(h(x)),
  browserCallbackStrategy: (x) => browserCallbackStrategy(h(x)),
  oidcCallbackStrategy: (x) => oidcCallbackStrategy(h(x)),
  samlCallbackStrategy: (x) => samlCallbackStrategy(h(x)),
  manualPasscodeStrategy: (x) => manualPasscodeStrategy(h(x)),
  staticCodeStrategy: (x) => staticCodeStrategy(h(x)),
  asOidcResult: (x) => asOidcResult(h(x)),
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
