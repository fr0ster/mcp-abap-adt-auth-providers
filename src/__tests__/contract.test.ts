import { describe, expect, it } from '@jest/globals';
import type {
  IAuthorizationStrategy,
  IAuthProvider,
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces-auth';
import * as surface from '../index';
import { refreshThenLogin } from '../renewal';
import { recordingTargets } from './helpers/targets';
import { fakeSystem, peLibrary } from './snc/fakeSystem';

// Every secret below is named SECRET…; no outcome may contain one.
class FailingTokenProvider extends surface.BaseTokenProvider {
  protected async performLogin(): Promise<ITokenResult> {
    throw new Error('login failed for SECRET-CLIENT');
  }
  protected async performRefresh(
    _refreshToken: string,
    _signal: AbortSignal,
    dispatched: () => void,
  ): Promise<ITokenResult> {
    // The request leaves: the site would call this right before it.
    dispatched();
    throw new Error('refresh failed for SECRET-REFRESH');
  }
  protected getAuthType(): OAuth2GrantType {
    return 'client_credentials';
  }
}
const throwingStrategy: IAuthorizationStrategy<string> = {
  authorize: async () => {
    // A look-alike of the former ValidationError (gone in 6.0.0).
    throw Object.assign(new Error('SECRET-MSG'), {
      name: 'ValidationError',
      missingFields: ['SECRET-FIELD'],
    });
  },
};
const SLC = 'C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\lib\\sapcrypto.dll';
const system = fakeSystem({
  files: { [SLC]: peLibrary('x64') },
  registry: {
    'HKLM\\Software\\SAP\\SecureLogin\\InstallPath64':
      'C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\',
  },
});

// The remaining token providers inherit prepare/establish/authorize/rejected
// from BaseTokenProvider unmodified (exercised here via FailingTokenProvider,
// a local stand-in, and via AuthorizationCodeProvider); Saml2PureProvider's
// cookie-writing applyToken override is pinned in tokenProviderContract.test.ts.
// The refresh path of a real provider (one refresh, one login) is pinned in
// providers/oneRenewal.test.ts.
const providers: [string, IAuthProvider][] = [
  ['basic', new surface.BasicAuthProvider('SECRET-USER', 'SECRET-PW')],
  ['saml cookies', new surface.SamlAuthProvider('MYSAPSSO2=SECRET-COOKIE')],
  ['token fixed', surface.TokenAuthProvider.fixed('SECRET-TOKEN')],
  [
    'token from',
    surface.TokenAuthProvider.from({
      getToken: async () => {
        throw new Error('rejected SECRET-GET');
      },
      refreshToken: async () => {
        throw new Error('rejected SECRET-REFRESH');
      },
    }),
  ],
  [
    'certificate',
    new surface.CertificateAuthProvider(
      { load: async () => ({ cert: 'C', key: 'K', passphrase: 'SECRET-PP' }) },
      { url: 'https://h', authType: 'certificate' },
    ),
  ],
  [
    'token provider (failing)',
    new FailingTokenProvider({ renewal: refreshThenLogin() }),
  ],
  [
    'authorization code, throwing strategy',
    new surface.AuthorizationCodeProvider({
      renewal: refreshThenLogin(),
      uaaUrl: 'https://uaa',
      clientId: 'c',
      clientSecret: 'SECRET-CS',
      authorization: throwingStrategy,
    }),
  ],
  [
    'snc',
    new surface.SncLogonProvider({
      partnerName: 'p:CN=SID',
      locator: new surface.DefaultSncLibraryLocator(system),
      probes: [new surface.SecureLoginClientProbe(system)],
    }),
  ],
];

const isOutcome = (o: unknown) =>
  typeof o === 'object' &&
  o !== null &&
  ((o as { ok: unknown }).ok === true ||
    ((o as { ok: unknown }).ok === false &&
      typeof (o as { refusal: { reason: unknown } }).refusal?.reason ===
        'string'));

describe.each(providers)('%s answers the whole contract', (_, provider) => {
  it('has a kind', () => {
    expect(typeof provider.kind).toBe('string');
    expect(provider.kind.length).toBeGreaterThan(0);
  });
  it('every moment resolves to an AuthOutcome with no secret — working and throwing targets', async () => {
    for (const t of [recordingTargets(), recordingTargets({ throws: true })]) {
      for (const answer of [
        await provider.prepare(),
        await provider.establish(t.logonTarget),
        await provider.authorize(t.requestTarget),
        await provider.rejected({
          at: 'request',
          status: 401,
          error: new Error('401 SECRET-HTTP'),
        }),
        await provider.rejected({
          at: 'logon',
          error: 'refused SECRET-STRING',
        }),
        await provider.rejected({
          at: 'logon',
          error: {
            key: 'SECRET_KEY',
            code: 'ESECRET',
            name: 'SECRETError',
            missingFields: ['SECRET'],
            message: 'SECRET-SDK',
          },
        }),
      ]) {
        expect(isOutcome(answer)).toBe(true);
        expect(JSON.stringify(answer)).not.toMatch(/SECRET/);
      }
    }
  });
});
