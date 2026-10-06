import { describe, expect, it, jest } from '@jest/globals';
import { blamesCredential } from '@mcp-abap-adt/auth-errors';
import type {
  IAuthProvider,
  IAuthRejection,
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces-auth';
import * as surface from '../index';
import { minted } from './helpers/minted';
import { recordingTargets } from './helpers/targets';
import { fakeSystem, peLibrary } from './snc/fakeSystem';

const r401: IAuthRejection = { at: 'request', status: 401, error: {} };
const logonRefused: IAuthRejection = {
  at: 'logon',
  error: { key: 'RFC_LOGON_FAILURE' },
};
const r403: IAuthRejection = { at: 'request', status: 403, error: {} };
const r302: IAuthRejection = { at: 'request', status: 302, error: {} };
const r503: IAuthRejection = { at: 'request', status: 503, error: {} };
const network: IAuthRejection = {
  at: 'logon',
  error: { key: 'RFC_COMMUNICATION_FAILURE', message: 'partner not reached' },
};
const unknownLogon: IAuthRejection = { at: 'logon', error: new Error('?') };

const refusal = async (p: IAuthProvider, r: IAuthRejection) => {
  const outcome = await p.rejected(r);
  expect(outcome.ok).toBe(false);
  return outcome.ok ? undefined : outcome.refusal;
};

describe.each([
  [
    'basic',
    () => new surface.BasicAuthProvider('u', 'p'),
    'the user or password was refused',
  ],
  [
    'certificate',
    () =>
      new surface.CertificateAuthProvider(
        { load: async () => ({ cert: 'C', key: 'K' }) },
        { url: 'https://h', authType: 'certificate' },
      ),
    'the client certificate was refused',
  ],
  [
    'saml cookies',
    () => new surface.SamlAuthProvider('MYSAPSSO2=x'),
    'the SAML session was refused or has expired',
  ],
  [
    'token fixed',
    () => surface.TokenAuthProvider.fixed('t'),
    'the token was refused',
  ],
] as const)(
  '%s blames its credential only when it was refused',
  (_, make, blame) => {
    it.each([
      ['401', r401],
      ['RFC_LOGON_FAILURE', logonRefused],
    ])('%s → its own refusal', async (_, r) => {
      expect((await refusal(make(), r))?.reason).toBe(blame);
    });

    it.each([
      ['403', r403, /not authorized \(403\)/],
      ['302', r302, /redirected .* \(302\)/],
      ['503', r503, /failed \(503\), not the credential/],
      ['a network failure', network, /RFC_COMMUNICATION_FAILURE/],
      [
        'an unknown logon failure',
        unknownLogon,
        /^the logon failed \(unknown error\)$/,
      ],
    ])('%s → a neutral refusal', async (_, r, reason) => {
      const got = await refusal(make(), r);
      expect(got?.reason).toMatch(reason);
      expect(got?.reason).not.toBe(blame);
    });
  },
);

describe('TokenAuthProvider.from renews only a refused credential', () => {
  const make = () => {
    const refreshToken = jest.fn(async () => 'NEW');
    const p = surface.TokenAuthProvider.from({
      getToken: async () => 'OLD',
      refreshToken,
    });
    return { p, refreshToken };
  };

  it.each([
    ['401', r401],
    ['RFC_LOGON_FAILURE', logonRefused],
    ['an unknown logon failure', unknownLogon],
  ])('%s → renews → Ok', async (_, r) => {
    const { p, refreshToken } = make();
    await p.authorize(recordingTargets().requestTarget);
    await expect(p.rejected(r)).resolves.toEqual({ ok: true });
    expect(refreshToken).toHaveBeenCalledTimes(1);
  });

  it.each([
    ['403', r403],
    ['302', r302],
    ['503', r503],
    ['a network failure', network],
  ])('%s → no renewal, a neutral refusal', async (_, r) => {
    const { p, refreshToken } = make();
    await p.authorize(recordingTargets().requestTarget);
    expect((await p.rejected(r)).ok).toBe(false);
    expect(refreshToken).not.toHaveBeenCalled();
  });
});

class CountingTokenProvider extends surface.BaseTokenProvider {
  login = jest.fn(
    async (): Promise<ITokenResult> => ({
      authorizationToken: `T${this.login.mock.calls.length}`,
      refreshToken: 'R',
      authType: 'client_credentials',
      tokenType: 'opaque',
      expiresAt: Date.now() + 3600_000,
    }),
  );
  refresh = jest.fn(
    async (): Promise<ITokenResult> => ({
      authorizationToken: `F${this.refresh.mock.calls.length}`,
      refreshToken: 'R',
      authType: 'client_credentials',
      tokenType: 'opaque',
      expiresAt: Date.now() + 3600_000,
    }),
  );
  protected performLogin() {
    return this.login();
  }
  protected performRefresh() {
    return this.refresh();
  }
  protected getAuthType(): OAuth2GrantType {
    return 'client_credentials';
  }
}

describe('BaseTokenProvider renews only a refused credential', () => {
  it.each([
    ['401', r401],
    ['RFC_LOGON_FAILURE', logonRefused],
    ['an unknown logon failure', unknownLogon],
  ])('%s → one renewal → Ok', async (_, r) => {
    const p = new CountingTokenProvider();
    await p.authorize(recordingTargets().requestTarget);
    await expect(p.rejected(r)).resolves.toEqual({ ok: true });
    expect(p.refresh).toHaveBeenCalledTimes(1);
  });

  it.each([
    ['403', r403, /not authorized \(403\)/],
    ['302', r302, /redirected/],
    ['503', r503, /failed \(503\)/],
    ['a network failure', network, /RFC_COMMUNICATION_FAILURE/],
  ])('%s → no renewal, a neutral refusal', async (_, r, reason) => {
    const p = new CountingTokenProvider();
    await p.authorize(recordingTargets().requestTarget);
    const outcome = await p.rejected(r);
    expect(outcome.ok === false && outcome.refusal.reason).toMatch(reason);
    expect(p.refresh).not.toHaveBeenCalled();
    expect(p.login).toHaveBeenCalledTimes(1); // only the authorize
  });
});

describe('SncLogonProvider leaves a status that is not about the logon to the neutral words', () => {
  const SLC =
    'C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\lib\\sapcrypto.dll';
  const system = fakeSystem({
    files: { [SLC]: peLibrary('x64') },
    registry: {
      'HKLM\\Software\\SAP\\SecureLogin\\InstallPath64':
        'C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\',
    },
  });
  const make = () =>
    new surface.SncLogonProvider({
      partnerName: 'p:CN=SID',
      locator: new surface.DefaultSncLibraryLocator(system),
      probes: [new surface.SecureLoginClientProbe(system)],
    });

  it('403 on a call → the neutral refusal, not an SNC one', async () => {
    const got = await refusal(make(), r403);
    expect(got?.reason).toMatch(/not authorized \(403\)/);
  });

  it('a GSS code in a communication failure is still explained', async () => {
    const got = await refusal(make(), {
      at: 'logon',
      error: {
        key: 'RFC_COMMUNICATION_FAILURE',
        message:
          'GSS-API(min): A2200019:Operation aborted by user or application',
      },
    });
    expect(got?.reason).toBe(
      'the SNC library has no credential to present (A2200019)',
    );
  });
});

describe('a neutral refusal is system-refused and never blames the credential', () => {
  const providers: ReadonlyArray<readonly [string, () => IAuthProvider]> = [
    ['basic', () => new surface.BasicAuthProvider('u', 'p')],
    ['saml cookies', () => new surface.SamlAuthProvider('MYSAPSSO2=x')],
    ['token fixed', () => surface.TokenAuthProvider.fixed('t')],
    ['token provider', () => new CountingTokenProvider()],
  ];

  it.each(
    providers.flatMap(([name, make]) =>
      (
        [
          ['403', r403, 'not-authorized'],
          ['302', r302, 'redirected'],
          ['503', r503, 'system-failed'],
          ['a network failure', network, 'rfc-failure'],
        ] as const
      ).map(([what, r, verdict]) => [name, what, make, r, verdict] as const),
    ),
  )('%s, %s → system-refused %s', async (_n, _w, make, r, verdict) => {
    const p = make();
    await p.authorize(recordingTargets().requestTarget);
    const error = minted(await refusal(p, r));
    expect(error.kind).toBe('system-refused');
    expect(error.facts).toMatchObject({ verdict, at: r.at });
    expect(blamesCredential(error)).toBe(false);
  });

  it.each(
    providers
      .filter(([name]) => name !== 'token provider')
      .map(([name, make]) => [name, make] as const),
  )(
    '%s, an unknown logon failure → system-refused unknown',
    async (_, make) => {
      const error = minted(await refusal(make(), unknownLogon));
      expect(error.kind).toBe('system-refused');
      expect(error.facts).toEqual({ verdict: 'unknown', at: 'logon' });
      expect(blamesCredential(error)).toBe(false);
    },
  );
});
