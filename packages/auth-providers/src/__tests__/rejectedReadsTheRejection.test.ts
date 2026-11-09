import assert from 'node:assert/strict';
import { describe, it, mock } from 'node:test';
import { blamesCredential } from '@mcp-abap-adt/auth-errors';
import type {
  IAuthProvider,
  IAuthRejection,
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces-auth';
import * as surface from '../index';
import { refreshThenLogin } from '../renewal';
import {
  cases,
  caseTitle,
  contains,
  matchObject,
  matchText,
} from './helpers/expectations';
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
  assert.equal(outcome.ok, false);
  return outcome.ok ? undefined : outcome.refusal;
};

for (const [caseIndex, caseRow] of (
  [
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
  ] as const
).entries()) {
  const [_, make, blame] = caseRow;
  describe(
    caseTitle(
      '%s blames its credential only when it was refused',
      caseRow,
      caseIndex,
    ),
    () => {
      for (const [caseIndex, caseRow] of cases([
        ['401', r401],
        ['RFC_LOGON_FAILURE', logonRefused],
      ]).entries()) {
        const [_, r] = caseRow;
        it(caseTitle('%s → its own refusal', caseRow, caseIndex), async () => {
          assert.equal((await refusal(make(), r))?.reason, blame);
        });
      }

      for (const [caseIndex, caseRow] of cases([
        ['403', r403, /not authorized \(403\)/],
        ['302', r302, /redirected .* \(302\)/],
        ['503', r503, /failed \(503\), not the credential/],
        ['a network failure', network, /RFC_COMMUNICATION_FAILURE/],
        [
          'an unknown logon failure',
          unknownLogon,
          /^the logon failed \(unknown error\)$/,
        ],
      ]).entries()) {
        const [_, r, reason] = caseRow;
        it(
          caseTitle('%s → a neutral refusal', caseRow, caseIndex),
          async () => {
            const got = await refusal(make(), r);
            matchText(got?.reason, reason);
            assert.notEqual(got?.reason, blame);
          },
        );
      }
    },
  );
}

describe('TokenAuthProvider.from renews only a refused credential', () => {
  const make = () => {
    const refreshToken = mock.fn(async () => 'NEW');
    const p = surface.TokenAuthProvider.from({
      getToken: async () => 'OLD',
      refreshToken,
    });
    return { p, refreshToken };
  };

  for (const [caseIndex, caseRow] of cases([
    ['401', r401],
    ['RFC_LOGON_FAILURE', logonRefused],
    ['an unknown logon failure', unknownLogon],
  ]).entries()) {
    const [_, r] = caseRow;
    it(caseTitle('%s → renews → Ok', caseRow, caseIndex), async () => {
      const { p, refreshToken } = make();
      await p.authorize(recordingTargets().requestTarget);
      assert.deepEqual(await p.rejected(r), { ok: true });
      assert.equal(refreshToken.mock.callCount(), 1);
    });
  }

  for (const [caseIndex, caseRow] of cases([
    ['403', r403],
    ['302', r302],
    ['503', r503],
    ['a network failure', network],
  ]).entries()) {
    const [_, r] = caseRow;
    it(
      caseTitle('%s → no renewal, a neutral refusal', caseRow, caseIndex),
      async () => {
        const { p, refreshToken } = make();
        await p.authorize(recordingTargets().requestTarget);
        assert.equal((await p.rejected(r)).ok, false);
        assert.equal(refreshToken.mock.callCount(), 0);
      },
    );
  }
});

class CountingTokenProvider extends surface.BaseTokenProvider {
  login = mock.fn(
    async (): Promise<ITokenResult> => ({
      authorizationToken: `T${this.login.mock.calls.map((call) => call.arguments).length}`,
      refreshToken: 'R',
      authType: 'client_credentials',
      tokenType: 'opaque',
      expiresAt: Date.now() + 3600_000,
    }),
  );
  refresh = mock.fn(
    async (): Promise<ITokenResult> => ({
      authorizationToken: `F${this.refresh.mock.calls.map((call) => call.arguments).length}`,
      refreshToken: 'R',
      authType: 'client_credentials',
      tokenType: 'opaque',
      expiresAt: Date.now() + 3600_000,
    }),
  );
  protected performLogin() {
    return this.login();
  }
  protected performRefresh(
    _refreshToken: string,
    _signal: AbortSignal,
    dispatched: () => void,
  ) {
    // The request leaves: the site would call this right before it.
    dispatched();
    return this.refresh();
  }
  protected getAuthType(): OAuth2GrantType {
    return 'client_credentials';
  }
}

describe('BaseTokenProvider renews only a refused credential', () => {
  for (const [caseIndex, caseRow] of cases([
    ['401', r401],
    ['RFC_LOGON_FAILURE', logonRefused],
    ['an unknown logon failure', unknownLogon],
  ]).entries()) {
    const [_, r] = caseRow;
    it(caseTitle('%s → one renewal → Ok', caseRow, caseIndex), async () => {
      const p = new CountingTokenProvider({ renewal: refreshThenLogin() });
      await p.authorize(recordingTargets().requestTarget);
      assert.deepEqual(await p.rejected(r), { ok: true });
      assert.equal(p.refresh.mock.callCount(), 1);
    });
  }

  for (const [caseIndex, caseRow] of cases([
    ['403', r403, /not authorized \(403\)/],
    ['302', r302, /redirected/],
    ['503', r503, /failed \(503\)/],
    ['a network failure', network, /RFC_COMMUNICATION_FAILURE/],
  ]).entries()) {
    const [_, r, reason] = caseRow;
    it(
      caseTitle('%s → no renewal, a neutral refusal', caseRow, caseIndex),
      async () => {
        const p = new CountingTokenProvider({ renewal: refreshThenLogin() });
        await p.authorize(recordingTargets().requestTarget);
        const outcome = await p.rejected(r);
        matchText(outcome.ok === false && outcome.refusal.reason, reason);
        assert.equal(p.refresh.mock.callCount(), 0);
        assert.equal(p.login.mock.callCount(), 1); // only the authorize
      },
    );
  }
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
    matchText(got?.reason, /not authorized \(403\)/);
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
    assert.equal(
      got?.reason,
      'the SNC library has no credential to present (A2200019)',
    );
  });
});

describe('a neutral refusal is system-refused and never blames the credential', () => {
  const providers: ReadonlyArray<readonly [string, () => IAuthProvider]> = [
    ['basic', () => new surface.BasicAuthProvider('u', 'p')],
    ['saml cookies', () => new surface.SamlAuthProvider('MYSAPSSO2=x')],
    ['token fixed', () => surface.TokenAuthProvider.fixed('t')],
    [
      'token provider',
      () => new CountingTokenProvider({ renewal: refreshThenLogin() }),
    ],
  ];

  for (const [caseIndex, caseRow] of providers
    .flatMap(([name, make]) =>
      (
        [
          ['403', r403, 'not-authorized'],
          ['302', r302, 'redirected'],
          ['503', r503, 'system-failed'],
          ['a network failure', network, 'rfc-failure'],
        ] as const
      ).map(([what, r, verdict]) => [name, what, make, r, verdict] as const),
    )
    .entries()) {
    const [_n, _w, make, r, verdict] = caseRow;
    it(
      caseTitle('%s, %s → system-refused %s', caseRow, caseIndex),
      async () => {
        const p = make();
        await p.authorize(recordingTargets().requestTarget);
        const error = minted(await refusal(p, r));
        assert.equal(error.kind, 'system-refused');
        matchObject(error.facts, { verdict, at: r.at });
        assert.equal(blamesCredential(error), false);
      },
    );
  }

  for (const [caseIndex, caseRow] of providers
    .filter(([name]) => name !== 'token provider')
    .map(([name, make]) => [name, make] as const)
    .entries()) {
    const [_, make] = caseRow;
    it(
      caseTitle(
        '%s, an unknown logon failure → system-refused unknown',
        caseRow,
        caseIndex,
      ),
      async () => {
        const error = minted(await refusal(make(), unknownLogon));
        assert.equal(error.kind, 'system-refused');
        assert.deepEqual(error.facts, { verdict: 'unknown', at: 'logon' });
        assert.equal(blamesCredential(error), false);
      },
    );
  }
});
