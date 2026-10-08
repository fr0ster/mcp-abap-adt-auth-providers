import { describe, expect, it } from '@jest/globals';
import { DefaultSncLibraryLocator } from '../../snc/DefaultSncLibraryLocator';
import { SecureLoginClientProbe } from '../../snc/SecureLoginClientProbe';
import { SncLogonProvider } from '../../snc/SncLogonProvider';
import type { SncSystem } from '../../snc/SncSystem';
import { configurationOf, mintedRefusal, wordsOf } from '../helpers/minted';
import { recordingTargets } from '../helpers/targets';
import { fakeSystem, peLibrary } from './fakeSystem';

const SLC = 'C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\lib\\sapcrypto.dll';
const KRB = 'C:\\Windows\\System32\\gsskrb5.dll';
const REGISTRY = {
  'HKLM\\Software\\SAP\\SecureLogin\\InstallPath64':
    'C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\',
};
const machine = () =>
  fakeSystem({
    files: { [SLC]: peLibrary('x64'), [KRB]: peLibrary('x64') },
    registry: REGISTRY,
  });
const throwingLogger = () => {
  const boom = () => {
    throw new Error('log sink down SECRET-LOG');
  };
  return { debug: boom, info: boom, warn: boom, error: boom };
};
/** What forSecureLoginClient assembles, on a fake machine. */
const snc = (
  system: SncSystem,
  extra: { sncLib?: string; qop?: string; myName?: string } = {},
) =>
  new SncLogonProvider({
    partnerName: 'p:CN=SID',
    qop: extra.qop,
    myName: extra.myName,
    locator: new DefaultSncLibraryLocator(system, extra.sncLib),
    probes: [new SecureLoginClientProbe(system)],
  });
const sdkError = {
  name: 'RfcLibError',
  message:
    '\nERROR       GSS-API(maj): Miscellaneous failure\n            GSS-API(min): A2200019:Operation aborted by user or\n',
};

describe('construction', () => {
  const parts = (s: SncSystem) => ({
    locator: new DefaultSncLibraryLocator(s),
    probes: [],
  });
  it('requires partnerName', () => {
    let thrown: unknown;
    try {
      new SncLogonProvider({ partnerName: ' ', ...parts(machine()) });
    } catch (error) {
      thrown = error;
    }
    expect(configurationOf(thrown).case).toBe('snc-partner-name-missing');
  });
  it('names partnerName with an ASCII apostrophe', () => {
    expect(
      () => new SncLogonProvider({ partnerName: ' ', ...parts(machine()) }),
    ).toThrow("SncLogonProvider needs partnerName — the system's SNC name");
  });
  it.each(['0', '4', '5', '6', '7', '10', 'max', ''])(
    'refuses qop %p',
    (qop) => {
      expect(
        () =>
          new SncLogonProvider({
            partnerName: 'p:CN=SID',
            qop,
            ...parts(machine()),
          }),
      ).toThrow(/qop/);
    },
  );
  it.each(['1', '2', '3', '8', '9'])('accepts qop %p', (qop) => {
    expect(
      () =>
        new SncLogonProvider({
          partnerName: 'p:CN=SID',
          qop,
          ...parts(machine()),
        }),
    ).not.toThrow();
  });
  it('locator and probes are required (compile-time)', () => {
    expect(
      () =>
        // @ts-expect-error locator and probes are required
        new SncLogonProvider({ partnerName: 'p:CN=SID' }),
    ).toBeDefined();
  });
  it('forSecureLoginClient assembles the locator and the Secure Login Client probe', () => {
    const p = SncLogonProvider.forSecureLoginClient({
      partnerName: 'p:CN=SID',
    }) as unknown as { locator: unknown; probes: unknown[] };
    expect(p.locator).toBeInstanceOf(DefaultSncLibraryLocator);
    expect(p.probes).toHaveLength(1);
    expect(p.probes[0]).toBeInstanceOf(SecureLoginClientProbe);
  });
});

describe('the four moments', () => {
  it('prepare → establish writes the SNC parameters, no user or passwd', async () => {
    const p = snc(machine());
    await expect(p.prepare()).resolves.toEqual({ ok: true });
    const t = recordingTargets();
    await expect(p.establish(t.logonTarget)).resolves.toEqual({ ok: true });
    expect(t.logon.params).toEqual([
      {
        snc_mode: '1',
        snc_partnername: 'p:CN=SID',
        snc_qop: '9',
        snc_lib: SLC,
      },
    ]);
    await expect(p.authorize(t.requestTarget)).resolves.toEqual({ ok: true });
    expect(t.request).toEqual({ headers: {}, cookies: [] });
  });
  it('snc_myname only when configured', async () => {
    const p = snc(machine(), { myName: 'p:CN=ME', qop: '8' });
    await p.prepare();
    const t = recordingTargets();
    await p.establish(t.logonTarget);
    expect(t.logon.params[0]).toMatchObject({
      snc_myname: 'p:CN=ME',
      snc_qop: '8',
    });
  });
  it('an HTTP wire: the target Oops is SNC’s own', async () => {
    const p = snc(machine());
    await p.prepare();
    await expect(
      p.establish(
        recordingTargets({ acceptsLogonParameters: false }).logonTarget,
      ),
    ).resolves.toMatchObject({
      ok: false,
      refusal: { reason: 'this wire takes no logon parameters (HTTP)' },
    });
  });
  it('a throwing target is an Oops', async () => {
    const p = snc(machine());
    await p.prepare();
    const outcome = await p.establish(
      recordingTargets({ throws: true }).logonTarget,
    );
    expect(outcome.ok).toBe(false);
    expect(JSON.stringify(outcome)).not.toMatch(/SECRET-IN-TARGET/);
  });
  it('establish before prepare is an Oops', async () => {
    await expect(
      snc(machine()).establish(recordingTargets().logonTarget),
    ).resolves.toMatchObject({ ok: false });
  });
  it('SLC library → Ok: the product is named, not checked', async () => {
    await expect(snc(machine()).prepare()).resolves.toEqual({ ok: true });
  });
  it('non-SLC library → Ok, no product named', async () => {
    await expect(snc(machine(), { sncLib: KRB }).prepare()).resolves.toEqual({
      ok: true,
    });
  });
  it('no candidate at all → the refusal says so; the hint needs no logger', async () => {
    const outcome = await snc(fakeSystem({ platform: 'linux' })).prepare();
    expect(wordsOf(outcome)).toEqual({
      ok: false,
      refusal: {
        reason:
          'no usable SNC library was found: no candidate (SNC_LIB_64 and SNC_LIB are unset and no Secure Login Client installation was found)',
        hint: 'set sncLib to the SNC (GSS) library of your SNC product',
      },
    });
  });
  // The path is in the diagnostics, not the words.
  it('explicit sncLib unusable → that one source and its reason', async () => {
    const outcome = await snc(machine(), {
      sncLib: 'C:\\nope\\sapcrypto.dll',
    }).prepare();
    expect(wordsOf(outcome)).toEqual({
      ok: false,
      refusal: {
        reason: 'no usable SNC library was found: sncLib (missing)',
        hint: 'set sncLib to the SNC (GSS) library of your SNC product',
      },
    });
    expect(mintedRefusal(outcome).diagnostics).toEqual({
      candidatePaths: ['C:\\nope\\sapcrypto.dll'],
    });
  });
  // The paths are in the diagnostics, not the words.
  it('automatic → every candidate, each with its fixed reason', async () => {
    const X86 =
      'C:\\Program Files (x86)\\SAP\\FrontEnd\\SecureLogin\\lib\\sapcrypto.dll';
    const TXT = 'D:\\readme.txt';
    const outcome = await snc(
      fakeSystem({
        env: { SNC_LIB_64: TXT, SNC_LIB: X86 },
        files: { [X86]: peLibrary('ia32'), [TXT]: Buffer.from('hello') },
        registry: REGISTRY,
      }),
    ).prepare();
    expect(outcome).toMatchObject({
      ok: false,
      refusal: {
        reason:
          'no usable SNC library was found: SNC_LIB_64 (not a library); SNC_LIB (wrong architecture); registry (missing)',
      },
    });
    expect(mintedRefusal(outcome).diagnostics).toEqual({
      candidatePaths: [TXT, X86, SLC],
    });
  });
  it('a custom locator throwing a foreign error lends no message', async () => {
    const p = new SncLogonProvider({
      partnerName: 'p:CN=SID',
      locator: {
        locate: async () => {
          throw new Error('vault said SECRET-VAULT');
        },
      },
      probes: [],
    });
    expect(JSON.stringify(await p.prepare())).not.toMatch(/SECRET/);
  });
  it('a throwing logger never makes a method throw', async () => {
    const make = (system: SncSystem, sncLib?: string) =>
      new SncLogonProvider({
        partnerName: 'p:CN=SID',
        locator: new DefaultSncLibraryLocator(system, sncLib),
        probes: [new SecureLoginClientProbe(system)],
        logger: throwingLogger() as never,
      });
    for (const p of [
      make(machine()),
      make(machine(), 'C:\\nope.dll'),
      make(fakeSystem({ platform: 'linux' })),
    ]) {
      const outcomes = [
        await p.prepare(),
        await p.establish(recordingTargets().logonTarget),
        await p.authorize(recordingTargets().requestTarget),
        await p.rejected({ at: 'logon', error: sdkError }),
      ];
      for (const outcome of outcomes) {
        expect(outcome).toHaveProperty('ok');
        expect(JSON.stringify(outcome)).not.toMatch(/SECRET/);
      }
    }
    // A log sink that is down changes no answer.
    const usable = make(machine());
    await expect(usable.prepare()).resolves.toEqual({ ok: true });
    // The path is a diagnostic, never a word.
    await expect(
      make(machine(), 'C:\\nope.dll').prepare(),
    ).resolves.toMatchObject({
      refusal: {
        reason: 'no usable SNC library was found: sncLib (missing)',
        diagnostics: { candidatePaths: ['C:\\nope.dll'] },
      },
    });
  });
  it('a custom locator returning a library without archs does not throw', async () => {
    const p = new SncLogonProvider({
      partnerName: 'p:CN=SID',
      locator: { locate: async () => ({ path: KRB }) as never },
      probes: [],
      logger: { debug() {}, info() {}, warn() {}, error() {} },
    });
    await expect(p.prepare()).resolves.toEqual({ ok: true });
    // The library is a diagnostic.
    await expect(
      p.rejected({ at: 'logon', error: 'SNCERR_INIT' }),
    ).resolves.toMatchObject({
      ok: false,
      refusal: {
        reason:
          'the RFC SDK could not initialise the SNC library as its SNC library (SNCERR_INIT)',
        diagnostics: { library: KRB },
      },
    });
  });
  it('a probe that throws is skipped, not a refusal', async () => {
    const p = new SncLogonProvider({
      partnerName: 'p:CN=SID',
      locator: new DefaultSncLibraryLocator(machine(), KRB),
      probes: [
        {
          product: 'Broken',
          appliesTo: async () => {
            throw new Error('SECRET');
          },
        },
      ],
    });
    await expect(p.prepare()).resolves.toEqual({ ok: true });
  });
});

describe('rejected', () => {
  it('A2200019 → the fixed reason, asserted', async () => {
    const p = snc(machine());
    await p.prepare();
    expect(wordsOf(await p.rejected({ at: 'logon', error: sdkError }))).toEqual(
      {
        ok: false,
        refusal: {
          reason: 'the SNC library has no credential to present (A2200019)',
          hint: 'log on in the Secure Login Client, to the profile used for SAP applications',
        },
      },
    );
  });
  it('before prepare(): the generic hint, no throw', async () => {
    expect(
      wordsOf(await snc(machine()).rejected({ at: 'logon', error: sdkError })),
    ).toEqual({
      ok: false,
      refusal: {
        reason: 'the SNC library has no credential to present (A2200019)',
        hint: 'make sure the SNC product behind the SNC library is logged on',
      },
    });
  });
  it.each([
    ['a free-text name', 'SECRET-PRODUCT'],
    ['the shipped name, not the shipped probe', 'SAP Secure Login Client'],
  ])('a consumer probe with %s → the generic hint', async (_, product) => {
    const p = new SncLogonProvider({
      partnerName: 'p:CN=SID',
      locator: new DefaultSncLibraryLocator(machine(), SLC),
      probes: [{ product, appliesTo: async () => true }],
    });
    await p.prepare();
    const outcome = await p.rejected({ at: 'logon', error: sdkError });
    // "The SNC library" in the hint, the path in diagnostics.
    expect(outcome).toMatchObject({
      ok: false,
      refusal: {
        hint: 'make sure the SNC product behind the SNC library is logged on',
        diagnostics: { library: SLC },
      },
    });
    expect(JSON.stringify(outcome)).not.toMatch(/SECRET|Secure Login Client/);
  });
  it.each([
    ['the SDK object', sdkError],
    [
      'an Error',
      new Error(`Failed to open RFC connection: ${JSON.stringify(sdkError)}`),
    ],
    ['a string', 'GSS-API(min): A2200019:Operation aborted'],
  ])('A2200019 in %s → log on in the Secure Login Client', async (_, error) => {
    const p = snc(machine());
    await p.prepare();
    await expect(p.rejected({ at: 'logon', error })).resolves.toMatchObject({
      ok: false,
      refusal: {
        hint: expect.stringMatching(/log on in the Secure Login Client/),
      },
    });
  });
  // The library is named in diagnostics, not in the words.
  it('another library: names it in diagnostics, not the Secure Login Client', async () => {
    const p = snc(machine(), { sncLib: KRB });
    await p.prepare();
    const refused = mintedRefusal(
      await p.rejected({ at: 'logon', error: sdkError }),
    );
    expect(refused.diagnostics).toEqual({ library: KRB });
    expect(`${refused.reason} ${refused.hint}`).not.toMatch(
      /gsskrb5|Secure Login Client/,
    );
  });
  // The architecture stays a word, the path is a diagnostic.
  it('SNCERR_INIT names the architecture; the library a diagnostic', async () => {
    const p = snc(machine());
    await p.prepare();
    await expect(
      p.rejected({
        at: 'logon',
        error: new Error('SNCERR_INIT, gssapi library invalid/missing'),
      }),
    ).resolves.toMatchObject({
      ok: false,
      refusal: {
        reason:
          'the RFC SDK could not initialise the SNC library (x64) as its SNC library (SNCERR_INIT)',
        diagnostics: { library: SLC },
      },
    });
  });
  it('anything else: fixed reason, an allowlisted key only', async () => {
    const p = snc(machine());
    await p.prepare();
    expect(
      wordsOf(
        await p.rejected({
          at: 'logon',
          error: {
            key: 'RFC_LOGON_FAILURE',
            message: 'SECRET-SDK',
            detail: 'SECRET',
          },
        }),
      ),
    ).toEqual({
      ok: false,
      refusal: { reason: 'SNC logon refused (RFC_LOGON_FAILURE)' },
    });
    expect(
      wordsOf(
        await p.rejected({
          at: 'logon',
          error: { key: 'SECRET_TOKEN_KEY', message: 'x' },
        }),
      ),
    ).toEqual({ ok: false, refusal: { reason: 'SNC logon refused' } });
    expect(
      wordsOf(
        await p.rejected({
          at: 'logon',
          error: new Error('SECRET-IN-MESSAGE'),
        }),
      ),
    ).toEqual({ ok: false, refusal: { reason: 'SNC logon refused' } });
  });
});
