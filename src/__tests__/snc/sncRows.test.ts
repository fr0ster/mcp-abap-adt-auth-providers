/**
 * The refusals of `SncLogonProvider`, with the relay matrix and the
 * fixtures — each refusal a
 * minted `snc` (or `not-prepared`, `unknown`, `configuration`) error, its
 * words verbatim, every path a diagnostic and never a word.
 */
import { describe, expect, it, jest } from '@jest/globals';
import {
  AuthProviderFailure,
  authError,
  isAuthProviderFailure,
  isMinted,
  readFailure,
  renderDiagnostics,
} from '@mcp-abap-adt/auth-errors';
import type {
  AuthOutcome,
  ILogonTarget,
  IRequestTarget,
} from '@mcp-abap-adt/interfaces-auth';
import { DefaultSncLibraryLocator } from '../../snc/DefaultSncLibraryLocator';
import { SecureLoginClientProbe } from '../../snc/SecureLoginClientProbe';
import { SncLogonProvider } from '../../snc/SncLogonProvider';
import type { SncSystem } from '../../snc/SncSystem';
import { configurationOf, mintedRefusal } from '../helpers/minted';
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
const HINT = 'set sncLib to the SNC (GSS) library of your SNC product';
const MARKER = 'SECRET-MARKER';
const A2200019 = {
  name: 'RfcLibError',
  message:
    '\nERROR       GSS-API(maj): Miscellaneous failure\n            GSS-API(min): A2200019:Operation aborted by user or\n',
};

const snc = (
  system: SncSystem,
  extra: { sncLib?: string; signal?: AbortSignal; logger?: never } = {},
) =>
  new SncLogonProvider({
    partnerName: 'p:CN=SID',
    locator: new DefaultSncLibraryLocator(system, extra.sncLib),
    probes: [new SecureLoginClientProbe(system)],
    signal: extra.signal,
    logger: extra.logger,
  });

function recordingLogger() {
  const lines: { level: string; message: string; meta: unknown }[] = [];
  const at =
    (level: string) =>
    (message: string, meta?: unknown): void => {
      lines.push({ level, message, meta });
    };
  return {
    logger: {
      debug: at('debug'),
      info: at('info'),
      warn: at('warn'),
      error: at('error'),
    } as never,
    lines,
  };
}

describe('A2200019: no credential to present', () => {
  it('Secure Login Client library → its hint; the path a diagnostic only', async () => {
    const p = snc(machine());
    await p.prepare();
    const error = mintedRefusal(
      await p.rejected({ at: 'logon', error: A2200019 }),
    );
    expect(error).toMatchObject({
      kind: 'snc',
      variant: 'no-credential',
      facts: {
        problem: 'no-credential',
        secureLoginClient: true,
        libraryArchs: ['x64'],
      },
      reason: 'the SNC library has no credential to present (A2200019)',
      hint: 'log on in the Secure Login Client, to the profile used for SAP applications',
      diagnostics: { library: SLC },
    });
  });
  it('another product: "the SNC library" in the hint, the path in diagnostics', async () => {
    const p = snc(machine(), { sncLib: KRB });
    await p.prepare();
    const error = mintedRefusal(
      await p.rejected({ at: 'logon', error: A2200019 }),
    );
    expect(error.reason).toBe(
      'the SNC library has no credential to present (A2200019)',
    );
    expect(error.hint).toBe(
      'make sure the SNC product behind the SNC library is logged on',
    );
    expect(error.facts).toEqual({
      problem: 'no-credential',
      secureLoginClient: false,
      libraryArchs: ['x64'],
    });
    expect(renderDiagnostics(error)).toBe(`library: ${JSON.stringify(KRB)}`);
    expect(`${error.reason} ${error.hint}`).not.toContain('gsskrb5');
  });
  it('before prepare(): no library, no diagnostics', async () => {
    const error = mintedRefusal(
      await snc(machine()).rejected({ at: 'logon', error: A2200019 }),
    );
    expect(error.hint).toBe(
      'make sure the SNC product behind the SNC library is logged on',
    );
    expect(error).not.toHaveProperty('diagnostics');
  });
  it('found in a string and in an Error, never copied', async () => {
    const p = snc(machine());
    await p.prepare();
    for (const error of [
      `${MARKER} GSS-API(min): A2200019:Operation aborted`,
      new Error(`${MARKER} A2200019`),
    ]) {
      const outcome = await p.rejected({ at: 'logon', error });
      expect(mintedRefusal(outcome).variant).toBe('no-credential');
      expect(JSON.stringify(outcome)).not.toContain(MARKER);
    }
  });
});

describe('SNCERR_INIT: the library could not be initialised', () => {
  it.each([
    'SNCERR_INIT',
    'sncerr_init while loading',
    'GSSAPI LIBRARY INVALID/MISSING',
  ])(
    '%s → the architectures as a fact, the path a diagnostic',
    async (text) => {
      const p = snc(machine());
      await p.prepare();
      const error = mintedRefusal(
        await p.rejected({ at: 'logon', error: new Error(text) }),
      );
      expect(error).toMatchObject({
        kind: 'snc',
        facts: { problem: 'library-init-failed', libraryArchs: ['x64'] },
        reason:
          'the RFC SDK could not initialise the SNC library (x64) as its SNC library (SNCERR_INIT)',
        diagnostics: { library: SLC },
      });
      expect(error).not.toHaveProperty('hint');
    },
  );
  it('a custom locator without archs: the words without them', async () => {
    const p = new SncLogonProvider({
      partnerName: 'p:CN=SID',
      locator: { locate: async () => ({ path: KRB }) as never },
      probes: [],
    });
    await expect(p.prepare()).resolves.toEqual({ ok: true });
    const error = mintedRefusal(
      await p.rejected({ at: 'logon', error: 'SNCERR_INIT' }),
    );
    expect(error.reason).toBe(
      'the RFC SDK could not initialise the SNC library as its SNC library (SNCERR_INIT)',
    );
    expect(error.diagnostics).toEqual({ library: KRB });
  });
});

describe('SNC logon refused', () => {
  it('RFC_LOGON_FAILURE → the key as a fact', async () => {
    const p = snc(machine());
    await p.prepare();
    const error = mintedRefusal(
      await p.rejected({
        at: 'logon',
        error: { key: 'RFC_LOGON_FAILURE', message: MARKER },
      }),
    );
    expect(error).toMatchObject({
      kind: 'snc',
      facts: { problem: 'logon-refused', rfcKey: 'RFC_LOGON_FAILURE' },
      reason: 'SNC logon refused (RFC_LOGON_FAILURE)',
    });
    expect(JSON.stringify(error)).not.toContain(MARKER);
  });
  it.each([
    ['an unlisted key', { key: 'SECRET_KEY', message: 'x' }],
    ['an Error', new Error(MARKER)],
    ['nothing', undefined],
  ])('%s → the words alone', async (_, error) => {
    const p = snc(machine());
    await p.prepare();
    const refused = mintedRefusal(await p.rejected({ at: 'logon', error }));
    expect(refused.facts).toEqual({ problem: 'logon-refused' });
    expect(refused.reason).toBe('SNC logon refused');
    expect(JSON.stringify(refused)).not.toContain(MARKER);
  });
});

describe('a locator that is not the shipped one', () => {
  it('a foreign error → the fixed sentence, no facts beyond the problem', async () => {
    const p = new SncLogonProvider({
      partnerName: 'p:CN=SID',
      locator: {
        locate: async () => {
          throw new Error(`vault said ${MARKER}`);
        },
      },
      probes: [],
    });
    const outcome = await p.prepare();
    const error = mintedRefusal(outcome);
    expect(error).toMatchObject({
      kind: 'snc',
      facts: { problem: 'library-not-found' },
      reason: 'no usable SNC library was found',
      hint: HINT,
    });
    expect(error.facts).toEqual({ problem: 'library-not-found' });
    expect(JSON.stringify(outcome)).not.toContain(MARKER);
  });
  it('even a minted library-not-found with paths: not the approved source', async () => {
    const forged = authError.snc(
      {
        problem: 'library-not-found',
        searched: true,
        candidates: [{ source: 'sncLib', reason: 'missing' }],
      },
      { candidatePaths: ['/home/user/SECRET-MARKER.so'] },
    );
    const p = new SncLogonProvider({
      partnerName: 'p:CN=SID',
      locator: {
        locate: async () => {
          throw new AuthProviderFailure(forged);
        },
      },
      probes: [],
    });
    const error = mintedRefusal(await p.prepare());
    expect(error.facts).toEqual({ problem: 'library-not-found' });
    expect(JSON.stringify(error)).not.toContain(MARKER);
  });
});

describe('what the shipped locator tried', () => {
  it('automatic: each source and reason in the words, each path a diagnostic', async () => {
    const X86 =
      'C:\\Program Files (x86)\\SAP\\FrontEnd\\SecureLogin\\lib\\sapcrypto.dll';
    const TXT = 'D:\\readme.txt';
    const error = mintedRefusal(
      await snc(
        fakeSystem({
          env: { SNC_LIB_64: TXT, SNC_LIB: X86 },
          files: { [X86]: peLibrary('ia32'), [TXT]: Buffer.from('hello') },
          registry: REGISTRY,
        }),
      ).prepare(),
    );
    expect(error).toMatchObject({
      kind: 'snc',
      variant: 'library-not-found',
      reason:
        'no usable SNC library was found: SNC_LIB_64 (not a library); SNC_LIB (wrong architecture); registry (missing)',
      hint: HINT,
    });
    expect(error.facts).toEqual({
      problem: 'library-not-found',
      searched: true,
      candidates: [
        { source: 'SNC_LIB_64', reason: 'not a library' },
        { source: 'SNC_LIB', reason: 'wrong architecture', archs: ['ia32'] },
        { source: 'registry', reason: 'missing' },
      ],
      processArch: 'x64',
    });
    expect(error.diagnostics).toEqual({ candidatePaths: [TXT, X86, SLC] });
    expect(renderDiagnostics(error)).toBe(
      `candidates: SNC_LIB_64 ${JSON.stringify(TXT)} (not a library); SNC_LIB ${JSON.stringify(X86)} (wrong architecture); registry ${JSON.stringify(SLC)} (missing)`,
    );
  });
  it('explicit sncLib: that one candidate, its path a diagnostic', async () => {
    const NOPE = 'C:\\nope\\sapcrypto.dll';
    const error = mintedRefusal(
      await snc(machine(), { sncLib: NOPE }).prepare(),
    );
    expect(error.reason).toBe(
      'no usable SNC library was found: sncLib (missing)',
    );
    expect(error.hint).toBe(HINT);
    expect(error.diagnostics).toEqual({ candidatePaths: [NOPE] });
  });
  it('no candidate: verbatim, candidates empty, no diagnostics', async () => {
    const error = mintedRefusal(
      await snc(fakeSystem({ platform: 'linux' })).prepare(),
    );
    expect(error).toMatchObject({
      reason:
        'no usable SNC library was found: no candidate (SNC_LIB_64 and SNC_LIB are unset and no Secure Login Client installation was found)',
      hint: HINT,
    });
    expect(error.facts).toEqual({
      problem: 'library-not-found',
      searched: true,
      candidates: [],
      processArch: 'x64',
    });
    expect(error).not.toHaveProperty('diagnostics');
  });
  it('docs/passwordless-sso.md quotes the A2200019 reason as it is', () => {
    const { readFileSync } =
      jest.requireActual<typeof import('node:fs')>('node:fs');
    const { join } =
      jest.requireActual<typeof import('node:path')>('node:path');
    const doc = readFileSync(
      join(__dirname, '..', '..', '..', 'docs', 'passwordless-sso.md'),
      'utf8',
    ).replace(/\s+/g, ' ');
    expect(doc).toContain(
      '"the SNC library has no credential to present (A2200019)"',
    );
  });
});

describe('the shipped locator throws a minted failure', () => {
  it('an AuthProviderFailure: facts with archs and the process arch, paths aligned', async () => {
    const X86 =
      'C:\\Program Files (x86)\\SAP\\FrontEnd\\SecureLogin\\lib\\sapcrypto.dll';
    const thrown = await new DefaultSncLibraryLocator(
      fakeSystem({
        arch: 'arm64',
        env: { SNC_LIB_64: X86 },
        files: { [X86]: peLibrary('x64') },
      }),
    )
      .locate()
      .catch((e: unknown) => e);
    expect(isAuthProviderFailure(thrown)).toBe(true);
    const error = readFailure(thrown, 'resolving-snc-library');
    expect(isMinted(error)).toBe(true);
    expect(error.facts).toEqual({
      problem: 'library-not-found',
      searched: true,
      candidates: [
        { source: 'SNC_LIB_64', reason: 'wrong architecture', archs: ['x64'] },
      ],
      processArch: 'arm64',
    });
    expect(error.diagnostics).toEqual({ candidatePaths: [X86] });
    // The message is the words: no path, no detail of the header.
    expect((thrown as Error).message).toBe(
      `no usable SNC library was found: SNC_LIB_64 (wrong architecture) — ${HINT}`,
    );
  });
});

describe('the locator returned no path', () => {
  it.each([
    ['blank', { path: '  ', archs: ['x64'] }],
    ['not a string', { path: 42 }],
    ['nothing', undefined],
  ])('%s → verbatim', async (_, found) => {
    const p = new SncLogonProvider({
      partnerName: 'p:CN=SID',
      locator: { locate: async () => found as never },
      probes: [],
    });
    const error = mintedRefusal(await p.prepare());
    expect(error).toMatchObject({
      kind: 'snc',
      facts: { problem: 'locator-returned-no-path' },
      reason: 'no usable SNC library was found: the locator returned no path',
      hint: HINT,
    });
  });
});

describe('establish before prepare', () => {
  it('not-prepared, provider snc, verbatim', async () => {
    const t = recordingTargets();
    const error = mintedRefusal(await snc(machine()).establish(t.logonTarget));
    expect(error).toMatchObject({
      kind: 'not-prepared',
      facts: { provider: 'snc' },
      reason: 'the SNC provider is not prepared',
      hint: 'connect() prepares it first',
    });
    expect(t.logon.params).toEqual([]);
  });
});

describe('the outer boundary names the SNC operation', () => {
  class GrantThrows extends SncLogonProvider {
    protected override grant(): never {
      throw new Error(MARKER);
    }
  }
  class MomentsGetter extends SncLogonProvider {
    get moments(): never {
      throw new Error(MARKER);
    }
  }
  const config = (system: SncSystem) => ({
    partnerName: 'p:CN=SID',
    locator: new DefaultSncLibraryLocator(system),
    probes: [new SecureLoginClientProbe(system)],
  });
  const t = recordingTargets();
  const moments: [string, (p: SncLogonProvider) => Promise<AuthOutcome>][] = [
    ['resolving the SNC library', (p) => p.prepare()],
    [
      'handing over the SNC logon parameters',
      (p) => p.establish(t.logonTarget),
    ],
    ['authorizing a request', (p) => p.authorize(t.requestTarget)],
    [
      'explaining the SNC refusal',
      (p) => p.rejected({ at: 'logon', error: A2200019 }),
    ],
  ];
  it.each(moments)('grant() throws → %s', async (words, call) => {
    const outcome = await call(new GrantThrows(config(machine())));
    const error = mintedRefusal(outcome);
    expect(error.kind).toBe('unknown');
    expect(error.reason).toBe(
      `the SNC provider failed while ${words} (unknown error)`,
    );
    expect(JSON.stringify(outcome)).not.toContain(MARKER);
  });
  it('a moments getter on a subclass changes nothing', async () => {
    const p = new MomentsGetter(config(machine()));
    await expect(p.prepare()).resolves.toEqual({ ok: true });
    await expect(p.establish(recordingTargets().logonTarget)).resolves.toEqual({
      ok: true,
    });
  });
  it('a locator answer whose path getter throws → resolving the SNC library', async () => {
    const p = new SncLogonProvider({
      partnerName: 'p:CN=SID',
      locator: {
        locate: async () =>
          ({
            get path(): string {
              throw new Error(MARKER);
            },
          }) as never,
      },
      probes: [],
    });
    const outcome = await p.prepare();
    expect(mintedRefusal(outcome).reason).toBe(
      'the SNC provider failed while resolving the SNC library (unknown error)',
    );
    expect(JSON.stringify(outcome)).not.toContain(MARKER);
  });
  it('a rejection whose error throws on every read → explaining the SNC refusal or neutral, never a rejection', async () => {
    const p = snc(machine());
    await p.prepare();
    const hostile = new Proxy(
      {},
      {
        get() {
          throw new Error(MARKER);
        },
      },
    );
    const outcome = await p.rejected({ at: 'logon', error: hostile });
    expect(outcome.ok).toBe(false);
    expect(JSON.stringify(outcome)).not.toContain(MARKER);
  });
});

describe('the log lines', () => {
  it('SNC library not found: <reason>, the paths as a field only', async () => {
    const NOPE = 'C:\\nope\\sapcrypto.dll';
    const { logger, lines } = recordingLogger();
    await snc(machine(), { sncLib: NOPE, logger }).prepare();
    const line = lines.find((l) => l.message.startsWith('SNC library not'));
    expect(line).toBeDefined();
    expect(line?.level).toBe('warn');
    expect(line?.message).toBe(
      'SNC library not found: no usable SNC library was found: sncLib (missing)',
    );
    expect(line?.meta).toEqual({
      error: 'no usable SNC library was found: sncLib (missing)',
      kind: 'snc',
      diagnostics: `candidates: sncLib ${JSON.stringify(NOPE)} (missing)`,
    });
  });
  it('an SNC product probe failed: <words>, no message of the throw', async () => {
    const { logger, lines } = recordingLogger();
    const p = new SncLogonProvider({
      partnerName: 'p:CN=SID',
      locator: new DefaultSncLibraryLocator(machine(), KRB),
      probes: [
        {
          product: 'Broken',
          appliesTo: async () => {
            throw new Error(MARKER);
          },
        },
      ],
      logger,
    });
    await expect(p.prepare()).resolves.toEqual({ ok: true });
    const line = lines.find((l) => l.message.startsWith('an SNC product'));
    expect(line?.level).toBe('warn');
    expect(line?.message).toBe(
      'an SNC product probe failed: the probe failed (unknown error)',
    );
    expect(JSON.stringify(lines)).not.toContain(MARKER);
  });
  it('a rejecting async logger changes no answer and leaves nothing unhandled', async () => {
    const reject = () => Promise.reject(new Error(MARKER));
    const logger = {
      debug: reject,
      info: reject,
      warn: reject,
      error: reject,
    } as never;
    await expect(
      snc(machine(), { sncLib: 'C:\\nope.dll', logger }).prepare(),
    ).resolves.toMatchObject({ ok: false });
    await expect(snc(machine(), { logger }).prepare()).resolves.toEqual({
      ok: true,
    });
  });
});

describe('construction', () => {
  const parts = () => ({
    locator: new DefaultSncLibraryLocator(machine()),
    probes: [],
  });
  it.each([' ', '', undefined, 42])(
    'partnerName %p → snc-partner-name-missing',
    (partnerName) => {
      let thrown: unknown;
      try {
        new SncLogonProvider({ partnerName: partnerName as never, ...parts() });
      } catch (error) {
        thrown = error;
      }
      expect(configurationOf(thrown)).toEqual({
        case: 'snc-partner-name-missing',
        fields: ['partnerName'],
        reason: "SncLogonProvider needs partnerName — the system's SNC name",
      });
    },
  );
  it.each(['0', '4', '10', 'max', '', ' 9', 9])(
    'qop %p → snc-qop-invalid, allowed snc-qop, the value never echoed',
    (qop) => {
      let thrown: unknown;
      try {
        new SncLogonProvider({
          partnerName: 'p:CN=SID',
          qop: qop as never,
          ...parts(),
        });
      } catch (error) {
        thrown = error;
      }
      expect(configurationOf(thrown)).toEqual({
        case: 'snc-qop-invalid',
        fields: ['qop'],
        reason: 'SncLogonProvider: qop must be one of 1, 2, 3, 8, 9',
      });
      const error = readFailure(thrown, 'unfamiliar-error');
      expect(error.facts).toMatchObject({ allowed: 'snc-qop' });
      expect((thrown as Error).message).not.toContain(`'${String(qop)}'`);
    },
  );
});

describe('no other way in: the target answer is the provider’s own', () => {
  const MINTED: AuthOutcome = {
    ok: false,
    refusal: authError['logon-target']({
      wire: 'http',
      refused: 'logon-parameters',
    }),
  };
  const mintedRefusalObject = () =>
    MINTED.ok ? undefined : (MINTED.refusal as unknown);
  const target = (respond: () => unknown): ILogonTarget => ({
    tlsMaterial: respond as never,
    logonParameters: respond as never,
  });
  const prepared = async () => {
    const p = snc(machine());
    await p.prepare();
    return p;
  };
  it('returned refusal → that refusal', async () => {
    const out = await (await prepared()).establish(target(() => MINTED));
    expect(mintedRefusal(out)).toBe(mintedRefusalObject());
  });
  it('thrown refusal → that refusal', async () => {
    const out = await (await prepared()).establish(
      target(() => {
        throw mintedRefusalObject();
      }),
    );
    expect(mintedRefusal(out)).toBe(mintedRefusalObject());
  });
  it('garbage returned → the logon-target fallback', async () => {
    const out = await (await prepared()).establish(
      target(() => ({ ok: 'maybe', reason: MARKER })),
    );
    expect(mintedRefusal(out)).toMatchObject({
      kind: 'logon-target',
      facts: { wire: 'unknown', refused: 'logon-parameters' },
    });
    expect(JSON.stringify(out)).not.toContain(MARKER);
  });
  it('garbage thrown → unknown, handing over the SNC logon parameters', async () => {
    const out = await (await prepared()).establish(
      target(() => {
        throw new Error(MARKER);
      }),
    );
    expect(mintedRefusal(out)).toMatchObject({
      kind: 'unknown',
      facts: { operation: 'handing-over-snc-parameters' },
    });
    expect(JSON.stringify(out)).not.toContain(MARKER);
  });
  it('another copy’s refusal returned → rebuilt by this copy, never the target’s object', async () => {
    let foreign: unknown;
    jest.isolateModules(() => {
      const other = require('@mcp-abap-adt/auth-errors') as {
        authError: typeof authError;
        isMinted: typeof isMinted;
      };
      foreign = other.authError['logon-target']({
        wire: 'rfc',
        refused: 'logon-parameters',
      });
      expect(other.isMinted(foreign)).toBe(true);
    });
    expect(isMinted(foreign)).toBe(false);
    const out = await (await prepared()).establish(
      target(() => ({ ok: false, refusal: foreign })),
    );
    const error = mintedRefusal(out);
    expect(error).not.toBe(foreign);
    expect(error).toMatchObject({
      kind: 'logon-target',
      facts: { wire: 'rfc', refused: 'logon-parameters' },
      // Re-rendered by this copy: its own words for the same facts.
      reason: authError['logon-target']({
        wire: 'rfc',
        refused: 'logon-parameters',
      }).reason,
    });
  });
  it('Ok → the SNC parameters were written', async () => {
    const t = recordingTargets();
    await expect((await prepared()).establish(t.logonTarget)).resolves.toEqual({
      ok: true,
    });
    expect(t.logon.params).toHaveLength(1);
  });
});

describe('RF4 — library paths as they occur on users’ machines', () => {
  const CYRILLIC = 'C:\\Users\\Олексій\\AppData\\Local\\SAP\\sapcrypto.dll';
  const UNC = '\\\\server\\share\\sapcrypto.dll';
  const X86_DIR = 'C:\\Program Files (x86)\\SAP\\FrontEnd\\SecureLogin\\';
  const X86 = `${X86_DIR}lib\\sapcrypto.dll`;
  const BUNDLE =
    '/Applications/Secure Login Client.app/Contents/MacOS/lib/libsapcrypto.dylib';

  it('Windows: a non-ASCII profile, a UNC share and a registry value ending in spaces and CR/LF — each admitted unchanged, rendered', async () => {
    const error = mintedRefusal(
      await snc(
        fakeSystem({
          env: { SNC_LIB_64: CYRILLIC, SNC_LIB: UNC },
          registry: {
            'HKLM\\Software\\SAP\\SecureLogin\\InstallPath64': `${X86_DIR}   \r\n`,
          },
        }),
      ).prepare(),
    );
    expect(error.diagnostics).toEqual({
      candidatePaths: [CYRILLIC, UNC, X86],
    });
    const rendered = renderDiagnostics(error) ?? '';
    for (const path of [CYRILLIC, UNC, X86]) {
      expect(rendered).toContain(JSON.stringify(path));
    }
  });
  it('macOS: the bundle path, spaces included', async () => {
    const error = mintedRefusal(
      await snc(fakeSystem({ platform: 'darwin', arch: 'arm64' })).prepare(),
    );
    expect(error.diagnostics).toEqual({ candidatePaths: [BUNDLE] });
    expect(renderDiagnostics(error)).toBe(
      `candidates: macOS bundle ${JSON.stringify(BUNDLE)} (missing)`,
    );
  });
  it('a usable library at a non-ASCII path is the library diagnostic later', async () => {
    const p = snc(
      fakeSystem({
        env: { SNC_LIB_64: CYRILLIC },
        files: { [CYRILLIC]: peLibrary('x64') },
      }),
    );
    await expect(p.prepare()).resolves.toEqual({ ok: true });
    const t = recordingTargets();
    await p.establish(t.logonTarget);
    expect(t.logon.params[0]?.snc_lib).toBe(CYRILLIC);
    const error = mintedRefusal(
      await p.rejected({ at: 'logon', error: A2200019 }),
    );
    expect(renderDiagnostics(error)).toBe(
      `library: ${JSON.stringify(CYRILLIC)}`,
    );
  });
});

describe('cancelling prepare() (the user’s rule: no built-in timeout)', () => {
  /** A registry read that waits until its signal aborts, as reg.exe killed would. */
  const hangingRegistry =
    (seen: (AbortSignal | undefined)[]) =>
    (_key: string, _name: string, signal?: AbortSignal) => {
      seen.push(signal);
      return new Promise<string | undefined>((_resolve, reject) => {
        signal?.addEventListener('abort', () => reject(new Error(MARKER)), {
          once: true,
        });
      });
    };
  it('the config signal reaches the registry query; its abort ends prepare() aborted', async () => {
    const seen: (AbortSignal | undefined)[] = [];
    const controller = new AbortController();
    const p = snc(fakeSystem({ readRegistryValue: hangingRegistry(seen) }), {
      signal: controller.signal,
    });
    const outcome = p.prepare();
    await new Promise((resolve) => setImmediate(resolve));
    expect(seen).toHaveLength(1);
    expect(seen[0]?.aborted).toBe(false);
    controller.abort();
    const error = mintedRefusal(await outcome);
    expect(error).toMatchObject({
      kind: 'interactive-login',
      facts: { outcome: 'aborted' },
    });
    expect(seen[0]?.aborted).toBe(true);
    expect(JSON.stringify(error)).not.toContain(MARKER);
  });
  it('an attached party: the moment ends when every party has aborted', async () => {
    const seen: (AbortSignal | undefined)[] = [];
    const first = new AbortController();
    const second = new AbortController();
    const p = snc(fakeSystem({ readRegistryValue: hangingRegistry(seen) }), {
      signal: first.signal,
    });
    p.attach(second.signal);
    const outcome = p.prepare();
    await new Promise((resolve) => setImmediate(resolve));
    first.abort();
    await new Promise((resolve) => setImmediate(resolve));
    expect(seen[0]?.aborted).toBe(false);
    second.abort();
    expect(mintedRefusal(await outcome).facts).toEqual({ outcome: 'aborted' });
  });
  it('without a party, the query is given no signal: it waits for reg.exe', async () => {
    const reads: { key: string; name: string; signal?: AbortSignal }[] = [];
    await snc(
      fakeSystem({
        registry: REGISTRY,
        files: { [SLC]: peLibrary('x64') },
        registryReads: reads,
      }),
    ).prepare();
    expect(reads.length).toBeGreaterThan(0);
    for (const read of reads) expect(read).not.toHaveProperty('signal');
  });
  it('a probe gets the moment’s signal too; an abort during the probe ends prepare() aborted', async () => {
    const controller = new AbortController();
    const given: (AbortSignal | undefined)[] = [];
    const p = new SncLogonProvider({
      partnerName: 'p:CN=SID',
      locator: new DefaultSncLibraryLocator(machine(), KRB),
      probes: [
        {
          product: 'slow',
          appliesTo: async (_path, signal) => {
            given.push(signal);
            controller.abort();
            return false;
          },
        },
      ],
      signal: controller.signal,
    });
    const error = mintedRefusal(await p.prepare());
    expect(error.facts).toEqual({ outcome: 'aborted' });
    expect(given[0]).toBeDefined();
  });
});

describe('the moments a request goes through', () => {
  it('authorize writes nothing and answers Ok', async () => {
    const header = jest.fn();
    const cookies = jest.fn();
    const request: IRequestTarget = { header, cookies };
    await expect(snc(machine()).authorize(request)).resolves.toEqual({
      ok: true,
    });
    expect(header).not.toHaveBeenCalled();
    expect(cookies).not.toHaveBeenCalled();
  });
});

describe('review round 1', () => {
  it('the success debug line: fixed words, only admitted values as fields (\\n, U+202E)', async () => {
    const { logger, lines } = recordingLogger();
    const p = new SncLogonProvider({
      partnerName: 'p:CN=SID',
      locator: {
        locate: async () =>
          ({
            path: '/lib.so\n[ERROR] forged line\u202e',
            archs: ['x64\nforged-arch', 'x64'],
          }) as never,
      },
      probes: [{ product: 'P\nforged-product', appliesTo: async () => true }],
      logger,
    });
    await expect(p.prepare()).resolves.toEqual({ ok: true });
    const debug = lines.filter((l) => l.level === 'debug');
    expect(debug).toEqual([
      {
        level: 'debug',
        message: 'SNC library resolved',
        meta: { library: null, archs: ['x64'], product: 'a consumer probe' },
      },
    ]);
    expect(JSON.stringify(lines)).not.toMatch(/forged|\u202e/);
  });
  it('the debug line keeps an admitted path and names only the shipped product', async () => {
    const { logger, lines } = recordingLogger();
    await snc(machine(), { logger }).prepare();
    expect(lines.filter((l) => l.level === 'debug')).toEqual([
      {
        level: 'debug',
        message: 'SNC library resolved',
        meta: {
          library: SLC,
          archs: ['x64'],
          product: 'SAP Secure Login Client',
        },
      },
    ]);
  });
  it('an abort during a probe logs no "probe failed" line', async () => {
    const { logger, lines } = recordingLogger();
    const controller = new AbortController();
    const p = new SncLogonProvider({
      partnerName: 'p:CN=SID',
      locator: new DefaultSncLibraryLocator(machine(), KRB),
      probes: [
        {
          product: 'slow',
          appliesTo: async () => {
            controller.abort();
            throw new Error(MARKER);
          },
        },
      ],
      signal: controller.signal,
      logger,
    });
    expect(mintedRefusal(await p.prepare()).facts).toEqual({
      outcome: 'aborted',
    });
    expect(lines.some((l) => l.message.includes('probe failed'))).toBe(false);
  });
  const parts = () => ({
    locator: new DefaultSncLibraryLocator(machine()),
    probes: [],
  });
  /** A config whose `getterKey` is an accessor that throws — set after the spread, so building it runs no getter. */
  const construct = (config: object, getterKey?: string): unknown => {
    const full: Record<string, unknown> = {
      partnerName: 'p:CN=SID',
      ...parts(),
      ...config,
    };
    if (getterKey !== undefined) {
      delete full[getterKey];
      Object.defineProperty(full, getterKey, {
        enumerable: true,
        get() {
          throw new Error(MARKER);
        },
      });
    }
    try {
      new SncLogonProvider(full as never);
    } catch (error) {
      return error;
    }
    return undefined;
  };
  it.each([
    ['a number', { myName: 42 }, undefined],
    ['an object', { myName: { toString: () => MARKER } }, undefined],
    ['a throwing getter', {}, 'myName'],
  ])(
    'myName as %s → configuration naming myName, never a TypeError',
    (_, config, getterKey) => {
      const thrown = construct(config, getterKey);
      expect(configurationOf(thrown)).toEqual({
        case: 'required-fields-missing',
        fields: ['myName'],
        reason: 'required configuration is missing: myName',
      });
      expect(JSON.stringify(thrown)).not.toContain(MARKER);
    },
  );
  it('qop behind a throwing getter → snc-qop-invalid, never the getter’s error', () => {
    const thrown = construct({}, 'qop');
    expect(configurationOf(thrown).case).toBe('snc-qop-invalid');
    expect(JSON.stringify(thrown)).not.toContain(MARKER);
  });
  it('partnerName behind a getter is not read: snc-partner-name-missing', () => {
    const thrown = construct({}, 'partnerName');
    expect(configurationOf(thrown).case).toBe('snc-partner-name-missing');
    expect(JSON.stringify(thrown)).not.toContain(MARKER);
  });
  it('a valid myName and an absent qop still construct', () => {
    expect(construct({ myName: ' p:CN=ME ' })).toBeUndefined();
    expect(construct({ qop: undefined })).toBeUndefined();
  });
});
