/**
 * The refusals of `SncLogonProvider`, with the relay matrix and the
 * fixtures — each refusal a
 * minted `snc` (or `not-prepared`, `unknown`, `configuration`) error, its
 * words verbatim, every path a diagnostic and never a word.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join, sep } from 'node:path';
import { describe, it, mock } from 'node:test';
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
import {
  cases,
  caseTitle,
  contains,
  hasProperty,
  matchObject,
  notContains,
} from '../helpers/expectations';
import { configurationOf, mintedRefusal } from '../helpers/minted';
import { PACKAGE_ROOT } from '../helpers/packagePaths';
import { recordingTargets } from '../helpers/targets';
import { fakeSystem, peLibrary } from './fakeSystem';

/**
 * A second, separate copy of auth-errors, as another package's would be:
 * its modules are loaded afresh through `require.cache`, and the cache is
 * then given back the copy every other import of this file holds.
 */
function anotherCopyOfAuthErrors(): typeof import('@mcp-abap-adt/auth-errors') {
  const root = `${dirname(require.resolve('@mcp-abap-adt/auth-errors/package.json'))}${sep}`;
  const held = Object.entries(require.cache).filter(([path]) =>
    path.startsWith(root),
  );
  for (const [path] of held) delete require.cache[path];
  try {
    return require('@mcp-abap-adt/auth-errors');
  } finally {
    for (const path of Object.keys(require.cache)) {
      if (path.startsWith(root)) delete require.cache[path];
    }
    for (const [path, module] of held) require.cache[path] = module;
  }
}

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
    matchObject(error, {
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
    assert.equal(
      error.reason,
      'the SNC library has no credential to present (A2200019)',
    );
    assert.equal(
      error.hint,
      'make sure the SNC product behind the SNC library is logged on',
    );
    assert.deepEqual(error.facts, {
      problem: 'no-credential',
      secureLoginClient: false,
      libraryArchs: ['x64'],
    });
    assert.equal(renderDiagnostics(error), `library: ${JSON.stringify(KRB)}`);
    notContains(`${error.reason} ${error.hint}`, 'gsskrb5');
  });
  it('before prepare(): no library, no diagnostics', async () => {
    const error = mintedRefusal(
      await snc(machine()).rejected({ at: 'logon', error: A2200019 }),
    );
    assert.equal(
      error.hint,
      'make sure the SNC product behind the SNC library is logged on',
    );
    assert.equal(hasProperty(error, 'diagnostics'), false);
  });
  it('found in a string and in an Error, never copied', async () => {
    const p = snc(machine());
    await p.prepare();
    for (const error of [
      `${MARKER} GSS-API(min): A2200019:Operation aborted`,
      new Error(`${MARKER} A2200019`),
    ]) {
      const outcome = await p.rejected({ at: 'logon', error });
      assert.equal(mintedRefusal(outcome).variant, 'no-credential');
      notContains(JSON.stringify(outcome), MARKER);
    }
  });
});

describe('SNCERR_INIT: the library could not be initialised', () => {
  for (const [caseIndex, caseRow] of [
    'SNCERR_INIT',
    'sncerr_init while loading',
    'GSSAPI LIBRARY INVALID/MISSING',
  ].entries()) {
    const text = caseRow;
    it(
      caseTitle(
        '%s → the architectures as a fact, the path a diagnostic',
        caseRow,
        caseIndex,
      ),
      async () => {
        const p = snc(machine());
        await p.prepare();
        const error = mintedRefusal(
          await p.rejected({ at: 'logon', error: new Error(text) }),
        );
        matchObject(error, {
          kind: 'snc',
          facts: { problem: 'library-init-failed', libraryArchs: ['x64'] },
          reason:
            'the RFC SDK could not initialise the SNC library (x64) as its SNC library (SNCERR_INIT)',
          diagnostics: { library: SLC },
        });
        assert.equal(hasProperty(error, 'hint'), false);
      },
    );
  }
  it('a custom locator with no archs: the words without them', async () => {
    const p = new SncLogonProvider({
      partnerName: 'p:CN=SID',
      locator: { locate: async () => ({ path: KRB, archs: [] }) },
      probes: [],
    });
    assert.deepEqual(await p.prepare(), { ok: true });
    const error = mintedRefusal(
      await p.rejected({ at: 'logon', error: 'SNCERR_INIT' }),
    );
    assert.equal(
      error.reason,
      'the RFC SDK could not initialise the SNC library as its SNC library (SNCERR_INIT)',
    );
    assert.deepEqual(error.diagnostics, { library: KRB });
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
    matchObject(error, {
      kind: 'snc',
      facts: { problem: 'logon-refused', rfcKey: 'RFC_LOGON_FAILURE' },
      reason: 'SNC logon refused (RFC_LOGON_FAILURE)',
    });
    notContains(JSON.stringify(error), MARKER);
  });
  for (const [caseIndex, caseRow] of cases([
    ['an unlisted key', { key: 'SECRET_KEY', message: 'x' }],
    ['an Error', new Error(MARKER)],
    ['nothing', undefined],
  ]).entries()) {
    const [_, error] = caseRow;
    it(caseTitle('%s → the words alone', caseRow, caseIndex), async () => {
      const p = snc(machine());
      await p.prepare();
      const refused = mintedRefusal(await p.rejected({ at: 'logon', error }));
      assert.deepEqual(refused.facts, { problem: 'logon-refused' });
      assert.equal(refused.reason, 'SNC logon refused');
      notContains(JSON.stringify(refused), MARKER);
    });
  }
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
    matchObject(error, {
      kind: 'snc',
      facts: { problem: 'library-not-found' },
      reason: 'no usable SNC library was found',
      hint: HINT,
    });
    assert.deepEqual(error.facts, { problem: 'library-not-found' });
    notContains(JSON.stringify(outcome), MARKER);
  });
  it('an answer whose path getter throws → the locator failed: the fixed sentence', async () => {
    const p = new SncLogonProvider({
      partnerName: 'p:CN=SID',
      locator: {
        locate: async () => ({
          get path(): string {
            throw new Error(MARKER);
          },
          archs: [],
        }),
      },
      probes: [],
    });
    const outcome = await p.prepare();
    const error = mintedRefusal(outcome);
    matchObject(error, {
      kind: 'snc',
      reason: 'no usable SNC library was found',
      hint: HINT,
    });
    assert.deepEqual(error.facts, { problem: 'library-not-found' });
    notContains(JSON.stringify(outcome), MARKER);
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
    assert.deepEqual(error.facts, { problem: 'library-not-found' });
    notContains(JSON.stringify(error), MARKER);
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
    matchObject(error, {
      kind: 'snc',
      variant: 'library-not-found',
      reason:
        'no usable SNC library was found: SNC_LIB_64 (not a library); SNC_LIB (wrong architecture); registry (missing)',
      hint: HINT,
    });
    assert.deepEqual(error.facts, {
      problem: 'library-not-found',
      searched: true,
      candidates: [
        { source: 'SNC_LIB_64', reason: 'not a library' },
        { source: 'SNC_LIB', reason: 'wrong architecture', archs: ['ia32'] },
        { source: 'registry', reason: 'missing' },
      ],
      processArch: 'x64',
    });
    assert.deepEqual(error.diagnostics, { candidatePaths: [TXT, X86, SLC] });
    assert.equal(
      renderDiagnostics(error),
      `candidates: SNC_LIB_64 ${JSON.stringify(TXT)} (not a library); SNC_LIB ${JSON.stringify(X86)} (wrong architecture); registry ${JSON.stringify(SLC)} (missing)`,
    );
  });
  it('explicit sncLib: that one candidate, its path a diagnostic', async () => {
    const NOPE = 'C:\\nope\\sapcrypto.dll';
    const error = mintedRefusal(
      await snc(machine(), { sncLib: NOPE }).prepare(),
    );
    assert.equal(
      error.reason,
      'no usable SNC library was found: sncLib (missing)',
    );
    assert.equal(error.hint, HINT);
    assert.deepEqual(error.diagnostics, { candidatePaths: [NOPE] });
  });
  it('no candidate: verbatim, candidates empty, no diagnostics', async () => {
    const error = mintedRefusal(
      await snc(fakeSystem({ platform: 'linux' })).prepare(),
    );
    matchObject(error, {
      reason:
        'no usable SNC library was found: no candidate (SNC_LIB_64 and SNC_LIB are unset and no Secure Login Client installation was found)',
      hint: HINT,
    });
    assert.deepEqual(error.facts, {
      problem: 'library-not-found',
      searched: true,
      candidates: [],
      processArch: 'x64',
    });
    assert.equal(hasProperty(error, 'diagnostics'), false);
  });
  it('docs/passwordless-sso.md quotes the A2200019 reason as it is', () => {
    const doc = readFileSync(
      join(PACKAGE_ROOT, 'docs', 'passwordless-sso.md'),
      'utf8',
    ).replace(/\s+/g, ' ');
    contains(doc, '"the SNC library has no credential to present (A2200019)"');
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
    assert.equal(isAuthProviderFailure(thrown), true);
    const error = readFailure(thrown, 'resolving-snc-library');
    assert.equal(isMinted(error), true);
    assert.deepEqual(error.facts, {
      problem: 'library-not-found',
      searched: true,
      candidates: [
        { source: 'SNC_LIB_64', reason: 'wrong architecture', archs: ['x64'] },
      ],
      processArch: 'arm64',
    });
    assert.deepEqual(error.diagnostics, { candidatePaths: [X86] });
    // The message is the words: no path, no detail of the header.
    assert.equal(
      (thrown as Error).message,
      `no usable SNC library was found: SNC_LIB_64 (wrong architecture) — ${HINT}`,
    );
  });
});

describe('the locator returned no path', () => {
  for (const [caseIndex, caseRow] of cases([
    ['blank', { path: '  ', archs: ['x64'] }],
  ]).entries()) {
    const [_, found] = caseRow;
    it(caseTitle('%s → verbatim', caseRow, caseIndex), async () => {
      const p = new SncLogonProvider({
        partnerName: 'p:CN=SID',
        locator: { locate: async () => found as never },
        probes: [],
      });
      const error = mintedRefusal(await p.prepare());
      matchObject(error, {
        kind: 'snc',
        facts: { problem: 'locator-returned-no-path' },
        reason: 'no usable SNC library was found: the locator returned no path',
        hint: HINT,
      });
    });
  }
});

describe('establish before prepare', () => {
  it('not-prepared, provider snc, verbatim', async () => {
    const t = recordingTargets();
    const error = mintedRefusal(await snc(machine()).establish(t.logonTarget));
    matchObject(error, {
      kind: 'not-prepared',
      facts: { provider: 'snc' },
      reason: 'the SNC provider is not prepared',
      hint: 'connect() prepares it first',
    });
    assert.deepEqual(t.logon.params, []);
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
  for (const [caseIndex, caseRow] of moments.entries()) {
    const [words, call] = caseRow;
    it(caseTitle('grant() throws → %s', caseRow, caseIndex), async () => {
      const outcome = await call(new GrantThrows(config(machine())));
      const error = mintedRefusal(outcome);
      assert.equal(error.kind, 'unknown');
      assert.equal(
        error.reason,
        `the SNC provider failed while ${words} (unknown error)`,
      );
      notContains(JSON.stringify(outcome), MARKER);
    });
  }
  it('a moments getter on a subclass changes nothing', async () => {
    const p = new MomentsGetter(config(machine()));
    assert.deepEqual(await p.prepare(), { ok: true });
    assert.deepEqual(await p.establish(recordingTargets().logonTarget), {
      ok: true,
    });
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
    assert.equal(outcome.ok, false);
    notContains(JSON.stringify(outcome), MARKER);
  });
});

describe('the log lines', () => {
  it('SNC library not found: <reason>, the paths as a field only', async () => {
    const NOPE = 'C:\\nope\\sapcrypto.dll';
    const { logger, lines } = recordingLogger();
    await snc(machine(), { sncLib: NOPE, logger }).prepare();
    const line = lines.find((l) => l.message.startsWith('SNC library not'));
    assert.notEqual(line, undefined);
    assert.equal(line?.level, 'warn');
    assert.equal(
      line?.message,
      'SNC library not found: no usable SNC library was found: sncLib (missing)',
    );
    assert.deepEqual(line?.meta, {
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
    assert.deepEqual(await p.prepare(), { ok: true });
    const line = lines.find((l) => l.message.startsWith('an SNC product'));
    assert.equal(line?.level, 'warn');
    assert.equal(
      line?.message,
      'an SNC product probe failed: the probe failed (unknown error)',
    );
    notContains(JSON.stringify(lines), MARKER);
  });
});

describe('construction', () => {
  const parts = () => ({
    locator: new DefaultSncLibraryLocator(machine()),
    probes: [],
  });
  for (const [caseIndex, caseRow] of [' ', ''].entries()) {
    const partnerName = caseRow;
    it(
      caseTitle(
        'partnerName %p → snc-partner-name-missing',
        caseRow,
        caseIndex,
      ),
      () => {
        let thrown: unknown;
        try {
          new SncLogonProvider({ partnerName, ...parts() });
        } catch (error) {
          thrown = error;
        }
        assert.deepEqual(configurationOf(thrown), {
          case: 'snc-partner-name-missing',
          fields: ['partnerName'],
          reason: "SncLogonProvider needs partnerName — the system's SNC name",
        });
      },
    );
  }
  for (const [caseIndex, caseRow] of [
    '0',
    '4',
    '10',
    'max',
    '',
    ' 9',
  ].entries()) {
    const qop = caseRow;
    it(
      caseTitle(
        'qop %p → snc-qop-invalid, allowed snc-qop, the value never echoed',
        caseRow,
        caseIndex,
      ),
      () => {
        let thrown: unknown;
        try {
          new SncLogonProvider({
            partnerName: 'p:CN=SID',
            qop,
            ...parts(),
          });
        } catch (error) {
          thrown = error;
        }
        assert.deepEqual(configurationOf(thrown), {
          case: 'snc-qop-invalid',
          fields: ['qop'],
          reason: 'SncLogonProvider: qop must be one of 1, 2, 3, 8, 9',
        });
        const error = readFailure(thrown, 'unfamiliar-error');
        matchObject(error.facts, { allowed: 'snc-qop' });
        notContains((thrown as Error).message, `'${String(qop)}'`);
      },
    );
  }
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
    assert.equal(mintedRefusal(out), mintedRefusalObject());
  });
  it('thrown refusal → that refusal', async () => {
    const out = await (await prepared()).establish(
      target(() => {
        throw mintedRefusalObject();
      }),
    );
    assert.equal(mintedRefusal(out), mintedRefusalObject());
  });
  it('garbage returned → the logon-target fallback', async () => {
    const out = await (await prepared()).establish(
      target(() => ({ ok: 'maybe', reason: MARKER })),
    );
    matchObject(mintedRefusal(out), {
      kind: 'logon-target',
      facts: { wire: 'unknown', refused: 'logon-parameters' },
    });
    notContains(JSON.stringify(out), MARKER);
  });
  it('garbage thrown → unknown, handing over the SNC logon parameters', async () => {
    const out = await (await prepared()).establish(
      target(() => {
        throw new Error(MARKER);
      }),
    );
    matchObject(mintedRefusal(out), {
      kind: 'unknown',
      facts: { operation: 'handing-over-snc-parameters' },
    });
    notContains(JSON.stringify(out), MARKER);
  });
  it('another copy’s refusal returned → rebuilt by this copy, never the target’s object', async () => {
    const other = anotherCopyOfAuthErrors();
    const foreign: unknown = other.authError['logon-target']({
      wire: 'rfc',
      refused: 'logon-parameters',
    });
    assert.equal(other.isMinted(foreign), true);
    assert.equal(isMinted(foreign), false);
    const out = await (await prepared()).establish(
      target(() => ({ ok: false, refusal: foreign })),
    );
    const error = mintedRefusal(out);
    assert.notEqual(error, foreign);
    matchObject(error, {
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
    assert.deepEqual(await (await prepared()).establish(t.logonTarget), {
      ok: true,
    });
    assert.equal(t.logon.params.length, 1);
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
    assert.deepEqual(error.diagnostics, {
      candidatePaths: [CYRILLIC, UNC, X86],
    });
    const rendered = renderDiagnostics(error) ?? '';
    for (const path of [CYRILLIC, UNC, X86]) {
      contains(rendered, JSON.stringify(path));
    }
  });
  it('macOS: the bundle path, spaces included', async () => {
    const error = mintedRefusal(
      await snc(fakeSystem({ platform: 'darwin', arch: 'arm64' })).prepare(),
    );
    assert.deepEqual(error.diagnostics, { candidatePaths: [BUNDLE] });
    assert.equal(
      renderDiagnostics(error),
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
    assert.deepEqual(await p.prepare(), { ok: true });
    const t = recordingTargets();
    await p.establish(t.logonTarget);
    assert.equal(t.logon.params[0]?.snc_lib, CYRILLIC);
    const error = mintedRefusal(
      await p.rejected({ at: 'logon', error: A2200019 }),
    );
    assert.equal(
      renderDiagnostics(error),
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
    assert.equal(seen.length, 1);
    assert.equal(seen[0]?.aborted, false);
    controller.abort();
    const error = mintedRefusal(await outcome);
    matchObject(error, {
      kind: 'interactive-login',
      facts: { outcome: 'aborted' },
    });
    assert.equal(seen[0]?.aborted, true);
    notContains(JSON.stringify(error), MARKER);
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
    assert.equal(seen[0]?.aborted, false);
    second.abort();
    assert.deepEqual(mintedRefusal(await outcome).facts, {
      outcome: 'aborted',
    });
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
    assert.ok(reads.length > 0, `${reads.length} > ${0}`);
    for (const read of reads) assert.equal(hasProperty(read, 'signal'), false);
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
    assert.deepEqual(error.facts, { outcome: 'aborted' });
    assert.notEqual(given[0], undefined);
  });
});

describe('the moments a request goes through', () => {
  it('authorize writes nothing and answers Ok', async () => {
    const header = mock.fn();
    const cookies = mock.fn();
    const request: IRequestTarget = { header, cookies };
    assert.deepEqual(await snc(machine()).authorize(request), {
      ok: true,
    });
    assert.equal(header.mock.callCount(), 0);
    assert.equal(cookies.mock.callCount(), 0);
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
    assert.deepEqual(await p.prepare(), { ok: true });
    const debug = lines.filter((l) => l.level === 'debug');
    assert.deepEqual(debug, [
      {
        level: 'debug',
        message: 'SNC library resolved',
        meta: { library: null, archs: ['x64'], product: 'a consumer probe' },
      },
    ]);
    assert.doesNotMatch(JSON.stringify(lines), /forged|\u202e/);
  });
  it('the debug line keeps an admitted path and names only the shipped product', async () => {
    const { logger, lines } = recordingLogger();
    await snc(machine(), { logger }).prepare();
    assert.deepEqual(
      lines.filter((l) => l.level === 'debug'),
      [
        {
          level: 'debug',
          message: 'SNC library resolved',
          meta: {
            library: SLC,
            archs: ['x64'],
            product: 'SAP Secure Login Client',
          },
        },
      ],
    );
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
    assert.deepEqual(mintedRefusal(await p.prepare()).facts, {
      outcome: 'aborted',
    });
    assert.equal(
      lines.some((l) => l.message.includes('probe failed')),
      false,
    );
  });
  const parts = () => ({
    locator: new DefaultSncLibraryLocator(machine()),
    probes: [],
  });
  const construct = (config: object): unknown => {
    const full: Record<string, unknown> = {
      partnerName: 'p:CN=SID',
      ...parts(),
      ...config,
    };
    try {
      new SncLogonProvider(full as never);
    } catch (error) {
      return error;
    }
    return undefined;
  };
  it('a valid myName and an absent qop still construct', () => {
    assert.equal(construct({ myName: ' p:CN=ME ' }), undefined);
    assert.equal(construct({ qop: undefined }), undefined);
  });
});
