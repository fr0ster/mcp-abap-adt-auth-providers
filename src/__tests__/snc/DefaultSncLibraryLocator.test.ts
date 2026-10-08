import { describe, expect, it } from '@jest/globals';
import { isAuthProviderFailure, readFailure } from '@mcp-abap-adt/auth-errors';
import { DefaultSncLibraryLocator } from '../../snc/DefaultSncLibraryLocator';
import { fakeSystem, peLibrary } from './fakeSystem';

/** What the shipped locator throws, as its minted error. */
function notFound(thrown: unknown) {
  expect(isAuthProviderFailure(thrown)).toBe(true);
  const error = readFailure(thrown, 'resolving-snc-library');
  expect(error.kind).toBe('snc');
  return error as unknown as {
    facts: Record<string, unknown>;
    diagnostics?: { candidatePaths?: (string | null)[] };
  };
}

const X64 = 'C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\lib\\sapcrypto.dll';
const X86 =
  'C:\\Program Files (x86)\\SAP\\FrontEnd\\SecureLogin\\lib\\sapcrypto.dll';
const REGISTRY = {
  'HKLM\\Software\\SAP\\SecureLogin\\InstallPath64':
    'C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\',
  'HKLM\\Software\\SAP\\SecureLogin\\InstallPath32':
    'C:\\Program Files (x86)\\SAP\\FrontEnd\\SecureLogin\\',
};
const FILES = { [X64]: peLibrary('x64'), [X86]: peLibrary('ia32') };
const DYLIB =
  '/Applications/Secure Login Client.app/Contents/MacOS/lib/libsapcrypto.dylib';
function fat64(cputypes: number[]): Buffer {
  const b = Buffer.alloc(8 + cputypes.length * 32);
  b.writeUInt32BE(0xcafebabf, 0);
  b.writeUInt32BE(cputypes.length, 4);
  cputypes.forEach((c, i) => {
    b.writeUInt32BE(c, 8 + i * 32);
  });
  return b;
}

describe('explicit sncLib', () => {
  it('returned when usable', async () => {
    await expect(
      new DefaultSncLibraryLocator(fakeSystem({ files: FILES }), X64).locate(),
    ).resolves.toEqual({ path: X64, archs: ['x64'] });
  });
  // The
  // architectures are facts, the path a diagnostic.
  it('wrong architecture fails, nothing else tried', async () => {
    const thrown = await new DefaultSncLibraryLocator(
      fakeSystem({ files: FILES, registry: REGISTRY }),
      X86,
    )
      .locate()
      .catch((e: unknown) => e);
    const error = notFound(thrown);
    expect(error.facts).toEqual({
      problem: 'library-not-found',
      searched: true,
      candidates: [
        { source: 'sncLib', reason: 'wrong architecture', archs: ['ia32'] },
      ],
      processArch: 'x64',
    });
    expect(error.diagnostics).toEqual({ candidatePaths: [X86] });
  });
  it('missing file fails naming sncLib, the path a diagnostic', async () => {
    const thrown = await new DefaultSncLibraryLocator(
      fakeSystem(),
      'C:\\nope.dll',
    )
      .locate()
      .catch((e: unknown) => e);
    const error = notFound(thrown);
    expect(error.facts.candidates).toEqual([
      { source: 'sncLib', reason: 'missing' },
    ]);
    expect(error.diagnostics).toEqual({ candidatePaths: ['C:\\nope.dll'] });
    expect((thrown as Error).message).not.toContain('nope');
  });
});

describe('automatic discovery', () => {
  it('the measured mix: no SNC_LIB_64, x86 SNC_LIB, x64 in the registry → the registry library', async () => {
    await expect(
      new DefaultSncLibraryLocator(
        fakeSystem({ env: { SNC_LIB: X86 }, files: FILES, registry: REGISTRY }),
      ).locate(),
    ).resolves.toEqual({ path: X64, archs: ['x64'] });
  });
  it('prefers SNC_LIB_64 in a 64-bit process', async () => {
    const other = 'D:\\snc\\sapcrypto.dll';
    await expect(
      new DefaultSncLibraryLocator(
        fakeSystem({
          env: { SNC_LIB_64: other, SNC_LIB: X86 },
          files: { ...FILES, [other]: peLibrary('x64') },
          registry: REGISTRY,
        }),
      ).locate(),
    ).resolves.toMatchObject({ path: other });
  });
  it('ignores SNC_LIB_64 in a 32-bit process and takes InstallPath32', async () => {
    await expect(
      new DefaultSncLibraryLocator(
        fakeSystem({
          arch: 'ia32',
          env: { SNC_LIB_64: X64 },
          files: FILES,
          registry: REGISTRY,
        }),
      ).locate(),
    ).resolves.toEqual({ path: X86, archs: ['ia32'] });
  });
  it('empty or whitespace variables count as unset', async () => {
    await expect(
      new DefaultSncLibraryLocator(
        fakeSystem({
          env: { SNC_LIB_64: '  ', SNC_LIB: '' },
          files: FILES,
          registry: REGISTRY,
        }),
      ).locate(),
    ).resolves.toMatchObject({ path: X64 });
  });
  it('an absent registry value is skipped', async () => {
    const other = 'D:\\snc\\sapcrypto.dll';
    await expect(
      new DefaultSncLibraryLocator(
        fakeSystem({
          env: { SNC_LIB: other },
          files: { [other]: peLibrary('x64') },
        }),
      ).locate(),
    ).resolves.toMatchObject({ path: other });
  });
  it('macOS: FAT_MAGIC_64 holding the process architecture is accepted', async () => {
    await expect(
      new DefaultSncLibraryLocator(
        fakeSystem({
          platform: 'darwin',
          arch: 'arm64',
          files: { [DYLIB]: fat64([0x01000007, 0x0100000c]) },
        }),
      ).locate(),
    ).resolves.toEqual({ path: DYLIB, archs: ['x64', 'arm64'] });
  });
  it('macOS: FAT_MAGIC_64 without it is skipped, naming what it holds', async () => {
    const thrown = await new DefaultSncLibraryLocator(
      fakeSystem({
        platform: 'darwin',
        arch: 'arm64',
        files: { [DYLIB]: fat64([0x01000007]) },
      }),
    )
      .locate()
      .catch((e: unknown) => e);
    const error = notFound(thrown);
    expect(error.facts.candidates).toEqual([
      { source: 'macOS bundle', reason: 'wrong architecture', archs: ['x64'] },
    ]);
    expect(error.facts.processArch).toBe('arm64');
  });
  it('nothing usable: one error listing every candidate, paths aligned', async () => {
    const thrown = await new DefaultSncLibraryLocator(
      fakeSystem({
        env: { SNC_LIB: X86 },
        files: { [X86]: peLibrary('ia32') },
      }),
    )
      .locate()
      .catch((e: unknown) => e);
    const error = notFound(thrown);
    expect(error.facts.candidates).toEqual([
      { source: 'SNC_LIB', reason: 'wrong architecture', archs: ['ia32'] },
    ]);
    expect(error.diagnostics).toEqual({ candidatePaths: [X86] });
  });
  it('no candidate at all says so', async () => {
    const thrown = await new DefaultSncLibraryLocator(
      fakeSystem({ platform: 'linux' }),
    )
      .locate()
      .catch((e: unknown) => e);
    const error = notFound(thrown);
    expect(error.facts).toMatchObject({ searched: true, candidates: [] });
    expect((thrown as Error).message).toContain('no candidate');
  });
  // A registry value ending in spaces and CR/LF reaches candidatePaths
  // trimmed — untrimmed, LocalPath would drop it to null.
  it('RF4: the registry value is trimmed before it becomes a candidate path', async () => {
    const thrown = await new DefaultSncLibraryLocator(
      fakeSystem({
        registry: {
          'HKLM\\Software\\SAP\\SecureLogin\\InstallPath64':
            'C:\\Program Files (x86)\\SAP\\FrontEnd\\SecureLogin\\  \r\n',
        },
      }),
    )
      .locate()
      .catch((e: unknown) => e);
    expect(notFound(thrown).diagnostics).toEqual({ candidatePaths: [X86] });
  });
  it('a path no LocalPath admits is null, indices aligned', async () => {
    const BAD = 'C:\\evil\u202e.dll';
    const thrown = await new DefaultSncLibraryLocator(
      fakeSystem({ env: { SNC_LIB_64: BAD, SNC_LIB: X86 } }),
    )
      .locate()
      .catch((e: unknown) => e);
    const error = notFound(thrown);
    expect(error.facts.candidates).toEqual([
      { source: 'SNC_LIB_64', reason: 'missing' },
      { source: 'SNC_LIB', reason: 'missing' },
    ]);
    expect(error.diagnostics).toEqual({ candidatePaths: [null, X86] });
  });
  it('passes its signal to each registry read', async () => {
    const reads: { key: string; name: string; signal?: AbortSignal }[] = [];
    const controller = new AbortController();
    await new DefaultSncLibraryLocator(
      fakeSystem({ files: FILES, registry: REGISTRY, registryReads: reads }),
    ).locate(controller.signal);
    expect(reads).toEqual([
      {
        key: 'HKLM\\Software\\SAP\\SecureLogin',
        name: 'InstallPath64',
        signal: controller.signal,
      },
    ]);
  });
});
