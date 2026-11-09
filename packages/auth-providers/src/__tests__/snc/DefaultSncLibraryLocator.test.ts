import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { isAuthProviderFailure, readFailure } from '@mcp-abap-adt/auth-errors';
import { DefaultSncLibraryLocator } from '../../snc/DefaultSncLibraryLocator';
import { contains, matchObject, notContains } from '../helpers/expectations';
import { fakeSystem, peLibrary } from './fakeSystem';

/** What the shipped locator throws, as its minted error. */
function notFound(thrown: unknown) {
  assert.equal(isAuthProviderFailure(thrown), true);
  const error = readFailure(thrown, 'resolving-snc-library');
  assert.equal(error.kind, 'snc');
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
    assert.deepEqual(
      await new DefaultSncLibraryLocator(
        fakeSystem({ files: FILES }),
        X64,
      ).locate(),
      { path: X64, archs: ['x64'] },
    );
  });
  // The architectures are facts, the path a diagnostic.
  it('wrong architecture fails, nothing else tried', async () => {
    const thrown = await new DefaultSncLibraryLocator(
      fakeSystem({ files: FILES, registry: REGISTRY }),
      X86,
    )
      .locate()
      .catch((e: unknown) => e);
    const error = notFound(thrown);
    assert.deepEqual(error.facts, {
      problem: 'library-not-found',
      searched: true,
      candidates: [
        { source: 'sncLib', reason: 'wrong architecture', archs: ['ia32'] },
      ],
      processArch: 'x64',
    });
    assert.deepEqual(error.diagnostics, { candidatePaths: [X86] });
  });
  it('missing file fails naming sncLib, the path a diagnostic', async () => {
    const thrown = await new DefaultSncLibraryLocator(
      fakeSystem(),
      'C:\\nope.dll',
    )
      .locate()
      .catch((e: unknown) => e);
    const error = notFound(thrown);
    assert.deepEqual(error.facts.candidates, [
      { source: 'sncLib', reason: 'missing' },
    ]);
    assert.deepEqual(error.diagnostics, { candidatePaths: ['C:\\nope.dll'] });
    notContains((thrown as Error).message, 'nope');
  });
});

describe('automatic discovery', () => {
  it('the measured mix: no SNC_LIB_64, x86 SNC_LIB, x64 in the registry → the registry library', async () => {
    assert.deepEqual(
      await new DefaultSncLibraryLocator(
        fakeSystem({ env: { SNC_LIB: X86 }, files: FILES, registry: REGISTRY }),
      ).locate(),
      { path: X64, archs: ['x64'] },
    );
  });
  it('prefers SNC_LIB_64 in a 64-bit process', async () => {
    const other = 'D:\\snc\\sapcrypto.dll';
    matchObject(
      await new DefaultSncLibraryLocator(
        fakeSystem({
          env: { SNC_LIB_64: other, SNC_LIB: X86 },
          files: { ...FILES, [other]: peLibrary('x64') },
          registry: REGISTRY,
        }),
      ).locate(),
      { path: other },
    );
  });
  it('ignores SNC_LIB_64 in a 32-bit process and takes InstallPath32', async () => {
    assert.deepEqual(
      await new DefaultSncLibraryLocator(
        fakeSystem({
          arch: 'ia32',
          env: { SNC_LIB_64: X64 },
          files: FILES,
          registry: REGISTRY,
        }),
      ).locate(),
      { path: X86, archs: ['ia32'] },
    );
  });
  it('empty or whitespace variables count as unset', async () => {
    matchObject(
      await new DefaultSncLibraryLocator(
        fakeSystem({
          env: { SNC_LIB_64: '  ', SNC_LIB: '' },
          files: FILES,
          registry: REGISTRY,
        }),
      ).locate(),
      { path: X64 },
    );
  });
  it('an absent registry value is skipped', async () => {
    const other = 'D:\\snc\\sapcrypto.dll';
    matchObject(
      await new DefaultSncLibraryLocator(
        fakeSystem({
          env: { SNC_LIB: other },
          files: { [other]: peLibrary('x64') },
        }),
      ).locate(),
      { path: other },
    );
  });
  it('macOS: FAT_MAGIC_64 holding the process architecture is accepted', async () => {
    assert.deepEqual(
      await new DefaultSncLibraryLocator(
        fakeSystem({
          platform: 'darwin',
          arch: 'arm64',
          files: { [DYLIB]: fat64([0x01000007, 0x0100000c]) },
        }),
      ).locate(),
      { path: DYLIB, archs: ['x64', 'arm64'] },
    );
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
    assert.deepEqual(error.facts.candidates, [
      { source: 'macOS bundle', reason: 'wrong architecture', archs: ['x64'] },
    ]);
    assert.equal(error.facts.processArch, 'arm64');
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
    assert.deepEqual(error.facts.candidates, [
      { source: 'SNC_LIB', reason: 'wrong architecture', archs: ['ia32'] },
    ]);
    assert.deepEqual(error.diagnostics, { candidatePaths: [X86] });
  });
  it('no candidate at all says so', async () => {
    const thrown = await new DefaultSncLibraryLocator(
      fakeSystem({ platform: 'linux' }),
    )
      .locate()
      .catch((e: unknown) => e);
    const error = notFound(thrown);
    matchObject(error.facts, { searched: true, candidates: [] });
    contains((thrown as Error).message, 'no candidate');
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
    assert.deepEqual(notFound(thrown).diagnostics, { candidatePaths: [X86] });
  });
  it('a path no LocalPath admits is null, indices aligned', async () => {
    const BAD = 'C:\\evil\u202e.dll';
    const thrown = await new DefaultSncLibraryLocator(
      fakeSystem({ env: { SNC_LIB_64: BAD, SNC_LIB: X86 } }),
    )
      .locate()
      .catch((e: unknown) => e);
    const error = notFound(thrown);
    assert.deepEqual(error.facts.candidates, [
      { source: 'SNC_LIB_64', reason: 'missing' },
      { source: 'SNC_LIB', reason: 'missing' },
    ]);
    assert.deepEqual(error.diagnostics, { candidatePaths: [null, X86] });
  });
  it('passes its signal to each registry read', async () => {
    const reads: { key: string; name: string; signal?: AbortSignal }[] = [];
    const controller = new AbortController();
    await new DefaultSncLibraryLocator(
      fakeSystem({ files: FILES, registry: REGISTRY, registryReads: reads }),
    ).locate(controller.signal);
    assert.deepEqual(reads, [
      {
        key: 'HKLM\\Software\\SAP\\SecureLogin',
        name: 'InstallPath64',
        signal: controller.signal,
      },
    ]);
  });
});
