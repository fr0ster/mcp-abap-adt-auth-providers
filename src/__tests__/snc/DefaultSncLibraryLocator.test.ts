import { describe, expect, it } from '@jest/globals';
import { ValidationError } from '../../errors/TokenProviderErrors';
import { DefaultSncLibraryLocator } from '../../snc/DefaultSncLibraryLocator';
import { fakeSystem, peLibrary } from './fakeSystem';

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
  it('wrong architecture fails, nothing else tried', async () => {
    const locate = new DefaultSncLibraryLocator(
      fakeSystem({ files: FILES, registry: REGISTRY }),
      X86,
    ).locate();
    await expect(locate).rejects.toThrow(/built for ia32, this process is x64/);
  });
  it('missing file fails as a ValidationError on sncLib', async () => {
    const error = await new DefaultSncLibraryLocator(
      fakeSystem(),
      'C:\\nope.dll',
    )
      .locate()
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ValidationError);
    expect((error as ValidationError).missingFields).toEqual(['sncLib']);
    expect((error as Error).message).toMatch(/C:\\nope\.dll: not found/);
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
    await expect(
      new DefaultSncLibraryLocator(
        fakeSystem({
          platform: 'darwin',
          arch: 'arm64',
          files: { [DYLIB]: fat64([0x01000007]) },
        }),
      ).locate(),
    ).rejects.toThrow(/built for x64, this process is arm64/);
  });
  it('nothing usable: one error listing every candidate', async () => {
    const error = await new DefaultSncLibraryLocator(
      fakeSystem({
        env: { SNC_LIB: X86 },
        files: { [X86]: peLibrary('ia32') },
      }),
    )
      .locate()
      .catch((e: unknown) => e);
    expect((error as ValidationError).missingFields).toEqual(['sncLib']);
    expect((error as Error).message).toMatch(
      /SNC_LIB .*sapcrypto\.dll: built for ia32, this process is x64/,
    );
  });
  it('no candidate at all says so', async () => {
    await expect(
      new DefaultSncLibraryLocator(fakeSystem({ platform: 'linux' })).locate(),
    ).rejects.toThrow(/No candidate/);
  });
});
