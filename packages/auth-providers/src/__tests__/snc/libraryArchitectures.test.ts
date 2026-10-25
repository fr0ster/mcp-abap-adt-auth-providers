import { describe, expect, it } from '@jest/globals';
import { libraryArchitectures } from '../../snc/libraryArchitectures';

function pe(machine: number): Buffer {
  const b = Buffer.alloc(0x100);
  b.write('MZ', 0, 'latin1');
  b.writeUInt32LE(0x80, 0x3c);
  b.write('PE\0\0', 0x80, 'latin1');
  b.writeUInt16LE(machine, 0x84);
  return b;
}
function machoThin(cputype: number): Buffer {
  const b = Buffer.alloc(32);
  b.writeUInt32LE(0xfeedfacf, 0);
  b.writeUInt32LE(cputype, 4);
  return b;
}
// FAT_MAGIC: 20-byte fat_arch records; FAT_MAGIC_64: 32-byte fat_arch_64.
function machoFat(cputypes: number[], wide = false): Buffer {
  const width = wide ? 32 : 20;
  const b = Buffer.alloc(8 + cputypes.length * width);
  b.writeUInt32BE(wide ? 0xcafebabf : 0xcafebabe, 0);
  b.writeUInt32BE(cputypes.length, 4);
  cputypes.forEach((c, i) => {
    b.writeUInt32BE(c, 8 + i * width);
  });
  return b;
}
function elf(machine: number): Buffer {
  const b = Buffer.alloc(64);
  b.writeUInt32BE(0x7f454c46, 0);
  b[5] = 1;
  b.writeUInt16LE(machine, 0x12);
  return b;
}

describe('libraryArchitectures', () => {
  it.each([
    [0x014c, 'ia32'],
    [0x8664, 'x64'],
    [0xaa64, 'arm64'],
  ])('PE %s → %s', (m, a) => {
    expect(libraryArchitectures(pe(m))).toEqual([a]);
  });
  it.each([
    [0x01000007, 'x64'],
    [0x0100000c, 'arm64'],
  ])('thin Mach-O %s → %s', (c, a) => {
    expect(libraryArchitectures(machoThin(c))).toEqual([a]);
  });
  it('universal Mach-O (FAT_MAGIC)', () => {
    expect(libraryArchitectures(machoFat([0x01000007, 0x0100000c]))).toEqual([
      'x64',
      'arm64',
    ]);
  });
  it('64-bit universal Mach-O (FAT_MAGIC_64)', () => {
    expect(
      libraryArchitectures(machoFat([0x01000007, 0x0100000c], true)),
    ).toEqual(['x64', 'arm64']);
  });
  it('FAT_MAGIC_64 with one architecture is read as what it holds', () => {
    expect(libraryArchitectures(machoFat([0x00000007], true))).toEqual([
      'ia32',
    ]);
  });
  it.each([
    [0x3e, 'x64'],
    [0xb7, 'arm64'],
  ])('ELF %s → %s', (m, a) => {
    expect(libraryArchitectures(elf(m))).toEqual([a]);
  });
  it('not a library → []', () => {
    expect(libraryArchitectures(Buffer.from('hello, world'))).toEqual([]);
    expect(libraryArchitectures(Buffer.alloc(0))).toEqual([]);
  });
  it('PE header offset past the bytes read → []', () => {
    const b = pe(0x8664);
    b.writeUInt32LE(0x1000, 0x3c);
    expect(libraryArchitectures(b)).toEqual([]);
  });
  it('unknown PE machine → []', () => {
    expect(libraryArchitectures(pe(0x01c4))).toEqual([]);
  });
});
