import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { libraryArchitectures } from '../../snc/libraryArchitectures';
import { cases, caseTitle } from '../helpers/expectations';

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
  for (const [caseIndex, caseRow] of cases([
    [0x014c, 'ia32'],
    [0x8664, 'x64'],
    [0xaa64, 'arm64'],
  ]).entries()) {
    const [m, a] = caseRow;
    it(caseTitle('PE %s → %s', caseRow, caseIndex), () => {
      assert.deepEqual(libraryArchitectures(pe(m)), [a]);
    });
  }
  for (const [caseIndex, caseRow] of cases([
    [0x01000007, 'x64'],
    [0x0100000c, 'arm64'],
  ]).entries()) {
    const [c, a] = caseRow;
    it(caseTitle('thin Mach-O %s → %s', caseRow, caseIndex), () => {
      assert.deepEqual(libraryArchitectures(machoThin(c)), [a]);
    });
  }
  it('universal Mach-O (FAT_MAGIC)', () => {
    assert.deepEqual(libraryArchitectures(machoFat([0x01000007, 0x0100000c])), [
      'x64',
      'arm64',
    ]);
  });
  it('64-bit universal Mach-O (FAT_MAGIC_64)', () => {
    assert.deepEqual(
      libraryArchitectures(machoFat([0x01000007, 0x0100000c], true)),
      ['x64', 'arm64'],
    );
  });
  it('FAT_MAGIC_64 with one architecture is read as what it holds', () => {
    assert.deepEqual(libraryArchitectures(machoFat([0x00000007], true)), [
      'ia32',
    ]);
  });
  for (const [caseIndex, caseRow] of cases([
    [0x3e, 'x64'],
    [0xb7, 'arm64'],
  ]).entries()) {
    const [m, a] = caseRow;
    it(caseTitle('ELF %s → %s', caseRow, caseIndex), () => {
      assert.deepEqual(libraryArchitectures(elf(m)), [a]);
    });
  }
  it('not a library → []', () => {
    assert.deepEqual(libraryArchitectures(Buffer.from('hello, world')), []);
    assert.deepEqual(libraryArchitectures(Buffer.alloc(0)), []);
  });
  it('PE header offset past the bytes read → []', () => {
    const b = pe(0x8664);
    b.writeUInt32LE(0x1000, 0x3c);
    assert.deepEqual(libraryArchitectures(b), []);
  });
  it('unknown PE machine → []', () => {
    assert.deepEqual(libraryArchitectures(pe(0x01c4)), []);
  });
});
