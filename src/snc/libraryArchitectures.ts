/**
 * Which architectures a shared library is built for, from its first bytes.
 *
 * The RFC SDK loads the SNC library into this process, and a library of the
 * wrong architecture fails there with nothing but `SNCERR_INIT`. The Secure
 * Login Client installer sets the machine-wide `SNC_LIB` to its x86 library,
 * so a 64-bit Node meets exactly that. Reading the header first turns it into
 * a message naming the file and both architectures.
 */

export type SncArch = 'ia32' | 'x64' | 'arm64';

// Biome forbids hex object keys, so the IMAGE_FILE_MACHINE_* / CPU_TYPE_* /
// EM_* constants are spelled out here in hex and used as keys below.
const IMAGE_FILE_MACHINE_I386 = 0x014c;
const IMAGE_FILE_MACHINE_AMD64 = 0x8664;
const IMAGE_FILE_MACHINE_ARM64 = 0xaa64;
const CPU_TYPE_I386 = 0x00000007;
const CPU_TYPE_X86_64 = 0x01000007;
const CPU_TYPE_ARM64 = 0x0100000c;
const EM_386 = 0x03;
const EM_X86_64 = 0x3e;
const EM_AARCH64 = 0xb7;

const PE_MACHINE: Record<number, SncArch> = {
  [IMAGE_FILE_MACHINE_I386]: 'ia32',
  [IMAGE_FILE_MACHINE_AMD64]: 'x64',
  [IMAGE_FILE_MACHINE_ARM64]: 'arm64',
};
const MACHO_CPU: Record<number, SncArch> = {
  [CPU_TYPE_I386]: 'ia32',
  [CPU_TYPE_X86_64]: 'x64',
  [CPU_TYPE_ARM64]: 'arm64',
};
const ELF_MACHINE: Record<number, SncArch> = {
  [EM_386]: 'ia32',
  [EM_X86_64]: 'x64',
  [EM_AARCH64]: 'arm64',
};

export function libraryArchitectures(head: Buffer): SncArch[] {
  if (head.length >= 0x40 && head.toString('latin1', 0, 2) === 'MZ') {
    const offset = head.readUInt32LE(0x3c);
    if (
      offset + 6 > head.length ||
      head.toString('latin1', offset, offset + 4) !== 'PE\0\0'
    ) {
      return [];
    }
    const arch = PE_MACHINE[head.readUInt16LE(offset + 4)];
    return arch ? [arch] : [];
  }
  if (head.length >= 8) {
    const magicLe = head.readUInt32LE(0);
    if (magicLe === 0xfeedfacf || magicLe === 0xfeedface) {
      const arch = MACHO_CPU[head.readUInt32LE(4)];
      return arch ? [arch] : [];
    }
    const magicBe = head.readUInt32BE(0);
    if (magicBe === 0xcafebabe || magicBe === 0xcafebabf) {
      // FAT_MAGIC: fat_arch is 20 bytes; FAT_MAGIC_64: fat_arch_64 is 32.
      // cputype is the first field of both.
      const width = magicBe === 0xcafebabf ? 32 : 20;
      const count = head.readUInt32BE(4);
      const archs: SncArch[] = [];
      for (let i = 0; i < count && 8 + i * width + 4 <= head.length; i++) {
        const arch = MACHO_CPU[head.readUInt32BE(8 + i * width)];
        if (arch && !archs.includes(arch)) archs.push(arch);
      }
      return archs;
    }
  }
  if (head.length >= 0x14 && head.readUInt32BE(0) === 0x7f454c46) {
    const machine =
      head[5] === 2 ? head.readUInt16BE(0x12) : head.readUInt16LE(0x12);
    const arch = ELF_MACHINE[machine];
    return arch ? [arch] : [];
  }
  return [];
}
