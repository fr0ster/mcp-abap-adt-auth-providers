import type { SncSystem } from '../../snc/SncSystem';

export interface FakeSystemOptions {
  platform?: NodeJS.Platform;
  arch?: string;
  env?: Record<string, string | undefined>;
  /** Path → file head. A path not here cannot be read. */
  files?: Record<string, Buffer>;
  /** "<key>\\<name>" → value. */
  registry?: Record<string, string>;
  /** The process list, or the error listing it throws. */
  processes?: string[] | Error;
}

export function fakeSystem(options: FakeSystemOptions = {}): SncSystem {
  return {
    platform: options.platform ?? 'win32',
    arch: options.arch ?? 'x64',
    env: options.env ?? {},
    async readHead(path) {
      return options.files?.[path] ?? null;
    },
    async readRegistryValue(key, name) {
      return options.registry?.[`${key}\\${name}`];
    },
    async listProcessNames() {
      if (options.processes instanceof Error) throw options.processes;
      return options.processes ?? [];
    },
  };
}

export function peLibrary(arch: 'ia32' | 'x64'): Buffer {
  const b = Buffer.alloc(0x100);
  b.write('MZ', 0, 'latin1');
  b.writeUInt32LE(0x80, 0x3c);
  b.write('PE\0\0', 0x80, 'latin1');
  b.writeUInt16LE(arch === 'x64' ? 0x8664 : 0x014c, 0x84);
  return b;
}
