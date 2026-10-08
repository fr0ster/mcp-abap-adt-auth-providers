import type { SncSystem } from '../../snc/SncSystem';

export interface FakeSystemOptions {
  platform?: NodeJS.Platform;
  arch?: string;
  env?: Record<string, string | undefined>;
  /** Path → file head. A path not here cannot be read. */
  files?: Record<string, Buffer>;
  /** "<key>\\<name>" → value. */
  registry?: Record<string, string>;
  /**
   * Each registry read as it was asked for, with the signal it was given —
   * so a test can see which signal reached the query.
   */
  registryReads?: { key: string; name: string; signal?: AbortSignal }[];
  /** A registry read that answers only through this function. */
  readRegistryValue?: SncSystem['readRegistryValue'];
}

export function fakeSystem(options: FakeSystemOptions = {}): SncSystem {
  return {
    platform: options.platform ?? 'win32',
    arch: options.arch ?? 'x64',
    env: options.env ?? {},
    async readHead(path) {
      return options.files?.[path] ?? null;
    },
    async readRegistryValue(key, name, signal) {
      options.registryReads?.push({
        key,
        name,
        ...(signal === undefined ? {} : { signal }),
      });
      if (options.readRegistryValue) {
        return options.readRegistryValue(key, name, signal);
      }
      return options.registry?.[`${key}\\${name}`];
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
