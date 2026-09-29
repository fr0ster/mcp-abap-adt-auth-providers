/**
 * Where the SNC library is.
 *
 * An explicit `sncLib` is the caller's decision: the only candidate, and an
 * unusable one fails naming the path and the reason. Without it, candidates
 * are tried in order and an unusable one is skipped with its reason kept:
 * the installer's machine-wide x86 `SNC_LIB` must not hide the x64 library
 * the registry points at.
 */

import { win32 } from 'node:path';
import { ValidationError } from '../errors/TokenProviderErrors';
import { libraryArchitectures, type SncArch } from './libraryArchitectures';
import type { SncSystem } from './SncSystem';
import { MACOS_SLC_LIBRARY, SLC_REGISTRY_KEY } from './secureLoginClient';

export interface SncLibrary {
  path: string;
  archs: SncArch[];
}

export interface ISncLibraryLocator {
  locate(): Promise<SncLibrary>;
}

const HEAD_BYTES = 4096;

export class DefaultSncLibraryLocator implements ISncLibraryLocator {
  constructor(
    private readonly system: SncSystem,
    private readonly explicit?: string,
  ) {}

  async locate(): Promise<SncLibrary> {
    const explicit = this.explicit?.trim();
    if (explicit) {
      const result = await this.inspect(explicit);
      if ('reason' in result) {
        throw new ValidationError(`sncLib ${explicit}: ${result.reason}`, [
          'sncLib',
        ]);
      }
      return result;
    }
    const skipped: string[] = [];
    for (const candidate of await this.candidates()) {
      const result = await this.inspect(candidate.path);
      if (!('reason' in result)) return result;
      skipped.push(`${candidate.source} ${candidate.path}: ${result.reason}`);
    }
    const detail = skipped.length
      ? ['Tried:', ...skipped.map((line) => `  - ${line}`)]
      : [
          'No candidate: SNC_LIB_64 and SNC_LIB are unset and no Secure Login Client installation was found.',
        ];
    throw new ValidationError(
      [
        'No usable SNC library found. Set sncLib to the SNC (GSS) library of your SNC product.',
        ...detail,
      ].join('\n'),
      ['sncLib'],
    );
  }

  private async candidates(): Promise<{ source: string; path: string }[]> {
    const { system } = this;
    const is64 = system.arch === 'x64' || system.arch === 'arm64';
    const variable = (name: string) => system.env[name]?.trim() || undefined;
    const found: { source: string; path: string }[] = [];
    const lib64 = variable('SNC_LIB_64');
    if (is64 && lib64) found.push({ source: 'SNC_LIB_64', path: lib64 });
    const lib = variable('SNC_LIB');
    if (lib) found.push({ source: 'SNC_LIB', path: lib });
    if (system.platform === 'win32') {
      const name = is64 ? 'InstallPath64' : 'InstallPath32';
      const dir = (
        await system.readRegistryValue(SLC_REGISTRY_KEY, name)
      )?.trim();
      if (dir)
        found.push({
          source: `registry ${name}`,
          path: win32.join(dir, 'lib', 'sapcrypto.dll'),
        });
    }
    if (system.platform === 'darwin') {
      found.push({
        source: 'Secure Login Client default',
        path: MACOS_SLC_LIBRARY,
      });
    }
    return found;
  }

  private async inspect(
    path: string,
  ): Promise<SncLibrary | { reason: string }> {
    const head = await this.system.readHead(path, HEAD_BYTES);
    if (!head) return { reason: 'not found or not readable' };
    const archs = libraryArchitectures(head);
    if (archs.length === 0)
      return { reason: 'not a recognised library (PE, Mach-O or ELF)' };
    if (!archs.includes(this.system.arch as SncArch)) {
      return {
        reason: `built for ${archs.join('/')}, this process is ${this.system.arch}`,
      };
    }
    return { path, archs };
  }
}
