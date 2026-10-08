/**
 * Where the SNC library is.
 *
 * An explicit `sncLib` is the caller's decision: the only candidate, and an
 * unusable one fails naming its source and the reason. Without it, candidates
 * are tried in order and an unusable one is skipped with its reason kept:
 * the installer's machine-wide x86 `SNC_LIB` must not hide the x64 library
 * the registry points at.
 *
 * Nothing usable is an `AuthProviderFailure` of `snc` `library-not-found`, built here — the one approved source of the
 * `candidatePaths` diagnostic: each candidate's source, reason
 * and architectures as facts, its path as a diagnostic, index for index.
 */

import { win32 } from 'node:path';
import {
  AuthProviderFailure,
  authError,
  isSncArch,
} from '@mcp-abap-adt/auth-errors';
import { libraryArchitectures, type SncArch } from './libraryArchitectures';
import type { SncSystem } from './SncSystem';
import { MACOS_SLC_LIBRARY, SLC_REGISTRY_KEY } from './secureLoginClient';

export interface SncLibrary {
  path: string;
  archs: SncArch[];
}

export interface ISncLibraryLocator {
  /**
   * The library to use. `signal`, when given, is the moment's: a locator
   * that waits on the machine (a registry query) ends when it aborts.
   */
  locate(signal?: AbortSignal): Promise<SncLibrary>;
}

/** Where a candidate came from — a fixed set, so a refusal may name it. */
export type SncCandidateSource =
  | 'sncLib'
  | 'SNC_LIB_64'
  | 'SNC_LIB'
  | 'registry'
  | 'macOS bundle';

const HEAD_BYTES = 4096;

/** Why a candidate is unusable; only a wrong architecture names what it holds. */
type Unusable =
  | { reason: 'missing' | 'not a library' }
  | { reason: 'wrong architecture'; archs: readonly SncArch[] };

type Inspection = SncLibrary | Unusable;

type Tried = Unusable & { source: SncCandidateSource; path: string };

/** The failures this module built — the only ones whose paths are trusted. */
const shipped = new WeakSet<object>();

/**
 * Whether `thrown` is a failure the shipped locator built (the
 * `candidatePaths` diagnostic is read only from the shipped locator). A
 * failure a consumer's locator throws — even one minted by this copy of
 * auth-errors — is not.
 */
export function isShippedLocatorFailure(
  thrown: unknown,
): thrown is AuthProviderFailure {
  return typeof thrown === 'object' && thrown !== null && shipped.has(thrown);
}

function libraryNotFound(
  tried: readonly Tried[],
  arch: string,
): AuthProviderFailure {
  // Built apart: a union as the contextual type widens the problem (One<P>).
  const error = authError.snc(
    {
      problem: 'library-not-found',
      searched: true,
      candidates: tried.map((t) =>
        t.reason === 'wrong architecture'
          ? { source: t.source, reason: t.reason, archs: t.archs }
          : { source: t.source, reason: t.reason },
      ),
      ...(isSncArch(arch) ? { processArch: arch } : {}),
    },
    tried.length ? { candidatePaths: tried.map(({ path }) => path) } : {},
  );
  const failure = new AuthProviderFailure(error);
  shipped.add(failure);
  return failure;
}

export class DefaultSncLibraryLocator implements ISncLibraryLocator {
  constructor(
    private readonly system: SncSystem,
    private readonly explicit?: string,
  ) {}

  async locate(signal?: AbortSignal): Promise<SncLibrary> {
    const explicit = this.explicit?.trim();
    if (explicit) {
      const result = await this.inspect(explicit);
      if ('reason' in result) {
        throw libraryNotFound(
          [{ source: 'sncLib', path: explicit, ...result }],
          this.system.arch,
        );
      }
      return result;
    }
    const tried: Tried[] = [];
    for (const candidate of await this.candidates(signal)) {
      const result = await this.inspect(candidate.path);
      if (!('reason' in result)) return result;
      tried.push({ ...candidate, ...result });
    }
    throw libraryNotFound(tried, this.system.arch);
  }

  private async candidates(
    signal: AbortSignal | undefined,
  ): Promise<{ source: SncCandidateSource; path: string }[]> {
    const { system } = this;
    const is64 = system.arch === 'x64' || system.arch === 'arm64';
    const variable = (name: string) => system.env[name]?.trim() || undefined;
    const found: { source: SncCandidateSource; path: string }[] = [];
    const lib64 = variable('SNC_LIB_64');
    if (is64 && lib64) found.push({ source: 'SNC_LIB_64', path: lib64 });
    const lib = variable('SNC_LIB');
    if (lib) found.push({ source: 'SNC_LIB', path: lib });
    if (system.platform === 'win32') {
      const name = is64 ? 'InstallPath64' : 'InstallPath32';
      // Trimmed before it becomes a path: a value ending in spaces or
      // a CR/LF would make the whole candidate path inadmissible.
      const value = await system.readRegistryValue(
        SLC_REGISTRY_KEY,
        name,
        signal,
      );
      const dir = typeof value === 'string' ? value.trim() : '';
      if (dir)
        found.push({
          source: 'registry',
          path: win32.join(dir, 'lib', 'sapcrypto.dll'),
        });
    }
    if (system.platform === 'darwin') {
      found.push({ source: 'macOS bundle', path: MACOS_SLC_LIBRARY });
    }
    return found;
  }

  private async inspect(path: string): Promise<Inspection> {
    const head = await this.system.readHead(path, HEAD_BYTES);
    if (!head) return { reason: 'missing' };
    const archs = libraryArchitectures(head);
    if (archs.length === 0) return { reason: 'not a library' };
    if (!archs.includes(this.system.arch as SncArch)) {
      return { reason: 'wrong architecture', archs };
    }
    return { path, archs };
  }
}
