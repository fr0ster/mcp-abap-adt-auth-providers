/**
 * What SNC refusals say (spec A.7, G1–G4). The RFC SDK reports both common
 * logon failures as a generic communication error; the cause is in the GSS
 * text. Measured: `A2200019` — no credential to present; `SNCERR_INIT` — the
 * library could not be loaded. The text is searched by plain code, never
 * copied and never matched by a regular expression: only the minted words,
 * the library's architectures and an allowlisted SDK key are facts; the
 * library this provider resolved is a diagnostic, never a word (L9).
 */

import { authError, isRfcKey, isSncArch } from '@mcp-abap-adt/auth-errors';
import { readSafely } from '../auth/knownCodes';
import type { SncLibrary } from './DefaultSncLibraryLocator';
import type { SncArch } from './libraryArchitectures';

/** What `rejected()` knows when it explains a refusal. */
export interface SncContext {
  readonly library?: SncLibrary | undefined;
  readonly secureLoginClient: boolean;
}

/** The SNC refusals: built here, minted by auth-errors. */
export type SncRefusal = ReturnType<typeof authError.snc>;

/** The text to search for GSS codes — never returned. */
function searchable(error: unknown): string {
  if (typeof error === 'string') return error;
  const text = readSafely(error, 'message');
  return typeof text === 'string' ? text : '';
}

/** The library's architectures, each on the allowlist; none when unknown. */
export function archsOf(library: SncLibrary | undefined): SncArch[] {
  const archs = library?.archs;
  if (!Array.isArray(archs)) return [];
  return archs.filter((arch): arch is SncArch => isSncArch(arch));
}

/** The resolved library's path as the `library` diagnostic, when there is one. */
function libraryDiagnostic(library: SncLibrary | undefined) {
  return library === undefined ? {} : { library: library.path };
}

/**
 * `path` as the `library` diagnostic admits it (LocalPath), or `undefined`
 * when admission drops it — the one check, auth-errors', for a log field.
 */
export function admittedLibraryPath(path: string): string | undefined {
  const admitted = authError.snc(
    { problem: 'library-init-failed' },
    { library: path },
  ).diagnostics?.library;
  return typeof admitted === 'string' ? admitted : undefined;
}

/** The explanation of a GSS code in the error, when it carries one (G1, G2). */
export function sncCause(
  error: unknown,
  context: SncContext,
): SncRefusal | undefined {
  const text = searchable(error);
  const archs = archsOf(context.library);
  if (text.includes('A2200019')) {
    return authError.snc(
      {
        problem: 'no-credential',
        secureLoginClient: context.secureLoginClient,
        ...(archs.length ? { libraryArchs: archs } : {}),
      },
      libraryDiagnostic(context.library),
    );
  }
  const lower = text.toLowerCase();
  if (
    lower.includes('sncerr_init') ||
    lower.includes('gssapi library invalid/missing')
  ) {
    return authError.snc(
      {
        problem: 'library-init-failed',
        ...(archs.length ? { libraryArchs: archs } : {}),
      },
      libraryDiagnostic(context.library),
    );
  }
  return undefined;
}

/** A GSS cause, else "SNC logon refused" with an allowlisted SDK key (G3). */
export function sncRefusal(error: unknown, context: SncContext): SncRefusal {
  const cause = sncCause(error, context);
  if (cause) return cause;
  const key = readSafely(error, 'key');
  return authError.snc(
    isRfcKey(key)
      ? { problem: 'logon-refused', rfcKey: key }
      : { problem: 'logon-refused' },
  );
}

/** A locator's own failure: the fixed sentence alone (G4). */
export function foreignLocatorRefusal(): SncRefusal {
  return authError.snc({ problem: 'library-not-found' });
}
