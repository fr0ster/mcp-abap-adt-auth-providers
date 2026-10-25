/**
 * What SNC refusals say. The RFC SDK reports both common
 * logon failures as a generic communication error; the cause is in the GSS
 * text. Measured: `A2200019` — no credential to present; `SNCERR_INIT` — the
 * library could not be loaded. The text is searched by plain code, never
 * copied and never matched by a regular expression: only the minted words,
 * the library's architectures and an allowlisted SDK key are facts; the
 * library this provider resolved is a diagnostic, never a word.
 */

import { authError, isRfcKey, isSncArch } from '@mcp-abap-adt/auth-errors';
import { readSafely } from '../auth/knownCodes';
import type { SncLibrary } from './DefaultSncLibraryLocator';
import type { SncArch } from './libraryArchitectures';

/**
 * The two GSS explanations, minted once by `prepare()` — the one site that
 * extracts the `library` diagnostic — so `rejected()` relays them
 * and builds no diagnostic of its own.
 */
export interface GssRefusals {
  readonly noCredential: SncRefusal;
  readonly initFailed: SncRefusal;
}

/** What `rejected()` knows when it explains a refusal. */
export interface SncContext {
  readonly secureLoginClient: boolean;
  /** Absent until `prepare()` resolved a library. */
  readonly explained?: GssRefusals | undefined;
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

/** The explanation of a GSS code in the error, when it carries one. */
export function sncCause(
  error: unknown,
  context: SncContext,
): SncRefusal | undefined {
  const text = searchable(error);
  if (text.includes('A2200019')) {
    return (
      context.explained?.noCredential ??
      authError.snc({
        problem: 'no-credential',
        secureLoginClient: context.secureLoginClient,
      })
    );
  }
  const lower = text.toLowerCase();
  if (
    lower.includes('sncerr_init') ||
    lower.includes('gssapi library invalid/missing')
  ) {
    return (
      context.explained?.initFailed ??
      authError.snc({ problem: 'library-init-failed' })
    );
  }
  return undefined;
}

/** A GSS cause, else "SNC logon refused" with an allowlisted SDK key. */
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

/** A locator's own failure: the fixed sentence alone. */
export function foreignLocatorRefusal(): SncRefusal {
  return authError.snc({ problem: 'library-not-found' });
}
