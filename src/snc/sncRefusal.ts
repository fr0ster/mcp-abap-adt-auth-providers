/**
 * What SNC refusals say. The RFC SDK reports both common logon failures as a
 * generic communication error; the cause is in the GSS text. Measured:
 * `A2200019` — no credential to present; `SNCERR_INIT` — the library could not
 * be loaded. The text is searched, never copied: only fixed wording, the
 * library this provider resolved, and an allowlisted SDK key go out (rule 2).
 */

import type { IAuthRefusal } from '@mcp-abap-adt/interfaces-auth';
import { KNOWN_RFC_KEYS } from '../auth/refusal';
import {
  SNC_CANDIDATE_SOURCES,
  SNC_UNUSABLE_REASONS,
  type SncLibrary,
  SncLibraryNotFoundError,
} from './DefaultSncLibraryLocator';

/** The text to search for GSS codes — never returned. */
function searchable(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === 'string') return error;
  const text = (error as { message?: unknown } | null)?.message;
  return typeof text === 'string' ? text : '';
}

function sdkKey(error: unknown): string {
  const key = (error as { key?: unknown } | null)?.key;
  return typeof key === 'string' && KNOWN_RFC_KEYS.has(key) ? ` (${key})` : '';
}

function describeLibrary(library?: SncLibrary): string {
  if (!library) return 'the SNC library';
  const archs = Array.isArray(library.archs) ? library.archs.join('/') : '';
  return archs ? `${library.path} (${archs})` : library.path;
}

/** The explanation of a GSS code in the error, when it carries one. */
export function sncCause(
  error: unknown,
  context: { library?: SncLibrary; secureLoginClient: boolean },
): IAuthRefusal | undefined {
  const text = searchable(error);
  const library = describeLibrary(context.library);
  if (/A2200019/.test(text)) {
    return {
      reason: 'the SNC library has no credential to present (A2200019)',
      hint: context.secureLoginClient
        ? 'log on in the Secure Login Client, to the profile used for SAP applications'
        : `make sure the SNC product behind ${library} is logged on`,
    };
  }
  if (/SNCERR_INIT|gssapi library invalid\/missing/i.test(text)) {
    return {
      reason: `the RFC SDK could not initialise ${library} as its SNC library (SNCERR_INIT)`,
    };
  }
  return undefined;
}

export function sncRefusal(
  error: unknown,
  context: { library?: SncLibrary; secureLoginClient: boolean },
): IAuthRefusal {
  return (
    sncCause(error, context) ?? { reason: `SNC logon refused${sdkKey(error)}` }
  );
}

const LOCATE_HINT = 'set sncLib to the SNC (GSS) library of your SNC product';

/**
 * Why no library could be used: each candidate's source, path and fixed reason
 * — built only from those parts, and only when they are the package's own
 * values; anything else a locator throws gets the fixed sentence alone.
 */
export function locateRefusal(error: unknown): IAuthRefusal {
  const reason = 'no usable SNC library was found';
  if (!(error instanceof SncLibraryNotFoundError)) {
    return { reason, hint: LOCATE_HINT };
  }
  const tried = error.tried.filter(
    (t) =>
      SNC_CANDIDATE_SOURCES.has(t.source) &&
      SNC_UNUSABLE_REASONS.has(t.reason) &&
      typeof t.path === 'string',
  );
  const detail = tried.length
    ? tried.map((t) => `${t.source} ${t.path} (${t.reason})`).join('; ')
    : 'no candidate (SNC_LIB_64 and SNC_LIB are unset and no Secure Login Client installation was found)';
  return { reason: `${reason}: ${detail}`, hint: LOCATE_HINT };
}
