/**
 * What a refused SNC logon means. The RFC SDK reports both common failures as
 * a generic communication error; the cause is in the GSS text. Measured:
 * `A2200019` — no credential to present; `SNCERR_INIT` — the library could not
 * be loaded. The text is searched, never copied: only fixed wording, the
 * library this provider resolved, and an allowlisted SDK key go out (rule 2).
 */

import type { IAuthRefusal } from '@mcp-abap-adt/interfaces-auth';
import { KNOWN_RFC_KEYS } from '../auth/refusal';
import type { SncLibrary } from './DefaultSncLibraryLocator';
import { SECURE_LOGIN_CLIENT } from './secureLoginClient';

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

export function sncRefusal(
  error: unknown,
  context: { library?: SncLibrary; product?: string },
): IAuthRefusal {
  const text = searchable(error);
  const library = context.library
    ? `${context.library.path} (${context.library.archs.join('/')})`
    : 'the SNC library';
  if (/A2200019/.test(text)) {
    return {
      reason: 'the SNC library has no credential to present (A2200019)',
      hint:
        context.product === SECURE_LOGIN_CLIENT
          ? 'log on in the Secure Login Client, to the profile used for SAP applications'
          : `make sure the SNC product behind ${library} is logged on`,
    };
  }
  if (/SNCERR_INIT|gssapi library invalid\/missing/i.test(text)) {
    return {
      reason: `the RFC SDK could not initialise ${library} as its SNC library (SNCERR_INIT)`,
    };
  }
  return { reason: `SNC logon refused${sdkKey(error)}` };
}
