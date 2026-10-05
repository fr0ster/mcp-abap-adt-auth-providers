/**
 * What a rejection says about the credential — read the same way by every
 * provider in this package.
 *
 * A provider blames its credential, and a token provider renews, only when the
 * rejection says the credential was refused: a 401, or the RFC SDK's
 * RFC_LOGON_FAILURE. Anything else the system said — 403, a redirect, 5xx,
 * another status, another RFC key — is answered with a neutral refusal that
 * names only the status or the allowlisted key (rule 2), and nothing is
 * renewed: a new credential would be refused the same way. A rejection that
 * carries neither is `unknown`, and each provider decides what that means for
 * it.
 */

import type {
  AuthOutcome,
  IAuthRefusal,
  IAuthRejection,
} from '@mcp-abap-adt/interfaces-auth';
import { KNOWN_RFC_KEYS } from './refusal';

export type RejectionReading =
  | { readonly verdict: 'credential' }
  | { readonly verdict: 'unknown' }
  | { readonly verdict: 'not-credential'; readonly refusal: IAuthRefusal };

const CREDENTIAL: RejectionReading = Object.freeze({ verdict: 'credential' });
const UNKNOWN: RejectionReading = Object.freeze({ verdict: 'unknown' });

function notCredential(reason: string, hint?: string): RejectionReading {
  return {
    verdict: 'not-credential',
    refusal: hint === undefined ? { reason } : { reason, hint },
  };
}

function fromStatus(status: number): RejectionReading {
  if (status === 401) return CREDENTIAL;
  if (status === 403) {
    return notCredential(
      'the credential was accepted, but the user is not authorized (403)',
      "check the user's authorizations in the system",
    );
  }
  if (status >= 300 && status < 400) {
    return notCredential(
      `the system redirected instead of accepting the credential (${status})`,
      'the service may require another logon procedure (single sign-on, an identity provider)',
    );
  }
  if (status >= 500) {
    return notCredential(
      `the system failed (${status}), not the credential`,
      'try again later',
    );
  }
  return notCredential(
    `the system answered ${status}, which is not a credential refusal`,
  );
}

export function readRejection(
  rejection: IAuthRejection | undefined,
): RejectionReading {
  const status = rejection?.status;
  if (
    typeof status === 'number' &&
    Number.isInteger(status) &&
    status >= 100 &&
    status <= 599
  ) {
    return fromStatus(status);
  }
  const key = (rejection?.error as { key?: unknown } | null | undefined)?.key;
  if (typeof key === 'string' && KNOWN_RFC_KEYS.has(key)) {
    if (key === 'RFC_LOGON_FAILURE') return CREDENTIAL;
    const what = rejection?.at === 'request' ? 'call' : 'logon';
    return notCredential(
      `the RFC ${what} failed (${key}), not as a credential refusal`,
    );
  }
  return UNKNOWN;
}

/** The neutral words for a rejection that cannot be told. */
export function unknownRefusal(
  rejection: IAuthRejection | undefined,
): IAuthRefusal {
  return {
    reason:
      rejection?.at === 'request'
        ? 'the request was refused (unknown error)'
        : 'the logon failed (unknown error)',
  };
}

/**
 * A provider that cannot renew: its own refusal when the credential was
 * refused, the neutral words otherwise.
 */
export function refuseFor(
  rejection: IAuthRejection | undefined,
  blame: IAuthRefusal,
): AuthOutcome {
  const read = readRejection(rejection);
  if (read.verdict === 'credential') return { ok: false, refusal: blame };
  if (read.verdict === 'not-credential') {
    return { ok: false, refusal: read.refusal };
  }
  return { ok: false, refusal: unknownRefusal(rejection) };
}
