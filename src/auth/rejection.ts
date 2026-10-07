/**
 * What a rejection says about the credential — read the same way by every
 * provider in this package.
 *
 * A provider blames its credential, and a token provider renews, only when the
 * rejection says the credential was refused: a 401, or the RFC SDK's
 * RFC_LOGON_FAILURE. Anything else the system said — 403, a redirect, 5xx,
 * another status, another RFC key — is answered `system-refused` with its
 * `verdict`, the status or the allowlisted key, and the moment (`at`); nothing
 * is renewed: a new credential would be refused the same way. A rejection that
 * carries neither is `unknown`, and each provider decides what that means for
 * it.
 *
 * The refusals are minted by auth-errors.
 */

import { authError, httpStatus, isRfcKey } from '@mcp-abap-adt/auth-errors';
import type {
  AuthOutcome,
  CredentialKind,
  IAuthRefusal,
  IAuthRejection,
  RenewalCause,
} from '@mcp-abap-adt/interfaces-auth';
import { readSafely } from './knownCodes';

export type RejectionReading =
  | { readonly verdict: 'credential' }
  | { readonly verdict: 'unknown' }
  | { readonly verdict: 'not-credential'; readonly refusal: IAuthRefusal };

const CREDENTIAL: RejectionReading = Object.freeze({ verdict: 'credential' });
const UNKNOWN: RejectionReading = Object.freeze({ verdict: 'unknown' });

type Moment = 'logon' | 'request';

/** The moment of a rejection; anything but a request reads as a logon, as in 5.4.2. */
export function momentOf(rejection: IAuthRejection | undefined): Moment {
  return readSafely(rejection, 'at') === 'request' ? 'request' : 'logon';
}

function fromStatus(status: number, at: Moment): RejectionReading {
  if (status === 401) return CREDENTIAL;
  const checked = httpStatus(status);
  if (checked === undefined) return UNKNOWN;
  const verdict =
    status === 403
      ? 'not-authorized'
      : status >= 300 && status < 400
        ? 'redirected'
        : status >= 500
          ? 'system-failed'
          : 'other-status';
  return {
    verdict: 'not-credential',
    refusal: authError['system-refused']({ verdict, status: checked, at }),
  };
}

export function readRejection(
  rejection: IAuthRejection | undefined,
): RejectionReading {
  const at = momentOf(rejection);
  const status = readSafely(rejection, 'status');
  if (
    typeof status === 'number' &&
    Number.isInteger(status) &&
    status >= 100 &&
    status <= 599
  ) {
    return fromStatus(status, at);
  }
  const key = readSafely(readSafely(rejection, 'error'), 'key');
  if (isRfcKey(key)) {
    if (key === 'RFC_LOGON_FAILURE') return CREDENTIAL;
    return {
      verdict: 'not-credential',
      refusal: authError['system-refused']({
        verdict: 'rfc-failure',
        rfcKey: key,
        at,
      }),
    };
  }
  return UNKNOWN;
}

/**
 * A rejection as the cause of a renewal (spec §6c.2): rule 5's reading —
 * `not-credential` with its `system-refused` refusal, what a `stop` answers —
 * the moment, and the allowlisted status or RFC key. A reading the renewal
 * strategy receives, not a guard (G9). Frozen: the strategy cannot change
 * what the provider reads back.
 */
export function rejectionCause(
  rejection: IAuthRejection | undefined,
): RenewalCause {
  const read = readRejection(rejection);
  const status = readSafely(rejection, 'status');
  const checked =
    typeof status === 'number' && Number.isInteger(status)
      ? httpStatus(status)
      : undefined;
  const key = readSafely(readSafely(rejection, 'error'), 'key');
  return Object.freeze({
    trigger: 'rejected',
    reading: read.verdict,
    ...(read.verdict === 'not-credential' ? { refusal: read.refusal } : {}),
    at: momentOf(rejection),
    ...(checked === undefined ? {} : { status: checked }),
    ...(isRfcKey(key) ? { rfcKey: key } : {}),
  });
}

/** The neutral refusal for a rejection that cannot be told: `system-refused` `unknown`. */
export function unknownRefusal(
  rejection: IAuthRejection | undefined,
): IAuthRefusal {
  return authError['system-refused']({
    verdict: 'unknown',
    at: momentOf(rejection),
  });
}

/**
 * A provider that cannot renew: `credential-refused` naming its credential
 * and the moment when the credential was refused (B7, B9–B11), the neutral
 * `system-refused` error otherwise.
 */
export function refuseFor(
  rejection: IAuthRejection | undefined,
  credential: CredentialKind,
): AuthOutcome {
  const read = readRejection(rejection);
  if (read.verdict === 'credential') {
    return {
      ok: false,
      refusal: authError['credential-refused']({
        credential,
        at: momentOf(rejection),
      }),
    };
  }
  if (read.verdict === 'not-credential') {
    return { ok: false, refusal: read.refusal };
  }
  return { ok: false, refusal: unknownRefusal(rejection) };
}
