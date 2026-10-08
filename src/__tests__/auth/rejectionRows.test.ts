/**
 * Rejection reading and the certificate check:
 * each answers its kind and facts in the verbatim words of 5.4.2.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from '@jest/globals';
import type { IAuthRejection } from '@mcp-abap-adt/interfaces-auth';
import { checkCertificateMaterial } from '../../auth/certificateMaterial';
import { readRejection, refuseFor, unknownRefusal } from '../../auth/rejection';
import { minted, mintedRefusal } from '../helpers/minted';

const status = (n: number, at: 'request' | 'logon' = 'request') =>
  ({ at, status: n, error: new Error('SECRET') }) as IAuthRejection;

/** The neutral refusal readRejection answers for a rejection. */
function neutral(rejection: IAuthRejection | undefined) {
  const read = readRejection(rejection);
  expect(read.verdict).toBe('not-credential');
  if (read.verdict !== 'not-credential') throw new Error('unreachable');
  return minted(read.refusal);
}

describe('A.2 — rejection reading', () => {
  it('403 → system-refused not-authorized, verbatim', () => {
    const error = neutral(status(403));
    expect(error.kind).toBe('system-refused');
    expect(error.facts).toEqual({
      verdict: 'not-authorized',
      status: 403,
      at: 'request',
    });
    expect(error.reason).toBe(
      'the credential was accepted, but the user is not authorized (403)',
    );
    expect(error.hint).toBe("check the user's authorizations in the system");
  });

  it('a 3xx → system-refused redirected, verbatim', () => {
    const error = neutral(status(302, 'logon'));
    expect(error.kind).toBe('system-refused');
    expect(error.facts).toEqual({
      verdict: 'redirected',
      status: 302,
      at: 'logon',
    });
    expect(error.reason).toBe(
      'the system redirected instead of accepting the credential (302)',
    );
    expect(error.hint).toBe(
      'the service may require another logon procedure (single sign-on, an identity provider)',
    );
  });

  it('a 5xx → system-refused system-failed, verbatim', () => {
    const error = neutral(status(503));
    expect(error.kind).toBe('system-refused');
    expect(error.facts).toEqual({
      verdict: 'system-failed',
      status: 503,
      at: 'request',
    });
    expect(error.reason).toBe('the system failed (503), not the credential');
    expect(error.hint).toBe('try again later');
  });

  it('any other status → system-refused other-status, verbatim, no hint', () => {
    const error = neutral(status(404));
    expect(error.kind).toBe('system-refused');
    expect(error.facts).toEqual({
      verdict: 'other-status',
      status: 404,
      at: 'request',
    });
    expect(error.reason).toBe(
      'the system answered 404, which is not a credential refusal',
    );
    expect(Object.hasOwn(error, 'hint')).toBe(false);
  });

  it('another RFC key → system-refused rfc-failure, logon and call, verbatim', () => {
    const logon = neutral({
      at: 'logon',
      error: { key: 'RFC_COMMUNICATION_FAILURE', message: 'SECRET' },
    });
    expect(logon.kind).toBe('system-refused');
    expect(logon.facts).toEqual({
      verdict: 'rfc-failure',
      rfcKey: 'RFC_COMMUNICATION_FAILURE',
      at: 'logon',
    });
    expect(logon.reason).toBe(
      'the RFC logon failed (RFC_COMMUNICATION_FAILURE), not as a credential refusal',
    );
    const call = neutral({
      at: 'request',
      error: { key: 'RFC_ABAP_RUNTIME_FAILURE' },
    });
    expect(call.facts).toEqual({
      verdict: 'rfc-failure',
      rfcKey: 'RFC_ABAP_RUNTIME_FAILURE',
      at: 'request',
    });
    expect(call.reason).toBe(
      'the RFC call failed (RFC_ABAP_RUNTIME_FAILURE), not as a credential refusal',
    );
  });

  it('neither a status nor a known key → system-refused unknown, per moment, verbatim', () => {
    const request = minted(unknownRefusal({ at: 'request', error: {} }));
    expect(request.kind).toBe('system-refused');
    expect(request.facts).toEqual({ verdict: 'unknown', at: 'request' });
    expect(request.reason).toBe('the request was refused (unknown error)');
    const logon = minted(unknownRefusal({ at: 'logon', error: {} }));
    expect(logon.facts).toEqual({ verdict: 'unknown', at: 'logon' });
    expect(logon.reason).toBe('the logon failed (unknown error)');
    // No rejection at all reads as a logon, as in 5.4.2.
    expect(minted(unknownRefusal(undefined)).reason).toBe(
      'the logon failed (unknown error)',
    );
    // refuseFor answers the same error for a rejection it cannot tell.
    const told = mintedRefusal(
      refuseFor({ at: 'request', error: {} }, 'user-password'),
    );
    expect(told.facts).toEqual({ verdict: 'unknown', at: 'request' });
  });

  it('refuseFor relays the neutral error itself for a rejection that is not the credential', () => {
    const error = mintedRefusal(refuseFor(status(403), 'user-password'));
    expect(error.kind).toBe('system-refused');
    expect(error.facts).toMatchObject({ verdict: 'not-authorized' });
  });

  it('nothing of the rejection error reaches the refusal', () => {
    for (const n of [302, 403, 404, 503]) {
      expect(JSON.stringify(neutral(status(n)))).not.toMatch(/SECRET/);
    }
  });
});

describe('checkCertificateMaterial', () => {
  const dir = join(__dirname, '..', 'fixtures', 'certificates');
  const read = (name: string) => readFileSync(join(dir, name));

  it('incomplete, unusable and expired material → client-certificate with its problem, verbatim', () => {
    const incomplete = mintedRefusal(checkCertificateMaterial({}));
    expect(incomplete.kind).toBe('client-certificate');
    expect(incomplete.facts).toEqual({ problem: 'incomplete' });
    expect(incomplete.reason).toBe('the client certificate is incomplete');
    expect(incomplete.hint).toBe(
      'give a PFX, or a certificate together with its key',
    );

    const unusable = mintedRefusal(
      checkCertificateMaterial({ pfx: read('client.pfx'), passphrase: 'no' }),
    );
    expect(unusable.kind).toBe('client-certificate');
    expect(unusable.facts).toEqual({ problem: 'unusable' });
    expect(unusable.reason).toBe('the client certificate could not be used');
    expect(unusable.hint).toBe(
      'check the certificate, the key and the passphrase, and that a PFX uses current encryption (not legacy RC2)',
    );

    const expired = mintedRefusal(
      checkCertificateMaterial({
        cert: read('expired.crt'),
        key: read('client.key'),
      }),
    );
    expect(expired.kind).toBe('client-certificate');
    expect(expired.facts).toEqual({ problem: 'expired' });
    expect(expired.reason).toBe('the client certificate has expired');
    expect(expired.hint).toBe(
      'renew the certificate; a token provider pins its certificate for life, so give the renewed one to a new provider',
    );
  });
});
