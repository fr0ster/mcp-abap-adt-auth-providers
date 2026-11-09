/**
 * Rejection reading and the certificate check:
 * each answers its kind and facts in the verbatim words of 5.4.2.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import type { IAuthRejection } from '@mcp-abap-adt/interfaces-auth';
import { checkCertificateMaterial } from '../../auth/certificateMaterial';
import { readRejection, refuseFor, unknownRefusal } from '../../auth/rejection';
import { matchObject } from '../helpers/expectations';
import { minted, mintedRefusal } from '../helpers/minted';
import { CERTIFICATES } from '../helpers/packagePaths';

const status = (n: number, at: 'request' | 'logon' = 'request') =>
  ({ at, status: n, error: new Error('SECRET') }) as IAuthRejection;

/** The neutral refusal readRejection answers for a rejection. */
function neutral(rejection: IAuthRejection | undefined) {
  const read = readRejection(rejection);
  assert.equal(read.verdict, 'not-credential');
  if (read.verdict !== 'not-credential') throw new Error('unreachable');
  return minted(read.refusal);
}

describe('A.2 — rejection reading', () => {
  it('403 → system-refused not-authorized, verbatim', () => {
    const error = neutral(status(403));
    assert.equal(error.kind, 'system-refused');
    assert.deepEqual(error.facts, {
      verdict: 'not-authorized',
      status: 403,
      at: 'request',
    });
    assert.equal(
      error.reason,
      'the credential was accepted, but the user is not authorized (403)',
    );
    assert.equal(error.hint, "check the user's authorizations in the system");
  });

  it('a 3xx → system-refused redirected, verbatim', () => {
    const error = neutral(status(302, 'logon'));
    assert.equal(error.kind, 'system-refused');
    assert.deepEqual(error.facts, {
      verdict: 'redirected',
      status: 302,
      at: 'logon',
    });
    assert.equal(
      error.reason,
      'the system redirected instead of accepting the credential (302)',
    );
    assert.equal(
      error.hint,
      'the service may require another logon procedure (single sign-on, an identity provider)',
    );
  });

  it('a 5xx → system-refused system-failed, verbatim', () => {
    const error = neutral(status(503));
    assert.equal(error.kind, 'system-refused');
    assert.deepEqual(error.facts, {
      verdict: 'system-failed',
      status: 503,
      at: 'request',
    });
    assert.equal(error.reason, 'the system failed (503), not the credential');
    assert.equal(error.hint, 'try again later');
  });

  it('any other status → system-refused other-status, verbatim, no hint', () => {
    const error = neutral(status(404));
    assert.equal(error.kind, 'system-refused');
    assert.deepEqual(error.facts, {
      verdict: 'other-status',
      status: 404,
      at: 'request',
    });
    assert.equal(
      error.reason,
      'the system answered 404, which is not a credential refusal',
    );
    assert.equal(Object.hasOwn(error, 'hint'), false);
  });

  it('another RFC key → system-refused rfc-failure, logon and call, verbatim', () => {
    const logon = neutral({
      at: 'logon',
      error: { key: 'RFC_COMMUNICATION_FAILURE', message: 'SECRET' },
    });
    assert.equal(logon.kind, 'system-refused');
    assert.deepEqual(logon.facts, {
      verdict: 'rfc-failure',
      rfcKey: 'RFC_COMMUNICATION_FAILURE',
      at: 'logon',
    });
    assert.equal(
      logon.reason,
      'the RFC logon failed (RFC_COMMUNICATION_FAILURE), not as a credential refusal',
    );
    const call = neutral({
      at: 'request',
      error: { key: 'RFC_ABAP_RUNTIME_FAILURE' },
    });
    assert.deepEqual(call.facts, {
      verdict: 'rfc-failure',
      rfcKey: 'RFC_ABAP_RUNTIME_FAILURE',
      at: 'request',
    });
    assert.equal(
      call.reason,
      'the RFC call failed (RFC_ABAP_RUNTIME_FAILURE), not as a credential refusal',
    );
  });

  it('neither a status nor a known key → system-refused unknown, per moment, verbatim', () => {
    const request = minted(unknownRefusal({ at: 'request', error: {} }));
    assert.equal(request.kind, 'system-refused');
    assert.deepEqual(request.facts, { verdict: 'unknown', at: 'request' });
    assert.equal(request.reason, 'the request was refused (unknown error)');
    const logon = minted(unknownRefusal({ at: 'logon', error: {} }));
    assert.deepEqual(logon.facts, { verdict: 'unknown', at: 'logon' });
    assert.equal(logon.reason, 'the logon failed (unknown error)');
    // No rejection at all reads as a logon, as in 5.4.2.
    assert.equal(
      minted(unknownRefusal(undefined)).reason,
      'the logon failed (unknown error)',
    );
    // refuseFor answers the same error for a rejection it cannot tell.
    const told = mintedRefusal(
      refuseFor({ at: 'request', error: {} }, 'user-password'),
    );
    assert.deepEqual(told.facts, { verdict: 'unknown', at: 'request' });
  });

  it('refuseFor relays the neutral error itself for a rejection that is not the credential', () => {
    const error = mintedRefusal(refuseFor(status(403), 'user-password'));
    assert.equal(error.kind, 'system-refused');
    matchObject(error.facts, { verdict: 'not-authorized' });
  });

  it('nothing of the rejection error reaches the refusal', () => {
    for (const n of [302, 403, 404, 503]) {
      assert.doesNotMatch(JSON.stringify(neutral(status(n))), /SECRET/);
    }
  });
});

describe('checkCertificateMaterial', () => {
  const dir = CERTIFICATES;
  const read = (name: string) => readFileSync(join(dir, name));

  it('incomplete, unusable and expired material → client-certificate with its problem, verbatim', () => {
    const incomplete = mintedRefusal(checkCertificateMaterial({}));
    assert.equal(incomplete.kind, 'client-certificate');
    assert.deepEqual(incomplete.facts, { problem: 'incomplete' });
    assert.equal(incomplete.reason, 'the client certificate is incomplete');
    assert.equal(
      incomplete.hint,
      'give a PFX, or a certificate together with its key',
    );

    const unusable = mintedRefusal(
      checkCertificateMaterial({ pfx: read('client.pfx'), passphrase: 'no' }),
    );
    assert.equal(unusable.kind, 'client-certificate');
    assert.deepEqual(unusable.facts, { problem: 'unusable' });
    assert.equal(unusable.reason, 'the client certificate could not be used');
    assert.equal(
      unusable.hint,
      'check the certificate, the key and the passphrase, and that a PFX uses current encryption (not legacy RC2)',
    );

    const expired = mintedRefusal(
      checkCertificateMaterial({
        cert: read('expired.crt'),
        key: read('client.key'),
      }),
    );
    assert.equal(expired.kind, 'client-certificate');
    assert.deepEqual(expired.facts, { problem: 'expired' });
    assert.equal(expired.reason, 'the client certificate has expired');
    assert.equal(
      expired.hint,
      'renew the certificate; a token provider pins its certificate for life, so give the renewed one to a new provider',
    );
  });
});
