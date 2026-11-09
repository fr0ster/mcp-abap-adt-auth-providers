import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { isAuthProviderFailure, readFailure } from '@mcp-abap-adt/auth-errors';
import {
  assertCertificateMaterial,
  certificateThumbprint,
  checkCertificateMaterial,
} from '../../auth/certificateMaterial';
import { matchObject, notContains } from '../helpers/expectations';
import { refusedWith, wordsOf } from '../helpers/minted';
import { CERTIFICATES } from '../helpers/packagePaths';

const dir = CERTIFICATES;
const read = (name: string) => readFileSync(join(dir, name));
const PASSPHRASE = 'test-passphrase';
const FIXTURE_THUMBPRINT = 'Hxfr0QUzsXiurYY1W5T4th39ZFrzAnaXsecrqFmlKiQ';
const otherCert = read('other.crt');

const thrown = (fn: () => unknown): unknown => {
  try {
    fn();
  } catch (e) {
    return e;
  }
  throw new Error('did not throw');
};

describe('checkCertificateMaterial', () => {
  it('is Ok for a PEM pair and for a PFX', () => {
    assert.deepEqual(
      checkCertificateMaterial({
        cert: read('client.crt'),
        key: read('client.key'),
      }),
      { ok: true },
    );
    assert.deepEqual(
      checkCertificateMaterial({
        pfx: read('client.pfx'),
        passphrase: PASSPHRASE,
      }),
      { ok: true },
    );
  });

  it('refuses incomplete material in fixed words', () => {
    for (const m of [
      {},
      { cert: read('client.crt') },
      { key: read('client.key') },
    ])
      assert.deepEqual(wordsOf(checkCertificateMaterial(m)), {
        ok: false,
        refusal: {
          reason: 'the client certificate is incomplete',
          hint: 'give a PFX, or a certificate together with its key',
        },
      });
  });

  it('refuses material a TLS context cannot be built from', () => {
    assert.deepEqual(
      wordsOf(
        checkCertificateMaterial({
          pfx: read('client.pfx'),
          passphrase: 'wrong',
        }),
      ),
      {
        ok: false,
        refusal: {
          reason: 'the client certificate could not be used',
          hint: 'check the certificate, the key and the passphrase, and that a PFX uses current encryption (not legacy RC2)',
        },
      },
    );
  });
});

describe('an expired client certificate', () => {
  const EXPIRED = {
    ok: false,
    refusal: {
      reason: 'the client certificate has expired',
      hint: 'renew the certificate; a token provider pins its certificate for life, so give the renewed one to a new provider',
    },
  };

  it('is refused in fixed words (fixture: valid 2020-01-01 to 2021-01-01)', () => {
    assert.deepEqual(
      wordsOf(
        checkCertificateMaterial({
          cert: read('expired.crt'),
          key: read('client.key'),
        }),
      ),
      EXPIRED,
    );
  });

  it('throws a client-certificate failure, read by classify into the same words', () => {
    const e = thrown(() =>
      assertCertificateMaterial({
        cert: read('expired.crt'),
        key: read('client.key'),
      }),
    );
    // A client-certificate failure, no longer the class.
    assert.equal(isAuthProviderFailure(e), true);
    assert.deepEqual(wordsOf(refusedWith(e)), EXPIRED);
  });

  it('a certificate still valid is not refused', () => {
    assert.deepEqual(
      checkCertificateMaterial({
        cert: read('client.crt'),
        key: read('client.key'),
      }),
      { ok: true },
    );
  });
});

describe('certificateThumbprint', () => {
  const pem = { cert: read('client.crt'), key: read('client.key') };
  const pfx = { pfx: read('client.pfx'), passphrase: PASSPHRASE };

  it('is the known value for the fixture, from PEM and from PFX alike', () => {
    assert.equal(certificateThumbprint(pem), FIXTURE_THUMBPRINT);
    assert.equal(certificateThumbprint(pfx), FIXTURE_THUMBPRINT);
  });

  it('is the leaf of a chain: the first certificate', () => {
    const chain = Buffer.concat([
      read('client.crt'),
      Buffer.from('\n'),
      otherCert,
    ]);
    assert.equal(
      certificateThumbprint({ cert: chain, key: read('client.key') }),
      FIXTURE_THUMBPRINT,
    );
    assert.notEqual(
      certificateThumbprint({ cert: otherCert, key: read('client.key') }),
      FIXTURE_THUMBPRINT,
    );
  });

  it('is the leaf of a PFX that carries a chain', () => {
    assert.equal(
      certificateThumbprint({
        pfx: read('client-chain.pfx'),
        passphrase: PASSPHRASE,
      }),
      FIXTURE_THUMBPRINT,
    );
  });

  it('throws a client-certificate failure for incomplete material, with its words', () => {
    const e = thrown(() => certificateThumbprint({ cert: read('client.crt') }));
    // A client-certificate failure, no longer the class.
    assert.equal(isAuthProviderFailure(e), true);
    assert.deepEqual(wordsOf(refusedWith(e)), {
      ok: false,
      refusal: {
        reason: 'the client certificate is incomplete',
        hint: 'give a PFX, or a certificate together with its key',
      },
    });
  });

  it('throws a client-certificate failure for unusable material, nothing of it in the refusal', () => {
    const e = thrown(() =>
      certificateThumbprint({
        pfx: read('client.pfx'),
        passphrase: 'sEcReT-wrong',
      }),
    );
    // A client-certificate failure, no longer the class.
    assert.equal(isAuthProviderFailure(e), true);
    const out = refusedWith(e);
    assert.deepEqual(wordsOf(out), {
      ok: false,
      refusal: {
        reason: 'the client certificate could not be used',
        hint: 'check the certificate, the key and the passphrase, and that a PFX uses current encryption (not legacy RC2)',
      },
    });
    assert.doesNotMatch(JSON.stringify(out), /sEcReT|mac verify/);
    const garbage = thrown(() =>
      certificateThumbprint({
        cert: Buffer.from('not a cert'),
        key: read('client.key'),
      }),
    );
    // A client-certificate failure, no longer the class.
    matchObject(readFailure(garbage, 'unfamiliar-error'), {
      kind: 'client-certificate',
      facts: { problem: 'unusable' },
    });
  });
});

// The class is gone: a material getter throwing a look-alike
// of the former CertificateMaterialError — its flags and its own `words` —
// is a foreign throw: `client-certificate` `unusable`, its text nowhere.
describe('checkCertificateMaterial and a material getter throwing a look-alike', () => {
  const forgedMaterial = (words: PropertyDescriptor) => {
    const forged = Object.assign(new Error('MARK'), {
      name: 'CertificateMaterialError',
      incomplete: true,
    });
    Object.defineProperty(forged, 'words', words);
    return {
      get pfx(): Buffer {
        throw forged;
      },
    };
  };

  it('own `words` carrying a marker → the fixed unusable words', () => {
    const outcome = checkCertificateMaterial(
      forgedMaterial({ get: () => ({ reason: 'MARK', hint: 'MARK' }) }),
    );
    assert.deepEqual(wordsOf(outcome), {
      ok: false,
      refusal: {
        reason: 'the client certificate could not be used',
        hint: 'check the certificate, the key and the passphrase, and that a PFX uses current encryption (not legacy RC2)',
      },
    });
    notContains(JSON.stringify(outcome), 'MARK');
  });

  it('a throwing `words` getter → fixed words, no throw', () => {
    assert.doesNotThrow(() =>
      checkCertificateMaterial(
        forgedMaterial({
          get: () => {
            throw new Error('MARK');
          },
        }),
      ),
    );
  });
});
