import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from '@jest/globals';
import { isAuthProviderFailure, readFailure } from '@mcp-abap-adt/auth-errors';
import {
  assertCertificateMaterial,
  certificateThumbprint,
  checkCertificateMaterial,
} from '../../auth/certificateMaterial';
import { refusedWith, wordsOf } from '../helpers/minted';

const dir = join(__dirname, '..', 'fixtures', 'certificates');
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
    expect(
      checkCertificateMaterial({
        cert: read('client.crt'),
        key: read('client.key'),
      }),
    ).toEqual({ ok: true });
    expect(
      checkCertificateMaterial({
        pfx: read('client.pfx'),
        passphrase: PASSPHRASE,
      }),
    ).toEqual({ ok: true });
  });

  it('refuses incomplete material in fixed words', () => {
    for (const m of [
      {},
      { cert: read('client.crt') },
      { key: read('client.key') },
    ])
      expect(wordsOf(checkCertificateMaterial(m))).toEqual({
        ok: false,
        refusal: {
          reason: 'the client certificate is incomplete',
          hint: 'give a PFX, or a certificate together with its key',
        },
      });
  });

  it('refuses material a TLS context cannot be built from', () => {
    expect(
      wordsOf(
        checkCertificateMaterial({
          pfx: read('client.pfx'),
          passphrase: 'wrong',
        }),
      ),
    ).toEqual({
      ok: false,
      refusal: {
        reason: 'the client certificate could not be used',
        hint: 'check the certificate, the key and the passphrase, and that a PFX uses current encryption (not legacy RC2)',
      },
    });
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
    expect(
      wordsOf(
        checkCertificateMaterial({
          cert: read('expired.crt'),
          key: read('client.key'),
        }),
      ),
    ).toEqual(EXPIRED);
  });

  it('throws a client-certificate failure, read by classify into the same words (A4)', () => {
    const e = thrown(() =>
      assertCertificateMaterial({
        cert: read('expired.crt'),
        key: read('client.key'),
      }),
    );
    // A client-certificate failure, no longer the class.
    expect(isAuthProviderFailure(e)).toBe(true);
    expect(wordsOf(refusedWith(e))).toEqual(EXPIRED);
  });

  it('a certificate still valid is not refused', () => {
    expect(
      checkCertificateMaterial({
        cert: read('client.crt'),
        key: read('client.key'),
      }),
    ).toEqual({ ok: true });
  });
});

describe('certificateThumbprint', () => {
  const pem = { cert: read('client.crt'), key: read('client.key') };
  const pfx = { pfx: read('client.pfx'), passphrase: PASSPHRASE };

  it('is the known value for the fixture, from PEM and from PFX alike', () => {
    expect(certificateThumbprint(pem)).toBe(FIXTURE_THUMBPRINT);
    expect(certificateThumbprint(pfx)).toBe(FIXTURE_THUMBPRINT);
  });

  it('is the leaf of a chain: the first certificate', () => {
    const chain = Buffer.concat([
      read('client.crt'),
      Buffer.from('\n'),
      otherCert,
    ]);
    expect(
      certificateThumbprint({ cert: chain, key: read('client.key') }),
    ).toBe(FIXTURE_THUMBPRINT);
    expect(
      certificateThumbprint({ cert: otherCert, key: read('client.key') }),
    ).not.toBe(FIXTURE_THUMBPRINT);
  });

  it('is the leaf of a PFX that carries a chain', () => {
    expect(
      certificateThumbprint({
        pfx: read('client-chain.pfx'),
        passphrase: PASSPHRASE,
      }),
    ).toBe(FIXTURE_THUMBPRINT);
  });

  it('throws a client-certificate failure for incomplete material, with its words (A4)', () => {
    const e = thrown(() => certificateThumbprint({ cert: read('client.crt') }));
    // A client-certificate failure, no longer the class.
    expect(isAuthProviderFailure(e)).toBe(true);
    expect(wordsOf(refusedWith(e))).toEqual({
      ok: false,
      refusal: {
        reason: 'the client certificate is incomplete',
        hint: 'give a PFX, or a certificate together with its key',
      },
    });
  });

  it('throws a client-certificate failure for unusable material, nothing of it in the refusal (A4)', () => {
    const e = thrown(() =>
      certificateThumbprint({
        pfx: read('client.pfx'),
        passphrase: 'sEcReT-wrong',
      }),
    );
    // A client-certificate failure, no longer the class.
    expect(isAuthProviderFailure(e)).toBe(true);
    const out = refusedWith(e);
    expect(wordsOf(out)).toEqual({
      ok: false,
      refusal: {
        reason: 'the client certificate could not be used',
        hint: 'check the certificate, the key and the passphrase, and that a PFX uses current encryption (not legacy RC2)',
      },
    });
    expect(JSON.stringify(out)).not.toMatch(/sEcReT|mac verify/);
    const garbage = thrown(() =>
      certificateThumbprint({
        cert: Buffer.from('not a cert'),
        key: read('client.key'),
      }),
    );
    // A client-certificate failure, no longer the class.
    expect(readFailure(garbage, 'unfamiliar-error')).toMatchObject({
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
    expect(wordsOf(outcome)).toEqual({
      ok: false,
      refusal: {
        reason: 'the client certificate could not be used',
        hint: 'check the certificate, the key and the passphrase, and that a PFX uses current encryption (not legacy RC2)',
      },
    });
    expect(JSON.stringify(outcome)).not.toContain('MARK');
  });

  it('a throwing `words` getter → fixed words, no throw', () => {
    expect(() =>
      checkCertificateMaterial(
        forgedMaterial({
          get: () => {
            throw new Error('MARK');
          },
        }),
      ),
    ).not.toThrow();
  });
});
