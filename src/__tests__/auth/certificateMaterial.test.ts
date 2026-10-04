import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from '@jest/globals';
import {
  certificateThumbprint,
  checkCertificateMaterial,
} from '../../auth/certificateMaterial';
import { refusalFrom } from '../../auth/refusal';
import { CertificateMaterialError } from '../../errors/CertificateMaterialError';

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
      expect(checkCertificateMaterial(m)).toEqual({
        ok: false,
        refusal: {
          reason: 'the client certificate is incomplete',
          hint: 'give a PFX, or a certificate together with its key',
        },
      });
  });

  it('refuses material a TLS context cannot be built from', () => {
    expect(
      checkCertificateMaterial({
        pfx: read('client.pfx'),
        passphrase: 'wrong',
      }),
    ).toEqual({
      ok: false,
      refusal: {
        reason: 'the client certificate could not be used',
        hint: 'check the certificate, the key and the passphrase, and that a PFX uses current encryption (not legacy RC2)',
      },
    });
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

  it('throws an allowlisted class for incomplete material, with its words', () => {
    const e = thrown(() => certificateThumbprint({ cert: read('client.crt') }));
    expect(e).toBeInstanceOf(CertificateMaterialError);
    expect(refusalFrom(e, 'x')).toEqual({
      ok: false,
      refusal: {
        reason: 'the client certificate is incomplete',
        hint: 'give a PFX, or a certificate together with its key',
      },
    });
  });

  it('throws an allowlisted class for unusable material, nothing of it in the refusal', () => {
    const e = thrown(() =>
      certificateThumbprint({
        pfx: read('client.pfx'),
        passphrase: 'sEcReT-wrong',
      }),
    );
    expect(e).toBeInstanceOf(CertificateMaterialError);
    const out = refusalFrom(e, 'x');
    expect(out).toEqual({
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
    expect(garbage).toBeInstanceOf(CertificateMaterialError);
  });
});
