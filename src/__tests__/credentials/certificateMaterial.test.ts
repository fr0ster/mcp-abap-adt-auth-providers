/**
 * The certificate material is proven usable in prepare(), not at the wire.
 *
 * A wrong PFX passphrase, a key that is not the certificate's, or a damaged
 * file used to pass prepare() — the loader only reads bytes — and surfaced in
 * the first TLS handshake as a raw `mac verify failure` / key-mismatch error
 * (measured 2026-10-04). That broke rule 1: no exception crosses the contract,
 * and a refusal carries fixed words only.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from '@jest/globals';
import type { ICertificateMaterial } from '@mcp-abap-adt/interfaces-auth';
import type { ISapConfig } from '@mcp-abap-adt/interfaces-auth-sap';
import { CertificateAuthProvider } from '../../credentials/CertificateAuthProvider';
import { recordingTargets } from '../helpers/targets';

const dir = join(__dirname, '..', 'fixtures', 'certificates');
const read = (name: string) => readFileSync(join(dir, name));
const config = { url: 'https://h', authType: 'certificate' } as ISapConfig;
const PASSPHRASE = 'test-passphrase';

const withMaterial = (material: ICertificateMaterial) =>
  new CertificateAuthProvider({ load: async () => material }, config);

const UNUSABLE = {
  ok: false,
  refusal: {
    reason: 'the client certificate could not be used',
    hint: 'check the certificate and key files and the passphrase',
  },
};

describe('CertificateAuthProvider: the material is checked in prepare()', () => {
  it('a PEM pair that belongs together is Ok, and reaches the logon', async () => {
    const p = withMaterial({
      cert: read('client.crt'),
      key: read('client.key'),
    });
    await expect(p.prepare()).resolves.toEqual({ ok: true });
    const t = recordingTargets();
    await expect(p.establish(t.logonTarget)).resolves.toEqual({ ok: true });
    expect(t.logon.tls).toHaveLength(1);
  });

  it('a PFX with its passphrase is Ok', async () => {
    const p = withMaterial({ pfx: read('client.pfx'), passphrase: PASSPHRASE });
    await expect(p.prepare()).resolves.toEqual({ ok: true });
  });

  it('a PFX with the wrong passphrase is refused in prepare(), naming nothing it read', async () => {
    const p = withMaterial({
      pfx: read('client.pfx'),
      passphrase: 'SECRET-WRONG-PP',
    });
    const outcome = await p.prepare();
    expect(outcome).toEqual(UNUSABLE);
    expect(JSON.stringify(outcome)).not.toMatch(/SECRET-WRONG-PP|mac verify/);
  });

  it('a key that is not the certificate is refused in prepare()', async () => {
    const p = withMaterial({
      cert: read('client.crt'),
      key: read('other.key'),
    });
    const outcome = await p.prepare();
    expect(outcome).toEqual(UNUSABLE);
    expect(JSON.stringify(outcome)).not.toMatch(/MISMATCH|x509/i);
  });

  it('a damaged file is refused in prepare()', async () => {
    const p = withMaterial({
      cert: Buffer.from('not a certificate'),
      key: read('client.key'),
    });
    await expect(p.prepare()).resolves.toEqual(UNUSABLE);
  });

  it('a refused material is not presented: establish answers Oops, nothing reaches the logon', async () => {
    const p = withMaterial({ pfx: read('client.pfx'), passphrase: 'wrong' });
    await p.prepare();
    const t = recordingTargets();
    await expect(p.establish(t.logonTarget)).resolves.toMatchObject({
      ok: false,
    });
    expect(t.logon.tls).toHaveLength(0);
  });
});
