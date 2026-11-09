/**
 * The certificate material is proven usable in prepare(), not at the wire.
 *
 * A wrong PFX passphrase, a key that is not the certificate's, or a damaged
 * file used to pass prepare() — the loader only reads bytes — and surfaced in
 * the first TLS handshake as a raw `mac verify failure` / key-mismatch error
 * (measured 2026-10-04). That broke rule 1: no exception crosses the contract,
 * and a refusal carries fixed words only.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it, mock } from 'node:test';
import type { ICertificateMaterial } from '@mcp-abap-adt/interfaces-auth';
import type { ISapConfig } from '@mcp-abap-adt/interfaces-auth-sap';
import { CertificateAuthProvider } from '../../credentials/CertificateAuthProvider';
import { cases, caseTitle, matchObject } from '../helpers/expectations';
import { wordsOf } from '../helpers/minted';
import { CERTIFICATES } from '../helpers/packagePaths';
import { recordingTargets } from '../helpers/targets';

const dir = CERTIFICATES;
const read = (name: string) => readFileSync(join(dir, name));
const config = { url: 'https://h', authType: 'certificate' } as ISapConfig;
const PASSPHRASE = 'test-passphrase';

const withMaterial = (material: ICertificateMaterial) =>
  new CertificateAuthProvider({ load: async () => material }, config);

const INCOMPLETE = {
  ok: false,
  refusal: {
    reason: 'the client certificate is incomplete',
    hint: 'give a PFX, or a certificate together with its key',
  },
};

const UNUSABLE = {
  ok: false,
  refusal: {
    reason: 'the client certificate could not be used',
    hint: 'check the certificate, the key and the passphrase, and that a PFX uses current encryption (not legacy RC2)',
  },
};

describe('CertificateAuthProvider: the material is checked in prepare()', () => {
  it('a PEM pair that belongs together is Ok, and reaches the logon', async () => {
    const p = withMaterial({
      cert: read('client.crt'),
      key: read('client.key'),
    });
    assert.deepEqual(await p.prepare(), { ok: true });
    const t = recordingTargets();
    assert.deepEqual(await p.establish(t.logonTarget), { ok: true });
    assert.equal(t.logon.tls.length, 1);
  });

  it('a PFX with its passphrase is Ok', async () => {
    const p = withMaterial({ pfx: read('client.pfx'), passphrase: PASSPHRASE });
    assert.deepEqual(await p.prepare(), { ok: true });
  });

  it('a PFX with the wrong passphrase is refused in prepare(), naming nothing it read', async () => {
    const p = withMaterial({
      pfx: read('client.pfx'),
      passphrase: 'SECRET-WRONG-PP',
    });
    const outcome = await p.prepare();
    assert.deepEqual(wordsOf(outcome), UNUSABLE);
    assert.doesNotMatch(JSON.stringify(outcome), /SECRET-WRONG-PP|mac verify/);
  });

  it('a key that is not the certificate is refused in prepare()', async () => {
    const p = withMaterial({
      cert: read('client.crt'),
      key: read('other.key'),
    });
    const outcome = await p.prepare();
    assert.deepEqual(wordsOf(outcome), UNUSABLE);
    assert.doesNotMatch(JSON.stringify(outcome), /MISMATCH|x509/i);
  });

  it('a damaged file is refused in prepare()', async () => {
    const p = withMaterial({
      cert: Buffer.from('not a certificate'),
      key: read('client.key'),
    });
    assert.deepEqual(wordsOf(await p.prepare()), UNUSABLE);
  });

  it('a refused material is not presented: establish answers Oops, nothing reaches the logon', async () => {
    const p = withMaterial({ pfx: read('client.pfx'), passphrase: 'wrong' });
    await p.prepare();
    const t = recordingTargets();
    matchObject(await p.establish(t.logonTarget), {
      ok: false,
    });
    assert.equal(t.logon.tls.length, 0);
  });
});

describe('CertificateAuthProvider: what a material must hold', () => {
  it('an encrypted PEM key with its passphrase is Ok', async () => {
    const p = withMaterial({
      cert: read('client.crt'),
      key: read('client-encrypted.key'),
      passphrase: PASSPHRASE,
    });
    assert.deepEqual(await p.prepare(), { ok: true });
  });

  it('an encrypted PEM key without its passphrase is refused', async () => {
    const p = withMaterial({
      cert: read('client.crt'),
      key: read('client-encrypted.key'),
    });
    assert.deepEqual(wordsOf(await p.prepare()), UNUSABLE);
  });

  for (const [caseIndex, caseRow] of cases([
    ['nothing', {}],
    ['a certificate alone', { cert: read('client.crt') }],
    ['a key alone', { key: read('client.key') }],
  ]).entries()) {
    const [_label, material] = caseRow;
    it(
      caseTitle(
        '%s is refused — a logon would go out with no client certificate',
        caseRow,
        caseIndex,
      ),
      async () => {
        const p = withMaterial(material as ICertificateMaterial);
        assert.deepEqual(wordsOf(await p.prepare()), INCOMPLETE);
      },
    );
  }

  it('a prepare() that fails after one that succeeded leaves nothing to present', async () => {
    const good = { cert: read('client.crt'), key: read('client.key') };
    const bad = { pfx: read('client.pfx'), passphrase: 'wrong' };
    let next: ICertificateMaterial = good;
    const p = new CertificateAuthProvider({ load: async () => next }, config);
    assert.deepEqual(await p.prepare(), { ok: true });
    next = bad;
    assert.deepEqual(wordsOf(await p.prepare()), UNUSABLE);
    const t = recordingTargets();
    matchObject(await p.establish(t.logonTarget), {
      ok: false,
    });
    assert.equal(t.logon.tls.length, 0);
  });
});

describe('CertificateAuthProvider: an expired certificate', () => {
  const EXPIRED = {
    ok: false,
    refusal: {
      reason: 'the client certificate has expired',
      hint: 'renew the certificate; a token provider pins its certificate for life, so give the renewed one to a new provider',
    },
  };

  it('is refused in prepare() — already expired (fixture: 2020-01-01 to 2021-01-01)', async () => {
    const p = withMaterial({
      cert: read('expired.crt'),
      key: read('client.key'),
    });
    assert.deepEqual(wordsOf(await p.prepare()), EXPIRED);
    const t = recordingTargets();
    await p.establish(t.logonTarget);
    assert.equal(t.logon.tls.length, 0);
  });

  it('is refused at the logon once it expires after prepare(), nothing presented', async () => {
    const p = withMaterial({
      cert: read('client.crt'),
      key: read('client.key'),
    });
    assert.deepEqual(await p.prepare(), { ok: true });
    // client.crt is valid until 2126: the clock is moved past it, not crypto.
    const now = mock.method(Date, 'now', () => Date.UTC(2127, 0, 1));
    try {
      const t = recordingTargets();
      assert.deepEqual(wordsOf(await p.establish(t.logonTarget)), EXPIRED);
      assert.equal(t.logon.tls.length, 0);
    } finally {
      now.mock.restore();
    }
  });
});
