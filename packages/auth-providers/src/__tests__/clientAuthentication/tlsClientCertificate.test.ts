import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it, mock } from 'node:test';
import { readFailure } from '@mcp-abap-adt/auth-errors';
import type { ICertificateMaterial } from '@mcp-abap-adt/interfaces-auth';
import { tlsClientCertificate } from '../../clientAuthentication';
import { matchObject, thrown } from '../helpers/expectations';
import { refusedWith, wordsOf } from '../helpers/minted';
import { CERTIFICATES } from '../helpers/packagePaths';

const dir = CERTIFICATES;
const pem: ICertificateMaterial = {
  cert: readFileSync(join(dir, 'client.crt')),
  key: readFileSync(join(dir, 'client.key')),
};
const pfx: ICertificateMaterial = {
  pfx: readFileSync(join(dir, 'client.pfx')),
  passphrase: 'test-passphrase',
};

const base = {
  endpoint: 'https://uaa.example/oauth/token',
  clientId: 'my-client',
  grantType: 'client_credentials',
};
const withAlias = { ...base, mtlsEndpoint: 'https://mtls.uaa.example/token' };

describe('tlsClientCertificate — what it sends and where', () => {
  it('sends client_id only, to the explicit endpoint first', async () => {
    const sent = await tlsClientCertificate({
      material: pem,
      endpoint: 'https://certurl.example/oauth/token',
    }).authenticate(withAlias);
    assert.deepEqual(sent, {
      endpoint: 'https://certurl.example/oauth/token',
      parameters: { client_id: 'my-client' },
    });
  });
  it('else to the draft mtlsEndpoint', async () => {
    const sent = await tlsClientCertificate({ material: pem }).authenticate(
      withAlias,
    );
    assert.equal(sent.endpoint, 'https://mtls.uaa.example/token');
  });
  it('else to the draft endpoint', async () => {
    const sent = await tlsClientCertificate({ material: pem }).authenticate(
      base,
    );
    assert.equal(sent.endpoint, base.endpoint);
  });
  it('sends no header and no secret', async () => {
    const sent = await tlsClientCertificate({ material: pem }).authenticate(
      base,
    );
    assert.equal(sent.headers, undefined);
    assert.deepEqual(Object.keys(sent.parameters ?? {}), ['client_id']);
  });
});

describe('tlsClientCertificate — the material', () => {
  it('returns the checked material from tlsMaterial()', async () => {
    const auth = tlsClientCertificate({ material: pfx });
    assert.equal(await auth.tlsMaterial?.(), pfx);
  });
  it('reads a loader once across concurrent and later calls', async () => {
    const loader = mock.fn(async () => pem);
    const auth = tlsClientCertificate({ material: loader });
    await Promise.all([
      auth.authenticate(base),
      auth.authenticate(base),
      auth.tlsMaterial?.(),
    ]);
    await auth.authenticate(base);
    assert.equal(loader.mock.callCount(), 1);
  });
  it('does not read the loader before first use', () => {
    const loader = mock.fn(async () => pem);
    tlsClientCertificate({ material: loader });
    assert.equal(loader.mock.callCount(), 0);
  });
  it('refuses incomplete material as incomplete, in the 5.2.3 words', async () => {
    const auth = tlsClientCertificate({ material: { cert: pem.cert! } });
    const e = await auth.authenticate(base).catch((x) => x);
    // A client-certificate failure, no longer the class.
    matchObject(readFailure(e, 'unfamiliar-error'), {
      kind: 'client-certificate',
      facts: { problem: 'incomplete' },
    });
    assert.deepEqual(wordsOf(refusedWith(e)), {
      ok: false,
      refusal: {
        reason: 'the client certificate is incomplete',
        hint: 'give a PFX, or a certificate together with its key',
      },
    });
  });
  it('refuses unusable material as unusable, from tlsMaterial() too', async () => {
    const auth = tlsClientCertificate({
      material: { pfx: pfx.pfx!, passphrase: 'wrong' },
    });
    const e = await auth.tlsMaterial?.().catch((x) => x);
    // A client-certificate failure, no longer the class.
    matchObject(readFailure(e, 'unfamiliar-error'), {
      kind: 'client-certificate',
      facts: { problem: 'unusable' },
    });
    matchObject(refusedWith(e), {
      refusal: { reason: 'the client certificate could not be used' },
    });
  });
  it('retries after a failed load; a success stays memoized', async () => {
    const loader = mock.fn<() => Promise<ICertificateMaterial>>(
      async () => pem,
    );
    loader.mock.mockImplementationOnce(async () => {
      throw new Error('mid-rotation');
    }, 0);
    const auth = tlsClientCertificate({ material: loader });
    await assert.rejects(auth.authenticate(base), thrown('mid-rotation'));
    assert.notEqual(await auth.authenticate(base), undefined);
    await auth.authenticate(base);
    assert.equal(loader.mock.callCount(), 2);
  });
  it('shares one failing load among concurrent callers', async () => {
    const boom = new Error('timeout');
    const loader = mock.fn(async (): Promise<ICertificateMaterial> => {
      throw boom;
    });
    const auth = tlsClientCertificate({ material: loader });
    const results = await Promise.allSettled([
      auth.authenticate(base),
      auth.authenticate(base),
      auth.tlsMaterial?.(),
    ]);
    assert.equal(loader.mock.callCount(), 1);
    for (const r of results) {
      assert.equal(r.status, 'rejected');
      assert.equal((r as PromiseRejectedResult).reason, boom);
    }
  });
  it('retries after unusable material too', async () => {
    const loader = mock.fn<() => Promise<ICertificateMaterial>>(
      async () => pem,
    );
    loader.mock.mockImplementationOnce(async () => ({ cert: pem.cert! }), 0);
    const auth = tlsClientCertificate({ material: loader });
    // A client-certificate failure, no longer the class.
    await assert.rejects(auth.authenticate(base), (error) => {
      matchObject(error, {
        error: { kind: 'client-certificate', facts: { problem: 'incomplete' } },
      });
      return true;
    });
    assert.notEqual(await auth.authenticate(base), undefined);
  });
});

describe('tlsClientCertificate — its configuration is read once, as a typed copy', () => {
  it('fixes the material and the endpoint at creation', async () => {
    const config: Parameters<typeof tlsClientCertificate>[0] = {
      material: pem,
      endpoint: 'https://first.example/token',
    };
    const auth = tlsClientCertificate(config);
    config.material = { cert: pem.cert! };
    config.endpoint = 'https://second.example/token';
    assert.deepEqual(await auth.authenticate(base), {
      endpoint: 'https://first.example/token',
      parameters: { client_id: 'my-client' },
    });
  });
  it('calls a loader as the configuration object’s method, as before', async () => {
    const config = {
      pem,
      async material(this: { pem: ICertificateMaterial }) {
        return this.pem;
      },
    };
    assert.notEqual(
      await tlsClientCertificate(config).authenticate(base),
      undefined,
    );
  });
  it('runs an endpoint getter once, at creation', async () => {
    let reads = 0;
    const config = {
      material: pem,
      get endpoint() {
        reads += 1;
        return 'https://getter.example/token';
      },
    };
    const auth = tlsClientCertificate(config);
    assert.equal(reads, 1);
    const sent = await auth.authenticate(withAlias);
    assert.equal(reads, 1);
    assert.equal(sent.endpoint, 'https://getter.example/token');
  });
  it('runs a material getter once, at creation', async () => {
    let reads = 0;
    const config = {
      get material() {
        reads += 1;
        return pem;
      },
    };
    const auth = tlsClientCertificate(config);
    assert.equal(reads, 1);
    await auth.authenticate(base);
    await auth.authenticate(base);
    assert.equal(reads, 1);
  });
});
