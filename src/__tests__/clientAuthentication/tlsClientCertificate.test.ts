import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it, jest } from '@jest/globals';
import { readFailure } from '@mcp-abap-adt/auth-errors';
import type { ICertificateMaterial } from '@mcp-abap-adt/interfaces-auth';
import { refusalFrom } from '../../auth/refusal';
import { tlsClientCertificate } from '../../clientAuthentication';
import { wordsOf } from '../helpers/minted';

const dir = join(__dirname, '..', 'fixtures', 'certificates');
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
    expect(sent).toEqual({
      endpoint: 'https://certurl.example/oauth/token',
      parameters: { client_id: 'my-client' },
    });
  });
  it('else to the draft mtlsEndpoint', async () => {
    const sent = await tlsClientCertificate({ material: pem }).authenticate(
      withAlias,
    );
    expect(sent.endpoint).toBe('https://mtls.uaa.example/token');
  });
  it('else to the draft endpoint', async () => {
    const sent = await tlsClientCertificate({ material: pem }).authenticate(
      base,
    );
    expect(sent.endpoint).toBe(base.endpoint);
  });
  it('sends no header and no secret', async () => {
    const sent = await tlsClientCertificate({ material: pem }).authenticate(
      base,
    );
    expect(sent.headers).toBeUndefined();
    expect(Object.keys(sent.parameters ?? {})).toEqual(['client_id']);
  });
});

describe('tlsClientCertificate — the material', () => {
  it('returns the checked material from tlsMaterial()', async () => {
    const auth = tlsClientCertificate({ material: pfx });
    expect(await auth.tlsMaterial?.()).toBe(pfx);
  });
  it('reads a loader once across concurrent and later calls', async () => {
    const loader = jest.fn(async () => pem);
    const auth = tlsClientCertificate({ material: loader });
    await Promise.all([
      auth.authenticate(base),
      auth.authenticate(base),
      auth.tlsMaterial?.(),
    ]);
    await auth.authenticate(base);
    expect(loader).toHaveBeenCalledTimes(1);
  });
  it('does not read the loader before first use', () => {
    const loader = jest.fn(async () => pem);
    tlsClientCertificate({ material: loader });
    expect(loader).not.toHaveBeenCalled();
  });
  it('refuses incomplete material as incomplete, in the 5.2.3 words', async () => {
    const auth = tlsClientCertificate({ material: { cert: pem.cert! } });
    const e = await auth.authenticate(base).catch((x) => x);
    // A4 (Task 26): a client-certificate failure, no longer the class.
    expect(readFailure(e, 'unfamiliar-error')).toMatchObject({
      kind: 'client-certificate',
      facts: { problem: 'incomplete' },
    });
    expect(wordsOf(refusalFrom(e, 'x'))).toEqual({
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
    // A4 (Task 26): a client-certificate failure, no longer the class.
    expect(readFailure(e, 'unfamiliar-error')).toMatchObject({
      kind: 'client-certificate',
      facts: { problem: 'unusable' },
    });
    expect(refusalFrom(e, 'x')).toMatchObject({
      refusal: { reason: 'the client certificate could not be used' },
    });
  });
  it('retries after a failed load; a success stays memoized', async () => {
    const loader = jest
      .fn<() => Promise<ICertificateMaterial>>()
      .mockRejectedValueOnce(new Error('mid-rotation'))
      .mockResolvedValue(pem);
    const auth = tlsClientCertificate({ material: loader });
    await expect(auth.authenticate(base)).rejects.toThrow('mid-rotation');
    await expect(auth.authenticate(base)).resolves.toBeDefined();
    await auth.authenticate(base);
    expect(loader).toHaveBeenCalledTimes(2);
  });
  it('shares one failing load among concurrent callers', async () => {
    const boom = new Error('timeout');
    const loader = jest.fn(async (): Promise<ICertificateMaterial> => {
      throw boom;
    });
    const auth = tlsClientCertificate({ material: loader });
    const results = await Promise.allSettled([
      auth.authenticate(base),
      auth.authenticate(base),
      auth.tlsMaterial?.(),
    ]);
    expect(loader).toHaveBeenCalledTimes(1);
    for (const r of results) {
      expect(r.status).toBe('rejected');
      expect((r as PromiseRejectedResult).reason).toBe(boom);
    }
  });
  it('retries after unusable material too', async () => {
    const loader = jest
      .fn<() => Promise<ICertificateMaterial>>()
      .mockResolvedValueOnce({ cert: pem.cert! })
      .mockResolvedValue(pem);
    const auth = tlsClientCertificate({ material: loader });
    // A4 (Task 26): a client-certificate failure, no longer the class.
    await expect(auth.authenticate(base)).rejects.toMatchObject({
      error: { kind: 'client-certificate', facts: { problem: 'incomplete' } },
    });
    await expect(auth.authenticate(base)).resolves.toBeDefined();
  });
});
