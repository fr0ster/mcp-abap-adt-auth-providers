import { generateKeyPairSync, type KeyObject, verify } from 'node:crypto';
import { describe, expect, it } from '@jest/globals';
import { isAuthProviderFailure, readFailure } from '@mcp-abap-adt/auth-errors';
import type { ITokenRequestDraft } from '@mcp-abap-adt/interfaces-auth';
import { privateKeyJwt } from '../../clientAuthentication';
import { refusedWith, wordsOf } from '../helpers/minted';

const draft = {
  endpoint: 'https://uaa.example/oauth/token',
  mtlsEndpoint: 'https://mtls.uaa.example/token',
  clientId: 'my-client',
  grantType: 'client_credentials',
};
const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const ec384 = generateKeyPairSync('ec', { namedCurve: 'P-384' });

const JWT_BEARER = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

function parts(jwt: string) {
  const [h = '', p = '', s = ''] = jwt.split('.');
  return {
    header: JSON.parse(Buffer.from(h, 'base64url').toString()),
    claims: JSON.parse(Buffer.from(p, 'base64url').toString()),
    signingInput: Buffer.from(`${h}.${p}`),
    signature: Buffer.from(s, 'base64url'),
  };
}

async function assertion(
  config: Parameters<typeof privateKeyJwt>[0],
  d: ITokenRequestDraft = draft,
) {
  const sent = await privateKeyJwt(config).authenticate(d);
  return { sent, jwt: sent.parameters?.client_assertion as string };
}

describe('privateKeyJwt — the request', () => {
  it('sends client_id, the jwt-bearer type and the assertion, and keeps the endpoint', async () => {
    const { sent, jwt } = await assertion({
      key: rsa.privateKey,
      algorithm: 'RS256',
    });
    expect(sent.endpoint).toBeUndefined();
    expect(sent.headers).toBeUndefined();
    expect(sent.parameters).toEqual({
      client_id: 'my-client',
      client_assertion_type: JWT_BEARER,
      client_assertion: jwt,
    });
  });
  it('presents no TLS material', () => {
    expect(
      privateKeyJwt({ key: rsa.privateKey, algorithm: 'RS256' }).tlsMaterial,
    ).toBeUndefined();
  });
});

describe('privateKeyJwt — claims and header', () => {
  it('iss = sub = client id, aud = the endpoint the request goes to, exp = iat + 60', async () => {
    const before = Math.floor(Date.now() / 1000);
    const { jwt } = await assertion({
      key: rsa.privateKey,
      algorithm: 'RS256',
    });
    const { header, claims } = parts(jwt);
    expect(header).toEqual({ alg: 'RS256', typ: 'JWT' });
    expect(claims.iss).toBe('my-client');
    expect(claims.sub).toBe('my-client');
    expect(claims.aud).toBe(draft.endpoint);
    expect(claims.iat).toBeGreaterThanOrEqual(before);
    expect(claims.iat).toBeLessThanOrEqual(before + 5);
    expect(claims.exp - claims.iat).toBe(60);
    expect(Object.keys(claims).sort()).toEqual(
      ['aud', 'exp', 'iat', 'iss', 'jti', 'sub'].sort(),
    );
  });
  it('aud is the draft tokenEndpoint when there is one and no audience — not the endpoint', async () => {
    const { jwt } = await assertion(
      { key: rsa.privateKey, algorithm: 'RS256' },
      {
        ...draft,
        endpoint: 'https://idp.example/device',
        tokenEndpoint: 'https://idp.example/token',
      },
    );
    expect(parts(jwt).claims.aud).toBe('https://idp.example/token');
  });
  it('the configured audience wins over the draft tokenEndpoint', async () => {
    const { jwt } = await assertion(
      {
        key: rsa.privateKey,
        algorithm: 'RS256',
        audience: 'https://issuer.example',
      },
      { ...draft, tokenEndpoint: 'https://idp.example/token' },
    );
    expect(parts(jwt).claims.aud).toBe('https://issuer.example');
  });
  it('aud is the configured audience when given', async () => {
    const { jwt } = await assertion({
      key: rsa.privateKey,
      algorithm: 'RS256',
      audience: 'https://issuer.example',
    });
    expect(parts(jwt).claims.aud).toBe('https://issuer.example');
  });
  it('jti is unique per call', async () => {
    const auth = privateKeyJwt({ key: rsa.privateKey, algorithm: 'RS256' });
    const a = parts(
      (await auth.authenticate(draft)).parameters?.client_assertion as string,
    );
    const b = parts(
      (await auth.authenticate(draft)).parameters?.client_assertion as string,
    );
    expect(a.claims.jti).not.toBe(b.claims.jti);
    expect(a.claims.jti).toMatch(/^[0-9a-f-]{36}$/);
  });
  it('kid only with keyId', async () => {
    const { jwt } = await assertion({
      key: rsa.privateKey,
      algorithm: 'RS256',
      keyId: 'key-1',
    });
    expect(parts(jwt).header).toEqual({
      alg: 'RS256',
      typ: 'JWT',
      kid: 'key-1',
    });
  });
});

describe('privateKeyJwt — signatures verify with the public key', () => {
  it('RS256', async () => {
    const { jwt } = await assertion({
      key: rsa.privateKey,
      algorithm: 'RS256',
    });
    const p = parts(jwt);
    expect(verify('sha256', p.signingInput, rsa.publicKey, p.signature)).toBe(
      true,
    );
  });
  it('ES256 as raw r||s of 64 bytes', async () => {
    const { jwt } = await assertion({ key: ec.privateKey, algorithm: 'ES256' });
    const p = parts(jwt);
    expect(p.header.alg).toBe('ES256');
    expect(p.signature.length).toBe(64);
    expect(
      verify(
        'sha256',
        p.signingInput,
        { key: ec.publicKey, dsaEncoding: 'ieee-p1363' },
        p.signature,
      ),
    ).toBe(true);
  });
  it('accepts a PEM string and a PEM Buffer', async () => {
    const pem = rsa.privateKey.export({ type: 'pkcs8', format: 'pem' });
    for (const key of [pem as string, Buffer.from(pem as string)]) {
      const { jwt } = await assertion({ key, algorithm: 'RS256' });
      const p = parts(jwt);
      expect(verify('sha256', p.signingInput, rsa.publicKey, p.signature)).toBe(
        true,
      );
    }
  });
});

describe('privateKeyJwt — a key that does not fit', () => {
  const cases: Array<[string, KeyObject | string, 'RS256' | 'ES256']> = [
    ['an EC key for RS256', ec.privateKey, 'RS256'],
    ['an RSA key for ES256', rsa.privateKey, 'ES256'],
    ['a P-384 key for ES256', ec384.privateKey, 'ES256'],
    ['a public key', rsa.publicKey, 'RS256'],
    ['garbage', 'not a key', 'RS256'],
  ];
  // A6 (Task 26): an AuthProviderFailure of client-authentication, no
  // longer a ClientAuthenticationError.
  it.each(cases)(
    'refuses %s as client-authentication signing-key-unusable (A6)',
    async (_n, key, algorithm) => {
      const e = await privateKeyJwt({ key, algorithm })
        .authenticate(draft)
        .catch((x) => x);
      expect(isAuthProviderFailure(e)).toBe(true);
      expect(readFailure(e, 'unfamiliar-error')).toMatchObject({
        kind: 'client-authentication',
        facts: { problem: 'signing-key-unusable' },
      });
    },
  );
  it('answers fixed words with no key bytes', async () => {
    const pem = ec.privateKey.export({
      type: 'pkcs8',
      format: 'pem',
    }) as string;
    const e = await privateKeyJwt({ key: pem, algorithm: 'RS256' })
      .authenticate(draft)
      .catch((x) => x);
    const outcome = refusedWith(e);
    expect(wordsOf(outcome)).toEqual({
      ok: false,
      refusal: {
        reason: 'the client signing key could not be used',
        hint: 'check the private key and that it matches the algorithm',
      },
    });
    const body = pem.split('\n')[1];
    expect(JSON.stringify(outcome)).not.toContain(body);
    expect((e as Error).message).not.toContain(body);
  });
});
