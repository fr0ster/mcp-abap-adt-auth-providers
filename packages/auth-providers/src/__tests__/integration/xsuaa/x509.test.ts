/**
 * A client certificate instead of a secret, against a real XSUAA: the x509
 * service key tests/xsuaa/setup.sh creates on the application instance
 * (`credential-types: ["binding-secret", "x509"]`, key parameter
 * `{"credential-type": "x509"}`) and teardown.sh removes. `npm run
 * test:xsuaa` does both around this suite. Not part of CI: it needs a
 * subaccount.
 *
 * Runs only when XSUAA_LOCAL points at the directory setup.sh filled; the
 * suite's title says why it is skipped otherwise.
 *
 * The key carries `certificate` (a PEM chain), `key` (its PEM private key),
 * `certurl` (the mTLS host), `url` and `clientid` — and no `clientsecret`.
 * The test maps those fields as a consumer would: nothing in this package
 * reads a service key.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from '@jest/globals';
import { tlsClientCertificate } from '../../../clientAuthentication';
import {
  ClientCredentialsProvider,
  type ClientCredentialsProviderConfig,
} from '../../../providers/ClientCredentialsProvider';
import { refreshThenLogin } from '../../../renewal';

const LOCAL = process.env.XSUAA_LOCAL;
const describeXsuaa = LOCAL ? describe : describe.skip;
const unlessSet = LOCAL
  ? ''
  : ' — skipped: XSUAA_LOCAL is not set (npm run test:xsuaa sets it)';

/** A token's claims; {} for anything unreadable, whose parse error would quote it. */
const claims = (jwt: string): Record<string, unknown> => {
  try {
    return JSON.parse(
      Buffer.from(jwt.split('.')[1]!, 'base64url').toString('utf8'),
    );
  } catch {
    return {};
  }
};

interface X509Key {
  url: string;
  certurl: string;
  clientid: string;
  certificate: string;
  key: string;
  clientsecret?: string;
}

describeXsuaa(`An x509 service key against a real XSUAA${unlessSet}`, () => {
  let x509: X509Key;

  beforeAll(() => {
    // A parse error quotes part of its input — here, part of a private key.
    let key: { credentials?: X509Key } & X509Key;
    try {
      key = JSON.parse(
        readFileSync(join(LOCAL as string, 'x509-key.json'), 'utf8'),
      );
    } catch {
      throw new Error('x509-key.json is not JSON');
    }
    x509 = key.credentials ?? key;
  });

  // Jest prints the received value when a matcher fails: every assertion on
  // the key's material or on a token is made on a boolean projection of it,
  // so a failure never echoes a private key, a certificate or a token.
  it('the key holds a certificate, its key and the mTLS host — and no secret', () => {
    expect(
      typeof x509.certificate === 'string' &&
        x509.certificate.includes('-----BEGIN CERTIFICATE-----'),
    ).toBe(true);
    expect(
      typeof x509.key === 'string' && x509.key.includes('PRIVATE KEY-----'),
    ).toBe(true);
    expect(x509.certurl).toMatch(/^https:\/\//);
    expect(typeof x509.clientid).toBe('string');
    expect('clientsecret' in x509).toBe(false);
  });

  it('ClientCredentialsProvider gets a client token over mTLS at certurl, with no secret anywhere', async () => {
    const config: ClientCredentialsProviderConfig = {
      renewal: refreshThenLogin(),
      uaaUrl: x509.url,
      clientId: x509.clientid,
      // The provider's uaaUrl builds <url>/oauth/token, which takes a secret;
      // the certificate is presented at the key's certurl instead.
      clientAuthentication: tlsClientCertificate({
        material: { cert: x509.certificate, key: x509.key },
        endpoint: `${x509.certurl}/oauth/token`,
      }),
    };
    // The client authenticates with its certificate: no secret is given.
    expect('clientSecret' in config).toBe(false);

    const provider = new ClientCredentialsProvider(config);
    expect(await provider.prepare()).toEqual({ ok: true });

    // prepare() obtained the token; getTokens() hands back the one it holds.
    // Only the claims are read and compared — never the token itself.
    const token = claims((await provider.getTokens()).authorizationToken);
    expect(token.client_id ?? token.cid).toBe(x509.clientid);
    expect(token.grant_type).toBe('client_credentials');
  });
});
