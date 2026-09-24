/**
 * Saml2BearerProvider against a real Cloud Foundry UAA — the open-source
 * server XSUAA is built from — started by tests/uaa/up.sh.
 *
 * Runs only when UAA_URL is set (`npm run test:uaa`); a plain `npm test`
 * skips it. What it proves that no unit test can: that the token endpoint of
 * a real server accepts what the provider sends, issues a refresh token for
 * the saml2-bearer grant exactly when the client may hold one, and takes that
 * refresh token back without an assertion.
 */

import { randomUUID } from 'node:crypto';
import { setDefaultResultOrder } from 'node:dns';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it, jest } from '@jest/globals';
import { signXml } from '@mcp-abap-adt/auth-mocks';
import type { IAuthorizationStrategy } from '@mcp-abap-adt/interfaces-auth';
import { Saml2BearerProvider } from '../../providers/Saml2BearerProvider';
import { staticCodeStrategy } from '../../strategies';

// The stand publishes only on 127.0.0.1. Node 18 resolves `localhost` to ::1
// first and does not fall back, so without this every request is refused.
setDefaultResultOrder('ipv4first');

const UAA_URL = process.env.UAA_URL?.replace(/\/+$/, '');
const describeUaa = UAA_URL ? describe : describe.skip;

const GENERATED = join(__dirname, '../../../tests/uaa/.generated');

/**
 * A bearer assertion as RFC 7522 §2.1 wants it: one signed Assertion,
 * base64url-encoded. Issuer, Audience and Recipient are what tests/uaa
 * configures: the `test-idp` provider and the `uaa-sp` service provider.
 */
function bearerAssertion(): string {
  const key = {
    privateKeyPem: readFileSync(join(GENERATED, 'idp.key'), 'utf8'),
    certificatePem: readFileSync(join(GENERATED, 'idp.crt'), 'utf8'),
  };
  const iso = (d: Date) => d.toISOString().replace(/\.\d+Z$/, 'Z');
  const now = new Date();
  const until = new Date(now.getTime() + 10 * 60_000);
  const notBefore = new Date(now.getTime() - 5_000);
  const recipient = `${UAA_URL}/oauth/token/alias/uaa-sp`;
  const assertion =
    `<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_${randomUUID()}" IssueInstant="${iso(now)}" Version="2.0">` +
    '<saml2:Issuer>test-idp</saml2:Issuer>' +
    '<saml2:Subject><saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">bearer-user</saml2:NameID>' +
    '<saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">' +
    `<saml2:SubjectConfirmationData NotOnOrAfter="${iso(until)}" Recipient="${recipient}"/>` +
    '</saml2:SubjectConfirmation></saml2:Subject>' +
    `<saml2:Conditions NotBefore="${iso(notBefore)}" NotOnOrAfter="${iso(until)}">` +
    '<saml2:AudienceRestriction><saml2:Audience>uaa-sp</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions>' +
    `<saml2:AuthnStatement AuthnInstant="${iso(now)}" SessionIndex="s1"><saml2:AuthnContext>` +
    '<saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml2:AuthnContextClassRef>' +
    '</saml2:AuthnContext></saml2:AuthnStatement></saml2:Assertion>';
  return Buffer.from(signXml(assertion, key), 'utf8').toString('base64url');
}

/** Unsigned, and never sent anywhere: only its `exp` is read, to force a refresh. */
const expiredJwt = (): string => {
  const encode = (value: object) =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  const exp = Math.floor(Date.now() / 1000) - 3600;
  return `${encode({ alg: 'none' })}.${encode({ exp })}.sig`;
};

const issuerOf = (jwt: string): string =>
  JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString('utf8')).iss;

const baseConfig = (clientId: string) => ({
  idpSsoUrl: 'http://test-idp.invalid/sso',
  spEntityId: 'uaa-sp',
  uaaUrl: UAA_URL as string,
  clientId,
  clientSecret: 'secret',
});

describeUaa('Saml2BearerProvider against Cloud Foundry UAA', () => {
  it('exchanges a bearer assertion and receives a refresh token when the client may hold one', async () => {
    const tokens = await new Saml2BearerProvider({
      ...baseConfig('saml_rt'),
      authorization: staticCodeStrategy({ payload: bearerAssertion() }),
    }).getTokens();

    expect(issuerOf(tokens.authorizationToken)).toBe(`${UAA_URL}/oauth/token`);
    expect(tokens.refreshToken).toEqual(expect.any(String));
  });

  it('spends that refresh token without running the authorization strategy', async () => {
    const first = await new Saml2BearerProvider({
      ...baseConfig('saml_rt'),
      authorization: staticCodeStrategy({ payload: bearerAssertion() }),
    }).getTokens();

    const authorize = jest.fn(async () => {
      throw new Error('the refresh must not reach the authorization strategy');
    });
    const refreshed = await new Saml2BearerProvider({
      ...baseConfig('saml_rt'),
      accessToken: expiredJwt(),
      refreshToken: first.refreshToken,
      authorization: { authorize } as unknown as IAuthorizationStrategy<string>,
    }).getTokens();

    expect(authorize).not.toHaveBeenCalled();
    expect(issuerOf(refreshed.authorizationToken)).toBe(
      `${UAA_URL}/oauth/token`,
    );
    expect(refreshed.authorizationToken).not.toBe(first.authorizationToken);
    expect(refreshed.refreshToken).toEqual(expect.any(String));
  });

  it('receives no refresh token when the client may not hold one', async () => {
    const tokens = await new Saml2BearerProvider({
      ...baseConfig('saml_nort'),
      authorization: staticCodeStrategy({ payload: bearerAssertion() }),
    }).getTokens();

    expect(issuerOf(tokens.authorizationToken)).toBe(`${UAA_URL}/oauth/token`);
    expect(tokens.refreshToken).toBeUndefined();
  });
});
