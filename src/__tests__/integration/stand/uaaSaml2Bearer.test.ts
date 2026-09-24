/**
 * Saml2BearerProvider against a real Cloud Foundry UAA — the open-source
 * server XSUAA is built from — started by tests/stand/up.sh.
 *
 * Runs only when UAA_URL is set (`npm run test:stand`); a plain `npm test`
 * skips it. What it proves that no unit test can: that the token endpoint of
 * a real server accepts what the provider sends, issues a refresh token for
 * the saml2-bearer grant exactly when the client may hold one, and takes that
 * refresh token back without an assertion.
 */

import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it, jest } from '@jest/globals';
import { signXml } from '@mcp-abap-adt/auth-mocks';
import type { IAuthorizationStrategy } from '@mcp-abap-adt/interfaces-auth';
import { Saml2BearerProvider } from '../../../providers/Saml2BearerProvider';
import { staticCodeStrategy } from '../../../strategies';

const UAA_URL = process.env.UAA_URL?.replace(/\/+$/, '');
const describeUaa = UAA_URL ? describe : describe.skip;

const GENERATED = join(__dirname, '../../../../tests/stand/.generated');

/**
 * A bearer assertion as RFC 7522 §2.1 wants it: one signed Assertion,
 * base64url-encoded. Issuer, Audience and Recipient are what tests/stand/uaa
 * configures: the `test-idp` provider and the `uaa-sp` service provider.
 */
function signedAssertionXml(): string {
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
    `<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="_${randomUUID()}" IssueInstant="${iso(now)}" Version="2.0">` +
    '<saml2:Issuer>test-idp</saml2:Issuer>' +
    '<saml2:Subject><saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">bearer-user</saml2:NameID>' +
    '<saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">' +
    `<saml2:SubjectConfirmationData NotOnOrAfter="${iso(until)}" Recipient="${recipient}"/>` +
    '</saml2:SubjectConfirmation></saml2:Subject>' +
    `<saml2:Conditions NotBefore="${iso(notBefore)}" NotOnOrAfter="${iso(until)}">` +
    '<saml2:AudienceRestriction><saml2:Audience>uaa-sp</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions>' +
    `<saml2:AuthnStatement AuthnInstant="${iso(now)}" SessionIndex="s1"><saml2:AuthnContext>` +
    '<saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml2:AuthnContextClassRef>' +
    '</saml2:AuthnContext></saml2:AuthnStatement>' +
    // `xs` appears only inside an attribute value, as IdPs typically write it.
    '<saml2:AttributeStatement><saml2:Attribute Name="role">' +
    '<saml2:AttributeValue xsi:type="xs:string">tester</saml2:AttributeValue>' +
    '</saml2:Attribute></saml2:AttributeStatement></saml2:Assertion>';
  return signXml(assertion, key);
}

function bearerAssertion(): string {
  return Buffer.from(signedAssertionXml(), 'utf8').toString('base64url');
}

/**
 * What a browser or ACS login actually delivers: the IdP's whole
 * `samlp:Response`, in standard base64. The `saml2` prefix is declared on the
 * Response only, so the Assertion inside relies on inherited namespaces —
 * `saml2` and `xsi` used in names, and `xs` used only inside the value of
 * `xsi:type`, which a serializer does not see as a namespace use.
 */
function samlResponse(): string {
  const declarations = [
    ' xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"',
    ' xmlns:xs="http://www.w3.org/2001/XMLSchema"',
    ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"',
  ];
  // Signed first, then moved: exclusive canonicalisation does not depend on
  // where a namespace is declared, so the signature still holds.
  const assertion = declarations.reduce(
    (xml, declaration) => xml.replace(declaration, ''),
    signedAssertionXml(),
  );
  const response =
    '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
    `${declarations.join('').trim()} ` +
    `ID="_${randomUUID()}" Version="2.0" IssueInstant="${new Date().toISOString()}">` +
    '<saml2:Issuer>test-idp</saml2:Issuer>' +
    '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
    `${assertion}</samlp:Response>`;
  return Buffer.from(response, 'utf8').toString('base64');
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

  // #37: RFC 7522 wants one base64url Assertion. UAA refuses a Response in
  // either encoding, so the provider has to take the Assertion out of it.
  it('exchanges the SAMLResponse an interactive login delivers', async () => {
    const tokens = await new Saml2BearerProvider({
      ...baseConfig('saml_rt'),
      authorization: staticCodeStrategy({ payload: samlResponse() }),
    }).getTokens();

    expect(issuerOf(tokens.authorizationToken)).toBe(`${UAA_URL}/oauth/token`);
    expect(tokens.refreshToken).toEqual(expect.any(String));
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
