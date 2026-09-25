/**
 * Live checks against a real XSUAA, in an environment tests/xsuaa/setup.sh
 * creates in a BTP subaccount and teardown.sh removes. `npm run test:xsuaa`
 * does both around this suite. Not part of CI: it needs a subaccount.
 *
 * Runs only when XSUAA_LOCAL points at the directory setup.sh filled — the
 * service key, and the test identity provider's key generated there.
 *
 * - Saml2BearerProvider: an IdP-initiated assertion (no InResponseTo) is
 *   exchanged and a refresh token issued; a whole SAMLResponse is converted
 *   by the provider; the refresh never reaches the strategy; an assertion
 *   carrying InResponseTo — the answer to an AuthnRequest — is refused by the
 *   provider's own validator before XSUAA sees it. Every login is validated
 *   against the per-run test IdP certificate, and declares `idpInitiated:
 *   true`, since none of these assertions answers a request.
 * - UaaPasscodeProvider, only when XSUAA_PASSCODE holds a one-time code
 *   fetched from <xsuaa>/passcode: it is exchanged, and refreshed.
 */

import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, describe, expect, it, jest } from '@jest/globals';
import { signXml } from '@mcp-abap-adt/auth-mocks';
import type { IAuthorizationStrategy } from '@mcp-abap-adt/interfaces-auth';
import { AssertionValidationError } from '../../../errors/AssertionValidationError';
import { Saml2BearerProvider } from '../../../providers/Saml2BearerProvider';
import { UaaPasscodeProvider } from '../../../providers/UaaPasscodeProvider';
import { staticCodeStrategy } from '../../../strategies';

const LOCAL = process.env.XSUAA_LOCAL;
const PASSCODE = process.env.XSUAA_PASSCODE;
const describeXsuaa = LOCAL ? describe : describe.skip;
const itWithPasscode = PASSCODE ? it : it.skip;

const ORIGIN = 'auth-providers-test-idp';

const claims = (jwt: string): Record<string, unknown> =>
  JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString('utf8'));

/** Unsigned, never sent: only its `exp` is read, to force a refresh. */
const expiredJwt = (): string => {
  const encode = (value: object) =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode({ alg: 'none' })}.${encode({ exp: Math.floor(Date.now() / 1000) - 3600 })}.sig`;
};

/** A logger recording every message, to tell whether a token exchange began. */
const recordingLogger = () => {
  const messages: string[] = [];
  const failures: unknown[] = [];
  const logger = {
    info: (message: string) => messages.push(message),
    warn: (message: string) => messages.push(message),
    debug: (message: string) => messages.push(message),
    error: (message: string, meta?: unknown) => {
      messages.push(message);
      failures.push(meta);
    },
  };
  return { logger, messages, failures };
};

const EXCHANGE_STARTED = '[SAML] Exchanging assertion for token';

const refuseStrategy = () => {
  const authorize = jest.fn(async () => {
    throw new Error('a refresh must not reach the authorization strategy');
  });
  return {
    authorize,
    strategy: { authorize } as unknown as IAuthorizationStrategy<string>,
  };
};

describeXsuaa('Providers against a real XSUAA', () => {
  const read = (file: string) =>
    readFileSync(join(LOCAL as string, file), 'utf8');
  let credentials: { url: string; clientid: string; clientsecret: string };
  let entityId = '';
  let bearerAcs = '';

  beforeAll(async () => {
    const key = JSON.parse(read('bearer-key.json'));
    credentials = key.credentials ?? key;
    // XSUAA's service provider identity, from its own SAML metadata.
    const metadata = await (
      await fetch(`${credentials.url}/saml/metadata`)
    ).text();
    entityId = /entityID="([^"]+)"/.exec(metadata)?.[1] ?? '';
    bearerAcs =
      /AssertionConsumerService[^>]*bindings:URI"[^>]*Location="([^"]+)"/.exec(
        metadata,
      )?.[1] ?? '';
    expect(bearerAcs).toMatch(/\/oauth\/token\/alias\//);
  });

  /** A signed Assertion from the test IdP, as XSUAA's trust expects it. */
  const assertion = (inResponseTo?: string): string => {
    const iso = (d: Date) => d.toISOString().replace(/\.\d+Z$/, 'Z');
    const now = new Date();
    const until = new Date(now.getTime() + 10 * 60_000);
    const notBefore = new Date(now.getTime() - 5_000);
    const xml =
      `<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_${randomUUID()}" IssueInstant="${iso(now)}" Version="2.0">` +
      `<saml2:Issuer>${ORIGIN}</saml2:Issuer>` +
      '<saml2:Subject><saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">bearer-tester</saml2:NameID>' +
      '<saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">' +
      `<saml2:SubjectConfirmationData NotOnOrAfter="${iso(until)}" Recipient="${bearerAcs}"` +
      `${inResponseTo ? ` InResponseTo="${inResponseTo}"` : ''}/>` +
      '</saml2:SubjectConfirmation></saml2:Subject>' +
      `<saml2:Conditions NotBefore="${iso(notBefore)}" NotOnOrAfter="${iso(until)}">` +
      `<saml2:AudienceRestriction><saml2:Audience>${entityId}</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions>` +
      `<saml2:AuthnStatement AuthnInstant="${iso(now)}" SessionIndex="s1"><saml2:AuthnContext>` +
      '<saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml2:AuthnContextClassRef>' +
      '</saml2:AuthnContext></saml2:AuthnStatement></saml2:Assertion>';
    return signXml(xml, {
      privateKeyPem: read('idp.key'),
      certificatePem: read('idp.crt'),
    });
  };

  const bearer = (payload: string, extra: object = {}) =>
    new Saml2BearerProvider({
      idpSsoUrl: `https://${ORIGIN}.invalid/sso`,
      spEntityId: entityId,
      acsUrl: bearerAcs,
      uaaUrl: credentials.url,
      clientId: credentials.clientid,
      clientSecret: credentials.clientsecret,
      authorization: staticCodeStrategy({ redirectUri: bearerAcs, payload }),
      // The per-run key setup.sh generated and registered as XSUAA's trust.
      idpCertificates: [read('idp.crt')],
      idpEntityId: ORIGIN,
      // No AuthnRequest is sent: an assertion answering one must be refused.
      idpInitiated: true,
      ...extra,
    });

  it('Saml2BearerProvider: an IdP-initiated assertion becomes a token with a refresh token', async () => {
    const { logger, messages } = recordingLogger();
    const tokens = await bearer(
      Buffer.from(assertion()).toString('base64url'),
      { logger },
    ).getTokens();

    // The control for the InResponseTo case: an exchange that happens is seen.
    expect(messages).toContain(EXCHANGE_STARTED);

    const token = claims(tokens.authorizationToken);
    expect(token.origin).toBe(ORIGIN);
    expect(token.grant_type).toBe(
      'urn:ietf:params:oauth:grant-type:saml2-bearer',
    );
    expect(tokens.refreshToken).toEqual(expect.any(String));
  });

  it('Saml2BearerProvider: a whole SAMLResponse is converted and accepted', async () => {
    const response =
      '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
      `ID="_${randomUUID()}" Version="2.0" IssueInstant="${new Date().toISOString()}">` +
      '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
      `${assertion()}</samlp:Response>`;

    const tokens = await bearer(
      Buffer.from(response).toString('base64'),
    ).getTokens();

    expect(claims(tokens.authorizationToken).origin).toBe(ORIGIN);
  });

  it('Saml2BearerProvider: a refresh never reaches the strategy', async () => {
    const first = await bearer(
      Buffer.from(assertion()).toString('base64url'),
    ).getTokens();
    const { authorize, strategy } = refuseStrategy();

    const refreshed = await bearer('unused', {
      accessToken: expiredJwt(),
      refreshToken: first.refreshToken,
      authorization: strategy,
    }).getTokens();

    expect(authorize).not.toHaveBeenCalled();
    expect(refreshed.authorizationToken).not.toBe(first.authorizationToken);
  });

  // Option B: with no request ID expected, an InResponseTo is refused by the
  // provider's validator. XSUAA refused it too ("No subject confirmation
  // methods were met"), but no longer gets the chance.
  it('Saml2BearerProvider: an assertion carrying InResponseTo is refused before XSUAA sees it', async () => {
    const { logger, messages, failures } = recordingLogger();

    const refused = expect(
      bearer(
        Buffer.from(assertion('_an-authn-request')).toString('base64url'),
        { logger },
      ).getTokens(),
    ).rejects;
    await refused.toBeInstanceOf(AssertionValidationError);
    await refused.toMatchObject({ check: 'bearerConfirmation' });

    expect(messages).not.toContain(EXCHANGE_STARTED);
    expect(failures).toEqual([]);
  });

  itWithPasscode(
    'UaaPasscodeProvider: a code from /passcode is exchanged and refreshed',
    async () => {
      const first = await new UaaPasscodeProvider({
        uaaUrl: credentials.url,
        clientId: credentials.clientid,
        clientSecret: credentials.clientsecret,
        authorization: staticCodeStrategy({ payload: PASSCODE as string }),
      }).getTokens();
      expect(claims(first.authorizationToken).grant_type).toBe('password');
      expect(first.refreshToken).toEqual(expect.any(String));

      const { authorize, strategy } = refuseStrategy();
      const refreshed = await new UaaPasscodeProvider({
        uaaUrl: credentials.url,
        clientId: credentials.clientid,
        clientSecret: credentials.clientsecret,
        accessToken: expiredJwt(),
        refreshToken: first.refreshToken,
        authorization: strategy,
      }).getTokens();
      expect(authorize).not.toHaveBeenCalled();
      expect(refreshed.authorizationToken).not.toBe(first.authorizationToken);
    },
  );
});
