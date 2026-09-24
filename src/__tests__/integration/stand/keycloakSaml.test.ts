/**
 * The SAML providers with Keycloak as the identity provider: a real login
 * issues a real, signed SAMLResponse — nothing here builds or signs one.
 *
 * - Saml2BearerProvider end to end: Keycloak → the provider's conversion →
 *   UAA's saml2-bearer grant → a token. UAA is told to trust Keycloak at the
 *   start of the run, from the metadata Keycloak publishes, since its signing
 *   keys are generated when it starts.
 *
 *   Only an IdP-initiated assertion gets through. UAA's bearer grant refuses
 *   any assertion carrying SubjectConfirmationData/@InResponseTo — it has no
 *   AuthnRequest to match it against, and `disableInResponseToCheck` covers
 *   web SSO only — and an IdP answering the provider's own AuthnRequest always
 *   sets it. The suite pins both halves.
 * - Saml2PureProvider, the identity-provider half: Keycloak accepts the
 *   provider's AuthnRequest and answers with a signed SAMLResponse for that
 *   service provider. Turning it into session cookies is the consumer's
 *   cookieProvider and needs a real SAP system.
 *
 * Runs only with both UAA_URL and KEYCLOAK_URL set (`npm run test:stand`).
 */

import { beforeAll, describe, expect, it } from '@jest/globals';
import { DOMParser } from '@xmldom/xmldom';
import { Saml2BearerProvider } from '../../../providers/Saml2BearerProvider';
import { Saml2PureProvider } from '../../../providers/Saml2PureProvider';
import { externalCodeStrategy } from '../../../strategies';
import { FormBrowser, samlResponseByForm } from './formLogin';

const UAA_URL = process.env.UAA_URL?.replace(/\/+$/, '');
const KEYCLOAK_URL = process.env.KEYCLOAK_URL?.replace(/\/+$/, '');
const describeBoth = UAA_URL && KEYCLOAK_URL ? describe : describe.skip;

const USER = { username: 'tester', password: 'tester' };
const SAML_NS = 'urn:oasis:names:tc:SAML:2.0:assertion';

const claims = (jwt: string): Record<string, unknown> =>
  JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString('utf8'));

const basic = (client: string) =>
  `Basic ${Buffer.from(`${client}:secret`).toString('base64')}`;

/** Register — or refresh — Keycloak as UAA's `keycloak` SAML provider. */
async function trustKeycloakInUaa(): Promise<void> {
  const metadata = await (
    await fetch(`${KEYCLOAK_URL}/protocol/saml/descriptor`)
  ).text();
  const token = (
    (await (
      await fetch(`${UAA_URL}/oauth/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: basic('stand_admin'),
        },
        body: 'grant_type=client_credentials',
      })
    ).json()) as { access_token: string }
  ).access_token;
  const headers = {
    Authorization: `Bearer ${token}`,
    'Content-Type': 'application/json',
  };
  const provider = {
    type: 'saml',
    originKey: 'keycloak',
    name: 'keycloak',
    active: true,
    config: {
      metaDataLocation: metadata,
      idpEntityAlias: 'keycloak',
      nameID: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
      assertionConsumerIndex: 0,
      metadataTrustCheck: false,
      showSamlLink: false,
      addShadowUserOnLogin: true,
    },
  };
  const existing = (
    (await (
      await fetch(`${UAA_URL}/identity-providers?rawConfig=true`, { headers })
    ).json()) as { id: string; originKey: string }[]
  ).find((p) => p.originKey === 'keycloak');
  const response = await fetch(
    existing
      ? `${UAA_URL}/identity-providers/${existing.id}?rawConfig=true`
      : `${UAA_URL}/identity-providers?rawConfig=true`,
    {
      method: existing ? 'PUT' : 'POST',
      headers,
      body: JSON.stringify(
        existing ? { ...provider, id: existing.id } : provider,
      ),
    },
  );
  if (!response.ok) {
    throw new Error(
      `UAA refused the Keycloak provider: ${response.status} ${await response.text()}`,
    );
  }
}

/** Where UAA receives bearer assertions, from its own SAML metadata. */
async function uaaBearerAcs(): Promise<string> {
  const metadata = await (await fetch(`${UAA_URL}/saml/metadata`)).text();
  const acs =
    /AssertionConsumerService[^>]*bindings:URI"[^>]*Location="([^"]+)"/.exec(
      metadata,
    )?.[1];
  if (!acs) throw new Error('no URI-binding ACS in UAA metadata');
  return acs;
}

/**
 * Configure Keycloak's `uaa-sp` client for IdP-initiated SSO, posting to
 * `acsUrl`, and return the URL that starts it. Done at run time because the
 * ACS depends on the port UAA runs on.
 */
async function idpInitiatedSsoTo(acsUrl: string): Promise<string> {
  const base = (KEYCLOAK_URL as string).replace(/\/realms\/.*$/, '');
  const admin = (
    (await (
      await fetch(`${base}/realms/master/protocol/openid-connect/token`, {
        method: 'POST',
        body: new URLSearchParams({
          grant_type: 'password',
          client_id: 'admin-cli',
          username: 'admin',
          password: 'admin',
        }),
      })
    ).json()) as { access_token: string }
  ).access_token;
  const headers = {
    Authorization: `Bearer ${admin}`,
    'Content-Type': 'application/json',
  };
  const [client] = (await (
    await fetch(`${base}/admin/realms/test/clients?clientId=uaa-sp`, {
      headers,
    })
  ).json()) as { id: string; attributes: Record<string, string> }[];
  client.attributes = {
    ...client.attributes,
    saml_idp_initiated_sso_url_name: 'uaa-sp',
    saml_assertion_consumer_url_post: acsUrl,
  };
  const updated = await fetch(
    `${base}/admin/realms/test/clients/${client.id}`,
    { method: 'PUT', headers, body: JSON.stringify(client) },
  );
  if (!updated.ok) {
    throw new Error(`Keycloak refused the client update: ${updated.status}`);
  }
  return `${KEYCLOAK_URL}/protocol/saml/clients/uaa-sp`;
}

/** Log in at an IdP-initiated SSO URL and take the SAMLResponse it posts. */
async function unsolicitedSamlResponse(url: string): Promise<string> {
  const browser = new FormBrowser();
  const page = await browser.submitLogin(await browser.open(url), USER);
  const value = /name="SAMLResponse" value="([^"]+)"/.exec(
    page.html ?? '',
  )?.[1];
  if (!value) throw new Error(`no SAMLResponse from ${url}`);
  return value;
}

describeBoth('SAML providers with Keycloak as the identity provider', () => {
  let bearerAcs = '';
  let idpInitiatedUrl = '';
  beforeAll(async () => {
    await trustKeycloakInUaa();
    bearerAcs = await uaaBearerAcs();
    idpInitiatedUrl = await idpInitiatedSsoTo(bearerAcs);
  });

  const bearerConfig = () => ({
    idpSsoUrl: `${KEYCLOAK_URL}/protocol/saml`,
    spEntityId: 'uaa-sp',
    acsUrl: bearerAcs,
    uaaUrl: UAA_URL as string,
    clientId: 'saml_kc',
    clientSecret: 'secret',
  });

  it('Saml2BearerProvider: an IdP-initiated Keycloak login becomes a UAA token', async () => {
    const tokens = await new Saml2BearerProvider({
      ...bearerConfig(),
      // The provider's AuthnRequest URL is not used: the assertion comes from
      // Keycloak's IdP-initiated SSO, which carries no InResponseTo.
      authorization: externalCodeStrategy({
        redirectUri: bearerAcs,
        provide: async () => unsolicitedSamlResponse(idpInitiatedUrl),
      }),
    }).getTokens();

    const token = claims(tokens.authorizationToken);
    expect(token.grant_type).toBe(
      'urn:ietf:params:oauth:grant-type:saml2-bearer',
    );
    expect(token.origin).toBe('keycloak');
    expect(token.user_name).toBe('tester');
    expect(tokens.refreshToken).toEqual(expect.any(String));
  });

  it('Saml2BearerProvider: UAA refuses the answer to the provider’s own AuthnRequest (InResponseTo)', async () => {
    const failures: unknown[] = [];
    const logger = {
      info: () => {},
      warn: () => {},
      debug: () => {},
      error: (_message: string, meta?: unknown) => failures.push(meta),
    };

    await expect(
      new Saml2BearerProvider({
        ...bearerConfig(),
        logger,
        authorization: externalCodeStrategy({
          redirectUri: bearerAcs,
          provide: async (url) =>
            (await samlResponseByForm(url, USER)).samlResponse,
        }),
      }).getTokens(),
    ).rejects.toThrow(/401/);
    expect(JSON.stringify(failures)).toMatch(
      /SubjectConfirmationData\/@InResponseTo.*did not match the valid value: null/,
    );
  });

  it('Saml2PureProvider: Keycloak answers its AuthnRequest with a signed response for the SP', async () => {
    const acsUrl = 'http://localhost/sap/saml2/sp/acs';
    const delivered: { samlResponse: string; acsUrl: string }[] = [];
    const received: string[] = [];

    const tokens = await new Saml2PureProvider({
      idpSsoUrl: `${KEYCLOAK_URL}/protocol/saml`,
      spEntityId: 'sap-sp',
      acsUrl,
      authorization: externalCodeStrategy({
        redirectUri: acsUrl,
        provide: async (url) => {
          const posted = await samlResponseByForm(url, USER);
          delivered.push(posted);
          return posted.samlResponse;
        },
      }),
      // Stands in for the SAP system: records what it would receive.
      cookieProvider: async (samlResponse) => {
        received.push(samlResponse);
        return 'SAP_SESSIONID=stand';
      },
    }).getTokens();

    expect(tokens.authorizationToken).toBe('SAP_SESSIONID=stand');
    // Keycloak posts to the ACS the provider's AuthnRequest named…
    expect(delivered[0].acsUrl).toBe(acsUrl);
    // …and the cookie provider gets exactly what Keycloak issued.
    expect(received).toEqual([delivered[0].samlResponse]);

    const doc = new DOMParser().parseFromString(
      Buffer.from(received[0], 'base64').toString('utf8'),
      'text/xml',
    );
    const text = (name: string) =>
      doc.getElementsByTagNameNS(SAML_NS, name)[0]?.textContent;
    expect(text('Issuer')).toBe(KEYCLOAK_URL);
    expect(text('Audience')).toBe('sap-sp');
    expect(text('NameID')).toBe('tester');
    expect(
      doc.getElementsByTagNameNS(
        'http://www.w3.org/2000/09/xmldsig#',
        'Signature',
      ).length,
    ).toBeGreaterThan(0);
    // The lifetime comes from the response, as the provider promises.
    expect(tokens.expiresAt).toEqual(expect.any(Number));
  });
});
