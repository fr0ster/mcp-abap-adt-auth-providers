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
 *
 *   Both halves also pass the provider's own validation first — option B's
 *   evidence. The IdP-initiated login declares `idpInitiated: true` and so
 *   expects no InResponseTo; the SP-initiated one keeps the ID the provider
 *   minted, which Keycloak answers. Validation accepts both; only UAA tells
 *   them apart.
 * - Saml2PureProvider, the identity-provider half: Keycloak accepts the
 *   provider's AuthnRequest and answers with a signed SAMLResponse for that
 *   service provider, which the provider's default signed-Response validator
 *   accepts against the ID it minted. Turning it into session cookies is the
 *   consumer's cookieProvider and needs a real SAP system.
 *
 * Every provider trusts the signing certificate Keycloak publishes in its
 * SAML metadata, and the realm URL as the issuer.
 *
 * Runs only with both UAA_URL and KEYCLOAK_URL set (`npm run test:stand`).
 */

import { beforeAll, describe, expect, it } from '@jest/globals';
import { DOMParser } from '@xmldom/xmldom';
import { parseStrictXml } from '../../../auth/strictXml';
import { Saml2BearerProvider } from '../../../providers/Saml2BearerProvider';
import { Saml2PureProvider } from '../../../providers/Saml2PureProvider';
import { externalCodeStrategy, staticCodeStrategy } from '../../../strategies';
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

const MD_NS = 'urn:oasis:names:tc:SAML:2.0:metadata';
const DSIG_NS = 'http://www.w3.org/2000/09/xmldsig#';

/**
 * The certificates under every `KeyDescriptor use="signing"`, whitespace
 * removed, each once, in document order. A KeyDescriptor for encryption, or
 * one that does not state its use, is not a key to verify signatures with.
 * Kept in this test file: a separate module under src/__tests__ would be
 * compiled into dist/ and published.
 */
function signingCertificates(metadata: string): string[] {
  const doc = parseStrictXml(metadata);
  const found: string[] = [];
  const descriptors = doc.getElementsByTagNameNS(MD_NS, 'KeyDescriptor');
  for (let i = 0; i < descriptors.length; i++) {
    const descriptor = descriptors[i];
    if (descriptor.getAttribute('use') !== 'signing') continue;
    const certificates = descriptor.getElementsByTagNameNS(
      DSIG_NS,
      'X509Certificate',
    );
    for (let j = 0; j < certificates.length; j++) {
      const body = (certificates[j].textContent ?? '').replace(/\s+/g, '');
      if (body) found.push(body);
    }
  }
  return [...new Set(found)];
}

/**
 * The certificates Keycloak signs with — those under `KeyDescriptor
 * use="signing"` in the metadata it publishes, generated when it starts, so
 * never a committed fixture.
 */
async function keycloakCertificates(): Promise<string[]> {
  const metadata = await (
    await fetch(`${KEYCLOAK_URL}/protocol/saml/descriptor`)
  ).text();
  const found = signingCertificates(metadata);
  if (found.length === 0) {
    throw new Error('no signing certificate in Keycloak metadata');
  }
  return found;
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
  let idpCertificates: string[] = [];
  beforeAll(async () => {
    await trustKeycloakInUaa();
    bearerAcs = await uaaBearerAcs();
    idpInitiatedUrl = await idpInitiatedSsoTo(bearerAcs);
    idpCertificates = await keycloakCertificates();
  });

  /** What every provider here trusts: Keycloak's key, and its realm as issuer. */
  const trust = () => ({
    idpCertificates,
    idpEntityId: KEYCLOAK_URL as string,
  });

  const bearerConfig = () => ({
    idpSsoUrl: `${KEYCLOAK_URL}/protocol/saml`,
    spEntityId: 'uaa-sp',
    acsUrl: bearerAcs,
    uaaUrl: UAA_URL as string,
    clientId: 'saml_kc',
    clientSecret: 'secret',
    ...trust(),
  });

  it('Saml2BearerProvider: an IdP-initiated Keycloak login becomes a UAA token', async () => {
    // Taken before the provider runs, and handed over by a strategy that
    // never asks for an authorization URL: an IdP-initiated login sends no
    // AuthnRequest, so no ID is minted and none is expected.
    const payload = await unsolicitedSamlResponse(idpInitiatedUrl);
    const tokens = await new Saml2BearerProvider({
      ...bearerConfig(),
      idpInitiated: true,
      authorization: staticCodeStrategy({ redirectUri: bearerAcs, payload }),
    }).getTokens();

    const token = claims(tokens.authorizationToken);
    expect(token.grant_type).toBe(
      'urn:ietf:params:oauth:grant-type:saml2-bearer',
    );
    expect(token.origin).toBe('keycloak');
    expect(token.user_name).toBe('tester');
    expect(tokens.refreshToken).toEqual(expect.any(String));
  });

  // Validation passes here — the assertion answers the ID the provider minted
  // — so the refusal below is UAA's, logged from its token endpoint.
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
      // The default, signed-Response validator: Keycloak signs the Response
      // as well as the assertion, and answers the ID the provider minted.
      ...trust(),
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
    // The lifetime comes from the validated assertion: the earlier of its
    // Conditions and its bearer confirmation.
    const until = (name: string) =>
      Date.parse(
        doc
          .getElementsByTagNameNS(SAML_NS, name)[0]
          ?.getAttribute('NotOnOrAfter') ?? '',
      );
    expect(tokens.expiresAt).toBe(
      Math.min(until('Conditions'), until('SubjectConfirmationData')),
    );
  });
});

// Ungated: the certificate filter needs no server, only metadata.
describe('signingCertificates', () => {
  const entity = (descriptors: string) =>
    '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" ' +
    'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="urn:idp">' +
    '<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">' +
    `${descriptors}</md:IDPSSODescriptor></md:EntityDescriptor>`;

  const key = (certificate: string, use?: string) =>
    `<md:KeyDescriptor${use ? ` use="${use}"` : ''}><ds:KeyInfo><ds:X509Data>` +
    `<ds:X509Certificate>${certificate}</ds:X509Certificate>` +
    '</ds:X509Data></ds:KeyInfo></md:KeyDescriptor>';

  it('ignores an encryption key', () => {
    expect(
      signingCertificates(
        entity(key('U0lHTg==', 'signing') + key('RU5D', 'encryption')),
      ),
    ).toEqual(['U0lHTg==']);
  });

  // No use attribute means both uses in SAML metadata; only an explicit
  // signing key is trusted to sign.
  it('ignores a key that does not say it signs', () => {
    expect(
      signingCertificates(entity(key('U0lHTg==', 'signing') + key('Qk9USA=='))),
    ).toEqual(['U0lHTg==']);
  });

  it('strips whitespace and lists each certificate once', () => {
    expect(
      signingCertificates(
        entity(
          key('\n  U0lH\n  Tg==\n', 'signing') + key('U0lHTg==', 'signing'),
        ),
      ),
    ).toEqual(['U0lHTg==']);
  });
});
