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
 *   service provider, which the shipped signed-Response validator
 *   (`createSignedResponseValidator`) accepts against the ID it minted.
 *   Turning it into session cookies is the consumer's cookieProvider and
 *   needs a real SAP system.
 * - A declined login: Keycloak
 *   answers a passive AuthnRequest with no session by declining it, and the
 *   provider refuses with the `declined` rule — which StatusCode Keycloak
 *   sends is measured here, and whether it arrives as a registered fact.
 *
 * Every provider trusts the signing certificate Keycloak publishes in its
 * SAML metadata, and the realm URL as the issuer.
 *
 * Runs only with both UAA_URL and KEYCLOAK_URL set (`npm run test:stand`).
 */

import { inspect } from 'node:util';
import { deflateRawSync, inflateRawSync } from 'node:zlib';
import { beforeAll, describe, expect, it } from '@jest/globals';
import { isSamlStatusCode } from '@mcp-abap-adt/auth-errors';
import { DOMParser } from '@xmldom/xmldom';
import { parseStrictXml } from '../../../auth/strictXml';
import { composeAuthorization } from '../../../authorization/compose';
import { samlResponse } from '../../../authorization/protocol';
import {
  type ConsumerHandoffOptions,
  consumerHandoff,
} from '../../../authorization/transport';
import { Saml2BearerProvider } from '../../../providers/Saml2BearerProvider';
import { Saml2PureProvider } from '../../../providers/Saml2PureProvider';
import { refreshThenLogin } from '../../../renewal';
import { staticCodeStrategy } from '../../../strategies';

/**
 * The consumer's own code obtains the SAMLResponse for the URL it is handed:
 * the SAML protocol over a handoff (`externalCodeStrategy` is an OAuth code,
 * bound by `state`, which a SAML URL does not carry).
 */
const samlHandedOver = (options: ConsumerHandoffOptions) =>
  composeAuthorization({
    ...consumerHandoff(options),
    protocol: samlResponse(),
    endpoint: '/callback',
  });

import {
  createSignedAssertionValidator,
  createSignedResponseValidator,
} from '../../../validation/assertionValidator';
import { defaultReplayStore } from '../../../validation/inMemoryReplayStore';
import { expectSamlRejection } from '../../helpers/samlRefusal';
import { FormBrowser, samlResponseByForm } from './formLogin';

const UAA_URL = process.env.UAA_URL?.replace(/\/+$/, '');
const KEYCLOAK_URL = process.env.KEYCLOAK_URL?.replace(/\/+$/, '');
const describeBoth = UAA_URL && KEYCLOAK_URL ? describe : describe.skip;

const USER = { username: 'tester', password: 'tester' };
const SAML_NS = 'urn:oasis:names:tc:SAML:2.0:assertion';

const claims = (jwt: string): Record<string, unknown> =>
  JSON.parse(Buffer.from(jwt.split('.')[1]!, 'base64url').toString('utf8'));

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
    const descriptor = descriptors[i]!;
    if (descriptor.getAttribute('use') !== 'signing') continue;
    const certificates = descriptor.getElementsByTagNameNS(
      DSIG_NS,
      'X509Certificate',
    );
    for (let j = 0; j < certificates.length; j++) {
      const body = (certificates[j]!.textContent ?? '').replace(/\s+/g, '');
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
  if (!client) throw new Error('Keycloak has no client uaa-sp');
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
  const idpEntityId = () => KEYCLOAK_URL as string;

  const bearerConfig = () => ({
    idpSsoUrl: `${KEYCLOAK_URL}/protocol/saml`,
    spEntityId: 'uaa-sp',
    acsUrl: bearerAcs,
    uaaUrl: UAA_URL as string,
    clientId: 'saml_kc',
    clientSecret: 'secret',
    idpEntityId: idpEntityId(),
    assertionValidator: createSignedAssertionValidator({
      idpCertificates,
      replayStore: defaultReplayStore,
    }),
  });

  it('Saml2BearerProvider: an IdP-initiated Keycloak login becomes a UAA token', async () => {
    // Taken before the provider runs, and handed over by a strategy that
    // never asks for an authorization URL: an IdP-initiated login sends no
    // AuthnRequest, so no ID is minted and none is expected.
    const payload = await unsolicitedSamlResponse(idpInitiatedUrl);
    const tokens = await new Saml2BearerProvider({
      renewal: refreshThenLogin(),
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
  // — so the refusal below is UAA's. The log names only the safe facts, and
  // the thrown failure carries no body.
  it('Saml2BearerProvider: UAA refuses the answer to the provider’s own AuthnRequest (InResponseTo)', async () => {
    const failures: unknown[] = [];
    const logger = {
      info: () => {},
      warn: () => {},
      debug: () => {},
      error: (_message: string, meta?: unknown) => failures.push(meta),
    };

    const thrown = await new Saml2BearerProvider({
      renewal: refreshThenLogin(),
      ...bearerConfig(),
      logger,
      authorization: samlHandedOver({
        redirectUri: bearerAcs,
        provide: async (url) =>
          (await samlResponseByForm(url, USER)).samlResponse,
      }),
    })
      .getTokens()
      .then(
        () => undefined,
        (error: unknown) => error as { response?: { data?: unknown } },
      );
    // UAA refuses with 401. Its reason (the InResponseTo it expects null)
    // was in the description, which since 5.4.2 is written nowhere: the
    // error keeps the status and a registered code at most.
    expect(String(thrown)).toMatch(/401/);
    expect(inspect(thrown, { depth: null })).not.toMatch(/InResponseTo/);
    expect(
      Object.keys(
        (thrown?.response?.data ?? {}) as Record<string, unknown>,
      ).filter((key) => key !== 'error'),
    ).toEqual([]);
    expect(JSON.stringify(failures)).toContain('HTTP 401');
    expect(JSON.stringify(failures)).not.toMatch(/InResponseTo/);
  });

  it('Saml2PureProvider: Keycloak answers its AuthnRequest with a signed response for the SP', async () => {
    const acsUrl = 'http://localhost/sap/saml2/sp/acs';
    const delivered: { samlResponse: string; acsUrl: string }[] = [];
    const received: string[] = [];

    const tokens = await new Saml2PureProvider({
      renewal: refreshThenLogin(),
      idpSsoUrl: `${KEYCLOAK_URL}/protocol/saml`,
      spEntityId: 'sap-sp',
      acsUrl,
      idpEntityId: idpEntityId(),
      // The signed-Response validator: Keycloak signs the Response as well as
      // the assertion, and answers the ID the provider minted.
      assertionValidator: createSignedResponseValidator({
        idpCertificates,
        replayStore: defaultReplayStore,
      }),
      authorization: samlHandedOver({
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
    expect(delivered[0]!.acsUrl).toBe(acsUrl);
    // …and the cookie provider gets exactly what Keycloak issued.
    expect(received).toEqual([delivered[0]!.samlResponse]);

    const doc = new DOMParser().parseFromString(
      Buffer.from(received[0]!, 'base64').toString('utf8'),
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

  // Measured (2026-10-06): with no session and IsPassive="true",
  // Keycloak must not show a login page, so it declines in a signed
  // Response — with no Assertion, top-level StatusCode Responder, second
  // level NoPassive. The signed-Response validator reads Status before it
  // counts Assertions, so the login is refused `declined`, the registered
  // status a fact.
  it('Saml2PureProvider: a passive login Keycloak declines is refused declined, Responder a fact', async () => {
    const delivered: string[] = [];
    const acsUrl = 'http://localhost/sap/saml2/sp/acs';
    const passive = (url: string): string => {
      const parsed = new URL(url);
      const request = inflateRawSync(
        Buffer.from(parsed.searchParams.get('SAMLRequest') ?? '', 'base64'),
      ).toString('utf8');
      const open = request.indexOf('AuthnRequest ');
      if (open < 0) throw new Error('no AuthnRequest in the URL');
      const at = open + 'AuthnRequest '.length;
      const edited = `${request.slice(0, at)}IsPassive="true" ${request.slice(at)}`;
      parsed.searchParams.set(
        'SAMLRequest',
        deflateRawSync(Buffer.from(edited, 'utf8')).toString('base64'),
      );
      return parsed.toString();
    };

    const error = await expectSamlRejection(
      new Saml2PureProvider({
        renewal: refreshThenLogin(),
        idpSsoUrl: `${KEYCLOAK_URL}/protocol/saml`,
        spEntityId: 'sap-sp',
        acsUrl,
        idpEntityId: idpEntityId(),
        assertionValidator: createSignedResponseValidator({
          idpCertificates,
          replayStore: defaultReplayStore,
        }),
        authorization: samlHandedOver({
          redirectUri: acsUrl,
          provide: async (url) => {
            // A fresh browser: no Keycloak session, so nothing to be passive about.
            const page = await new FormBrowser().open(passive(url));
            const value = /name="SAMLResponse" value="([^"]+)"/.exec(
              page.html ?? '',
            )?.[1];
            if (!value) throw new Error(`no SAMLResponse from ${page.url}`);
            delivered.push(value);
            return value;
          },
        }),
        cookieProvider: async () => 'unreachable',
      }).getTokens(),
      'declined',
      {
        facts: { statusCode: 'urn:oasis:names:tc:SAML:2.0:status:Responder' },
      },
    );
    expect(error.facts).toEqual({
      rule: 'declined',
      check: 'status',
      statusCode: 'urn:oasis:names:tc:SAML:2.0:status:Responder',
    });
    const doc = new DOMParser().parseFromString(
      Buffer.from(delivered[0] ?? '', 'base64').toString('utf8'),
      'text/xml',
    );
    const PROTOCOL = 'urn:oasis:names:tc:SAML:2.0:protocol';
    const codes = Array.from(
      doc.getElementsByTagNameNS(PROTOCOL, 'StatusCode'),
      (code) => code.getAttribute('Value'),
    );
    process.stderr.write(
      `[measured] Keycloak declined with ${JSON.stringify(codes)}\n`,
    );
    expect(doc.getElementsByTagNameNS(SAML_NS, 'Assertion')).toHaveLength(0);
    // The top-level code is the one `declined` carries: a registered one.
    expect(isSamlStatusCode(codes[0])).toBe(true);
    expect(codes[0]).toBe(error.facts.statusCode);
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
