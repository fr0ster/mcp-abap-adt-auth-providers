/**
 * Both shipped validators, end to end, against documents a separately
 * published identity provider produced: `@mcp-abap-adt/auth-mocks`.
 *
 * Every login here is real. `Saml2PureProvider` builds its AuthnRequest, the
 * SAML callback strategy binds the ACS the mock has registered, `visit` plays
 * the browser — follows the IdP's auto-submitting form and posts the
 * SAMLResponse to that ACS — and the provider validates what arrived. The
 * validators have unit tests over fixtures their author wrote; this suite is
 * what says they are right about documents somebody else wrote.
 *
 * Two facts about the mock shape the matrix, both read from its source:
 * - it signs the Assertion unless `signWhat: 'response'`, which puts the
 *   Response's Signature after its Issuer. The signed-Response validator
 *   refuses an assertion-signed document outright, so every signed-Response
 *   case runs with `signWhat: 'response'`;
 * - `wrongIssuer` writes one value into both `Response/Issuer` and
 *   `Assertion/Issuer`. The assertion's issuer is inside the signature, so
 *   both validators refuse it at `issuer` — which says nothing about the
 *   response-level cross-check. That has a case of its own below, built by
 *   re-signing.
 */

import { randomUUID } from 'node:crypto';
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  jest,
} from '@jest/globals';
import {
  generateKeyMaterial,
  type KeyMaterial,
  type MockSamlIdp,
  type SamlVariant,
  signXml,
  startMockSamlIdp,
  visit,
} from '@mcp-abap-adt/auth-mocks';
import type {
  IAssertionReplayStore,
  IAssertionValidator,
  ITokenResult,
  ValidatedAssertion,
} from '@mcp-abap-adt/interfaces-auth';
import { DOMParser } from '@xmldom/xmldom';
import type { AssertionCheck } from '../../errors/AssertionValidationError';
import { Saml2PureProvider } from '../../providers/Saml2PureProvider';
import { samlCallbackStrategy } from '../../strategies';
import {
  createSignedAssertionValidator,
  createSignedResponseValidator,
} from '../../validation/assertionValidator';
import { createInMemoryReplayStore } from '../../validation/inMemoryReplayStore';
import { getAvailablePort } from '../helpers/netHelpers';

jest.setTimeout(30_000);

/** Which element is signed — by the IdP, and required by the validator. */
type Signed = 'response' | 'assertion';

const ISSUER = 'urn:e2e:idp';
const AUDIENCE = 'urn:e2e:sp';
const COOKIE = 'SAP_SESSIONID=e2e';
const SAML_NS = 'urn:oasis:names:tc:SAML:2.0:assertion';

const RESPONSE_SIGNATURE = {
  referenceXPath: "//*[local-name(.)='Response']",
  location: {
    reference: "//*[local-name(.)='Response']/*[local-name(.)='Issuer']",
    action: 'after' as const,
  },
};

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()?.();
});

interface Stand {
  idp: MockSamlIdp;
  port: number;
}

/**
 * One IdP per signing mode, started once for the file: every start generates
 * a 2048-bit RSA key, and a start per test made this the slowest suite in the
 * package. Each IdP's only registered ACS is the one its logins bind — the
 * port is chosen first because the mock takes its registrations at start,
 * exactly as a real IdP holds them in service-provider metadata. A test sets
 * the variant it needs through standFor and never inherits one.
 */
const stands = {} as Record<Signed, Stand>;

beforeAll(async () => {
  for (const signWhat of ['response', 'assertion'] as const) {
    const port = await getAvailablePort();
    const idp = await startMockSamlIdp({
      variant: 'valid',
      signWhat,
      acsUrls: [`http://localhost:${port}/callback`],
      issuer: ISSUER,
      audience: AUDIENCE,
    });
    stands[signWhat] = { idp, port };
  }
});

afterAll(async () => {
  for (const stand of Object.values(stands)) await stand.idp.close();
});

/** The shared IdP for `signWhat`, switched to `variant`. */
function standFor(signWhat: Signed, variant: SamlVariant = 'valid'): Stand {
  const stand = stands[signWhat];
  stand.idp.setVariant(variant);
  return stand;
}

/**
 * A replay store of this test's own. The mock mints a fresh assertion ID per
 * delivery unless a test asks it to repeat one, so each test's assertions
 * are its own as well.
 */
let replayStore: IAssertionReplayStore;
beforeEach(() => {
  replayStore = createInMemoryReplayStore();
});

interface LoginOptions {
  /** Stands in for the browser. Defaults to `visit`. */
  browser?: (url: string) => Promise<unknown>;
  /** The certificates trusted. Defaults to the mock's own. */
  certificates?: string[];
  /** Receives what the validator returned, for the cases that need it. */
  onValidated?: (validated: ValidatedAssertion) => void;
}

interface LoginResult {
  tokens: ITokenResult;
  /** Every payload the cookie provider was handed. */
  received: string[];
}

/**
 * One real login through `Saml2PureProvider`. `validator` picks the shipped
 * validator: `'response'` is the provider's own default, left unconfigured
 * so the default itself is what runs; `'assertion'` is supplied explicitly.
 */
async function login(
  stand: Stand,
  validator: Signed,
  options: LoginOptions = {},
): Promise<LoginResult> {
  const certificates = options.certificates ?? [stand.idp.certificatePem];
  const browse = options.browser ?? visit;
  const strategy = samlCallbackStrategy({
    port: stand.port,
    timeoutMs: 10_000,
    openUrl: async (url) => {
      await browse(url);
    },
  });
  // A supplied strategy is never disposed by the provider.
  cleanups.push(async () => strategy.dispose?.());

  let assertionValidator: IAssertionValidator | undefined =
    validator === 'assertion'
      ? createSignedAssertionValidator({
          idpCertificates: certificates,
          replayStore,
        })
      : undefined;
  if (options.onValidated) {
    // A spy around the real validator: the provider returns an ITokenResult,
    // so this is the only honest way to see which element was signed.
    const real =
      assertionValidator ??
      createSignedResponseValidator({
        idpCertificates: certificates,
        replayStore,
      });
    const report = options.onValidated;
    assertionValidator = {
      async validate(samlResponse, context) {
        const validated = await real.validate(samlResponse, context);
        report(validated);
        return validated;
      },
    };
  }

  const received: string[] = [];
  const provider = new Saml2PureProvider({
    idpSsoUrl: `${stand.idp.url}/sso`,
    spEntityId: AUDIENCE,
    idpEntityId: ISSUER,
    idpCertificates: certificates,
    assertionValidator,
    assertionReplayStore: replayStore,
    authorization: strategy,
    cookieProvider: async (samlResponse) => {
      received.push(samlResponse);
      return COOKIE;
    },
  });
  const tokens = await provider.getTokens();
  return { tokens, received };
}

async function loginWith(
  signWhat: Signed,
  variant: SamlVariant,
): Promise<LoginResult> {
  return login(standFor(signWhat, variant), signWhat);
}

/**
 * A browser that intercepts the IdP's form, rewrites the SAMLResponse, and
 * posts the result to the ACS the form names — the man in the middle a
 * wrapping or re-signing case needs, since `visit` posts what it was given.
 */
function tamperingBrowser(rewrite: (xml: string) => string) {
  return async (url: string): Promise<void> => {
    const page = await (await fetch(url)).text();
    const action = /<form[^>]*action="([^"]+)"/.exec(page)?.[1];
    const value = /name="SAMLResponse" value="([^"]+)"/.exec(page)?.[1];
    if (!action || !value) {
      throw new Error(`the IdP answered with no SAML form: ${page}`);
    }
    const xml = rewrite(Buffer.from(value, 'base64').toString('utf8'));
    const posted = await fetch(action.replace(/&amp;/g, '&'), {
      method: 'POST',
      body: new URLSearchParams({
        SAMLResponse: Buffer.from(xml, 'utf8').toString('base64'),
      }),
    });
    if (!posted.ok) {
      throw new Error(`the ACS refused the post: ${posted.status}`);
    }
  };
}

const decode = (samlResponse: string): string =>
  Buffer.from(samlResponse, 'base64').toString('utf8');

function firstAttribute(xml: string, element: string, name: string): string {
  const doc = new DOMParser().parseFromString(xml, 'text/xml');
  const found = doc.getElementsByTagNameNS(SAML_NS, element)[0];
  const value = found?.getAttribute(name);
  if (!value) throw new Error(`no ${element}/@${name} in ${xml}`);
  return value;
}

/** The first `<saml:Issuer>` in the mock's document is the Response's own. */
function corruptResponseIssuer(xml: string): string {
  const own = `<saml:Issuer>${ISSUER}</saml:Issuer>`;
  const at = xml.indexOf(own);
  const assertionAt = xml.indexOf('<saml:Assertion');
  if (at < 0 || at > assertionAt) {
    throw new Error('the Response carries no Issuer of its own');
  }
  return `${xml.slice(0, at)}<saml:Issuer>urn:other:idp</saml:Issuer>${xml.slice(at + own.length)}`;
}

function resign(xml: string, key: KeyMaterial, signWhat: Signed): string {
  return signWhat === 'response'
    ? signXml(xml, key, RESPONSE_SIGNATURE)
    : signXml(xml, key);
}

/** The Assertion element of the mock's document, as written. */
function assertionOf(xml: string): string {
  const start = xml.indexOf('<saml:Assertion');
  const end = xml.indexOf('</saml:Assertion>') + '</saml:Assertion>'.length;
  if (start < 0 || end < start) throw new Error('no Assertion');
  return xml.slice(start, end);
}

/** Another assertion saying something the IdP never said, unsigned. */
function forgedAssertionFrom(xml: string): string {
  return assertionOf(xml)
    .replace(/<ds:Signature[\s\S]*<\/ds:Signature>/, '')
    .replace(/<Signature[\s\S]*<\/Signature>/, '')
    .replace(/ ID="[^"]+"/, ` ID="_forged-${randomUUID()}"`)
    .replace('mock-user', 'attacker');
}

// Refused by both, for the same check and the same reason: everything here is
// inside the assertion, or is the signature itself.
const REFUSED_BY_BOTH: Array<[SamlVariant, AssertionCheck, string]> = [
  ['unsigned', 'signature', 'the document carries no signature'],
  [
    'wrongKey',
    'signature',
    'does not verify against any configured certificate',
  ],
  [
    'tamperedAfterSign',
    'signature',
    'does not verify against any configured certificate',
  ],
  ['wrongIssuer', 'issuer', 'not the trusted issuer'],
  ['notYetValid', 'notBefore', 'the assertion is not valid yet'],
  ['expired', 'notOnOrAfter', 'the assertion has expired'],
  ['wrongAudience', 'audience', 'does not name us'],
  [
    'wrongInResponseTo',
    'bearerConfirmation',
    '#1 InResponseTo does not answer our request',
  ],
  ['wrongRecipient', 'bearerConfirmation', '#1 Recipient is not the ACS'],
];

// Refused by the signed-Response validator, accepted by the other, which does
// not read these fields. Both halves are asserted: a check silently dropped
// and a check documented as absent look identical from outside.
const RESPONSE_LEVEL: Array<[SamlVariant, AssertionCheck, string]> = [
  ['statusFailure', 'status', 'the identity provider declined the login'],
  ['wrongDestination', 'destination', 'not to us'],
];

describe('SAML validation end to end against auth-mocks', () => {
  describe('every corruption variant, refused at its own check', () => {
    for (const [variant, check, fragment] of REFUSED_BY_BOTH) {
      it(`refuses ${variant} at ${check}, whichever validator`, async () => {
        const refusal = { check, message: expect.stringContaining(fragment) };
        await expect(loginWith('response', variant)).rejects.toMatchObject(
          refusal,
        );
        await expect(loginWith('assertion', variant)).rejects.toMatchObject(
          refusal,
        );
      });
    }

    for (const [variant, check, fragment] of RESPONSE_LEVEL) {
      it(`refuses ${variant} at ${check} only when the Response is signed`, async () => {
        await expect(loginWith('response', variant)).rejects.toMatchObject({
          check,
          message: expect.stringContaining(fragment),
        });
        await expect(loginWith('assertion', variant)).resolves.toBeDefined();
      });
    }
  });

  describe('a successful login', () => {
    for (const signWhat of ['response', 'assertion'] as const) {
      it(`takes expiresAt from the assertion and the cookie from cookieProvider (${signWhat} signed)`, async () => {
        const stand = standFor(signWhat);
        const validated: ValidatedAssertion[] = [];

        const { tokens, received } = await login(stand, signWhat, {
          onValidated: (v) => validated.push(v),
        });

        expect(tokens.authorizationToken).toBe(COOKIE);
        expect(received).toHaveLength(1);
        const xml = decode(received[0]);
        expect(firstAttribute(xml, 'Assertion', 'ID')).toBe(
          stand.idp.lastAssertionId(),
        );
        // The mock gives Conditions and the bearer confirmation one lifetime;
        // expiresAt is the earlier of the two, so it is that one.
        const conditionsEnd = firstAttribute(xml, 'Conditions', 'NotOnOrAfter');
        expect(
          firstAttribute(xml, 'SubjectConfirmationData', 'NotOnOrAfter'),
        ).toBe(conditionsEnd);
        expect(tokens.expiresAt).toBe(Date.parse(conditionsEnd));

        // Which element the signature covered, as the validator reported it.
        expect(validated).toHaveLength(1);
        const signedRoot = new DOMParser().parseFromString(
          validated[0].signedXml,
          'text/xml',
        ).documentElement;
        expect(signedRoot?.localName).toBe(
          signWhat === 'response' ? 'Response' : 'Assertion',
        );
      });
    }
  });

  describe('the signature on the wrong element', () => {
    it('refuses a response-signed document under the assertion-only validator', async () => {
      await expect(
        login(standFor('response'), 'assertion'),
      ).rejects.toMatchObject({
        check: 'signedNode',
        message: expect.stringContaining(
          'does not cover the saml:Assertion this validator requires',
        ),
      });
    });

    it('refuses an assertion-signed document under the signed-Response validator', async () => {
      await expect(
        login(standFor('assertion'), 'response'),
      ).rejects.toMatchObject({
        check: 'signedNode',
        message: expect.stringContaining(
          'does not cover the samlp:Response this validator requires',
        ),
      });
    });
  });

  describe('the response-level issuer cross-check', () => {
    // Re-signed with a key of our own: the mock's `wrongIssuer` corrupts both
    // issuers, so it cannot show a cross-check that compares them.
    const key = generateKeyMaterial();

    it('accepts the re-signed document untouched, in both modes — so a refusal below is the corruption', async () => {
      for (const signWhat of ['response', 'assertion'] as const) {
        const stand = standFor(signWhat, 'unsigned');
        await expect(
          login(stand, signWhat, {
            certificates: [key.certificatePem],
            browser: tamperingBrowser((xml) => resign(xml, key, signWhat)),
          }),
        ).resolves.toBeDefined();
      }
    });

    it('refuses a Response/Issuer that differs from the assertion’s only when the Response is signed', async () => {
      const bySignedResponse = login(
        standFor('response', 'unsigned'),
        'response',
        {
          certificates: [key.certificatePem],
          browser: tamperingBrowser((xml) =>
            resign(corruptResponseIssuer(xml), key, 'response'),
          ),
        },
      );
      await expect(bySignedResponse).rejects.toMatchObject({
        check: 'issuer',
        message: expect.stringContaining('name different issuers'),
      });

      const byAssertion = login(
        standFor('assertion', 'unsigned'),
        'assertion',
        {
          certificates: [key.certificatePem],
          browser: tamperingBrowser((xml) =>
            resign(corruptResponseIssuer(xml), key, 'assertion'),
          ),
        },
      );
      await expect(byAssertion).resolves.toBeDefined();
    });
  });

  describe('replay', () => {
    for (const signWhat of ['response', 'assertion'] as const) {
      it(`refuses the same assertion the second time (${signWhat} signed)`, async () => {
        const stand = standFor(signWhat);
        await login(stand, signWhat);
        const first = stand.idp.lastAssertionId();

        stand.idp.repeatLastAssertion();
        await expect(login(stand, signWhat)).rejects.toMatchObject({
          check: 'replay',
          message: expect.stringContaining(
            'this assertion has been presented before',
          ),
        });
        // The mock really did send the same ID again.
        expect(stand.idp.lastAssertionId()).toBe(first);
      });
    }
  });

  describe('signature wrapping', () => {
    it('refuses a forged assertion placed beside the signed one', async () => {
      // The forgery goes first: a reader taking "the first Assertion" takes it.
      const wrap = (xml: string) => {
        const signed = assertionOf(xml);
        return xml.replace(signed, `${forgedAssertionFrom(xml)}${signed}`);
      };
      await expect(
        login(standFor('assertion'), 'assertion', {
          browser: tamperingBrowser(wrap),
        }),
      ).rejects.toMatchObject({
        check: 'signedNode',
        message: expect.stringContaining(
          '2 direct-child saml:Assertion; exactly one is allowed',
        ),
      });
    });

    it('refuses a forged Response wrapping the genuinely signed one', async () => {
      // The signed Response survives intact inside Extensions of a new root
      // that carries a forged assertion — the signature still verifies, over
      // the wrong element.
      const wrap = (xml: string) => {
        const acs = /Destination="([^"]+)"/.exec(xml)?.[1] ?? '';
        const inResponseTo = /InResponseTo="([^"]+)"/.exec(xml)?.[1] ?? '';
        return (
          '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
          'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ' +
          `ID="_outer-${randomUUID()}" Version="2.0" IssueInstant="${new Date().toISOString()}" ` +
          `Destination="${acs}" InResponseTo="${inResponseTo}">` +
          `<saml:Issuer>${ISSUER}</saml:Issuer>` +
          `<samlp:Extensions>${xml}</samlp:Extensions>` +
          '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
          `${forgedAssertionFrom(xml)}</samlp:Response>`
        );
      };
      await expect(
        login(standFor('response'), 'response', {
          browser: tamperingBrowser(wrap),
        }),
      ).rejects.toMatchObject({
        check: 'signedNode',
        message: expect.stringContaining(
          'does not cover the samlp:Response this validator requires',
        ),
      });
    });
  });

  describe('isolation between tests', () => {
    // Each test's logins record into that test's own store — not the
    // process-wide default — so no test can see another's assertions.
    for (const signWhat of ['response', 'assertion'] as const) {
      it(`records the assertion in this test's own replay store (${signWhat} signed)`, async () => {
        const stand = standFor(signWhat);
        await login(stand, signWhat);
        const assertionId = stand.idp.lastAssertionId();
        expect(assertionId).toBeDefined();
        await expect(
          replayStore.recordIfUnseen(
            { issuer: ISSUER, assertionId: assertionId as string },
            new Date(Date.now() + 60_000),
          ),
        ).resolves.toBe(false);
      });
    }

    // Two tests in order: the first leaves a record behind, the second must
    // not see it. Run alone, the second passes trivially — it is the pair
    // that proves a store per test.
    const probe = { issuer: 'urn:isolation', assertionId: '_probe' };
    it('leaves a record behind (1 of 2)', async () => {
      await expect(
        replayStore.recordIfUnseen(probe, new Date(Date.now() + 60_000)),
      ).resolves.toBe(true);
    });

    it('does not see the record the previous test left (2 of 2)', async () => {
      await expect(
        replayStore.recordIfUnseen(probe, new Date(Date.now() + 60_000)),
      ).resolves.toBe(true);
    });
  });
});
