import { afterEach, describe, expect, it, jest } from '@jest/globals';
import { generateKeyMaterial, signXml } from '@mcp-abap-adt/auth-mocks';
import { DOMParser, type Document } from '@xmldom/xmldom';
import {
  createSignedAssertionValidator,
  createSignedResponseValidator,
} from '../../validation/assertionValidator';
import { createInMemoryReplayStore } from '../../validation/inMemoryReplayStore';
import { resolveSignedElements, toPem } from '../../validation/signedNode';

const KEY = generateKeyMaterial();
const ACS = 'http://localhost:61001/acs';
const ISSUER = 'urn:mock:idp';
const AUDIENCE = 'urn:mock:sp';
const REQUEST_ID = '_req1';

const iso = (offsetMs: number) => new Date(Date.now() + offsetMs).toISOString();

/**
 * One valid response, with named holes so a test can remove or alter exactly
 * one thing. Every parameter defaults to the correct value.
 */
function buildResponse(
  o: {
    status?: string;
    assertionId?: string | null;
    issuer?: string | null;
    responseIssuer?: string | null;
    conditions?: string | null;
    notBefore?: string | null;
    notOnOrAfter?: string | null;
    audiences?: string[][] | null;
    confirmations?: string[] | null;
    destination?: string | null;
    /**
     * Defaults to `"response"`, because the signed-Response validator — this
     * suite's main subject, and `Saml2PureProvider`'s default — requires it.
     * A fixture signing the assertion while the test runs the signed-Response
     * validator fails at `signedNode` before reaching the check it was written
     * for — every negative case would then pass for the wrong reason.
     */
    signWhat?: 'assertion' | 'response';
  } = {},
): string {
  const status = o.status ?? 'urn:oasis:names:tc:SAML:2.0:status:Success';
  const assertionId = o.assertionId === null ? '' : (o.assertionId ?? '_a1');
  const idAttr = o.assertionId === null ? '' : ` ID="${assertionId}"`;
  const issuer =
    o.issuer === null ? '' : `<saml:Issuer>${o.issuer ?? ISSUER}</saml:Issuer>`;
  const responseIssuer =
    o.responseIssuer === undefined
      ? ''
      : o.responseIssuer === null
        ? ''
        : `<saml:Issuer>${o.responseIssuer}</saml:Issuer>`;
  const audiences =
    o.audiences === null
      ? ''
      : (o.audiences ?? [[AUDIENCE]])
          .map(
            (group) =>
              `<saml:AudienceRestriction>${group
                .map((a) => `<saml:Audience>${a}</saml:Audience>`)
                .join('')}</saml:AudienceRestriction>`,
          )
          .join('');
  const conditions =
    o.conditions === null
      ? ''
      : `<saml:Conditions${o.notBefore === null ? '' : ` NotBefore="${o.notBefore ?? iso(-60_000)}"`}` +
        `${o.notOnOrAfter === null ? '' : ` NotOnOrAfter="${o.notOnOrAfter ?? iso(300_000)}"`}>` +
        `${audiences}</saml:Conditions>`;
  const confirmations =
    o.confirmations === null
      ? ''
      : (
          o.confirmations ?? [
            `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
              `<saml:SubjectConfirmationData InResponseTo="${REQUEST_ID}" Recipient="${ACS}" ` +
              `NotOnOrAfter="${iso(300_000)}"/></saml:SubjectConfirmation>`,
          ]
        ).join('');

  const assertion =
    `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"${idAttr}>` +
    `${issuer}<saml:Subject><saml:NameID>mock-user</saml:NameID>${confirmations}</saml:Subject>` +
    `${conditions}</saml:Assertion>`;

  const destination =
    o.destination === null ? '' : ` Destination="${o.destination ?? ACS}"`;

  if ((o.signWhat ?? 'response') === 'assertion') {
    const signed = signXml(assertion, KEY);
    return (
      `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
      `xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1"${destination}>` +
      `${responseIssuer}<samlp:Status><samlp:StatusCode Value="${status}"/></samlp:Status>` +
      `${signed}</samlp:Response>`
    );
  }
  const response =
    `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
    `xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1"${destination}>` +
    `${responseIssuer}<samlp:Status><samlp:StatusCode Value="${status}"/></samlp:Status>` +
    `${assertion}</samlp:Response>`;
  // Where SAML Core's ResponseType puts it: right after the Response's own
  // Issuer when there is one, otherwise first — Issuer is optional and nothing
  // else may precede the Signature. The default fixture has no Response
  // Issuer, so a location naming it would find nothing and signXml would
  // throw. Without any `location` the Signature would follow the Assertion.
  return signXml(response, KEY, {
    referenceXPath: "//*[local-name(.)='Response']",
    location: responseIssuer
      ? {
          reference: "//*[local-name(.)='Response']/*[local-name(.)='Issuer']",
          action: 'after',
        }
      : { reference: "//*[local-name(.)='Response']", action: 'prepend' },
  });
}

const encode = (xml: string) => Buffer.from(xml, 'utf8').toString('base64');

/** The elements every signature in `xml` covers — the premise probe. */
const signedElementsOf = (xml: string) =>
  resolveSignedElements(
    xml,
    new DOMParser().parseFromString(xml, 'text/xml') as unknown as Document,
    [toPem(KEY.certificatePem)],
  );

/** `xml` with its one Signature element removed, ready to be re-signed. */
const stripSignature = (xml: string) =>
  xml.replace(/<(\w+:)?Signature[\s>][\s\S]*?<\/(\w+:)?Signature>/, '');

/**
 * The default response-signed fixture, altered before it is signed, so the
 * signature covers the alteration and only the rule under test can refuse
 * it. The default fixture has no Response Issuer, so the Signature goes
 * first.
 */
const alteredResponse = (
  alter: (unsigned: string) => string,
  o: Parameters<typeof buildResponse>[0] = {},
) =>
  signXml(alter(stripSignature(buildResponse(o))), KEY, {
    referenceXPath: "//*[local-name(.)='Response']",
    location: {
      reference: "//*[local-name(.)='Response']",
      action: 'prepend',
    },
  });

const context = {
  expectedInResponseTo: REQUEST_ID,
  audience: AUDIENCE,
  acsUrl: ACS,
  expectedIssuer: ISSUER,
};

/** Saml2PureProvider's default: requires the Response to be signed. */
const validator = (over: Partial<{ clockSkewMs: number }> = {}) =>
  createSignedResponseValidator({
    idpCertificates: [KEY.certificatePem],
    replayStore: createInMemoryReplayStore(),
    ...over,
  });

/** The other one: accepts a signature over the Assertion. */
const assertionValidator = (over: Partial<{ clockSkewMs: number }> = {}) =>
  createSignedAssertionValidator({
    idpCertificates: [KEY.certificatePem],
    replayStore: createInMemoryReplayStore(),
    ...over,
  });

const BEARER_METHOD = 'urn:oasis:names:tc:SAML:2.0:cm:bearer';
const HOLDER_OF_KEY = 'urn:oasis:names:tc:SAML:2.0:cm:holder-of-key';
const ELSEWHERE = 'http://elsewhere/acs';
/** Lexically an xsd:dateTime, but 30 February. */
const INVALID_DATE = '2026-02-30T00:00:00Z';

/** One SubjectConfirmation around `inner`, bearer unless told otherwise. */
const confirmation = (inner: string, method = BEARER_METHOD) =>
  `<saml:SubjectConfirmation Method="${method}">${inner}</saml:SubjectConfirmation>`;

/** A SubjectConfirmationData whose attributes default to valid values; null omits one. */
const confirmationData = (
  a: {
    inResponseTo?: string | null;
    recipient?: string | null;
    notBefore?: string;
    notOnOrAfter?: string | null;
  } = {},
) =>
  '<saml:SubjectConfirmationData' +
  (a.inResponseTo === null
    ? ''
    : ` InResponseTo="${a.inResponseTo ?? REQUEST_ID}"`) +
  (a.recipient === null ? '' : ` Recipient="${a.recipient ?? ACS}"`) +
  (a.notBefore ? ` NotBefore="${a.notBefore}"` : '') +
  (a.notOnOrAfter === null
    ? ''
    : ` NotOnOrAfter="${a.notOnOrAfter ?? iso(300_000)}"`) +
  '/>';

/** The signed-Response validator on a response whose Subject holds exactly these. */
const refusalFor = (confirmations: string[], ctx = context) =>
  validator().validate(encode(buildResponse({ confirmations })), ctx);

describe("the signed-Response validator (Saml2PureProvider's default)", () => {
  it('refuses a malformed certificate at construction, not at login', () => {
    expect(() =>
      createSignedResponseValidator({ idpCertificates: ['AAAA'] }),
    ).toThrow(/not a valid X.509 certificate/i);
  });

  // A bad entry must not hide a good one: normalising the whole list up front
  // is what stops the rotation loop aborting on its first element.
  it('refuses a list whose first entry is malformed, whatever follows', () => {
    expect(() =>
      createSignedResponseValidator({
        idpCertificates: ['AAAA', KEY.certificatePem],
      }),
    ).toThrow(/not a valid X.509 certificate/i);
  });

  it('accepts a well-formed assertion and reports what the flow needs', async () => {
    const result = await validator().validate(encode(buildResponse()), context);
    expect(result.assertionId).toBe('_a1');
    // signedXml is the element this validator required — the Response, which
    // carries Status. Without this the assertion-only case below is the only
    // one pinning signedXml, and an implementation that always returned the
    // Assertion would satisfy the suite.
    expect(result.signedXml).toContain('samlp:Response');
    expect(result.signedXml).toContain('samlp:Status');
    expect(result.issuer).toBe(ISSUER);
    expect(result.nameId).toBe('mock-user');
    expect(result.expiresAt.getTime()).toBeGreaterThan(Date.now());
  });

  it('accepts an assertion-signed document through the other validator', async () => {
    const result = await assertionValidator().validate(
      encode(buildResponse({ signWhat: 'assertion' })),
      context,
    );
    expect(result.assertionId).toBe('_a1');
  });

  // Each validator refuses the placement it was not built for. This is the
  // refusal that makes shipping two meaningful rather than decorative.
  it('the signed-Response validator refuses an assertion-signed document', async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ signWhat: 'assertion' })),
        context,
      ),
    ).rejects.toMatchObject({
      check: 'signedNode',
      message: expect.stringMatching(
        /does not cover the samlp:Response this validator requires/,
      ),
    });
  });

  it('the assertion-only validator refuses a response-signed document', async () => {
    await expect(
      assertionValidator().validate(
        encode(buildResponse({ signWhat: 'response' })),
        context,
      ),
    ).rejects.toMatchObject({
      check: 'signedNode',
      message: expect.stringMatching(
        /does not cover the saml:Assertion this validator requires/,
      ),
    });
  });

  // The three fields it does not read. Each is a refusal for the
  // signed-Response validator and an acceptance here, and both halves need
  // pinning: a validator that silently dropped a check and one documented as
  // not performing it look identical from outside.
  it('the assertion-only validator accepts a failed Status', async () => {
    const result = await assertionValidator().validate(
      encode(
        buildResponse({
          signWhat: 'assertion',
          status: 'urn:oasis:names:tc:SAML:2.0:status:Responder',
        }),
      ),
      context,
    );
    expect(result.assertionId).toBe('_a1');
  });

  it('the assertion-only validator accepts a wrong Destination', async () => {
    const result = await assertionValidator().validate(
      encode(
        buildResponse({
          signWhat: 'assertion',
          destination: 'http://elsewhere/acs',
        }),
      ),
      context,
    );
    expect(result.assertionId).toBe('_a1');
  });

  it('the assertion-only validator accepts a missing Destination', async () => {
    const result = await assertionValidator().validate(
      encode(buildResponse({ signWhat: 'assertion', destination: null })),
      context,
    );
    expect(result.assertionId).toBe('_a1');
  });

  // signedXml is the signed element, not the response — the difference
  // between "signed" and "arrived".
  it('reports the signed element separately from what arrived', async () => {
    const result = await assertionValidator().validate(
      encode(buildResponse({ signWhat: 'assertion' })),
      context,
    );
    expect(result.signedXml).toContain('Assertion');
    expect(result.signedXml).not.toContain('samlp:Status');
    expect(Buffer.from(result.raw, 'base64').toString('utf8')).toContain(
      'samlp:Status',
    );
  });

  it('refuses a Status that is not Success', async () => {
    await expect(
      validator().validate(
        encode(
          buildResponse({
            status: 'urn:oasis:names:tc:SAML:2.0:status:Responder',
          }),
        ),
        context,
      ),
    ).rejects.toMatchObject({
      check: 'status',
      message: expect.stringMatching(/declined the login/),
    });
  });

  it('refuses an assertion with no ID', async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ assertionId: null })),
        context,
      ),
    ).rejects.toMatchObject({ check: 'assertionId' });
  });

  it('refuses an assertion with no Issuer', async () => {
    await expect(
      validator().validate(encode(buildResponse({ issuer: null })), context),
    ).rejects.toMatchObject({
      check: 'issuer',
      message: expect.stringMatching(/the assertion carries no saml:Issuer/),
    });
  });

  it('refuses an Issuer that is not the one configured', async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ issuer: 'urn:someone:else' })),
        context,
      ),
    ).rejects.toMatchObject({
      check: 'issuer',
      message: expect.stringMatching(/not the trusted issuer/),
    });
  });

  it('refuses a Response Issuer disagreeing with the Assertion Issuer', async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ responseIssuer: 'urn:someone:else' })),
        context,
      ),
    ).rejects.toMatchObject({
      check: 'issuer',
      message: expect.stringMatching(/name different issuers/),
    });
  });

  it('refuses an assertion with no Conditions', async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ conditions: null })),
        context,
      ),
    ).rejects.toMatchObject({
      check: 'conditions',
      message: expect.stringMatching(
        /the assertion carries no saml:Conditions/,
      ),
    });
  });

  // Two siblings are an ambiguity, not a choice: resolving it in favour of
  // the first is how a forged element comes to be read in preference to a
  // real one. The first names us, the second does not — reading only the
  // first would accept. Built from the valid fixture, its signature removed
  // and the Response re-signed after the second Conditions is added, so the
  // signature is intact and only the ambiguity can refuse it.
  it('refuses an assertion carrying two Conditions', async () => {
    const unsigned = buildResponse().replace(
      /<(\w+:)?Signature[\s>][\s\S]*?<\/(\w+:)?Signature>/,
      '',
    );
    const second =
      `<saml:Conditions NotBefore="${iso(-60_000)}" NotOnOrAfter="${iso(300_000)}">` +
      `<saml:AudienceRestriction><saml:Audience>urn:someone:else</saml:Audience>` +
      `</saml:AudienceRestriction></saml:Conditions>`;
    const twice = unsigned.replace(
      '</saml:Conditions>',
      `</saml:Conditions>${second}`,
    );
    const signed = signXml(twice, KEY, {
      referenceXPath: "//*[local-name(.)='Response']",
      location: {
        reference: "//*[local-name(.)='Response']",
        action: 'prepend',
      },
    });
    expect(signed.match(/<saml:Conditions/g)).toHaveLength(2);
    await expect(
      validator().validate(encode(signed), context),
    ).rejects.toMatchObject({
      check: 'conditions',
      message: expect.stringMatching(
        /the assertion carries 2 saml:Conditions; exactly one is allowed/,
      ),
    });
  });

  // Cardinality: every exactly-once element says which way its count failed.
  // Each fixture is signed after the alteration (alteredResponse), and the
  // premise probe proves the Response is what the signature covers.
  it('refuses a Response carrying no direct-child Assertion', async () => {
    const xml = alteredResponse((u) =>
      u.replace(/<saml:Assertion[\s\S]*<\/saml:Assertion>/, ''),
    );
    expect(signedElementsOf(xml)[0].localName).toBe('Response');
    await expect(
      validator().validate(encode(xml), context),
    ).rejects.toMatchObject({
      check: 'signedNode',
      message: expect.stringMatching(
        /the response carries no direct-child saml:Assertion/,
      ),
    });
  });

  it('refuses a Response carrying two direct-child Assertions', async () => {
    const xml = alteredResponse((u) => {
      const assertion =
        /<saml:Assertion[\s\S]*<\/saml:Assertion>/.exec(u)?.[0] ?? '';
      return u.replace(
        assertion,
        `${assertion}${assertion.replace('ID="_a1"', 'ID="_a2"')}`,
      );
    });
    expect(signedElementsOf(xml)[0].localName).toBe('Response');
    await expect(
      validator().validate(encode(xml), context),
    ).rejects.toMatchObject({
      check: 'signedNode',
      message: expect.stringMatching(
        /the response carries 2 direct-child saml:Assertion; exactly one is allowed/,
      ),
    });
  });

  // The assertion-only validator meets the same rule: the signed Assertion
  // moved into the unsigned Extensions still verifies, and the Response then
  // has no direct-child Assertion at all.
  it('refuses, under the assertion-only validator, an Assertion that sits only in Extensions', async () => {
    const original = buildResponse({ signWhat: 'assertion' });
    const assertion =
      /<saml:Assertion[\s\S]*<\/saml:Assertion>/.exec(original)?.[0] ?? '';
    const xml = original
      .replace(assertion, '')
      .replace(
        '<samlp:Status>',
        `<samlp:Extensions>${assertion}</samlp:Extensions><samlp:Status>`,
      );
    expect(signedElementsOf(xml)[0].getAttribute('ID')).toBe('_a1');
    await expect(
      assertionValidator().validate(encode(xml), context),
    ).rejects.toMatchObject({
      check: 'signedNode',
      message: expect.stringMatching(
        /the response carries no direct-child saml:Assertion/,
      ),
    });
  });

  it('refuses a Response with no Status', async () => {
    const xml = alteredResponse((u) =>
      u.replace(/<samlp:Status>[\s\S]*?<\/samlp:Status>/, ''),
    );
    expect(signedElementsOf(xml)[0].localName).toBe('Response');
    await expect(
      validator().validate(encode(xml), context),
    ).rejects.toMatchObject({
      check: 'status',
      message: expect.stringMatching(/the response carries no samlp:Status/),
    });
  });

  it('refuses a Response with two Status elements', async () => {
    const xml = alteredResponse((u) =>
      u.replace(
        '</samlp:Status>',
        '</samlp:Status><samlp:Status><samlp:StatusCode ' +
          'Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>',
      ),
    );
    expect(signedElementsOf(xml)[0].localName).toBe('Response');
    await expect(
      validator().validate(encode(xml), context),
    ).rejects.toMatchObject({
      check: 'status',
      message: expect.stringMatching(
        /the response carries 2 samlp:Status; exactly one is allowed/,
      ),
    });
  });

  it('refuses a Status with no StatusCode', async () => {
    const xml = alteredResponse((u) =>
      u.replace(/<samlp:StatusCode [^>]*\/>/, ''),
    );
    expect(signedElementsOf(xml)[0].localName).toBe('Response');
    await expect(
      validator().validate(encode(xml), context),
    ).rejects.toMatchObject({
      check: 'status',
      message: expect.stringMatching(
        /the samlp:Status carries no samlp:StatusCode/,
      ),
    });
  });

  it('refuses a Status with two StatusCode elements', async () => {
    const xml = alteredResponse((u) =>
      u.replace(/(<samlp:StatusCode [^>]*\/>)/, '$1$1'),
    );
    expect(signedElementsOf(xml)[0].localName).toBe('Response');
    await expect(
      validator().validate(encode(xml), context),
    ).rejects.toMatchObject({
      check: 'status',
      message: expect.stringMatching(
        /the samlp:Status carries 2 samlp:StatusCode; exactly one is allowed/,
      ),
    });
  });

  it('refuses a StatusCode with no Value', async () => {
    const xml = alteredResponse((u) =>
      u.replace(/<samlp:StatusCode [^>]*\/>/, '<samlp:StatusCode/>'),
    );
    expect(signedElementsOf(xml)[0].localName).toBe('Response');
    await expect(
      validator().validate(encode(xml), context),
    ).rejects.toMatchObject({
      check: 'status',
      message: expect.stringMatching(/the samlp:StatusCode carries no Value/),
    });
  });

  // The default fixture has no Response Issuer, so the first </saml:Issuer>
  // is the assertion's.
  it('refuses an assertion carrying two Issuers', async () => {
    const xml = alteredResponse((u) =>
      u.replace(
        '</saml:Issuer>',
        '</saml:Issuer><saml:Issuer>urn:someone:else</saml:Issuer>',
      ),
    );
    expect(signedElementsOf(xml)[0].localName).toBe('Response');
    await expect(
      validator().validate(encode(xml), context),
    ).rejects.toMatchObject({
      check: 'issuer',
      message: expect.stringMatching(
        /the assertion carries 2 saml:Issuer; exactly one is allowed/,
      ),
    });
  });

  it('refuses an assertion whose Issuer is empty', async () => {
    await expect(
      validator().validate(encode(buildResponse({ issuer: '' })), context),
    ).rejects.toMatchObject({
      check: 'issuer',
      message: expect.stringMatching(/the assertion's saml:Issuer is empty/),
    });
  });

  it('refuses an AudienceRestriction naming no audience at all', async () => {
    await expect(
      validator().validate(encode(buildResponse({ audiences: [[]] })), context),
    ).rejects.toMatchObject({
      check: 'audience',
      message: expect.stringMatching(
        /an AudienceRestriction names no audience/,
      ),
    });
  });

  // NameID is surfaced, never refused: none, or more than one, is undefined.
  it('reports no nameId when the Subject carries none', async () => {
    const xml = alteredResponse((u) =>
      u.replace('<saml:NameID>mock-user</saml:NameID>', ''),
    );
    const result = await validator().validate(encode(xml), context);
    expect(result.nameId).toBeUndefined();
  });

  it('reports no nameId when the Subject carries two', async () => {
    const xml = alteredResponse((u) =>
      u.replace(
        '<saml:NameID>mock-user</saml:NameID>',
        '<saml:NameID>mock-user</saml:NameID><saml:NameID>other</saml:NameID>',
      ),
    );
    const result = await validator().validate(encode(xml), context);
    expect(result.nameId).toBeUndefined();
  });

  it('refuses an assertion with no NotOnOrAfter', async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ notOnOrAfter: null })),
        context,
      ),
    ).rejects.toMatchObject({
      check: 'notOnOrAfter',
      message: expect.stringMatching(/Conditions carries no NotOnOrAfter/),
    });
  });

  // An empty NotOnOrAfter is not a value to parse — it is the attribute
  // stating nothing, exactly as its absence does.
  it('treats an empty Conditions NotOnOrAfter as absent', async () => {
    const xml = alteredResponse((u) =>
      u.replace(
        /(<saml:Conditions[^>]*) NotOnOrAfter="[^"]*"/,
        '$1 NotOnOrAfter=""',
      ),
    );
    await expect(
      validator().validate(encode(xml), context),
    ).rejects.toMatchObject({
      check: 'notOnOrAfter',
      message: expect.stringMatching(/Conditions carries no NotOnOrAfter/),
    });
  });

  it('refuses a NotOnOrAfter that is not a valid xsd:dateTime', async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ notOnOrAfter: '2026-02-30T00:00:00Z' })),
        context,
      ),
    ).rejects.toMatchObject({
      check: 'notOnOrAfter',
      message: expect.stringMatching(
        /Conditions NotOnOrAfter is not a valid xsd:dateTime: "2026-02-30T00:00:00Z"/,
      ),
    });
  });

  it('refuses an expired assertion', async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ notOnOrAfter: iso(-1000) })),
        context,
      ),
    ).rejects.toMatchObject({
      check: 'notOnOrAfter',
      message: expect.stringMatching(/has expired/),
    });
  });

  it('accepts an expired assertion inside the configured skew', async () => {
    const result = await validator({ clockSkewMs: 60_000 }).validate(
      encode(buildResponse({ notOnOrAfter: iso(-1000) })),
      context,
    );
    expect(result.assertionId).toBe('_a1');
  });

  it('refuses an assertion that is not yet valid', async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ notBefore: iso(300_000) })),
        context,
      ),
    ).rejects.toMatchObject({
      check: 'notBefore',
      message: expect.stringMatching(/not valid yet/),
    });
  });

  it('refuses an assertion with no AudienceRestriction', async () => {
    await expect(
      validator().validate(encode(buildResponse({ audiences: null })), context),
    ).rejects.toMatchObject({
      check: 'audience',
      message: expect.stringMatching(/restricts no audience/),
    });
  });

  it('refuses an audience that is not ours', async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ audiences: [['urn:someone:else']] })),
        context,
      ),
    ).rejects.toMatchObject({
      check: 'audience',
      message: expect.stringMatching(/does not name us/),
    });
  });

  it('accepts our audience among alternatives inside one restriction', async () => {
    const result = await validator().validate(
      encode(buildResponse({ audiences: [['urn:someone:else', AUDIENCE]] })),
      context,
    );
    expect(result.assertionId).toBe('_a1');
  });

  // AND across restrictions: one permitting and one excluding must be refused.
  // Implemented as "our audience appears somewhere", this passes.
  it('refuses when a second restriction excludes us', async () => {
    await expect(
      validator().validate(
        encode(
          buildResponse({ audiences: [[AUDIENCE], ['urn:someone:else']] }),
        ),
        context,
      ),
    ).rejects.toMatchObject({
      check: 'audience',
      message: expect.stringMatching(/does not name us/),
    });
  });

  it('refuses when there is no bearer confirmation at all', async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ confirmations: null })),
        context,
      ),
    ).rejects.toMatchObject({
      check: 'bearerConfirmation',
      message: expect.stringMatching(
        /the saml:Subject holds no SubjectConfirmation/,
      ),
    });
  });

  // Option B. Each case is load-bearing on its own half of the rule: without
  // the `hasAttribute` branch the second goes green wrongly; without the
  // equality the third does.
  const unsolicitedConfirmation =
    `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
    `<saml:SubjectConfirmationData Recipient="${ACS}" ` +
    `NotOnOrAfter="${iso(300_000)}"/></saml:SubjectConfirmation>`;
  // The same context with no expected request ID — an IdP-initiated login.
  const { expectedInResponseTo: _requestId, ...unsolicitedContext } = context;

  it('accepts an unsolicited assertion when no request ID is expected', async () => {
    const result = await validator().validate(
      encode(buildResponse({ confirmations: [unsolicitedConfirmation] })),
      unsolicitedContext,
    );
    expect(result.assertionId).toBe('_a1');
  });

  it('refuses an InResponseTo when no request ID is expected', async () => {
    // The ordinary valid fixture, whose confirmation answers REQUEST_ID.
    await expect(
      validator().validate(encode(buildResponse()), unsolicitedContext),
    ).rejects.toMatchObject({
      check: 'bearerConfirmation',
      message: expect.stringMatching(
        /qualifies: #1 InResponseTo is present, but this login sent no request$/,
      ),
    });
  });

  it('refuses a missing InResponseTo when one is expected', async () => {
    // Absence never satisfies an expectation.
    await expect(
      validator().validate(
        encode(buildResponse({ confirmations: [unsolicitedConfirmation] })),
        context,
      ),
    ).rejects.toMatchObject({
      check: 'bearerConfirmation',
      message: expect.stringMatching(
        /qualifies: #1 InResponseTo does not answer our request$/,
      ),
    });
  });

  it('accepts a response signed at both levels, under either validator', async () => {
    // Many identity providers sign the Response and the Assertion both: take
    // the assertion-signed fixture and sign the Response around it, the
    // Signature first since this fixture has no Response Issuer.
    const both = signXml(buildResponse({ signWhat: 'assertion' }), KEY, {
      referenceXPath: "//*[local-name(.)='Response']",
      location: {
        reference: "//*[local-name(.)='Response']",
        action: 'prepend',
      },
    });
    expect(
      (await validator().validate(encode(both), context)).assertionId,
    ).toBe('_a1');
    expect(
      (await assertionValidator().validate(encode(both), context)).assertionId,
    ).toBe('_a1');
  });

  // The saml2-bearer grant exchanges an Assertion; 3.0.0 accepts one bare.
  const bareAssertion = () =>
    /<saml:Assertion[\s\S]*<\/saml:Assertion>/.exec(
      buildResponse({ signWhat: 'assertion' }),
    )?.[0] ?? '';

  it('the assertion-only validator accepts a bare signed Assertion', async () => {
    const result = await assertionValidator().validate(
      Buffer.from(bareAssertion()).toString('base64url'),
      context,
    );
    expect(result.assertionId).toBe('_a1');
  });

  it('the signed-Response validator refuses a bare Assertion', async () => {
    await expect(
      validator().validate(encode(bareAssertion()), context),
    ).rejects.toMatchObject({
      check: 'document',
      message: expect.stringMatching(
        /expected the document element to be a samlp:Response/,
      ),
    });
  });

  it('refuses a confirmation whose InResponseTo is not ours', async () => {
    await expect(
      validator().validate(
        encode(
          buildResponse({
            confirmations: [
              `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
                `<saml:SubjectConfirmationData InResponseTo="_other" Recipient="${ACS}" ` +
                `NotOnOrAfter="${iso(300_000)}"/></saml:SubjectConfirmation>`,
            ],
          }),
        ),
        context,
      ),
    ).rejects.toMatchObject({
      check: 'bearerConfirmation',
      message: expect.stringMatching(
        /qualifies: #1 InResponseTo does not answer our request$/,
      ),
    });
  });

  it('refuses a confirmation whose Recipient is not our ACS', async () => {
    await expect(
      validator().validate(
        encode(
          buildResponse({
            confirmations: [
              `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
                `<saml:SubjectConfirmationData InResponseTo="${REQUEST_ID}" ` +
                `Recipient="http://elsewhere/acs" NotOnOrAfter="${iso(300_000)}"/>` +
                `</saml:SubjectConfirmation>`,
            ],
          }),
        ),
        context,
      ),
    ).rejects.toMatchObject({
      check: 'bearerConfirmation',
      message: expect.stringMatching(/qualifies: #1 Recipient is not the ACS$/),
    });
  });

  it('refuses a confirmation whose own window has closed, though Conditions are open', async () => {
    await expect(
      validator().validate(
        encode(
          buildResponse({
            notOnOrAfter: iso(300_000),
            confirmations: [
              `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
                `<saml:SubjectConfirmationData InResponseTo="${REQUEST_ID}" Recipient="${ACS}" ` +
                `NotOnOrAfter="${iso(-1000)}"/></saml:SubjectConfirmation>`,
            ],
          }),
        ),
        context,
      ),
    ).rejects.toMatchObject({
      check: 'bearerConfirmation',
      message: expect.stringMatching(/qualifies: #1 NotOnOrAfter has passed$/),
    });
  });

  // The fields must come from ONE confirmation. Here each is right in a
  // different element, and the assertion must still be refused.
  it('refuses when the right values are spread across two confirmations', async () => {
    await expect(
      validator().validate(
        encode(
          buildResponse({
            confirmations: [
              `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
                `<saml:SubjectConfirmationData InResponseTo="${REQUEST_ID}" ` +
                `Recipient="http://elsewhere/acs" NotOnOrAfter="${iso(300_000)}"/>` +
                `</saml:SubjectConfirmation>`,
              `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
                `<saml:SubjectConfirmationData InResponseTo="_other" Recipient="${ACS}" ` +
                `NotOnOrAfter="${iso(300_000)}"/></saml:SubjectConfirmation>`,
            ],
          }),
        ),
        context,
      ),
    ).rejects.toMatchObject({
      check: 'bearerConfirmation',
      message: expect.stringMatching(
        /qualifies: #1 Recipient is not the ACS \| #2 InResponseTo does not answer our request$/,
      ),
    });
  });

  it('refuses a Response with no Destination', async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ destination: null })),
        context,
      ),
    ).rejects.toMatchObject({
      check: 'destination',
      message: expect.stringMatching(/carries no Destination/),
    });
  });

  it('refuses a Destination naming somewhere else', async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ destination: 'http://elsewhere/acs' })),
        context,
      ),
    ).rejects.toMatchObject({
      check: 'destination',
      message: expect.stringMatching(/not to us/),
    });
  });

  it('refuses the same assertion twice', async () => {
    const shared = validator();
    const payload = encode(buildResponse());
    await shared.validate(payload, context);
    await expect(shared.validate(payload, context)).rejects.toMatchObject({
      check: 'replay',
    });
  });

  // Retention must outlast the skew window: inside it the assertion is still
  // acceptable, so the store must still remember it.
  it('refuses a replay inside the skew window', async () => {
    const shared = createSignedResponseValidator({
      idpCertificates: [KEY.certificatePem],
      replayStore: createInMemoryReplayStore(),
      clockSkewMs: 60_000,
    });
    const payload = encode(buildResponse({ notOnOrAfter: iso(-1000) }));
    await shared.validate(payload, context);
    await expect(shared.validate(payload, context)).rejects.toMatchObject({
      check: 'replay',
    });
  });

  it('takes expiresAt from whichever window closes first', async () => {
    const result = await validator().validate(
      encode(
        buildResponse({
          notOnOrAfter: iso(600_000),
          confirmations: [
            `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
              `<saml:SubjectConfirmationData InResponseTo="${REQUEST_ID}" Recipient="${ACS}" ` +
              `NotOnOrAfter="${iso(120_000)}"/></saml:SubjectConfirmation>`,
          ],
        }),
      ),
      context,
    );
    expect(result.expiresAt.getTime()).toBeLessThan(Date.now() + 300_000);
  });

  // The wrapping shape at the validator level: one genuinely signed assertion,
  // one forged beside it. Reading only the signed one is not enough, because
  // Saml2PureProvider hands the whole payload to the cookie provider.
  //
  // The fixture is assertion-signed on purpose. Under a signed Response the
  // insert changes the bytes the Response's digest covers, so the signature
  // check refuses first and the one-assertion guard is never reached. With
  // only the Assertion signed and the Response unsigned, the forged sibling
  // leaves every signature intact — the probe below proves it — and it is
  // the guard that must refuse.
  it('refuses a response carrying a second, forged assertion', async () => {
    const forged =
      `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_forged">` +
      `<saml:Issuer>urn:attacker</saml:Issuer></saml:Assertion>`;
    const doctored = buildResponse({ signWhat: 'assertion' }).replace(
      '</samlp:Response>',
      `${forged}</samlp:Response>`,
    );

    // The premise: the signature still verifies and covers exactly the one
    // genuine Assertion, so a refusal cannot be coming from step 2.
    const covered = resolveSignedElements(
      doctored,
      new DOMParser().parseFromString(
        doctored,
        'text/xml',
      ) as unknown as Document,
      [toPem(KEY.certificatePem)],
    );
    expect(covered).toHaveLength(1);
    expect(covered[0].localName).toBe('Assertion');
    expect(covered[0].getAttribute('ID')).toBe('_a1');

    await expect(
      assertionValidator().validate(encode(doctored), context),
    ).rejects.toMatchObject({
      check: 'signedNode',
      message: expect.stringMatching(
        /carries 2 direct-child saml:Assertion; exactly one is allowed/,
      ),
    });
  });

  it('refuses a document carrying two elements with the same ID', async () => {
    const doctored = buildResponse().replace('ID="_r1"', 'ID="_a1"');
    await expect(
      validator().validate(encode(doctored), context),
    ).rejects.toMatchObject({
      check: 'duplicateId',
    });
  });

  // Wrapping, the other way round: the genuine signed Assertion is buried in
  // a forged one's Advice, and the forged one stands where a reader looks.
  // The genuine signature is untouched — each probe proves it — so only the
  // rule that the signed element IS the one read can refuse these.
  const forgedWrapping = () => {
    const genuine = bareAssertion();
    const forged = stripSignature(genuine).replace('ID="_a1"', 'ID="_forged"');
    return forged.replace(
      /<\/saml:Assertion>$/,
      `<saml:Advice>${genuine}</saml:Advice></saml:Assertion>`,
    );
  };

  it('refuses a bare forged Assertion carrying the signed one in its Advice', async () => {
    const attack = forgedWrapping();
    const covered = signedElementsOf(attack);
    expect(covered).toHaveLength(1);
    expect(covered[0].getAttribute('ID')).toBe('_a1');
    expect(
      (
        new DOMParser().parseFromString(attack, 'text/xml')
          .documentElement as unknown as { getAttribute(n: string): string }
      ).getAttribute('ID'),
    ).toBe('_forged');

    await expect(
      assertionValidator().validate(encode(attack), context),
    ).rejects.toMatchObject({
      check: 'signedNode',
      message: expect.stringMatching(
        /does not cover the saml:Assertion this validator requires/,
      ),
    });
  });

  it('refuses a Response whose Assertion is forged and wraps the signed one', async () => {
    const attack =
      `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
      `xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Destination="${ACS}">` +
      `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
      `${forgedWrapping()}</samlp:Response>`;
    const covered = signedElementsOf(attack);
    expect(covered).toHaveLength(1);
    expect(covered[0].getAttribute('ID')).toBe('_a1');

    await expect(
      assertionValidator().validate(encode(attack), context),
    ).rejects.toMatchObject({
      check: 'signedNode',
      message: expect.stringMatching(
        /does not cover the saml:Assertion this validator requires/,
      ),
    });
  });

  // An unrelated, genuinely signed assertion nested inside the unsigned
  // direct-child Assertion. The signature is valid and covers only _inner, so
  // only placement — the direct-child Assertion must be the element signed —
  // can refuse it.
  it('refuses a Response whose unsigned Assertion carries an unrelated signed one inside it', async () => {
    const inner = signXml(
      `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_inner">` +
        `<saml:Issuer>${ISSUER}</saml:Issuer></saml:Assertion>`,
      KEY,
    );
    const outer = stripSignature(bareAssertion()).replace(
      '</saml:Conditions>',
      `</saml:Conditions><saml:Advice>${inner}</saml:Advice>`,
    );
    const attack =
      `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
      `xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Destination="${ACS}">` +
      `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
      `${outer}</samlp:Response>`;
    expect(signedElementsOf(attack).map((e) => e.getAttribute('ID'))).toEqual([
      '_inner',
    ]);

    await expect(
      assertionValidator().validate(encode(attack), context),
    ).rejects.toMatchObject({
      check: 'signedNode',
      message: expect.stringMatching(
        /does not cover the saml:Assertion this validator requires/,
      ),
    });
  });

  // The genuinely signed Response, intact inside the Extensions of a forged
  // outer Response that carries a forged assertion. The signature verifies —
  // over the inner Response, which is not the document element.
  it('refuses a forged Response carrying the genuinely signed Response in its Extensions', async () => {
    const genuine = buildResponse();
    const forged = (
      /<saml:Assertion[\s\S]*<\/saml:Assertion>/.exec(genuine)?.[0] ?? ''
    ).replace('ID="_a1"', 'ID="_forged"');
    const attack =
      `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
      `xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_outer" Destination="${ACS}">` +
      `<samlp:Extensions>${genuine}</samlp:Extensions>` +
      `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
      `${forged}</samlp:Response>`;
    expect(
      signedElementsOf(attack).map(
        (e) => `${e.localName}:${e.getAttribute('ID')}`,
      ),
    ).toEqual(['Response:_r1']);

    await expect(
      validator().validate(encode(attack), context),
    ).rejects.toMatchObject({
      check: 'signedNode',
      message: expect.stringMatching(
        /does not cover the samlp:Response this validator requires/,
      ),
    });
  });

  // Every Assertion or EncryptedAssertion in the document must be the one
  // read, or inside it. Under the assertion-only validator the wrapper is
  // unsigned, so anything placed in it survives the signature — and the cookie
  // provider reads the whole payload.
  it('refuses a forged Assertion hidden in the unsigned Extensions', async () => {
    const doctored = buildResponse({ signWhat: 'assertion' }).replace(
      '<samlp:Status>',
      `<samlp:Extensions><saml:Assertion ID="_forged">` +
        `<saml:Issuer>urn:attacker</saml:Issuer></saml:Assertion></samlp:Extensions>` +
        `<samlp:Status>`,
    );
    const covered = signedElementsOf(doctored);
    expect(covered).toHaveLength(1);
    expect(covered[0].getAttribute('ID')).toBe('_a1');

    await expect(
      assertionValidator().validate(encode(doctored), context),
    ).rejects.toMatchObject({
      check: 'signedNode',
      message: expect.stringMatching(/outside the one the signature covers/),
    });
  });

  it('refuses an EncryptedAssertion beside the signed Assertion', async () => {
    const doctored = buildResponse({ signWhat: 'assertion' }).replace(
      '</samlp:Response>',
      `<saml:EncryptedAssertion><xenc:EncryptedData ` +
        `xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"/></saml:EncryptedAssertion>` +
        `</samlp:Response>`,
    );
    const covered = signedElementsOf(doctored);
    expect(covered).toHaveLength(1);
    expect(covered[0].getAttribute('ID')).toBe('_a1');

    await expect(
      assertionValidator().validate(encode(doctored), context),
    ).rejects.toMatchObject({
      check: 'signedNode',
      message: expect.stringMatching(/outside the one the signature covers/),
    });
  });

  // SAML 1.x is assertion-shaped too: a later reader may take it for the real
  // one. The premise probe shows the signature is untouched, so only the
  // stray-assertion rule can refuse it.
  it('refuses a SAML 1.x Assertion hidden in the unsigned Extensions', async () => {
    const doctored = buildResponse({ signWhat: 'assertion' }).replace(
      '<samlp:Status>',
      '<samlp:Extensions><saml1:Assertion ' +
        'xmlns:saml1="urn:oasis:names:tc:SAML:1.0:assertion" ' +
        'AssertionID="_forged1" Issuer="urn:attacker"/></samlp:Extensions>' +
        '<samlp:Status>',
    );
    const covered = signedElementsOf(doctored);
    expect(covered).toHaveLength(1);
    expect(covered[0].getAttribute('ID')).toBe('_a1');

    await expect(
      assertionValidator().validate(encode(doctored), context),
    ).rejects.toMatchObject({
      check: 'signedNode',
      message: expect.stringMatching(
        /SAML 2\.0 or 1\.x, outside the one the signature covers/,
      ),
    });
  });

  // Same rule, proven under the signed-Response validator too: a SAML 1.x
  // stray assertion is checked whichever element the signature covers.
  it('refuses a SAML 1.x Assertion hidden in the unsigned Extensions, under the signed-Response validator', async () => {
    const xml = alteredResponse((u) =>
      u.replace(
        '<samlp:Status>',
        '<samlp:Extensions><saml1:Assertion ' +
          'xmlns:saml1="urn:oasis:names:tc:SAML:1.0:assertion"/></samlp:Extensions>' +
          '<samlp:Status>',
      ),
    );
    await expect(
      validator().validate(encode(xml), context),
    ).rejects.toMatchObject({
      check: 'signedNode',
      message: expect.stringMatching(
        /SAML 2\.0 or 1\.x, outside the one the signature covers/,
      ),
    });
  });

  // An enveloped signature leaves its own ds:Signature out of the digest, so
  // ds:Object inside it is unsigned. The walk up from an element placed there
  // reaches the signed assertion, and would call it "inside" it.
  const intoFirstSignature = (xml: string, what: string) =>
    xml.replace(
      /(<\/(\w+:)?Signature>)/,
      `<ds:Object xmlns:ds="http://www.w3.org/2000/09/xmldsig#">${what}</ds:Object>$1`,
    );
  const HIDDEN = {
    'a SAML 2.0 Assertion':
      '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_hidden"><saml:Issuer>evil</saml:Issuer></saml:Assertion>',
    'an EncryptedAssertion':
      '<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>',
    'a SAML 1.x Assertion':
      '<s1:Assertion xmlns:s1="urn:oasis:names:tc:SAML:1.0:assertion" AssertionID="_hidden1"/>',
  } as const;

  it.each(Object.entries(HIDDEN))(
    "refuses %s inside the signed assertion's own ds:Signature",
    async (_label, hidden) => {
      const xml = intoFirstSignature(
        buildResponse({ signWhat: 'assertion' }),
        hidden,
      );
      // Premise: the signature still verifies and covers the assertion, so
      // only the stray rule can refuse this document.
      expect(signedElementsOf(xml).map((e) => e.localName)).toEqual([
        'Assertion',
      ]);
      await expect(
        assertionValidator().validate(encode(xml), context),
      ).rejects.toMatchObject({
        check: 'signedNode',
        message: expect.stringContaining('inside a ds:Signature'),
      });
    },
  );

  // Only the xmldsig namespace makes an element a signature. An element that
  // merely has the local name Signature, in any other namespace, is ordinary
  // content: an Advice assertion inside it is inside the signed assertion and
  // is accepted.
  it.each([
    ['a private namespace', 'urn:x'],
    ['xmldsig 1.1', 'http://www.w3.org/2009/xmldsig11#'],
  ])(
    'accepts an Advice assertion inside a Signature element from %s',
    async (_label, ns) => {
      const xml = alteredResponse((u) =>
        u.replace(
          '</saml:Conditions>',
          `</saml:Conditions><saml:Advice><x:Signature xmlns:x="${ns}">` +
            '<saml:Assertion ID="_advice"><saml:Issuer>x</saml:Issuer></saml:Assertion>' +
            '</x:Signature></saml:Advice>',
        ),
      );
      expect(signedElementsOf(xml).map((e) => e.localName)).toEqual([
        'Response',
      ]);
      await expect(
        validator().validate(encode(xml), context),
      ).resolves.toBeDefined();
    },
  );

  it("refuses an Assertion inside the signed Response's own ds:Signature", async () => {
    const xml = intoFirstSignature(
      buildResponse({ signWhat: 'response' }),
      HIDDEN['a SAML 2.0 Assertion'],
    );
    expect(signedElementsOf(xml).map((e) => e.localName)).toEqual(['Response']);
    await expect(
      validator().validate(encode(xml), context),
    ).rejects.toMatchObject({
      check: 'signedNode',
      message: expect.stringContaining('inside a ds:Signature'),
    });
  });

  // Row 5b. Both are signed after the Issuers are in place, so the signature
  // covers them and only the rule can refuse.
  it('refuses a Response carrying two Issuers', async () => {
    const twice = stripSignature(
      buildResponse({ responseIssuer: ISSUER }),
    ).replace(
      '</saml:Issuer>',
      '</saml:Issuer><saml:Issuer>urn:someone:else</saml:Issuer>',
    );
    const signed = signXml(twice, KEY, {
      referenceXPath: "//*[local-name(.)='Response']",
      location: {
        reference:
          "//*[local-name(.)='Response']/*[local-name(.)='Issuer'][last()]",
        action: 'after',
      },
    });
    const covered = signedElementsOf(signed);
    expect(covered).toHaveLength(1);
    expect(covered[0].localName).toBe('Response');

    await expect(
      validator().validate(encode(signed), context),
    ).rejects.toMatchObject({
      check: 'issuer',
      message: expect.stringMatching(/at most one saml:Issuer/),
    });
  });

  it('refuses an empty Response Issuer', async () => {
    const signed = buildResponse({ responseIssuer: '' });
    // signXml serialises the empty element self-closed.
    expect(signed).toContain('<saml:Issuer/>');
    expect(signedElementsOf(signed)[0].localName).toBe('Response');

    await expect(
      validator().validate(encode(signed), context),
    ).rejects.toMatchObject({
      check: 'issuer',
      message: expect.stringMatching(/name different issuers/),
    });
  });

  // Fail closed: with nothing to compare against, any issuer whose key we
  // hold would do, which is not what a shipped validator promises.
  it('refuses when no expectedIssuer was configured', async () => {
    const { expectedIssuer: _issuer, ...noIssuer } = context;
    await expect(
      validator().validate(encode(buildResponse()), noIssuer),
    ).rejects.toMatchObject({
      check: 'issuer',
      message: expect.stringMatching(/no expectedIssuer was configured/),
    });
  });

  // Row 10's sub-rules, each on its own.
  it('refuses a holder-of-key confirmation', async () => {
    await expect(
      validator().validate(
        encode(
          buildResponse({
            confirmations: [
              `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:holder-of-key">` +
                `<saml:SubjectConfirmationData InResponseTo="${REQUEST_ID}" Recipient="${ACS}" ` +
                `NotOnOrAfter="${iso(300_000)}"/></saml:SubjectConfirmation>`,
            ],
          }),
        ),
        context,
      ),
    ).rejects.toMatchObject({
      check: 'bearerConfirmation',
      message: expect.stringMatching(/qualifies: #1 Method is not bearer$/),
    });
  });

  it('refuses a confirmation that is not valid yet', async () => {
    await expect(
      validator().validate(
        encode(
          buildResponse({
            confirmations: [
              `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
                `<saml:SubjectConfirmationData InResponseTo="${REQUEST_ID}" Recipient="${ACS}" ` +
                `NotBefore="${iso(300_000)}" NotOnOrAfter="${iso(600_000)}"/>` +
                `</saml:SubjectConfirmation>`,
            ],
          }),
        ),
        context,
      ),
    ).rejects.toMatchObject({
      check: 'bearerConfirmation',
      message: expect.stringMatching(
        /qualifies: #1 NotBefore has not arrived$/,
      ),
    });
  });

  it('takes the earliest window when two confirmations qualify', async () => {
    const early = iso(120_000);
    const bearer = (notOnOrAfter: string) =>
      `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
      `<saml:SubjectConfirmationData InResponseTo="${REQUEST_ID}" Recipient="${ACS}" ` +
      `NotOnOrAfter="${notOnOrAfter}"/></saml:SubjectConfirmation>`;
    const result = await validator().validate(
      encode(
        buildResponse({
          notOnOrAfter: iso(900_000),
          confirmations: [bearer(iso(600_000)), bearer(early)],
        }),
      ),
      context,
    );
    expect(result.expiresAt.toISOString()).toBe(early);
  });

  // Check 10. Subject first: exactly once, and holding a confirmation.
  it('refuses an assertion with no Subject', async () => {
    const xml = alteredResponse((u) =>
      u.replace(/<saml:Subject>[\s\S]*?<\/saml:Subject>/, ''),
    );
    expect(signedElementsOf(xml)[0].localName).toBe('Response');
    await expect(
      validator().validate(encode(xml), context),
    ).rejects.toMatchObject({
      check: 'bearerConfirmation',
      message: expect.stringMatching(/the assertion carries no saml:Subject/),
    });
  });

  it('refuses an assertion carrying two Subjects', async () => {
    const xml = alteredResponse((u) =>
      u.replace(
        '</saml:Subject>',
        '</saml:Subject><saml:Subject><saml:NameID>other</saml:NameID></saml:Subject>',
      ),
    );
    expect(signedElementsOf(xml)[0].localName).toBe('Response');
    await expect(
      validator().validate(encode(xml), context),
    ).rejects.toMatchObject({
      check: 'bearerConfirmation',
      message: expect.stringMatching(
        /the assertion carries 2 saml:Subject; exactly one is allowed/,
      ),
    });
  });

  // Each sub-rule on a single candidate: exactly one reason, anchored.
  it('refuses a bearer confirmation with no SubjectConfirmationData', async () => {
    await expect(refusalFor([confirmation('')])).rejects.toMatchObject({
      check: 'bearerConfirmation',
      message: expect.stringMatching(
        /qualifies: #1 carries no SubjectConfirmationData$/,
      ),
    });
  });

  it('refuses a bearer confirmation with two SubjectConfirmationData', async () => {
    await expect(
      refusalFor([confirmation(confirmationData() + confirmationData())]),
    ).rejects.toMatchObject({
      check: 'bearerConfirmation',
      message: expect.stringMatching(
        /qualifies: #1 carries 2 SubjectConfirmationData; exactly one is allowed$/,
      ),
    });
  });

  it('refuses a confirmation with no NotOnOrAfter', async () => {
    await expect(
      refusalFor([confirmation(confirmationData({ notOnOrAfter: null }))]),
    ).rejects.toMatchObject({
      check: 'bearerConfirmation',
      message: expect.stringMatching(
        /qualifies: #1 SubjectConfirmationData has no NotOnOrAfter$/,
      ),
    });
  });

  it('refuses a confirmation whose NotOnOrAfter is not a valid xsd:dateTime', async () => {
    await expect(
      refusalFor([
        confirmation(confirmationData({ notOnOrAfter: INVALID_DATE })),
      ]),
    ).rejects.toMatchObject({
      check: 'bearerConfirmation',
      message: expect.stringMatching(
        /qualifies: #1 SubjectConfirmationData NotOnOrAfter is not a valid xsd:dateTime$/,
      ),
    });
  });

  it('refuses a confirmation whose NotBefore is not a valid xsd:dateTime', async () => {
    await expect(
      refusalFor([confirmation(confirmationData({ notBefore: INVALID_DATE }))]),
    ).rejects.toMatchObject({
      check: 'bearerConfirmation',
      message: expect.stringMatching(
        /qualifies: #1 SubjectConfirmationData NotBefore is not a valid xsd:dateTime$/,
      ),
    });
  });

  // Every candidate is evaluated, and named in document order.
  it('names every candidate in document order: a wrong Recipient, then an expired one', async () => {
    await expect(
      refusalFor([
        confirmation(confirmationData({ recipient: ELSEWHERE })),
        confirmation(confirmationData({ notOnOrAfter: iso(-1000) })),
      ]),
    ).rejects.toMatchObject({
      check: 'bearerConfirmation',
      message: expect.stringMatching(
        /qualifies: #1 Recipient is not the ACS \| #2 NotOnOrAfter has passed$/,
      ),
    });
  });

  // Existential: stopping at the first failing candidate would refuse this.
  it('accepts an invalid candidate followed by a valid one', async () => {
    const result = await validator().validate(
      encode(
        buildResponse({
          confirmations: [
            confirmation(confirmationData({ recipient: ELSEWHERE })),
            confirmation(confirmationData()),
          ],
        }),
      ),
      context,
    );
    expect(result.assertionId).toBe('_a1');
  });

  it('names at most five candidates, then how many more', async () => {
    await expect(
      refusalFor(
        Array.from({ length: 7 }, () =>
          confirmation(confirmationData(), HOLDER_OF_KEY),
        ),
      ),
    ).rejects.toMatchObject({
      check: 'bearerConfirmation',
      message:
        'no bearer confirmation qualifies: #1 Method is not bearer | ' +
        '#2 Method is not bearer | #3 Method is not bearer | ' +
        '#4 Method is not bearer | #5 Method is not bearer | and 2 more',
    });
  });

  // The fixed order: each row fails two adjacent sub-rules, and only the
  // earlier one may be reported.
  const FIRST_FAILED: Array<[string, string, string]> = [
    [
      'Method before SubjectConfirmationData',
      confirmation('', HOLDER_OF_KEY),
      'Method is not bearer',
    ],
    [
      'SubjectConfirmationData count before InResponseTo',
      confirmation(
        confirmationData({ inResponseTo: '_other' }) + confirmationData(),
      ),
      'carries 2 SubjectConfirmationData; exactly one is allowed',
    ],
    [
      'InResponseTo before Recipient',
      confirmation(
        confirmationData({ inResponseTo: '_other', recipient: ELSEWHERE }),
      ),
      'InResponseTo does not answer our request',
    ],
    [
      'Recipient before NotOnOrAfter',
      confirmation(
        confirmationData({ recipient: ELSEWHERE, notOnOrAfter: null }),
      ),
      'Recipient is not the ACS',
    ],
    [
      'NotOnOrAfter validity before NotBefore validity',
      confirmation(
        confirmationData({
          notOnOrAfter: INVALID_DATE,
          notBefore: INVALID_DATE,
        }),
      ),
      'SubjectConfirmationData NotOnOrAfter is not a valid xsd:dateTime',
    ],
    [
      'NotBefore validity before the window',
      confirmation(
        confirmationData({ notBefore: INVALID_DATE, notOnOrAfter: iso(-1000) }),
      ),
      'SubjectConfirmationData NotBefore is not a valid xsd:dateTime',
    ],
    [
      'NotOnOrAfter passed before NotBefore not arrived',
      confirmation(
        confirmationData({ notBefore: iso(300_000), notOnOrAfter: iso(-1000) }),
      ),
      'NotOnOrAfter has passed',
    ],
  ];

  it.each(FIRST_FAILED)(
    'reports the first sub-rule a candidate fails: %s',
    async (_order, only, reason) => {
      await expect(refusalFor([only])).rejects.toMatchObject({
        check: 'bearerConfirmation',
        message: `no bearer confirmation qualifies: #1 ${reason}`,
      });
    },
  );

  // Replay retention is bounded by the LATEST confirmation that can still let
  // the assertion in, not by the session's (earliest) window. The reviewer's
  // case: confirmations closing at +120 s and +600 s, Conditions at +900 s.
  // At +200 s the first has closed but the second still qualifies, so the
  // assertion is acceptable again — and the store must still remember it.
  describe('replay retention across several qualifying confirmations', () => {
    afterEach(() => {
      jest.restoreAllMocks();
    });

    const bearer = (notOnOrAfter: string, notBefore?: string) =>
      `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
      `<saml:SubjectConfirmationData InResponseTo="${REQUEST_ID}" Recipient="${ACS}" ` +
      `${notBefore ? `NotBefore="${notBefore}" ` : ''}` +
      `NotOnOrAfter="${notOnOrAfter}"/></saml:SubjectConfirmation>`;

    it('refuses a replay at +200 s when a later confirmation still qualifies', async () => {
      const t0 = Date.now();
      const payload = encode(
        buildResponse({
          notOnOrAfter: iso(900_000),
          confirmations: [bearer(iso(120_000)), bearer(iso(600_000))],
        }),
      );
      const shared = validator();

      const first = await shared.validate(payload, context);
      // The session still ends with the earliest window.
      expect(first.expiresAt.getTime()).toBeLessThanOrEqual(t0 + 120_000);

      jest.spyOn(Date, 'now').mockReturnValue(t0 + 200_000);
      await expect(shared.validate(payload, context)).rejects.toMatchObject({
        check: 'replay',
        message: expect.stringMatching(/presented before/),
      });
    });

    // A confirmation not open yet at the first presentation qualifies once
    // its NotBefore arrives, so it bounds retention too.
    it('refuses a replay once a confirmation that was not yet open qualifies', async () => {
      const t0 = Date.now();
      const payload = encode(
        buildResponse({
          notOnOrAfter: iso(900_000),
          confirmations: [
            bearer(iso(120_000)),
            bearer(iso(600_000), iso(150_000)),
          ],
        }),
      );
      const shared = validator();

      await shared.validate(payload, context);

      jest.spyOn(Date, 'now').mockReturnValue(t0 + 200_000);
      await expect(shared.validate(payload, context)).rejects.toMatchObject({
        check: 'replay',
        message: expect.stringMatching(/presented before/),
      });
    });

    it('never retains past Conditions, plus skew', async () => {
      const t0 = Date.now();
      let retained: Date | undefined;
      const spyStore = {
        async recordIfUnseen(_key: unknown, retainUntil: Date) {
          retained = retainUntil;
          return true;
        },
      };
      await createSignedResponseValidator({
        idpCertificates: [KEY.certificatePem],
        replayStore: spyStore,
        clockSkewMs: 5_000,
      }).validate(
        encode(
          buildResponse({
            notOnOrAfter: new Date(t0 + 300_000).toISOString(),
            confirmations: [
              bearer(iso(120_000)),
              bearer(new Date(t0 + 600_000).toISOString()),
            ],
          }),
        ),
        context,
      );
      expect(retained?.getTime()).toBe(
        new Date(new Date(t0 + 300_000).toISOString()).getTime() + 5_000,
      );
    });
  });

  it('refuses a Conditions NotBefore that is not a valid xsd:dateTime', async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ notBefore: '2026-02-30T00:00:00Z' })),
        context,
      ),
    ).rejects.toMatchObject({
      check: 'notBefore',
      message: expect.stringMatching(/NotBefore is not a valid xsd:dateTime/),
    });
  });

  // The replay key is the pair: one ID from two trusted issuers is two
  // assertions, not a replay.
  it('accepts one ID from two issuers through one store', async () => {
    const shared = validator();
    const first = await shared.validate(encode(buildResponse()), context);
    const second = await shared.validate(
      encode(buildResponse({ issuer: 'urn:mock:idp2' })),
      { ...context, expectedIssuer: 'urn:mock:idp2' },
    );
    expect(first.assertionId).toBe('_a1');
    expect(second.assertionId).toBe('_a1');
    expect(second.issuer).toBe('urn:mock:idp2');
  });

  // Only an accepted assertion is recorded: a refusal must not use up the ID.
  it('a refused presentation does not use up the assertion', async () => {
    const shared = validator();
    const payload = encode(buildResponse());
    await expect(
      shared.validate(payload, { ...context, acsUrl: 'http://elsewhere/acs' }),
    ).rejects.toMatchObject({
      check: 'bearerConfirmation',
      message: expect.stringMatching(/qualifies: #1 Recipient is not the ACS$/),
    });
    const result = await shared.validate(payload, context);
    expect(result.assertionId).toBe('_a1');
  });

  // No DTD, whatever it holds: the document is parsed by two xmldom versions,
  // and a DOCTYPE is where parsers diverge. The rest of the document is
  // genuinely signed, so only the DOCTYPE rule can refuse it.
  it('refuses a document carrying a DOCTYPE declaration', async () => {
    const withDoctype = `<!DOCTYPE samlp:Response>${buildResponse()}`;
    expect(signedElementsOf(withDoctype)[0].localName).toBe('Response');
    await expect(
      validator().validate(encode(withDoctype), context),
    ).rejects.toMatchObject({
      check: 'document',
      message: expect.stringMatching(/carries a DOCTYPE declaration/),
    });
  });

  // Read before any signature is verified, so attacker-chosen: a newline
  // smuggled in as &#10; must not reach the message raw.
  it('quotes a duplicated ID, so a newline in it cannot forge a log line', async () => {
    const doctored =
      `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
      `xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_x&#10;forged">` +
      `<saml:Assertion ID="_x&#10;forged"/></samlp:Response>`;
    const refusal = validator()
      .validate(encode(doctored), context)
      .then(
        () => undefined,
        (error: Error & { check?: string }) => error,
      );
    const error = await refusal;
    expect(error?.check).toBe('duplicateId');
    expect(error?.message).not.toContain('\n');
    expect(error?.message).toContain('"_x\\nforged"');
  });

  it('cuts a long untrusted value short in the message', async () => {
    const long = `_${'x'.repeat(200)}`;
    const doctored =
      `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
      `xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${long}">` +
      `<saml:Assertion ID="${long}"/></samlp:Response>`;
    await expect(
      validator().validate(encode(doctored), context),
    ).rejects.toMatchObject({
      check: 'duplicateId',
      message: expect.not.stringContaining(long),
    });
  });

  // Values read after the signature are the identity provider's text, not
  // ours: quoted, so a newline (&#10;) cannot forge a log line, and cut.
  it('quotes the Status code the identity provider declined with', async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ status: 'urn:x&#10;forged' })),
        context,
      ),
    ).rejects.toMatchObject({
      check: 'status',
      message: 'the identity provider declined the login: "urn:x\\nforged"',
    });
  });

  it('quotes an untrusted issuer', async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ issuer: 'urn:x&#10;forged' })),
        context,
      ),
    ).rejects.toMatchObject({
      check: 'issuer',
      message:
        'the assertion was issued by "urn:x\\nforged", not the trusted issuer',
    });
  });

  it('cuts a long issuer short', async () => {
    const long = `urn:${'x'.repeat(200)}`;
    await expect(
      validator().validate(encode(buildResponse({ issuer: long })), context),
    ).rejects.toMatchObject({
      check: 'issuer',
      message: `the assertion was issued by "${long.slice(0, 64)}…", not the trusted issuer`,
    });
  });

  const ROOT_REFUSALS: Array<[string, typeof validator, string]> = [
    [
      'signed-Response',
      validator,
      'expected the document element to be a samlp:Response, got ',
    ],
    [
      'assertion-only',
      assertionValidator,
      'expected a samlp:Response or a saml:Assertion, got ',
    ],
  ];

  it.each(ROOT_REFUSALS)(
    'quotes and cuts the root name in the %s validator refusal',
    async (_name, make, prefix) => {
      const name = `x${'y'.repeat(99)}`;
      await expect(
        make().validate(encode(`<${name}/>`), context),
      ).rejects.toMatchObject({
        check: 'document',
        message: `${prefix}"${name.slice(0, 64)}…"`,
      });
    },
  );

  it('quotes a Destination naming somewhere else', async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ destination: 'http://x&#10;forged' })),
        context,
      ),
    ).rejects.toMatchObject({
      check: 'destination',
      message: 'the response is addressed to "http://x\\nforged", not to us',
    });
  });

  it('quotes an invalid Conditions NotBefore', async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ notBefore: 'x&#10;forged' })),
        context,
      ),
    ).rejects.toMatchObject({
      check: 'notBefore',
      message: 'Conditions NotBefore is not a valid xsd:dateTime: "x\\nforged"',
    });
  });

  it('quotes an invalid Conditions NotOnOrAfter', async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ notOnOrAfter: 'x&#10;forged' })),
        context,
      ),
    ).rejects.toMatchObject({
      check: 'notOnOrAfter',
      message:
        'Conditions NotOnOrAfter is not a valid xsd:dateTime: "x\\nforged"',
    });
  });

  // The assertion read is the Response's direct-child Assertion, not the
  // first covered one. Here a genuinely signed assertion sits in the outer
  // assertion's Advice, and the outer one's signature was moved to its end,
  // so the Advice signature comes first in document order. Taking "the first
  // covered Assertion" would pick the Advice one and refuse a sound document.
  it('reads the direct-child Assertion when a signed Advice assertion comes first', async () => {
    const inner = signXml(
      `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_inner">` +
        `<saml:Issuer>${ISSUER}</saml:Issuer></saml:Assertion>`,
      KEY,
    );
    const outerUnsigned =
      `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1">` +
      `<saml:Issuer>${ISSUER}</saml:Issuer>` +
      `<saml:Subject><saml:NameID>mock-user</saml:NameID>` +
      `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
      `<saml:SubjectConfirmationData InResponseTo="${REQUEST_ID}" Recipient="${ACS}" ` +
      `NotOnOrAfter="${iso(300_000)}"/></saml:SubjectConfirmation></saml:Subject>` +
      `<saml:Conditions NotBefore="${iso(-60_000)}" NotOnOrAfter="${iso(300_000)}">` +
      `<saml:AudienceRestriction><saml:Audience>${AUDIENCE}</saml:Audience>` +
      `</saml:AudienceRestriction></saml:Conditions>` +
      `<saml:Advice>${inner}</saml:Advice></saml:Assertion>`;
    const outer = signXml(outerUnsigned, KEY, {
      referenceXPath: "/*[local-name(.)='Assertion']",
      location: {
        reference: "/*[local-name(.)='Assertion']",
        action: 'append',
      },
    });
    const response =
      `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
      `xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Destination="${ACS}">` +
      `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
      `${outer}</samlp:Response>`;

    // The premise: both signatures verify, and the Advice one comes first.
    const covered = signedElementsOf(response);
    expect(covered.map((e) => e.getAttribute('ID'))).toEqual(['_inner', '_a1']);

    const result = await assertionValidator().validate(
      encode(response),
      context,
    );
    expect(result.assertionId).toBe('_a1');
  });

  it('refuses something that is not XML', async () => {
    await expect(
      validator().validate(
        Buffer.from('nope', 'utf8').toString('base64'),
        context,
      ),
    ).rejects.toMatchObject({
      check: 'document',
      message: expect.stringMatching(/did not parse as XML/),
    });
  });

  // @xmldom/xmldom reports to the console unless given onError, and recovers
  // from an `error`-level fault (an undeclared entity) by returning a DOM.
  // Either would let an unauthenticated caller write to the process's stderr,
  // bypassing ILogger, or reach the later checks with a repaired document.
  it('refuses XML the parser would recover from, and writes nothing to the console', async () => {
    const spies = (['error', 'warn', 'log'] as const).map((level) =>
      jest.spyOn(console, level).mockImplementation(() => undefined),
    );
    try {
      for (const xml of [
        `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r">&bogus;</samlp:Response>`,
        '<a><b></a>',
      ]) {
        await expect(
          validator().validate(
            Buffer.from(xml, 'utf8').toString('base64'),
            context,
          ),
        ).rejects.toMatchObject({
          check: 'document',
          message: expect.stringMatching(/did not parse as XML/),
        });
      }
      for (const spy of spies) expect(spy).not.toHaveBeenCalled();
    } finally {
      for (const spy of spies) spy.mockRestore();
    }
  });
});
