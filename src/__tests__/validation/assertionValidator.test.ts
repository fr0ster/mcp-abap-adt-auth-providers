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
      message: expect.stringMatching(/does not cover the assertion/),
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
      message: expect.stringMatching(/does not cover the assertion/),
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
      message: expect.stringMatching(/exactly one non-empty saml:Issuer/),
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
      message: expect.stringMatching(/exactly one saml:Conditions/),
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
      message: expect.stringMatching(/exactly one saml:Conditions/),
    });
  });

  it('refuses an assertion with no NotOnOrAfter', async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ notOnOrAfter: null })),
        context,
      ),
    ).rejects.toMatchObject({
      check: 'notOnOrAfter',
      message: expect.stringMatching(/no usable NotOnOrAfter/),
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
      message: expect.stringMatching(/no usable NotOnOrAfter/),
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
      message: expect.stringMatching(/no single bearer SubjectConfirmation/),
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
      message: expect.stringMatching(/no single bearer SubjectConfirmation/),
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
      message: expect.stringMatching(/no single bearer SubjectConfirmation/),
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
      message: expect.stringMatching(/no single bearer SubjectConfirmation/),
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
      message: expect.stringMatching(/no single bearer SubjectConfirmation/),
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
      message: expect.stringMatching(/no single bearer SubjectConfirmation/),
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
      message: expect.stringMatching(/no single bearer SubjectConfirmation/),
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
      message: expect.stringMatching(/does not cover the assertion/),
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
      message: expect.stringMatching(/does not cover the assertion/),
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
      message: expect.stringMatching(/does not cover the assertion/),
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
      message: expect.stringMatching(/no single bearer SubjectConfirmation/),
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
      message: expect.stringMatching(/no single bearer SubjectConfirmation/),
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
    ).rejects.toMatchObject({ check: 'bearerConfirmation' });
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
});
