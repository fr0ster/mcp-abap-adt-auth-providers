import { describe, expect, it } from '@jest/globals';
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
    ).rejects.toMatchObject({ check: 'signedNode' });
  });

  it('the assertion-only validator refuses a response-signed document', async () => {
    await expect(
      assertionValidator().validate(
        encode(buildResponse({ signWhat: 'response' })),
        context,
      ),
    ).rejects.toMatchObject({ check: 'signedNode' });
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
    ).rejects.toMatchObject({ check: 'status' });
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
    ).rejects.toMatchObject({ check: 'issuer' });
  });

  it('refuses an Issuer that is not the one configured', async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ issuer: 'urn:someone:else' })),
        context,
      ),
    ).rejects.toMatchObject({ check: 'issuer' });
  });

  it('refuses a Response Issuer disagreeing with the Assertion Issuer', async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ responseIssuer: 'urn:someone:else' })),
        context,
      ),
    ).rejects.toMatchObject({ check: 'issuer' });
  });

  it('refuses an assertion with no Conditions', async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ conditions: null })),
        context,
      ),
    ).rejects.toMatchObject({ check: 'conditions' });
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
    ).rejects.toMatchObject({ check: 'conditions' });
  });

  it('refuses an assertion with no NotOnOrAfter', async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ notOnOrAfter: null })),
        context,
      ),
    ).rejects.toMatchObject({ check: 'notOnOrAfter' });
  });

  it('refuses a NotOnOrAfter that is not a valid xsd:dateTime', async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ notOnOrAfter: '2026-02-30T00:00:00Z' })),
        context,
      ),
    ).rejects.toMatchObject({ check: 'notOnOrAfter' });
  });

  it('refuses an expired assertion', async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ notOnOrAfter: iso(-1000) })),
        context,
      ),
    ).rejects.toMatchObject({ check: 'notOnOrAfter' });
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
    ).rejects.toMatchObject({ check: 'notBefore' });
  });

  it('refuses an assertion with no AudienceRestriction', async () => {
    await expect(
      validator().validate(encode(buildResponse({ audiences: null })), context),
    ).rejects.toMatchObject({ check: 'audience' });
  });

  it('refuses an audience that is not ours', async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ audiences: [['urn:someone:else']] })),
        context,
      ),
    ).rejects.toMatchObject({ check: 'audience' });
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
    ).rejects.toMatchObject({ check: 'audience' });
  });

  it('refuses when there is no bearer confirmation at all', async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ confirmations: null })),
        context,
      ),
    ).rejects.toMatchObject({ check: 'bearerConfirmation' });
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
    ).rejects.toMatchObject({ check: 'bearerConfirmation' });
  });

  it('refuses a missing InResponseTo when one is expected', async () => {
    // Absence never satisfies an expectation.
    await expect(
      validator().validate(
        encode(buildResponse({ confirmations: [unsolicitedConfirmation] })),
        context,
      ),
    ).rejects.toMatchObject({ check: 'bearerConfirmation' });
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
    ).rejects.toMatchObject({ check: 'document' });
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
    ).rejects.toMatchObject({ check: 'bearerConfirmation' });
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
    ).rejects.toMatchObject({ check: 'bearerConfirmation' });
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
    ).rejects.toMatchObject({ check: 'bearerConfirmation' });
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
    ).rejects.toMatchObject({ check: 'bearerConfirmation' });
  });

  it('refuses a Response with no Destination', async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ destination: null })),
        context,
      ),
    ).rejects.toMatchObject({ check: 'destination' });
  });

  it('refuses a Destination naming somewhere else', async () => {
    await expect(
      validator().validate(
        encode(buildResponse({ destination: 'http://elsewhere/acs' })),
        context,
      ),
    ).rejects.toMatchObject({ check: 'destination' });
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
    ).rejects.toMatchObject({ check: 'signedNode' });
  });

  it('refuses a document carrying two elements with the same ID', async () => {
    const doctored = buildResponse().replace('ID="_r1"', 'ID="_a1"');
    await expect(
      validator().validate(encode(doctored), context),
    ).rejects.toMatchObject({
      check: 'duplicateId',
    });
  });

  it('refuses something that is not XML', async () => {
    await expect(
      validator().validate(
        Buffer.from('nope', 'utf8').toString('base64'),
        context,
      ),
    ).rejects.toMatchObject({ check: 'document' });
  });
});
