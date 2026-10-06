/**
 * How a test reads a SAML refusal (spec Appendix B): the thrown value is an
 * `AuthProviderFailure` whose minted `saml-assertion` error names its `rule`,
 * the `check` fixed by that rule, the rule's own words, and the one
 * diagnostic its row permits — or none.
 *
 * The words fragment and the check are written here as literals, not read
 * from auth-errors' tables: a test computing its expectation from the code
 * under test proves nothing. `RULE_WORDS` is a `Record` over every rule, so a
 * rule without a fragment does not compile.
 */
import { expect } from '@jest/globals';
import { AuthProviderFailure, isMinted } from '@mcp-abap-adt/auth-errors';
import type {
  AssertionCheck,
  AssertionRule,
  SamlAssertionError,
} from '@mcp-abap-adt/interfaces-auth';

/** Each rule's check (Appendix B's first column). */
export const RULE_CHECK: Readonly<Record<AssertionRule, AssertionCheck>> = {
  doctype: 'document',
  'not-xml': 'document',
  'root-not-response-or-assertion': 'document',
  'root-not-response': 'document',
  'duplicate-id': 'duplicateId',
  'no-signature': 'signature',
  'signature-malformed': 'signature',
  'signature-not-verified': 'signature',
  'no-reference': 'signature',
  'several-references': 'signature',
  'reference-not-same-document': 'signature',
  'reference-not-found': 'signature',
  'signature-not-enveloped': 'signature',
  'no-direct-assertion': 'signedNode',
  'several-direct-assertions': 'signedNode',
  'response-not-signed': 'signedNode',
  'assertion-not-signed': 'signedNode',
  'assertion-outside-signed': 'signedNode',
  'assertion-inside-signature': 'signedNode',
  'no-status': 'status',
  'several-status': 'status',
  'no-status-code': 'status',
  'several-status-codes': 'status',
  'status-code-no-value': 'status',
  declined: 'status',
  'no-assertion-id': 'assertionId',
  'no-issuer': 'issuer',
  'several-issuers': 'issuer',
  'empty-issuer': 'issuer',
  'no-expected-issuer': 'issuer',
  'untrusted-issuer': 'issuer',
  'several-response-issuers': 'issuer',
  'issuers-differ': 'issuer',
  'no-conditions': 'conditions',
  'several-conditions': 'conditions',
  'not-before-invalid': 'notBefore',
  'not-yet-valid': 'notBefore',
  'no-not-on-or-after': 'notOnOrAfter',
  'not-on-or-after-invalid': 'notOnOrAfter',
  expired: 'notOnOrAfter',
  'no-audience-restriction': 'audience',
  'audience-restriction-empty': 'audience',
  'audience-not-us': 'audience',
  'no-subject': 'bearerConfirmation',
  'several-subjects': 'bearerConfirmation',
  'no-subject-confirmation': 'bearerConfirmation',
  'no-bearer-qualifies': 'bearerConfirmation',
  'no-destination': 'destination',
  'destination-not-us': 'destination',
  replayed: 'replay',
  'payload-not-base64-xml': 'document',
  'payload-not-well-formed': 'document',
  'payload-not-saml': 'document',
  'only-encrypted-assertion': 'document',
  'no-assertion': 'document',
  'several-assertions': 'document',
};

/**
 * A fragment of each rule's words that no other rule under the same check
 * produces (the existing convention: no two rules under one check share a
 * message). A test asserting it fails when a neighbouring rule refused.
 */
export const RULE_WORDS: Readonly<Record<AssertionRule, string>> = {
  doctype: 'carries a DOCTYPE declaration',
  'not-xml': 'the SAMLResponse did not parse as XML',
  'root-not-response-or-assertion':
    'expected a samlp:Response or a saml:Assertion',
  'root-not-response': 'expected the document element to be a samlp:Response',
  'duplicate-id': 'uses an ID more than once',
  'no-signature': 'the document carries no signature',
  'signature-malformed': 'the signature element is malformed',
  'signature-not-verified':
    'does not verify against any configured certificate',
  'no-reference': 'the signature carries no ds:Reference',
  'several-references': 'ds:Reference; exactly one is allowed',
  'reference-not-same-document': 'is not a same-document URI',
  'reference-not-found': 'references an element that is not in the document',
  'signature-not-enveloped': 'is not inside the element it references',
  'no-direct-assertion': 'carries no direct-child saml:Assertion',
  'several-direct-assertions':
    'direct-child saml:Assertion; exactly one is allowed',
  'response-not-signed': 'does not cover the samlp:Response',
  'assertion-not-signed': 'does not cover the saml:Assertion',
  'assertion-outside-signed': 'outside the one the signature covers',
  'assertion-inside-signature': 'inside a ds:Signature',
  'no-status': 'the response carries no samlp:Status',
  'several-status': 'samlp:Status; exactly one is allowed',
  'no-status-code': 'the samlp:Status carries no samlp:StatusCode',
  'several-status-codes': 'samlp:StatusCode; exactly one is allowed',
  'status-code-no-value': 'the samlp:StatusCode carries no Value',
  declined: 'the identity provider declined the login',
  'no-assertion-id': 'the assertion carries no ID',
  'no-issuer': 'the assertion carries no saml:Issuer',
  'several-issuers': 'saml:Issuer; exactly one is allowed',
  'empty-issuer': "the assertion's saml:Issuer is empty",
  'no-expected-issuer': 'no expectedIssuer was configured',
  'untrusted-issuer': 'was not issued by the trusted issuer',
  'several-response-issuers': 'must carry at most one saml:Issuer',
  'issuers-differ': 'name different issuers',
  'no-conditions': 'the assertion carries no saml:Conditions',
  'several-conditions': 'saml:Conditions; exactly one is allowed',
  'not-before-invalid': 'Conditions NotBefore is not a valid xsd:dateTime',
  'not-yet-valid': 'the assertion is not valid yet',
  'no-not-on-or-after': 'Conditions carries no NotOnOrAfter',
  'not-on-or-after-invalid':
    'Conditions NotOnOrAfter is not a valid xsd:dateTime',
  expired: 'the assertion has expired',
  'no-audience-restriction': 'the assertion restricts no audience',
  'audience-restriction-empty': 'an AudienceRestriction names no audience',
  'audience-not-us': 'does not name us',
  'no-subject': 'the assertion carries no saml:Subject',
  'several-subjects': 'saml:Subject; exactly one is allowed',
  'no-subject-confirmation': 'holds no SubjectConfirmation',
  'no-bearer-qualifies': 'no bearer confirmation qualifies',
  'no-destination': 'the response carries no Destination',
  'destination-not-us': 'the response is not addressed to us',
  replayed: 'this assertion has been presented before',
  'payload-not-base64-xml': 'SAML bearer payload is not base64-encoded XML',
  'payload-not-well-formed': 'SAML bearer payload is not well-formed XML',
  'payload-not-saml': 'neither a SAML Response nor an Assertion',
  'only-encrypted-assertion': 'carries only an EncryptedAssertion',
  'no-assertion': 'SAML Response carries no Assertion',
  'several-assertions': 'a bearer grant takes one',
};

/** What a refusal is expected to carry beyond its rule. */
export interface SamlExpectation {
  /** The whole `diagnostics` object, or absent: then the error has none. */
  readonly diagnostics?: Readonly<Record<string, unknown>>;
  /** Facts beyond `rule` / `check`, matched as a subset. */
  readonly facts?: Readonly<Record<string, unknown>>;
}

/**
 * Asserts that `thrown` is this copy's `AuthProviderFailure` carrying a
 * minted `saml-assertion` error of `rule`, and answers that error.
 */
export function expectSamlRefusal(
  thrown: unknown,
  rule: AssertionRule,
  expected: SamlExpectation = {},
): SamlAssertionError {
  expect(thrown).toBeInstanceOf(AuthProviderFailure);
  if (!(thrown instanceof AuthProviderFailure)) throw new Error('unreachable');
  const error = thrown.error;
  expect(isMinted(error)).toBe(true);
  expect(error.kind).toBe('saml-assertion');
  if (error.kind !== 'saml-assertion') throw new Error('unreachable');
  expect(error.variant).toBe(rule);
  expect(error.facts.rule).toBe(rule);
  expect(error.facts.check).toBe(RULE_CHECK[rule]);
  expect(error.reason).toContain(
    `the SAML assertion was refused (${RULE_CHECK[rule]}): `,
  );
  expect(error.reason).toContain(RULE_WORDS[rule]);
  if (expected.facts !== undefined) {
    expect(error.facts).toMatchObject(expected.facts);
  }
  if (expected.diagnostics === undefined) {
    expect('diagnostics' in error).toBe(false);
  } else {
    expect(error.diagnostics).toEqual(expected.diagnostics);
  }
  return error;
}

/** What `run` throws, else the test fails. */
export function thrownBy(run: () => unknown): unknown {
  try {
    run();
  } catch (error) {
    return error;
  }
  throw new Error('expected a throw, got none');
}

/** What `promise` rejects with, else the test fails. */
export async function rejectionOf(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error('expected a rejection, got a fulfilment');
}

/** `promise` rejects with a refusal of `rule` (see `expectSamlRefusal`). */
export async function expectSamlRejection(
  promise: Promise<unknown>,
  rule: AssertionRule,
  expected: SamlExpectation = {},
): Promise<SamlAssertionError> {
  return expectSamlRefusal(await rejectionOf(promise), rule, expected);
}
