/**
 * The shipped assertion validator: the spec's check table, in order.
 *
 * Two properties matter more than any individual check. First, the signature
 * is resolved to an element and every assertion-level field is read *from that
 * element* — a document holding a validly signed fragment beside a forged one
 * is the wrapping attack, and reading the wrong node is how it succeeds.
 * Second, no two refusals share a distinguishing phrase, so a test cannot pass
 * for a neighbouring check's reason.
 *
 * Three fields live on the Response rather than the assertion: Status,
 * Response/Issuer and Destination. The signed-Response validator reads them,
 * because there they are inside the signature. The assertion-only validator
 * does not read them at all — not weakly. That is safe because a declined
 * login carries no assertion, so flipping Status buys an attacker nothing they
 * can sign, and addressing rests on Recipient inside the signed assertion.
 */

import type {
  AssertionContext,
  IAssertionReplayStore,
  IAssertionValidator,
  ValidatedAssertion,
} from '@mcp-abap-adt/interfaces-auth';
import { type Document, type Element, XMLSerializer } from '@xmldom/xmldom';
import { parseStrictXml } from '../auth/strictXml';
import {
  type AssertionCheck,
  AssertionValidationError,
} from '../errors/AssertionValidationError';
import { findDuplicateId, readRequiredId } from './documentIds';
import { defaultReplayStore } from './inMemoryReplayStore';
import { quoteUntrusted, resolveSignedElements, toPem } from './signedNode';
import { parseXsdDateTime } from './xsdDateTime';

const SAML_NS = 'urn:oasis:names:tc:SAML:2.0:assertion';
const PROTOCOL_NS = 'urn:oasis:names:tc:SAML:2.0:protocol';
const BEARER = 'urn:oasis:names:tc:SAML:2.0:cm:bearer';
const SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success';

export interface ShippedValidatorOptions {
  readonly idpCertificates: readonly string[];
  readonly clockSkewMs?: number;
  readonly replayStore?: IAssertionReplayStore;
}

/**
 * Which element this validator insists the signature covers.
 *
 * Internal. The public surface is two factories, so a reader of a call site
 * sees the choice; making it a public parameter would put it back where nobody
 * looks.
 */
type SignedElement = 'response' | 'assertion';

/** How a refusal names the element each validator requires to be signed. */
const REQUIRED_LABEL: Record<SignedElement, string> = {
  response: 'samlp:Response',
  assertion: 'saml:Assertion',
};

/**
 * Marks a validator as one of the two shipped here. Module-private and
 * non-enumerable, so it is neither part of the public surface nor visible to
 * a consumer spreading or serialising the object.
 *
 * It exists for one reason: a shipped validator fails closed without
 * `expectedIssuer`, so a provider handed one must insist on `idpEntityId` at
 * construction — otherwise the mistake surfaces only as an `issuer` refusal
 * after a human has finished a browser login. A custom validator carries no
 * brand and may establish trust however it likes.
 */
const SHIPPED = Symbol('mcp-abap-adt.shippedAssertionValidator');

function brand(validator: IAssertionValidator): IAssertionValidator {
  Object.defineProperty(validator, SHIPPED, {
    value: true,
    enumerable: false,
  });
  return validator;
}

/** Whether this validator came from one of the two shipped factories. */
export function isShippedValidator(validator: IAssertionValidator): boolean {
  return (validator as unknown as Record<symbol, unknown>)[SHIPPED] === true;
}

export const createSignedResponseValidator = (
  options: ShippedValidatorOptions,
): IAssertionValidator => brand(createValidator('response', options));

export const createSignedAssertionValidator = (
  options: ShippedValidatorOptions,
): IAssertionValidator => brand(createValidator('assertion', options));

function createValidator(
  require: SignedElement,
  options: ShippedValidatorOptions,
): IAssertionValidator {
  const skew = options.clockSkewMs ?? 0;
  if (!Number.isInteger(skew) || skew < 0) {
    throw new Error(
      `clockSkewMs must be a finite non-negative integer, got ${String(options.clockSkewMs)}`,
    );
  }
  if (options.idpCertificates.length === 0) {
    throw new Error(
      'idpCertificates must not be empty: nothing could be verified',
    );
  }
  // Normalised and proved here, once, rather than inside verification. Three
  // reasons, and the last bites hardest: a malformed entry standing first in
  // the list would abort the rotation loop before a later valid certificate
  // was tried; a constructor is where this package already refuses a bad
  // configuration; and a login happens after a human has used a browser, so a
  // formatting mistake found then wastes their work, not ours.
  const certificates = options.idpCertificates.map(toPem);
  const store = options.replayStore ?? defaultReplayStore;

  return {
    async validate(samlResponse, context): Promise<ValidatedAssertion> {
      // 1. Parses, and the document element is a samlp:Response.
      const xml = Buffer.from(samlResponse, 'base64').toString('utf8');
      // No DTD, ever. A SAML message has no use for one, and a DOCTYPE is
      // where parsers diverge — entity expansion, internal subsets — and this
      // document is parsed twice: by @xmldom/xmldom 0.9 here and by the 0.8
      // nested inside xml-crypto. Refused before either parse is trusted.
      if (/<!DOCTYPE/i.test(xml)) {
        return fail(
          'document',
          'the SAMLResponse carries a DOCTYPE declaration, which is never accepted',
        );
      }
      let doc: Document;
      try {
        doc = parseStrictXml(xml) as unknown as Document;
      } catch {
        return fail('document', 'the SAMLResponse did not parse as XML');
      }
      const root = doc.documentElement as unknown as Element | null;
      if (!root)
        return fail('document', 'the SAMLResponse did not parse as XML');
      const rootIsResponse =
        root.localName === 'Response' && root.namespaceURI === PROTOCOL_NS;
      const rootIsAssertion =
        root.localName === 'Assertion' && root.namespaceURI === SAML_NS;
      // A bare Assertion is a document only the assertion-only validator
      // accepts: the saml2-bearer grant exchanges an Assertion, and 3.0.0
      // already takes one as Saml2BearerProvider's payload.
      if (!rootIsResponse && !(require === 'assertion' && rootIsAssertion)) {
        return fail(
          'document',
          require === 'assertion'
            ? `expected a samlp:Response or a saml:Assertion, got ${quoteUntrusted(root.localName ?? '')}`
            : `expected the document element to be a samlp:Response, got ${quoteUntrusted(root.localName ?? '')}`,
        );
      }

      // 1b. Unique IDs, before any reference is resolved.
      const duplicate = findDuplicateId(doc);
      if (duplicate) {
        return fail(
          'duplicateId',
          `the document uses the ID ${quoteUntrusted(duplicate)} more than once, so which element is signed is ambiguous`,
        );
      }

      // 2 + 3. Verify every signature, then take the element this validator
      // requires from among those they cover. A response signed at both
      // levels — as many identity providers send — satisfies either validator.
      let covered: Element[];
      try {
        covered = resolveSignedElements(xml, doc, certificates);
      } catch (error) {
        return fail('signature', (error as Error).message);
      }
      // 3a. A Response carries exactly one direct-child Assertion, and a
      // refusal says which way the count failed. Checked once, here, for both
      // validators: the signed-Response validator reads that assertion, and
      // the assertion-only validator requires it to be the element signed.
      const direct = rootIsResponse
        ? directChildren(root, SAML_NS, 'Assertion')
        : [];
      if (rootIsResponse && direct.length === 0) {
        return fail(
          'signedNode',
          'the response carries no direct-child saml:Assertion',
        );
      }
      if (direct.length > 1) {
        return fail(
          'signedNode',
          `the response carries ${direct.length} direct-child saml:Assertion; exactly one is allowed`,
        );
      }

      // 3b. The element this validator requires signed is fixed by the
      // document's shape, not by which signature happens to come first: the
      // Response itself, or for the assertion-only validator the bare root
      // Assertion or the Response's single direct-child Assertion. Taking
      // "the first covered Assertion" instead would pick a signed assertion
      // nested in Advice whenever its signature precedes the outer one's —
      // and a covered element anywhere but here is the wrapping attack.
      const target =
        require === 'response' || rootIsAssertion ? root : direct[0];
      const signed = covered.find((element) => element === target);
      if (!signed) {
        return fail(
          'signedNode',
          `the signature does not cover the ${REQUIRED_LABEL[require]} this validator requires`,
        );
      }

      // 3c. Everything below is read from `assertion` and nowhere else: the
      // bare root Assertion, or the Response's single direct-child one —
      // either the signed element itself or, when the Response is signed,
      // inside it.
      const assertion = rootIsAssertion ? root : direct[0];
      // 3d. Nothing assertion-shaped outside the one read. Wherever the
      // signature sits, the payload travels on whole — Saml2PureProvider hands
      // it to the cookie provider — so an Assertion or EncryptedAssertion in
      // an unsigned part of it (Extensions, a sibling, a wrapper) is something
      // a later reader may take for the real one.
      if (!everyAssertionWithin(doc, assertion)) {
        return fail(
          'signedNode',
          'the document carries a saml:Assertion or saml:EncryptedAssertion outside the one the signature covers',
        );
      }

      // 4. Status. Only when the Response is the signed element: otherwise it
      // lies outside the signature, and checking a field an attacker sets is
      // worse than not checking it — it reads like verification.
      if (require === 'response') {
        const status = requireOne(
          root,
          PROTOCOL_NS,
          'Status',
          'status',
          'the response',
          'samlp:Status',
        );
        const code = requireOne(
          status,
          PROTOCOL_NS,
          'StatusCode',
          'status',
          'the samlp:Status',
          'samlp:StatusCode',
        );
        const codeValue = code.getAttribute('Value');
        if (!codeValue) {
          return fail('status', 'the samlp:StatusCode carries no Value');
        }
        if (codeValue !== SUCCESS) {
          return fail(
            'status',
            `the identity provider declined the login: ${codeValue}`,
          );
        }
      }

      // 4b. The assertion's own ID.
      const assertionId = readRequiredId(assertion);
      if (!assertionId)
        return fail('assertionId', 'the assertion carries no ID');

      // 5. The assertion's Issuer — inside the signature either way, so both
      // validators check it.
      const issuer =
        requireOne(
          assertion,
          SAML_NS,
          'Issuer',
          'issuer',
          'the assertion',
          'saml:Issuer',
        ).textContent ?? '';
      if (!issuer) {
        return fail('issuer', "the assertion's saml:Issuer is empty");
      }
      // Fail closed: with nothing to compare against, any issuer whose key is
      // configured would pass, which is not what this validator promises.
      if (!context.expectedIssuer) {
        return fail(
          'issuer',
          'no expectedIssuer was configured, so the assertion issuer cannot be trusted',
        );
      }
      if (issuer !== context.expectedIssuer) {
        return fail(
          'issuer',
          `the assertion was issued by ${issuer}, not the trusted issuer`,
        );
      }
      // 5b. The cross-check against the Response's Issuer belongs to the
      // signed-Response validator alone: only there are both inside the
      // signature.
      if (require === 'response') {
        // Optional, so none is fine; but two are an ambiguity, and one that is
        // present must agree — empty included, since empty is not absent.
        const responseIssuers = directChildren(root, SAML_NS, 'Issuer');
        if (responseIssuers.length > 1) {
          return fail(
            'issuer',
            'the response must carry at most one saml:Issuer',
          );
        }
        if (
          responseIssuers.length === 1 &&
          (responseIssuers[0].textContent ?? '') !== issuer
        ) {
          return fail(
            'issuer',
            'the response and the assertion name different issuers',
          );
        }
      }

      // 6, 7, 8. Conditions and their window.
      const conditions = requireOne(
        assertion,
        SAML_NS,
        'Conditions',
        'conditions',
        'the assertion',
        'saml:Conditions',
      );

      const notBeforeRaw = conditions.getAttribute('NotBefore');
      if (notBeforeRaw) {
        const notBefore = parseXsdDateTime(notBeforeRaw);
        if (!notBefore) {
          return fail(
            'notBefore',
            `Conditions NotBefore is not a valid xsd:dateTime: ${notBeforeRaw}`,
          );
        }
        if (notBefore.getTime() - skew > Date.now()) {
          return fail('notBefore', 'the assertion is not valid yet');
        }
      }

      const notOnOrAfterRaw = conditions.getAttribute('NotOnOrAfter');
      if (!notOnOrAfterRaw) {
        return fail(
          'notOnOrAfter',
          'Conditions carries no NotOnOrAfter, so the assertion states no lifetime',
        );
      }
      const conditionsExpiry = parseXsdDateTime(notOnOrAfterRaw);
      if (!conditionsExpiry) {
        return fail(
          'notOnOrAfter',
          `Conditions NotOnOrAfter is not a valid xsd:dateTime: ${quoteUntrusted(notOnOrAfterRaw)}`,
        );
      }
      if (conditionsExpiry.getTime() + skew <= Date.now()) {
        return fail('notOnOrAfter', 'the assertion has expired');
      }

      // 9. Every AudienceRestriction must name us; several Audience inside one
      // are alternatives.
      const restrictions = directChildren(
        conditions,
        SAML_NS,
        'AudienceRestriction',
      );
      if (restrictions.length === 0) {
        return fail('audience', 'the assertion restricts no audience');
      }
      for (const restriction of restrictions) {
        const names = directChildren(restriction, SAML_NS, 'Audience').map(
          (a) => a.textContent ?? '',
        );
        if (names.length === 0) {
          return fail('audience', 'an AudienceRestriction names no audience');
        }
        if (!names.includes(context.audience)) {
          return fail(
            'audience',
            'an AudienceRestriction on this assertion does not name us',
          );
        }
      }

      // 10. One bearer confirmation satisfying everything together.
      const chosen = chooseBearerConfirmation(assertion, context, skew);
      if (!chosen) {
        return fail(
          'bearerConfirmation',
          'no single bearer SubjectConfirmation, under exactly one saml:Subject and with exactly one SubjectConfirmationData, answers our request, names our ACS and is still open',
        );
      }

      // 11. Destination — the signed-Response validator only, for the same
      // reason as Status. Addressing in the other flow rests on Recipient,
      // which step 10 required and which sits inside the signed assertion.
      if (require === 'response') {
        const destination = root.getAttribute('Destination');
        if (!destination) {
          return fail('destination', 'the response carries no Destination');
        }
        if (destination !== context.acsUrl) {
          return fail(
            'destination',
            `the response is addressed to ${destination}, not to us`,
          );
        }
      }

      // Expiry: the earlier of the two windows.
      const expiresAt = new Date(
        Math.min(conditionsExpiry.getTime(), chosen.notOnOrAfter.getTime()),
      );

      // 12. Replay. Retention is NOT expiresAt: it must last for as long as
      // this validator could accept the assertion again. Conditions bound
      // that, but so does the LATEST bearer confirmation that can qualify —
      // with confirmations closing at +120 s and +600 s the session ends at
      // +120 s, yet at +200 s the second one still qualifies, and an entry
      // dropped at +120 s would let the same assertion in a second time. The
      // skew is added on top, since inside it the assertion is still accepted.
      const retainUntil = new Date(
        Math.min(
          conditionsExpiry.getTime(),
          chosen.latestNotOnOrAfter.getTime(),
        ) + skew,
      );
      const fresh = await store.recordIfUnseen(
        { issuer, assertionId },
        retainUntil,
      );
      if (!fresh) {
        return fail('replay', 'this assertion has been presented before');
      }

      return {
        expiresAt,
        assertionId,
        issuer,
        nameId: (() => {
          // Subject, then NameID — no `?? assertion` fallback, which would
          // read a NameID from outside the Subject when the Subject is absent.
          const subject = directChild(assertion, SAML_NS, 'Subject');
          return subject
            ? (directChild(subject, SAML_NS, 'NameID')?.textContent ??
                undefined)
            : undefined;
        })(),
        raw: samlResponse,
        // The signed element, not the response: this is what a consumer may
        // parse without re-deriving what the signature covered.
        signedXml: new XMLSerializer().serializeToString(signed),
      };
    },
  };
}

function fail(check: AssertionCheck, message: string): never {
  throw new AssertionValidationError(check, message);
}

/**
 * Direct children with this namespace and local name — **not** descendants.
 *
 * `getElementsByTagNameNS` searches the whole subtree, and that is the wrong
 * tool for a structural path. An assertion with no `Conditions` of its own but
 * a `Conditions` buried somewhere inside it would answer the descendant search
 * and satisfy a check it does not meet; the same trick works for `Issuer`,
 * `Status` and `Subject`. Each segment of a SAML path is therefore walked
 * explicitly, one level at a time.
 */
function directChildren(parent: Element, ns: string, local: string): Element[] {
  const out: Element[] = [];
  const nodes = parent.childNodes;
  for (let i = 0; i < nodes.length; i++) {
    const node = nodes[i] as unknown as Element;
    // nodeType 1 is ELEMENT_NODE; the constant is unavailable without the dom
    // lib, which this project deliberately does not use.
    if (
      node.nodeType === 1 &&
      node.namespaceURI === ns &&
      node.localName === local
    ) {
      out.push(node);
    }
  }
  return out;
}

/** The single direct child with this name, or null when there is not exactly one. */
function directChild(
  parent: Element,
  ns: string,
  local: string,
): Element | null {
  const found = directChildren(parent, ns, local);
  // Not "the first": two siblings sharing a name is an ambiguity, and
  // resolving it silently in favour of the first is how a forged element comes
  // to be read in preference to a real one.
  return found.length === 1 ? found[0] : null;
}

/**
 * The single direct child with this name, or a refusal that says which way
 * the count failed: absent and more than one are different faults, and a
 * message that cannot tell them apart sends the reader to the wrong one.
 */
function requireOne(
  parent: Element,
  ns: string,
  local: string,
  check: AssertionCheck,
  holder: string,
  label: string,
): Element {
  const found = directChildren(parent, ns, local);
  if (found.length === 0) return fail(check, `${holder} carries no ${label}`);
  if (found.length > 1) {
    return fail(
      check,
      `${holder} carries ${found.length} ${label}; exactly one is allowed`,
    );
  }
  return found[0];
}

/**
 * Whether every `saml:Assertion` and `saml:EncryptedAssertion` in the
 * document is `assertion` itself or lies inside it.
 */
function everyAssertionWithin(doc: Document, assertion: Element): boolean {
  for (const local of ['Assertion', 'EncryptedAssertion']) {
    const found = doc.getElementsByTagNameNS(SAML_NS, local);
    for (let i = 0; i < found.length; i++) {
      let node = found[i] as unknown as Element | null;
      while (node && node !== assertion) {
        node = node.parentNode as unknown as Element | null;
      }
      if (!node) return false;
    }
  }
  return true;
}

/**
 * The bearer confirmation this login may rely on.
 *
 * Every part must hold on the **same** element: gathering `InResponseTo` from
 * one confirmation and `Recipient` from another is how a document satisfies a
 * check nothing in it actually satisfies. When several qualify — which a real
 * identity provider does not produce — the earliest window wins, so the
 * outcome is a shorter session rather than a longer one.
 *
 * `latestNotOnOrAfter` answers a different question: until when could some
 * confirmation let this assertion in? It is the latest `NotOnOrAfter` among
 * the confirmations that satisfy every non-temporal part — including one whose
 * `NotBefore` has not arrived yet, since it qualifies once it does. Replay
 * retention needs that bound, not the session's; see the caller.
 */
function chooseBearerConfirmation(
  assertion: Element,
  context: AssertionContext,
  skew: number,
): { notOnOrAfter: Date; latestNotOnOrAfter: Date } | null {
  const now = Date.now();
  let best: Date | null = null;
  let latest: Date | null = null;

  const subject = directChild(assertion, SAML_NS, 'Subject');
  if (!subject) return null;

  for (const confirmation of directChildren(
    subject,
    SAML_NS,
    'SubjectConfirmation',
  )) {
    if (confirmation.getAttribute('Method') !== BEARER) continue;

    const data = directChild(confirmation, SAML_NS, 'SubjectConfirmationData');
    if (!data) continue;
    // Option B: an expected ID must be matched exactly; no expected ID — an
    // IdP-initiated login — means the attribute must not be there at all.
    if (context.expectedInResponseTo === undefined) {
      if (data.hasAttribute('InResponseTo')) continue;
    } else if (
      data.getAttribute('InResponseTo') !== context.expectedInResponseTo
    ) {
      continue;
    }
    if (data.getAttribute('Recipient') !== context.acsUrl) continue;

    const notOnOrAfter = parseXsdDateTime(data.getAttribute('NotOnOrAfter'));
    if (!notOnOrAfter) continue;
    const notBeforeRaw = data.getAttribute('NotBefore');
    const notBefore = notBeforeRaw ? parseXsdDateTime(notBeforeRaw) : null;
    if (notBeforeRaw && !notBefore) continue;

    // Could qualify at some instant: counts towards how long to remember.
    if (!latest || notOnOrAfter.getTime() > latest.getTime()) {
      latest = notOnOrAfter;
    }

    // Qualifies now: a candidate for the session's window.
    if (notOnOrAfter.getTime() + skew <= now) continue;
    if (notBefore && notBefore.getTime() - skew > now) continue;

    if (!best || notOnOrAfter.getTime() < best.getTime()) best = notOnOrAfter;
  }

  // `latest` is set whenever `best` is: every qualifying confirmation was
  // counted towards it first.
  return best && latest
    ? { notOnOrAfter: best, latestNotOnOrAfter: latest }
    : null;
}
