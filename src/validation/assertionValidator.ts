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

import {
  AuthProviderFailure,
  authError,
  count,
  isSamlStatusCode,
} from '@mcp-abap-adt/auth-errors';
import type {
  AssertionContext,
  IAssertionReplayStore,
  IAssertionValidator,
  ValidatedAssertion,
} from '@mcp-abap-adt/interfaces-auth';
import {
  type Document,
  type Element,
  type Node,
  XMLSerializer,
} from '@xmldom/xmldom';
import { misconfigured } from '../auth/configuration';
import { asContract } from '../auth/contractShape';
import type { SamlAssertionError } from '../auth/contractTransition';
import { parseStrictXml } from '../auth/strictXml';
import { findDuplicateId, readRequiredId } from './documentIds';
import { refuse, type SamlRefusal, several } from './samlRefusal';
import { resolveSignedElements, toPem } from './signedNode';
import { parseXsdDateTime } from './xsdDateTime';

const SAML_NS = 'urn:oasis:names:tc:SAML:2.0:assertion';
const PROTOCOL_NS = 'urn:oasis:names:tc:SAML:2.0:protocol';
const BEARER = 'urn:oasis:names:tc:SAML:2.0:cm:bearer';
const SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success';

const SAML1_NS = 'urn:oasis:names:tc:SAML:1.0:assertion';
const DSIG_NS = 'http://www.w3.org/2000/09/xmldsig#';

/**
 * Everything a later reader might take for the assertion: SAML 2.0's
 * Assertion and EncryptedAssertion, and SAML 1.x's Assertion.
 */
const ASSERTION_SHAPED: ReadonlyArray<readonly [string, string]> = [
  [SAML_NS, 'Assertion'],
  [SAML_NS, 'EncryptedAssertion'],
  [SAML1_NS, 'Assertion'],
];

export interface ShippedValidatorOptions {
  /**
   * The identity provider's signing certificates, PEM or bare base64 DER — the
   * form `<X509Certificate>` has in IdP metadata. A list, because keys rotate.
   * Each is parsed when the validator is built; an empty list is refused there.
   */
  readonly idpCertificates: readonly string[];
  /** Tolerance for the time checks, in ms; default `0`. */
  readonly clockSkewMs?: number | undefined;
  /**
   * Where accepted assertions are recorded so a second presentation is refused
   * as a replay. Required: `defaultReplayStore` (process-wide, in memory) or a
   * store of your own, whose `recordIfUnseen` must be atomic.
   */
  readonly replayStore: IAssertionReplayStore;
}

/**
 * Which element this validator insists the signature covers.
 *
 * Internal. The public surface is two factories, so a reader of a call site
 * sees the choice; making it a public parameter would put it back where nobody
 * looks.
 */
type SignedElement = 'response' | 'assertion';

/**
 * The refusal when the signature does not cover the element each validator
 * requires — a rule each, so the words name that element.
 */
const NOT_SIGNED: Record<SignedElement, () => SamlRefusal> = {
  response: () =>
    authError['saml-assertion']({
      rule: 'response-not-signed',
      check: 'signedNode',
    }),
  assertion: () =>
    authError['saml-assertion']({
      rule: 'assertion-not-signed',
      check: 'signedNode',
    }),
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
  const branded: IAssertionValidator & { readonly [SHIPPED]?: unknown } =
    validator;
  return branded[SHIPPED] === true;
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
    // E24: the value given is not echoed (L5).
    throw misconfigured(
      authError.configuration({
        case: 'validator-clock-skew-invalid',
        fields: ['clockSkewMs'],
      }),
    );
  }
  if (options.idpCertificates.length === 0) {
    // E25.
    throw misconfigured(
      authError.configuration({
        case: 'validator-no-certificates',
        fields: ['idpCertificates'],
      }),
    );
  }
  // Normalised and proved here, once, rather than inside verification. Three
  // reasons, and the last bites hardest: a malformed entry standing first in
  // the list would abort the rotation loop before a later valid certificate
  // was tried; a constructor is where this package already refuses a bad
  // configuration; and a login happens after a human has used a browser, so a
  // formatting mistake found then wastes their work, not ours.
  const certificates = options.idpCertificates.map(toPem);
  const store = options.replayStore;

  return {
    async validate(samlResponse, context): Promise<ValidatedAssertion> {
      // 1. Parses, and the document element is a samlp:Response.
      const xml = Buffer.from(samlResponse, 'base64').toString('utf8');
      // No DTD, ever. A SAML message has no use for one, and a DOCTYPE is
      // where parsers diverge — entity expansion, internal subsets — and this
      // document is parsed twice: by @xmldom/xmldom 0.9 here and by the 0.8
      // nested inside xml-crypto. Refused before either parse is trusted.
      if (carriesDoctype(xml)) {
        return refuse(
          authError['saml-assertion']({ rule: 'doctype', check: 'document' }),
        );
      }
      // parseStrictXml refuses with `not-xml` itself (F7).
      const doc: Document = parseStrictXml(xml);
      const root = doc.documentElement;
      if (!root) {
        return refuse(
          authError['saml-assertion']({ rule: 'not-xml', check: 'document' }),
        );
      }
      const rootIsResponse =
        root.localName === 'Response' && root.namespaceURI === PROTOCOL_NS;
      const rootIsAssertion =
        root.localName === 'Assertion' && root.namespaceURI === SAML_NS;
      // A bare Assertion is a document only the assertion-only validator
      // accepts: the saml2-bearer grant exchanges an Assertion, and 3.0.0
      // already takes one as Saml2BearerProvider's payload.
      if (!rootIsResponse && !(require === 'assertion' && rootIsAssertion)) {
        const rootElement = root.localName;
        return refuse(
          require === 'assertion'
            ? authError['saml-assertion'](
                { rule: 'root-not-response-or-assertion', check: 'document' },
                { rootElement },
              )
            : authError['saml-assertion'](
                { rule: 'root-not-response', check: 'document' },
                { rootElement },
              ),
        );
      }

      // 1b. Unique IDs, before any reference is resolved.
      const duplicate = findDuplicateId(doc);
      if (duplicate) {
        return refuse(
          authError['saml-assertion'](
            { rule: 'duplicate-id', check: 'duplicateId' },
            { id: duplicate },
          ),
        );
      }

      // 2 + 3. Verify every signature, then take the element this validator
      // requires from among those they cover. A response signed at both
      // levels — as many identity providers send — satisfies either validator.
      let covered: Element[];
      try {
        covered = resolveSignedElements(xml, doc, certificates);
      } catch (error) {
        // Each rule of verification refuses at its site; anything else the
        // walk throws is the signature's malformation (F8), with nothing of
        // what was thrown.
        if (error instanceof AuthProviderFailure) throw error;
        return refuse(
          authError['saml-assertion']({
            rule: 'signature-malformed',
            check: 'signature',
          }),
        );
      }
      // 3 + 4. For the signed-Response validator: the Response itself must be
      // signed, and then its Status is read before anything else — a
      // declined login carries no Assertion to count (see checkStatus).
      if (require === 'response') {
        if (!covered.includes(root)) {
          return refuse(NOT_SIGNED.response());
        }
        checkStatus(root);
      }

      // 3a. A Response carries exactly one direct-child Assertion, and a
      // refusal says which way the count failed. Checked once, here, for both
      // validators: the signed-Response validator reads that assertion, and
      // the assertion-only validator requires it to be the element signed.
      const direct = rootIsResponse
        ? directChildren(root, SAML_NS, 'Assertion')
        : [];
      // 3c. Everything below is read from `assertion` and nowhere else: the
      // bare root Assertion, or the Response's single direct-child one —
      // either the signed element itself or, when the Response is signed,
      // inside it.
      const assertion = rootIsResponse ? direct[0] : root;
      if (assertion === undefined) {
        return refuse(
          authError['saml-assertion']({
            rule: 'no-direct-assertion',
            check: 'signedNode',
          }),
        );
      }
      if (direct.length > 1) {
        return refuse(
          authError['saml-assertion']({
            rule: 'several-direct-assertions',
            check: 'signedNode',
            ...several(direct.length),
          }),
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
        require === 'response' || rootIsAssertion ? root : assertion;
      const signed = covered.find((element) => element === target);
      if (!signed) {
        return refuse(NOT_SIGNED[require]());
      }

      // 3d. Nothing assertion-shaped outside the one read. Wherever the
      // signature sits, the payload travels on whole — Saml2PureProvider hands
      // it to the cookie provider — so an Assertion or EncryptedAssertion in
      // an unsigned part of it (Extensions, a sibling, a wrapper) is something
      // a later reader may take for the real one. Nor inside a ds:Signature,
      // whose subtree an enveloped signature leaves unsigned.
      const place = placeOfAssertions(doc, assertion);
      if (place === 'inSignature') {
        return refuse(
          authError['saml-assertion']({
            rule: 'assertion-inside-signature',
            check: 'signedNode',
          }),
        );
      }
      if (place === 'outside') {
        return refuse(
          authError['saml-assertion']({
            rule: 'assertion-outside-signed',
            check: 'signedNode',
          }),
        );
      }

      // 4b. The assertion's own ID.
      const assertionId = readRequiredId(assertion);
      if (!assertionId) {
        return refuse(
          authError['saml-assertion']({
            rule: 'no-assertion-id',
            check: 'assertionId',
          }),
        );
      }

      // 5. The assertion's Issuer — inside the signature either way, so both
      // validators check it.
      const issuer =
        requireOne(
          assertion,
          SAML_NS,
          'Issuer',
          () =>
            authError['saml-assertion']({ rule: 'no-issuer', check: 'issuer' }),
          (n) =>
            authError['saml-assertion']({
              rule: 'several-issuers',
              check: 'issuer',
              ...several(n),
            }),
        ).textContent ?? '';
      if (!issuer) {
        return refuse(
          authError['saml-assertion']({
            rule: 'empty-issuer',
            check: 'issuer',
          }),
        );
      }
      // Fail closed: with nothing to compare against, any issuer whose key is
      // configured would pass, which is not what this validator promises.
      if (!context.expectedIssuer) {
        return refuse(
          authError['saml-assertion']({
            rule: 'no-expected-issuer',
            check: 'issuer',
          }),
        );
      }
      if (issuer !== context.expectedIssuer) {
        return refuse(
          authError['saml-assertion'](
            { rule: 'untrusted-issuer', check: 'issuer' },
            { issuer },
          ),
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
          return refuse(
            authError['saml-assertion']({
              rule: 'several-response-issuers',
              check: 'issuer',
            }),
          );
        }
        const [responseIssuer] = responseIssuers;
        if (
          responseIssuer !== undefined &&
          (responseIssuer.textContent ?? '') !== issuer
        ) {
          return refuse(
            authError['saml-assertion']({
              rule: 'issuers-differ',
              check: 'issuer',
            }),
          );
        }
      }

      // 6, 7, 8. Conditions and their window.
      const conditions = requireOne(
        assertion,
        SAML_NS,
        'Conditions',
        () =>
          authError['saml-assertion']({
            rule: 'no-conditions',
            check: 'conditions',
          }),
        (n) =>
          authError['saml-assertion']({
            rule: 'several-conditions',
            check: 'conditions',
            ...several(n),
          }),
      );

      const notBeforeRaw = conditions.getAttribute('NotBefore');
      if (notBeforeRaw) {
        const notBefore = parseXsdDateTime(notBeforeRaw);
        if (!notBefore) {
          return refuse(
            authError['saml-assertion'](
              { rule: 'not-before-invalid', check: 'notBefore' },
              { notBefore: notBeforeRaw },
            ),
          );
        }
        if (notBefore.getTime() - skew > Date.now()) {
          return refuse(
            authError['saml-assertion']({
              rule: 'not-yet-valid',
              check: 'notBefore',
            }),
          );
        }
      }

      const notOnOrAfterRaw = conditions.getAttribute('NotOnOrAfter');
      if (!notOnOrAfterRaw) {
        return refuse(
          authError['saml-assertion']({
            rule: 'no-not-on-or-after',
            check: 'notOnOrAfter',
          }),
        );
      }
      const conditionsExpiry = parseXsdDateTime(notOnOrAfterRaw);
      if (!conditionsExpiry) {
        return refuse(
          authError['saml-assertion'](
            { rule: 'not-on-or-after-invalid', check: 'notOnOrAfter' },
            { notOnOrAfter: notOnOrAfterRaw },
          ),
        );
      }
      if (conditionsExpiry.getTime() + skew <= Date.now()) {
        return refuse(
          authError['saml-assertion']({
            rule: 'expired',
            check: 'notOnOrAfter',
          }),
        );
      }

      // 9. Every AudienceRestriction must name us; several Audience inside one
      // are alternatives.
      const restrictions = directChildren(
        conditions,
        SAML_NS,
        'AudienceRestriction',
      );
      if (restrictions.length === 0) {
        return refuse(
          authError['saml-assertion']({
            rule: 'no-audience-restriction',
            check: 'audience',
          }),
        );
      }
      for (const restriction of restrictions) {
        const names = directChildren(restriction, SAML_NS, 'Audience').map(
          (a) => a.textContent ?? '',
        );
        if (names.length === 0) {
          return refuse(
            authError['saml-assertion']({
              rule: 'audience-restriction-empty',
              check: 'audience',
            }),
          );
        }
        if (!names.includes(context.audience)) {
          return refuse(
            authError['saml-assertion']({
              rule: 'audience-not-us',
              check: 'audience',
            }),
          );
        }
      }

      // 10. One bearer confirmation satisfying everything together. It
      // refuses by itself, naming why each candidate failed.
      const chosen = chooseBearerConfirmation(assertion, context, skew);

      // 11. Destination — the signed-Response validator only, for the same
      // reason as Status. Addressing in the other flow rests on Recipient,
      // which step 10 required and which sits inside the signed assertion.
      if (require === 'response') {
        const destination = root.getAttribute('Destination');
        if (!destination) {
          return refuse(
            authError['saml-assertion']({
              rule: 'no-destination',
              check: 'destination',
            }),
          );
        }
        if (destination !== context.acsUrl) {
          return refuse(
            authError['saml-assertion'](
              { rule: 'destination-not-us', check: 'destination' },
              { destination },
            ),
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
        return refuse(
          authError['saml-assertion']({ rule: 'replayed', check: 'replay' }),
        );
      }

      // Subject, then NameID — no `?? assertion` fallback, which would read a
      // NameID from outside the Subject when the Subject is absent.
      const subject = directChild(assertion, SAML_NS, 'Subject');
      const nameId = subject
        ? (directChild(subject, SAML_NS, 'NameID')?.textContent ?? undefined)
        : undefined;
      return asContract<ValidatedAssertion>({
        expiresAt,
        assertionId,
        issuer,
        nameId,
        raw: samlResponse,
        // The signed element, not the response: this is what a consumer may
        // parse without re-deriving what the signature covered.
        signedXml: new XMLSerializer().serializeToString(signed),
      });
    },
  };
}

/**
 * Step 4, Status — the signed-Response validator only, read as soon as the
 * Response is known to be the signed element and before any Assertion is
 * counted: a login the identity provider declined carries no Assertion
 * (measured: Keycloak, Responder / NoPassive), and counting first would
 * refuse it `no-direct-assertion`, hiding why. Either order refuses;
 * nothing is accepted on the strength of Status. Outside the signed
 * Response it is never read: a field an attacker sets is worse checked than
 * not, since a check reads like verification.
 */
function checkStatus(root: Element): void {
  const status = requireOne(
    root,
    PROTOCOL_NS,
    'Status',
    () => authError['saml-assertion']({ rule: 'no-status', check: 'status' }),
    (n) =>
      authError['saml-assertion']({
        rule: 'several-status',
        check: 'status',
        ...several(n),
      }),
  );
  const code = requireOne(
    status,
    PROTOCOL_NS,
    'StatusCode',
    () =>
      authError['saml-assertion']({
        rule: 'no-status-code',
        check: 'status',
      }),
    (n) =>
      authError['saml-assertion']({
        rule: 'several-status-codes',
        check: 'status',
        ...several(n),
      }),
  );
  const codeValue = code.getAttribute('Value');
  if (!codeValue) {
    refuse(
      authError['saml-assertion']({
        rule: 'status-code-no-value',
        check: 'status',
      }),
    );
  }
  if (codeValue !== SUCCESS) {
    // A registered status is a fact, in the words; any other value is
    // the diagnostic, admitted as printable ASCII or dropped.
    refuse(
      isSamlStatusCode(codeValue)
        ? authError['saml-assertion']({
            rule: 'declined',
            check: 'status',
            statusCode: codeValue,
          })
        : authError['saml-assertion'](
            { rule: 'declined', check: 'status' },
            { statusCode: codeValue },
          ),
    );
  }
}

/**
 * Whether the document carries `<!DOCTYPE`, in any letter case — read as
 * plain characters, since no regular expression runs over document text.
 * Only ASCII letters fold, as the `/i` flag folded them.
 */
function carriesDoctype(xml: string): boolean {
  const name = 'doctype';
  for (let at = xml.indexOf('<!'); at >= 0; at = xml.indexOf('<!', at + 1)) {
    let matched = true;
    for (let i = 0; i < name.length; i += 1) {
      const c = xml.charCodeAt(at + 2 + i);
      // An ASCII capital folds to its small letter; nothing else changes.
      const folded = c >= 0x41 && c <= 0x5a ? c + 0x20 : c;
      if (folded !== name.charCodeAt(i)) {
        matched = false;
        break;
      }
    }
    if (matched) return true;
  }
  return false;
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
  for (const node of parent.childNodes) {
    if (
      isElementNode(node) &&
      node.namespaceURI === ns &&
      node.localName === local
    ) {
      out.push(node);
    }
  }
  return out;
}

/**
 * Whether the node is an element. nodeType 1 is ELEMENT_NODE; the constant is
 * unavailable without the dom lib, which this project deliberately does not use.
 */
function isElementNode(node: Node): node is Element {
  return node.nodeType === 1;
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
  const [first] = found;
  return found.length === 1 ? (first ?? null) : null;
}

/**
 * The single direct child with this name, or a refusal that says which way
 * the count failed: absent and more than one are different rules, and a
 * refusal that cannot tell them apart sends the reader to the wrong one.
 * Each caller builds both refusals, so each names its own rule.
 */
function requireOne(
  parent: Element,
  ns: string,
  local: string,
  absent: () => SamlRefusal,
  many: (found: number) => SamlRefusal,
): Element {
  const found = directChildren(parent, ns, local);
  const [first] = found;
  if (first === undefined) return refuse(absent());
  if (found.length > 1) return refuse(many(found.length));
  return first;
}

/** Where the assertion-shaped elements of a document sit relative to the one read. */
type AssertionPlace = 'within' | 'outside' | 'inSignature';

/**
 * Walks up from every assertion-shaped element. Reaching the assertion that
 * was read means it is inside it — unless a ds:Signature came first: an
 * enveloped signature leaves its own subtree out of the digest, so anything
 * there is unsigned, however deep inside the signed assertion it sits.
 */
function placeOfAssertions(doc: Document, assertion: Element): AssertionPlace {
  for (const [ns, local] of ASSERTION_SHAPED) {
    for (const element of doc.getElementsByTagNameNS(ns, local)) {
      let node: Node | null = element;
      while (node && node !== assertion) {
        if (
          isElementNode(node) &&
          node.localName === 'Signature' &&
          node.namespaceURI === DSIG_NS
        ) {
          return 'inSignature';
        }
        node = node.parentNode;
      }
      if (!node) return 'outside';
    }
  }
  return 'within';
}

/** One candidate's first failed sub-rule, as the `no-bearer-qualifies` fact. */
type BearerCandidate = NonNullable<
  Extract<
    SamlAssertionError,
    { variant: 'no-bearer-qualifies' }
  >['facts']['candidates']
>[number];

/** A candidate's first failed non-temporal sub-rule, or the window it states. */
type Candidate =
  | { readonly failed: BearerCandidate }
  | { readonly notOnOrAfter: Date; readonly notBefore: Date | null };

/**
 * How many candidates a `no-bearer-qualifies` refusal lists; the rest are
 * counted in `moreCandidates`, so the error stays bounded however many the
 * document carries.
 */
const LISTED_CANDIDATES = 5;

/**
 * The bearer confirmation this login may rely on, or a refusal naming why
 * each candidate failed.
 *
 * Every part must hold on the **same** element: gathering `InResponseTo` from
 * one confirmation and `Recipient` from another is how a document satisfies a
 * check nothing in it actually satisfies. It is existential: one candidate
 * passing every sub-rule is enough, and every candidate is evaluated, so a
 * failing one never hides a valid one after it. When several qualify — which
 * a real identity provider does not produce — the earliest window wins, so
 * the outcome is a shorter session rather than a longer one.
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
): { notOnOrAfter: Date; latestNotOnOrAfter: Date } {
  const subject = requireOne(
    assertion,
    SAML_NS,
    'Subject',
    () =>
      authError['saml-assertion']({
        rule: 'no-subject',
        check: 'bearerConfirmation',
      }),
    (n) =>
      authError['saml-assertion']({
        rule: 'several-subjects',
        check: 'bearerConfirmation',
        ...several(n),
      }),
  );
  const confirmations = directChildren(subject, SAML_NS, 'SubjectConfirmation');
  if (confirmations.length === 0) {
    return refuse(
      authError['saml-assertion']({
        rule: 'no-subject-confirmation',
        check: 'bearerConfirmation',
      }),
    );
  }

  const now = Date.now();
  let best: Date | null = null;
  let latest: Date | null = null;
  const failures: BearerCandidate[] = [];

  for (const confirmation of confirmations) {
    const candidate = readConfirmation(confirmation, context);
    if ('failed' in candidate) {
      failures.push(candidate.failed);
      continue;
    }
    const { notOnOrAfter, notBefore } = candidate;

    // Could qualify at some instant: counts towards how long to remember.
    if (!latest || notOnOrAfter.getTime() > latest.getTime()) {
      latest = notOnOrAfter;
    }

    // 7, 8. Qualifies now: a candidate for the session's window.
    if (notOnOrAfter.getTime() + skew <= now) {
      failures.push({ reason: 'not-on-or-after-passed' });
      continue;
    }
    if (notBefore && notBefore.getTime() - skew > now) {
      failures.push({ reason: 'not-before-not-arrived' });
      continue;
    }

    if (!best || notOnOrAfter.getTime() < best.getTime()) best = notOnOrAfter;
  }

  // `latest` is set whenever `best` is: every qualifying confirmation was
  // counted towards it first. When nothing qualified, every candidate left
  // exactly one failure, in document order.
  if (best && latest) return { notOnOrAfter: best, latestNotOnOrAfter: latest };
  const more = count(failures.length - LISTED_CANDIDATES);
  return refuse(
    authError['saml-assertion']({
      rule: 'no-bearer-qualifies',
      check: 'bearerConfirmation',
      candidates: failures.slice(0, LISTED_CANDIDATES),
      ...(more === undefined || more === 0 ? {} : { moreCandidates: more }),
    }),
  );
}

/**
 * Sub-rules 1 to 6, in the spec's fixed order: the first one this candidate
 * fails, or the window it states. The temporal sub-rules 7 and 8 are the
 * caller's, since a candidate failing only those still bounds replay
 * retention.
 */
function readConfirmation(
  confirmation: Element,
  context: AssertionContext,
): Candidate {
  // 1.
  if (confirmation.getAttribute('Method') !== BEARER) {
    return { failed: { reason: 'method-not-bearer' } };
  }
  // 2.
  const data = directChildren(confirmation, SAML_NS, 'SubjectConfirmationData');
  const [only] = data;
  if (only === undefined) {
    return { failed: { reason: 'no-confirmation-data' } };
  }
  if (data.length > 1) {
    return {
      failed: { reason: 'several-confirmation-data', ...several(data.length) },
    };
  }
  // 3. Option B: an expected ID must be matched exactly; no expected ID — an
  // IdP-initiated login — means the attribute must not be there at all.
  if (context.expectedInResponseTo === undefined) {
    if (only.hasAttribute('InResponseTo')) {
      return { failed: { reason: 'in-response-to-unexpected' } };
    }
  } else if (
    only.getAttribute('InResponseTo') !== context.expectedInResponseTo
  ) {
    return { failed: { reason: 'in-response-to-mismatch' } };
  }
  // 4.
  if (only.getAttribute('Recipient') !== context.acsUrl) {
    return { failed: { reason: 'recipient-not-acs' } };
  }
  // 5.
  const notOnOrAfterRaw = only.getAttribute('NotOnOrAfter');
  if (!notOnOrAfterRaw) {
    return { failed: { reason: 'no-not-on-or-after' } };
  }
  const notOnOrAfter = parseXsdDateTime(notOnOrAfterRaw);
  if (!notOnOrAfter) {
    return { failed: { reason: 'not-on-or-after-invalid' } };
  }
  // 6.
  const notBeforeRaw = only.getAttribute('NotBefore');
  const notBefore = notBeforeRaw ? parseXsdDateTime(notBeforeRaw) : null;
  if (notBeforeRaw && !notBefore) {
    return { failed: { reason: 'not-before-invalid' } };
  }
  return { notOnOrAfter, notBefore };
}
