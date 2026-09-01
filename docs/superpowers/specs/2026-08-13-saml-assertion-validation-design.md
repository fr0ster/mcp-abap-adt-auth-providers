# SAML assertion validation

**Date:** 2026-08-13
**Status:** approved 2026-08-14; amended and re-approved 2026-09-01 with "Two validators, not one with a blind spot" — approved, not implemented
**Closes:** issue #19 — SAML assertions are accepted without any validation
**Depends on:** `@mcp-abap-adt/auth-mocks`, published — and on a **minor
addition to it**: `startMockSamlIdp` needs `signWhat?: 'assertion' | 'response'`
before the signed-Response validator can be tested end to end. See "Testing".

## The problem, verified in the code

`src/auth/saml2Auth.ts:141` accepts whatever arrives at the ACS, provided the
string is non-empty. That is the entire check. `src/auth/saml2Auth.ts:95-101`
then derives the session lifetime with a regular expression over the decoded,
unverified XML:

```ts
const decoded = Buffer.from(samlResponse, "base64").toString("utf8");
const match = decoded.match(/NotOnOrAfter="([^"]+)"/);
```

Nothing in `src/` reads `<samlp:Status>`, so an assertion whose IdP **declined
the login** is indistinguishable from one that succeeded.

The two providers are not equally exposed:

- `Saml2BearerProvider` forwards the string to UAA, which validates it
  server-side. The cost is a misleading error, not a breach.
- `Saml2PureProvider` has no such backstop: the assertion becomes the session
  and its lifetime comes from the regex above.

One more fact settles the shape of the fix. The `AuthnRequest`'s `ID` is
generated inside `buildAuthnRequestXml` (`src/auth/saml2Auth.ts:31`), used in
the XML, and never returned — `buildSamlAuthorizationUrl` yields only a URL. So
`InResponseTo` cannot be checked today even in principle.

## Decisions

Five were taken by the owner before this document was written, and two defaults
were proposed here and accepted:

1. **The shipped default verifies the signature.** A missing certificate is a
   configuration error that fails the login, never a silent skip.
2. **`IAssertionValidator` lives in `@mcp-abap-adt/interfaces`**, like
   `IAuthorizationStrategy`; the defaults ship in `auth-providers`.
3. **Certificates come from configuration** — `idpCertificates: string[]`, PEM
   or base64 DER. A list, because identity providers rotate keys and two are
   live during a rotation. The package performs no I/O and fetches no metadata:
   the consumer reads the file.
4. **`InResponseTo` is required, and the ID must come from somewhere real.**
   There are exactly two sources, and no third: the package minted it while
   building the request, or the consumer declared it. See "Where the expected
   request ID comes from" — an earlier draft said "when `authorizationUrl` is
   set", which was too narrow and missed a flow the package already supports.
5. **Replay is detected**, through a store interface with an in-memory default.
6. **`clockSkewMs` defaults to `0`.** Real deployments often need tolerance, but
   this package's rule is that a consumer owns its own leniency.
7. **A signature on either `Response` or `Assertion` is accepted**, provided it
   covers the element the assertions are read from — see below. Requiring it on
   the `Assertion` specifically would be stricter and would reject real
   identity providers that sign only the response.

## The rule everything else depends on

The signature must cover the element the validator then reads.

This is not the same as "the document contains a valid signature". A signature
wrapping attack supplies a document holding a genuinely signed fragment **and**
a second, unsigned one, and the victim validates the first while reading the
second. `@node-saml/node-saml` guards this with `signature.parentNode ===
referencedNode`; building `auth-mocks` produced a live demonstration, where an
IdP whose signature sat outside the element it referenced was refused outright.

So each shipped validator resolves, in order:

1. which element the signature references, and that the signature is valid for
   the certificates configured;
2. that the referenced element is the one it was told to require — the
   `Response` for `createSignedResponseValidator`, the `Assertion` for
   `createSignedAssertionValidator` — and that the response carries exactly one
   `Assertion` either way;
3. only then, the fields, read **from that element**.

A document where the signed node and the read node differ is refused, whatever
else is true of it.

### Two validators, not one with a blind spot

Decision 7 accepts a signature on the `Response` **or** on the `Assertion`, and
those two do not protect the same fields. Three checks read from the
`Response` — `Status`, `Response/Issuer` and `Destination` — and with an
assertion-only signature all three sit outside the signature, where anyone able
to deliver a response can set them to whatever we expect.

An earlier draft kept one validator and documented those three as
"misconfiguration checks rather than controls" in that mode. That is a
validator whose contract changes underneath the caller, and it made the
invariant above — everything is read from the signed element — false in the
common case.

**So the package ships two, and the consumer chooses.**

- **`createSignedResponseValidator`** requires the signature to cover the
  `Response`. All twelve checks are then controls, because every field they
  read is inside the signature. This is the default: it is the stronger
  contract, and a package whose thesis is strictness should not make the weaker
  one the thing you get by not deciding.
- **`createSignedAssertionValidator`** accepts a signature covering the
  `Assertion`. It does not check `Status`, `Response/Issuer` or `Destination`
  **at all** — not "checks them weakly". Performing a check on a field an
  attacker controls is worse than omitting it, because it reads in the code and
  in the logs as though something was verified.

Both honour the same invariant, which is what makes them comprehensible: each
reads only what its signature covers.

They take the same options and return the same interface, so switching between
them is one identifier and nothing else — a consumer who chooses wrongly should
not also have to rewrite their configuration:

```ts
/** Shared by both shipped validators. */
export interface ShippedValidatorOptions {
  /**
   * PEM or bare base64 DER — the form `<X509Certificate>` carries in identity
   * provider metadata. A list, because providers rotate keys and two are live
   * during a rotation. Normalised and parsed once, at construction, so a
   * malformed entry is a configuration error rather than a login failure, and
   * a bad first entry cannot hide a good second one.
   */
  readonly idpCertificates: readonly string[];
  /** Finite, non-negative, integer. Defaults to 0. */
  readonly clockSkewMs?: number;
  /** Defaults to a process-wide in-memory store. */
  readonly replayStore?: IAssertionReplayStore;
}

/**
 * Requires the signature to cover the `Response`. All twelve checks are then
 * controls. This is what a provider builds when the consumer configures no
 * validator of their own.
 */
export function createSignedResponseValidator(
  options: ShippedValidatorOptions,
): IAssertionValidator;

/**
 * Accepts a signature covering the `Assertion`. Does not read `Status`,
 * `Response/Issuer` or `Destination` — see above for why that is a smaller
 * loss than it looks, and why performing those checks here would be worse
 * than omitting them.
 */
export function createSignedAssertionValidator(
  options: ShippedValidatorOptions,
): IAssertionValidator;
```

Neither takes the signature placement as a parameter. That is deliberate: a
`placement: 'response' | 'assertion'` option is the same validator-with-a-mode
this section exists to remove, and it would put the choice somewhere a reader
of the call site cannot see.

Dropping those three from the assertion-only validator costs less than it
looks:

- **`Destination`** — addressing is already established by
  `SubjectConfirmationData/@Recipient`, which is inside the signed assertion and
  required by step 10.
- **`Status`** — a declined login carries no assertion. An identity provider
  that refuses does not mint one, so an attacker flipping `Status` to `Success`
  still has nothing signed to put beneath it, and signature resolution fails
  before `Status` would be read. Success is established by a signed assertion
  passing every assertion-level check, not by the `Status` element.
- **`Response/Issuer`** — the assertion's own `Issuer` is checked against
  `expectedIssuer` inside the signature.

A consumer whose identity provider signs only assertions selects the second
validator explicitly and can read, in one sentence, what they gave up. A
consumer who selects nothing gets the strict one and a refusal naming the
remedy — which is the outcome we want for somebody who has not thought about
it yet.

## Interfaces

In `@mcp-abap-adt/interfaces`:

```ts
/** What the provider knows about the login the assertion is answering. */
export interface AssertionContext {
  /** The AuthnRequest ID this response must answer. */
  readonly expectedInResponseTo: string;
  /** Our entity ID, which the AudienceRestriction must name. */
  readonly audience: string;
  /**
   * The ACS the response arrived at. `SubjectConfirmationData/@Recipient` must
   * match it in both validators; `Response/@Destination` is compared only by
   * the signed-Response validator, since the assertion-only one does not read
   * an unsigned field.
   */
  readonly acsUrl: string;
  /**
   * Trusted issuer; the assertion's `Issuer` must equal it.
   *
   * Optional on the interface because a custom validator may establish trust
   * without it. The shipped default always receives it — `idpEntityId` is
   * required configuration — so for that validator it is never absent.
   */
  readonly expectedIssuer?: string;
  readonly logger?: ILogger;
}

/** What a validated assertion yields to the flow. */
export interface ValidatedAssertion {
  /**
   * The earlier of `Conditions/@NotOnOrAfter` and the `NotOnOrAfter` of the
   * bearer confirmation that was accepted — never later than either, so a
   * session cannot outlive a window the assertion itself closed. From the
   * verified document, never from a regex over unverified XML.
   *
   * When several confirmations satisfy step 10, the one with the **earliest**
   * `NotOnOrAfter` is the accepted one; see "Two windows, one expiry".
   */
  readonly expiresAt: Date;
  readonly assertionId: string;
  /**
   * The assertion's own `Issuer`. Not decoration: with `assertionId` it forms
   * the replay key, and a store keyed on the ID alone rejects a legitimate
   * second login the moment two identity providers mint the same `_id`.
   */
  readonly issuer: string;
  readonly nameId?: string;
  readonly sessionIndex?: string;
  readonly attributes?: Readonly<Record<string, readonly string[]>>;
  /**
   * The response exactly as it arrived, for a flow that must forward it
   * verbatim — `Saml2BearerProvider` sends it to the token endpoint,
   * `Saml2PureProvider` hands it to the cookie provider.
   *
   * **This is the wire payload, not a validated artifact.** It is the whole
   * `samlp:Response`, and with `createSignedAssertionValidator` that includes
   * `Status`, `Response/Issuer` and `Destination`, which that validator never
   * read and nothing has checked. Holding a `ValidatedAssertion` does not make
   * every byte of `raw` trustworthy; it means the fields named above this one
   * were established. Anything read out of `raw` is read at the reader's own
   * risk — which is why the signed element is offered separately.
   */
  readonly raw: string;
  /**
   * The signed element, serialised: the `Assertion`, or the `Response` when
   * that is what the signature covered.
   *
   * Everything in here is inside the signature that verified. A consumer
   * wanting attributes, or anything else this interface does not surface,
   * should parse this rather than `raw` — the difference between the two is
   * precisely the difference between "signed" and "arrived".
   */
  readonly signedXml: string;
}

/**
 * Establishes that an assertion is genuine, addressed to us, currently valid,
 * and answers a request we made. Rejects by throwing, with a reason naming the
 * check that failed.
 */
export interface IAssertionValidator {
  validate(
    samlResponse: string,
    context: AssertionContext,
  ): Promise<ValidatedAssertion>;
}

/**
 * What identifies an assertion for replay purposes.
 *
 * An assertion's `ID` is unique only within the identity provider that minted
 * it, so a store shared by two providers — or one tenant's provider and
 * another's — would reject a perfectly good second login as a replay the
 * moment two issuers happened to mint the same `_id`. The key is therefore the
 * pair, never the ID alone.
 */
export interface AssertionReplayKey {
  /** The trusted issuer, as validated at step 5. */
  readonly issuer: string;
  readonly assertionId: string;
}

/** Remembers assertions so a replay is refused. */
export interface IAssertionReplayStore {
  /**
   * Records this ID if it is not already recorded, and reports which happened:
   * `true` when it was newly recorded, `false` when it was already there — a
   * replay.
   *
   * **Must be atomic.** Two validations of the same assertion running at once
   * must not both be told `true`; a check followed by a separate write is a
   * race, and it is precisely the race a replay exploits. The interface is
   * shaped as one call rather than `has` plus `record` so that an implementation
   * backed by a shared store can express it as a single conditional write.
   *
   * `retainUntil` is **not** `expiresAt`. It is the last instant at which this
   * validator would still accept the assertion — `expiresAt + clockSkewMs` —
   * because an entry dropped any earlier reopens exactly the window in which a
   * replay would be accepted again. See "Two windows, one expiry".
   */
  recordIfUnseen(key: AssertionReplayKey, retainUntil: Date): Promise<boolean>;
}
```

`IAssertionReplayStore` is separate because its lifetime is deployment-shaped:
an in-memory default is right for one long-lived process and useless across
several, and a consumer running more than one replaces it with a shared store
without rewriting validation.

## What the default checks, and in what order

Each step has its own refusal reason. No two share a message, so no test can
pass for a neighbouring check's reason — a lesson the `auth-mocks` work paid
for twice.

Three rows are marked _signed-Response validator only_. The assertion-only
validator does not perform them, because their fields lie outside the signature
it accepts — see "Two validators, not one with a blind spot". Everything
unmarked is performed by both.

| #   | Check                                                      | Refused when                                                                |
| --- | ---------------------------------------------------------- | --------------------------------------------------------------------------- |
| 1   | Parses as XML, document element is `samlp:Response`        | it is not                                                                   |
| 1b  | Every `ID` attribute in the document is unique             | any value appears twice                                                     |
| 2   | Signature valid against `idpCertificates`                  | absent, wrong key, or content altered after signing                         |
| 3   | Signed node is the node read                               | the reference points elsewhere                                              |
| 4   | `samlp:Status` _(signed-Response validator only)_          | absent, or `StatusCode` is not `…:status:Success`                           |
| 4b  | `Assertion/@ID`                                            | **absent** or empty                                                         |
| 5   | `Assertion/Issuer`                                         | **absent**, or not `context.expectedIssuer`                                 |
| 5b  | `Response/Issuer` _(signed-Response validator only)_       | present and disagreeing with `Assertion/Issuer`                             |
| 6   | `Conditions`                                               | **absent**                                                                  |
| 7   | `Conditions/@NotBefore`                                    | present and in the future, beyond `clockSkewMs`                             |
| 8   | `Conditions/@NotOnOrAfter`                                 | **absent**, not a valid `xsd:dateTime`, or in the past beyond `clockSkewMs` |
| 9   | `Conditions/AudienceRestriction`                           | absent, or **any one** restriction fails to name `context.audience`         |
| 10  | One bearer `SubjectConfirmation`                           | no single confirmation satisfies every part of it — see below               |
| 11  | `Response/@Destination` _(signed-Response validator only)_ | **absent**, or not `context.acsUrl`                                         |
| 12  | Replay                                                     | the store has already recorded this `{issuer, ID}`                          |

**Absent is refused, not skipped.** Every row above that names a field refuses
when the field is missing, and this is deliberate: a rule phrased "present and
not X" is one an attacker satisfies by deleting the field. An earlier draft of
this table said exactly that for `Recipient`, `Destination` and `Issuer`, which
would have let a forged response drop its addressing entirely and still pass a
validator whose whole contract is that the assertion is addressed to us.

**Step 1b is not bookkeeping, it is the wrapping defence again.** XML-DSig
resolves its reference by `ID`, so a document containing two elements with the
same `ID` makes "which element is signed" a question the parser answers rather
than one the specification does. That ambiguity is the classic lever for
signature wrapping, and step 3 cannot be trusted while it exists. Duplicate IDs
are therefore refused before anything is read, wherever in the document they
appear — not only on the two elements this validator happens to care about.

**Step 4b exists because the ID can genuinely be missing.** `assertionId` is
required on the result and forms half the replay key, yet nothing so far obliged
the assertion to carry one. When the **`Response`** is the signed node, the
XML-DSig reference names the response, so the assertion's own `ID` is not needed
for the signature to verify and an assertion without one would sail through into
a replay key built on `undefined`. A non-empty `Assertion/@ID` is required
outright.

**Step 10 is one element, not four fields.** A bearer assertion may carry
several `SubjectConfirmation` elements, and the danger is reading each attribute
from whichever one happens to have it. The rule is therefore: there must exist a
**single** `SubjectConfirmation` whose `Method` is
`urn:oasis:names:tc:SAML:2.0:cm:bearer` and whose own `SubjectConfirmationData`
satisfies, together, all of

- `@InResponseTo` equal to `context.expectedInResponseTo`,
- `@Recipient` equal to `context.acsUrl`,
- `@NotOnOrAfter` present, a valid `xsd:dateTime`, and not in the past beyond
  `clockSkewMs`,
- `@NotBefore`, if present, not in the future beyond `clockSkewMs`.

If no one confirmation satisfies all of them, the assertion is refused, even
when every value appears somewhere in the document. Note that this
`NotOnOrAfter` is **not** the one in `Conditions`: SAML Profiles §4.1.4.2 makes
the bearer confirmation's own window the one that governs when the assertion may
be presented, and an assertion whose `Conditions` are still open while its
bearer window has closed must be refused.

**Step 9 is AND across restrictions, OR within one.** SAML Core §2.5.1.4 makes
each `AudienceRestriction` an independent condition: _every_ restriction must
name us, while the several `Audience` elements inside one restriction are
alternatives. Implemented as "some `Audience` anywhere in the document equals
ours", an assertion carrying one permitting restriction beside one that excludes
us would pass. It must not.

Two of these deserve their citation, because "required" is a choice:

- **`SubjectConfirmationData/@Recipient`** — SAML 2.0 Profiles §4.1.4.3 requires
  a bearer `SubjectConfirmationData` to carry a `Recipient` matching the service
  provider's assertion consumer service. There is no solicited Web Browser SSO
  assertion that legitimately omits it.
- **`Response/@Destination`** — required by the **signed-Response validator**,
  which is exactly where the specification supports it: the HTTP POST binding
  (§3.5.5.2) requires `Destination` on a signed message, and there the field is
  inside the signature. The assertion-only validator does not read it at all,
  because there it is outside the signature and an attacker sets it to whatever
  we expect. Addressing in that flow rests on `Recipient`, inside the signed
  assertion and required by step 10.

**Two windows, one expiry.** The assertion carries two `NotOnOrAfter` values
and the result carries one date: `expiresAt` is the **earlier** of them.

Step 10 is existential — it asks whether _some_ confirmation satisfies
everything — so more than one may qualify, and then "the bearer window" is
ambiguous. The rule is deterministic and conservative: **the qualifying
confirmation with the earliest `NotOnOrAfter` is the accepted one**, and its
window is the one that meets `Conditions` in the minimum above. A real identity
provider does not emit two qualifying confirmations; picking the earliest means
that if one ever does, the outcome is a session shorter than intended rather
than one longer than some confirmation allowed. Replay retention is computed
from that same chosen expiry, so the two can never disagree. Taking
either alone would let a session outlive a window the assertion itself closed —
`Conditions` may run past the bearer window or the reverse, and only the minimum
respects both. The replay store is **not** given that date. It is given
`expiresAt + clockSkewMs`, the last instant this validator would still accept
the assertion. Pruning at `expiresAt` would drop the entry while the skew
window was still open, and inside that window the same assertion becomes
"unseen" again — a replay hole cut by the very tolerance meant to absorb
imprecise clocks. The two dates answer different questions: one bounds the
session, the other bounds how long we must remember.

**`NotOnOrAfter` is required**, because `ValidatedAssertion.expiresAt` is not
optional: a flow that takes its session lifetime from the assertion cannot be
handed an assertion with no stated lifetime. It must also parse as a valid
`xsd:dateTime` with real calendar components — `Date.parse` silently normalises
`2026-02-30` into 2 March, a trap `auth-mocks` already hit and fixed.

**Which `Issuer`.** The `Assertion`'s, always: it is the assertion that is
trusted, whichever element carries the signature. Both validators check it
against `expectedIssuer`.

The cross-check against `Response/Issuer` belongs to the **signed-Response
validator** alone. There both are inside the signature, and a response claiming
one issuer while wrapping an assertion from another is refused as a mismatch
rather than silently resolved in favour of either. The assertion-only validator
does not read `Response/Issuer`, for the same reason it does not read `Status`
or `Destination`.

Steps 4, 5, 11 and 12, and the `Recipient` half of step 10, are precisely what
`@node-saml/node-saml` does **not**
judge on the SSO path, established by reading its source while building
`auth-mocks`. They are the clearest evidence that this validator is not a
wrapper around somebody else's library.

## Configuration, and what breaks

New on the SAML config:

- `assertionValidator?: IAssertionValidator` — which validator to use, and the
  place a consumer chooses between the two shipped ones:
  `createSignedResponseValidator(...)` (the default when this is omitted) or
  `createSignedAssertionValidator(...)`, or an implementation of their own.
  When supplied,
  the package constructs no default, and the **default-validator-specific**
  fields below stop being required: `idpCertificates`, `idpEntityId`,
  `assertionReplayStore` and `clockSkewMs`. A custom validator may establish
  trust by any means it likes, and demanding certificates it will never read
  would be a requirement with no purpose.

  Two distinctions worth keeping straight. `spEntityId` is **not** in that set:
  it populates `AssertionContext.audience`, which the provider builds for
  whichever validator is in play, so it stays required either way. And
  `idpEntityId`, when it is supplied, still populates
  `AssertionContext.expectedIssuer` for a custom validator — it stops being
  _required_, not ignored.

- `idpCertificates: string[]` — required **when no `assertionValidator` is
  supplied**. Absent or empty is then a configuration error raised before any
  network call.
- `idpEntityId: string` — required **when no `assertionValidator` is supplied**.
  The `Issuer` the assertion must name, and the value behind
  `AssertionContext.expectedIssuer`. Without it the default would establish only
  that _an_ issuer is present and that the response and assertion agree on it —
  so an assertion signed with a certificate that is on our rotation list, but
  issued by somebody else, would pass. Required rather than optional for the
  same reason the certificates are: this is a value the consumer already holds
  from the identity provider's metadata, and making it optional would mean
  shipping a default whose strictest configuration is not the one you get.
- `spEntityId: string` — the `Audience` the assertion must name.
- `assertionReplayStore?: IAssertionReplayStore` — a consumer's own, for a
  deployment running more than one process. Its absence is what the shipped
  default covers; see "Wiring" for the scope that default has.
- `clockSkewMs?: number` — default `0`. Must be a finite, non-negative integer;
  `NaN`, `Infinity` and negative values are configuration errors, since each
  would make both the temporal comparisons and `retainUntil` meaningless rather
  than merely lenient.
- `authnRequestId?: string` — required whenever the package did not mint an ID
  itself: a pre-built `authorizationUrl`, or a strategy that never called the
  builder. See "Where the expected request ID comes from".

`buildSamlAuthorizationUrl` changes shape: it returns the URL **and** the
request ID it minted, since the ID must survive to validation.

`parseSamlNotOnOrAfter` is removed. Expiry becomes `ValidatedAssertion.expiresAt`.

`Saml2PureProvider`'s `expiresAt` therefore comes from a different source.

A consumer whose identity provider returns non-`Success` responses will see
them refused **under the default validator** — `createSignedResponseValidator`,
which reads `Status`. Under `createSignedAssertionValidator` they are not
refused for that reason, because it does not read `Status`; they are refused,
if at all, for want of a validly signed assertion, which a declining identity
provider does not mint. Stating this without the qualifier, as an earlier draft
did, would have promised behaviour one of the two shipped validators does not
have.

**`auth-providers` goes major; `interfaces` goes minor.**

## Wiring

Both providers construct the default validator when the consumer supplies none.

**The default replay store is process-wide, not per provider.** A store held
per provider instance would be no defence at all: replaying an assertion would
need only a second provider constructed in the same process, which is a step an
attacker who can replay at all can certainly take. The shipped default is
therefore a single module-level store, shared by every default validator in the
process.

`createInMemoryReplayStore()` is exported so a test — or a consumer wanting
isolation — can construct its own and pass it as `assertionReplayStore`. The
suite uses that rather than the shared one, so no test can be made to pass or
fail by another test's assertions.

The honest limit stays what it was: process-wide means nothing across
processes, which is precisely why the interface exists.

Unlike an authorization strategy, a validator owns no socket and no timer, so
`IAssertionValidator` carries no `dispose()` and there is no lifecycle rule to
observe. The in-memory replay store prunes expired entries lazily, when it is
next consulted, precisely so that it needs no timer and therefore no disposal.
A consumer whose own store does hold a resource owns that resource, since it
constructed it.

`Saml2BearerProvider` validates **before** exchanging the assertion at the token
endpoint, so an IdP's refusal is reported as an IdP refusal rather than
resurfacing as UAA's `invalid_grant`.

`Saml2PureProvider` validates before handing the assertion to the cookie
provider, and takes its session lifetime from the result.

## Errors

A new `AssertionValidationError extends TokenProviderError`, carrying the check
that failed as a discriminable field, so a consumer can tell "your IdP declined"
from "this response was not addressed to us" without parsing a message.
Configuration faults raise the existing `ValidationError` with `missingFields`,
because they are the same kind of mistake it already reports: no
`idpCertificates`, no `idpEntityId`, and no `authnRequestId` in either case that
needs one — a pre-built `authorizationUrl`, **or** a strategy that returned a
payload without calling the builder. The message names which of the two
happened, since the remedy reads differently to a consumer who never configured
a URL at all.

## Testing

`@mcp-abap-adt/auth-mocks` becomes a devDependency of `auth-providers`. The
package it exists to serve finally uses it.

Every corruption variant the mock ships maps onto exactly one check above:
`unsigned`, `wrongKey` and `tamperedAfterSign` onto step 2; `statusFailure` onto
4; `wrongIssuer` onto 5; `notYetValid` onto 7; `expired` onto 8; `wrongAudience`
onto 9; `wrongInResponseTo` and `wrongRecipient` each onto part of 10;
`wrongDestination` onto 11. The mock's two-delivery replay sequence covers 12.

Which validator judges which variant follows from the split — but two facts
about the published mock make the naive matrix wrong, and both were found by
reading its source rather than assuming:

**`auth-mocks@0.1.1` signs the assertion, never the response.** `startMockSamlIdp`
calls `signXml(xml, key)` with no `referenceXPath`, so the reference is always
the `Assertion` and there is no option to change it. Against that mock,
`createSignedResponseValidator` refuses _every_ response at step 3 — including
the valid one — and no corruption variant ever reaches the check it was built
for. **This is a prerequisite in another repository, not something to work
around here:** `auth-mocks` needs a `signWhat?: 'assertion' | 'response'`
option, defaulting to `'assertion'` so nothing existing changes, released as a
minor. Until it exists, only the assertion-only validator can be exercised end
to end, and the plan must say so rather than describe a matrix it cannot run.

**`wrongIssuer` corrupts both issuers, not just the response's.** The mock
builds one `issuerValue` and writes it into the `Response` _and_ the
`Assertion`. The corrupted assertion issuer is inside the signature, so
**both** validators refuse that variant at step 5 — the assertion-only one does
not "accept `wrongIssuer`", and saying so would have been wrong. Proving that
the response-level cross-check is absent needs a fixture corrupting
`Response/Issuer` **alone**, built here rather than taken from a variant.

With those two settled, the matrix is: `statusFailure` and `wrongDestination`
are refused by the signed-Response validator and **accepted** by the
assertion-only one, which does not read those fields. Every other variant is
refused by both. The acceptances need their own cases — a validator silently
dropping a check and a validator documented as not performing it look identical
from the outside unless something pins the difference.

**But the mock only corrupts values, never removes them**, and the gap this
review found is exactly about removal. Every "absent" refusal — `Status`,
`Issuer`, `Conditions`, `NotOnOrAfter`, `Audience`, `InResponseTo`, `Recipient`,
`Destination` — therefore has no variant behind it and needs a fixture built
here, by taking the mock's valid response, stripping the one field, and
re-signing it with the mock's own key material (`generateKeyMaterial` and
`signXml` are exported for this). Two of those removals belong to one validator only, and both halves must be
pinned: a **missing `Status`** and a **missing `Destination`** are refusals of
`createSignedResponseValidator` and are **accepted** by
`createSignedAssertionValidator`, which does not read either field. Asserting
only the refusal would leave the acceptance to chance, and asserting only the
acceptance would let the refusal quietly disappear. The other six removals are
refusals of both.

A wrong-value test and a missing-value test
protect different halves of the same rule, and only the pair proves it whole.

Step 10 needs cases the mock cannot express at all, because it emits one
well-formed `SubjectConfirmation`. Build them here: an assertion carrying **two**
confirmations, one holding the right `Recipient` and the other the right
`InResponseTo`, must be refused — that is the whole point of requiring a single
coherent element. A bearer confirmation whose own `NotOnOrAfter` has passed
while `Conditions` are still open must be refused too, and that pair is what
distinguishes the two windows.

Step 9 needs the same treatment: an assertion with two `AudienceRestriction`
elements, one naming us and one not, must be refused. Implemented as a search
for our audience anywhere in the document, it would pass.

Steps 1b and 4b need cases the mock cannot produce either, since it always emits
one well-formed assertion with a unique ID: an assertion with **no** `ID` — most
sharply with the signature on the `Response`, where it verifies anyway — and a
document carrying **two** elements with the same `ID`, which must be refused
before any reference is resolved.

Replay needs two cases beyond the mock's sequence, and neither is a corruption:

- **Retention outlasts the skew window.** With `clockSkewMs` set, replay the
  assertion at a moment past its `expiresAt` but inside the tolerance. The
  validator still accepts such an assertion on temporal grounds, so the store
  must still remember it; an entry pruned at `expiresAt` would report it unseen
  and the replay would succeed. This test fails against a store given
  `expiresAt` and passes only against one given `expiresAt + clockSkewMs`.
- **Two issuers, one ID.** Two mock identity providers, each minting an
  assertion with the same `ID`, validated against their own configurations.
  Both must be accepted: a store keyed on the ID alone rejects the second as a
  replay, which is a working login refused rather than an attack stopped.

Three further cases have no variant for the same reason:

- **Signature wrapping**, step 3: take a validly signed assertion, wrap it in a
  response carrying a second, forged one, and require the validator to refuse
  rather than read the forged one.
- **A missing request ID**, from the provenance rule: a strategy that never
  calls the builder, with no `authnRequestId` configured, must fail as a
  configuration error naming the remedy — not as a validation failure blamed on
  the assertion, and not by validating against `undefined`.
- **A malformed `NotOnOrAfter`**, step 8: `2026-02-30T00:00:00Z` is a real
  calendar trap — `Date.parse` normalises it into 2 March rather than rejecting
  it — and `2026-01-01T00:00:00+99:99` is an out-of-range offset. Both were
  found and fixed in `auth-mocks`; the validator must not reintroduce them.

Every rule gets a test that fails when the rule is deleted, and a conjunction is
mutated one half at a time — the two disciplines the `auth-mocks` cycle had to
learn after a two-part check shipped with only one half load-bearing.

## Out of scope

Identity provider metadata fetching, encrypted assertions
(`EncryptedAssertion`), single logout, and `AuthnContext` comparison. Each is a
separate concern and none is needed to close #19. The two findings deferred from
the #11 arc — `OidcBrowserProvider` sending no `state`, and
`exchangeSamlAssertion` sending a base64 `samlp:Response` where RFC 7522 wants a
base64url `Assertion` — remain deferred; the second is now demonstrable with
`samlBearer: 'strict'`.

## Risks

The dependency surface grows: `xml-crypto` and `@xmldom/xmldom` become runtime
dependencies of `auth-providers`. Both are already proven in `auth-mocks`, and
two of their behaviours are documented there — `checkSignature` throws on a bad
signature value while returning `false` only for a digest mismatch, and a
signature must sit inside the element it references.

Canonicalisation remains the honest limitation. Verifying with `xml-crypto` a
signature that `auth-mocks` produced with `xml-crypto` proves the profile logic,
not that our C14N matches a real identity provider's. Only live testing answers
that, and the README must keep saying so.
