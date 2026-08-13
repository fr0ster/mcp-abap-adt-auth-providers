# SAML assertion validation

**Date:** 2026-08-13
**Status:** awaiting review
**Closes:** issue #19 — SAML assertions are accepted without any validation
**Depends on:** `@mcp-abap-adt/auth-mocks@0.1.1`, published, which makes every
rule below testable deterministically

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
4. **`InResponseTo` is required.** When the package builds the request it knows
   the ID. When the consumer supplies a pre-built `authorizationUrl`, it must
   supply the ID too, or the login fails as a configuration error.
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

So the default resolves, in order:

1. which element the signature references, and that the signature is valid for
   the certificates configured;
2. that the referenced element is the one it will read — the `Assertion`, or a
   `Response` that directly contains exactly one `Assertion`;
3. only then, the assertions themselves, read **from that element**.

A document where the signed node and the read node differ is refused, whatever
else is true of it.

## Interfaces

In `@mcp-abap-adt/interfaces`:

```ts
/** What the provider knows about the login the assertion is answering. */
export interface AssertionContext {
  /** The AuthnRequest ID this response must answer. */
  readonly expectedInResponseTo: string;
  /** Our entity ID, which the AudienceRestriction must name. */
  readonly audience: string;
  /** The ACS the response arrived at; Recipient and Destination must match. */
  readonly acsUrl: string;
  /** Trusted issuer; the assertion's Issuer must equal it when set. */
  readonly expectedIssuer?: string;
  readonly logger?: ILogger;
}

/** What a validated assertion yields to the flow. */
export interface ValidatedAssertion {
  /** From the verified document, never from a regex over unverified XML. */
  readonly expiresAt: Date;
  readonly assertionId: string;
  readonly nameId?: string;
  readonly sessionIndex?: string;
  readonly attributes?: Readonly<Record<string, readonly string[]>>;
  /** The raw response, for a flow that must forward it verbatim. */
  readonly raw: string;
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

/** Remembers assertion IDs so a replay is refused. */
export interface IAssertionReplayStore {
  /** True when this ID has been seen; records it otherwise. Expiry is the assertion's own. */
  seen(assertionId: string, expiresAt: Date): Promise<boolean>;
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

| #   | Check                                                         | Refused when                                              |
| --- | ------------------------------------------------------------- | --------------------------------------------------------- |
| 1   | Parses as XML, document element is `samlp:Response`           | it is not                                                 |
| 2   | Signature valid against `idpCertificates`                     | absent, wrong key, or content altered after signing       |
| 3   | Signed node is the node read                                  | the reference points elsewhere                            |
| 4   | `samlp:Status`                                                | `StatusCode` is not `…:status:Success`                    |
| 5   | `Issuer`                                                      | present and not `expectedIssuer`, when that is configured |
| 6   | `Conditions/@NotBefore`                                       | in the future, beyond `clockSkewMs`                       |
| 7   | `Conditions/@NotOnOrAfter`                                    | in the past, beyond `clockSkewMs`                         |
| 8   | `AudienceRestriction/Audience`                                | does not contain `context.audience`                       |
| 9   | `SubjectConfirmationData/@InResponseTo`                       | not `context.expectedInResponseTo`                        |
| 10  | `SubjectConfirmationData/@Recipient`, `Response/@Destination` | present and not `context.acsUrl`                          |
| 11  | Replay                                                        | the store has seen this `ID`                              |

Steps 4, 5, 10 and 11 are precisely the four things `@node-saml/node-saml` does
**not** judge on the SSO path, established by reading its source while building
`auth-mocks`. They are the clearest evidence that this validator is not a
wrapper around somebody else's library.

## Configuration, and what breaks

New on the SAML config:

- `idpCertificates: string[]` — required. Absent or empty is a configuration
  error raised before any network call.
- `spEntityId: string` — the `Audience` the assertion must name.
- `clockSkewMs?: number` — default `0`.
- `authnRequestId?: string` — required **only** when `authorizationUrl` is set,
  because then the package did not build the request.

`buildSamlAuthorizationUrl` changes shape: it returns the URL **and** the
request ID it minted, since the ID must survive to validation.

`parseSamlNotOnOrAfter` is removed. Expiry becomes `ValidatedAssertion.expiresAt`.

`Saml2PureProvider`'s `expiresAt` therefore comes from a different source, and
any consumer whose IdP returns non-`Success` responses will now see them
refused. **`auth-providers` goes major; `interfaces` goes minor.**

## Wiring

Both providers construct the default validator when the consumer supplies none,
and both dispose nothing they did not construct — the same lifecycle rule the
authorization strategies follow.

`Saml2BearerProvider` validates **before** exchanging the assertion at the token
endpoint, so an IdP's refusal is reported as an IdP refusal rather than
resurfacing as UAA's `invalid_grant`.

`Saml2PureProvider` validates before handing the assertion to the cookie
provider, and takes its session lifetime from the result.

## Errors

A new `AssertionValidationError extends TokenProviderError`, carrying the check
that failed as a discriminable field, so a consumer can tell "your IdP declined"
from "this response was not addressed to us" without parsing a message.
Configuration faults — no certificates, no request ID with a pre-built URL —
raise the existing `ValidationError` with `missingFields`, because they are the
same kind of mistake it already reports.

## Testing

`@mcp-abap-adt/auth-mocks` becomes a devDependency of `auth-providers`. The
package it exists to serve finally uses it.

Every corruption variant the mock ships maps onto exactly one check above:
`unsigned`, `wrongKey` and `tamperedAfterSign` onto step 2; `statusFailure` onto
4; `wrongIssuer` onto 5; `notYetValid` onto 6; `expired` onto 7;
`wrongAudience` onto 8; `wrongInResponseTo` onto 9; `wrongDestination` and
`wrongRecipient` onto 10. The mock's two-delivery replay sequence covers 11.

Signature wrapping — step 3 — has no variant, because the mock produces
well-formed documents. Its test builds the attack directly: take a validly
signed assertion, wrap it in a response carrying a second, forged assertion,
and require the validator to refuse rather than read the forged one.

Every rule gets a test that fails when the rule is deleted, and a conjunction is
mutated one half at a time.

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
