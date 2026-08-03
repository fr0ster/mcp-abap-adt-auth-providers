# Mock authorization servers for deterministic testing

**Date:** 2026-08-02
**Status:** approved, not implemented
**Follows:** the authorization-strategies arc (issue #11), released as `interfaces@11.6.0`, `auth-providers@2.0.0`, `proxy@2.0.0`, `auth-broker@2.0.0`
**Unblocks:** issue #19 — SAML assertions are accepted without any validation

## Why

Nothing in this family can exercise a full authorization round trip. The only
stub that exists is in `proxy`'s `callbackPortLifecycle.test.ts`, and it serves
`/oauth/token` alone — no `/oauth/authorize`, no OIDC discovery, no SAML IdP.

The cost was visible throughout the arc that just shipped. Properties that a
real server would have checked were instead guarded by hand and asserted
against ourselves:

- that the `redirect_uri` in the token exchange matches the one the
  authorization request advertised — enforced by two guards we wrote, verified
  by tests we wrote;
- that the PKCE `code_challenge` in the URL derives from the verifier that
  reaches the exchange — verified by recomputing the hash inside the test;
- that an ephemeral port travels intact from bind to exchange — never verified
  end to end at all.

Live tests against BTP did not close the gap: they need a profile, they reuse a
cached token when one exists, and the interactive cases need a human. The one
live run in this arc completed in 1.7 s from cache, so the redirect path it was
meant to prove was never taken.

Mocks make that path deterministic. They do not replace live testing; they
remove the load from it.

## Scope

**In, for the first version:**

- UAA `authorization_code`, including refresh
- the SAML bearer grant at the same token endpoint, so `Saml2BearerProvider` is
  reachable end to end
- OIDC authorization code with PKCE, including discovery
- A SAML IdP that signs, and that can violate each rule issue #19 will enforce — one rule at a time

**Out, for later:** UAA device flow, `client_credentials`, OIDC device /
password / token-exchange. They are used by the packages, but the interactive
redirect flows are what has never been testable, and the SAML IdP is what issue
#19 depends on.

**Out permanently:** any CLI. This is a library that tests start and stop.
Manual clicking through a real browser stays a live-system activity.

## The package

`@mcp-abap-adt/auth-mocks`, a devDependency of `auth-providers`, `proxy` and
`auth-broker`.

```
src/
├── index.ts       # startMockUaa, startMockOidc, startMockSamlIdp, visit
├── server.ts      # ephemeral bind, graceful close, the request journal
├── uaa.ts         # /oauth/authorize, /oauth/token
├── oidc.ts        # /.well-known/openid-configuration, /authorize, /token
├── saml.ts        # consumes an AuthnRequest, returns an auto-submitting form
├── signing.ts     # a self-signed certificate per instance, XML-DSig
└── browser.ts     # visit(url) — an HTTP client that follows redirects
```

A separate package rather than a subpath of `auth-providers` for one decisive
reason: signing SAML assertions needs XML-DSig and certificate generation, and
those belong nowhere near the authorization package's dependency tree — not
even as devDependencies, because the boundary this arc built would start eroding
from the test side.

**The package does not import anything from `auth-providers`.** It speaks HTTP,
OAuth2 and SAML. A mock that knows our types will eventually agree with our
mistakes instead of catching them.

Each mock binds an ephemeral port and returns a handle carrying `url`,
`close()`, and a **journal of the requests it received**. The journal is not a
convenience: without it a test can only assert the outcome, while with it the
test asserts what the client *sent* — `redirect_uri`, `code_challenge`,
`client_id`, `grant_type`. That is where every defect in the last arc lived.

## What the mocks enforce

Strict by default: the mock rejects what a real server would reject, so a
failure surfaces as the server's refusal rather than as our own assertion.

**UAA and OIDC, at `/oauth/token`:**

- `redirect_uri` must match the one presented at `/authorize` exactly; otherwise
  `invalid_grant`
- an authorization code is single-use; a second exchange fails
- codes expire, after a lifetime the mock is configured with (short by default,
  so an expiry test does not have to wait)

**Client authentication, stated exactly, because the two clients differ.** UAA's
`exchangeCodeForToken` sends credentials only as HTTP Basic and puts no
`client_id` in the body; OIDC's `exchangeAuthorizationCode` puts `client_id` in
the body. A mock that assumed either shape would reject one of our own clients.

So the mock accepts all three of:

- `client_secret_basic` — credentials in the `Authorization: Basic` header
- `client_secret_post` — `client_id` and `client_secret` in the form body
- public client — `client_id` in the body, no secret, allowed only when the mock
  is configured for it

Whichever arrives, the `client_id` must match the one from `/authorize`. If both
Basic and body credentials are present and disagree, that is
`invalid_client` — a real server treats it as a malformed request rather than
picking a winner, and so does this one.

Errors follow RFC 6749 §5.2: HTTP 400 with a JSON body carrying `error` and
`error_description`. `invalid_client` is the exception, and the rule is
conditional rather than flat: **401 with a matching `WWW-Authenticate` header
when the client attempted to authenticate through the `Authorization` header,
400 otherwise.** A mock that always answered 401 would enshrine behaviour the
specification does not require — precisely the drift a strict mock is supposed
to prevent. Tests assert on these codes, so they are part of the contract.

**The SAML bearer grant.** `/oauth/token` also serves
`grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer`, taking the assertion
in the `assertion` parameter. Without it `Saml2BearerProvider` cannot be tested
at flow level at all — it consumes the SAML IdP's output and immediately
exchanges it, so an IdP mock without a matching token endpoint leaves half that
provider unreachable.

This one carries a deliberate trap, and it is the point rather than a hazard.
RFC 7522 §2.1 requires the `assertion` parameter to be a base64url-encoded
`Assertion`; `exchangeSamlAssertion` forwards the whole base64 `samlp:Response`
exactly as the ACS received it. Strict mode enforces the RFC, so if our client
is non-compliant the mock says so on the first run. **A failure there is a
finding about the client, not a defect in the mock** — and one that belongs to
issue #19's cycle, where the SAML path is being reworked anyway. A lenient mode
accepts what we currently send, so this discovery does not block the rest of the
package; which mode a test uses is explicit, never a default that hides the
question.

**Access tokens are JWTs, and that is a contract, not a detail.**
`BaseTokenProvider.parseExpirationFromJWT` splits on `.`, requires exactly three
parts, and reads `exp`; anything else yields `undefined`, and
`calculateExpiresIn` then yields `undefined` too. A mock handing back an opaque
string would leave the provider with no basis to consider a freshly issued token
valid, so the next `getTokens()` would refresh or log in again — a loop caused
entirely by the mock, and one that would look like a provider bug.

So the mock issues syntactically valid JWTs: real header, base64url payload
carrying at least `exp` and `iat`, and a signature segment. The signature is not
verified by anything in this family — the provider only parses — so it need not
be cryptographically meaningful, and the spec says so out loud rather than
leaving an implementer to wonder whether to sign.

Lifetimes are configurable per mock, and the handle exposes a way to mint a
**consistent pair**: an access token already expired alongside a refresh token
still valid. Without that, a test wanting the refresh path has to either
hand-craft a JWT or run a full code flow first and then wait — the first is
duplication, the second is a slow test.

**Refresh.** `/oauth/token` also serves `grant_type=refresh_token`:

- a successful code exchange issues a refresh token alongside the access token,
  and the mock remembers it
- refreshing returns a new access token; whether it also rotates the refresh
  token is configurable, because both behaviours exist in the wild and a client
  must survive either
- with rotation on, presenting a superseded refresh token fails with
  `invalid_grant` — this is the reuse detection a real server performs
- an unknown or explicitly revoked token fails with `invalid_grant`
- client authentication applies exactly as above

A test forces the refresh path rather than the cached-token path by constructing
the provider with an expired access token and a valid refresh token — the shape
`AuthorizationCodeProvider` already accepts. The mock can also be told to fail
every refresh, which is how the refresh-then-login fallback gets exercised
without hand-writing an invalid token.

**OIDC additionally — PKCE, demanded at both ends.** `/authorize` **refuses** a
request that omits `code_challenge`, that omits `code_challenge_method`, or
whose method is anything other than `S256`. Verifying a challenge only if one
happened to arrive would let a non-PKCE request through while still satisfying
the letter of the exchange rule — a strict mock that quietly tolerates the
weaker flow is not strict. Refusals here get their own tests, like every other
refusal in this package.

Then `code_challenge` is recorded, and `/token` recomputes `S256(code_verifier)`
and compares. This moves PKCE pairing
from a string comparison inside our test to a check by the server, which is how
a real identity provider will check it.

**OIDC additionally — `state`:** the mock **mirrors** `state` back on the
callback and never judges it. Validating `state` is the client's duty, and a
mock that checked it would be doing the client's job while hiding whether the
client does it. Variants the mock can be asked for: `wrongState` (returns a
different value) and `missingState` (returns none).

This matters more than it looks. `OidcBrowserProvider` does not send `state` at
all today — `src/providers/OidcBrowserProvider.ts:90-95` appends
`response_type`, `client_id`, `redirect_uri`, `scope`, `code_challenge` and
`code_challenge_method`, and nothing else — while `OidcCallbackResult` carries a
`state` field that nothing populates a request with and nothing checks. A mock
without `state` would enshrine that gap as normal. With it, the absence becomes
a test someone can write, and the CSRF / callback-substitution exposure becomes
visible rather than theoretical. Closing the gap in the provider is not this
package's job; making it observable is.

**The SAML IdP** inflates and parses `SAMLRequest` for its
`AssertionConsumerServiceURL` and `ID`, and reads `RelayState` from the **HTTP
query string**, where the Redirect binding puts it — alongside `SAMLRequest`,
never inside the XML (`buildSamlAuthorizationUrl` appends it as its own
parameter). It then **responds with an HTML auto-submitting form** targeting
that ACS — the same thing a real IdP
returns to a browser under HTTP-POST binding. It does not deliver the assertion
itself.

Delivering it is `visit()`'s job, because that is what a browser does. If the
IdP posted to the ACS server-side, `openUrl` would never be called and the seam
this whole design turns on would go untested — the self-driving shape rejected
below. `RelayState` is carried through the form and posted back unchanged.

Assertions are valid and signed by default; on request, any single way of being
wrong:

| variant | what is broken |
|---|---|
| `unsigned` | no signature at all |
| `wrongKey` | signed with a different key |
| `tamperedAfterSign` | signature present, but verification fails — content altered after signing |
| `statusFailure` | `samlp:Status` is not `Success` |
| `expired` / `notYetValid` | `Conditions` outside its window |
| `wrongAudience` | `AudienceRestriction` names someone else |
| `wrongInResponseTo` | does not match the request's `ID` |
| `wrongDestination` | `Destination` names a different ACS |
| `wrongRecipient` | `SubjectConfirmationData@Recipient` names a different ACS |
| `wrongIssuer` | `Issuer` is not the IdP the SP trusts |
| `replayedAssertionId` | *a sequence, not a single response — see below* |

The last four were missing and matter more than their position suggests.
`Destination` and `Recipient` are what stop a **validly signed** assertion being
captured and replayed at a different ACS — the one attack signature verification
alone does not address, because the signature stays perfectly valid. `Issuer`
distinguishes a genuine assertion from one signed by some other IdP the SP has
no relationship with.

`replayedAssertionId` is different in kind and must be described as what it is:
**a sequence, not a corrupted response.** Every other variant is one delivery a
verifier rejects on its own merits. A replayed assertion, taken in isolation, is
perfectly valid — that is precisely why replay is dangerous. The scenario runs:
deliver a valid assertion, watch it be accepted and its `ID` recorded, then
deliver one carrying that same `ID` and watch the second be rejected. Written as
a single call it would prove nothing, so the mock's API must make the two-step
shape obvious rather than offering replay as another row of corruption.

Each rule the validation strategy in issue #19 enforces has a scenario here that
violates exactly that rule and nothing else. The claim is deliberately that
narrow: this list covers the rules #19 will define, not "every way a SAML
assertion can be wrong" — SAML has more failure modes than any test package
should pretend to enumerate.

Signing keys are generated per mock instance at startup and live in memory. The
test receives the public certificate to configure a validator with. No key
material in the repository.

## How a test drives it

The "user" is an HTTP client, wired through the seam the strategies already
expose:

```ts
const uaa = await startMockUaa();
const provider = new AuthorizationCodeProvider({
  uaaUrl: uaa.url, clientId: 'c', clientSecret: 's',
  authorization: browserCallbackStrategy({ port: 0, timeoutMs: 5000, openUrl: visit }),
});
const tokens = await provider.getTokens();
```

`visit(url)` follows the authorize redirect and lands on the callback. For SAML
it does what a browser does under HTTP-POST binding: takes the auto-submitting
form and posts it to the ACS.

**There is no login page and no credentials.** `/authorize` decides on the spot
what to do with the request and redirects — it does not render a form, and the
fake browser never types anything. Authenticating a user is not what these mocks
are for; what they verify is the protocol around it. A test that wants a login
to fail asks the mock to deny, rather than supplying a wrong password.

Two alternatives were considered and rejected. A mock that drives itself —
issuing the callback server-side — never calls `openUrl`, so the seam this arc
was built around goes untested, and "the browser never opened" becomes
indistinguishable from "the user never finished". A test that scripts each step
by hand re-implements the flow, so it verifies itself rather than the provider —
the trap this project has already fallen into twice, where a test stayed green
while the rule it existed to protect could be deleted outright.

The low-level handle stays available for cases that cannot be assembled any
other way, but it is not the ordinary path.

`port: 0` in the example is deliberate. The mock sees the real bound port in
`redirect_uri` and answers `invalid_grant` if the chain diverges anywhere — so
the ephemeral port is finally verified end to end rather than in pieces.

**Failure scenarios are configured on the mock, not simulated in the test:**

```ts
const uaa = await startMockUaa({ authorize: 'deny' });   // error=access_denied
```

The login then fails the way it will in production — through a callback
carrying `error=` — which is the branch added to the OIDC route during the last
arc and never exercised along its real path.

**What each package gets.** `auth-providers` covers its providers and
strategies. `proxy` replaces its one-endpoint stub and can drive a login through
the CLI end to end. `auth-broker` gains flow-level tests it has never had, for
`mcp-auth` and `mcp-sso` including the `--config` path where a regression was
caught by review rather than by tests.

## Testing the mocks

A mock that is wrong leniently produces a green suite and false confidence —
worse than having none. So the package's own tests assert **refusals**, not
successes: an exchange with a mismatched `redirect_uri` must fail, a second
exchange of one code must fail, an `S256` derived from a different verifier must
be rejected.

For SAML, from both directions: an assertion this mock signs must be accepted by
an independent verifier, and each corrupted variant must be rejected by it —
with `replayedAssertionId` exercised as the two-step sequence above, since a
single delivery of it is valid by design.
Otherwise we risk writing a validator and a mock that agree with each other and
are both wrong.

The package's tests are written against the protocol, never against our
providers.

## Release

`0.1.0`, published because three repositories consume it. The sequence is the
one this family uses: branch, PR for review, merge, tag, and the user publishes.
Consumers adopt it in separate PRs afterwards, one per repository, so each
review stays readable.

## Risks, stated plainly

**Drift between the mock and reality.** A mock written from our understanding of
a protocol enshrines that understanding. Live tests against BTP remain
necessary; the mocks reduce the load on them rather than replacing them. This
belongs in the package README, or in six months someone will conclude that live
runs are obsolete.

**The temptation to bend the mock.** When a test goes red, editing the mock is
the easiest fix. The defences are that the mock's own tests come from the
protocol and that the package cannot import our types.

**SAML signing is not trivial.** XML canonicalisation must match what a real
identity provider produces, or a validator written against this mock will reject
a genuine assertion. Verification against an external tool belongs in the
implementation, not against a verifier we also wrote.
