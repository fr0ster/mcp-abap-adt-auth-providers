# Goal: a Kerberos credential over HTTP (SPNego)

## The target

An `IAuthProvider` in this package that logs on to an HTTP service with the
user's Kerberos ticket and no password: every request carries
`Authorization: Negotiate <token>` (RFC 4559), the token a SPNego-wrapped
Kerberos service ticket for the service principal the consumer names.

Its conformance to the protocol is proved first on a Kerberos stand in Docker,
beside the provider stand's UAA and Keycloak: a KDC, a service that accepts
only `Negotiate` and checks the token against its keytab, and a client with a
ticket from `kinit`. No SAP system is needed for that proof.

An ABAP system that accepts SPNego at ICF is the second stage: the same
provider against a real system, once one is known to have SPNego switched on.

## Why

SNC over RFC (`SncLogonProvider`) already gives a passwordless logon where the
SAP GUI does. Over HTTP there is none: a system reached over HTTP still needs a
password, a certificate or a browser login. SPNego is what a browser on a
domain machine does on its own, and what ICF accepts once its administrators
switch it on.

The earlier `KerberosAbapConnection` in the connection package was removed
because it had never met a KDC. This provider exists only together with the
stand that proves it.

## What changes

- **`SpnegoAuthProvider`** in this package, extending `AuthProviderBase`,
  answering the four moments of `IAuthProvider` like every other provider here.
  It is named for the mechanism the service sees, as `SncLogonProvider` is.
- **Where the token comes from is a strategy the consumer composes:** a token
  source behind a contract in interfaces-auth, since both this package and a
  consumer implement it.
- **A ready token source over a GSSAPI/SSPI binding is shipped in a package of its own,** built on
  the `kerberos` npm package. This package stays free of native code and of
  install scripts and does not depend on it; only a consumer who installs that
  package takes the native build, allowing its script knowingly. Both live in
  this repository, which becomes a multi-package repository, so the stand
  proves them together before either is published. The source's build is
  proved in CI on Linux, macOS and Windows.
- A refusal the error contract cannot express yet (no ticket, an NTLM token)
  is added to interfaces-auth and auth-errors first, published before this
  package uses it.
- The stand gains the Kerberos services, its fixtures committed like the other
  stand fixtures, and a suite that runs the provider with the system source against
  them; CI runs it on Linux.
- README, `docs/passwordless-sso.md` (the SPNego rows flip from Inference to
  Measured, with the date, only after the stand run) and the CHANGELOG.

## Holds throughout

- Rules 1–8 of this package hold for the new provider: no exception crosses the
  contract, every refusal minted by auth-errors with allowlisted facts only, no
  error's message in a refusal or a log line.
- **A fresh token for every request.** A Kerberos authenticator carries a
  timestamp and the service keeps a replay cache; a token is never resent or
  cached across requests.
- **The token never reaches a log line, an error or a refusal**, nor does the
  ticket or any key material.
- **Nothing is guessed.** The service principal is stated by the consumer; it
  is not derived from a host the provider never sees. No fallback to another
  mechanism: a token that is NTLM, not Kerberos, is refused. The provider does
  not tell HTTP from RFC either: SPNego has nothing for a logon, so
  `establish()` writes nothing and answers Ok (rule 3); an RFC logon without a
  user is the system's to refuse, and the README says SPNego is for HTTP.
- **A `401` is a `401`.** `rejected()` reads it as rule 5 does, the credential
  refused. A service that continues the negotiation (`WWW-Authenticate:
  Negotiate <token>` on a `401`) is not answered and reads the same; the README
  says so.
- **Where the ticket lives is the consumer's.** The provider holds no ticket
  and keeps none: it asks its token source for a token. The system source uses the
  system's own ticket cache — what `kinit` or the domain logon filled — and may
  name the client principal in it; a consumer that keeps tickets elsewhere, a
  store of its own included, supplies its own token source through the same
  contract.
- **The consumer composes.** No token source is built when none is given.
- **Supply chain.** The native binding enters only the system source's package,
  through `allowScripts`, reviewed and built from source; dependencies come
  from the registry.
- No timeouts and no retries of the package's choosing; nothing written to
  stdout.
- The stand proves the rules on the wire: each rule gets a test that goes red
  when the rule is removed.

## Scope

In: the token-source contract, the error contract's new refusals, the
provider, the system source's package, the stand, the suite, the docs.

Out: the live run against an ABAP system and the manual runs on macOS and
Windows with a real ticket (the second stage); SNC (built); NTLM; X.509 client
certificates (built); answering a multi-leg exchange; verifying the service's
mutual-authentication token; Windows on arm64.
