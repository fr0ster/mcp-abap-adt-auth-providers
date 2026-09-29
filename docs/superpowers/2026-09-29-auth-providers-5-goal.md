# auth-providers 5.0.0 — goal and path

**Status:** agreed direction, before the spec. The spec and then the plan come
next; this file fixes what they are for.

## Goal

`@mcp-abap-adt/auth-providers` 5.0.0 is the home of **every** implementation
of `IAuthProvider`, on the contract released in `@mcp-abap-adt/interfaces-auth`
3.0.0 (with `interfaces-auth-sap` 1.1.0).

**The principle it serves.** A provider is injected into the process, and the
process delegates authentication to it through one contract it calls the same
way for every provider — basic, authorization code, SAML, certificate,
passwordless SNC, anything later:

```
prepare()                      once per connect
establish(logon target)        every logon (HTTP session, RFC conversation)
authorize(request target)      every request attempt
rejected(rejection)            the system said no — Ok: try once more
```

Each answers **Ok** or **Oops** with a refusal (`reason`, `hint?`). The
process never asks what it was given, never narrows, never branches on a
kind; the provider does all the work of its way in.

**Success:** any provider from this package can be handed to the process with
no check of what it is, and every one answers all four moments.

## What is in it

- **Token providers** — `AuthorizationCodeProvider`, the four OIDC providers,
  `ClientCredentialsProvider`, `UaaPasscodeProvider`, `Saml2BearerProvider`:
  `prepare` → `getTokens()`, `authorize` → `Authorization: Bearer …`,
  `rejected` → `refreshTokens()` (Ok) or Oops.
- **SAML session cookies** — `Saml2PureProvider`: `authorize` → `cookies(…)`,
  `rejected` → log in again.
- **Moved in from `@mcp-abap-adt/connection`** — `BasicAuthProvider`,
  `CertificateAuthProvider` with `FileCertificateMaterialLoader`,
  `SamlAuthProvider` (cookies handed over), `TokenAuthProvider` (a token that
  comes from elsewhere: a string, or the broker's `ITokenRefresher`).
- **`SncLogonProvider`** — passwordless RFC logon through an installed SNC
  product (SAP Secure Login Client). The SNC-specific design reviewed in #55
  carries over: library discovery (explicit `sncLib` only; automatic
  candidates skipped when unusable; architecture from PE / Mach-O incl.
  `FAT_MAGIC_64` / ELF), the Secure Login Client probe scoped to its own
  library, `snc_qop` from `1, 2, 3, 8, 9` with default `9`, and the
  explanations of `A2200019` and `SNCERR_INIT`. On the new contract:
  `prepare` = discovery + probe, `establish` → `logonParameters(…)`,
  `rejected` → Oops with the cause and what to do.
- **Scope of the package changes** — `CLAUDE.md` and the README stop saying
  "ONLY implements `ITokenProvider`": this package provides the credentials
  the process delegates to.

**Stays:** `ITokenProvider` / `IRefreshableTokenProvider` on the token
providers — the broker's token API and consumers such as `mcp-calm-*` want a
token and nothing else.

## Open, for the spec

1. **How a token provider becomes an `IAuthProvider`.** Proposed:
   `BaseTokenProvider` implements both contracts, so every token provider *is*
   an `IAuthProvider` with no wrapper; `TokenAuthProvider` remains only for a
   token that comes from outside. Alternative: token providers stay pure and a
   `TokenAuthProvider(tokenProvider)` wraps them — fewer changes here, but the
   consumer must know to wrap.
2. **Where renewed tokens are persisted.** The broker persists today, after
   `getTokens()`. When a provider renews inside `prepare()` or `rejected()`,
   the new token must reach the session store before the provider answers
   Ok — an injected hook on the token providers, or the broker wrapping them.
3. **`rejected()` that needs an interactive login** (refresh token expired):
   who bounds its time — the provider's strategy timeout, or the process.

## Path

1. ~~`interfaces-auth` 3.0.0, `interfaces-auth-sap` 1.1.0~~ — released
   2026-09-29 (interfaces #111).
2. **This package, 5.0.0** — spec → plan → implementation, in this PR's
   successor. ← next
3. `@mcp-abap-adt/connection` 10.0.0 — the process on the contract: wires
   implement the targets, RFC logon takes `user`/`passwd` from the provider,
   its own providers removed.
4. `@mcp-abap-adt/auth-broker` 4.0.0 — `getProvider(destination)`: a provider
   already paired with the stores. Independent of step 3.
5. `mcp-abap-adt` — the provider from the broker into the connector; the
   per-auth-type construction and the broker 2.x call removed. Live check:
   basic over HTTP and RFC, a token destination, SNC over RFC — one code path.

Each step is its own PR in its own repository, merged and released before the
next that depends on it.
