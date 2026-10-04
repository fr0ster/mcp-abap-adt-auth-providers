# Client certificates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. This plan lists steps, files, interfaces and what each test proves; code is written at implementation, test first.

**Goal:** token providers authenticate their client with a certificate (mTLS), a signed JWT, a secret or nothing, through a strategy the consumer composes; a certificate-bound token is presented only with its certificate.

**Architecture:** a contract `IClientAuthentication` in `@mcp-abap-adt/interfaces-auth` (released first); five shipped strategies here; every token-request site builds its request from the strategy, or — without one — exactly as today; `BaseTokenProvider` pins one certificate per provider and checks a token's binding before presenting it.

**Tech Stack:** TypeScript, axios, `node:https` / `node:tls` / `node:crypto`, Jest (`npm test`, never `npx jest`), Biome, Docker stand (UAA v79.7.0, Keycloak 26.7.4), BTP trial for XSUAA.

**Spec:** `docs/superpowers/specs/2026-10-04-client-certificates-design.md`, answering `docs/superpowers/2026-10-04-client-certificates-goal.md` (its "Holds throughout" binds every task).

## Global Constraints

- The `IAuthProvider` rules 1–7 in `CLAUDE.md` hold unchanged: no exception crosses the contract; a refusal is fixed words plus allowlisted metadata only.
- Without `clientAuthentication`, every request is byte-for-byte what it is today (spec §3 table).
- `rejectUnauthorized` is never set; a private CA is `NODE_EXTRA_CA_CERTS`.
- No key, passphrase, certificate content, thumbprint, client assertion or secret in a refusal or a log line.
- Dependencies only from the registry: this package uses the published `interfaces-auth` minor, never a link. No new runtime dependency (`node:crypto` signs).
- Version: auth-providers 5.3.0; `interfaces-auth` a minor.
- Every rule protected by a test gets the load-bearing check: break it, watch its own test go red, revert — each half of a compound rule separately.
- Live tests state where they run and skip with a reason elsewhere; the stand suites run only with `UAA_URL` / `KEYCLOAK_URL` (and the new `KEYCLOAK_HTTPS_URL`); XSUAA only under `npm run test:xsuaa`.
- The main checkout is not touched; all work in `.worktrees/client-certificates`.

## Review Focus

1. **A consumer's own strategy misbehaves** — throws, returns a non-string parameter, returns an `endpoint` that is not an absolute `https:` URL: the provider answers Oops in fixed words; no request goes out to a half-built URL. → Task 5.
2. **The server refuses the certificate** (expired, unknown CA, not mapped) at the token endpoint: a `401`/TLS failure becomes the existing token-endpoint refusal, with nothing from the TLS error's message. → Task 5, stand case in Task 8.
3. **A malformed `cnf`** (not an object, `x5t#S256` empty or not a string): treated as bound to nothing this provider presents — Oops, fail closed — never as unbound. → Task 7.
4. **A provider restored with only a refresh token, whose strategy then fails to load its material**: the refresh is refused in fixed words, the stored token is not sent. → Task 6.
5. **A private CA without `NODE_EXTRA_CA_CERTS`**: the TLS error (`UNABLE_TO_VERIFY_LEAF_SIGNATURE` / `SELF_SIGNED_CERT_IN_CHAIN`) becomes a fixed refusal whose hint names `NODE_EXTRA_CA_CERTS`. → Task 5.

---

### Task 1: The contract in `@mcp-abap-adt/interfaces-auth`

Another repository (`fr0ster/mcp-abap-adt-interfaces`), its own worktree, branch and PR; released before Task 3 can build.

**Files (in that repo):**
- Create: `packages/interfaces-auth/src/auth/IClientAuthentication.ts`
- Modify: `packages/interfaces-auth/src/index.ts`, its `CHANGELOG.md`, `package.json` (minor), the package README's contract list

**Interfaces — Produces:** `ITokenRequestDraft { endpoint; mtlsEndpoint?; clientId; grantType }`, `ITokenRequestAuthentication { endpoint?; parameters?; headers? }`, `IClientAuthentication { authenticate(draft): Promise<ITokenRequestAuthentication>; tlsMaterial?(): Promise<ICertificateMaterial> }` — exactly as spec §1, with its doc comments.

- [ ] Create a worktree in that repo from `origin/master`; follow its CLAUDE.md for layout and release (`release:publish` of changed packages).
- [ ] Add the three types, types only (the interfaces package holds no logic); export them.
- [ ] Type-check and build that package; its own checks green.
- [ ] Commit, push, open the PR; stop for the user's review. Merge, tag and the user's publish follow the user's word.
- [ ] After publish: confirm the version on the registry.

### Task 2: Pin today's request shapes

Characterization first, before any site changes.

**Files:**
- Create: `src/__tests__/auth/tokenRequestShapes.test.ts`

- [ ] One test per row of spec §3's table (seven rows; the OIDC row covers code, refresh, poll, password and exchange separately): mock axios at the module boundary, call the site, record URL, method, body (parsed form) and headers; assert them exactly — with and without a secret where the row has both.
- [ ] Run: green against today's code. These tests are not edited by later tasks.
- [ ] Commit.

### Task 3: Certificate material — one check, one thumbprint

**Files:**
- Create: `src/auth/certificateMaterial.ts`
- Modify: `src/credentials/CertificateAuthProvider.ts` (use the shared check)
- Test: `src/__tests__/auth/certificateMaterial.test.ts`; the existing `src/__tests__/credentials/certificateMaterial.test.ts` stays green unchanged

**Interfaces — Produces:** `checkCertificateMaterial(material): AuthOutcome` — the 5.2.3 rules (incomplete, then `createSecureContext`), the same fixed refusals; `certificateThumbprint(material): string` — SHA-256 of the leaf certificate's DER, base64url; from `cert` PEM via `X509Certificate`, from `pfx` via a `TLSSocket` over the secure context.

- [ ] Tests: the thumbprint of `client.crt` equals that of `client.pfx` (measured equal); a known fixed value for the fixture; a chain PEM yields the leaf's thumbprint; unusable material throws a class on the refusal allowlist, nothing of the material in it.
- [ ] Move the check out of `CertificateAuthProvider.prepare()`; its tests stay green unchanged.
- [ ] Load-bearing: break the incomplete rule, then the context rule — each turns its own test red.
- [ ] Commit.

### Task 4: The five strategies

**Files:**
- Create: `src/clientAuthentication/noClientAuthentication.ts`, `clientSecret.ts` (Basic and Post), `tlsClientCertificate.ts`, `privateKeyJwt.ts`, `index.ts`
- Create: `src/errors/ClientAuthenticationError.ts` (signing key unusable)
- Modify: `src/auth/refusal.ts` (allowlist the new class, its fixed words per spec §5), `src/index.ts` (exports)
- Modify: `package.json` — `interfaces-auth` range to the Task 1 version, `npm install`, lockfile checked for `"link": true` and non-registry entries
- Test: `src/__tests__/clientAuthentication/*.test.ts`

**Interfaces — Consumes:** Task 1 types; `checkCertificateMaterial` (Task 3). **Produces:** `noClientAuthentication()`, `clientSecretBasic(secret)`, `clientSecretPost(secret)`, `tlsClientCertificate({ material, endpoint? })`, `privateKeyJwt({ key, algorithm: 'RS256' | 'ES256', keyId?, audience? })`, each returning `IClientAuthentication`.

- [ ] Tests per strategy, each asserting what only its rule produces: the parameters/headers each sends (spec §2 table); `tlsClientCertificate` endpoint order — `endpoint`, else `draft.mtlsEndpoint`, else `draft.endpoint`; its material read once across many calls; unusable material → the 5.2.3 refusal words; `privateKeyJwt` claims (`iss`=`sub`=client id, `aud` = `audience` else the endpoint the request goes to, unique `jti`, `exp` − `iat` = 60 s, `kid` only with `keyId`) and the signature verifies with the public key, RS256 and ES256; a key of the wrong type → `ClientAuthenticationError`, refusal in fixed words, no key bytes in it.
- [ ] Implement.
- [ ] Load-bearing: each endpoint-order branch, the `aud` fallback, the read-once memo — break each, its test red, revert.
- [ ] Commit.

### Task 5: One token-request path

**Files:**
- Create: `src/auth/tokenRequest.ts` — builds and sends one request from grant parameters, a draft and an `IClientAuthentication` (or a private today's-shape adapter), with an `https.Agent` from given TLS material when there is one
- Modify: `src/auth/clientCredentialsAuth.ts`, `tokenRefresher.ts`, `browserAuth.ts` (code exchange only), `passcodeAuth.ts`, `saml2TokenExchange.ts`, `oidcToken.ts` (all six requests, device initiation included) — each takes an optional authentication + pinned material and otherwise keeps its adapter
- Modify: `src/__tests__/providers/noTokensInLogs.test.ts`; `describeOAuthErrorBody` callers — the strategy's parameter values (`client_secret`, `client_assertion`) join the redaction list
- Test: `src/__tests__/auth/tokenRequest.test.ts`; Task 2's tests must stay green unchanged

**Interfaces — Consumes:** Tasks 1, 3, 4. **Produces:** each site's signature gains `auth?: { strategy: IClientAuthentication; material?: ICertificateMaterial }` (the material already pinned by the provider, Task 6).

- [ ] Tests: with a strategy, its parameters and headers reach the body and headers, its `endpoint` replaces the URL; with material, the request uses an agent carrying exactly that material and no `rejectUnauthorized`; a strategy that throws, returns a non-string parameter or a non-`https:` endpoint → fixed refusal, no request sent (Review Focus 1); a TLS trust failure → fixed refusal naming `NODE_EXTRA_CA_CERTS` in the hint (Review Focus 5); a `401` after mTLS → the existing token-endpoint refusal (Review Focus 2); a secret or assertion in an error body is redacted; `noTokensInLogs.test.ts` extended — no key, passphrase, certificate, assertion or secret from any strategy reaches a log line.
- [ ] Refactor each site onto `tokenRequest`; Task 2 stays green after every site.
- [ ] Load-bearing: drop the endpoint override, drop the agent, drop the redaction of the assertion — each red.
- [ ] Commit.

### Task 6: Providers take `clientAuthentication`; one certificate pinned

**Files:**
- Modify: `src/providers/BaseTokenProvider.ts` (pinning), the eight providers of spec §3, their config types; `src/auth/oidcDiscovery.ts` (`mtls_endpoint_aliases` → `mtlsEndpoint`)
- Test: `src/__tests__/providers/clientAuthentication.test.ts`

**Interfaces — Consumes:** Tasks 3–5. **Produces:** `clientAuthentication?: IClientAuthentication` on each provider config; `BaseTokenProvider` holds `pinned?: { material: ICertificateMaterial; thumbprint: string }`, set on first need, never replaced.

- [ ] Tests: for each provider, the strategy reaches every request it sends (first token, refresh, device initiation and poll, exchange); `clientSecret` + strategy → `ValidationError` naming `clientSecret`; a strategy alone satisfies the `clientSecret` requirement of `ClientCredentialsProvider` and `AuthorizationCodeProvider`; a strategy whose `tlsMaterial()` answers A then B is called once and every request and logon presents A; a provider restored with only a refresh token whose material fails to load → refusal, nothing sent (Review Focus 4); discovery with aliases fills `mtlsEndpoint`, without them leaves it absent.
- [ ] Implement.
- [ ] Load-bearing: call `tlsMaterial()` per request instead of once — the A/B test red; drop the both-given check — its test red.
- [ ] Commit.

### Task 7: The binding check in `establish()` and `authorize()`

**Files:**
- Create: `src/auth/tokenBinding.ts` — `readBinding(token): { state: 'bound'; thumbprint } | { state: 'unbound' } | { state: 'unknown' }`
- Modify: `src/providers/BaseTokenProvider.ts` (`establish`, `authorize`); `src/auth/refusal.ts` (the binding refusal's fixed words, spec §4)
- Test: `src/__tests__/providers/tokenBinding.test.ts`

- [ ] Tests: every row of spec §4's table with recording targets — bound/equal, bound/none, bound/other, unbound with and without material, unknown with material on a wire that refuses TLS material (Oops) and on one that takes it (Ok), unknown without material (Bearer); a seeded bound `accessToken` without a strategy → Oops in both methods, no header written; a malformed `cnf` → Oops (Review Focus 3); the refusal names no thumbprint.
- [ ] Implement.
- [ ] Load-bearing: treat unknown as unbound — its rows red; skip the check in `authorize()` — the seeded-token test red; compare without the thumbprint — the other-certificate row red.
- [ ] Commit.

### Task 8: The stand

**Files:**
- Modify: `tests/stand/compose.yaml` (Keycloak HTTPS on `127.0.0.1:${KEYCLOAK_HTTPS_PORT:-8444}`, `KC_HTTPS_CERTIFICATE_*`, `KC_HTTPS_CLIENT_AUTH=request`, `KC_TRUSTSTORE_PATHS`), `tests/stand/run.sh` / `up.sh` (export `KEYCLOAK_HTTPS_URL`, `NODE_EXTRA_CA_CERTS`), `tests/stand/keycloak/realm-test.json` (clients `mtls`, `jwt`, the X.509 direct-grant flow and a user mapped from `client-a`), `tests/stand/uaa/config/uaa.yml` (a `private_key_jwt` client with `jwks`), `.gitignore` (each committed key named)
- Create: `tests/stand/keycloak/tls/` — CA, server (`localhost`, `127.0.0.1`), `client-a`, `client-b`, the JWT signing pair, a README saying they are trusted by nothing but the stand and how they were made
- Create: `src/__tests__/integration/stand/clientCertificates.test.ts`

- [ ] Fixtures generated once, committed; the stand comes up; existing stand suites still green.
- [ ] Cases (spec §8 stand rows): mTLS client credentials → a token with `cnf.x5t#S256` equal to `client-a`'s thumbprint; userinfo through a Node `https` request presenting what `establish()` handed a recording target → 200, with none → 401, with `client-b` → 401; token request with `client-b` → the fixed refusal; `OidcPasswordProvider` + mTLS → refresh, the new token bound to the same thumbprint; `privateKeyJwt` on Keycloak → token; `privateKeyJwt` on UAA → token; part A (spec §6) — `CertificateAuthProvider` material accepted for `client-a` mapped to its user, refused for `client-b` and for none.
- [ ] `npm run test:stand` green; CI's stand job runs it.
- [ ] Commit.

### Task 9: XSUAA x509 on the trial

**Files:**
- Modify: `tests/xsuaa/setup.sh` (instance with `oauth2-configuration.credential-types: ["x509", "binding-secret"]`, a key with `{"credential-type": "x509"}`, recorded in `.local/owned` like every other resource), `teardown` accordingly
- Create: `src/__tests__/integration/xsuaa/x509.test.ts`

- [ ] Before any `cf` write: `cf target` equals `XSUAA_CF_API`/`ORG`/`SPACE` exactly (the scripts refuse otherwise).
- [ ] Case: the key's `certificate`/`key`/`certurl` mapped by the test (as a consumer would) → `ClientCredentialsProvider` + `tlsClientCertificate({ material, endpoint: certurl })` → a token; no secret anywhere in the configuration.
- [ ] Run `npm run test:xsuaa`; teardown removes everything, also on failure.
- [ ] Commit.

### Task 10: Documentation and release preparation

**Files:**
- Modify: `README.md` ("Client authentication": the five strategies, a bound token and its certificate, the opaque-token limit of spec §4, the XSUAA x509 recipe with the consumer mapping the key's fields), `docs/btp-setup.md` (x509 per provider, tags honest: Measured where measured, ADT accepting such a token stays Inference), `CLAUDE.md` (`src/clientAuthentication/`, rule 7's collaborator list, the binding rule), `CHANGELOG.md` 5.3.0, `package.json` 5.3.0 + lockfile
- Delete: `docs/superpowers/2026-10-04-client-certificates-goal.md`, the spec and this plan — before the release, after their owed items are in the PR description

- [ ] Docs written against the code as built, not the spec's wording.
- [ ] `npm run build`, `npm run test:check`, `npm run lint:check`, `npm test` in the worktree; `npm run test:stand`.
- [ ] Push; external review on the PR; fixes into the same PR.
- [ ] Merge, tag and publish only on the user's word; before saying "publish", the main checkout on the tag, git-verified, built.
