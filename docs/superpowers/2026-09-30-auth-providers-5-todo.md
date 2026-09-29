# auth-providers 5.0.0 — what is left (TODO)

Goal and path: `2026-09-29-auth-providers-5-goal.md`. Spec and plan under
`specs/` and `plans/`. This file goes away with them, in the PR that finishes
the goal's last step (the server).

## Where things stand (2026-09-30)

Branch `feat/auth-providers-5` — all 14 plan tasks done, final whole-branch
review "ready to merge" after one fix wave; version is already `5.0.0` in
`package.json` / `package-lock.json`.

| Check | Result |
|---|---|
| `npm test` | 43 suites / 599 tests pass (5 live suites skipped without their environment) |
| Provider stand, `npm run test:stand` (UAA + Keycloak) | 5 suites / 21 tests pass (Windows, Podman rootful) |
| Live SNC on E19 (Windows, Secure Login Client 3.0.3) | Steps 1–3 pass — see "Live SNC" below |
| XSUAA trial, `npm run test:xsuaa` | **not done** — do it on the laptop (below) |

Live SNC, 2026-09-29:
1. `SncLogonProvider.forSecureLoginClient` → `prepare` / `establish` Ok; the
   registry's x64 `sapcrypto.dll` chosen although the machine-wide `SNC_LIB`
   is the installer's x86 copy.
2. Those parameters into an RFC conversation: logon without a password;
   systeminformation, discovery, search, class source, LOCK/UNLOCK — all 200.
3. Client logged out, logon window closed → RFC open fails `A2200019`;
   `rejected` → "the SNC library has no credential to present (A2200019)".
   Observed: the SNC library starts the client on demand and it logs on (SSO
   or its window) — so the probe no longer refuses in `prepare()` (owner's
   decision, in the spec).

## TODO

### 1. XSUAA trial — on the laptop (macOS)

- [ ] `git fetch && git checkout feat/auth-providers-5` (needs step 2's push
      first if the branch is not on origin yet)
- [ ] `npm ci`
- [ ] `cf login -a https://api.cf.us10-001.hana.ondemand.com --sso -o 0b0ef6f5trial -s dev`
- [ ] `XSUAA_CF_API=https://api.cf.us10-001.hana.ondemand.com XSUAA_CF_ORG=0b0ef6f5trial XSUAA_CF_SPACE=dev npm run test:xsuaa`
- [ ] Put the result into the PR description (the "XSUAA trial" line).
- [ ] If anything is left behind: `tests/xsuaa/teardown.sh` with the same
      variables; check `cf services` in `dev` for `auth-providers-bearer-test`
      / `auth-providers-trust-test`.

Found while trying it on Windows (Git Bash) — the scripts are fine on macOS,
but two things to fix some day:
- Git Bash turns `-subj /CN=…` into a path (`C:/Program Files/Git/CN=…`) and
  openssl fails; `MSYS2_ARG_CONV_EXCL="/CN="` works around it.
- `setup.sh` generates the IdP certificate only when `idp.key` is missing; a
  failed openssl can leave `idp.key` without `idp.crt`, and every later run
  then fails in `trust.mjs` (ENOENT on `idp.crt`). Check for `idp.crt` too.

### 2. PR and merge

- [ ] Push `feat/auth-providers-5` (from Windows: PowerShell, YubiKey touch).
- [ ] Decide the order with PR #55 (goal + spec + plan, still open): merge
      #55 first and then the implementation PR, or close #55 and take
      everything in one PR (the branch already carries those documents).
- [ ] Open the PR into `master`. Description — see "PR description" below.
- [ ] Review → merge.

### 3. Release 5.0.0

- [ ] Tag `v5.0.0` on master → GitHub Actions builds and makes the release.
- [ ] `npm publish` (the owner publishes).

### 4. Next steps of the goal

- [ ] `@mcp-abap-adt/connection` 10.0.0 — takes `IAuthProvider` as it is
      (Basic / Certificate / SAML / Token credentials leave connection; they
      now live in auth-providers).
- [ ] `@mcp-abap-adt/auth-broker` 4.0.0 — `getProvider(destination)`,
      including SNC from `IConnectionConfig`'s `sncPartnerName`, `sncQop`,
      `sncLib`, `sncMyName`.
- [ ] mcp-abap-adt server; then delete goal, spec, plan and this file.

### 5. Housekeeping on the Windows machine

- [ ] Podman machine was switched to rootful for the stand (user systemd in
      WSL fails: `user@1000.service … Device or resource busy`). Back:
      `podman machine stop; podman machine set --rootful=false; podman machine start`.
- [ ] `.superpowers/sdd/2026-09-29-auth-providers-5/` (git-ignored SDD
      workspace: ledger, briefs, reviews) — delete after the merge.

## Deferred, not blocking

- T2: `rejected()` before any `authorize()` compares against
  `config.accessToken` (defensive fallback).
- T4: `saml2Utils.test.ts` describe title still says `resolveAssertionValidator`.
- T5: the presenter refusal test's `not.toMatch(/SECRET/)` cannot discriminate.
- T6: Basic header has no `?? ''` fallback (typed callers only).
- macOS SNC path (`libsapcrypto.dylib` in the app bundle) is not measured live.

## PR description

```markdown
## auth-providers 5.0.0 — every IAuthProvider on one contract (a migration, not an update)

Implements the approved spec `docs/superpowers/specs/2026-09-29-auth-providers-on-iauthprovider-design.md`.

### What changes
- Every provider implements `IAuthProvider` from `@mcp-abap-adt/interfaces-auth` 3.0.0:
  `prepare` / `establish` / `authorize` / `rejected`, each answering Ok or Oops `{ reason, hint? }`.
  The process takes any provider as it is — no check of what it got.
- `BaseTokenProvider` implements it beside `IRefreshableTokenProvider`; `onTokens` for persistence (best effort).
- One renewal: at most one refresh, then one login; never Ok on an unchanged credential; concurrent
  renewals share one flight; `getTokens()` waits for a renewal in flight; no provider-side retries.
- No exception crosses the contract; refusals come from fixed wording plus package-owned allowlists.
- No implicit defaults: constructors take every collaborator; static factories are the recipes —
  `inBrowser`, `fromTerminal`, `toConsole`, `fromFiles`, `forSecureLoginClient`.
- Basic / Certificate / SAML / Token credentials and `FileCertificateMaterialLoader` move in from
  `@mcp-abap-adt/connection` (`TokenAuthProvider.fixed` / `.from` only).
- `IDeviceCodePresenter` injected like the strategies; SAML trust settings moved to `SamlTrust` / the
  validator; `ShippedValidatorOptions.replayStore` required; manual strategies `timeoutMs` / `dispose()` /
  `read(prompt, signal)`.
- New: `SncLogonProvider` — passwordless RFC logon through an installed SNC product (SAP Secure Login
  Client). Finds the library (explicit, or `SNC_LIB_64` → `SNC_LIB` → registry → macOS bundle, by
  architecture); the product probe only names the product for the hint in `rejected`.

### Verification
- `npm test`: 43 suites / 599 tests pass (5 live suites skipped without their environment).
- Provider stand (UAA + Keycloak, `npm run test:stand`): 5 suites / 21 tests pass.
- XSUAA trial (`npm run test:xsuaa`): <result>
- Live SNC on an on-prem system (Windows, Secure Login Client 3.0.3), 2026-09-29:
  1. `forSecureLoginClient` → `prepare` / `establish` Ok; the registry's x64 `sapcrypto.dll` chosen
     although the machine-wide `SNC_LIB` names the installer's x86 copy.
  2. Those parameters into an RFC conversation: logon without a password; discovery, reads, LOCK/UNLOCK — 200.
  3. Client logged out, logon window closed → the RFC open fails `A2200019`; `rejected` answers
     "the SNC library has no credential to present (A2200019)". The SNC library starts the client on
     demand and it logs on (SSO or its window) — hence the probe no longer refuses in `prepare`.
- Whole-branch review: 5 Important findings fixed, re-review "ready to merge".

Needs `@mcp-abap-adt/connection` 10.0.0 on the consumer side.
```
