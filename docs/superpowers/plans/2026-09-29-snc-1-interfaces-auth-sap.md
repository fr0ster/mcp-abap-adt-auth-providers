# SNC logon — step 1: `interfaces-auth-sap` contract — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Release `@mcp-abap-adt/interfaces-auth-sap` 1.1.0 carrying every contract the later SNC steps need: `IRfcLogonCredential`, `'snc'` as an auth type, and the `snc*` settings on both `ISapConfig` and `IConnectionConfig`.

**Architecture:** Types only, additive, a minor. SNC and RFC are SAP's, so everything goes in `interfaces-auth-sap`. `IConnectionConfig` carries the settings because that is what the stores already hand the broker (`getConnectionConfig`); `ISapConfig` carries them for consumers that build a connection from config directly.

**Tech Stack:** TypeScript 5.9, npm workspaces, Biome, `tsc -b`; repo `fr0ster/mcp-abap-adt-interfaces`, package `packages/interfaces-auth-sap`.

**Spec:** `mcp-abap-adt-auth-providers/docs/superpowers/specs/2026-09-29-snc-logon-provider-design.md` (approved in auth-providers PR #55) — section "1. Contract".

## Global Constraints

- Types only: no function is exported. The contract packages export types and `const`s, never functions; a consumer narrows with its own structural check, as `connection` does for `IRenewableCredential` (`typeof c.renew === 'function'`). This refines the spec, which listed an `isRfcLogonCredential` export.
- Additive only: no existing field, member or union value changes or disappears.
- `SapAuthType` gains `'snc'`; `IConnectionConfig.authType` gains `'snc'`.
- New optional fields, same names on both configs: `sncPartnerName?: string`, `sncQop?: string`, `sncLib?: string`, `sncMyName?: string`.
- `sncQop` is a string: it goes into the RFC params unchanged, and every RFC param is a string.
- Version 1.1.0; change `package.json` version only as part of this plan's release task.
- `IRfcLogonCredential` must be placed in `interfaces-auth-sap` in `tools/package-map.json`, or `check:surface` fails.

## Review Focus

- A consumer that switches on `SapAuthType` exhaustively stops compiling when `'snc'` is added — expected for a new union member; the CHANGELOG must say so, since it is a minor.
- A store that round-trips `IConnectionConfig` through JSON must keep the `snc*` fields — nothing to do here, but the type test proves the fields are optional strings a JSON store preserves.
- `explainLogonFailure` is optional; a credential without it must still type-check as `IRfcLogonCredential`.

---

### Task 1: The contract, its type test, docs and release prep

**Files:**
- Create: `packages/interfaces-auth-sap/src/rfc/IRfcLogonCredential.ts`
- Create: `packages/interfaces-auth-sap/src/__typechecks__/sncTypes.ts`
- Modify: `packages/interfaces-auth-sap/src/sap/SapAuthType.ts`
- Modify: `packages/interfaces-auth-sap/src/sap/ISapConfig.ts`
- Modify: `packages/interfaces-auth-sap/src/auth/IConnectionConfig.ts`
- Modify: `packages/interfaces-auth-sap/src/index.ts`
- Modify: `tools/package-map.json`
- Modify: `packages/interfaces-auth-sap/CHANGELOG.md`, `packages/interfaces-auth-sap/README.md`, `packages/interfaces-auth-sap/package.json` (version), `package-lock.json`

**Interfaces:**
- Produces: `IRfcLogonCredential { rfcLogonParams(): Record<string, string>; explainLogonFailure?(error: unknown): string | undefined }`; `SapAuthType` including `'snc'`; `ISapConfig` and `IConnectionConfig` with `sncPartnerName?`, `sncQop?`, `sncLib?`, `sncMyName?`; `IConnectionConfig.authType` including `'snc'`.

- [ ] **Step 1: Branch from the default branch**

```bash
git fetch origin && git checkout -b feat/snc-logon-contract origin/master
npm ci
```

- [ ] **Step 2: Write the type test first**

`packages/interfaces-auth-sap/src/__typechecks__/sncTypes.ts`:

```ts
// Compile-only assertions. If these stop compiling, the types regressed.

import type { IConnectionConfig } from '../auth/IConnectionConfig';
import type { IRfcLogonCredential } from '../rfc/IRfcLogonCredential';
import type { ISapConfig } from '../sap/ISapConfig';
import type { SapAuthType } from '../sap/SapAuthType';

const _authType: SapAuthType = 'snc';
void _authType;

const _sap: ISapConfig = {
  url: 'http://h:8000',
  authType: 'snc',
  connectionType: 'rfc',
  sncPartnerName: 'p:CN=SID',
  sncQop: '9',
  sncLib: '/lib/sapcrypto.so',
  sncMyName: 'p:CN=USER',
};
void _sap;

// An SNC-only destination: no username, no password, no UAA fields.
const _conn: IConnectionConfig = {
  serviceUrl: 'http://h:8000',
  authType: 'snc',
  sapClient: '100',
  sncPartnerName: 'p:CN=SID',
  sncQop: '9',
};
void _conn;

// explainLogonFailure is optional.
const _minimal: IRfcLogonCredential = {
  rfcLogonParams: () => ({ snc_mode: '1' }),
};
void _minimal;

const _full: IRfcLogonCredential = {
  rfcLogonParams: () => ({ snc_mode: '1', snc_partnername: 'p:CN=SID' }),
  explainLogonFailure: (e: unknown) =>
    String(e).includes('A2200019') ? 'log on' : undefined,
};
void _full;
```

- [ ] **Step 3: Run the type check to see it fail**

Run: `npm run test:check --workspace packages/interfaces-auth-sap`
Expected: FAIL — `Cannot find module '../rfc/IRfcLogonCredential'`, `'snc'` not assignable to `SapAuthType`, unknown property `sncPartnerName`.

- [ ] **Step 4: Add the contract**

`packages/interfaces-auth-sap/src/rfc/IRfcLogonCredential.ts`:

```ts
/**
 * A credential that logs an RFC conversation on instead of `user`/`passwd`.
 *
 * SNC is the reason it exists: the SNC library of an installed product (the
 * SAP Secure Login Client, a Kerberos GSS library) authenticates during the
 * RFC logon itself, so there is no header, no cookie and no TLS material —
 * nothing `IAuthProvider` can carry. What replaces the password is a set of
 * logon parameters, and that is all this contract hands over.
 *
 * Separate from `IAuthProvider`, as `IRenewableCredential` is: most
 * credentials have no RFC logon. A credential that has one implements both,
 * and the connector takes it on the credential axis like any other.
 *
 * No type guard is exported — this package exports no functions. Narrow with
 * `typeof (c as Partial<IRfcLogonCredential>).rfcLogonParams === 'function'`.
 */
export interface IRfcLogonCredential {
  /**
   * RFC logon parameters replacing `user` and `passwd` — for SNC,
   * `snc_mode`, `snc_partnername`, `snc_qop`, `snc_lib`, optionally
   * `snc_myname`. Every value a string, as the RFC SDK takes them.
   *
   * Read when a conversation opens, and a connection opens more than one, so
   * every conversation gets them — not only the first.
   */
  rfcLogonParams(): Record<string, string>;
  /**
   * A message naming the cause and the fix, for an RFC open that failed — or
   * `undefined` when this credential does not recognise the failure, in which
   * case the caller reports the error as it is.
   */
  explainLogonFailure?(error: unknown): string | undefined;
}
```

`packages/interfaces-auth-sap/src/sap/SapAuthType.ts`:

```ts
export type SapAuthType =
  | 'basic'
  | 'jwt'
  | 'saml'
  | 'certificate'
  | 'kerberos'
  | 'snc';

export type SapConnectionType = 'http' | 'rfc';
```

In `packages/interfaces-auth-sap/src/sap/ISapConfig.ts`, after the Kerberos block and before `uaaUrl`:

```ts
  // SNC over RFC — the SNC library of an installed product authenticates the
  // RFC logon; no username or password. See IRfcLogonCredential.
  sncPartnerName?: string; // the system's SNC name, e.g. "p:CN=SID, O=ACME"
  sncQop?: string; // quality of protection: "1" auth, "2" integrity, "3" privacy, "8" default, "9" maximum available
  sncLib?: string; // path to the SNC (GSS) library; discovered when absent
  sncMyName?: string; // the user's SNC name; taken from the credential when absent
```

`packages/interfaces-auth-sap/src/auth/IConnectionConfig.ts` — change the `authType` line and add the fields (keep the file's existing comments):

```ts
  authType?: 'basic' | 'jwt' | 'saml' | 'snc';
```

and after `sessionCookies?: string;`:

```ts
  /**
   * SNC settings for a destination whose `authType` is `'snc'` — how to reach
   * the system, not a secret. Such a destination needs no authorization
   * config, no username and no password.
   */
  sncPartnerName?: string;
  sncQop?: string;
  sncLib?: string;
  sncMyName?: string;
```

In `packages/interfaces-auth-sap/src/index.ts`, beside the other `auth` exports:

```ts
export type { IRfcLogonCredential } from './rfc/IRfcLogonCredential';
```

In `tools/package-map.json`, add (keep the file's key order — alphabetical if it is):

```json
  "IRfcLogonCredential": "interfaces-auth-sap",
```

- [ ] **Step 5: Run the checks**

Run: `npm run build && npm run test:check && npm run check:surface && npm run check:graph`
Expected: PASS, no Biome errors.

- [ ] **Step 6: Prove the type test is load-bearing**

Temporarily remove `| 'snc'` from `SapAuthType`, run `npm run test:check --workspace packages/interfaces-auth-sap`, expect FAIL at `_authType`; restore. Do the same for `sncPartnerName` in `IConnectionConfig` (expect FAIL at `_conn`); restore.

- [ ] **Step 7: CHANGELOG and README**

`packages/interfaces-auth-sap/CHANGELOG.md`, under `## [Unreleased]`:

```markdown
### Added

- **`IRfcLogonCredential`** — a credential that logs an RFC conversation on
  with parameters instead of `user`/`passwd` (`rfcLogonParams()`), with an
  optional `explainLogonFailure()`. For SNC: the SNC library of an installed
  product authenticates the logon. Types only; narrow with
  `typeof c.rfcLogonParams === 'function'`.
- **`'snc'`** in `SapAuthType` and in `IConnectionConfig.authType`. A consumer
  that switches exhaustively on either union gets a new case to handle.
- **`sncPartnerName`, `sncQop`, `sncLib`, `sncMyName`** (all optional strings)
  on `ISapConfig` and `IConnectionConfig`. On `IConnectionConfig` because
  that is what the stores hand the broker: an SNC-only destination needs no
  authorization config, no username and no password.
```

`packages/interfaces-auth-sap/README.md`: add `IRfcLogonCredential` to the symbol list/table in the same form as `ICertificateMaterialLoader`, with the one-line description from the CHANGELOG.

- [ ] **Step 8: Commit**

```bash
git add packages/interfaces-auth-sap tools/package-map.json
git commit -m "feat(auth-sap): IRfcLogonCredential, 'snc' auth type and snc* settings"
```

### Task 2: Release 1.1.0

**Files:**
- Modify: `packages/interfaces-auth-sap/package.json`, `packages/interfaces-auth-sap/CHANGELOG.md`, `package-lock.json`

**Interfaces:**
- Consumes: Task 1.
- Produces: `@mcp-abap-adt/interfaces-auth-sap@1.1.0` on npm — the version every later step depends on (`^1.1.0`).

- [ ] **Step 1: Version** — set `"version": "1.1.0"` in `packages/interfaces-auth-sap/package.json`; turn `## [Unreleased]` into `## [1.1.0] - <date>` and add a fresh empty `## [Unreleased]` above it; run `npm install --package-lock-only`.
- [ ] **Step 2: Full check** — `npm run check`. Expected: PASS (it includes `check:packed` and `check:publish`).
- [ ] **Step 3: Commit** — `git commit -am "chore(release): interfaces-auth-sap 1.1.0 — SNC logon contract"`.
- [ ] **Step 4: PR** — push, open the PR, merge after review. Publishing follows this repo's release flow (`npm run release:publish` publishes the changed packages); do not publish from the feature branch.
