# auth-providers 5.0.0 — every IAuthProvider on one contract — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Release `@mcp-abap-adt/auth-providers` 5.0.0, where every provider implements `IAuthProvider` from `@mcp-abap-adt/interfaces-auth` 3.0.0, no provider builds a collaborator of its own, and named static factories assemble the common combinations.

**Architecture:** `BaseTokenProvider` implements `IAuthProvider` beside `IRefreshableTokenProvider`, so every token provider is an `IAuthProvider` with no wrapper. Constructors take every collaborator (strategy, SAML validator, device-code presenter, SNC locator/probes); static factories (`inBrowser`, `fromTerminal`, `toConsole`, `fromFiles`, `forSecureLoginClient`) are the recipes. One module turns thrown values into refusals built from fixed wording and package-owned allowlists only; every contract method runs inside `safely(…)`; no provider retries.

**Tech Stack:** TypeScript (CommonJS, imports without `.js`), Jest via `npm test -- <path>` (never `npx jest`), Biome; `node:child_process`, `node:fs/promises`, `node:path`, `node:readline` only.

**Spec (approved):** `docs/superpowers/specs/2026-09-29-auth-providers-on-iauthprovider-design.md`. Goal and path: `docs/superpowers/2026-09-29-auth-providers-5-goal.md`.

## Global Constraints

- Dependencies: `@mcp-abap-adt/interfaces-auth` `^3.0.0`, `@mcp-abap-adt/interfaces-auth-sap` `^1.1.0`. No new runtime dependency. `engines` stays `"^22 || ^24 || ^26"`.
- **Rule 1 — no exception crosses the contract.** Every body of `prepare`, `establish`, `authorize`, `rejected` runs inside `safely(what, work)`: own work, collaborators and targets (`header`, `cookies`, `logonParameters`, `tlsMaterial`) that throw become Oops. Constructors may throw `ValidationError` for bad configuration.
- **Rule 2 — a refusal never carries an error's message.** A refusal is fixed wording per error class plus metadata only from package-owned allowlists: field names in `KNOWN_CONFIG_FIELDS`; `AssertionCheck` values; system codes `ENOENT, EACCES, EPERM, ECONNREFUSED, ECONNRESET, ETIMEDOUT, ENOTFOUND, EAI_AGAIN, EPIPE`; RFC keys `RFC_COMMUNICATION_FAILURE, RFC_LOGON_FAILURE, RFC_ABAP_RUNTIME_FAILURE, RFC_ABAP_MESSAGE, RFC_EXTERNAL_FAILURE, RFC_INVALID_PARAMETER, RFC_CLOSED, RFC_TIMEOUT`; class labels by `instanceof` against the package's own constructors, else `unknown error`. A `name` property is never read. Messages go to the logger; `onTokens` failures log the class label only.
- **Rule 3 — nothing to add is Ok.**
- **Rule 4 — a target's Oops is the provider's to judge.** SNC and Certificate return it; Basic ignores it for logon parameters.
- **Rule 5 — one renewal, no step twice.** `rejected()` is at most one refresh, then (refresh refused or no refresh token) one login through the injected strategy. A renewal yielding the credential last presented is Oops `"the renewal returned the credential that was refused"`. No provider retries.
- **Rule 6 — no implicit defaults.** No `?? someDefault()` for a collaborator anywhere in a provider. Static factories are the recipes.
- **Persistence is best effort:** `onTokens` is awaited; its failure is logged and does not fail authentication.
- **`kind`:** token providers → `getAuthType()`; `'basic'`, `'certificate'`, `'saml'`, `'token'`, `'snc'`.
- **`TokenAuthProvider`:** `fixed(token)` and `from(refresher)` only.
- **`snc_qop`:** default `'9'`; allowed exactly `'1'`, `'2'`, `'3'`, `'8'`, `'9'`.
- **Universal Mach-O:** `FAT_MAGIC` `0xcafebabe` (20-byte records) and `FAT_MAGIC_64` `0xcafebabf` (32-byte records).
- Nothing writes to `process.stdout`.
- Version **5.0.0**.

## Review Focus

- A secret in **any** metadata slot — `missingFields`, `name`, `code`, `key`, `check` — or in a message, a thrown string, or foreign callback text wrapped in `BrowserAuthError`, must not reach a refusal — Tasks 1, 11, 12.
- A target that throws must give Oops, not a rejected promise — Tasks 2, 6, 11, 12.
- Refresh refused → exactly one login → Ok; login refused → Oops with no second login or refresh — Task 2.
- A manual strategy whose reader never answers must settle with `BrowserAuthError` at `timeoutMs` and close its `readline`; `dispose()` does the same at once — Task 4.
- Constructing a provider without its strategy / validator / presenter / locator / probes must not compile — Tasks 3, 5, 11.

## File Structure

| File | Responsibility |
|---|---|
| `src/auth/refusal.ts` | `OK`, `oops`, `refusalFrom(error, what)`, `safely(what, work)`, the allowlists |
| `src/providers/BaseTokenProvider.ts` | + `IAuthProvider`, `TokenProviderHooks`/`onTokens`, `applyToken`, one renewal |
| `src/providers/*Provider.ts`, `src/providers/saml2Utils.ts` | required collaborators, static factories |
| `src/validation/assertionValidator.ts` | `replayStore` required in `ShippedValidatorOptions` |
| `src/strategies/manualStrategies.ts` | `timeoutMs`, `dispose()`, cancellable terminal read |
| `src/deviceCode/DeviceCodePresenter.ts` | `IDeviceCodePresenter`, `DeviceCodePrompt`, `consoleDeviceCodePresenter` |
| `src/credentials/*.ts` | Basic, SAML, Token, Certificate, `FileCertificateMaterialLoader` |
| `src/snc/*.ts` | architecture reader, machine seam, locator, probe, refusal, `SncLogonProvider` |
| `src/__tests__/helpers/targets.ts`, `src/__tests__/snc/fakeSystem.ts` | test doubles |

---

### Task 1: Dependencies, test targets and the refusal module

**Files:**
- Modify: `package.json`, `package-lock.json`
- Create: `src/auth/refusal.ts`, `src/__tests__/helpers/targets.ts`
- Test: `src/__tests__/auth/refusal.test.ts`

**Interfaces:**
- Produces: `OK: AuthOutcome`; `oops(reason: string, hint?: string): AuthOutcome`; `refusalFrom(error: unknown, what: string): AuthOutcome`; `safely(what: string, work: () => AuthOutcome | Promise<AuthOutcome>): Promise<AuthOutcome>`; `KNOWN_CONFIG_FIELDS: ReadonlySet<string>`; `KNOWN_RFC_KEYS: ReadonlySet<string>`; `ownLabel(error: unknown): string`; test helper `recordingTargets(options?: { acceptsLogonParameters?: boolean; acceptsTls?: boolean; throws?: boolean })` → `{ logonTarget; requestTarget; logon: { tls: ICertificateMaterial[]; params: Record<string, string>[] }; request: { headers: Record<string, string>; cookies: string[] } }`.

- [ ] **Step 1: Branch and dependencies**

```bash
git fetch origin && git checkout -b feat/auth-providers-5 origin/master
npm install @mcp-abap-adt/interfaces-auth@^3.0.0 @mcp-abap-adt/interfaces-auth-sap@^1.1.0
npm run test:check
```

Expected: both ranges in `package.json`; `test:check` PASS.

- [ ] **Step 2: Test helper** — `src/__tests__/helpers/targets.ts`:

```ts
import type {
  AuthOutcome,
  ICertificateMaterial,
  ILogonTarget,
  IRequestTarget,
} from '@mcp-abap-adt/interfaces-auth';

export interface RecordingTargetsOptions {
  /** false: the wire has no parameter logon (HTTP). */
  acceptsLogonParameters?: boolean;
  /** false: the wire has no TLS (RFC). */
  acceptsTls?: boolean;
  /** true: every target member throws — a broken wire. */
  throws?: boolean;
}

export function recordingTargets(options: RecordingTargetsOptions = {}) {
  const logon = { tls: [] as ICertificateMaterial[], params: [] as Record<string, string>[] };
  const request = { headers: {} as Record<string, string>, cookies: [] as string[] };
  const broken = () => {
    if (options.throws) throw new Error('target exploded: SECRET-IN-TARGET');
  };
  const refuse = (what: string): AuthOutcome => ({
    ok: false,
    refusal: { reason: `this wire does not take ${what}` },
  });
  const logonTarget: ILogonTarget = {
    tlsMaterial(material) {
      broken();
      if (options.acceptsTls === false) return refuse('TLS material');
      logon.tls.push(material);
      return { ok: true };
    },
    logonParameters(parameters) {
      broken();
      if (options.acceptsLogonParameters === false) return refuse('logon parameters');
      logon.params.push({ ...parameters });
      return { ok: true };
    },
  };
  const requestTarget: IRequestTarget = {
    header(name, value) {
      broken();
      request.headers[name] = value;
    },
    cookies(value) {
      broken();
      request.cookies.push(value);
    },
  };
  return { logonTarget, requestTarget, logon, request };
}
```

- [ ] **Step 3: Write the failing refusal test** — `src/__tests__/auth/refusal.test.ts`:

```ts
import { describe, expect, it } from '@jest/globals';
import { OK, oops, refusalFrom, safely } from '../../auth/refusal';
import { AssertionValidationError } from '../../errors/AssertionValidationError';
import {
  BrowserAuthError,
  RefreshError,
  ServiceKeyError,
  SessionDataError,
  TokenProviderError,
  ValidationError,
} from '../../errors/TokenProviderErrors';

const text = (x: unknown) => JSON.stringify(x);

describe('refusal', () => {
  it('OK and oops build the two outcomes', () => {
    expect(OK).toEqual({ ok: true });
    expect(oops('r', 'h')).toEqual({ ok: false, refusal: { reason: 'r', hint: 'h' } });
    expect(oops('r')).toEqual({ ok: false, refusal: { reason: 'r' } });
  });

  it.each([
    [new BrowserAuthError('SECRET-MSG'), 'the interactive login did not complete', "complete the login within the strategy's time"],
    [new RefreshError('SECRET-MSG'), 'the refresh token was refused', 'log in again'],
    [new ValidationError('SECRET-MSG', ['clientId']), 'the provider configuration is incomplete or invalid: clientId', 'check the provider configuration'],
    [new ServiceKeyError('SECRET-MSG', ['uaaUrl']), 'the service key or session data is incomplete: uaaUrl', 'check the service key or session data'],
    [new SessionDataError('SECRET-MSG', ['refreshToken']), 'the service key or session data is incomplete: refreshToken', 'check the service key or session data'],
  ])('%p → fixed wording, never its message', (error, reason, hint) => {
    expect(refusalFrom(error, 'it')).toEqual({ ok: false, refusal: { reason, hint } });
  });

  it('an assertion refusal names its check only when it is an AssertionCheck', () => {
    expect(refusalFrom(new AssertionValidationError('issuer', 'SECRET'), 'it'))
      .toEqual({ ok: false, refusal: { reason: 'the SAML assertion was refused (issuer)' } });
    const forged = Object.assign(new AssertionValidationError('issuer', 'x'), { check: 'SECRET_CHECK' });
    expect(text(refusalFrom(forged, 'it'))).not.toMatch(/SECRET/);
  });

  it('foreign callback text wrapped in BrowserAuthError stays out', () => {
    const wrapped = new BrowserAuthError('access_denied: SECRET-IDP-DESCRIPTION (https://idp/SECRET-URI)');
    expect(text(refusalFrom(wrapped, 'it'))).not.toMatch(/SECRET/);
  });

  it('a field name not in KNOWN_CONFIG_FIELDS is dropped', () => {
    expect(refusalFrom(new ValidationError('x', ['clientId', 'SECRET-FIELD']), 'it')).toEqual({
      ok: false,
      refusal: { reason: 'the provider configuration is incomplete or invalid: clientId', hint: 'check the provider configuration' },
    });
    expect(refusalFrom(new ValidationError('x', ['SECRET-FIELD']), 'it')).toMatchObject({
      refusal: { reason: 'the provider configuration is incomplete or invalid' },
    });
  });

  it('another own error: its class label, no message', () => {
    expect(refusalFrom(new TokenProviderError('SECRET', 'CODE'), 'x token request'))
      .toEqual({ ok: false, refusal: { reason: 'x token request failed (TokenProviderError)' } });
  });

  it('a foreign error: "unknown error", plus an allowlisted code only', () => {
    const axios = Object.assign(new Error('Basic U0VDUkVU'), { name: 'AxiosError', code: 'ECONNREFUSED', response: { data: 'SECRET' } });
    expect(refusalFrom(axios, 'the token endpoint'))
      .toEqual({ ok: false, refusal: { reason: 'the token endpoint failed (unknown error, ECONNREFUSED)' } });
    const forged = Object.assign(new Error('x'), { name: 'SECRETError', code: 'ESECRET' });
    expect(refusalFrom(forged, 'it')).toEqual({ ok: false, refusal: { reason: 'it failed (unknown error)' } });
  });

  it('a thrown string or object lends nothing', () => {
    expect(refusalFrom('SECRET-STRING', 'it')).toEqual({ ok: false, refusal: { reason: 'it failed (unknown error)' } });
    expect(text(refusalFrom({ message: 'SECRET', key: 'SECRET_KEY', code: 'ENOENT' }, 'it')))
      .toBe(text({ ok: false, refusal: { reason: 'it failed (unknown error, ENOENT)' } }));
  });

  it('safely: sync throw, async rejection and a returned outcome', async () => {
    await expect(safely('it', () => { throw new Error('SECRET'); })).resolves.toEqual({ ok: false, refusal: { reason: 'it failed (unknown error)' } });
    await expect(safely('it', async () => { throw new RefreshError('SECRET'); })).resolves.toMatchObject({ ok: false, refusal: { reason: 'the refresh token was refused' } });
    await expect(safely('it', () => OK)).resolves.toEqual({ ok: true });
  });
});
```

- [ ] **Step 4: Run to see it fail** — `npm test -- src/__tests__/auth/refusal.test.ts` → FAIL, module not found.

- [ ] **Step 5: Implement** — `src/auth/refusal.ts`:

```ts
/**
 * How a provider in this package answers Oops — the one place thrown values
 * become refusals (spec rule 2).
 *
 * A refusal never carries an error's message: the class of an error says
 * nothing about what its message holds (BrowserAuthError is built from an IdP
 * callback's text; a consumer can construct any exported class). It is fixed
 * wording chosen per class, plus metadata only when the value is on an
 * allowlist this package owns. A `name` property is never read.
 */

import type { AuthOutcome } from '@mcp-abap-adt/interfaces-auth';
import {
  type AssertionCheck,
  AssertionValidationError,
} from '../errors/AssertionValidationError';
import {
  BrowserAuthError,
  RefreshError,
  ServiceKeyError,
  SessionDataError,
  TokenProviderError,
  ValidationError,
} from '../errors/TokenProviderErrors';

export const OK: AuthOutcome = { ok: true };

export function oops(reason: string, hint?: string): AuthOutcome {
  return hint === undefined
    ? { ok: false, refusal: { reason } }
    : { ok: false, refusal: { reason, hint } };
}

/** Every config property name this package's providers declare. */
export const KNOWN_CONFIG_FIELDS: ReadonlySet<string> = new Set([
  'accessToken', 'acsUrl', 'actorToken', 'actorTokenType', 'assertionValidator',
  'audience', 'authnRequestId', 'authorization', 'authorizationEndpoint',
  'authorizationUrl', 'certKeyPath', 'certPassphrase', 'certPath', 'certPfxPath',
  'clientId', 'clientSecret', 'clockSkewMs', 'cookieProvider',
  'deviceAuthorizationEndpoint', 'idpCertificates', 'idpEntityId', 'idpInitiated',
  'idpSsoUrl', 'issuerUrl', 'locator', 'logger', 'myName', 'onTokens', 'partnerName',
  'password', 'presenter', 'probes', 'qop', 'refreshToken', 'relayState', 'replayStore',
  'scope', 'scopes', 'sncLib', 'spEntityId', 'subjectToken', 'subjectTokenType',
  'tokenEndpoint', 'tokenUrl', 'uaaUrl', 'username',
]);

const ASSERTION_CHECKS: ReadonlySet<AssertionCheck> = new Set<AssertionCheck>([
  'document', 'duplicateId', 'signature', 'signedNode', 'status', 'assertionId',
  'issuer', 'conditions', 'notBefore', 'notOnOrAfter', 'audience',
  'bearerConfirmation', 'destination', 'replay',
]);

const KNOWN_SYSTEM_CODES: ReadonlySet<string> = new Set([
  'ENOENT', 'EACCES', 'EPERM', 'ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT',
  'ENOTFOUND', 'EAI_AGAIN', 'EPIPE',
]);

export const KNOWN_RFC_KEYS: ReadonlySet<string> = new Set([
  'RFC_COMMUNICATION_FAILURE', 'RFC_LOGON_FAILURE', 'RFC_ABAP_RUNTIME_FAILURE',
  'RFC_ABAP_MESSAGE', 'RFC_EXTERNAL_FAILURE', 'RFC_INVALID_PARAMETER',
  'RFC_CLOSED', 'RFC_TIMEOUT',
]);

/** Most specific first. */
const OWN_CLASSES: ReadonlyArray<readonly [abstract new (...a: never[]) => unknown, string]> = [
  [AssertionValidationError, 'AssertionValidationError'],
  [BrowserAuthError, 'BrowserAuthError'],
  [RefreshError, 'RefreshError'],
  [ValidationError, 'ValidationError'],
  [ServiceKeyError, 'ServiceKeyError'],
  [SessionDataError, 'SessionDataError'],
  [TokenProviderError, 'TokenProviderError'],
];

/** The label of one of this package's classes, by instanceof; else "unknown error". */
export function ownLabel(error: unknown): string {
  for (const [ctor, label] of OWN_CLASSES) {
    if (error instanceof ctor) return label;
  }
  return 'unknown error';
}

function knownFields(missing: unknown): string {
  if (!Array.isArray(missing)) return '';
  const names = missing.filter((m): m is string => typeof m === 'string' && KNOWN_CONFIG_FIELDS.has(m));
  return names.length ? `: ${names.join(', ')}` : '';
}

function systemCode(error: unknown): string {
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === 'string' && KNOWN_SYSTEM_CODES.has(code) ? `, ${code}` : '';
}

export function refusalFrom(error: unknown, what: string): AuthOutcome {
  if (error instanceof AssertionValidationError) {
    const check = ASSERTION_CHECKS.has(error.check) ? ` (${error.check})` : '';
    return oops(`the SAML assertion was refused${check}`);
  }
  if (error instanceof BrowserAuthError) {
    return oops('the interactive login did not complete', "complete the login within the strategy's time");
  }
  if (error instanceof RefreshError) {
    return oops('the refresh token was refused', 'log in again');
  }
  if (error instanceof ValidationError) {
    return oops(`the provider configuration is incomplete or invalid${knownFields(error.missingFields)}`, 'check the provider configuration');
  }
  if (error instanceof ServiceKeyError || error instanceof SessionDataError) {
    return oops(`the service key or session data is incomplete${knownFields(error.missingFields)}`, 'check the service key or session data');
  }
  if (error instanceof TokenProviderError) {
    return oops(`${what} failed (${ownLabel(error)})`);
  }
  return oops(`${what} failed (unknown error${systemCode(error)})`);
}

/** The boundary every contract method runs inside (spec rule 1). */
export async function safely(
  what: string,
  work: () => AuthOutcome | Promise<AuthOutcome>,
): Promise<AuthOutcome> {
  try {
    return await work();
  } catch (error) {
    return refusalFrom(error, what);
  }
}
```

- [ ] **Step 6: Run to see it pass** — same command → PASS.

- [ ] **Step 7: Load-bearing** — make `knownFields` return every string (drop the `has` filter) → "a field name not in KNOWN_CONFIG_FIELDS is dropped" FAILS. Revert.

- [ ] **Step 8: Commit**

```bash
git add package.json package-lock.json src/auth/refusal.ts src/__tests__/helpers/targets.ts src/__tests__/auth/refusal.test.ts
git commit -m "feat: refusals from fixed wording and package-owned allowlists; interfaces-auth ^3.0.0"
```

### Task 2: Token providers are `IAuthProvider`s

**Files:**
- Modify: `src/providers/BaseTokenProvider.ts`, `src/providers/Saml2PureProvider.ts`, and the other eight providers' config interfaces and constructors (`AuthorizationCodeProvider`, `ClientCredentialsProvider`, `OidcBrowserProvider`, `OidcDeviceFlowProvider`, `OidcPasswordProvider`, `OidcTokenExchangeProvider`, `Saml2BearerProvider`, `UaaPasscodeProvider`); `src/providers/index.ts`
- Test: `src/__tests__/providers/tokenProviderContract.test.ts`

**Interfaces:**
- Consumes: `OK`, `oops`, `safely` (Task 1); `recordingTargets` (Task 1).
- Produces: `interface TokenProviderHooks { onTokens?: (result: ITokenResult) => Promise<void> }` (exported); `BaseTokenProvider implements IRefreshableTokenProvider, IAuthProvider` with `get kind(): string`, `prepare()`, `establish()`, `authorize()`, `rejected()`, and `protected applyToken(request: IRequestTarget, result: ITokenResult): void`.

- [ ] **Step 1: Write the failing test**

`src/__tests__/providers/tokenProviderContract.test.ts`:

```ts
import { describe, expect, it, jest } from '@jest/globals';
import type { ITokenResult, OAuth2GrantType } from '@mcp-abap-adt/interfaces-auth';
import { BrowserAuthError, RefreshError } from '../../errors/TokenProviderErrors';
import {
  BaseTokenProvider,
  type TokenProviderHooks,
} from '../../providers/BaseTokenProvider';
import { Saml2PureProvider } from '../../providers/Saml2PureProvider';
import { recordingTargets } from '../helpers/targets';

const inAnHour = () => Date.now() + 3600_000;
const result = (token: string, refresh?: string): ITokenResult => ({
  authorizationToken: token,
  refreshToken: refresh,
  authType: 'client_credentials',
  tokenType: 'opaque',
  expiresAt: inAnHour(),
});

class TestProvider extends BaseTokenProvider {
  login = jest.fn(async () => result('T1', 'R1'));
  refresh = jest.fn(async () => result('T2', 'R2'));
  constructor(hooks: TokenProviderHooks = {}) {
    super(hooks);
  }
  protected performLogin() { return this.login(); }
  protected performRefresh() { return this.refresh(); }
  protected getAuthType(): OAuth2GrantType { return 'client_credentials'; }
  expire() { this.expiresAt = Date.now() - 1; }
}
const refused = { at: 'request' as const, status: 401, error: {} };

describe('BaseTokenProvider as IAuthProvider', () => {
  it('kind is the grant type', () => {
    expect(new TestProvider().kind).toBe('client_credentials');
  });

  it('prepare logs in and answers Ok', async () => {
    const p = new TestProvider();
    await expect(p.prepare()).resolves.toEqual({ ok: true });
    expect(p.login).toHaveBeenCalledTimes(1);
  });

  it('establish writes nothing and answers Ok', async () => {
    const t = recordingTargets();
    await expect(new TestProvider().establish(t.logonTarget)).resolves.toEqual({ ok: true });
    expect(t.logon).toEqual({ tls: [], params: [] });
  });

  it('authorize writes the bearer header', async () => {
    const t = recordingTargets();
    await expect(new TestProvider().authorize(t.requestTarget)).resolves.toEqual({ ok: true });
    expect(t.request.headers).toEqual({ Authorization: 'Bearer T1' });
  });

  it('authorize renews an expired token in that call', async () => {
    const p = new TestProvider();
    await p.prepare();
    p.expire();
    const t = recordingTargets();
    await p.authorize(t.requestTarget);
    expect(t.request.headers.Authorization).toBe('Bearer T2');
    expect(p.refresh).toHaveBeenCalledTimes(1);
  });

  it('a throwing target is an Oops, not a rejected promise', async () => {
    const p = new TestProvider();
    const outcome = await p.authorize(recordingTargets({ throws: true }).requestTarget);
    expect(outcome).toMatchObject({ ok: false });
    expect(JSON.stringify(outcome)).not.toMatch(/SECRET-IN-TARGET/);
  });

  it('rejected refreshes once and answers Ok when the token changed', async () => {
    const p = new TestProvider();
    await p.authorize(recordingTargets().requestTarget); // presents T1
    await expect(p.rejected(refused)).resolves.toEqual({ ok: true });
    expect(p.refresh).toHaveBeenCalledTimes(1);
  });

  it('rejected is Oops when the renewal returns the token that was refused', async () => {
    const p = new TestProvider();
    p.refresh.mockResolvedValue(result('T1', 'R2'));
    await p.authorize(recordingTargets().requestTarget); // presents T1
    await expect(p.rejected(refused)).resolves.toMatchObject({
      ok: false,
      refusal: { reason: 'the renewal returned the credential that was refused' },
    });
  });

  it('refresh refused → exactly one login → Ok', async () => {
    const p = new TestProvider();
    p.login.mockResolvedValueOnce(result('T1', 'R1')).mockResolvedValueOnce(result('T3', 'R3'));
    p.refresh.mockRejectedValue(new RefreshError('refused'));
    await p.authorize(recordingTargets().requestTarget); // login #1, presents T1
    await expect(p.rejected(refused)).resolves.toEqual({ ok: true });
    expect(p.refresh).toHaveBeenCalledTimes(1);
    expect(p.login).toHaveBeenCalledTimes(2);
  });

  it('login refused → Oops, no second refresh or login', async () => {
    const p = new TestProvider();
    await p.authorize(recordingTargets().requestTarget); // login #1, presents T1
    p.refresh.mockRejectedValue(new RefreshError('refused'));
    p.login.mockRejectedValue(new BrowserAuthError('SECRET-IDP-TEXT'));
    const outcome = await p.rejected(refused);
    expect(outcome).toMatchObject({ ok: false, refusal: { reason: 'the interactive login did not complete' } });
    expect(JSON.stringify(outcome)).not.toMatch(/SECRET/);
    expect(p.refresh).toHaveBeenCalledTimes(1);
    expect(p.login).toHaveBeenCalledTimes(2);
  });

  it('a failure is an Oops, never a throw, and nothing is retried', async () => {
    const p = new TestProvider();
    p.login.mockRejectedValue(new RefreshError('refused'));
    await expect(p.prepare()).resolves.toMatchObject({ ok: false });
    expect(p.login).toHaveBeenCalledTimes(1);
  });

  it('a foreign error from the login keeps its secret out of the refusal', async () => {
    const p = new TestProvider();
    p.login.mockRejectedValue(new Error('invalid_grant for SECRET-CLIENT-SECRET'));
    const outcome = await p.prepare();
    expect(outcome).toEqual({ ok: false, refusal: { reason: 'client_credentials token request failed (unknown error)' } });
  });

  it('onTokens after a login and after a refresh, never on a cache hit', async () => {
    const onTokens = jest.fn(async (_: ITokenResult) => {});
    const p = new TestProvider({ onTokens });
    await p.prepare();
    await p.authorize(recordingTargets().requestTarget); // cache hit
    await p.rejected(refused);
    expect(onTokens.mock.calls.map(([r]) => r.authorizationToken)).toEqual(['T1', 'T2']);
  });

  it('a failing onTokens does not fail authentication and logs no message', async () => {
    const warn = jest.fn();
    const p = new TestProvider({ onTokens: async () => { throw new Error('store down: SECRET-T1'); } });
    (p as unknown as { logger: unknown }).logger = { warn, debug: jest.fn(), info: jest.fn(), error: jest.fn() };
    await expect(p.prepare()).resolves.toEqual({ ok: true });
    expect(JSON.stringify(warn.mock.calls)).not.toMatch(/SECRET/);
  });

  it('Saml2PureProvider writes cookies, not a header', () => {
    const p = Object.create(Saml2PureProvider.prototype) as Saml2PureProvider;
    const t = recordingTargets();
    (p as unknown as { applyToken: (r: unknown, x: ITokenResult) => void }).applyToken(
      t.requestTarget,
      result('SAP_SESSIONID=x'),
    );
    expect(t.request.cookies).toEqual(['SAP_SESSIONID=x']);
    expect(t.request.headers).toEqual({});
  });
});
```

- [ ] **Step 2: Run to see it fail**

Run: `npm test -- src/__tests__/providers/tokenProviderContract.test.ts`
Expected: FAIL — `TokenProviderHooks` not exported / `prepare` is not a function.

- [ ] **Step 3: Implement in `BaseTokenProvider`**

Imports at the top become:

```ts
import type {
  AuthOutcome,
  IAuthProvider,
  IAuthRejection,
  ILogonTarget,
  IRefreshableTokenProvider,
  IRequestTarget,
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { OK, oops, ownLabel, safely } from '../auth/refusal';

/** What every token provider's config may carry beside its own fields. */
export interface TokenProviderHooks {
  /**
   * Called after every NEW token — a login or a refresh, never a cache hit —
   * and awaited before the provider answers. The broker persists through it.
   * Best effort: a failure is logged by class name and does not fail the
   * authentication.
   */
  onTokens?: (result: ITokenResult) => Promise<void>;
}
```

Class header and constructor:

```ts
export abstract class BaseTokenProvider
  implements IRefreshableTokenProvider, IAuthProvider
{
  protected authorizationToken?: string;
  protected refreshToken?: string;
  protected expiresAt?: number;
  protected tokenType?: 'jwt' | 'saml' | 'opaque';
  protected logger?: ILogger;
  private readonly onTokens?: TokenProviderHooks['onTokens'];
  /** The token last put on a request, so rejected() can tell a renewal from a repeat. */
  private presented?: string;

  constructor(hooks: TokenProviderHooks = {}) {
    this.onTokens = hooks.onTokens;
  }
```

In `refreshTokens()`, after each of the two `this.updateTokens(result);` lines add `await this.obtained(result);`. Add at the end of the class:

```ts
  private async obtained(result: ITokenResult): Promise<void> {
    if (!this.onTokens) return;
    try {
      await this.onTokens(result);
    } catch (error) {
      // Class name only: the hook holds the tokens, its message is foreign text.
      this.logger?.warn('[BaseTokenProvider] onTokens failed; the token stands', {
        error: ownLabel(error),
      });
    }
  }

  // ---- IAuthProvider: the process calls these, the same for every provider.

  /** The grant type, so a log line says which way in ran. */
  get kind(): string {
    return this.getAuthType();
  }

  /** The subject of a fixed refusal: "<grant type> token request failed". */
  private get obtaining(): string {
    return `${this.kind} token request`;
  }

  async prepare(): Promise<AuthOutcome> {
    return safely(this.obtaining, async () => {
      await this.getTokens();
      return OK;
    });
  }

  /** A token is presented per request; a logon needs nothing from it. */
  async establish(_logon: ILogonTarget): Promise<AuthOutcome> {
    return OK;
  }

  /** Per attempt: getTokens() renews an expired token here. */
  async authorize(request: IRequestTarget): Promise<AuthOutcome> {
    return safely(this.obtaining, async () => {
      const result = await this.getTokens();
      this.applyToken(request, result);
      this.presented = result.authorizationToken;
      return OK;
    });
  }

  /** A new token — refresh, else login. Ok only if it differs; retrying is the caller's. */
  async rejected(_rejection: IAuthRejection): Promise<AuthOutcome> {
    return safely(this.obtaining, async () => {
      const refused = this.presented ?? this.authorizationToken;
      const result = await this.refreshTokens();
      if (refused !== undefined && result.authorizationToken === refused) {
        return oops(
          'the renewal returned the credential that was refused',
          'the token source must issue a new token; log in again',
        );
      }
      return OK;
    });
  }

  /** How this provider's token rides on a request. Bearer by default. */
  protected applyToken(request: IRequestTarget, result: ITokenResult): void {
    request.header('Authorization', `Bearer ${result.authorizationToken}`);
  }
```

- [ ] **Step 4: Thread the hook through the nine providers**

For each of `AuthorizationCodeProvider`, `ClientCredentialsProvider`, `OidcBrowserProvider`, `OidcDeviceFlowProvider`, `OidcPasswordProvider`, `OidcTokenExchangeProvider`, `Saml2BearerProvider`, `Saml2PureProvider`, `UaaPasscodeProvider`:
- its `…Config` interface adds `TokenProviderHooks` to what it extends (`export interface XConfig extends TokenProviderHooks {`, or `extends Saml2CommonConfig, TokenProviderHooks` where it already extends);
- its constructor's `super();` becomes `super(config);`;
- import `type TokenProviderHooks` from `./BaseTokenProvider`.

In `src/providers/index.ts` add `export type { TokenProviderHooks } from './BaseTokenProvider';`.

- [ ] **Step 5: `Saml2PureProvider` presents cookies**

Add to the class (import the `IRequestTarget`, `ITokenResult` types):

```ts
  /** Its "token" is the SAML session's cookies (tokenType 'saml'). */
  protected override applyToken(request: IRequestTarget, result: ITokenResult): void {
    request.cookies(result.authorizationToken);
  }
```

- [ ] **Step 6: Run the new test and the whole suite**

Run: `npm test -- src/__tests__/providers/tokenProviderContract.test.ts` → PASS. Then `npm run test:check && npm test` → PASS.

- [ ] **Step 7: Prove three rules are load-bearing** (the one-renewal tests pin `refreshTokens()` as it is: one refresh, then one login)

1. Remove the `await this.obtained(result)` after the refresh → "onTokens after a login and after a refresh" FAILS. Revert.
2. Remove the `refused === result.authorizationToken` check → "Oops when the renewal returns the token that was refused" FAILS. Revert.
3. Call `this.applyToken(...)` outside `safely` → "a throwing target is an Oops" FAILS. Revert.

- [ ] **Step 8: Commit**

```bash
git add src/providers src/__tests__/providers/tokenProviderContract.test.ts
git commit -m "feat!: every token provider is an IAuthProvider; onTokens; no Ok on an unchanged token"
```

### Task 3: Manual strategies are bounded — `timeoutMs` and `dispose()`

**Files:**
- Modify: `src/strategies/manualStrategies.ts`
- Test: `src/__tests__/strategies/manualStrategiesTimeout.test.ts`

**Interfaces:**
- Produces: `ManualStrategyOptions` gains `timeoutMs?: number`; `read` becomes `(prompt: string, signal: AbortSignal) => Promise<string>`; `manualPasteStrategy`, `manualSamlResponseStrategy`, `manualPasscodeStrategy` return strategies with `dispose()`; on expiry or `dispose()` a pending `authorize` rejects with `BrowserAuthError` and the terminal `readline` is closed.

- [ ] **Step 1: Write the failing test** — `src/__tests__/strategies/manualStrategiesTimeout.test.ts`:

```ts
import { describe, expect, it, jest } from '@jest/globals';
import type { AuthorizationRequest } from '@mcp-abap-adt/interfaces-auth';
import { BrowserAuthError } from '../../errors/TokenProviderErrors';
import { manualPasscodeStrategy } from '../../strategies/manualStrategies';

const request = {
  buildAuthorizationUrl: async () => 'https://uaa/passcode',
} as unknown as AuthorizationRequest;

describe('manual strategies are bounded', () => {
  it('a reader that never answers is abandoned at timeoutMs, and told so', async () => {
    let seen: AbortSignal | undefined;
    const strategy = manualPasscodeStrategy({
      timeoutMs: 20,
      read: (_prompt, signal) => { seen = signal; return new Promise<string>(() => {}); },
    });
    await expect(strategy.authorize(request)).rejects.toBeInstanceOf(BrowserAuthError);
    expect(seen?.aborted).toBe(true);
  });

  it('dispose() ends a pending read at once', async () => {
    const strategy = manualPasscodeStrategy({ read: () => new Promise<string>(() => {}) });
    const pending = expect(strategy.authorize(request)).rejects.toBeInstanceOf(BrowserAuthError);
    await strategy.dispose?.();
    await pending;
  });

  it('a disposed strategy refuses the next authorize', async () => {
    const strategy = manualPasscodeStrategy({ read: async () => 'code' });
    await strategy.dispose?.();
    await expect(strategy.authorize(request)).rejects.toBeInstanceOf(BrowserAuthError);
  });

  it('without timeoutMs there is no deadline — an answer still arrives', async () => {
    const strategy = manualPasscodeStrategy({ read: async () => ' 123456 ' });
    await expect(strategy.authorize(request)).resolves.toMatchObject({ payload: '123456' });
  });

  it('the terminal reader closes its readline when aborted', async () => {
    const close = jest.fn();
    jest.resetModules();
    jest.doMock('node:readline', () => ({
      createInterface: () => ({
        close,
        [Symbol.asyncIterator]: () => ({ next: () => new Promise(() => {}) }),
      }),
    }));
    const tty = process.stdin.isTTY;
    Object.defineProperty(process.stdin, 'isTTY', { value: true, configurable: true });
    const write = jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
    try {
      const { manualPasscodeStrategy: fresh } = await import('../../strategies/manualStrategies');
      const strategy = fresh({ timeoutMs: 20 });
      await expect(strategy.authorize(request)).rejects.toThrow();
      expect(close).toHaveBeenCalled();
    } finally {
      Object.defineProperty(process.stdin, 'isTTY', { value: tty, configurable: true });
      write.mockRestore();
      jest.dontMock('node:readline');
    }
  });
});
```

- [ ] **Step 2: Run to see it fail** — `npm test -- src/__tests__/strategies/manualStrategiesTimeout.test.ts` → FAIL (no timeout; `dispose` undefined).

- [ ] **Step 3: Implement** — in `src/strategies/manualStrategies.ts`:

Options:

```ts
export interface ManualStrategyOptions {
  /** Must match what the authorization request advertises and the exchange sends. */
  redirectUri?: string;
  /**
   * Where the pasted value comes from. Defaults to an interactive stdin read.
   * The signal aborts when the timeout expires or the strategy is disposed.
   */
  read?: (prompt: string, signal: AbortSignal) => Promise<string>;
  /** Milliseconds before the read is abandoned. Absent: no deadline — the consumer's choice. */
  timeoutMs?: number;
}
```

The terminal reader takes the signal and closes its `readline` on abort:

```ts
async function readFromTerminal(prompt: string, signal: AbortSignal): Promise<string> {
  if (!process.stdin.isTTY) {
    throw new Error(
      'Manual input needs an interactive terminal. Supply `read` to source the value elsewhere.',
    );
  }
  process.stderr.write(prompt);
  const rl = createInterface({ input: process.stdin });
  const abort = () => rl.close();
  signal.addEventListener('abort', abort, { once: true });
  try {
    for await (const line of rl) return line.trim();
  } finally {
    signal.removeEventListener('abort', abort);
    rl.close();
  }
  throw new Error('No input received');
}
```

One bounded wrapper shared by the three strategies (add `import { BrowserAuthError } from '../errors/TokenProviderErrors';`):

```ts
/**
 * A manual strategy with a deadline and a dispose(): the read gets a signal,
 * and the race settles even when a custom reader ignores it.
 */
function boundedManual(
  options: ManualStrategyOptions,
  run: (request: AuthorizationRequest, read: (prompt: string) => Promise<string>) => Promise<AuthorizationOutcome<string>>,
): IAuthorizationStrategy<string> {
  const read = options.read ?? readFromTerminal;
  let disposed = false;
  let current: AbortController | undefined;
  return {
    async authorize(request) {
      if (disposed) throw new BrowserAuthError('the manual strategy was disposed');
      const controller = new AbortController();
      current = controller;
      const timer =
        options.timeoutMs === undefined
          ? undefined
          : setTimeout(() => controller.abort(), options.timeoutMs);
      const abandoned = new Promise<never>((_, reject) => {
        controller.signal.addEventListener(
          'abort',
          () => reject(new BrowserAuthError('the manual input did not arrive in time, or the strategy was disposed')),
          { once: true },
        );
      });
      const working = run(request, (prompt) => read(prompt, controller.signal));
      working.catch(() => {}); // a loser of the race must not surface as unhandled
      try {
        return await Promise.race([working, abandoned]);
      } finally {
        if (timer) clearTimeout(timer);
        if (current === controller) current = undefined;
      }
    },
    async dispose() {
      disposed = true;
      current?.abort();
    },
  };
}
```

Each of the three factories becomes `boundedManual(options, async (request, read) => { … })`, with its body unchanged except that it calls the `read` it is given: for `manualPasscodeStrategy`:

```ts
export function manualPasscodeStrategy(
  options: ManualStrategyOptions = {},
): IAuthorizationStrategy<string> {
  const redirectUri = options.redirectUri ?? defaultRedirectUri();
  return boundedManual(options, async (request, read) => {
    const url = await request.buildAuthorizationUrl(redirectUri);
    announce(request, url);
    const code = (await read('Paste the Temporary Authentication Code (passcode): ')).trim();
    if (!code) throw new Error('No passcode was provided');
    return { payload: code, redirectUri };
  });
}
```

`manualPasteStrategy` and `manualSamlResponseStrategy` are rewritten the same way around their existing bodies (prompt text, `extractCode` / trim checks unchanged).

- [ ] **Step 4: Run** — the new test → PASS; then `npm test -- src/__tests__/strategies` → PASS (existing manual-strategy tests that pass `read: async () => …` still compile: a one-parameter function is assignable to the two-parameter type).

- [ ] **Step 5: Commit** — `git add src/strategies/manualStrategies.ts src/__tests__/strategies/manualStrategiesTimeout.test.ts && git commit -m "feat(strategies): manual strategies take timeoutMs and dispose(), closing their readline"`

### Task 4: No implicit defaults — required collaborators and static factories

**Files:**
- Modify: `src/providers/AuthorizationCodeProvider.ts`, `OidcBrowserProvider.ts`, `UaaPasscodeProvider.ts`, `Saml2PureProvider.ts`, `Saml2BearerProvider.ts`, `saml2Utils.ts`; `src/validation/assertionValidator.ts`; every test file the type check flags (Step 5)
- Test: `src/__tests__/providers/noDefaults.test.ts`

**Interfaces:**
- Consumes: Task 3's `timeoutMs` on manual strategies.
- Produces:
  - `authorization` required in `AuthorizationCodeProviderConfig`, `OidcBrowserProviderConfig`, `UaaPasscodeProviderConfig`, `Saml2CommonConfig`;
  - `assertionValidator: IAssertionValidator` required in `Saml2CommonConfig`; `idpCertificates`, `clockSkewMs`, `assertionReplayStore` removed from it (they belong to building a validator); `idpEntityId` stays;
  - `ShippedValidatorOptions.replayStore` required;
  - `AuthorizationCodeProvider.inBrowser(config: Omit<AuthorizationCodeProviderConfig, 'authorization'>, options?: { timeoutMs?: number })`;
  - `OidcBrowserProvider.inBrowser(config: Omit<OidcBrowserProviderConfig, 'authorization'>, options?: { timeoutMs?: number })`;
  - `UaaPasscodeProvider.fromTerminal(config: Omit<UaaPasscodeProviderConfig, 'authorization'>, options?: { timeoutMs?: number })` — default `timeoutMs` 300 000;
  - `Saml2PureProvider.inBrowser(config: Omit<Saml2PureProviderConfig, 'authorization' | 'assertionValidator'>, trust: SamlTrust, options?: { timeoutMs?: number })` and the same for `Saml2BearerProvider`, with `export interface SamlTrust { idpCertificates: string[]; clockSkewMs?: number; replayStore?: IAssertionReplayStore }` in `saml2Utils.ts` (`replayStore` defaults to `defaultReplayStore` in the recipe).

- [ ] **Step 1: Write the failing test** — `src/__tests__/providers/noDefaults.test.ts`:

```ts
import { describe, expect, it } from '@jest/globals';
import { AuthorizationCodeProvider } from '../../providers/AuthorizationCodeProvider';
import { OidcBrowserProvider } from '../../providers/OidcBrowserProvider';
import { Saml2BearerProvider } from '../../providers/Saml2BearerProvider';
import { Saml2PureProvider } from '../../providers/Saml2PureProvider';
import { UaaPasscodeProvider } from '../../providers/UaaPasscodeProvider';
import { BrowserCallbackStrategy } from '../../strategies/BrowserCallbackStrategy';
import { isShippedValidator } from '../../validation/assertionValidator';

const configOf = (p: unknown) => (p as { config: Record<string, unknown> }).config;
const uaa = { uaaUrl: 'https://uaa', clientId: 'c', clientSecret: 's' };
const saml = {
  idpSsoUrl: 'https://idp/sso',
  spEntityId: 'sp',
  idpEntityId: 'idp',
  cookieProvider: async () => 'c=1',
};
const CERT = 'MIIB';

describe('no implicit defaults', () => {
  it('constructors require the collaborator (compile-time)', () => {
    // @ts-expect-error authorization is required
    expect(() => new AuthorizationCodeProvider({ ...uaa })).toBeDefined();
    // @ts-expect-error authorization is required
    expect(() => new OidcBrowserProvider({ clientId: 'c' })).toBeDefined();
    // @ts-expect-error authorization is required
    expect(() => new UaaPasscodeProvider({ uaaUrl: 'https://uaa', clientId: 'c' })).toBeDefined();
    // @ts-expect-error authorization and assertionValidator are required
    expect(() => new Saml2PureProvider({ ...saml })).toBeDefined();
  });

  it('inBrowser assembles a browser callback strategy', () => {
    expect(configOf(AuthorizationCodeProvider.inBrowser(uaa)).authorization).toBeInstanceOf(BrowserCallbackStrategy);
    expect(configOf(OidcBrowserProvider.inBrowser({ clientId: 'c' })).authorization).toBeInstanceOf(BrowserCallbackStrategy);
  });

  it('fromTerminal assembles a manual strategy with dispose()', () => {
    const strategy = configOf(UaaPasscodeProvider.fromTerminal({ uaaUrl: 'https://uaa', clientId: 'c' })).authorization as { dispose?: unknown };
    expect(typeof strategy.dispose).toBe('function');
  });

  it('the SAML recipes assemble a callback strategy and a shipped validator', () => {
    for (const p of [
      Saml2PureProvider.inBrowser(saml, { idpCertificates: [CERT] }),
      Saml2BearerProvider.inBrowser({ ...saml, tokenUrl: 'https://uaa/oauth/token', clientId: 'c', clientSecret: 's' }, { idpCertificates: [CERT] }),
    ]) {
      expect(configOf(p).authorization).toBeInstanceOf(BrowserCallbackStrategy);
      expect(isShippedValidator(configOf(p).assertionValidator as never)).toBe(true);
    }
  });
});
```

- [ ] **Step 2: Run to see it fail** — `npm test -- src/__tests__/providers/noDefaults.test.ts` → FAIL (factories missing; the `@ts-expect-error` lines are unused).

- [ ] **Step 3: Implement**

1. In the four configs make `authorization` required (drop `?`); update their doc comments ("How the login is conducted. Required — see the static factories for the usual choice.").
2. In `AuthorizationCodeProvider`, `OidcBrowserProvider`, `UaaPasscodeProvider` and `getSamlAssertion` (`saml2Utils.ts`): replace `const supplied = …; const strategy = supplied ?? xxxStrategy();` with `const strategy = this.config.authorization;` (or `config.authorization`), and delete the `finally { if (!supplied) { … dispose … } }` branch — the provider never disposes a strategy it was given. Remove the now-unused `browserCallbackStrategy` / `oidcCallbackStrategy` / `manualPasscodeStrategy` / `samlCallbackStrategy` imports.
3. `saml2Utils.ts`: `assertionValidator: IAssertionValidator` required; delete `idpCertificates`, `clockSkewMs`, `assertionReplayStore` from `Saml2CommonConfig`; `resolveAssertionValidator(config, provider)` becomes `checkAssertionValidator(config): IAssertionValidator` — keeps the "shipped validator without `idpEntityId`" `ValidationError`, returns `config.assertionValidator`; the building branch goes. Add:

```ts
/** What a recipe needs to build a shipped validator. */
export interface SamlTrust {
  idpCertificates: string[];
  clockSkewMs?: number;
  /** Default in the recipe: the process-wide `defaultReplayStore`. */
  replayStore?: IAssertionReplayStore;
}
```

4. `assertionValidator.ts`: `readonly replayStore: IAssertionReplayStore;` (required) and `const store = options.replayStore;`.
5. Static factories:

```ts
// AuthorizationCodeProvider
  /** The usual choice: a browser login answered on a local callback. */
  static inBrowser(
    config: Omit<AuthorizationCodeProviderConfig, 'authorization'>,
    options: { timeoutMs?: number } = {},
  ): AuthorizationCodeProvider {
    return new AuthorizationCodeProvider({
      ...config,
      authorization: browserCallbackStrategy({ timeoutMs: options.timeoutMs }),
    });
  }

// OidcBrowserProvider
  static inBrowser(
    config: Omit<OidcBrowserProviderConfig, 'authorization'>,
    options: { timeoutMs?: number } = {},
  ): OidcBrowserProvider {
    return new OidcBrowserProvider({
      ...config,
      authorization: oidcCallbackStrategy({ timeoutMs: options.timeoutMs }),
    });
  }

// UaaPasscodeProvider
  /** The passcode typed in a terminal; five minutes to paste it by default. */
  static fromTerminal(
    config: Omit<UaaPasscodeProviderConfig, 'authorization'>,
    options: { timeoutMs?: number } = {},
  ): UaaPasscodeProvider {
    return new UaaPasscodeProvider({
      ...config,
      authorization: manualPasscodeStrategy({ timeoutMs: options.timeoutMs ?? 300_000 }),
    });
  }

// Saml2PureProvider
  static inBrowser(
    config: Omit<Saml2PureProviderConfig, 'authorization' | 'assertionValidator'>,
    trust: SamlTrust,
    options: { timeoutMs?: number } = {},
  ): Saml2PureProvider {
    return new Saml2PureProvider({
      ...config,
      authorization: samlCallbackStrategy({ timeoutMs: options.timeoutMs }),
      assertionValidator: createSignedResponseValidator({
        idpCertificates: trust.idpCertificates,
        clockSkewMs: trust.clockSkewMs,
        replayStore: trust.replayStore ?? defaultReplayStore,
      }),
    });
  }
```

`Saml2BearerProvider.inBrowser` is the same with `createSignedAssertionValidator`. Import the strategy factories from `../strategies`, the validators from `../validation/assertionValidator`, `defaultReplayStore` from `../validation/inMemoryReplayStore`.

- [ ] **Step 4: Run the new test** — PASS.

- [ ] **Step 5: Migrate the existing tests** — run `npm run test:check`; every error is a construction that relied on a removed default. Fix each by the table (no other edits):

| Error at `new X({…})` | Add / change |
|---|---|
| `AuthorizationCodeProvider`: `authorization` missing | `authorization: browserCallbackStrategy()` — or call `AuthorizationCodeProvider.inBrowser({…})` |
| `OidcBrowserProvider`: `authorization` missing | `authorization: oidcCallbackStrategy()` |
| `UaaPasscodeProvider`: `authorization` missing | `authorization: manualPasscodeStrategy()` |
| `Saml2PureProvider`: `authorization` / `assertionValidator` missing, or `idpCertificates` / `clockSkewMs` / `assertionReplayStore` unknown | `authorization: samlCallbackStrategy()` (unless the test supplies one), `assertionValidator: createSignedResponseValidator({ idpCertificates: <the test's certs>, clockSkewMs: <the test's value>, replayStore: <the test's store> ?? defaultReplayStore })`, and delete the three removed fields |
| `Saml2BearerProvider`: same | same, with `createSignedAssertionValidator` |
| `createSigned…Validator({…})`: `replayStore` missing | `replayStore: defaultReplayStore` (or the test's own store) |
| an import of `resolveAssertionValidator` | `checkAssertionValidator(config)` for the "shipped validator without `idpEntityId`" cases; the cases that built a validator from `idpCertificates` move to `Saml2PureProvider.inBrowser` / `Saml2BearerProvider.inBrowser` with a `SamlTrust` |

A test whose purpose was "the provider builds the default validator / refuses without `idpCertificates`" now asserts the same through the recipe (`Saml2PureProvider.inBrowser(config, { idpCertificates: [] })` → `ValidationError` from the shipped validator) — move the assertion, do not drop it. Then `npm test` → PASS.

- [ ] **Step 6: Commit** — `git add src/providers src/validation src/__tests__ && git commit -m "feat!: no implicit defaults — strategies and SAML validators are constructor arguments; inBrowser / fromTerminal recipes"`

### Task 5: The device-code presenter

**Files:**
- Create: `src/deviceCode/DeviceCodePresenter.ts`
- Modify: `src/providers/OidcDeviceFlowProvider.ts`; its tests (add `presenter`); `src/auth/refusal.ts` (one mapping)
- Test: `src/__tests__/deviceCode/presenter.test.ts`, `src/__tests__/auth/refusal.test.ts` (one case)

**Interfaces:**
- Produces: `interface DeviceCodePrompt { verificationUri: string; verificationUriComplete?: string; userCode: string; expiresInSeconds?: number }`; `interface IDeviceCodePresenter { present(prompt: DeviceCodePrompt): Promise<void> }`; `consoleDeviceCodePresenter(logger?: ILogger): IDeviceCodePresenter`; internal `class DeviceCodePresentationError extends Error` (not exported from the package root); `OidcDeviceFlowProviderConfig.presenter: IDeviceCodePresenter` (required); `OidcDeviceFlowProvider.toConsole(config: Omit<OidcDeviceFlowProviderConfig, 'presenter'>)`.
- Changes `refusalFrom`: a `DeviceCodePresentationError` → exactly `{ ok: false, refusal: { reason: 'showing the device code failed' } }` (spec, *The device-code presenter*).

- [ ] **Step 1: Write the failing test** — `src/__tests__/deviceCode/presenter.test.ts`:

```ts
import { describe, expect, it, jest } from '@jest/globals';
import { consoleDeviceCodePresenter } from '../../deviceCode/DeviceCodePresenter';
import { OidcDeviceFlowProvider } from '../../providers/OidcDeviceFlowProvider';

const prompt = { verificationUri: 'https://idp/device', verificationUriComplete: 'https://idp/device?c=AB', userCode: 'AB-CD', expiresInSeconds: 600 };

describe('device-code presenter', () => {
  it('console presenter: to the logger when there is one, never stdout', async () => {
    const info = jest.fn();
    const out = jest.spyOn(process.stdout, 'write');
    await consoleDeviceCodePresenter({ info, debug: jest.fn(), warn: jest.fn(), error: jest.fn() } as never).present(prompt);
    expect(info.mock.calls.flat().join('\n')).toMatch(/https:\/\/idp\/device[\s\S]*AB-CD/);
    expect(out).not.toHaveBeenCalled();
    out.mockRestore();
  });

  it('console presenter: to stderr without a logger', async () => {
    const err = jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
    await consoleDeviceCodePresenter().present(prompt);
    expect(err.mock.calls.map((c) => String(c[0])).join('')).toMatch(/Enter code: AB-CD/);
    err.mockRestore();
  });

  it('the provider requires a presenter and toConsole assembles one', () => {
    // @ts-expect-error presenter is required
    expect(() => new OidcDeviceFlowProvider({ clientId: 'c' })).toBeDefined();
    const p = OidcDeviceFlowProvider.toConsole({ clientId: 'c' });
    expect(typeof (p as unknown as { config: { presenter: { present: unknown } } }).config.presenter.present).toBe('function');
  });
});
```

Add to the provider's existing login test file (where `initiateDeviceAuthorization` is mocked to return `{ deviceCode: 'dc', userCode: 'SECRET-UC', verificationUri: 'https://idp/device', verificationUriComplete: 'https://idp/device?c=SECRET-UC', expiresIn: 600, interval: 1 }`):

```ts
it('hands the presenter the structured prompt', async () => {
  const present = jest.fn(async (_: DeviceCodePrompt) => {});
  const p = new OidcDeviceFlowProvider({ clientId: 'c', issuerUrl: 'https://idp', presenter: { present } });
  await p.prepare();
  expect(present).toHaveBeenCalledWith({
    verificationUri: 'https://idp/device',
    verificationUriComplete: 'https://idp/device?c=SECRET-UC',
    userCode: 'SECRET-UC',
    expiresInSeconds: 600,
  });
});

it.each(['prepare', 'rejected'] as const)('a throwing presenter in %s → the fixed refusal, no code, no message', async (moment) => {
  const p = new OidcDeviceFlowProvider({
    clientId: 'c',
    issuerUrl: 'https://idp',
    presenter: { present: async () => { throw new Error('UI down SECRET-UI'); } },
  });
  const outcome =
    moment === 'prepare'
      ? await p.prepare()
      : await p.rejected({ at: 'request', status: 401, error: {} }); // no refresh token → one login → the presenter
  expect(outcome).toEqual({ ok: false, refusal: { reason: 'showing the device code failed' } });
  expect(JSON.stringify(outcome)).not.toMatch(/SECRET/);
});
```

With `import type { DeviceCodePrompt } from '../../deviceCode/DeviceCodePresenter';` at the top. Use the existing file's mocking of `initiateDeviceAuthorization` / `pollDeviceTokens` and its config fields for the endpoint; the assertions above are what is new.

And append to `src/__tests__/auth/refusal.test.ts`:

```ts
import { DeviceCodePresentationError } from '../../deviceCode/DeviceCodePresenter';

it('a presenter failure is the fixed device-code refusal', () => {
  expect(refusalFrom(new DeviceCodePresentationError(), 'x token request'))
    .toEqual({ ok: false, refusal: { reason: 'showing the device code failed' } });
});
```

- [ ] **Step 2: Run to see it fail** — `npm test -- src/__tests__/deviceCode/presenter.test.ts` → FAIL.

- [ ] **Step 3: Implement** — `src/deviceCode/DeviceCodePresenter.ts`:

```ts
/**
 * How the user learns where to go and what to enter in a device flow. Injected
 * like a strategy: the provider hands over structured data, and the consumer's
 * UI renders it its own way.
 */

import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { announcer } from '../auth/announce';

export interface DeviceCodePrompt {
  verificationUri: string;
  verificationUriComplete?: string;
  userCode: string;
  expiresInSeconds?: number;
}

export interface IDeviceCodePresenter {
  /** Show the prompt; resolves once it has been shown. */
  present(prompt: DeviceCodePrompt): Promise<void>;
}

/**
 * A presenter failed. Internal: carries no message and no cause on purpose,
 * so neither the device code nor the presenter's own text can reach a refusal.
 */
export class DeviceCodePresentationError extends Error {
  constructor() {
    super('showing the device code failed');
    this.name = 'DeviceCodePresentationError';
    Object.setPrototypeOf(this, DeviceCodePresentationError.prototype);
  }
}

/** The logger's info, or stderr without one — never stdout. */
export function consoleDeviceCodePresenter(logger?: ILogger): IDeviceCodePresenter {
  const announce = announcer(logger);
  return {
    async present(prompt) {
      announce('OIDC device authorization');
      announce(`Go to: ${prompt.verificationUri}`);
      if (prompt.verificationUriComplete) announce(`Or use: ${prompt.verificationUriComplete}`);
      announce(`Enter code: ${prompt.userCode}`);
    },
  };
}
```

In `OidcDeviceFlowProvider`: add `presenter: IDeviceCodePresenter;` to the config; replace the `announcer(...)` block (the five `announce(...)` lines) with

```ts
    try {
      await this.config.presenter.present({
        verificationUri: deviceFlow.verificationUri,
        verificationUriComplete: deviceFlow.verificationUriComplete,
        userCode: deviceFlow.userCode,
        expiresInSeconds: deviceFlow.expiresIn,
      });
    } catch (error) {
      // The presenter's text may hold the code; the log gets its class only.
      this.logger?.warn('[OidcDeviceFlowProvider] presenter failed', {
        error: error instanceof Error ? 'Error' : typeof error,
      });
      throw new DeviceCodePresentationError();
    }
```

In `src/auth/refusal.ts`, import `DeviceCodePresentationError` from `../deviceCode/DeviceCodePresenter`, add `[DeviceCodePresentationError, 'DeviceCodePresentationError']` to `OWN_CLASSES`, and as the first check in `refusalFrom`:

```ts
  if (error instanceof DeviceCodePresentationError) {
    return oops('showing the device code failed');
  }
```

and add

```ts
  /** The usual choice: print the prompt to the logger, or stderr. */
  static toConsole(config: Omit<OidcDeviceFlowProviderConfig, 'presenter'>): OidcDeviceFlowProvider {
    return new OidcDeviceFlowProvider({ ...config, presenter: consoleDeviceCodePresenter(config.logger) });
  }
```

Remove the `announcer` import if unused. In the provider's existing tests add `presenter: consoleDeviceCodePresenter()` (or a `jest.fn` presenter) to each construction the type check flags.

- [ ] **Step 4: Run** — the new tests, `npm test -- src/__tests__/auth/refusal.test.ts` and `npm test -- src/__tests__/providers` → PASS.

- [ ] **Step 5: Load-bearing** — remove the `DeviceCodePresentationError` branch from `refusalFrom` → both "a throwing presenter" cases FAIL (they now read "… token request failed (unknown error)"). Revert.

- [ ] **Step 6: Commit** — `git add src/deviceCode src/auth/refusal.ts src/providers/OidcDeviceFlowProvider.ts src/__tests__ && git commit -m "feat!: the device-code prompt is an injected presenter; toConsole recipe; fixed refusal when it fails"`

### Task 6: The providers moved in from `connection`

**Files:**
- Create: `src/credentials/BasicAuthProvider.ts`, `src/credentials/SamlAuthProvider.ts`, `src/credentials/TokenAuthProvider.ts`, `src/credentials/CertificateAuthProvider.ts`, `src/credentials/FileCertificateMaterialLoader.ts`
- Test: `src/__tests__/credentials/credentials.test.ts`

**Interfaces:**
- Consumes: `OK`, `oops`, `safely`; `recordingTargets`.
- Produces: `CertificateAuthProvider.fromFiles(config: ISapConfig)`; `BasicAuthProvider(username: string, password: string)`; `SamlAuthProvider(sessionCookies: string)`; `TokenAuthProvider.fixed(token: string)`, `TokenAuthProvider.from(refresher: ITokenRefresher)`; `CertificateAuthProvider(loader: ICertificateMaterialLoader, config: ISapConfig)`; `FileCertificateMaterialLoader` implementing `ICertificateMaterialLoader`, throwing `ValidationError` for configuration errors.

- [ ] **Step 1: Write the failing test**

`src/__tests__/credentials/credentials.test.ts`:

```ts
import { describe, expect, it, jest } from '@jest/globals';
import type { ITokenRefresher } from '@mcp-abap-adt/interfaces-auth';
import type { ISapConfig } from '@mcp-abap-adt/interfaces-auth-sap';
import { BasicAuthProvider } from '../../credentials/BasicAuthProvider';
import { CertificateAuthProvider } from '../../credentials/CertificateAuthProvider';
import { FileCertificateMaterialLoader } from '../../credentials/FileCertificateMaterialLoader';
import { SamlAuthProvider } from '../../credentials/SamlAuthProvider';
import { TokenAuthProvider } from '../../credentials/TokenAuthProvider';
import { ValidationError } from '../../errors/TokenProviderErrors';
import { recordingTargets } from '../helpers/targets';

const refusal = { at: 'request' as const, status: 401, error: {} };
const broken = () => recordingTargets({ throws: true });

describe('BasicAuthProvider', () => {
  const p = new BasicAuthProvider('USER', 'S3CRET-PW');

  it('writes the header and offers user/passwd to the logon', async () => {
    const t = recordingTargets();
    await expect(p.establish(t.logonTarget)).resolves.toEqual({ ok: true });
    await expect(p.authorize(t.requestTarget)).resolves.toEqual({ ok: true });
    expect(t.logon.params).toEqual([{ user: 'USER', passwd: 'S3CRET-PW' }]);
    expect(t.request.headers.Authorization).toBe(`Basic ${Buffer.from('USER:S3CRET-PW').toString('base64')}`);
  });

  it('goes on when the wire takes no logon parameters (HTTP)', async () => {
    await expect(p.establish(recordingTargets({ acceptsLogonParameters: false }).logonTarget)).resolves.toEqual({ ok: true });
  });

  it('a throwing target is an Oops without the password', async () => {
    for (const outcome of [await p.establish(broken().logonTarget), await p.authorize(broken().requestTarget)]) {
      expect(outcome).toMatchObject({ ok: false });
      expect(JSON.stringify(outcome)).not.toMatch(/S3CRET-PW|SECRET-IN-TARGET/);
    }
  });

  it('rejected is an Oops without the password', async () => {
    const outcome = await p.rejected(refusal);
    expect(outcome).toMatchObject({ ok: false, refusal: { reason: 'the user or password was refused' } });
    expect(JSON.stringify(outcome)).not.toMatch(/S3CRET-PW/);
  });
});

describe('SamlAuthProvider', () => {
  const p = new SamlAuthProvider('MYSAPSSO2=SECRET-COOKIE');

  it('writes the cookies', async () => {
    const t = recordingTargets();
    await p.authorize(t.requestTarget);
    expect(t.request.cookies).toEqual(['MYSAPSSO2=SECRET-COOKIE']);
  });

  it('a throwing target and rejected are Oops without the cookie', async () => {
    for (const outcome of [await p.authorize(broken().requestTarget), await p.rejected(refusal)]) {
      expect(outcome.ok).toBe(false);
      expect(JSON.stringify(outcome)).not.toMatch(/SECRET-COOKIE/);
    }
  });
});

describe('TokenAuthProvider', () => {
  it('fixed: bearer, and rejected is an Oops without the token', async () => {
    const p = TokenAuthProvider.fixed('SECRET-T');
    const t = recordingTargets();
    await p.authorize(t.requestTarget);
    expect(t.request.headers.Authorization).toBe('Bearer SECRET-T');
    const outcome = await p.rejected(refusal);
    expect(outcome).toMatchObject({ ok: false, refusal: { hint: 'obtain a new token' } });
    expect(JSON.stringify(outcome)).not.toMatch(/SECRET-T/);
  });

  it('from(refresher): getToken per attempt, refreshToken once, Ok on a new token', async () => {
    const refresher: ITokenRefresher = {
      getToken: jest.fn(async () => 'A'),
      refreshToken: jest.fn(async () => 'B'),
    };
    const p = TokenAuthProvider.from(refresher);
    await p.authorize(recordingTargets().requestTarget);
    await expect(p.rejected(refusal)).resolves.toEqual({ ok: true });
    expect(refresher.getToken).toHaveBeenCalledTimes(1);
    expect(refresher.refreshToken).toHaveBeenCalledTimes(1);
  });

  it('from(refresher): a renewal returning the refused token is an Oops', async () => {
    const p = TokenAuthProvider.from({ getToken: async () => 'unchanged', refreshToken: async () => 'unchanged' });
    await p.authorize(recordingTargets().requestTarget);
    await expect(p.rejected(refusal)).resolves.toMatchObject({
      ok: false,
      refusal: { reason: 'the renewal returned the credential that was refused' },
    });
  });

  it('from(refresher): a refresher error with a secret in its message stays out', async () => {
    const p = TokenAuthProvider.from({
      getToken: async () => { throw new Error('token rejected: SECRET-OPAQUE'); },
      refreshToken: async () => { throw new Error('refresh failed for SECRET-REFRESH'); },
    });
    for (const outcome of [await p.authorize(recordingTargets().requestTarget), await p.rejected(refusal)]) {
      expect(outcome).toMatchObject({ ok: false, refusal: { reason: 'the token source failed (unknown error)' } });
      expect(JSON.stringify(outcome)).not.toMatch(/SECRET/);
    }
  });
});

describe('CertificateAuthProvider', () => {
  const config = { url: 'https://h', authType: 'certificate' } as ISapConfig;

  it('prepare loads, establish hands the material to the logon', async () => {
    const p = new CertificateAuthProvider({ load: async () => ({ cert: 'C', key: 'K' }) }, config);
    await expect(p.prepare()).resolves.toEqual({ ok: true });
    const t = recordingTargets();
    await expect(p.establish(t.logonTarget)).resolves.toEqual({ ok: true });
    expect(t.logon.tls).toEqual([{ cert: 'C', key: 'K' }]);
  });

  it('a loader ValidationError gives the fixed wording with known field names; a foreign one gives its code only', async () => {
    const own = new CertificateAuthProvider({ load: async () => { throw new ValidationError('SECRET-MSG', ['certPath', 'certPfxPath']); } }, config);
    await expect(own.prepare()).resolves.toEqual({
      ok: false,
      refusal: { reason: 'the provider configuration is incomplete or invalid: certPath, certPfxPath', hint: 'check the provider configuration' },
    });
    const fsError = Object.assign(new Error("ENOENT: no such file 'C:\\\\SECRET\\\\key.pem'"), { code: 'ENOENT' });
    const foreign = new CertificateAuthProvider({ load: async () => { throw fsError; } }, config);
    const outcome = await foreign.prepare();
    expect(outcome).toEqual({ ok: false, refusal: { reason: 'loading the certificate failed (unknown error, ENOENT)' } });
  });

  it('returns the target Oops when the wire has no TLS; a throwing target is an Oops', async () => {
    const p = new CertificateAuthProvider({ load: async () => ({ pfx: Buffer.from('x'), passphrase: 'SECRET-PP' }) }, config);
    await p.prepare();
    await expect(p.establish(recordingTargets({ acceptsTls: false }).logonTarget))
      .resolves.toMatchObject({ ok: false, refusal: { reason: 'this wire does not take TLS material' } });
    const outcome = await p.establish(broken().logonTarget);
    expect(outcome.ok).toBe(false);
    expect(JSON.stringify(outcome)).not.toMatch(/SECRET-PP/);
  });

  it('establish before prepare is an Oops, not a throw', async () => {
    const p = new CertificateAuthProvider({ load: async () => ({}) }, config);
    await expect(p.establish(recordingTargets().logonTarget)).resolves.toMatchObject({ ok: false });
  });
});

describe('CertificateAuthProvider.fromFiles', () => {
  it('assembles a FileCertificateMaterialLoader', () => {
    const p = CertificateAuthProvider.fromFiles({ url: 'https://h', authType: 'certificate' } as ISapConfig);
    expect((p as unknown as { loader: unknown }).loader).toBeInstanceOf(FileCertificateMaterialLoader);
  });
});

describe('FileCertificateMaterialLoader', () => {
  it('configuration errors are ValidationError', async () => {
    const loader = new FileCertificateMaterialLoader();
    await expect(loader.load({ url: 'h', authType: 'certificate', certPath: 'a', certPfxPath: 'b' } as ISapConfig))
      .rejects.toBeInstanceOf(ValidationError);
    await expect(loader.load({ url: 'h', authType: 'certificate' } as ISapConfig))
      .rejects.toBeInstanceOf(ValidationError);
  });
});
```

- [ ] **Step 2: Run to see it fail**

Run: `npm test -- src/__tests__/credentials/credentials.test.ts`
Expected: FAIL — modules not found.

- [ ] **Step 3: Implement the five files**

`src/credentials/BasicAuthProvider.ts`:

```ts
import type {
  AuthOutcome,
  IAuthProvider,
  IAuthRejection,
  ILogonTarget,
  IRequestTarget,
} from '@mcp-abap-adt/interfaces-auth';
import { OK, oops, safely } from '../auth/refusal';

/** A user and a password: a header over HTTP, logon parameters over RFC. */
export class BasicAuthProvider implements IAuthProvider {
  readonly kind = 'basic';

  constructor(
    private readonly username: string,
    private readonly password: string,
  ) {}

  async prepare(): Promise<AuthOutcome> {
    return OK;
  }

  /** Offered; a wire without parameter logon says no, and the header carries it. */
  async establish(logon: ILogonTarget): Promise<AuthOutcome> {
    return safely('offering the logon parameters', () => {
      logon.logonParameters({ user: this.username, passwd: this.password });
      return OK;
    });
  }

  async authorize(request: IRequestTarget): Promise<AuthOutcome> {
    return safely('writing the Authorization header', () => {
      request.header(
        'Authorization',
        `Basic ${Buffer.from(`${this.username}:${this.password}`).toString('base64')}`,
      );
      return OK;
    });
  }

  async rejected(_rejection: IAuthRejection): Promise<AuthOutcome> {
    return oops('the user or password was refused', 'check the user and password');
  }
}
```

`src/credentials/SamlAuthProvider.ts`:

```ts
import type {
  AuthOutcome,
  IAuthProvider,
  IAuthRejection,
  ILogonTarget,
  IRequestTarget,
} from '@mcp-abap-adt/interfaces-auth';
import { OK, oops, safely } from '../auth/refusal';

/** A SAML session negotiated elsewhere and handed over as cookies. */
export class SamlAuthProvider implements IAuthProvider {
  readonly kind = 'saml';

  constructor(private readonly sessionCookies: string) {}

  async prepare(): Promise<AuthOutcome> {
    return OK;
  }

  async establish(_logon: ILogonTarget): Promise<AuthOutcome> {
    return OK;
  }

  async authorize(request: IRequestTarget): Promise<AuthOutcome> {
    return safely('writing the session cookies', () => {
      request.cookies(this.sessionCookies);
      return OK;
    });
  }

  async rejected(_rejection: IAuthRejection): Promise<AuthOutcome> {
    return oops('the SAML session was refused or has expired', 'obtain a new SAML session');
  }
}
```

`src/credentials/TokenAuthProvider.ts`:

```ts
import type {
  AuthOutcome,
  IAuthProvider,
  IAuthRejection,
  ILogonTarget,
  IRequestTarget,
  ITokenRefresher,
} from '@mcp-abap-adt/interfaces-auth';
import { OK, oops, safely } from '../auth/refusal';

/**
 * A token that comes from outside this package — a fixed string, or the
 * broker's refresher. A token provider from this package needs no wrapper: it
 * is an IAuthProvider itself.
 */
export class TokenAuthProvider implements IAuthProvider {
  readonly kind = 'token';
  /** The token last put on a request, so rejected() can tell a renewal from a repeat. */
  private presented?: string;

  private constructor(
    private readonly current: () => Promise<string>,
    private readonly renew: (() => Promise<string>) | undefined,
  ) {}

  static fixed(token: string): TokenAuthProvider {
    return new TokenAuthProvider(async () => token, undefined);
  }

  static from(refresher: ITokenRefresher): TokenAuthProvider {
    return new TokenAuthProvider(
      () => refresher.getToken(),
      () => refresher.refreshToken(),
    );
  }

  async prepare(): Promise<AuthOutcome> {
    return OK;
  }

  async establish(_logon: ILogonTarget): Promise<AuthOutcome> {
    return OK;
  }

  async authorize(request: IRequestTarget): Promise<AuthOutcome> {
    return safely('the token source', async () => {
      const token = await this.current();
      request.header('Authorization', `Bearer ${token}`);
      this.presented = token;
      return OK;
    });
  }

  async rejected(_rejection: IAuthRejection): Promise<AuthOutcome> {
    const renew = this.renew;
    if (!renew) return oops('the token was refused', 'obtain a new token');
    return safely('the token source', async () => {
      const renewed = await renew();
      if (this.presented !== undefined && renewed === this.presented) {
        return oops(
          'the renewal returned the credential that was refused',
          'the token source must issue a new token',
        );
      }
      return OK;
    });
  }
}
```

`src/credentials/FileCertificateMaterialLoader.ts` — copy `@mcp-abap-adt/connection`'s `src/auth/FileCertificateMaterialLoader.ts` (origin/master) and change its two `throw new Error(…)` into `throw new ValidationError(…, [...])`, keeping the messages: `'Certificate auth: provide either PEM (certPath+certKeyPath) OR certPfxPath, not both.'` with `['certPath', 'certPfxPath']`, and `'Certificate auth requires certPfxPath OR (certPath AND certKeyPath).'` with `['certPfxPath', 'certPath', 'certKeyPath']`. Import `ValidationError` from `../errors/TokenProviderErrors`. `readFile` errors stay as they are (foreign: they reach a refusal only as the fixed reason with their `code`).

`src/credentials/CertificateAuthProvider.ts`:

```ts
import type {
  AuthOutcome,
  IAuthProvider,
  IAuthRejection,
  ICertificateMaterial,
  ILogonTarget,
  IRequestTarget,
} from '@mcp-abap-adt/interfaces-auth';
import type { ICertificateMaterialLoader, ISapConfig } from '@mcp-abap-adt/interfaces-auth-sap';
import { OK, oops, safely } from '../auth/refusal';
import { FileCertificateMaterialLoader } from './FileCertificateMaterialLoader';

/** A client certificate, presented in the TLS handshake of each logon. */
export class CertificateAuthProvider implements IAuthProvider {
  readonly kind = 'certificate';
  private material: ICertificateMaterial | null = null;

  constructor(
    private readonly loader: ICertificateMaterialLoader,
    private readonly config: ISapConfig,
  ) {}

  async prepare(): Promise<AuthOutcome> {
    return safely('loading the certificate', async () => {
      this.material = await this.loader.load(this.config);
      return OK;
    });
  }

  /** No other way in: the wire's Oops is this provider's own. */
  async establish(logon: ILogonTarget): Promise<AuthOutcome> {
    const material = this.material;
    if (!material) return oops('the certificate is not loaded', 'connect() prepares it first');
    return safely('presenting the certificate', () => {
      const { cert, key, pfx, passphrase } = material;
      const presented: ICertificateMaterial = {};
      if (cert !== undefined) presented.cert = cert;
      if (key !== undefined) presented.key = key;
      if (pfx !== undefined) presented.pfx = pfx;
      if (passphrase !== undefined) presented.passphrase = passphrase;
      return logon.tlsMaterial(presented);
    });
  }

  /** The usual choice: PEM or PFX files named in the config. */
  static fromFiles(config: ISapConfig): CertificateAuthProvider {
    return new CertificateAuthProvider(new FileCertificateMaterialLoader(), config);
  }

  async authorize(_request: IRequestTarget): Promise<AuthOutcome> {
    return OK;
  }

  async rejected(_rejection: IAuthRejection): Promise<AuthOutcome> {
    return oops(
      'the client certificate was refused',
      'check that it is mapped to a user (CERTRULE / USREXTID)',
    );
  }
}
```

- [ ] **Step 4: Run to see it pass**

Run: `npm test -- src/__tests__/credentials/credentials.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/credentials src/__tests__/credentials
git commit -m "feat: Basic, SAML, Token and Certificate providers on the contract (moved from connection)"
```

### Task 7: SNC — library architecture reader

**Files:**
- Create: `src/snc/libraryArchitectures.ts`
- Test: `src/__tests__/snc/libraryArchitectures.test.ts`

**Interfaces:**
- Produces: `type SncArch = 'ia32' | 'x64' | 'arm64'`; `libraryArchitectures(head: Buffer): SncArch[]` (empty when not a recognised library).

- [ ] **Step 1: Write the failing test**

`src/__tests__/snc/libraryArchitectures.test.ts`:

```ts
import { describe, expect, it } from '@jest/globals';
import { libraryArchitectures } from '../../snc/libraryArchitectures';

function pe(machine: number): Buffer {
  const b = Buffer.alloc(0x100);
  b.write('MZ', 0, 'latin1');
  b.writeUInt32LE(0x80, 0x3c);
  b.write('PE\0\0', 0x80, 'latin1');
  b.writeUInt16LE(machine, 0x84);
  return b;
}
function machoThin(cputype: number): Buffer {
  const b = Buffer.alloc(32);
  b.writeUInt32LE(0xfeedfacf, 0);
  b.writeUInt32LE(cputype, 4);
  return b;
}
// FAT_MAGIC: 20-byte fat_arch records; FAT_MAGIC_64: 32-byte fat_arch_64.
function machoFat(cputypes: number[], wide = false): Buffer {
  const width = wide ? 32 : 20;
  const b = Buffer.alloc(8 + cputypes.length * width);
  b.writeUInt32BE(wide ? 0xcafebabf : 0xcafebabe, 0);
  b.writeUInt32BE(cputypes.length, 4);
  cputypes.forEach((c, i) => b.writeUInt32BE(c, 8 + i * width));
  return b;
}
function elf(machine: number): Buffer {
  const b = Buffer.alloc(64);
  b.writeUInt32BE(0x7f454c46, 0);
  b[5] = 1;
  b.writeUInt16LE(machine, 0x12);
  return b;
}

describe('libraryArchitectures', () => {
  it.each([[0x014c, 'ia32'], [0x8664, 'x64'], [0xaa64, 'arm64']])('PE %s → %s', (m, a) => {
    expect(libraryArchitectures(pe(m))).toEqual([a]);
  });
  it.each([[0x01000007, 'x64'], [0x0100000c, 'arm64']])('thin Mach-O %s → %s', (c, a) => {
    expect(libraryArchitectures(machoThin(c))).toEqual([a]);
  });
  it('universal Mach-O (FAT_MAGIC)', () => {
    expect(libraryArchitectures(machoFat([0x01000007, 0x0100000c]))).toEqual(['x64', 'arm64']);
  });
  it('64-bit universal Mach-O (FAT_MAGIC_64)', () => {
    expect(libraryArchitectures(machoFat([0x01000007, 0x0100000c], true))).toEqual(['x64', 'arm64']);
  });
  it('FAT_MAGIC_64 with one architecture is read as what it holds', () => {
    expect(libraryArchitectures(machoFat([0x00000007], true))).toEqual(['ia32']);
  });
  it.each([[0x3e, 'x64'], [0xb7, 'arm64']])('ELF %s → %s', (m, a) => {
    expect(libraryArchitectures(elf(m))).toEqual([a]);
  });
  it('not a library → []', () => {
    expect(libraryArchitectures(Buffer.from('hello, world'))).toEqual([]);
    expect(libraryArchitectures(Buffer.alloc(0))).toEqual([]);
  });
  it('PE header offset past the bytes read → []', () => {
    const b = pe(0x8664);
    b.writeUInt32LE(0x1000, 0x3c);
    expect(libraryArchitectures(b)).toEqual([]);
  });
  it('unknown PE machine → []', () => {
    expect(libraryArchitectures(pe(0x01c4))).toEqual([]);
  });
});
```

- [ ] **Step 2: Run to see it fail** — `npm test -- src/__tests__/snc/libraryArchitectures.test.ts` → FAIL, module not found.

- [ ] **Step 3: Implement**

`src/snc/libraryArchitectures.ts`:

```ts
/**
 * Which architectures a shared library is built for, from its first bytes.
 *
 * The RFC SDK loads the SNC library into this process, and a library of the
 * wrong architecture fails there with nothing but `SNCERR_INIT`. The Secure
 * Login Client installer sets the machine-wide `SNC_LIB` to its x86 library,
 * so a 64-bit Node meets exactly that. Reading the header first turns it into
 * a message naming the file and both architectures.
 */

export type SncArch = 'ia32' | 'x64' | 'arm64';

const PE_MACHINE: Record<number, SncArch> = { 0x014c: 'ia32', 0x8664: 'x64', 0xaa64: 'arm64' };
const MACHO_CPU: Record<number, SncArch> = { 0x00000007: 'ia32', 0x01000007: 'x64', 0x0100000c: 'arm64' };
const ELF_MACHINE: Record<number, SncArch> = { 0x03: 'ia32', 0x3e: 'x64', 0xb7: 'arm64' };

export function libraryArchitectures(head: Buffer): SncArch[] {
  if (head.length >= 0x40 && head.toString('latin1', 0, 2) === 'MZ') {
    const offset = head.readUInt32LE(0x3c);
    if (offset + 6 > head.length || head.toString('latin1', offset, offset + 4) !== 'PE\0\0') {
      return [];
    }
    const arch = PE_MACHINE[head.readUInt16LE(offset + 4)];
    return arch ? [arch] : [];
  }
  if (head.length >= 8) {
    const magicLe = head.readUInt32LE(0);
    if (magicLe === 0xfeedfacf || magicLe === 0xfeedface) {
      const arch = MACHO_CPU[head.readUInt32LE(4)];
      return arch ? [arch] : [];
    }
    const magicBe = head.readUInt32BE(0);
    if (magicBe === 0xcafebabe || magicBe === 0xcafebabf) {
      // FAT_MAGIC: fat_arch is 20 bytes; FAT_MAGIC_64: fat_arch_64 is 32.
      // cputype is the first field of both.
      const width = magicBe === 0xcafebabf ? 32 : 20;
      const count = head.readUInt32BE(4);
      const archs: SncArch[] = [];
      for (let i = 0; i < count && 8 + i * width + 4 <= head.length; i++) {
        const arch = MACHO_CPU[head.readUInt32BE(8 + i * width)];
        if (arch && !archs.includes(arch)) archs.push(arch);
      }
      return archs;
    }
  }
  if (head.length >= 0x14 && head.readUInt32BE(0) === 0x7f454c46) {
    const machine = head[5] === 2 ? head.readUInt16BE(0x12) : head.readUInt16LE(0x12);
    const arch = ELF_MACHINE[machine];
    return arch ? [arch] : [];
  }
  return [];
}
```

- [ ] **Step 4: Run to see it pass** — same command → PASS.

- [ ] **Step 5: Commit** — `git add src/snc/libraryArchitectures.ts src/__tests__/snc/libraryArchitectures.test.ts && git commit -m "feat(snc): read a library's architectures from its header"`

### Task 8: SNC — the machine seam

**Files:**
- Create: `src/snc/SncSystem.ts`, `src/snc/secureLoginClient.ts`, `src/__tests__/snc/fakeSystem.ts`
- Test: `src/__tests__/snc/SncSystem.test.ts`

**Interfaces:**
- Produces: `interface SncSystem { readonly platform: NodeJS.Platform; readonly arch: string; readonly env: Readonly<Record<string, string | undefined>>; readHead(path: string, bytes: number): Promise<Buffer | null>; readRegistryValue(key: string, name: string): Promise<string | undefined>; listProcessNames(): Promise<string[]> }`; `nodeSncSystem(): SncSystem`; internal `parseRegQuery(output, name)`, `parseTasklistCsv(output)`, `parsePsComm(output)`; constants `SECURE_LOGIN_CLIENT = 'SAP Secure Login Client'`, `SLC_REGISTRY_KEY = 'HKLM\\Software\\SAP\\SecureLogin'`, `MACOS_SLC_APP = '/Applications/Secure Login Client.app/'`, `MACOS_SLC_LIBRARY = '/Applications/Secure Login Client.app/Contents/MacOS/lib/libsapcrypto.dylib'`; test helpers `fakeSystem(options)`, `peLibrary(arch: 'ia32' | 'x64')`.

- [ ] **Step 1: Write the failing parser test**

`src/__tests__/snc/SncSystem.test.ts`:

```ts
import { describe, expect, it } from '@jest/globals';
import { parsePsComm, parseRegQuery, parseTasklistCsv } from '../../snc/SncSystem';

describe('parseRegQuery', () => {
  const output = [
    '',
    'HKEY_LOCAL_MACHINE\\Software\\SAP\\SecureLogin',
    '    InstallPath64    REG_SZ    C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\',
    '',
  ].join('\r\n');
  it('reads the value, spaces included, name case-insensitive', () => {
    expect(parseRegQuery(output, 'installpath64')).toBe('C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\');
  });
  it('undefined when absent or when reg reports an error', () => {
    expect(parseRegQuery(output, 'InstallPath32')).toBeUndefined();
    expect(parseRegQuery('ERROR: The system was unable to find the specified registry key or value.', 'InstallPath64')).toBeUndefined();
  });
});

describe('parseTasklistCsv', () => {
  it('takes the image name from each line', () => {
    expect(parseTasklistCsv('"System Idle Process","0","Services","0","8 K"\r\n"sbus.exe","4","Console","1","1 K"\r\n'))
      .toEqual(['System Idle Process', 'sbus.exe']);
  });
});

describe('parsePsComm', () => {
  it('drops the header and blank lines', () => {
    expect(parsePsComm('COMM\n/sbin/launchd\n/Applications/Secure Login Client.app/Contents/MacOS/Secure Login Client\n\n'))
      .toEqual(['/sbin/launchd', '/Applications/Secure Login Client.app/Contents/MacOS/Secure Login Client']);
  });
});
```

- [ ] **Step 2: Run to see it fail** — `npm test -- src/__tests__/snc/SncSystem.test.ts` → FAIL.

- [ ] **Step 3: Implement**

`src/snc/secureLoginClient.ts`:

```ts
/** What this package knows about the SAP Secure Login Client's installation. */
export const SECURE_LOGIN_CLIENT = 'SAP Secure Login Client';
/** Holds InstallPath64 / InstallPath32, each ending in a separator. */
export const SLC_REGISTRY_KEY = 'HKLM\\Software\\SAP\\SecureLogin';
export const MACOS_SLC_APP = '/Applications/Secure Login Client.app/';
export const MACOS_SLC_LIBRARY =
  '/Applications/Secure Login Client.app/Contents/MacOS/lib/libsapcrypto.dylib';
```

`src/snc/SncSystem.ts`:

```ts
/**
 * Everything SNC discovery asks of the machine, behind one seam, so the rules
 * — which library wins, when the Secure Login Client is checked — can be
 * tested with a fake. `nodeSncSystem()` is the real one.
 */

import { execFile } from 'node:child_process';
import { open } from 'node:fs/promises';
import { promisify } from 'node:util';

const run = promisify(execFile);

export interface SncSystem {
  readonly platform: NodeJS.Platform;
  /** `process.arch` — the architecture a library must be built for. */
  readonly arch: string;
  readonly env: Readonly<Record<string, string | undefined>>;
  /** The first `bytes` of a file, or `null` when it cannot be read. */
  readHead(path: string, bytes: number): Promise<Buffer | null>;
  /** A registry value (Windows), or `undefined` when absent or elsewhere. */
  readRegistryValue(key: string, name: string): Promise<string | undefined>;
  /** Running processes' names or paths. Throws when they cannot be listed. */
  listProcessNames(): Promise<string[]>;
}

export function parseRegQuery(output: string, name: string): string | undefined {
  for (const line of output.split(/\r?\n/)) {
    const match = /^\s+(\S.*?)\s+REG_\w+\s+(.*?)\s*$/.exec(line);
    if (match && match[1].toLowerCase() === name.toLowerCase()) return match[2];
  }
  return undefined;
}

export function parseTasklistCsv(output: string): string[] {
  return output
    .split(/\r?\n/)
    .map((line) => /^"([^"]*)"/.exec(line)?.[1])
    .filter((name): name is string => Boolean(name));
}

export function parsePsComm(output: string): string[] {
  return output
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && line !== 'COMM');
}

export function nodeSncSystem(): SncSystem {
  return {
    platform: process.platform,
    arch: process.arch,
    env: process.env,
    async readHead(path, bytes) {
      try {
        const file = await open(path, 'r');
        try {
          const buffer = Buffer.alloc(bytes);
          const { bytesRead } = await file.read(buffer, 0, bytes, 0);
          return buffer.subarray(0, bytesRead);
        } finally {
          await file.close();
        }
      } catch {
        return null;
      }
    },
    async readRegistryValue(key, name) {
      if (process.platform !== 'win32') return undefined;
      try {
        const { stdout } = await run('reg', ['query', key, '/v', name, '/reg:64'], { windowsHide: true });
        return parseRegQuery(stdout, name);
      } catch {
        return undefined;
      }
    },
    async listProcessNames() {
      if (process.platform === 'win32') {
        const { stdout } = await run('tasklist', ['/FO', 'CSV', '/NH'], { windowsHide: true });
        return parseTasklistCsv(stdout);
      }
      const { stdout } = await run('ps', ['-Ao', 'comm']);
      return parsePsComm(stdout);
    },
  };
}
```

`src/__tests__/snc/fakeSystem.ts`:

```ts
import type { SncSystem } from '../../snc/SncSystem';

export interface FakeSystemOptions {
  platform?: NodeJS.Platform;
  arch?: string;
  env?: Record<string, string | undefined>;
  /** Path → file head. A path not here cannot be read. */
  files?: Record<string, Buffer>;
  /** "<key>\\<name>" → value. */
  registry?: Record<string, string>;
  /** The process list, or the error listing it throws. */
  processes?: string[] | Error;
}

export function fakeSystem(options: FakeSystemOptions = {}): SncSystem {
  return {
    platform: options.platform ?? 'win32',
    arch: options.arch ?? 'x64',
    env: options.env ?? {},
    async readHead(path) {
      return options.files?.[path] ?? null;
    },
    async readRegistryValue(key, name) {
      return options.registry?.[`${key}\\${name}`];
    },
    async listProcessNames() {
      if (options.processes instanceof Error) throw options.processes;
      return options.processes ?? [];
    },
  };
}

export function peLibrary(arch: 'ia32' | 'x64'): Buffer {
  const b = Buffer.alloc(0x100);
  b.write('MZ', 0, 'latin1');
  b.writeUInt32LE(0x80, 0x3c);
  b.write('PE\0\0', 0x80, 'latin1');
  b.writeUInt16LE(arch === 'x64' ? 0x8664 : 0x014c, 0x84);
  return b;
}
```

- [ ] **Step 4: Run to see it pass** — same command → PASS.

- [ ] **Step 5: Commit** — `git add src/snc/SncSystem.ts src/snc/secureLoginClient.ts src/__tests__/snc && git commit -m "feat(snc): the machine seam and its parsers"`

### Task 9: SNC — library discovery

**Files:**
- Create: `src/snc/DefaultSncLibraryLocator.ts`
- Test: `src/__tests__/snc/DefaultSncLibraryLocator.test.ts`

**Interfaces:**
- Consumes: `SncSystem`, `libraryArchitectures`, `SncArch`, `SLC_REGISTRY_KEY`, `MACOS_SLC_LIBRARY`, `ValidationError`; `fakeSystem`, `peLibrary`.
- Produces: `interface SncLibrary { path: string; archs: SncArch[] }`; `interface ISncLibraryLocator { locate(): Promise<SncLibrary> }` (throws `ValidationError` with `missingFields: ['sncLib']` when nothing is usable); `class DefaultSncLibraryLocator` with `constructor(system: SncSystem, explicit?: string)`.

- [ ] **Step 1: Write the failing test**

`src/__tests__/snc/DefaultSncLibraryLocator.test.ts`:

```ts
import { describe, expect, it } from '@jest/globals';
import { ValidationError } from '../../errors/TokenProviderErrors';
import { DefaultSncLibraryLocator } from '../../snc/DefaultSncLibraryLocator';
import { fakeSystem, peLibrary } from './fakeSystem';

const X64 = 'C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\lib\\sapcrypto.dll';
const X86 = 'C:\\Program Files (x86)\\SAP\\FrontEnd\\SecureLogin\\lib\\sapcrypto.dll';
const REGISTRY = {
  'HKLM\\Software\\SAP\\SecureLogin\\InstallPath64': 'C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\',
  'HKLM\\Software\\SAP\\SecureLogin\\InstallPath32': 'C:\\Program Files (x86)\\SAP\\FrontEnd\\SecureLogin\\',
};
const FILES = { [X64]: peLibrary('x64'), [X86]: peLibrary('ia32') };
const DYLIB = '/Applications/Secure Login Client.app/Contents/MacOS/lib/libsapcrypto.dylib';
function fat64(cputypes: number[]): Buffer {
  const b = Buffer.alloc(8 + cputypes.length * 32);
  b.writeUInt32BE(0xcafebabf, 0);
  b.writeUInt32BE(cputypes.length, 4);
  cputypes.forEach((c, i) => b.writeUInt32BE(c, 8 + i * 32));
  return b;
}

describe('explicit sncLib', () => {
  it('returned when usable', async () => {
    await expect(new DefaultSncLibraryLocator(fakeSystem({ files: FILES }), X64).locate())
      .resolves.toEqual({ path: X64, archs: ['x64'] });
  });
  it('wrong architecture fails, nothing else tried', async () => {
    const locate = new DefaultSncLibraryLocator(fakeSystem({ files: FILES, registry: REGISTRY }), X86).locate();
    await expect(locate).rejects.toThrow(/built for ia32, this process is x64/);
  });
  it('missing file fails as a ValidationError on sncLib', async () => {
    const error = await new DefaultSncLibraryLocator(fakeSystem(), 'C:\\nope.dll').locate().catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ValidationError);
    expect((error as ValidationError).missingFields).toEqual(['sncLib']);
    expect((error as Error).message).toMatch(/C:\\nope\.dll: not found/);
  });
});

describe('automatic discovery', () => {
  it('the measured mix: no SNC_LIB_64, x86 SNC_LIB, x64 in the registry → the registry library', async () => {
    await expect(new DefaultSncLibraryLocator(fakeSystem({ env: { SNC_LIB: X86 }, files: FILES, registry: REGISTRY })).locate())
      .resolves.toEqual({ path: X64, archs: ['x64'] });
  });
  it('prefers SNC_LIB_64 in a 64-bit process', async () => {
    const other = 'D:\\snc\\sapcrypto.dll';
    await expect(new DefaultSncLibraryLocator(fakeSystem({ env: { SNC_LIB_64: other, SNC_LIB: X86 }, files: { ...FILES, [other]: peLibrary('x64') }, registry: REGISTRY })).locate())
      .resolves.toMatchObject({ path: other });
  });
  it('ignores SNC_LIB_64 in a 32-bit process and takes InstallPath32', async () => {
    await expect(new DefaultSncLibraryLocator(fakeSystem({ arch: 'ia32', env: { SNC_LIB_64: X64 }, files: FILES, registry: REGISTRY })).locate())
      .resolves.toEqual({ path: X86, archs: ['ia32'] });
  });
  it('empty or whitespace variables count as unset', async () => {
    await expect(new DefaultSncLibraryLocator(fakeSystem({ env: { SNC_LIB_64: '  ', SNC_LIB: '' }, files: FILES, registry: REGISTRY })).locate())
      .resolves.toMatchObject({ path: X64 });
  });
  it('an absent registry value is skipped', async () => {
    const other = 'D:\\snc\\sapcrypto.dll';
    await expect(new DefaultSncLibraryLocator(fakeSystem({ env: { SNC_LIB: other }, files: { [other]: peLibrary('x64') } })).locate())
      .resolves.toMatchObject({ path: other });
  });
  it('macOS: FAT_MAGIC_64 holding the process architecture is accepted', async () => {
    await expect(new DefaultSncLibraryLocator(fakeSystem({ platform: 'darwin', arch: 'arm64', files: { [DYLIB]: fat64([0x01000007, 0x0100000c]) } })).locate())
      .resolves.toEqual({ path: DYLIB, archs: ['x64', 'arm64'] });
  });
  it('macOS: FAT_MAGIC_64 without it is skipped, naming what it holds', async () => {
    await expect(new DefaultSncLibraryLocator(fakeSystem({ platform: 'darwin', arch: 'arm64', files: { [DYLIB]: fat64([0x01000007]) } })).locate())
      .rejects.toThrow(/built for x64, this process is arm64/);
  });
  it('nothing usable: one error listing every candidate', async () => {
    const error = await new DefaultSncLibraryLocator(fakeSystem({ env: { SNC_LIB: X86 }, files: { [X86]: peLibrary('ia32') } })).locate().catch((e: unknown) => e);
    expect((error as ValidationError).missingFields).toEqual(['sncLib']);
    expect((error as Error).message).toMatch(/SNC_LIB .*sapcrypto\.dll: built for ia32, this process is x64/);
  });
  it('no candidate at all says so', async () => {
    await expect(new DefaultSncLibraryLocator(fakeSystem({ platform: 'linux' })).locate()).rejects.toThrow(/No candidate/);
  });
});
```

- [ ] **Step 2: Run to see it fail** — `npm test -- src/__tests__/snc/DefaultSncLibraryLocator.test.ts` → FAIL.

- [ ] **Step 3: Implement**

`src/snc/DefaultSncLibraryLocator.ts`:

```ts
/**
 * Where the SNC library is.
 *
 * An explicit `sncLib` is the caller's decision: the only candidate, and an
 * unusable one fails naming the path and the reason. Without it, candidates
 * are tried in order and an unusable one is skipped with its reason kept:
 * the installer's machine-wide x86 `SNC_LIB` must not hide the x64 library
 * the registry points at.
 */

import { win32 } from 'node:path';
import { ValidationError } from '../errors/TokenProviderErrors';
import { libraryArchitectures, type SncArch } from './libraryArchitectures';
import type { SncSystem } from './SncSystem';
import { MACOS_SLC_LIBRARY, SLC_REGISTRY_KEY } from './secureLoginClient';

export interface SncLibrary {
  path: string;
  archs: SncArch[];
}

export interface ISncLibraryLocator {
  locate(): Promise<SncLibrary>;
}

const HEAD_BYTES = 4096;

export class DefaultSncLibraryLocator implements ISncLibraryLocator {
  constructor(
    private readonly system: SncSystem,
    private readonly explicit?: string,
  ) {}

  async locate(): Promise<SncLibrary> {
    const explicit = this.explicit?.trim();
    if (explicit) {
      const result = await this.inspect(explicit);
      if ('reason' in result) {
        throw new ValidationError(`sncLib ${explicit}: ${result.reason}`, ['sncLib']);
      }
      return result;
    }
    const skipped: string[] = [];
    for (const candidate of await this.candidates()) {
      const result = await this.inspect(candidate.path);
      if (!('reason' in result)) return result;
      skipped.push(`${candidate.source} ${candidate.path}: ${result.reason}`);
    }
    const detail = skipped.length
      ? ['Tried:', ...skipped.map((line) => `  - ${line}`)]
      : ['No candidate: SNC_LIB_64 and SNC_LIB are unset and no Secure Login Client installation was found.'];
    throw new ValidationError(
      ['No usable SNC library found. Set sncLib to the SNC (GSS) library of your SNC product.', ...detail].join('\n'),
      ['sncLib'],
    );
  }

  private async candidates(): Promise<{ source: string; path: string }[]> {
    const { system } = this;
    const is64 = system.arch === 'x64' || system.arch === 'arm64';
    const variable = (name: string) => system.env[name]?.trim() || undefined;
    const found: { source: string; path: string }[] = [];
    const lib64 = variable('SNC_LIB_64');
    if (is64 && lib64) found.push({ source: 'SNC_LIB_64', path: lib64 });
    const lib = variable('SNC_LIB');
    if (lib) found.push({ source: 'SNC_LIB', path: lib });
    if (system.platform === 'win32') {
      const name = is64 ? 'InstallPath64' : 'InstallPath32';
      const dir = (await system.readRegistryValue(SLC_REGISTRY_KEY, name))?.trim();
      if (dir) found.push({ source: `registry ${name}`, path: win32.join(dir, 'lib', 'sapcrypto.dll') });
    }
    if (system.platform === 'darwin') {
      found.push({ source: 'Secure Login Client default', path: MACOS_SLC_LIBRARY });
    }
    return found;
  }

  private async inspect(path: string): Promise<SncLibrary | { reason: string }> {
    const head = await this.system.readHead(path, HEAD_BYTES);
    if (!head) return { reason: 'not found or not readable' };
    const archs = libraryArchitectures(head);
    if (archs.length === 0) return { reason: 'not a recognised library (PE, Mach-O or ELF)' };
    if (!archs.includes(this.system.arch as SncArch)) {
      return { reason: `built for ${archs.join('/')}, this process is ${this.system.arch}` };
    }
    return { path, archs };
  }
}
```

- [ ] **Step 4: Run to see it pass** — same command → PASS.
- [ ] **Step 5: Load-bearing** — replace `skipped.push(...)` with `throw new ValidationError(result.reason, ['sncLib']);` → "the measured mix" FAILS. Revert.
- [ ] **Step 6: Commit** — `git add src/snc/DefaultSncLibraryLocator.ts src/__tests__/snc/DefaultSncLibraryLocator.test.ts && git commit -m "feat(snc): find the library — explicit fails loudly, discovery skips the unusable"`

### Task 10: SNC — the Secure Login Client probe

**Files:**
- Create: `src/snc/SecureLoginClientProbe.ts`
- Test: `src/__tests__/snc/SecureLoginClientProbe.test.ts`

**Interfaces:**
- Consumes: `SncSystem`, `SECURE_LOGIN_CLIENT`, `SLC_REGISTRY_KEY`, `MACOS_SLC_APP`, `ValidationError`; `fakeSystem`.
- Produces: `interface ISncProductProbe { readonly product: string; appliesTo(libraryPath: string): Promise<boolean>; check(): Promise<void> }` (`check` throws `ValidationError`); `class SecureLoginClientProbe implements ISncProductProbe` with `constructor(system: SncSystem)`.

- [ ] **Step 1: Write the failing test**

`src/__tests__/snc/SecureLoginClientProbe.test.ts`:

```ts
import { describe, expect, it } from '@jest/globals';
import { SecureLoginClientProbe } from '../../snc/SecureLoginClientProbe';
import { fakeSystem } from './fakeSystem';

const REGISTRY = {
  'HKLM\\Software\\SAP\\SecureLogin\\InstallPath64': 'C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\',
  'HKLM\\Software\\SAP\\SecureLogin\\InstallPath32': 'C:\\Program Files (x86)\\SAP\\FrontEnd\\SecureLogin\\',
};

describe('appliesTo', () => {
  const probe = new SecureLoginClientProbe(fakeSystem({ registry: REGISTRY }));
  it.each([
    'C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\lib\\sapcrypto.dll',
    'C:\\PROGRAM FILES\\SAP\\FrontEnd\\SecureLogin\\lib\\sapcrypto.dll',
    'C:\\Program Files (x86)\\SAP\\FrontEnd\\SecureLogin\\lib\\sapcrypto.dll',
  ])('applies to %s', async (p) => {
    await expect(probe.appliesTo(p)).resolves.toBe(true);
  });
  it.each([
    'C:\\Windows\\System32\\gsskrb5.dll',
    'C:\\Program Files\\SAP\\FrontEnd\\SecureLoginOther\\sapcrypto.dll',
  ])('not to %s', async (p) => {
    await expect(probe.appliesTo(p)).resolves.toBe(false);
  });
  it('to nothing when the client is not installed', async () => {
    await expect(new SecureLoginClientProbe(fakeSystem()).appliesTo('C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\lib\\sapcrypto.dll')).resolves.toBe(false);
  });
  it('to the app bundle on macOS', async () => {
    const mac = new SecureLoginClientProbe(fakeSystem({ platform: 'darwin' }));
    await expect(mac.appliesTo('/Applications/Secure Login Client.app/Contents/MacOS/lib/libsapcrypto.dylib')).resolves.toBe(true);
    await expect(mac.appliesTo('/usr/lib/libgssapi_krb5.dylib')).resolves.toBe(false);
  });
});

describe('check', () => {
  it('passes when sbus.exe runs, any case', async () => {
    await expect(new SecureLoginClientProbe(fakeSystem({ processes: ['SBUS.EXE'] })).check()).resolves.toBeUndefined();
  });
  it('fails when only sbusagent.exe runs', async () => {
    await expect(new SecureLoginClientProbe(fakeSystem({ processes: ['sbusagent.exe'] })).check()).rejects.toThrow(/not running .*sbus\.exe/);
  });
  it('an unreadable process list says the check could not run, without the tool’s message', async () => {
    const error = await new SecureLoginClientProbe(fakeSystem({ processes: new Error('access denied SECRET-TOOL') })).check().catch((e: unknown) => e);
    expect((error as Error).message).toMatch(/Could not check whether the SAP Secure Login Client is running/);
    expect((error as Error).message).not.toMatch(/SECRET-TOOL/);
  });
  it('macOS looks for the app bundle', async () => {
    await expect(new SecureLoginClientProbe(fakeSystem({ platform: 'darwin', processes: ['/Applications/Secure Login Client.app/Contents/MacOS/Secure Login Client'] })).check()).resolves.toBeUndefined();
    await expect(new SecureLoginClientProbe(fakeSystem({ platform: 'darwin', processes: ['/sbin/launchd'] })).check()).rejects.toThrow(/not running/);
  });
});
```

- [ ] **Step 2: Run to see it fail** — `npm test -- src/__tests__/snc/SecureLoginClientProbe.test.ts` → FAIL.

- [ ] **Step 3: Implement**

`src/snc/SecureLoginClientProbe.ts`:

```ts
/**
 * Is the SNC product behind a library ready? A probe applies only to a library
 * it recognises — this one to a library inside the Secure Login Client's
 * installation — so another SNC product is never refused for lacking a
 * process it does not have. It checks that the client runs, not that a
 * profile is logged on: no documented interface says so.
 */

import { win32 } from 'node:path';
import { ValidationError } from '../errors/TokenProviderErrors';
import type { SncSystem } from './SncSystem';
import { MACOS_SLC_APP, SECURE_LOGIN_CLIENT, SLC_REGISTRY_KEY } from './secureLoginClient';

export interface ISncProductProbe {
  readonly product: string;
  appliesTo(libraryPath: string): Promise<boolean>;
  /** Throws when the product is not usable. */
  check(): Promise<void>;
}

function asDirectory(path: string): string {
  const normal = win32.normalize(path.trim()).toLowerCase();
  return normal.endsWith('\\') ? normal : `${normal}\\`;
}

export class SecureLoginClientProbe implements ISncProductProbe {
  readonly product = SECURE_LOGIN_CLIENT;

  constructor(private readonly system: SncSystem) {}

  async appliesTo(libraryPath: string): Promise<boolean> {
    const { system } = this;
    if (system.platform === 'win32') {
      const dirs = await Promise.all(
        ['InstallPath64', 'InstallPath32'].map((name) => system.readRegistryValue(SLC_REGISTRY_KEY, name)),
      );
      const library = win32.normalize(libraryPath.trim()).toLowerCase();
      return dirs.some((dir) => typeof dir === 'string' && dir.trim() !== '' && library.startsWith(asDirectory(dir)));
    }
    if (system.platform === 'darwin') return libraryPath.startsWith(MACOS_SLC_APP);
    return false;
  }

  async check(): Promise<void> {
    let names: string[];
    try {
      names = await this.system.listProcessNames();
    } catch {
      // The listing tool's own message is foreign text; it stays out.
      throw new ValidationError(
        `Could not check whether the ${SECURE_LOGIN_CLIENT} is running (the process list could not be read).`,
      );
    }
    const windows = this.system.platform === 'win32';
    const running = windows
      ? names.some((name) => name.toLowerCase() === 'sbus.exe')
      : names.some((name) => name.startsWith(MACOS_SLC_APP));
    if (!running) {
      throw new ValidationError(
        `The ${SECURE_LOGIN_CLIENT} is not running (${windows ? 'sbus.exe' : 'Secure Login Client.app'} not found).`,
      );
    }
  }
}
```

- [ ] **Step 4: Run to see it pass** — same command → PASS.
- [ ] **Step 5: Commit** — `git add src/snc/SecureLoginClientProbe.ts src/__tests__/snc/SecureLoginClientProbe.test.ts && git commit -m "feat(snc): probe the Secure Login Client, only for its own library"`

### Task 11: `SncLogonProvider`

**Files:**
- Create: `src/snc/sncRefusal.ts`, `src/snc/SncLogonProvider.ts`
- Test: `src/__tests__/snc/SncLogonProvider.test.ts`

**Interfaces:**
- Consumes: Task 1 (`OK`, `oops`, `safely`, `KNOWN_RFC_KEYS`), Tasks 8–10.
- Produces: `sncRefusal(error: unknown, context: { library?: SncLibrary; product?: string }): IAuthRefusal`; `interface SncLogonProviderConfig { partnerName: string; qop?: string; myName?: string; locator: ISncLibraryLocator; probes: ISncProductProbe[]; logger?: ILogger }`; `class SncLogonProvider implements IAuthProvider` with `static forSecureLoginClient(options: { partnerName: string; qop?: string; sncLib?: string; myName?: string; logger?: ILogger }): SncLogonProvider`.

- [ ] **Step 1: Write the failing test** — `src/__tests__/snc/SncLogonProvider.test.ts`:

```ts
import { describe, expect, it } from '@jest/globals';
import { ValidationError } from '../../errors/TokenProviderErrors';
import { DefaultSncLibraryLocator } from '../../snc/DefaultSncLibraryLocator';
import { SecureLoginClientProbe } from '../../snc/SecureLoginClientProbe';
import { SncLogonProvider } from '../../snc/SncLogonProvider';
import type { SncSystem } from '../../snc/SncSystem';
import { recordingTargets } from '../helpers/targets';
import { fakeSystem, peLibrary } from './fakeSystem';

const SLC = 'C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\lib\\sapcrypto.dll';
const KRB = 'C:\\Windows\\System32\\gsskrb5.dll';
const REGISTRY = { 'HKLM\\Software\\SAP\\SecureLogin\\InstallPath64': 'C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\' };
const machine = (processes: string[]) =>
  fakeSystem({ files: { [SLC]: peLibrary('x64'), [KRB]: peLibrary('x64') }, registry: REGISTRY, processes });
/** What forSecureLoginClient assembles, on a fake machine. */
const snc = (system: SncSystem, extra: { sncLib?: string; qop?: string; myName?: string } = {}) =>
  new SncLogonProvider({
    partnerName: 'p:CN=SID',
    qop: extra.qop,
    myName: extra.myName,
    locator: new DefaultSncLibraryLocator(system, extra.sncLib),
    probes: [new SecureLoginClientProbe(system)],
  });
const sdkError = {
  name: 'RfcLibError',
  message: '\nERROR       GSS-API(maj): Miscellaneous failure\n            GSS-API(min): A2200019:Operation aborted by user or\n',
};

describe('construction', () => {
  const parts = (s: SncSystem) => ({ locator: new DefaultSncLibraryLocator(s), probes: [] });
  it('requires partnerName', () => {
    expect(() => new SncLogonProvider({ partnerName: ' ', ...parts(machine([])) })).toThrow(ValidationError);
  });
  it.each(['0', '4', '5', '6', '7', '10', 'max', ''])('refuses qop %p', (qop) => {
    expect(() => new SncLogonProvider({ partnerName: 'p:CN=SID', qop, ...parts(machine([])) })).toThrow(/qop/);
  });
  it.each(['1', '2', '3', '8', '9'])('accepts qop %p', (qop) => {
    expect(() => new SncLogonProvider({ partnerName: 'p:CN=SID', qop, ...parts(machine([])) })).not.toThrow();
  });
  it('locator and probes are required (compile-time)', () => {
    // @ts-expect-error locator and probes are required
    expect(() => new SncLogonProvider({ partnerName: 'p:CN=SID' })).toBeDefined();
  });
  it('forSecureLoginClient assembles the locator and the Secure Login Client probe', () => {
    const p = SncLogonProvider.forSecureLoginClient({ partnerName: 'p:CN=SID' }) as unknown as { locator: unknown; probes: unknown[] };
    expect(p.locator).toBeInstanceOf(DefaultSncLibraryLocator);
    expect(p.probes).toHaveLength(1);
    expect(p.probes[0]).toBeInstanceOf(SecureLoginClientProbe);
  });
});

describe('the four moments', () => {
  it('prepare → establish writes the SNC parameters, no user or passwd', async () => {
    const p = snc(machine(['sbus.exe']));
    await expect(p.prepare()).resolves.toEqual({ ok: true });
    const t = recordingTargets();
    await expect(p.establish(t.logonTarget)).resolves.toEqual({ ok: true });
    expect(t.logon.params).toEqual([{ snc_mode: '1', snc_partnername: 'p:CN=SID', snc_qop: '9', snc_lib: SLC }]);
    await expect(p.authorize(t.requestTarget)).resolves.toEqual({ ok: true });
    expect(t.request).toEqual({ headers: {}, cookies: [] });
  });
  it('snc_myname only when configured', async () => {
    const p = snc(machine(['sbus.exe']), { myName: 'p:CN=ME', qop: '8' });
    await p.prepare();
    const t = recordingTargets();
    await p.establish(t.logonTarget);
    expect(t.logon.params[0]).toMatchObject({ snc_myname: 'p:CN=ME', snc_qop: '8' });
  });
  it('an HTTP wire: the target Oops is SNC’s own', async () => {
    const p = snc(machine(['sbus.exe']));
    await p.prepare();
    await expect(p.establish(recordingTargets({ acceptsLogonParameters: false }).logonTarget))
      .resolves.toMatchObject({ ok: false, refusal: { reason: 'this wire does not take logon parameters' } });
  });
  it('a throwing target is an Oops', async () => {
    const p = snc(machine(['sbus.exe']));
    await p.prepare();
    const outcome = await p.establish(recordingTargets({ throws: true }).logonTarget);
    expect(outcome.ok).toBe(false);
    expect(JSON.stringify(outcome)).not.toMatch(/SECRET-IN-TARGET/);
  });
  it('establish before prepare is an Oops', async () => {
    await expect(snc(machine(['sbus.exe'])).establish(recordingTargets().logonTarget)).resolves.toMatchObject({ ok: false });
  });
  it('SLC library, client not running → fixed reason and hint', async () => {
    await expect(snc(machine([])).prepare()).resolves.toEqual({
      ok: false,
      refusal: {
        reason: 'the SAP Secure Login Client is not running or could not be checked',
        hint: 'Start the SAP Secure Login Client and log on to the profile used for SAP applications',
      },
    });
  });
  it('non-SLC library, no SLC process → Ok, no probe', async () => {
    await expect(snc(machine([]), { sncLib: KRB }).prepare()).resolves.toEqual({ ok: true });
  });
  it('no usable library → fixed reason naming sncLib in the hint; the candidates go to the log only', async () => {
    const outcome = await snc(fakeSystem({ platform: 'linux' })).prepare();
    expect(outcome).toEqual({
      ok: false,
      refusal: {
        reason: 'no usable SNC library was found',
        hint: 'set sncLib to the SNC (GSS) library of your SNC product; the log lists every candidate tried',
      },
    });
  });
  it('a custom locator throwing a foreign error lends no message', async () => {
    const p = new SncLogonProvider({
      partnerName: 'p:CN=SID',
      locator: { locate: async () => { throw new Error('vault said SECRET-VAULT'); } },
      probes: [],
    });
    expect(JSON.stringify(await p.prepare())).not.toMatch(/SECRET/);
  });
});

describe('rejected', () => {
  it.each([
    ['the SDK object', sdkError],
    ['an Error', new Error(`Failed to open RFC connection: ${JSON.stringify(sdkError)}`)],
    ['a string', 'GSS-API(min): A2200019:Operation aborted'],
  ])('A2200019 in %s → log on in the Secure Login Client', async (_, error) => {
    const p = snc(machine(['sbus.exe']));
    await p.prepare();
    await expect(p.rejected({ at: 'logon', error })).resolves.toMatchObject({
      ok: false,
      refusal: { hint: expect.stringMatching(/log on in the Secure Login Client/) },
    });
  });
  it('another library: names it, not the Secure Login Client', async () => {
    const p = snc(machine([]), { sncLib: KRB });
    await p.prepare();
    const outcome = JSON.stringify(await p.rejected({ at: 'logon', error: sdkError }));
    expect(outcome).toMatch(/gsskrb5\.dll/);
    expect(outcome).not.toMatch(/Secure Login Client/);
  });
  it('SNCERR_INIT names the library and its architecture', async () => {
    const p = snc(machine(['sbus.exe']));
    await p.prepare();
    await expect(p.rejected({ at: 'logon', error: new Error('SNCERR_INIT, gssapi library invalid/missing') }))
      .resolves.toMatchObject({ ok: false, refusal: { reason: expect.stringMatching(/sapcrypto\.dll \(x64\)/) } });
  });
  it('anything else: fixed reason, an allowlisted key only', async () => {
    const p = snc(machine(['sbus.exe']));
    await p.prepare();
    await expect(p.rejected({ at: 'logon', error: { key: 'RFC_LOGON_FAILURE', message: 'SECRET-SDK', detail: 'SECRET' } }))
      .resolves.toEqual({ ok: false, refusal: { reason: 'SNC logon refused (RFC_LOGON_FAILURE)' } });
    await expect(p.rejected({ at: 'logon', error: { key: 'SECRET_TOKEN_KEY', message: 'x' } }))
      .resolves.toEqual({ ok: false, refusal: { reason: 'SNC logon refused' } });
    await expect(p.rejected({ at: 'logon', error: new Error('SECRET-IN-MESSAGE') }))
      .resolves.toEqual({ ok: false, refusal: { reason: 'SNC logon refused' } });
  });
});
```

- [ ] **Step 2: Run to see it fail** — `npm test -- src/__tests__/snc/SncLogonProvider.test.ts` → FAIL.

- [ ] **Step 3: Implement** — `src/snc/sncRefusal.ts`:

```ts
/**
 * What a refused SNC logon means. The RFC SDK reports both common failures as
 * a generic communication error; the cause is in the GSS text. Measured:
 * `A2200019` — no credential to present; `SNCERR_INIT` — the library could not
 * be loaded. The text is searched, never copied: only fixed wording, the
 * library this provider resolved, and an allowlisted SDK key go out (rule 2).
 */

import type { IAuthRefusal } from '@mcp-abap-adt/interfaces-auth';
import { KNOWN_RFC_KEYS } from '../auth/refusal';
import type { SncLibrary } from './DefaultSncLibraryLocator';
import { SECURE_LOGIN_CLIENT } from './secureLoginClient';

/** The text to search for GSS codes — never returned. */
function searchable(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === 'string') return error;
  const text = (error as { message?: unknown } | null)?.message;
  return typeof text === 'string' ? text : '';
}

function sdkKey(error: unknown): string {
  const key = (error as { key?: unknown } | null)?.key;
  return typeof key === 'string' && KNOWN_RFC_KEYS.has(key) ? ` (${key})` : '';
}

export function sncRefusal(
  error: unknown,
  context: { library?: SncLibrary; product?: string },
): IAuthRefusal {
  const text = searchable(error);
  const library = context.library
    ? `${context.library.path} (${context.library.archs.join('/')})`
    : 'the SNC library';
  if (/A2200019/.test(text)) {
    return {
      reason: 'the SNC library has no credential to present (A2200019)',
      hint:
        context.product === SECURE_LOGIN_CLIENT
          ? 'log on in the Secure Login Client, to the profile used for SAP applications'
          : `make sure the SNC product behind ${library} is logged on`,
    };
  }
  if (/SNCERR_INIT|gssapi library invalid\/missing/i.test(text)) {
    return { reason: `the RFC SDK could not initialise ${library} as its SNC library (SNCERR_INIT)` };
  }
  return { reason: `SNC logon refused${sdkKey(error)}` };
}
```

`src/snc/SncLogonProvider.ts`:

```ts
/**
 * Passwordless RFC logon through an installed SNC product. The SNC library
 * authenticates during the RFC logon itself; this provider finds it (through
 * the locator it is given), checks the product when a probe applies, and hands
 * the wire the logon parameters. It opens no connection and loads no SAP
 * library. No collaborator is defaulted: forSecureLoginClient is the recipe.
 */

import type {
  AuthOutcome,
  IAuthProvider,
  IAuthRejection,
  ILogonTarget,
  IRequestTarget,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { OK, oops, safely } from '../auth/refusal';
import { ValidationError } from '../errors/TokenProviderErrors';
import { DefaultSncLibraryLocator, type ISncLibraryLocator, type SncLibrary } from './DefaultSncLibraryLocator';
import { type ISncProductProbe, SecureLoginClientProbe } from './SecureLoginClientProbe';
import { nodeSncSystem } from './SncSystem';
import { sncRefusal } from './sncRefusal';

/** SAP's SNC_QOP values: 1 authentication, 2 integrity, 3 privacy, 8 default, 9 maximum. */
const SNC_QOP_VALUES = ['1', '2', '3', '8', '9'];

export interface SncLogonProviderConfig {
  /** The system's SNC name, e.g. `p:CN=SID, O=ACME`. */
  partnerName: string;
  /** `'1' | '2' | '3' | '8' | '9'`; default `'9'` (maximum available). */
  qop?: string;
  /** Sent as `snc_myname` only when set. */
  myName?: string;
  /** Where the SNC library is. Required. */
  locator: ISncLibraryLocator;
  /** Product checks; `[]` for none. Required. */
  probes: ISncProductProbe[];
  logger?: ILogger;
}

const detail = (error: unknown) => (error instanceof Error ? error.message : String(error));

export class SncLogonProvider implements IAuthProvider {
  readonly kind = 'snc';
  private readonly partnerName: string;
  private readonly qop: string;
  private readonly myName?: string;
  private readonly locator: ISncLibraryLocator;
  private readonly probes: ISncProductProbe[];
  private readonly logger?: ILogger;
  private library?: SncLibrary;
  private product?: string;

  constructor(config: SncLogonProviderConfig) {
    const partnerName = config.partnerName?.trim();
    if (!partnerName) {
      throw new ValidationError('SncLogonProvider needs partnerName — the system’s SNC name.', ['partnerName']);
    }
    const qop = config.qop ?? '9';
    if (!SNC_QOP_VALUES.includes(qop)) {
      throw new ValidationError(`SncLogonProvider: qop must be one of ${SNC_QOP_VALUES.join(', ')}, got '${qop}'.`, ['qop']);
    }
    this.partnerName = partnerName;
    this.qop = qop;
    this.myName = config.myName?.trim() || undefined;
    this.locator = config.locator;
    this.probes = config.probes;
    this.logger = config.logger;
  }

  /** The usual choice: this machine, library discovery, the Secure Login Client probe. */
  static forSecureLoginClient(options: {
    partnerName: string;
    qop?: string;
    sncLib?: string;
    myName?: string;
    logger?: ILogger;
  }): SncLogonProvider {
    const system = nodeSncSystem();
    return new SncLogonProvider({
      partnerName: options.partnerName,
      qop: options.qop,
      myName: options.myName,
      logger: options.logger,
      locator: new DefaultSncLibraryLocator(system, options.sncLib),
      probes: [new SecureLoginClientProbe(system)],
    });
  }

  async prepare(): Promise<AuthOutcome> {
    let library: SncLibrary;
    try {
      library = await this.locator.locate();
    } catch (error) {
      this.logger?.warn(`SNC library not found: ${detail(error)}`);
      return oops(
        'no usable SNC library was found',
        'set sncLib to the SNC (GSS) library of your SNC product; the log lists every candidate tried',
      );
    }
    let product: string | undefined;
    for (const probe of this.probes) {
      try {
        if (!(await probe.appliesTo(library.path))) continue;
        await probe.check();
        product = probe.product;
        break;
      } catch (error) {
        this.logger?.warn(`${probe.product} check failed: ${detail(error)}`);
        return oops(
          `the ${probe.product} is not running or could not be checked`,
          `Start the ${probe.product} and log on to the profile used for SAP applications`,
        );
      }
    }
    this.library = library;
    this.product = product;
    this.logger?.debug(`SNC library ${library.path} (${library.archs.join('/')})${product ? `, ${product} running` : ', no product check'}`);
    return OK;
  }

  /** No other way in: the wire's answer is this provider's own. */
  async establish(logon: ILogonTarget): Promise<AuthOutcome> {
    const library = this.library;
    if (!library) return oops('the SNC provider is not prepared', 'connect() prepares it first');
    return safely('handing over the SNC logon parameters', () => {
      const params: Record<string, string> = {
        snc_mode: '1',
        snc_partnername: this.partnerName,
        snc_qop: this.qop,
        snc_lib: library.path,
      };
      if (this.myName) params.snc_myname = this.myName;
      return logon.logonParameters(params);
    });
  }

  async authorize(_request: IRequestTarget): Promise<AuthOutcome> {
    return OK;
  }

  async rejected(rejection: IAuthRejection): Promise<AuthOutcome> {
    return safely('explaining the SNC refusal', () => ({
      ok: false,
      refusal: sncRefusal(rejection.error, { library: this.library, product: this.product }),
    }));
  }
}
```

- [ ] **Step 4: Run to see it pass** — same command → PASS.
- [ ] **Step 5: Load-bearing** — in `prepare()`, drop the `appliesTo` condition → "non-SLC library, no SLC process" FAILS. Revert. Make `sdkKey` accept any `/^[A-Z_]+$/` → the `SECRET_TOKEN_KEY` case FAILS. Revert.
- [ ] **Step 6: Commit** — `git add src/snc/sncRefusal.ts src/snc/SncLogonProvider.ts src/__tests__/snc/SncLogonProvider.test.ts && git commit -m "feat(snc): SncLogonProvider — explicit locator and probes, forSecureLoginClient recipe, fixed refusals"`

### Task 12: Public surface and the whole-package contract test

**Files:**
- Modify: `src/index.ts`, `src/__tests__/exports.test.ts`
- Test: `src/__tests__/contract.test.ts`

**Interfaces:**
- Consumes: every provider and part from Tasks 2–11.

- [ ] **Step 1: Write the failing contract test** — `src/__tests__/contract.test.ts`:

```ts
import { describe, expect, it } from '@jest/globals';
import type { IAuthProvider, IAuthorizationStrategy, ITokenResult, OAuth2GrantType } from '@mcp-abap-adt/interfaces-auth';
import * as surface from '../index';
import { recordingTargets } from './helpers/targets';
import { fakeSystem, peLibrary } from './snc/fakeSystem';

// Every secret below is named SECRET…; no outcome may contain one.
class FailingTokenProvider extends surface.BaseTokenProvider {
  protected async performLogin(): Promise<ITokenResult> { throw new Error('login failed for SECRET-CLIENT'); }
  protected async performRefresh(): Promise<ITokenResult> { throw new Error('refresh failed for SECRET-REFRESH'); }
  protected getAuthType(): OAuth2GrantType { return 'client_credentials'; }
}
const throwingStrategy: IAuthorizationStrategy<string> = {
  authorize: async () => { throw new surface.ValidationError('SECRET-MSG', ['SECRET-FIELD']); },
};
const SLC = 'C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\lib\\sapcrypto.dll';
const system = fakeSystem({ files: { [SLC]: peLibrary('x64') }, registry: { 'HKLM\\Software\\SAP\\SecureLogin\\InstallPath64': 'C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\' }, processes: ['sbus.exe'] });

const providers: [string, IAuthProvider][] = [
  ['basic', new surface.BasicAuthProvider('SECRET-USER', 'SECRET-PW')],
  ['saml cookies', new surface.SamlAuthProvider('MYSAPSSO2=SECRET-COOKIE')],
  ['token fixed', surface.TokenAuthProvider.fixed('SECRET-TOKEN')],
  ['token from', surface.TokenAuthProvider.from({
    getToken: async () => { throw new Error('rejected SECRET-GET'); },
    refreshToken: async () => { throw new Error('rejected SECRET-REFRESH'); },
  })],
  ['certificate', new surface.CertificateAuthProvider({ load: async () => ({ cert: 'C', key: 'K', passphrase: 'SECRET-PP' }) }, { url: 'https://h', authType: 'certificate' })],
  ['token provider (failing)', new FailingTokenProvider()],
  ['authorization code, throwing strategy', new surface.AuthorizationCodeProvider({ uaaUrl: 'https://uaa', clientId: 'c', clientSecret: 'SECRET-CS', authorization: throwingStrategy })],
  ['snc', new surface.SncLogonProvider({
    partnerName: 'p:CN=SID',
    locator: new surface.DefaultSncLibraryLocator(system),
    probes: [new surface.SecureLoginClientProbe(system)],
  })],
];

const isOutcome = (o: unknown) =>
  typeof o === 'object' && o !== null && ((o as { ok: unknown }).ok === true ||
    ((o as { ok: unknown }).ok === false && typeof (o as { refusal: { reason: unknown } }).refusal?.reason === 'string'));

describe.each(providers)('%s answers the whole contract', (_, provider) => {
  it('has a kind', () => {
    expect(typeof provider.kind).toBe('string');
    expect(provider.kind.length).toBeGreaterThan(0);
  });
  it('every moment resolves to an AuthOutcome with no secret — working and throwing targets', async () => {
    for (const t of [recordingTargets(), recordingTargets({ throws: true })]) {
      for (const answer of [
        await provider.prepare(),
        await provider.establish(t.logonTarget),
        await provider.authorize(t.requestTarget),
        await provider.rejected({ at: 'request', status: 401, error: new Error('401 SECRET-HTTP') }),
        await provider.rejected({ at: 'logon', error: 'refused SECRET-STRING' }),
        await provider.rejected({ at: 'logon', error: { key: 'SECRET_KEY', code: 'ESECRET', name: 'SECRETError', missingFields: ['SECRET'], message: 'SECRET-SDK' } }),
      ]) {
        expect(isOutcome(answer)).toBe(true);
        expect(JSON.stringify(answer)).not.toMatch(/SECRET/);
      }
    }
  });
});
```

- [ ] **Step 2: Run to see it fail** — `npm test -- src/__tests__/contract.test.ts` → FAIL (exports missing).

- [ ] **Step 3: Exports** — in `src/index.ts`:

```ts
// Credentials the process delegates to — every one an IAuthProvider.
export { BasicAuthProvider } from './credentials/BasicAuthProvider';
export { CertificateAuthProvider } from './credentials/CertificateAuthProvider';
export { FileCertificateMaterialLoader } from './credentials/FileCertificateMaterialLoader';
export { SamlAuthProvider } from './credentials/SamlAuthProvider';
export { TokenAuthProvider } from './credentials/TokenAuthProvider';
// Device flow: how the user is shown the code — injected like a strategy.
export {
  consoleDeviceCodePresenter,
  type DeviceCodePrompt,
  type IDeviceCodePresenter,
} from './deviceCode/DeviceCodePresenter';
// SNC — passwordless RFC logon.
export {
  DefaultSncLibraryLocator,
  type ISncLibraryLocator,
  type SncLibrary,
} from './snc/DefaultSncLibraryLocator';
export type { SncArch } from './snc/libraryArchitectures';
export { type ISncProductProbe, SecureLoginClientProbe } from './snc/SecureLoginClientProbe';
export { SncLogonProvider, type SncLogonProviderConfig } from './snc/SncLogonProvider';
export { nodeSncSystem, type SncSystem } from './snc/SncSystem';
```

and add `type TokenProviderHooks` and `type SamlTrust` to the `export type { … }` lists (from `./providers` and `./providers/saml2Utils`). Run `npx biome check --write src`.

Append to `src/__tests__/exports.test.ts`:

```ts
describe('public exports — 5.0.0', () => {
  it.each([
    'BasicAuthProvider', 'CertificateAuthProvider', 'FileCertificateMaterialLoader',
    'SamlAuthProvider', 'TokenAuthProvider', 'SncLogonProvider',
    'DefaultSncLibraryLocator', 'SecureLoginClientProbe', 'nodeSncSystem',
    'consoleDeviceCodePresenter',
  ])('exports %s', (name) => {
    expect((surface as Record<string, unknown>)[name]).toBeDefined();
  });
  it.each([
    'libraryArchitectures', 'sncRefusal', 'refusalFrom', 'oops', 'safely', 'ownLabel', 'DeviceCodePresentationError',
    'KNOWN_CONFIG_FIELDS', 'KNOWN_RFC_KEYS', 'parseRegQuery', 'parseTasklistCsv', 'parsePsComm',
  ])('does not export the internal %s', (name) => {
    expect(name in surface).toBe(false);
  });
});
```

- [ ] **Step 4: Full suite** — `npm run lint:check && npm run test:check && npm test` → PASS.
- [ ] **Step 5: Commit** — `git add src/index.ts src/__tests__/exports.test.ts src/__tests__/contract.test.ts && git commit -m "feat: export every IAuthProvider and its parts; one contract test over all of them"`

### Task 13: Documentation and version 5.0.0

**Files:**
- Modify: `CLAUDE.md`, `README.md`, `docs/passwordless-sso.md`, `CHANGELOG.md`, `package.json`, `package-lock.json`

- [ ] **Step 1: `CLAUDE.md`** — describe the code as it now is: every provider implements `IAuthProvider` (`prepare` / `establish` / `authorize` / `rejected`, Ok or Oops); the six rules (no exception across the contract; refusals from fixed wording and allowlists only; nothing to add is Ok; a target's Oops is the provider's to judge; one renewal, no step twice; no implicit defaults — constructors take every collaborator, static factories are the recipes); the new directories `src/credentials/`, `src/deviceCode/`, `src/snc/`, `src/auth/refusal.ts`. Replace the sentence that the package "ships a working default so nobody is forced to write one" with: it ships the parts and named factories; the consumer composes.

- [ ] **Step 2: `README.md`** — first section "Migrating to 5.0.0 — a migration, not an update": credentials come from here, not `@mcp-abap-adt/connection`; a token provider is handed to the process as it is; persist with `onTokens`; nothing is defaulted — pass the strategy / SAML validator / device-code presenter, or call the factory (`inBrowser`, `fromTerminal`, `toConsole`, `fromFiles`, `forSecureLoginClient`); SAML `idpCertificates` / `clockSkewMs` / `assertionReplayStore` moved from the provider config to `SamlTrust` / the validator; `ShippedValidatorOptions.replayStore` is required; manual strategies' `read(prompt, signal)` and `timeoutMs`; needs `@mcp-abap-adt/connection` 10.0.0. Then a "Passwordless RFC logon (SNC)" section: prerequisites, `SncLogonProvider.forSecureLoginClient`, the explicit assembly, discovery order and skip rule, the probe rule, the two explained failures.

- [ ] **Step 3: `docs/passwordless-sso.md`** — SNC over RFC: Measured 2026-09-29 and Built (`SncLogonProvider`); replace "Rejected — an RFC/SNC transport"; `node-rfc` bullet → `@mcp-abap-adt/sap-rfc-lite`; open question 2 partly answered — the Secure Login Client enrols over `/api/v1/getProfiles`, `/api/v1/getCertificateTemplateStandardBrowser`, `/slc/v1/login` (Measured, from its profile registry; not used here).

- [ ] **Step 4: `CHANGELOG.md`** — `## [5.0.0] - <date>` under `## [Unreleased]`, **Breaking — a migration**, listing: `IAuthProvider` on every provider; `BaseTokenProvider` implements it beside `IRefreshableTokenProvider`; `onTokens`; `Saml2PureProvider` presents cookies; one renewal, no Ok on an unchanged credential; refusals from fixed wording and allowlists; no implicit defaults and the factories; SAML config fields moved and `replayStore` required; manual strategies `timeoutMs` / `dispose()` / `read(prompt, signal)`; `IDeviceCodePresenter`; Basic / Certificate / SAML / Token / `FileCertificateMaterialLoader` moved in (`TokenAuthProvider.fixed` / `.from` only); `SncLogonProvider`; dependencies `interfaces-auth ^3.0.0`, `interfaces-auth-sap ^1.1.0`.

- [ ] **Step 5: Version** — `"version": "5.0.0"`; `npm install --package-lock-only`; `npm run build && npm run lint:check && npm run test:check && npm test` → PASS.

- [ ] **Step 6: Commit** — `git add CLAUDE.md README.md docs/passwordless-sso.md CHANGELOG.md package.json package-lock.json && git commit -m "chore(release): 5.0.0 — every IAuthProvider on one contract; a migration, not an update"`. Push, open the PR, merge after review, publish through the repo's release flow. The spec and this plan are deleted in the PR that finishes the goal's last step (the server); the goal file goes with them.

### Task 14: Live SNC check (manual, not CI)

- [ ] **Step 1:** On a machine with the NW RFC SDK, `@mcp-abap-adt/sap-rfc-lite` and the Secure Login Client logged on: `SncLogonProvider.forSecureLoginClient({ partnerName: '<system SNC name>' })`, `await prepare()` → Ok; `establish()` into a recording target → the params, with the registry's x64 `sapcrypto.dll` even with the installer's x86 `SNC_LIB` set.
- [ ] **Step 2:** Feed those params into the private probe's hand-built RFC conversation factory in place of its own `snc_*`; discovery and LOCK/UNLOCK → 200.
- [ ] **Step 3:** Log the Secure Login Client profile out; the RFC open fails; `rejected({ at: 'logon', error })` → hint "log on in the Secure Login Client". Record all three in the PR.
