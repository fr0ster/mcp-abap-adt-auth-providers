# auth-providers 5.0.0 — every IAuthProvider on one contract — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Release `@mcp-abap-adt/auth-providers` 5.0.0, where every provider — the token providers, Basic, Certificate, SAML cookies, Token and SNC — implements `IAuthProvider` from `@mcp-abap-adt/interfaces-auth` 3.0.0 and answers `prepare` / `establish` / `authorize` / `rejected` with an `AuthOutcome`.

**Architecture:** `BaseTokenProvider` implements `IAuthProvider` beside `IRefreshableTokenProvider`, so every token provider is an `IAuthProvider` with no wrapper. The providers that lived in `@mcp-abap-adt/connection` are rewritten here on the new contract. `SncLogonProvider` finds the SNC library and hands logon parameters to the wire. One module turns thrown errors into secret-free refusals; no exception crosses the contract; no provider retries anything.

**Tech Stack:** TypeScript (CommonJS, imports without `.js`), Jest via `npm test -- <path>` (never `npx jest`), Biome; `node:child_process`, `node:fs/promises`, `node:path` only.

**Spec:** `docs/superpowers/specs/2026-09-29-auth-providers-on-iauthprovider-design.md`; goal and path: `docs/superpowers/2026-09-29-auth-providers-5-goal.md`.

## Global Constraints

- Dependencies: `@mcp-abap-adt/interfaces-auth` `^3.0.0`, `@mcp-abap-adt/interfaces-auth-sap` `^1.1.0`. No new runtime dependency. `engines` stays `"^22 || ^24 || ^26"`.
- **No exception crosses the contract.** `prepare`, `establish`, `authorize` and `rejected` catch what their work throws and answer Oops. Constructors may still throw `ValidationError` for bad configuration.
- **A refusal carries no secret.** `reason` and `hint` never contain a token, refresh token, password, passphrase, key material or cookie value. A refusal is built from an error's `message` only — never its `response`, `config`, `cause` or body.
- **Nothing to add is Ok.** A provider with nothing for a moment writes to no target and answers `{ ok: true }`.
- **A target's Oops is the provider's to judge.** SNC and Certificate return it as their own; Basic ignores it for logon parameters (the header carries a password).
- **No provider retries.** `rejected()` answers Ok only when it changed what it will present; whether to try again is the consumer's. No second login, refresh or request inside a provider.
- **`kind`** of a token provider is its grant type, `getAuthType()`; `BasicAuthProvider` `'basic'`, `CertificateAuthProvider` `'certificate'`, `SamlAuthProvider` `'saml'`, `TokenAuthProvider` `'token'`, `SncLogonProvider` `'snc'`.
- **`TokenAuthProvider`** has exactly two constructors: `fixed(token)` and `from(refresher)`. No function source.
- **`snc_qop`** default `'9'`; allowed exactly `'1'`, `'2'`, `'3'`, `'8'`, `'9'`.
- Universal Mach-O: `FAT_MAGIC` `0xcafebabe` (20-byte records) and `FAT_MAGIC_64` `0xcafebabf` (32-byte records), `cputype` first in each.
- Architecture names are Node's `process.arch`: `'ia32'`, `'x64'`, `'arm64'`.
- Nothing writes to `process.stdout`; diagnostics go to the optional `ILogger`.
- Version **5.0.0** — a migration, not an update.

## Review Focus

- An axios error carrying `config.headers.Authorization` and a `response.data` body with a token reaches `refusalFrom` — the refusal must not contain either — test in Task 1.
- `onTokens` that throws must not turn a successful login into an Oops, and must not be called on a cache hit — test in Task 2.
- `authorize()` after the token expired must renew in that call (per attempt), not present the stale token — test in Task 2.
- `SNC_LIB` / `SNC_LIB_64` set to an empty or whitespace string must count as unset — test in Task 6.
- The RFC error reaching SNC's `rejected()` may be an `Error`, a string, or the SDK's plain object `{ name: 'RfcLibError', message: '…A2200019…' }` — all three recognised — test in Task 8.

## File Structure

| File | Responsibility |
|---|---|
| `src/auth/refusal.ts` | `OK`, `oops(reason, hint?)`, `refusalFrom(error)` — the one place errors become refusals |
| `src/providers/BaseTokenProvider.ts` | + `IAuthProvider`, `TokenProviderHooks`/`onTokens`, `applyToken` |
| `src/providers/Saml2PureProvider.ts` | `applyToken` → cookies |
| `src/providers/*Provider.ts` (9) | configs extend `TokenProviderHooks`; `super(config)` |
| `src/credentials/BasicAuthProvider.ts`, `SamlAuthProvider.ts`, `TokenAuthProvider.ts`, `CertificateAuthProvider.ts`, `FileCertificateMaterialLoader.ts` | the providers moved from `connection`, on the contract |
| `src/snc/libraryArchitectures.ts` | file head → architectures (PE, Mach-O thin/fat/fat64, ELF) |
| `src/snc/SncSystem.ts`, `src/snc/secureLoginClient.ts` | the machine seam and its parsers; SLC constants |
| `src/snc/DefaultSncLibraryLocator.ts` | explicit or automatic library discovery |
| `src/snc/SecureLoginClientProbe.ts` | the product probe, scoped to its own library |
| `src/snc/sncRefusal.ts` | refused SNC logon → refusal with cause and hint |
| `src/snc/SncLogonProvider.ts` | the SNC provider |
| `src/__tests__/helpers/targets.ts` | recording `ILogonTarget` / `IRequestTarget` for tests |
| `src/__tests__/snc/fakeSystem.ts` | fake `SncSystem` |

---

### Task 1: Dependencies, test targets and the refusal module

**Files:**
- Modify: `package.json`, `package-lock.json`
- Create: `src/auth/refusal.ts`, `src/__tests__/helpers/targets.ts`
- Test: `src/__tests__/auth/refusal.test.ts`

**Interfaces:**
- Produces: `OK: AuthOutcome`; `oops(reason: string, hint?: string): AuthOutcome`; `refusalFrom(error: unknown): AuthOutcome`; test helper `recordingTargets(options?: { acceptsLogonParameters?: boolean; acceptsTls?: boolean })` → `{ logonTarget: ILogonTarget; requestTarget: IRequestTarget; logon: { tls: ICertificateMaterial[]; params: Record<string, string>[] }; request: { headers: Record<string, string>; cookies: string[] } }`.

- [ ] **Step 1: Branch and dependencies**

```bash
git fetch origin && git checkout -b feat/auth-providers-5 origin/master
npm install @mcp-abap-adt/interfaces-auth@^3.0.0 @mcp-abap-adt/interfaces-auth-sap@^1.1.0
```

Expected: both ranges in `package.json`. Run `npm run test:check`; if anything imports `IRenewableCredential` or the removed `IAuthProvider` members, it fails here — nothing in `src` does today, so expect PASS.

- [ ] **Step 2: Test helper**

`src/__tests__/helpers/targets.ts`:

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
}

export function recordingTargets(options: RecordingTargetsOptions = {}) {
  const logon = {
    tls: [] as ICertificateMaterial[],
    params: [] as Record<string, string>[],
  };
  const request = {
    headers: {} as Record<string, string>,
    cookies: [] as string[],
  };
  const refuse = (what: string): AuthOutcome => ({
    ok: false,
    refusal: { reason: `this wire does not take ${what}` },
  });
  const logonTarget: ILogonTarget = {
    tlsMaterial(material) {
      if (options.acceptsTls === false) return refuse('TLS material');
      logon.tls.push(material);
      return { ok: true };
    },
    logonParameters(parameters) {
      if (options.acceptsLogonParameters === false) {
        return refuse('logon parameters');
      }
      logon.params.push({ ...parameters });
      return { ok: true };
    },
  };
  const requestTarget: IRequestTarget = {
    header(name, value) {
      request.headers[name] = value;
    },
    cookies(value) {
      request.cookies.push(value);
    },
  };
  return { logonTarget, requestTarget, logon, request };
}
```

- [ ] **Step 3: Write the failing refusal test**

`src/__tests__/auth/refusal.test.ts`:

```ts
import { describe, expect, it } from '@jest/globals';
import { OK, oops, refusalFrom } from '../../auth/refusal';
import {
  BrowserAuthError,
  RefreshError,
  ServiceKeyError,
  SessionDataError,
  ValidationError,
} from '../../errors/TokenProviderErrors';

describe('refusal', () => {
  it('OK and oops build the two outcomes', () => {
    expect(OK).toEqual({ ok: true });
    expect(oops('r', 'h')).toEqual({ ok: false, refusal: { reason: 'r', hint: 'h' } });
    expect(oops('r')).toEqual({ ok: false, refusal: { reason: 'r' } });
  });

  it.each([
    [new BrowserAuthError('login timed out'), /complete the login in the browser/],
    [new RefreshError('refresh refused'), /log in again/],
    [new ValidationError('bad config', ['clientId']), /check the provider configuration: clientId/],
    [new ServiceKeyError('no url', ['url']), /check the service key or session data: url/],
    [new SessionDataError('no token', ['token']), /check the service key or session data: token/],
  ])('maps %p to its hint', (error, hint) => {
    const outcome = refusalFrom(error);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.refusal.reason).toBe((error as Error).message);
      expect(outcome.refusal.hint).toMatch(hint);
    }
  });

  it('an unknown error keeps its message and has no hint', () => {
    expect(refusalFrom(new Error('boom'))).toEqual({ ok: false, refusal: { reason: 'boom' } });
    expect(refusalFrom('plain')).toEqual({ ok: false, refusal: { reason: 'plain' } });
  });

  it('never carries what an axios error holds besides its message', () => {
    const error = Object.assign(new Error('Request failed with status code 401'), {
      config: { headers: { Authorization: 'Basic U0VDUkVULVBBU1M=' } },
      response: { status: 401, data: { access_token: 'SECRET-TOKEN' } },
      cause: new Error('SECRET-CAUSE'),
    });
    const text = JSON.stringify(refusalFrom(error));
    expect(text).not.toMatch(/U0VDUkVULVBBU1M=|SECRET-TOKEN|SECRET-CAUSE/);
    expect(text).toMatch(/status code 401/);
  });
});
```

- [ ] **Step 4: Run to see it fail**

Run: `npm test -- src/__tests__/auth/refusal.test.ts`
Expected: FAIL — `Cannot find module '../../auth/refusal'`.

- [ ] **Step 5: Implement**

`src/auth/refusal.ts`:

```ts
/**
 * How a provider in this package answers Oops.
 *
 * The one place a thrown error becomes a refusal, so the rule that a refusal
 * carries no secret is kept in one place: only the error's `message` is read —
 * never its `response`, `config`, `cause` or body, where an axios error keeps
 * the request's Authorization header and the token endpoint's answer.
 */

import type { AuthOutcome } from '@mcp-abap-adt/interfaces-auth';
import {
  BrowserAuthError,
  RefreshError,
  ServiceKeyError,
  SessionDataError,
  ValidationError,
} from '../errors/TokenProviderErrors';

export const OK: AuthOutcome = { ok: true };

export function oops(reason: string, hint?: string): AuthOutcome {
  return hint === undefined
    ? { ok: false, refusal: { reason } }
    : { ok: false, refusal: { reason, hint } };
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function fields(missing: string[] | undefined): string {
  return missing?.length ? `: ${missing.join(', ')}` : '';
}

export function refusalFrom(error: unknown): AuthOutcome {
  const reason = messageOf(error);
  if (error instanceof BrowserAuthError) {
    return oops(reason, 'complete the login in the browser within the timeout');
  }
  if (error instanceof RefreshError) {
    return oops(reason, 'the refresh token was refused; log in again');
  }
  if (error instanceof ValidationError) {
    return oops(reason, `check the provider configuration${fields(error.missingFields)}`);
  }
  if (error instanceof ServiceKeyError || error instanceof SessionDataError) {
    return oops(reason, `check the service key or session data${fields(error.missingFields)}`);
  }
  return oops(reason);
}
```

- [ ] **Step 6: Run to see it pass**

Run: `npm test -- src/__tests__/auth/refusal.test.ts`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add package.json package-lock.json src/auth/refusal.ts src/__tests__/helpers/targets.ts src/__tests__/auth/refusal.test.ts
git commit -m "feat: refusals from errors, secret-free; interfaces-auth ^3.0.0"
```

### Task 2: Token providers are `IAuthProvider`s

**Files:**
- Modify: `src/providers/BaseTokenProvider.ts`, `src/providers/Saml2PureProvider.ts`, and the other eight providers' config interfaces and constructors (`AuthorizationCodeProvider`, `ClientCredentialsProvider`, `OidcBrowserProvider`, `OidcDeviceFlowProvider`, `OidcPasswordProvider`, `OidcTokenExchangeProvider`, `Saml2BearerProvider`, `UaaPasscodeProvider`); `src/providers/index.ts`
- Test: `src/__tests__/providers/tokenProviderContract.test.ts`

**Interfaces:**
- Consumes: `OK`, `refusalFrom` (Task 1); `recordingTargets` (Task 1).
- Produces: `interface TokenProviderHooks { onTokens?: (result: ITokenResult) => Promise<void> }` (exported); `BaseTokenProvider implements IRefreshableTokenProvider, IAuthProvider` with `get kind(): string`, `prepare()`, `establish()`, `authorize()`, `rejected()`, and `protected applyToken(request: IRequestTarget, result: ITokenResult): void`.

- [ ] **Step 1: Write the failing test**

`src/__tests__/providers/tokenProviderContract.test.ts`:

```ts
import { describe, expect, it, jest } from '@jest/globals';
import type { ITokenResult, OAuth2GrantType } from '@mcp-abap-adt/interfaces-auth';
import { RefreshError } from '../../errors/TokenProviderErrors';
import {
  BaseTokenProvider,
  type TokenProviderHooks,
} from '../../providers/BaseTokenProvider';
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
    const p = new TestProvider();
    const t = recordingTargets();
    await expect(p.establish(t.logonTarget)).resolves.toEqual({ ok: true });
    expect(t.logon).toEqual({ tls: [], params: [] });
  });

  it('authorize writes the bearer header', async () => {
    const p = new TestProvider();
    const t = recordingTargets();
    await expect(p.authorize(t.requestTarget)).resolves.toEqual({ ok: true });
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

  it('rejected refreshes and answers Ok, once', async () => {
    const p = new TestProvider();
    await p.prepare();
    await expect(p.rejected({ at: 'request', status: 401, error: {} })).resolves.toEqual({ ok: true });
    expect(p.refresh).toHaveBeenCalledTimes(1);
  });

  it('a failure is an Oops, never a throw, and nothing is retried', async () => {
    const p = new TestProvider();
    p.login.mockRejectedValue(new RefreshError('refused'));
    const outcome = await p.prepare();
    expect(outcome.ok).toBe(false);
    expect(p.login).toHaveBeenCalledTimes(1);
    const t = recordingTargets();
    await expect(p.authorize(t.requestTarget)).resolves.toMatchObject({ ok: false });
    await expect(p.rejected({ at: 'request', error: {} })).resolves.toMatchObject({ ok: false });
  });

  it('onTokens after a login and after a refresh, never on a cache hit', async () => {
    const onTokens = jest.fn(async (_: ITokenResult) => {});
    const p = new TestProvider({ onTokens });
    await p.prepare();
    await p.authorize(recordingTargets().requestTarget); // cache hit
    await p.rejected({ at: 'request', error: {} });
    expect(onTokens.mock.calls.map(([r]) => r.authorizationToken)).toEqual(['T1', 'T2']);
  });

  it('a failing onTokens does not fail authentication', async () => {
    const p = new TestProvider({ onTokens: async () => { throw new Error('store down'); } });
    await expect(p.prepare()).resolves.toEqual({ ok: true });
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
import { OK, refusalFrom } from '../auth/refusal';

/** What every token provider's config may carry beside its own fields. */
export interface TokenProviderHooks {
  /**
   * Called after every NEW token — a login or a refresh, never a cache hit —
   * and awaited before the provider answers. The broker persists through it.
   * A failure here is logged and does not fail the authentication.
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

  constructor(hooks: TokenProviderHooks = {}) {
    this.onTokens = hooks.onTokens;
  }
```

In `refreshTokens()`, after each of the two `this.updateTokens(result);` lines add `await this.obtained(result);`. Add these members at the end of the class:

```ts
  private async obtained(result: ITokenResult): Promise<void> {
    if (!this.onTokens) return;
    try {
      await this.onTokens(result);
    } catch (error) {
      this.logger?.warn('[BaseTokenProvider] onTokens failed; the token stands', {
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  // ---- IAuthProvider: the process calls these, the same for every provider.

  /** The grant type, so a log line says which way in ran. */
  get kind(): string {
    return this.getAuthType();
  }

  async prepare(): Promise<AuthOutcome> {
    try {
      await this.getTokens();
      return OK;
    } catch (error) {
      return refusalFrom(error);
    }
  }

  /** A token is presented per request; a logon needs nothing from it. */
  async establish(_logon: ILogonTarget): Promise<AuthOutcome> {
    return OK;
  }

  /** Per attempt: getTokens() renews an expired token here. */
  async authorize(request: IRequestTarget): Promise<AuthOutcome> {
    try {
      this.applyToken(request, await this.getTokens());
      return OK;
    } catch (error) {
      return refusalFrom(error);
    }
  }

  /** A new token — refresh, else login — and Ok; retrying is the caller's. */
  async rejected(_rejection: IAuthRejection): Promise<AuthOutcome> {
    try {
      await this.refreshTokens();
      return OK;
    } catch (error) {
      return refusalFrom(error);
    }
  }

  /** How this provider's token rides on a request. Bearer by default. */
  protected applyToken(request: IRequestTarget, result: ITokenResult): void {
    request.header('Authorization', `Bearer ${result.authorizationToken}`);
  }
```

- [ ] **Step 4: Thread the hook through the nine providers**

For each of `AuthorizationCodeProvider`, `ClientCredentialsProvider`, `OidcBrowserProvider`, `OidcDeviceFlowProvider`, `OidcPasswordProvider`, `OidcTokenExchangeProvider`, `Saml2BearerProvider`, `Saml2PureProvider`, `UaaPasscodeProvider`:
- its `…Config` interface adds `TokenProviderHooks` to what it extends (`export interface XConfig extends TokenProviderHooks {` — or `extends Saml2CommonConfig, TokenProviderHooks` where it already extends);
- its constructor's `super();` becomes `super(config);`;
- import `type TokenProviderHooks` from `./BaseTokenProvider`.

In `src/providers/index.ts` add `export type { TokenProviderHooks } from './BaseTokenProvider';`.

- [ ] **Step 5: `Saml2PureProvider` presents cookies**

Add to the class (import `IRequestTarget`, `ITokenResult` types):

```ts
  /** Its "token" is the SAML session's cookies (tokenType 'saml'). */
  protected override applyToken(request: IRequestTarget, result: ITokenResult): void {
    request.cookies(result.authorizationToken);
  }
```

Add to the test file:

```ts
import { Saml2PureProvider } from '../../providers/Saml2PureProvider';

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
```

- [ ] **Step 6: Run the new test and the whole suite**

Run: `npm test -- src/__tests__/providers/tokenProviderContract.test.ts` → PASS. Then `npm run test:check && npm test` → PASS (the existing token-provider tests are unaffected: `getTokens` / `refreshTokens` behave as before).

- [ ] **Step 7: Prove two rules are load-bearing**

1. Replace `await this.obtained(result)` after the refresh with nothing → "onTokens after a login and after a refresh" FAILS. Revert.
2. Make `authorize` return OK without calling `getTokens()` a second time (cache the first result in a field) → "authorize renews an expired token" FAILS. Revert.

- [ ] **Step 8: Commit**

```bash
git add src/providers src/__tests__/providers/tokenProviderContract.test.ts
git commit -m "feat!: every token provider is an IAuthProvider; onTokens for persistence"
```

### Task 3: The providers moved in from `connection`

**Files:**
- Create: `src/credentials/BasicAuthProvider.ts`, `src/credentials/SamlAuthProvider.ts`, `src/credentials/TokenAuthProvider.ts`, `src/credentials/CertificateAuthProvider.ts`, `src/credentials/FileCertificateMaterialLoader.ts`
- Test: `src/__tests__/credentials/credentials.test.ts`

**Interfaces:**
- Consumes: `OK`, `oops`, `refusalFrom`; `recordingTargets`.
- Produces: `BasicAuthProvider(username: string, password: string)`; `SamlAuthProvider(sessionCookies: string)`; `TokenAuthProvider.fixed(token: string)`, `TokenAuthProvider.from(refresher: ITokenRefresher)`; `CertificateAuthProvider(loader: ICertificateMaterialLoader, config: ISapConfig)`; `FileCertificateMaterialLoader` implementing `ICertificateMaterialLoader`.

- [ ] **Step 1: Write the failing test**

`src/__tests__/credentials/credentials.test.ts`:

```ts
import { describe, expect, it, jest } from '@jest/globals';
import type { ITokenRefresher } from '@mcp-abap-adt/interfaces-auth';
import type { ISapConfig } from '@mcp-abap-adt/interfaces-auth-sap';
import { BasicAuthProvider } from '../../credentials/BasicAuthProvider';
import { CertificateAuthProvider } from '../../credentials/CertificateAuthProvider';
import { SamlAuthProvider } from '../../credentials/SamlAuthProvider';
import { TokenAuthProvider } from '../../credentials/TokenAuthProvider';
import { recordingTargets } from '../helpers/targets';

const refusal = { at: 'request' as const, status: 401, error: {} };

describe('BasicAuthProvider', () => {
  const p = new BasicAuthProvider('USER', 'S3CRET-PW');

  it('writes the header and offers user/passwd to the logon', async () => {
    const t = recordingTargets();
    await expect(p.establish(t.logonTarget)).resolves.toEqual({ ok: true });
    await expect(p.authorize(t.requestTarget)).resolves.toEqual({ ok: true });
    expect(t.logon.params).toEqual([{ user: 'USER', passwd: 'S3CRET-PW' }]);
    expect(t.request.headers.Authorization).toBe(
      `Basic ${Buffer.from('USER:S3CRET-PW').toString('base64')}`,
    );
  });

  it('goes on when the wire takes no logon parameters (HTTP)', async () => {
    const t = recordingTargets({ acceptsLogonParameters: false });
    await expect(p.establish(t.logonTarget)).resolves.toEqual({ ok: true });
  });

  it('rejected is an Oops without the password', async () => {
    const outcome = await p.rejected(refusal);
    expect(outcome).toMatchObject({ ok: false, refusal: { reason: 'the user or password was refused' } });
    expect(JSON.stringify(outcome)).not.toMatch(/S3CRET-PW|USER:/);
  });
});

describe('SamlAuthProvider', () => {
  const p = new SamlAuthProvider('MYSAPSSO2=SECRET-COOKIE');

  it('writes the cookies', async () => {
    const t = recordingTargets();
    await p.authorize(t.requestTarget);
    expect(t.request.cookies).toEqual(['MYSAPSSO2=SECRET-COOKIE']);
  });

  it('rejected is an Oops without the cookie', async () => {
    const outcome = await p.rejected(refusal);
    expect(outcome.ok).toBe(false);
    expect(JSON.stringify(outcome)).not.toMatch(/SECRET-COOKIE/);
  });
});

describe('TokenAuthProvider', () => {
  it('fixed: bearer, and rejected is an Oops', async () => {
    const p = TokenAuthProvider.fixed('SECRET-T');
    const t = recordingTargets();
    await p.authorize(t.requestTarget);
    expect(t.request.headers.Authorization).toBe('Bearer SECRET-T');
    const outcome = await p.rejected(refusal);
    expect(outcome).toMatchObject({ ok: false, refusal: { hint: 'obtain a new token' } });
    expect(JSON.stringify(outcome)).not.toMatch(/SECRET-T/);
  });

  it('from(refresher): asks getToken per attempt, refreshToken once on rejected', async () => {
    const refresher: ITokenRefresher = {
      getToken: jest.fn(async () => 'A'),
      refreshToken: jest.fn(async () => 'B'),
    };
    const p = TokenAuthProvider.from(refresher);
    const t = recordingTargets();
    await p.authorize(t.requestTarget);
    await expect(p.rejected(refusal)).resolves.toEqual({ ok: true });
    expect(refresher.getToken).toHaveBeenCalledTimes(1);
    expect(refresher.refreshToken).toHaveBeenCalledTimes(1);
  });

  it('from(refresher): a refresh that throws is an Oops', async () => {
    const p = TokenAuthProvider.from({
      getToken: async () => 'A',
      refreshToken: async () => { throw new Error('refresh refused'); },
    });
    await expect(p.rejected(refusal)).resolves.toMatchObject({ ok: false, refusal: { reason: 'refresh refused' } });
  });
});

describe('CertificateAuthProvider', () => {
  const config = { url: 'https://h', authType: 'certificate' } as ISapConfig;

  it('prepare loads, establish hands the material to the logon', async () => {
    const p = new CertificateAuthProvider({ load: async () => ({ cert: 'C', key: 'K' }) }, config);
    await expect(p.prepare()).resolves.toEqual({ ok: true });
    const t = recordingTargets();
    await expect(p.establish(t.logonTarget)).resolves.toEqual({ ok: true });
    expect(t.logon.tls).toEqual([{ cert: 'C', key: 'K', pfx: undefined, passphrase: undefined }]);
  });

  it('a loader failure is an Oops from prepare', async () => {
    const p = new CertificateAuthProvider({ load: async () => { throw new Error('no file'); } }, config);
    await expect(p.prepare()).resolves.toMatchObject({ ok: false, refusal: { reason: 'no file' } });
  });

  it('returns the target Oops when the wire has no TLS', async () => {
    const p = new CertificateAuthProvider({ load: async () => ({ pfx: Buffer.from('x'), passphrase: 'SECRET-PP' }) }, config);
    await p.prepare();
    const outcome = await p.establish(recordingTargets({ acceptsTls: false }).logonTarget);
    expect(outcome).toMatchObject({ ok: false, refusal: { reason: 'this wire does not take TLS material' } });
  });

  it('establish before prepare is an Oops, not a throw', async () => {
    const p = new CertificateAuthProvider({ load: async () => ({}) }, config);
    await expect(p.establish(recordingTargets().logonTarget)).resolves.toMatchObject({ ok: false });
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
import { OK, oops } from '../auth/refusal';

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
    logon.logonParameters({ user: this.username, passwd: this.password });
    return OK;
  }

  async authorize(request: IRequestTarget): Promise<AuthOutcome> {
    request.header(
      'Authorization',
      `Basic ${Buffer.from(`${this.username}:${this.password}`).toString('base64')}`,
    );
    return OK;
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
import { OK, oops } from '../auth/refusal';

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
    request.cookies(this.sessionCookies);
    return OK;
  }

  async rejected(_rejection: IAuthRejection): Promise<AuthOutcome> {
    return oops(
      'the SAML session was refused or has expired',
      'obtain a new SAML session',
    );
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
import { OK, oops, refusalFrom } from '../auth/refusal';

/**
 * A token that comes from outside this package — a fixed string, or the
 * broker's refresher. A token provider from this package needs no wrapper: it
 * is an IAuthProvider itself.
 */
export class TokenAuthProvider implements IAuthProvider {
  readonly kind = 'token';

  private constructor(
    private readonly current: () => Promise<string>,
    private readonly renew: (() => Promise<unknown>) | undefined,
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
    try {
      request.header('Authorization', `Bearer ${await this.current()}`);
      return OK;
    } catch (error) {
      return refusalFrom(error);
    }
  }

  async rejected(_rejection: IAuthRejection): Promise<AuthOutcome> {
    if (!this.renew) return oops('the token was refused', 'obtain a new token');
    try {
      await this.renew();
      return OK;
    } catch (error) {
      return refusalFrom(error);
    }
  }
}
```

`src/credentials/FileCertificateMaterialLoader.ts` — copy `@mcp-abap-adt/connection`'s `src/auth/FileCertificateMaterialLoader.ts` (origin/master) verbatim: PEM pair or PFX from files via `readFile`, `Error` on both or neither given. Its imports stay `ICertificateMaterial` from `@mcp-abap-adt/interfaces-auth` and `ICertificateMaterialLoader`, `ISapConfig` from `@mcp-abap-adt/interfaces-auth-sap`.

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
import type {
  ICertificateMaterialLoader,
  ISapConfig,
} from '@mcp-abap-adt/interfaces-auth-sap';
import { OK, oops, refusalFrom } from '../auth/refusal';

/** A client certificate, presented in the TLS handshake of each logon. */
export class CertificateAuthProvider implements IAuthProvider {
  readonly kind = 'certificate';
  private material: ICertificateMaterial | null = null;

  constructor(
    private readonly loader: ICertificateMaterialLoader,
    private readonly config: ISapConfig,
  ) {}

  async prepare(): Promise<AuthOutcome> {
    try {
      this.material = await this.loader.load(this.config);
      return OK;
    } catch (error) {
      return refusalFrom(error);
    }
  }

  /** No other way in: the wire's Oops is this provider's own. */
  async establish(logon: ILogonTarget): Promise<AuthOutcome> {
    if (!this.material) {
      return oops('the certificate is not loaded', 'connect() prepares it first');
    }
    const { cert, key, pfx, passphrase } = this.material;
    return logon.tlsMaterial({ cert, key, pfx, passphrase });
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

### Task 4: SNC — library architecture reader

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

### Task 5: SNC — the machine seam

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

### Task 6: SNC — library discovery

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

### Task 7: SNC — the Secure Login Client probe

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
  it('an unreadable process list says the check could not run', async () => {
    await expect(new SecureLoginClientProbe(fakeSystem({ processes: new Error('access denied') })).check())
      .rejects.toThrow(/Could not check whether the SAP Secure Login Client is running: access denied/);
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
      return dirs.some((dir) => dir?.trim() !== undefined && dir.trim() !== '' && library.startsWith(asDirectory(dir)));
    }
    if (system.platform === 'darwin') return libraryPath.startsWith(MACOS_SLC_APP);
    return false;
  }

  async check(): Promise<void> {
    let names: string[];
    try {
      names = await this.system.listProcessNames();
    } catch (error) {
      throw new ValidationError(
        `Could not check whether the ${SECURE_LOGIN_CLIENT} is running: ${error instanceof Error ? error.message : String(error)}`,
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

### Task 8: `SncLogonProvider`

**Files:**
- Create: `src/snc/sncRefusal.ts`, `src/snc/SncLogonProvider.ts`
- Test: `src/__tests__/snc/SncLogonProvider.test.ts`

**Interfaces:**
- Consumes: Tasks 1, 5–7.
- Produces: `sncRefusal(error: unknown, context: { library?: SncLibrary; product?: string }): IAuthRefusal`; `interface SncLogonProviderConfig { partnerName: string; qop?: string; sncLib?: string; myName?: string; system?: SncSystem; locator?: ISncLibraryLocator; probes?: ISncProductProbe[]; logger?: ILogger }`; `class SncLogonProvider implements IAuthProvider`.

- [ ] **Step 1: Write the failing test**

`src/__tests__/snc/SncLogonProvider.test.ts`:

```ts
import { describe, expect, it } from '@jest/globals';
import { ValidationError } from '../../errors/TokenProviderErrors';
import { SncLogonProvider } from '../../snc/SncLogonProvider';
import { recordingTargets } from '../helpers/targets';
import { fakeSystem, peLibrary } from './fakeSystem';

const SLC = 'C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\lib\\sapcrypto.dll';
const KRB = 'C:\\Windows\\System32\\gsskrb5.dll';
const REGISTRY = { 'HKLM\\Software\\SAP\\SecureLogin\\InstallPath64': 'C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\' };
const machine = (processes: string[]) =>
  fakeSystem({ files: { [SLC]: peLibrary('x64'), [KRB]: peLibrary('x64') }, registry: REGISTRY, processes });
const sdkError = {
  name: 'RfcLibError',
  message: '\nERROR       GSS-API(maj): Miscellaneous failure\n            GSS-API(min): A2200019:Operation aborted by user or\n',
};

describe('construction', () => {
  it('requires partnerName', () => {
    expect(() => new SncLogonProvider({ partnerName: ' ', system: machine([]) })).toThrow(ValidationError);
  });
  it.each(['0', '4', '5', '6', '7', '10', 'max', ''])('refuses qop %p', (qop) => {
    expect(() => new SncLogonProvider({ partnerName: 'p:CN=SID', qop, system: machine([]) })).toThrow(/qop/);
  });
  it.each(['1', '2', '3', '8', '9'])('accepts qop %p', (qop) => {
    expect(() => new SncLogonProvider({ partnerName: 'p:CN=SID', qop, system: machine([]) })).not.toThrow();
  });
});

describe('the four moments', () => {
  it('prepare → establish writes the SNC parameters, no user or passwd', async () => {
    const p = new SncLogonProvider({ partnerName: 'p:CN=SID', system: machine(['sbus.exe']) });
    await expect(p.prepare()).resolves.toEqual({ ok: true });
    const t = recordingTargets();
    await expect(p.establish(t.logonTarget)).resolves.toEqual({ ok: true });
    expect(t.logon.params).toEqual([{ snc_mode: '1', snc_partnername: 'p:CN=SID', snc_qop: '9', snc_lib: SLC }]);
    await expect(p.authorize(t.requestTarget)).resolves.toEqual({ ok: true });
    expect(t.request).toEqual({ headers: {}, cookies: [] });
  });
  it('snc_myname only when configured', async () => {
    const p = new SncLogonProvider({ partnerName: 'p:CN=SID', myName: 'p:CN=ME', qop: '8', system: machine(['sbus.exe']) });
    await p.prepare();
    const t = recordingTargets();
    await p.establish(t.logonTarget);
    expect(t.logon.params[0]).toMatchObject({ snc_myname: 'p:CN=ME', snc_qop: '8' });
  });
  it('an HTTP wire: the target Oops is SNC’s own', async () => {
    const p = new SncLogonProvider({ partnerName: 'p:CN=SID', system: machine(['sbus.exe']) });
    await p.prepare();
    await expect(p.establish(recordingTargets({ acceptsLogonParameters: false }).logonTarget))
      .resolves.toMatchObject({ ok: false, refusal: { reason: 'this wire does not take logon parameters' } });
  });
  it('establish before prepare is an Oops', async () => {
    const p = new SncLogonProvider({ partnerName: 'p:CN=SID', system: machine(['sbus.exe']) });
    await expect(p.establish(recordingTargets().logonTarget)).resolves.toMatchObject({ ok: false });
  });
  it('SLC library, client not running → prepare Oops with a hint', async () => {
    const outcome = await new SncLogonProvider({ partnerName: 'p:CN=SID', system: machine([]) }).prepare();
    expect(outcome).toMatchObject({ ok: false, refusal: { reason: expect.stringMatching(/not running/), hint: expect.stringMatching(/Start the SAP Secure Login Client/) } });
  });
  it('non-SLC library, no SLC process → prepare Ok, no probe', async () => {
    await expect(new SncLogonProvider({ partnerName: 'p:CN=SID', sncLib: KRB, system: machine([]) }).prepare()).resolves.toEqual({ ok: true });
  });
  it('no usable library → prepare Oops naming sncLib', async () => {
    await expect(new SncLogonProvider({ partnerName: 'p:CN=SID', system: fakeSystem({ platform: 'linux' }) }).prepare())
      .resolves.toMatchObject({ ok: false, refusal: { hint: expect.stringMatching(/sncLib/) } });
  });
});

describe('rejected', () => {
  it.each([
    ['the SDK object', sdkError],
    ['an Error', new Error(`Failed to open RFC connection: ${JSON.stringify(sdkError)}`)],
    ['a string', 'GSS-API(min): A2200019:Operation aborted'],
  ])('A2200019 in %s → log on in the Secure Login Client', async (_, error) => {
    const p = new SncLogonProvider({ partnerName: 'p:CN=SID', system: machine(['sbus.exe']) });
    await p.prepare();
    await expect(p.rejected({ at: 'logon', error })).resolves.toMatchObject({
      ok: false,
      refusal: { hint: expect.stringMatching(/log on in the Secure Login Client/) },
    });
  });
  it('another library: names it, not the Secure Login Client', async () => {
    const p = new SncLogonProvider({ partnerName: 'p:CN=SID', sncLib: KRB, system: machine([]) });
    await p.prepare();
    const outcome = await p.rejected({ at: 'logon', error: sdkError });
    expect(JSON.stringify(outcome)).toMatch(/gsskrb5\.dll/);
    expect(JSON.stringify(outcome)).not.toMatch(/Secure Login Client/);
  });
  it('SNCERR_INIT names the library and its architecture', async () => {
    const p = new SncLogonProvider({ partnerName: 'p:CN=SID', system: machine(['sbus.exe']) });
    await p.prepare();
    const outcome = await p.rejected({ at: 'logon', error: new Error('SNCERR_INIT, gssapi library invalid/missing') });
    expect(outcome).toMatchObject({ ok: false, refusal: { reason: expect.stringMatching(/sapcrypto\.dll \(x64\)/) } });
  });
  it('anything else is still an Oops', async () => {
    const p = new SncLogonProvider({ partnerName: 'p:CN=SID', system: machine(['sbus.exe']) });
    await p.prepare();
    await expect(p.rejected({ at: 'logon', error: new Error('RFC_LOGON_FAILURE') })).resolves.toMatchObject({
      ok: false,
      refusal: { reason: expect.stringMatching(/SNC logon refused: RFC_LOGON_FAILURE/) },
    });
  });
});
```

- [ ] **Step 2: Run to see it fail** — `npm test -- src/__tests__/snc/SncLogonProvider.test.ts` → FAIL.

- [ ] **Step 3: Implement**

`src/snc/sncRefusal.ts`:

```ts
/**
 * What a refused SNC logon means. The RFC SDK reports both common failures as
 * a generic communication error; the cause is in the GSS text. Measured:
 * `A2200019` — the SNC library has no credential (profile not logged on, or
 * the certificate expired); `SNCERR_INIT` — the SDK could not load the library.
 */

import type { IAuthRefusal } from '@mcp-abap-adt/interfaces-auth';
import type { SncLibrary } from './DefaultSncLibraryLocator';
import { SECURE_LOGIN_CLIENT } from './secureLoginClient';

function describe(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === 'string') return error;
  try {
    return JSON.stringify(error) ?? String(error);
  } catch {
    return String(error);
  }
}

export function sncRefusal(
  error: unknown,
  context: { library?: SncLibrary; product?: string },
): IAuthRefusal {
  const text = describe(error);
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
  return { reason: `SNC logon refused: ${text.trim()}` };
}
```

`src/snc/SncLogonProvider.ts`:

```ts
/**
 * Passwordless RFC logon through an installed SNC product. The SNC library
 * (for the SAP Secure Login Client, `sapcrypto`) authenticates during the RFC
 * logon itself; this provider finds it, checks the product when it can, and
 * hands the wire the logon parameters. It opens no connection and loads no
 * SAP library.
 */

import type {
  AuthOutcome,
  IAuthProvider,
  IAuthRejection,
  ILogonTarget,
  IRequestTarget,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { OK, oops } from '../auth/refusal';
import { ValidationError } from '../errors/TokenProviderErrors';
import { DefaultSncLibraryLocator, type ISncLibraryLocator, type SncLibrary } from './DefaultSncLibraryLocator';
import { type ISncProductProbe, SecureLoginClientProbe } from './SecureLoginClientProbe';
import { nodeSncSystem, type SncSystem } from './SncSystem';
import { sncRefusal } from './sncRefusal';

/** SAP's SNC_QOP values: 1 authentication, 2 integrity, 3 privacy, 8 default, 9 maximum. */
const SNC_QOP_VALUES = ['1', '2', '3', '8', '9'];

export interface SncLogonProviderConfig {
  /** The system's SNC name, e.g. `p:CN=SID, O=ACME`. */
  partnerName: string;
  /** `'1' | '2' | '3' | '8' | '9'`; default `'9'` (maximum available). */
  qop?: string;
  /** The SNC library. Only this one is tried when set. */
  sncLib?: string;
  /** Sent as `snc_myname` only when set. */
  myName?: string;
  system?: SncSystem;
  locator?: ISncLibraryLocator;
  /** Default: the Secure Login Client probe. `[]` for no product check. */
  probes?: ISncProductProbe[];
  logger?: ILogger;
}

const message = (error: unknown) => (error instanceof Error ? error.message : String(error));

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
      throw new ValidationError(
        `SncLogonProvider: qop must be one of ${SNC_QOP_VALUES.join(', ')} (SAP's SNC_QOP values), got '${qop}'.`,
        ['qop'],
      );
    }
    const system = config.system ?? nodeSncSystem();
    this.partnerName = partnerName;
    this.qop = qop;
    this.myName = config.myName?.trim() || undefined;
    this.locator = config.locator ?? new DefaultSncLibraryLocator(system, config.sncLib);
    this.probes = config.probes ?? [new SecureLoginClientProbe(system)];
    this.logger = config.logger;
  }

  async prepare(): Promise<AuthOutcome> {
    let library: SncLibrary;
    try {
      library = await this.locator.locate();
    } catch (error) {
      return oops(message(error), 'set sncLib to the SNC (GSS) library of your SNC product');
    }
    let product: string | undefined;
    for (const probe of this.probes) {
      try {
        if (!(await probe.appliesTo(library.path))) continue;
        await probe.check();
        product = probe.product;
        break;
      } catch (error) {
        return oops(message(error), `Start the ${probe.product} and log on to the profile used for SAP applications`);
      }
    }
    this.library = library;
    this.product = product;
    this.logger?.debug(
      `SNC library ${library.path} (${library.archs.join('/')})${product ? `, ${product} running` : ', no product check'}`,
    );
    return OK;
  }

  /** No other way in: the wire's answer is this provider's own. */
  async establish(logon: ILogonTarget): Promise<AuthOutcome> {
    if (!this.library) {
      return oops('the SNC provider is not prepared', 'connect() prepares it first');
    }
    const params: Record<string, string> = {
      snc_mode: '1',
      snc_partnername: this.partnerName,
      snc_qop: this.qop,
      snc_lib: this.library.path,
    };
    if (this.myName) params.snc_myname = this.myName;
    return logon.logonParameters(params);
  }

  async authorize(_request: IRequestTarget): Promise<AuthOutcome> {
    return OK;
  }

  async rejected(rejection: IAuthRejection): Promise<AuthOutcome> {
    return { ok: false, refusal: sncRefusal(rejection.error, { library: this.library, product: this.product }) };
  }
}
```

- [ ] **Step 4: Run to see it pass** — same command → PASS.
- [ ] **Step 5: Load-bearing** — in `prepare()`, drop the `appliesTo` condition (always `check()`) → "non-SLC library, no SLC process" FAILS. Revert.
- [ ] **Step 6: Commit** — `git add src/snc/sncRefusal.ts src/snc/SncLogonProvider.ts src/__tests__/snc/SncLogonProvider.test.ts && git commit -m "feat(snc): SncLogonProvider — SNC logon parameters, explained refusals"`

### Task 9: Public surface and the whole-package contract test

**Files:**
- Modify: `src/index.ts`, `src/__tests__/exports.test.ts`
- Test: `src/__tests__/contract.test.ts`

**Interfaces:**
- Consumes: every provider from Tasks 2, 3, 8.
- Produces: the root exports listed in Global Constraints / spec "Package".

- [ ] **Step 1: Write the failing contract test**

`src/__tests__/contract.test.ts` — one instance of each provider, every moment, every failure path:

```ts
import { describe, expect, it } from '@jest/globals';
import type { IAuthProvider, ITokenResult, OAuth2GrantType } from '@mcp-abap-adt/interfaces-auth';
import * as surface from '../index';
import { recordingTargets } from './helpers/targets';
import { fakeSystem, peLibrary } from './snc/fakeSystem';

class FailingTokenProvider extends surface.BaseTokenProvider {
  protected async performLogin(): Promise<ITokenResult> { throw new Error('login failed'); }
  protected async performRefresh(): Promise<ITokenResult> { throw new Error('refresh failed'); }
  protected getAuthType(): OAuth2GrantType { return 'client_credentials'; }
}

const SLC = 'C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\lib\\sapcrypto.dll';
const providers: [string, IAuthProvider][] = [
  ['basic', new surface.BasicAuthProvider('u', 'p')],
  ['saml', new surface.SamlAuthProvider('c=1')],
  ['token fixed', surface.TokenAuthProvider.fixed('t')],
  ['token from', surface.TokenAuthProvider.from({ getToken: async () => 't', refreshToken: async () => 't2' })],
  ['certificate', new surface.CertificateAuthProvider({ load: async () => ({ cert: 'C', key: 'K' }) }, { url: 'https://h', authType: 'certificate' })],
  ['token provider (failing)', new FailingTokenProvider()],
  ['snc', new surface.SncLogonProvider({
    partnerName: 'p:CN=SID',
    system: fakeSystem({ files: { [SLC]: peLibrary('x64') }, registry: { 'HKLM\\Software\\SAP\\SecureLogin\\InstallPath64': 'C:\\Program Files\\SAP\\FrontEnd\\SecureLogin\\' }, processes: ['sbus.exe'] }),
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
  it('every moment resolves to an AuthOutcome, never throws', async () => {
    const t = recordingTargets();
    for (const answer of [
      await provider.prepare(),
      await provider.establish(t.logonTarget),
      await provider.authorize(t.requestTarget),
      await provider.rejected({ at: 'request', status: 401, error: new Error('401') }),
      await provider.rejected({ at: 'logon', error: 'refused' }),
    ]) {
      expect(isOutcome(answer)).toBe(true);
    }
  });
});
```

- [ ] **Step 2: Run to see it fail** — `npm test -- src/__tests__/contract.test.ts` → FAIL: `surface.BasicAuthProvider` undefined.

- [ ] **Step 3: Exports**

In `src/index.ts` add:

```ts
// Credentials the process delegates to — every one an IAuthProvider.
export { BasicAuthProvider } from './credentials/BasicAuthProvider';
export { CertificateAuthProvider } from './credentials/CertificateAuthProvider';
export { FileCertificateMaterialLoader } from './credentials/FileCertificateMaterialLoader';
export { SamlAuthProvider } from './credentials/SamlAuthProvider';
export { TokenAuthProvider } from './credentials/TokenAuthProvider';
// SNC — passwordless RFC logon. The locator and probes are strategies.
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

and add `type TokenProviderHooks` to the existing `export type { … } from './providers'` list. Run `npx biome check --write src` to sort.

Append to `src/__tests__/exports.test.ts`:

```ts
describe('public exports — credentials and SNC', () => {
  it.each([
    'BasicAuthProvider', 'CertificateAuthProvider', 'FileCertificateMaterialLoader',
    'SamlAuthProvider', 'TokenAuthProvider', 'SncLogonProvider',
    'DefaultSncLibraryLocator', 'SecureLoginClientProbe', 'nodeSncSystem',
  ])('exports %s', (name) => {
    expect((surface as Record<string, unknown>)[name]).toBeDefined();
  });
  it.each([
    'libraryArchitectures', 'sncRefusal', 'refusalFrom', 'oops',
    'parseRegQuery', 'parseTasklistCsv', 'parsePsComm',
  ])('does not export the internal %s', (name) => {
    expect(name in surface).toBe(false);
  });
});
```

- [ ] **Step 4: Full suite** — `npm run lint:check && npm run test:check && npm test` → PASS.

- [ ] **Step 5: Commit** — `git add src/index.ts src/__tests__/exports.test.ts src/__tests__/contract.test.ts && git commit -m "feat: export every IAuthProvider; one contract test over all of them"`

### Task 10: Documentation and version 5.0.0

**Files:**
- Modify: `CLAUDE.md`, `README.md`, `docs/passwordless-sso.md`, `CHANGELOG.md`, `package.json`, `package-lock.json`

- [ ] **Step 1: `CLAUDE.md`** — "Project Overview": the package provides the credentials a process delegates to — every `IAuthProvider` (`interfaces-auth` 3.0.0: `prepare` / `establish` / `authorize` / `rejected`, each answering Ok or Oops) and the token providers behind them. Add the moved providers and `SncLogonProvider` to the list; `src/credentials/`, `src/snc/`, `src/auth/refusal.ts` to "Module structure". "Package responsibilities": "implements `ITokenProvider`" becomes "implements `IAuthProvider` (every provider) and `ITokenProvider` (the token providers)"; "does NOT" gains "retry — every retry is the consumer's" and "open connections or load SAP libraries". Add the four rules (no exception across the contract, no secret in a refusal, nothing to add is Ok, no provider retries) under "Core design principles".

- [ ] **Step 2: `README.md`** — a "Migrating to 5.0.0" section, first under the title: this is a migration, not an update: credentials come from here, not `@mcp-abap-adt/connection`; a token provider is handed to the process as it is; persist with `onTokens`; needs `@mcp-abap-adt/connection` 10.0.0. Then a "Passwordless RFC logon (SNC)" section: prerequisites (NW RFC SDK and `@mcp-abap-adt/sap-rfc-lite` on the connection side; an SNC product such as the SAP Secure Login Client, installed and logged on), `SncLogonProviderConfig`, the discovery order and skip rule, the probe rule, the two explained failures.

- [ ] **Step 3: `docs/passwordless-sso.md`** — SNC over RFC: Measured 2026-09-29 and Built (`SncLogonProvider`); replace "Rejected — an RFC/SNC transport"; `node-rfc` bullet → `@mcp-abap-adt/sap-rfc-lite`; open question 2 partly answered: the Secure Login Client enrols over `/api/v1/getProfiles`, `/api/v1/getCertificateTemplateStandardBrowser`, `/slc/v1/login` (Measured, from its profile registry; not used here).

- [ ] **Step 4: `CHANGELOG.md`** — a `## [5.0.0] - <date>` entry under `## [Unreleased]`: **Breaking — a migration**: every provider implements `IAuthProvider` (`interfaces-auth` 3.0.0); `BaseTokenProvider` implements it beside `IRefreshableTokenProvider`; `onTokens`; `Saml2PureProvider` presents cookies; Basic / Certificate / SAML / Token / `FileCertificateMaterialLoader` moved in from `connection` (`TokenAuthProvider.fixed` / `.from` only); `SncLogonProvider`; the four rules; dependencies `interfaces-auth ^3.0.0`, `interfaces-auth-sap ^1.1.0`.

- [ ] **Step 5: Version** — `"version": "5.0.0"`; `npm install --package-lock-only`; `npm run build && npm run lint:check && npm run test:check && npm test` → PASS.

- [ ] **Step 6: Commit** — `git add CLAUDE.md README.md docs/passwordless-sso.md CHANGELOG.md package.json package-lock.json && git commit -m "chore(release): 5.0.0 — every IAuthProvider on one contract; a migration, not an update"`. Push, open the PR, merge after review, publish through the repo's release flow. The spec and this plan are deleted in the PR that finishes step 5 of the goal (the server); the goal file goes with them.

### Task 11: Live SNC check (manual, not CI)

- [ ] **Step 1:** On a machine with the NW RFC SDK, `@mcp-abap-adt/sap-rfc-lite` and the Secure Login Client logged on: `new SncLogonProvider({ partnerName: '<system SNC name>' })`, `await prepare()` → Ok; `establish()` into a recording target → the params, with the registry's x64 `sapcrypto.dll` even with the installer's x86 `SNC_LIB` set.
- [ ] **Step 2:** Feed those params into the private probe's hand-built RFC conversation factory in place of its own `snc_*`; discovery and LOCK/UNLOCK → 200.
- [ ] **Step 3:** Log the Secure Login Client profile out; the RFC open fails; `rejected({ at: 'logon', error })` → hint "log on in the Secure Login Client". Record all three in the PR.
