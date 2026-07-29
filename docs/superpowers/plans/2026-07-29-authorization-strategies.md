# Authorization Strategies Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move callback reception out of the authorization library behind a consumer-implementable strategy, support ephemeral ports, and stop a code-less callback from ending a login.

**Architecture:** Providers stop owning sockets, browsers and stdin. They expose `buildAuthorizationUrl(redirectUri)` and hand it to an `IAuthorizationStrategy` supplied by the consumer; the package ships default strategies composed from its own `CallbackServerFactory` implementations. Because the URL is built *after* the strategy binds, ephemeral ports become possible and PKCE challenge/verifier stay one pair.

**Tech Stack:** TypeScript, Node ≥18, Express 5, Jest (`--experimental-vm-modules`), Biome for lint, four npm packages released in dependency order.

**Spec:** `docs/superpowers/specs/2026-07-29-authorization-strategies-design.md` (read it before Task 1; every design decision below is justified there).

## Global Constraints

- Release order is strict: `interfaces@11.5.0` → `auth-providers@2.0.0` → `proxy@1.7.0` → `auth-broker@1.0.9`. A consumer is never bumped before its dependency is published.
- **The agent never runs `npm publish`.** Tag, push the tag, then tell the user to publish and wait for confirmation.
- Every package: branch (`feat/authorization-strategies`), PR referencing the issue, squash merge, tag `vX.Y.Z`, push tag.
- Default callback port is `61001` — above Linux `ip_local_port_range` (32768–60999) and clear of the 3001/3333 range the proxy uses. Default login timeout is `30_000` ms.
- Nothing may write to `process.stdout`. User-facing prompts go to the logger, or to `process.stderr` when no logger exists — stdout carries MCP/LSP protocol traffic.
- `npm run lint:check` and `npm run build` must pass before every commit; `npm test` before every push.
- Repos live side by side under `/home/okyslytsia/prj/`: `mcp-abap-adt-interfaces`, `mcp-abap-adt-auth-providers`, `mcp-abap-adt-proxy`, `mcp-abap-adt-auth-broker`.

## File Structure

**`mcp-abap-adt-interfaces`**
- Create `src/auth/IAuthorizationStrategy.ts` — the strategy contract, types only.
- Modify `src/auth/ICallbackServer.ts` — allow `port: 0`, add `logger`.
- Modify `src/index.ts` — export the new types.
- Create `src/__typechecks__/authorizationStrategy.ts` — compile-only assertions.

**`mcp-abap-adt-auth-providers`**
- Modify `src/auth/callbackServer.ts` — bind-time port reporting, `settle.ignore`, tally.
- Modify `src/auth/oidcBrowserAuth.ts` — add the missing `error=` branch, then ignore.
- Modify `src/auth/saml2Auth.ts` — decide the response after checking the payload.
- Modify `src/auth/browserAuth.ts` — `redirectUri` replaces `port` in URL building and exchange; `startBrowserAuth` and the stdin reader are deleted.
- Create `src/strategies/BrowserCallbackStrategy.ts` — the class plus the three flow-specific constructors.
- Create `src/strategies/manualStrategies.ts` — paste-a-code and paste-a-SAMLResponse.
- Create `src/strategies/codeStrategies.ts` — `externalCodeStrategy`, `staticCodeStrategy`.
- Create `src/strategies/asOidcResult.ts` — the payload adapter.
- Create `src/strategies/index.ts` — one import surface for the above.
- Modify the four interactive providers and `src/providers/saml2Utils.ts`.
- Delete `src/auth/manualInput.ts` (its stdout prompt is replaced).

Strategies get their own directory rather than joining `src/auth/`: they are the consumer-facing surface, while `src/auth/` holds flow mechanics. Splitting them by kind keeps each file under ~150 lines.

**`mcp-abap-adt-proxy`** — `src/proxy/btpProxy.ts:295-298` only.
**`mcp-abap-adt-auth-broker`** — integration test config only.

---

# Phase A — `interfaces@11.5.0`

### Task 1: Add the authorization strategy contract

**Files:**
- Create: `/home/okyslytsia/prj/mcp-abap-adt-interfaces/src/auth/IAuthorizationStrategy.ts`
- Modify: `/home/okyslytsia/prj/mcp-abap-adt-interfaces/src/index.ts`
- Test: `/home/okyslytsia/prj/mcp-abap-adt-interfaces/src/__typechecks__/authorizationStrategy.ts`

**Interfaces:**
- Consumes: `ILogger` from `../logging/ILogger`.
- Produces: `AuthorizationRequest`, `AuthorizationOutcome<TResult>`, `IAuthorizationStrategy<TResult>` — every later task in every package imports these from `@mcp-abap-adt/interfaces`.

This package has no jest. Its tests are compile-only files under `src/__typechecks__/`, verified by `npm run test:check` (`tsc --noEmit`). A "failing test" here means a file that does not compile.

- [ ] **Step 1: Write the failing typecheck**

Create `src/__typechecks__/authorizationStrategy.ts`:

```ts
// Compile-only assertions. If these stop compiling, the types regressed.

import type {
  AuthorizationOutcome,
  AuthorizationRequest,
  IAuthorizationStrategy,
} from '../auth/IAuthorizationStrategy';

// A strategy that receives a URL builder and returns a payload plus the URI it used.
const _browserish: IAuthorizationStrategy<string> = {
  authorize: async (request: AuthorizationRequest) => {
    const redirectUri = 'http://localhost:61001/callback';
    const url = await request.buildAuthorizationUrl(redirectUri);
    void url;
    return { payload: 'code-123', redirectUri };
  },
  dispose: async () => undefined,
};
void _browserish;

// `dispose` is optional: a strategy holding nothing may omit it.
const _disposeless: IAuthorizationStrategy<{ code: string }> = {
  authorize: async () => ({
    payload: { code: 'abc' },
    redirectUri: 'http://localhost:61001/callback',
  }),
};
void _disposeless;

// The outcome is generic over the payload the flow delivers.
const _samlOutcome: AuthorizationOutcome<string> = {
  payload: 'base64-saml-response',
  redirectUri: 'http://localhost:61001/callback',
};
void _samlOutcome;
```

- [ ] **Step 2: Run the typecheck to verify it fails**

```bash
cd /home/okyslytsia/prj/mcp-abap-adt-interfaces && npm run test:check
```

Expected: FAIL — `Cannot find module '../auth/IAuthorizationStrategy'`.

- [ ] **Step 3: Write the contract**

Create `src/auth/IAuthorizationStrategy.ts`:

```ts
/**
 * How an interactive authorization is conducted.
 *
 * The provider owns what it can compute — the authorization URL and the token
 * exchange. Everything between them (reaching the URL, receiving what comes
 * back, the port, the timeout) belongs to whoever implements this interface,
 * which is why a consumer can replace it wholesale.
 *
 * See `ICallbackServer` for the transport a shipped strategy is composed of.
 */

import type { ILogger } from '../logging/ILogger';

/** What the provider tells a strategy about the login to conduct. */
export interface AuthorizationRequest {
  /**
   * Build the authorization URL for a redirect URI the strategy has settled on.
   *
   * Called once the strategy knows its redirect URI — which is what makes an
   * ephemeral port possible, since the URL cannot be assembled before the
   * socket is bound. May not be called at all: a strategy that already holds a
   * payload needs no URL.
   *
   * Asynchronous because building may require OIDC discovery. Rejects when the
   * redirect URI cannot be honoured — a pre-built authorization URL carries its
   * own redirect, and a mismatch must fail here, before a browser is opened,
   * rather than as a callback that never arrives.
   */
  buildAuthorizationUrl(redirectUri: string): Promise<string>;

  /** For progress messages. Absent means silence — never stdout. */
  readonly logger?: ILogger;
}

/** How the login ended. */
export interface AuthorizationOutcome<TResult> {
  /** What the redirect carried: a code, `{code, state}`, a SAMLResponse. */
  readonly payload: TResult;

  /**
   * The redirect URI that actually took part. The token exchange must send this
   * one — with an ephemeral port the provider has no other way to learn it.
   */
  readonly redirectUri: string;
}

/**
 * A way of conducting an interactive authorization.
 *
 * `authorize` may be called again sequentially; an implementation that holds a
 * fixed port should reject overlapping calls rather than queue them.
 *
 * `dispose` carries four obligations:
 * - idempotent — every call after the first resolves as a no-op;
 * - legal during an active `authorize`, which it ends with a rejection, since
 *   releasing resources while a socket is still bound would be untrue;
 * - resolves only once the resources are actually free;
 * - never masks a failure from `authorize` — a caller invoking it from
 *   `finally` propagates the original error and logs the cleanup one.
 */
export interface IAuthorizationStrategy<TResult> {
  authorize(
    request: AuthorizationRequest,
  ): Promise<AuthorizationOutcome<TResult>>;
  dispose?(): Promise<void>;
}
```

- [ ] **Step 4: Export from the index**

In `src/index.ts`, directly below the `ICallbackServer` export block (around line 309):

```ts
export type {
  AuthorizationOutcome,
  AuthorizationRequest,
  IAuthorizationStrategy,
} from './auth/IAuthorizationStrategy';
```

- [ ] **Step 5: Run the typecheck to verify it passes**

```bash
cd /home/okyslytsia/prj/mcp-abap-adt-interfaces && npm run test:check && npm run lint:check && npm run build
```

Expected: all three succeed.

- [ ] **Step 6: Commit**

```bash
cd /home/okyslytsia/prj/mcp-abap-adt-interfaces
git add src/auth/IAuthorizationStrategy.ts src/index.ts src/__typechecks__/authorizationStrategy.ts
git commit -m "feat: add IAuthorizationStrategy contract"
```

---

### Task 2: Allow an ephemeral callback port and a transport logger

**Files:**
- Modify: `/home/okyslytsia/prj/mcp-abap-adt-interfaces/src/auth/ICallbackServer.ts:15-45`
- Test: `/home/okyslytsia/prj/mcp-abap-adt-interfaces/src/__typechecks__/authorizationStrategy.ts`

**Interfaces:**
- Produces: `ICallbackServerOptions` gains `logger?: ILogger`; `port` accepts `0`.

- [ ] **Step 1: Extend the typecheck**

Append to `src/__typechecks__/authorizationStrategy.ts`:

```ts
import type { ICallbackServerOptions } from '../auth/ICallbackServer';
import type { ILogger } from '../logging/ILogger';

const logger: ILogger = {
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
};

// Ephemeral port plus a transport-level logger.
const _ephemeral: ICallbackServerOptions = {
  port: 0,
  timeoutMs: 30_000,
  logger,
};
void _ephemeral;
```

- [ ] **Step 2: Run the typecheck to verify it fails**

```bash
cd /home/okyslytsia/prj/mcp-abap-adt-interfaces && npm run test:check
```

Expected: FAIL — `Object literal may only specify known properties, and 'logger' does not exist in type 'ICallbackServerOptions'`.

If `ILogger`'s members differ from `debug/info/warn/error`, open `src/logging/ILogger.ts` and match it exactly — the point of the assertion is the options type, not the logger shape.

- [ ] **Step 3: Update the options contract**

In `src/auth/ICallbackServer.ts`, replace the `port` doc comment and add `logger`. The `import type { ILogger }` goes at the top of the file:

```ts
import type { ILogger } from '../logging/ILogger';
```

```ts
  /**
   * Port for the local listener. Must be an integer in 0..65535.
   *
   * `0` means "bind an ephemeral port": the handle then reports what the OS
   * actually gave, and the authorization URL must be built from
   * `handle.redirectUri` rather than from anything known beforehand. A flow
   * that assembles its URL before binding — or one whose redirect is
   * registered with the identity provider, as a SAML ACS always is — cannot
   * use it, because the redirect would advertise a port nobody is listening on.
   */
  readonly port: number;
```

```ts
  /**
   * Where the transport reports what it did — an ignored request that was not
   * our redirect, for instance. Absent means silence; never stdout.
   */
  readonly logger?: ILogger;
```

- [ ] **Step 4: Run the typecheck to verify it passes**

```bash
cd /home/okyslytsia/prj/mcp-abap-adt-interfaces && npm run test:check && npm run lint:check && npm run build
```

Expected: all three succeed.

- [ ] **Step 5: Commit**

```bash
cd /home/okyslytsia/prj/mcp-abap-adt-interfaces
git add src/auth/ICallbackServer.ts src/__typechecks__/authorizationStrategy.ts
git commit -m "feat: allow an ephemeral callback port and a transport logger"
```

---

### Task 3: Release `interfaces@11.5.0`

**Files:**
- Modify: `/home/okyslytsia/prj/mcp-abap-adt-interfaces/package.json` (version)
- Modify: `/home/okyslytsia/prj/mcp-abap-adt-interfaces/CHANGELOG.md`

- [ ] **Step 1: Open the tracking issue**

```bash
cd /home/okyslytsia/prj/mcp-abap-adt-interfaces
gh issue create --title "Add IAuthorizationStrategy and allow an ephemeral callback port" \
  --body "Needed by mcp-abap-adt-auth-providers#11. Adds \`IAuthorizationStrategy\`/\`AuthorizationRequest\`/\`AuthorizationOutcome\`, allows \`ICallbackServerOptions.port === 0\`, and adds \`ICallbackServerOptions.logger\`. Purely additive: no existing consumer changes behaviour. Consumer impact: auth-providers@2.0.0."
```

Note the issue number it prints; call it `$IFACE_ISSUE`.

- [ ] **Step 2: Bump the version**

In `package.json`, set `"version": "11.5.0"`.

- [ ] **Step 3: Write the changelog entry**

Prepend to `CHANGELOG.md` beneath the title, matching the file's existing heading style:

```markdown
## 11.5.0

### Added

- `IAuthorizationStrategy<TResult>`, `AuthorizationRequest` and
  `AuthorizationOutcome<TResult>` — the contract by which a consumer supplies
  its own way of conducting an interactive authorization.
- `ICallbackServerOptions.logger` — where the transport reports an ignored
  request.

### Changed

- `ICallbackServerOptions.port` accepts `0`, meaning an ephemeral port. Flows
  that build their authorization URL before binding still cannot use it.
```

- [ ] **Step 4: Verify, commit, push the branch and open the PR**

```bash
cd /home/okyslytsia/prj/mcp-abap-adt-interfaces
npm run lint:check && npm run test:check && npm run build
git add package.json CHANGELOG.md
git commit -m "release(11.5.0): authorization strategy contract"
git push -u origin feat/authorization-strategies
gh pr create --title "feat: authorization strategy contract + ephemeral callback port" \
  --body "Closes #$IFACE_ISSUE

Additive only. Adds \`IAuthorizationStrategy\`, allows \`port: 0\`, adds a transport logger.

\`\`\`ts
// after
const strategy: IAuthorizationStrategy<string> = {
  async authorize(req) {
    const redirectUri = 'http://localhost:61001/callback';
    const url = await req.buildAuthorizationUrl(redirectUri);
    return { payload: await receiveCode(url), redirectUri };
  },
};
\`\`\`

Consumer impact: auth-providers@2.0.0 depends on this."
```

- [ ] **Step 5: Merge and tag**

```bash
cd /home/okyslytsia/prj/mcp-abap-adt-interfaces
gh pr merge --squash --delete-branch
git checkout master && git pull --ff-only
git tag -a v11.5.0 -m "Authorization strategy contract, ephemeral callback port"
git push --tags
```

If the default branch is `main` rather than `master`, use that — check with `git symbolic-ref refs/remotes/origin/HEAD`.

- [ ] **Step 6: Hand the publish to the user**

Stop here and tell the user:

> `interfaces@11.5.0` is tagged and pushed. Next step is yours: `cd /home/okyslytsia/prj/mcp-abap-adt-interfaces && npm publish`. Tell me when it is on the registry.

Do not proceed to Phase B until the user confirms.

---

# Phase B — `auth-providers@2.0.0`

### Task 4: Consume the new interfaces build

**Files:**
- Modify: `/home/okyslytsia/prj/mcp-abap-adt-auth-providers/package.json:61`

- [ ] **Step 1: Create the branch and bump the dependency**

```bash
cd /home/okyslytsia/prj/mcp-abap-adt-auth-providers
git checkout -b feat/authorization-strategies
```

In `package.json`, change `"@mcp-abap-adt/interfaces": "^11.4.0"` to `"^11.5.0"`.

- [ ] **Step 2: Force-refresh the installed copy**

npm keeps stale `.d.ts` files after a range bump, which produces type errors that have nothing to do with your code.

```bash
cd /home/okyslytsia/prj/mcp-abap-adt-auth-providers
rm -rf node_modules/@mcp-abap-adt/interfaces
npm install @mcp-abap-adt/interfaces@11.5.0 --save
```

- [ ] **Step 3: Verify the installed version — not the registry's**

```bash
grep '"version"' node_modules/@mcp-abap-adt/interfaces/package.json
grep -c "IAuthorizationStrategy" node_modules/@mcp-abap-adt/interfaces/dist/index.d.ts
```

Expected: `11.5.0`, and a count of at least 1. `npm view` reports the registry, not what is on disk — do not use it here.

- [ ] **Step 4: Confirm the tree still builds**

```bash
npm run build && npm test
```

Expected: green. Nothing consumes the new types yet.

- [ ] **Step 5: Commit**

```bash
git add package.json package-lock.json
git commit -m "chore: depend on interfaces@11.5.0"
```

---

### Task 5: Report the bound port, not the requested one

**Files:**
- Modify: `src/auth/callbackServer.ts:45-62` (validation), `:215-255` (handle and listen)
- Test: `src/__tests__/auth/callbackServer.test.ts`

**Interfaces:**
- Produces: `runCallbackScope` accepts `port: 0`; `ICallbackServerHandle.port` and `.redirectUri` report the bound port.

- [ ] **Step 1: Write the failing test**

Append to `src/__tests__/auth/callbackServer.test.ts`:

```ts
describe('ephemeral port', () => {
  it('reports the bound port and frees it when the scope ends', async () => {
    let observed = 0;
    const code = await withBrowserCallbackServer(
      { port: 0, timeoutMs: 5000 },
      async (srv) => {
        observed = srv.port;
        expect(observed).toBeGreaterThan(0);
        expect(srv.redirectUri).toBe(`http://localhost:${observed}/callback`);
        expect(await portIsFree(observed)).toBe(false);
        const waiting = srv.waitForResult();
        void httpGetOn(observed, '/callback?code=eph').catch(() => undefined);
        return await waiting;
      },
    );
    expect(code).toBe('eph');
    expect(await portIsFree(observed)).toBe(true);
  }, 30000);
});
```

The existing `httpGet` helper is hard-wired to the module-level `PORT`. Add a port-taking variant beside it and redefine `httpGet` in terms of it, so the two cannot drift:

```ts
function httpGetOn(
  port: number,
  path: string,
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.get(
      { host: '127.0.0.1', port, path, agent: false },
      (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk: string) => {
          body += chunk;
        });
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body }));
      },
    );
    req.on('error', reject);
  });
}

function httpGet(path: string): Promise<{ status: number; body: string }> {
  return httpGetOn(PORT, path);
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd /home/okyslytsia/prj/mcp-abap-adt-auth-providers
npm test -- src/__tests__/auth/callbackServer.test.ts -t "reports the bound port"
```

Expected: FAIL — `Invalid callback server port: 0. Must be an integer in 1..65535.`

- [ ] **Step 3: Accept port 0 in validation**

In `src/auth/callbackServer.ts`, change the port check inside `validate`:

```ts
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error(
      `Invalid callback server port: ${String(port)}. Must be an integer in 0..65535.`,
    );
  }
```

- [ ] **Step 4: Build the handle from the bound address**

Delete the `const handle: ICallbackServerHandle<TResult> = {...}` block at `:215-230` and move it inside the `listen` callback. Add `import type { AddressInfo } from 'node:net';` at the top. The `listen` block becomes:

```ts
  server.listen(options.port, () => {
    if (scopeSettled) {
      // Aborted while binding.
      void shutdown();
      return;
    }
    alive = true;
    timer = setTimeout(() => {
      endScope({
        error: new Error(
          `Authentication timeout after ${options.timeoutMs / 1000} seconds. Please try again.`,
        ),
      });
    }, options.timeoutMs);

    // The requested port may be 0, in which case only the OS knows the answer.
    const bound = (server.address() as AddressInfo).port;
    const handle: ICallbackServerHandle<TResult> = {
      port: bound,
      redirectUri: `http://localhost:${bound}/callback`,
      waitForResult: () =>
        alive
          ? resultPromise
          : Promise.reject(new Error('Callback server scope has ended')),
      // Silent no-op once the scope has ended: this is called fire-and-forget
      // from a browser launcher's .catch(), and a late rejection must not become
      // a fresh unhandled rejection.
      fail: (error: Error) => {
        if (!alive) return;
        settleResult({ error });
        endScope({ error });
      },
    };

    void use(handle).then(
      (value) => endScope({ value }),
      (error: Error) => endScope({ error }),
    );
  });
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
npm test -- src/__tests__/auth/callbackServer.test.ts
```

Expected: PASS, including the pre-existing cases — the fixed-port ones assert `srv.port === PORT`, which still holds.

- [ ] **Step 6: Commit**

```bash
npm run lint:check && npm run build
git add src/auth/callbackServer.ts src/__tests__/auth/callbackServer.test.ts
git commit -m "feat: report the bound callback port and accept an ephemeral one"
```

---

### Task 6: Ignore incomplete callbacks instead of ending the login

**Files:**
- Modify: `src/auth/callbackServer.ts:28-43` (`Settle`), `:199-209` (settle object), `:236-249` (timeout), `:315-341` (UAA route)
- Test: `src/__tests__/auth/callbackServer.test.ts`

**Interfaces:**
- Produces: `Settle<TResult>.ignore(reason: string, res?: express.Response): void`.

- [ ] **Step 1: Write the failing tests**

Append to `src/__tests__/auth/callbackServer.test.ts`:

```ts
describe('incomplete callbacks', () => {
  it('answers 400 and keeps waiting when neither code nor error arrived', async () => {
    const code = await withBrowserCallbackServer(
      { port: PORT, timeoutMs: 5000 },
      async (srv) => {
        const waiting = srv.waitForResult();
        const stray = await httpGet('/callback');
        expect(stray.status).toBe(400);
        // The scope survived the stray request and still accepts a real one.
        void deliver('?code=after-stray');
        return await waiting;
      },
    );
    expect(code).toBe('after-stray');
  }, 30000);

  it('counts ignored requests in the timeout message', async () => {
    const attempt = withBrowserCallbackServer(
      { port: PORT, timeoutMs: 1500 },
      async (srv) => await srv.waitForResult(),
    );
    await httpGet('/callback');
    await httpGet('/callback');
    await expect(attempt).rejects.toThrow(
      /2 incomplete request\(s\) reached \/callback and were ignored/,
    );
  }, 30000);

  it('still ends the login at once on an explicit IdP error', async () => {
    const attempt = withBrowserCallbackServer(
      { port: PORT, timeoutMs: 30000 },
      async (srv) => await srv.waitForResult(),
    );
    void deliver('?error=access_denied&error_description=User%20said%20no');
    await expect(attempt).rejects.toThrow(/access_denied: User said no/);
  }, 30000);
});
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
npm test -- src/__tests__/auth/callbackServer.test.ts -t "incomplete callbacks"
```

Expected: the first two FAIL — the login currently ends with `Authorization code missing`. The third passes already; it is there to pin that the refusal path is untouched.

- [ ] **Step 3: Add `ignore` to the settle contract**

In `src/auth/callbackServer.ts`, extend the interface:

```ts
export interface Settle<TResult> {
  /** The callback delivered a result. Does not end the scope by itself. */
  ok(value: TResult, res?: express.Response): void;
  /** The callback reported a failure. Ends the scope. */
  err(error: Error, res?: express.Response): void;
  /**
   * This was not our redirect — a reloaded tab, a prefetch, a port scanner.
   * Answered and counted; the login keeps waiting, bounded as ever by the
   * timeout. Ends nothing.
   */
  ignore(reason: string, res?: express.Response): void;
}
```

- [ ] **Step 4: Count and report**

Beside `let alive = false;` add:

```ts
  let ignored = 0;
```

Extend the `settle` object with the third method (no `afterFlush`: nothing settles, so there is no race with shutdown):

```ts
    ignore(reason) {
      ignored += 1;
      options.logger?.warn(
        '[callbackServer] ignored an incomplete callback request',
        { reason, ignored },
      );
    },
```

Replace the timeout body so the tally travels with the message:

```ts
    timer = setTimeout(() => {
      const tally =
        ignored > 0
          ? ` ${ignored} incomplete request(s) reached /callback and were ignored.`
          : '';
      endScope({
        error: new Error(
          `Authentication timeout after ${options.timeoutMs / 1000} seconds. Please try again.${tally}`,
        ),
      });
    }, options.timeoutMs);
```

The wording names no payload on purpose: the same scope serves SAML, where what is missing is a `SAMLResponse`, not a code.

- [ ] **Step 5: Switch the UAA route**

In `withBrowserCallbackServer`, replace the missing-code branch:

```ts
        const { code } = req.query;
        if (!code || typeof code !== 'string') {
          res.status(400).send('Error: not an authorization callback');
          settle.ignore('no code and no error in query', res);
          return;
        }
```

- [ ] **Step 6: Run the tests to verify they pass**

```bash
npm test -- src/__tests__/auth/callbackServer.test.ts
```

Expected: PASS, all cases.

- [ ] **Step 7: Commit**

```bash
npm run lint:check && npm run build
git add src/auth/callbackServer.ts src/__tests__/auth/callbackServer.test.ts
git commit -m "feat: ignore incomplete callbacks and report the tally on timeout"
```

---

### Task 7: Give the OIDC route a refusal branch, then an ignore branch

**Files:**
- Modify: `src/auth/oidcBrowserAuth.ts:93-109`
- Test: `src/__tests__/auth/oidcCallbackRoutes.test.ts` (create)

**Interfaces:**
- Consumes: `Settle<TResult>` from Task 6.
- Produces: `withOidcCallbackServer` exported from `src/auth/oidcBrowserAuth.ts` (it is currently module-private; the test and Task 11 both need it).

Order matters here. The OIDC route has one failure branch — missing `code` — and **no `error=` branch at all**. Swapping that branch to `ignore` without adding the refusal branch first would turn `?error=access_denied` into a silent wait until timeout.

- [ ] **Step 1: Write the failing tests**

Create `src/__tests__/auth/oidcCallbackRoutes.test.ts`:

```ts
/**
 * The OIDC callback route.
 *
 * Its missing-code branch used to serve two very different requests: an IdP
 * refusing the login, and a stray request that was never part of one. They now
 * part ways, and the refusal must keep failing fast.
 */

import http from 'node:http';
import net from 'node:net';
import { afterEach, describe, expect, it } from '@jest/globals';
import { withOidcCallbackServer } from '../../auth/oidcBrowserAuth';

const PORT = 7877;

function portIsFree(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.once('error', () => resolve(false));
    s.listen(port, () => s.close(() => resolve(true)));
  });
}

function httpGet(path: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.get(
      { host: '127.0.0.1', port: PORT, path, agent: false },
      (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk: string) => {
          body += chunk;
        });
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body }));
      },
    );
    req.on('error', reject);
  });
}

afterEach(async () => {
  expect(await portIsFree(PORT)).toBe(true);
});

describe('withOidcCallbackServer', () => {
  it('ends the login at once when the IdP refuses', async () => {
    const attempt = withOidcCallbackServer(
      { port: PORT, timeoutMs: 30000 },
      async (srv) => await srv.waitForResult(),
    );
    const res = await httpGet(
      '/callback?error=access_denied&error_description=User%20said%20no',
    );
    expect(res.status).toBe(400);
    await expect(attempt).rejects.toThrow(/access_denied: User said no/);
  }, 30000);

  it('answers 400 and keeps waiting for a request carrying neither', async () => {
    const result = await withOidcCallbackServer(
      { port: PORT, timeoutMs: 5000 },
      async (srv) => {
        const waiting = srv.waitForResult();
        const stray = await httpGet('/callback');
        expect(stray.status).toBe(400);
        void httpGet('/callback?code=late&state=xyz').catch(() => undefined);
        return await waiting;
      },
    );
    expect(result).toEqual({ code: 'late', state: 'xyz' });
  }, 30000);
});
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
npm test -- src/__tests__/auth/oidcCallbackRoutes.test.ts
```

Expected: FAIL to compile — `withOidcCallbackServer` is not exported. After exporting it, the refusal case fails with `Missing authorization code` instead of the refusal message, and the stray case fails outright.

- [ ] **Step 3: Export the factory and rewrite the route**

In `src/auth/oidcBrowserAuth.ts`, add `export` to the factory declaration and replace the route body:

```ts
export const withOidcCallbackServer: CallbackServerFactory<OidcCallbackResult> = <
  TReturn,
>(
  options: ICallbackServerOptions,
  use: (server: ICallbackServerHandle<OidcCallbackResult>) => Promise<TReturn>,
): Promise<TReturn> =>
  runCallbackScope<OidcCallbackResult, TReturn>(
    options,
    (app, settle) => {
      app.get('/callback', (req, res) => {
        // An IdP that declines says so explicitly. That is a finished login,
        // not a stray request, and it must not wait for the timeout.
        const { error, error_description, error_uri } = req.query;
        if (error) {
          const message = error_description
            ? `${String(error)}: ${String(error_description)}`
            : String(error);
          res.status(400).send(`Authentication failed: ${message}`);
          settle.err(
            new Error(
              `OIDC authentication failed: ${message}` +
                (error_uri ? ` (${String(error_uri)})` : ''),
            ),
            res,
          );
          return;
        }

        const code = req.query.code;
        const state = req.query.state;
        if (!code || typeof code !== 'string') {
          res.status(400).send('Error: not an authorization callback');
          settle.ignore('no code and no error in query', res);
          return;
        }

        res
          .status(200)
          .send('Authentication complete. You can close this window.');
        settle.ok(
          { code, state: typeof state === 'string' ? state : undefined },
          res,
        );
      });
    },
    use,
  );
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
npm test -- src/__tests__/auth/oidcCallbackRoutes.test.ts
```

Expected: PASS, both cases.

- [ ] **Step 5: Commit**

```bash
npm run lint:check && npm run build
git add src/auth/oidcBrowserAuth.ts src/__tests__/auth/oidcCallbackRoutes.test.ts
git commit -m "feat: OIDC callback distinguishes an IdP refusal from a stray request"
```

---

### Task 8: Stop the SAML route from claiming success before it looks

**Files:**
- Modify: `src/auth/saml2Auth.ts:129-158`
- Test: `src/__tests__/auth/samlCallbackRoutes.test.ts` (create)

**Interfaces:**
- Produces: `withSamlCallbackServer` exported from `src/auth/saml2Auth.ts`.

The handler answers `200 "SAML authentication complete"` *before* it checks the payload, so a request with no `SAMLResponse` is shown a success page while the login fails behind it.

- [ ] **Step 1: Write the failing tests**

Create `src/__tests__/auth/samlCallbackRoutes.test.ts`:

```ts
/**
 * The SAML callback route, GET and POST separately.
 *
 * The two read the payload from different places — query versus form body — and
 * a shared handler makes it easy to fix one and miss the other.
 */

import http from 'node:http';
import net from 'node:net';
import { afterEach, describe, expect, it } from '@jest/globals';
import { withSamlCallbackServer } from '../../auth/saml2Auth';

const PORT = 7879;

function portIsFree(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.once('error', () => resolve(false));
    s.listen(port, () => s.close(() => resolve(true)));
  });
}

function request(
  method: 'GET' | 'POST',
  path: string,
  body?: string,
): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port: PORT,
        path,
        method,
        agent: false,
        headers: body
          ? {
              'content-type': 'application/x-www-form-urlencoded',
              'content-length': Buffer.byteLength(body),
            }
          : undefined,
      },
      (res) => {
        let text = '';
        res.setEncoding('utf8');
        res.on('data', (chunk: string) => {
          text += chunk;
        });
        res.on('end', () => resolve({ status: res.statusCode ?? 0, text }));
      },
    );
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

afterEach(async () => {
  expect(await portIsFree(PORT)).toBe(true);
});

describe('withSamlCallbackServer', () => {
  it('answers 400 without the completion page on a POST with no SAMLResponse', async () => {
    const assertion = await withSamlCallbackServer(
      { port: PORT, timeoutMs: 5000 },
      async (srv) => {
        const waiting = srv.waitForResult();
        const stray = await request('POST', '/callback', 'other=1');
        expect(stray.status).toBe(400);
        expect(stray.text).not.toMatch(/authentication complete/i);
        void request(
          'POST',
          '/callback',
          'SAMLResponse=PHNhbWw%2B',
        ).catch(() => undefined);
        return await waiting;
      },
    );
    expect(assertion).toBe('PHNhbWw+');
  }, 30000);

  it('answers 400 without the completion page on a GET with no SAMLResponse', async () => {
    const assertion = await withSamlCallbackServer(
      { port: PORT, timeoutMs: 5000 },
      async (srv) => {
        const waiting = srv.waitForResult();
        const stray = await request('GET', '/callback');
        expect(stray.status).toBe(400);
        expect(stray.text).not.toMatch(/authentication complete/i);
        void request('GET', '/callback?SAMLResponse=PHNhbWw%2B').catch(
          () => undefined,
        );
        return await waiting;
      },
    );
    expect(assertion).toBe('PHNhbWw+');
  }, 30000);
});
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
npm test -- src/__tests__/auth/samlCallbackRoutes.test.ts
```

Expected: FAIL to compile until the factory is exported; then both fail on `expect(stray.status).toBe(400)` — the route answers 200.

- [ ] **Step 3: Decide the response after the check**

In `src/auth/saml2Auth.ts`, add `export` to `withSamlCallbackServer` and replace the shared handler:

```ts
      const handle = (samlResponse: unknown, res: express.Response): void => {
        // The response is decided after the payload is examined. Answering 200
        // first told a request that carried nothing that it had authenticated.
        if (typeof samlResponse === 'string' && samlResponse) {
          res
            .status(200)
            .send('SAML authentication complete. You can close this window.');
          settle.ok(samlResponse, res);
          return;
        }
        res.status(400).send('Error: not a SAML assertion callback');
        settle.ignore('no SAMLResponse in the request', res);
      };
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
npm test -- src/__tests__/auth/samlCallbackRoutes.test.ts
```

Expected: PASS, both cases.

- [ ] **Step 5: Commit**

```bash
npm run lint:check && npm run build
git add src/auth/saml2Auth.ts src/__tests__/auth/samlCallbackRoutes.test.ts
git commit -m "fix: SAML callback answers 400 for a request carrying no assertion"
```

---

### Task 9: Take a redirect URI, not a port, when building and exchanging

**Files:**
- Modify: `src/auth/browserAuth.ts:60-73` (`getJwtAuthorizationUrl`), `:79-96` (`exchangeCodeForToken`)
- Test: `src/__tests__/auth/browserAuth.test.ts`

**Interfaces:**
- Produces: `getJwtAuthorizationUrl(authConfig, redirectUri: string): string` — now exported; `exchangeCodeForToken(authConfig, code, redirectUri: string, log?)`.

Both functions take a **port** today and rebuild `http://localhost:${port}/callback` internally. With an ephemeral port that guess is wrong, and the exchange would send a `redirect_uri` that never took part in the request.

- [ ] **Step 1: Write the failing test**

Append to `src/__tests__/auth/browserAuth.test.ts` (keep the file's existing import style; it already mocks axios):

```ts
describe('redirect URI plumbing', () => {
  it('builds the authorization URL around the URI it is given', () => {
    const url = getJwtAuthorizationUrl(
      {
        uaaUrl: 'https://uaa.example',
        uaaClientId: 'cid',
        uaaClientSecret: 's',
      },
      'http://localhost:54321/callback',
    );
    expect(url).toContain(
      `redirect_uri=${encodeURIComponent('http://localhost:54321/callback')}`,
    );
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
npm test -- src/__tests__/auth/browserAuth.test.ts -t "redirect URI plumbing"
```

Expected: FAIL — `getJwtAuthorizationUrl` is not exported, and its second parameter is a number.

- [ ] **Step 3: Change both signatures**

```ts
/**
 * Build the OAuth2 authorization URL for a redirect URI that is already known.
 *
 * The URI is a parameter rather than a port because the port may have been
 * chosen by the OS moments earlier — see `ICallbackServerOptions.port`.
 */
export function getJwtAuthorizationUrl(
  authConfig: IAuthorizationConfig,
  redirectUri: string,
): string {
  const oauthUrl = authConfig.uaaUrl;
  const clientid = authConfig.uaaClientId;

  if (!oauthUrl || !clientid) {
    throw new Error('Authorization config missing UAA URL or client ID');
  }

  return `${oauthUrl}/oauth/authorize?client_id=${encodeURIComponent(clientid)}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code`;
}
```

```ts
export async function exchangeCodeForToken(
  authConfig: IAuthorizationConfig,
  code: string,
  redirectUri: string,
  log?: ILogger | null,
): Promise<{ accessToken: string; refreshToken?: string }> {
```

and inside it delete the `const redirectUri = ...` line, keeping `params.append('redirect_uri', redirectUri);` as it stands.

- [ ] **Step 4: Update the existing callers and tests**

`startBrowserAuth` still calls both; it is deleted in Task 14, so for now pass `http://localhost:${port}/callback` at each call site to keep the build green. Any existing assertion in `browserAuth.test.ts` that passes a port to `exchangeCodeForToken` becomes a URI string.

- [ ] **Step 5: Run the tests to verify they pass**

```bash
npm test -- src/__tests__/auth/browserAuth.test.ts
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
npm run lint:check && npm run build
git add src/auth/browserAuth.ts src/__tests__/auth/browserAuth.test.ts
git commit -m "refactor: build and exchange around a redirect URI rather than a port"
```

---

### Task 10: The browser callback strategy

**Files:**
- Create: `src/strategies/BrowserCallbackStrategy.ts`
- Modify: `src/auth/browserAuth.ts` (export `launchBrowser`)
- Test: `src/__tests__/strategies/BrowserCallbackStrategy.test.ts` (create)

**Interfaces:**
- Consumes: `runCallbackScope` and the three factories; `AuthorizationRequest`, `AuthorizationOutcome`, `IAuthorizationStrategy` from `@mcp-abap-adt/interfaces`.
- Produces:
  - `DEFAULT_CALLBACK_PORT = 61001`, `DEFAULT_LOGIN_TIMEOUT_MS = 30_000`
  - `class BrowserCallbackStrategy<TResult> implements IAuthorizationStrategy<TResult>`
  - `browserCallbackStrategy(opts?): IAuthorizationStrategy<string>`
  - `oidcCallbackStrategy(opts?): IAuthorizationStrategy<OidcCallbackResult>`
  - `samlCallbackStrategy(opts?): IAuthorizationStrategy<string>`
  - `interface CallbackStrategyOptions { port?: number; timeoutMs?: number; browser?: string; openUrl?: (url: string, browser: string) => Promise<void>; signal?: AbortSignal }`

- [ ] **Step 1: Write the failing tests**

Create `src/__tests__/strategies/BrowserCallbackStrategy.test.ts`:

```ts
/**
 * The browser strategy against a fake transport.
 *
 * A fake `CallbackServerFactory` lets the four `dispose` obligations be tested
 * without binding a socket, which is what makes these assertions fast and
 * deterministic.
 */

import netModule from 'node:net';
import { describe, expect, it, jest } from '@jest/globals';
import type {
  CallbackServerFactory,
  ICallbackServerHandle,
} from '@mcp-abap-adt/interfaces';
import { BrowserCallbackStrategy } from '../../strategies/BrowserCallbackStrategy';

/** A factory that hands over a handle whose result the test controls. */
function fakeFactory(opts: {
  boundPort?: number;
  deliver?: (handle: ICallbackServerHandle<string>) => void;
}): { factory: CallbackServerFactory<string>; released: () => boolean } {
  let released = false;
  const factory: CallbackServerFactory<string> = async (options, use) => {
    const port = opts.boundPort ?? options.port ?? 61001;
    let settle!: (v: string) => void;
    let fail!: (e: Error) => void;
    const result = new Promise<string>((res, rej) => {
      settle = res;
      fail = rej;
    });
    void result.catch(() => undefined);
    const handle: ICallbackServerHandle<string> = {
      port,
      redirectUri: `http://localhost:${port}/callback`,
      waitForResult: () => result,
      fail: (e) => fail(e),
    };
    options.signal?.addEventListener('abort', () =>
      fail(new Error('Callback server aborted')),
    );
    opts.deliver?.({ ...handle, fail: (e) => fail(e) });
    setTimeout(() => settle('code-from-fake'), 0);
    try {
      return await use(handle);
    } finally {
      released = true;
    }
  };
  return { factory, released: () => released };
}

// `CallbackServerFactory` is generic in its return type, which an arrow
// function cannot express. If tsc objects, assert the shape once here rather
// than loosening the real contract:
//   const factory = impl as unknown as CallbackServerFactory<string>;

describe('BrowserCallbackStrategy', () => {
  it('builds the URL from the bound redirect URI and returns both halves', async () => {
    const { factory } = fakeFactory({ boundPort: 49999 });
    const openUrl = jest.fn(async () => undefined);
    const strategy = new BrowserCallbackStrategy<string>({
      callbackServer: factory,
      port: 0,
      openUrl,
    });

    const seen: string[] = [];
    const outcome = await strategy.authorize({
      buildAuthorizationUrl: async (redirectUri) => {
        seen.push(redirectUri);
        return `https://idp.example/authorize?redirect_uri=${encodeURIComponent(redirectUri)}`;
      },
    });

    expect(seen).toEqual(['http://localhost:49999/callback']);
    expect(outcome.payload).toBe('code-from-fake');
    expect(outcome.redirectUri).toBe('http://localhost:49999/callback');
    expect(openUrl).toHaveBeenCalledTimes(1);
  });

  it('rejects without opening a browser when the URL builder throws', async () => {
    const { factory, released } = fakeFactory({});
    const openUrl = jest.fn(async () => undefined);
    const strategy = new BrowserCallbackStrategy<string>({
      callbackServer: factory,
      openUrl,
    });

    await expect(
      strategy.authorize({
        buildAuthorizationUrl: async () => {
          throw new Error('redirect_uri mismatch');
        },
      }),
    ).rejects.toThrow('redirect_uri mismatch');
    expect(openUrl).not.toHaveBeenCalled();
    expect(released()).toBe(true);
  });

  it('refuses an overlapping authorize', async () => {
    const { factory } = fakeFactory({});
    const strategy = new BrowserCallbackStrategy<string>({
      callbackServer: factory,
      openUrl: async () => undefined,
    });
    const first = strategy.authorize({
      buildAuthorizationUrl: async () => 'https://idp.example/a',
    });
    await expect(
      strategy.authorize({
        buildAuthorizationUrl: async () => 'https://idp.example/b',
      }),
    ).rejects.toThrow(/already authorizing/);
    await first;
  });

  it('reports a busy fixed port in the words AuthBroker matches', async () => {
    const squatter = netModule.createServer();
    await new Promise<void>((resolve) => squatter.listen(7873, resolve));
    try {
      const { factory } = fakeFactory({});
      const strategy = new BrowserCallbackStrategy<string>({
        callbackServer: factory,
        port: 7873,
        openUrl: async () => undefined,
      });
      await expect(
        strategy.authorize({
          buildAuthorizationUrl: async () => 'https://idp.example/a',
        }),
      ).rejects.toThrow(/already in use/i);
    } finally {
      await new Promise<void>((resolve) => squatter.close(() => resolve()));
    }
  });

  it('skips the availability probe for an ephemeral port', async () => {
    const { factory } = fakeFactory({ boundPort: 49998 });
    const strategy = new BrowserCallbackStrategy<string>({
      callbackServer: factory,
      port: 0,
      openUrl: async () => undefined,
    });
    const outcome = await strategy.authorize({
      buildAuthorizationUrl: async () => 'https://idp.example/a',
    });
    expect(outcome.redirectUri).toBe('http://localhost:49998/callback');
  });

  it('disposes idempotently and ends an authorize in flight', async () => {
    const { factory, released } = fakeFactory({});
    const strategy = new BrowserCallbackStrategy<string>({
      callbackServer: factory,
      openUrl: async () => undefined,
    });

    const inFlight = strategy.authorize({
      buildAuthorizationUrl: async () =>
        await new Promise<string>(() => undefined), // never resolves
    });
    const settled = inFlight.catch((e: Error) => e.message);

    await strategy.dispose();
    await strategy.dispose(); // idempotent

    expect(await settled).toMatch(/abort/i);
    expect(released()).toBe(true);
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
npm test -- src/__tests__/strategies/BrowserCallbackStrategy.test.ts
```

Expected: FAIL — `Cannot find module '../../strategies/BrowserCallbackStrategy'`.

- [ ] **Step 3: Export the browser launcher**

In `src/auth/browserAuth.ts`, add `export` to `async function launchBrowser(` at line 177. Its signature is `(authorizationUrl: string, browser: string, port: number, announce: (msg: string) => void, log: ILogger | null)`; keep it unchanged — the strategy adapts to it.

- [ ] **Step 4: Write the strategy**

Create `src/strategies/BrowserCallbackStrategy.ts`:

```ts
/**
 * Reaching the authorization URL with a browser, receiving the redirect on a
 * local socket.
 *
 * The transport is injected rather than assumed: a consumer that already runs
 * an HTTP server can pass its own `CallbackServerFactory` and keep everything
 * else here.
 */

import * as net from 'node:net';
import type {
  AuthorizationOutcome,
  AuthorizationRequest,
  CallbackServerFactory,
  IAuthorizationStrategy,
  ILogger,
} from '@mcp-abap-adt/interfaces';
import { launchBrowser } from '../auth/browserAuth';
import { withBrowserCallbackServer } from '../auth/callbackServer';
import type { OidcCallbackResult } from '../auth/oidcBrowserAuth';
import { withOidcCallbackServer } from '../auth/oidcBrowserAuth';
import { withSamlCallbackServer } from '../auth/saml2Auth';

/**
 * Above Linux's `ip_local_port_range` (32768–60999), so an outbound connection
 * never squats on it, and far from the 3001/3333 range application servers use.
 */
export const DEFAULT_CALLBACK_PORT = 61001;

/** How long an interactive login may wait for its callback. */
export const DEFAULT_LOGIN_TIMEOUT_MS = 30_000;

export interface CallbackStrategyOptions {
  /** `0` binds an ephemeral port. Unusable where the IdP has a registered URI. */
  port?: number;
  timeoutMs?: number;
  /** 'none' | 'headless' print the URL; 'auto' | 'system' | 'chrome' | … open it. */
  browser?: string;
  openUrl?: (url: string, browser: string) => Promise<void>;
  signal?: AbortSignal;
}

export interface BrowserCallbackStrategyOptions<TResult>
  extends CallbackStrategyOptions {
  callbackServer: CallbackServerFactory<TResult>;
}

/**
 * Essential prompts must be visible without a logger, and must never go to
 * stdout: a stdio RPC transport carries protocol traffic there.
 */
function announcer(logger?: ILogger): (msg: string) => void {
  return (msg: string) => {
    if (logger) logger.info(msg);
    else process.stderr.write(`${msg}\n`);
  };
}

/**
 * Kept for its wording, not its certainty.
 *
 * `AuthBroker` matches /already in use/i to tell a busy port from every other
 * failure, and the bind error Node raises says `EADDRINUSE` instead. Skipped
 * entirely for an ephemeral port: there is nothing to check, and the answer
 * would be about a port we are not going to get.
 */
async function assertPortAvailable(port: number): Promise<void> {
  if (port === 0) return;
  const free = await new Promise<boolean>((resolve) => {
    const probe = net.createServer();
    probe.once('error', () => resolve(false));
    probe.listen(port, () => probe.close(() => resolve(true)));
  });
  if (!free) {
    throw new Error(
      `Port ${port} is already in use. Please specify a different port or free the port.`,
    );
  }
}

export class BrowserCallbackStrategy<TResult>
  implements IAuthorizationStrategy<TResult>
{
  private inFlight: Promise<AuthorizationOutcome<TResult>> | null = null;
  private controller: AbortController | null = null;
  private disposed = false;

  constructor(
    private readonly options: BrowserCallbackStrategyOptions<TResult>,
  ) {}

  async authorize(
    request: AuthorizationRequest,
  ): Promise<AuthorizationOutcome<TResult>> {
    if (this.disposed) {
      throw new Error('BrowserCallbackStrategy has been disposed');
    }
    if (this.inFlight) {
      throw new Error(
        'BrowserCallbackStrategy is already authorizing; it holds a single port',
      );
    }

    const port = this.options.port ?? DEFAULT_CALLBACK_PORT;
    await assertPortAvailable(port);

    const controller = new AbortController();
    this.controller = controller;
    const relay = () => controller.abort();
    this.options.signal?.addEventListener('abort', relay, { once: true });

    const announce = announcer(request.logger);
    const browser = this.options.browser ?? 'none';
    const open =
      this.options.openUrl ??
      ((url: string, which: string) =>
        launchBrowser(url, which, 0, announce, request.logger ?? null));

    const run = this.options.callbackServer(
      {
        port,
        timeoutMs: this.options.timeoutMs ?? DEFAULT_LOGIN_TIMEOUT_MS,
        signal: controller.signal,
        logger: request.logger,
      },
      async (server) => {
        // Thrown before anything is opened: a redirect the provider cannot
        // honour must fail here, not as a callback that never arrives.
        const url = await request.buildAuthorizationUrl(server.redirectUri);
        const waiting = server.waitForResult();
        // Not awaited: a launcher that hangs must not delay the timeout or the
        // release, and one that fails ends the scope through `fail`.
        void open(url, browser).catch((error: unknown) => {
          const message = error instanceof Error ? error.message : String(error);
          request.logger?.error(
            `Failed to open browser: ${message}. Open manually: ${url}`,
            { error: message, url },
          );
          server.fail(
            new Error(`Browser opening failed. Open manually: ${url}`),
          );
        });
        return {
          payload: await waiting,
          redirectUri: server.redirectUri,
        } satisfies AuthorizationOutcome<TResult>;
      },
    );

    this.inFlight = run;
    try {
      return await run;
    } finally {
      this.options.signal?.removeEventListener('abort', relay);
      this.controller = null;
      this.inFlight = null;
    }
  }

  /**
   * Idempotent; ends an authorization in flight and resolves only once the
   * factory has settled — which it does after the socket is free.
   */
  async dispose(): Promise<void> {
    this.disposed = true;
    const pending = this.inFlight;
    this.controller?.abort();
    if (pending) await pending.catch(() => undefined);
  }
}

export function browserCallbackStrategy(
  options: CallbackStrategyOptions = {},
): IAuthorizationStrategy<string> {
  return new BrowserCallbackStrategy<string>({
    ...options,
    callbackServer: withBrowserCallbackServer,
  });
}

export function oidcCallbackStrategy(
  options: CallbackStrategyOptions = {},
): IAuthorizationStrategy<OidcCallbackResult> {
  return new BrowserCallbackStrategy<OidcCallbackResult>({
    ...options,
    callbackServer: withOidcCallbackServer,
  });
}

export function samlCallbackStrategy(
  options: CallbackStrategyOptions = {},
): IAuthorizationStrategy<string> {
  return new BrowserCallbackStrategy<string>({
    ...options,
    callbackServer: withSamlCallbackServer,
  });
}
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
npm test -- src/__tests__/strategies/BrowserCallbackStrategy.test.ts
```

Expected: PASS, all four cases.

- [ ] **Step 6: Commit**

```bash
npm run lint:check && npm run build
git add src/strategies/BrowserCallbackStrategy.ts src/auth/browserAuth.ts src/__tests__/strategies/BrowserCallbackStrategy.test.ts
git commit -m "feat: browser callback strategy with an injectable transport"
```

---

### Task 11: The manual, external and static strategies

**Files:**
- Create: `src/strategies/manualStrategies.ts`, `src/strategies/codeStrategies.ts`
- Delete: `src/auth/manualInput.ts`
- Test: `src/__tests__/strategies/manualStrategies.test.ts` (create)

**Interfaces:**
- Produces:
  - `manualPasteStrategy(opts?): IAuthorizationStrategy<string>`
  - `manualSamlResponseStrategy(opts?): IAuthorizationStrategy<string>`
  - `externalCodeStrategy({ redirectUri?, provide }): IAuthorizationStrategy<string>`
  - `staticCodeStrategy({ redirectUri?, payload }): IAuthorizationStrategy<string>`
  - `interface ManualStrategyOptions { redirectUri?: string; read?: (prompt: string) => Promise<string> }`

- [ ] **Step 1: Write the failing tests**

Create `src/__tests__/strategies/manualStrategies.test.ts`:

```ts
/**
 * The non-browser strategies.
 *
 * The stdout assertion is the load-bearing one: under an MCP stdio transport a
 * stray prompt on stdout corrupts the protocol stream.
 */

import { describe, expect, it, jest } from '@jest/globals';
import {
  manualPasteStrategy,
  manualSamlResponseStrategy,
} from '../../strategies/manualStrategies';
import {
  externalCodeStrategy,
  staticCodeStrategy,
} from '../../strategies/codeStrategies';

describe('manual strategies', () => {
  it('prompts without writing a byte to stdout', async () => {
    const written: string[] = [];
    const spy = jest
      .spyOn(process.stdout, 'write')
      .mockImplementation((chunk: unknown) => {
        written.push(String(chunk));
        return true;
      });
    try {
      const strategy = manualPasteStrategy({
        redirectUri: 'http://localhost:61001/callback',
        read: async () => 'pasted-code',
      });
      const outcome = await strategy.authorize({
        buildAuthorizationUrl: async () => 'https://idp.example/authorize',
      });
      expect(outcome.payload).toBe('pasted-code');
    } finally {
      spy.mockRestore();
    }
    expect(written).toEqual([]);
  });

  it('accepts a full redirected URL as well as a bare code', async () => {
    const strategy = manualPasteStrategy({
      read: async () => 'http://localhost:61001/callback?code=from-url&state=x',
    });
    const outcome = await strategy.authorize({
      buildAuthorizationUrl: async () => 'https://idp.example/authorize',
    });
    expect(outcome.payload).toBe('from-url');
  });

  it('takes a SAMLResponse verbatim, since it never reaches a URL', async () => {
    const strategy = manualSamlResponseStrategy({
      read: async () => '  PHNhbWw+  ',
    });
    const outcome = await strategy.authorize({
      buildAuthorizationUrl: async () => 'https://idp.example/sso',
    });
    expect(outcome.payload).toBe('PHNhbWw+');
  });
});

describe('code strategies', () => {
  it('hands the assembled URL to an external provider', async () => {
    const seen: string[] = [];
    const strategy = externalCodeStrategy({
      redirectUri: 'http://localhost:61001/callback',
      provide: async (url) => {
        seen.push(url);
        return 'external-code';
      },
    });
    const outcome = await strategy.authorize({
      buildAuthorizationUrl: async (uri) =>
        `https://idp.example/authorize?redirect_uri=${encodeURIComponent(uri)}&code_challenge=abc`,
    });
    expect(seen[0]).toContain('code_challenge=abc');
    expect(outcome.payload).toBe('external-code');
    expect(outcome.redirectUri).toBe('http://localhost:61001/callback');
  });

  it('never calls the builder when the payload is already held', async () => {
    const build = jest.fn(async () => 'https://idp.example/authorize');
    const strategy = staticCodeStrategy({
      redirectUri: 'http://localhost:61001/callback',
      payload: 'already-have-it',
    });
    const outcome = await strategy.authorize({
      buildAuthorizationUrl: build,
    });
    expect(build).not.toHaveBeenCalled();
    expect(outcome.payload).toBe('already-have-it');
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
npm test -- src/__tests__/strategies/manualStrategies.test.ts
```

Expected: FAIL — neither module exists.

- [ ] **Step 3: Write the manual strategies**

Create `src/strategies/manualStrategies.ts`:

```ts
/**
 * Strategies where a human moves the payload.
 *
 * There are two because the payload is not acquired the same way. An
 * authorization code lands in the browser's address bar; a `SAMLResponse` does
 * not — our `AuthnRequest` declares the HTTP-POST binding, so the IdP posts it
 * in a form body and the user must lift it from there.
 */

import { createInterface } from 'node:readline';
import type {
  AuthorizationOutcome,
  AuthorizationRequest,
  IAuthorizationStrategy,
} from '@mcp-abap-adt/interfaces';
import { extractCode } from '../auth/browserAuth';
import { DEFAULT_CALLBACK_PORT } from './BrowserCallbackStrategy';

export interface ManualStrategyOptions {
  /** Must match what the authorization request advertises and the exchange sends. */
  redirectUri?: string;
  /** Where the pasted value comes from. Defaults to an interactive stdin read. */
  read?: (prompt: string) => Promise<string>;
}

const defaultRedirectUri = () =>
  `http://localhost:${DEFAULT_CALLBACK_PORT}/callback`;

/**
 * Reads one line from stdin.
 *
 * The prompt goes to stderr, never stdout, and stdin is touched only when it is
 * a terminal: under a stdio RPC transport those streams carry the protocol.
 */
async function readFromTerminal(prompt: string): Promise<string> {
  if (!process.stdin.isTTY) {
    throw new Error(
      'Manual input needs an interactive terminal. Supply `read` to source the value elsewhere.',
    );
  }
  process.stderr.write(prompt);
  const rl = createInterface({ input: process.stdin });
  try {
    for await (const line of rl) return line.trim();
  } finally {
    rl.close();
  }
  throw new Error('No input received');
}

function announce(request: AuthorizationRequest, url: string): void {
  const message = `Open this URL to authenticate:\n${url}`;
  if (request.logger) request.logger.info(message);
  else process.stderr.write(`${message}\n`);
}

/** The user copies the `code` out of the address bar after the redirect. */
export function manualPasteStrategy(
  options: ManualStrategyOptions = {},
): IAuthorizationStrategy<string> {
  const redirectUri = options.redirectUri ?? defaultRedirectUri();
  const read = options.read ?? readFromTerminal;
  return {
    async authorize(
      request: AuthorizationRequest,
    ): Promise<AuthorizationOutcome<string>> {
      const url = await request.buildAuthorizationUrl(redirectUri);
      announce(request, url);
      const raw = await read(
        'Paste the authorization code (or the whole redirected URL): ',
      );
      const code = extractCode(raw);
      if (!code) {
        throw new Error('Could not read an authorization code from that input');
      }
      return { payload: code, redirectUri };
    },
  };
}

/** The user lifts `SAMLResponse` from the POST body — it never reaches the URL. */
export function manualSamlResponseStrategy(
  options: ManualStrategyOptions = {},
): IAuthorizationStrategy<string> {
  const redirectUri = options.redirectUri ?? defaultRedirectUri();
  const read = options.read ?? readFromTerminal;
  return {
    async authorize(
      request: AuthorizationRequest,
    ): Promise<AuthorizationOutcome<string>> {
      const url = await request.buildAuthorizationUrl(redirectUri);
      announce(request, url);
      const raw = await read(
        'Paste the SAMLResponse (from the POST body — it is not in the address bar): ',
      );
      const assertion = raw.trim();
      if (!assertion) throw new Error('No SAMLResponse was provided');
      return { payload: assertion, redirectUri };
    },
  };
}
```

- [ ] **Step 4: Write the code strategies**

Create `src/strategies/codeStrategies.ts`:

```ts
/**
 * Strategies where the consumer supplies the payload.
 *
 * The two are separate because one needs the authorization URL and the other
 * does not — and asking for a URL that is not needed would drag in OIDC
 * discovery that a static payload never required.
 */

import type {
  AuthorizationOutcome,
  AuthorizationRequest,
  IAuthorizationStrategy,
} from '@mcp-abap-adt/interfaces';
import { DEFAULT_CALLBACK_PORT } from './BrowserCallbackStrategy';

const defaultRedirectUri = () =>
  `http://localhost:${DEFAULT_CALLBACK_PORT}/callback`;

export interface ExternalCodeStrategyOptions {
  redirectUri?: string;
  /** Receives the assembled URL — so the code returned matches its PKCE challenge. */
  provide: (authorizationUrl: string) => Promise<string>;
}

export interface StaticCodeStrategyOptions {
  redirectUri?: string;
  payload: string;
}

/** The consumer drives its own interactive flow and needs the URL to do it. */
export function externalCodeStrategy(
  options: ExternalCodeStrategyOptions,
): IAuthorizationStrategy<string> {
  const redirectUri = options.redirectUri ?? defaultRedirectUri();
  return {
    async authorize(
      request: AuthorizationRequest,
    ): Promise<AuthorizationOutcome<string>> {
      const url = await request.buildAuthorizationUrl(redirectUri);
      const payload = await options.provide(url);
      if (!payload) {
        throw new Error('Authorization code provider returned an empty value');
      }
      return { payload, redirectUri };
    },
  };
}

/** The consumer already holds the payload; the builder is never called. */
export function staticCodeStrategy(
  options: StaticCodeStrategyOptions,
): IAuthorizationStrategy<string> {
  const redirectUri = options.redirectUri ?? defaultRedirectUri();
  if (!options.payload) {
    throw new Error('staticCodeStrategy requires a payload');
  }
  return {
    async authorize(): Promise<AuthorizationOutcome<string>> {
      return { payload: options.payload, redirectUri };
    },
  };
}
```

- [ ] **Step 5: Delete the stdout-writing helper**

```bash
git rm src/auth/manualInput.ts
```

`src/providers/saml2Utils.ts:6` imports it; that import disappears in Task 13. Until then the build fails, so run Task 13 before pushing — or comment the import out and restore it there.

- [ ] **Step 6: Run the tests to verify they pass**

```bash
npm test -- src/__tests__/strategies/manualStrategies.test.ts
```

Expected: PASS, all five cases.

- [ ] **Step 7: Commit**

```bash
npm run lint:check
git add src/strategies/manualStrategies.ts src/strategies/codeStrategies.ts src/__tests__/strategies/manualStrategies.test.ts
git commit -m "feat: manual, external and static authorization strategies"
```

---

### Task 12: The OIDC payload adapter

**Files:**
- Create: `src/strategies/asOidcResult.ts`, `src/strategies/index.ts`
- Test: `src/__tests__/strategies/asOidcResult.test.ts` (create)

**Interfaces:**
- Produces: `asOidcResult(s: IAuthorizationStrategy<string>): IAuthorizationStrategy<OidcCallbackResult>`; `src/strategies/index.ts` re-exports everything from Tasks 10–12.

- [ ] **Step 1: Write the failing tests**

Create `src/__tests__/strategies/asOidcResult.test.ts`:

```ts
import { describe, expect, it, jest } from '@jest/globals';
import type { IAuthorizationStrategy } from '@mcp-abap-adt/interfaces';
import { asOidcResult } from '../../strategies/asOidcResult';

describe('asOidcResult', () => {
  it('wraps a code and leaves the redirect URI alone', async () => {
    const inner: IAuthorizationStrategy<string> = {
      authorize: async () => ({
        payload: 'the-code',
        redirectUri: 'http://localhost:61001/callback',
      }),
    };
    const outcome = await asOidcResult(inner).authorize({
      buildAuthorizationUrl: async () => 'https://idp.example/authorize',
    });
    expect(outcome.payload).toEqual({ code: 'the-code' });
    expect(outcome.redirectUri).toBe('http://localhost:61001/callback');
  });

  it('delegates dispose', async () => {
    const dispose = jest.fn(async () => undefined);
    const inner: IAuthorizationStrategy<string> = {
      authorize: async () => ({ payload: 'c', redirectUri: 'u' }),
      dispose,
    };
    const adapted = asOidcResult(inner);
    await adapted.dispose?.();
    await adapted.dispose?.();
    expect(dispose).toHaveBeenCalledTimes(2);
  });

  it('has no dispose when the wrapped strategy has none', () => {
    const inner: IAuthorizationStrategy<string> = {
      authorize: async () => ({ payload: 'c', redirectUri: 'u' }),
    };
    expect(asOidcResult(inner).dispose).toBeUndefined();
  });
});
```

Idempotence is the wrapped strategy's obligation, so the adapter forwards every call rather than swallowing the second — the assertion is `2`, deliberately.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
npm test -- src/__tests__/strategies/asOidcResult.test.ts
```

Expected: FAIL — module not found.

- [ ] **Step 3: Write the adapter**

Create `src/strategies/asOidcResult.ts`:

```ts
/**
 * Adapts a code-producing strategy to the OIDC provider's payload type.
 *
 * Everything a human or a consumer hands back is a string; only a real callback
 * carries `state` beside the code. Rather than an OIDC twin of every strategy,
 * the mismatch is bridged in one place.
 */

import type {
  AuthorizationOutcome,
  AuthorizationRequest,
  IAuthorizationStrategy,
} from '@mcp-abap-adt/interfaces';
import type { OidcCallbackResult } from '../auth/oidcBrowserAuth';

export function asOidcResult(
  inner: IAuthorizationStrategy<string>,
): IAuthorizationStrategy<OidcCallbackResult> {
  const adapted: IAuthorizationStrategy<OidcCallbackResult> = {
    async authorize(
      request: AuthorizationRequest,
    ): Promise<AuthorizationOutcome<OidcCallbackResult>> {
      const outcome = await inner.authorize(request);
      // No `state`: a value that never travelled through a redirect has none
      // to check.
      return {
        payload: { code: outcome.payload },
        redirectUri: outcome.redirectUri,
      };
    },
  };
  // Delegated, not reimplemented: the consumer holds only the adapter, so an
  // undelegated dispose would strand whatever the wrapped strategy owns. Absent
  // when the wrapped strategy has none, so optionality survives the wrapping.
  if (inner.dispose) {
    adapted.dispose = () => inner.dispose?.() ?? Promise.resolve();
  }
  return adapted;
}
```

- [ ] **Step 4: Add the strategy barrel**

Create `src/strategies/index.ts`:

```ts
export { asOidcResult } from './asOidcResult';
export {
  BrowserCallbackStrategy,
  browserCallbackStrategy,
  DEFAULT_CALLBACK_PORT,
  DEFAULT_LOGIN_TIMEOUT_MS,
  oidcCallbackStrategy,
  samlCallbackStrategy,
} from './BrowserCallbackStrategy';
export type {
  BrowserCallbackStrategyOptions,
  CallbackStrategyOptions,
} from './BrowserCallbackStrategy';
export {
  externalCodeStrategy,
  staticCodeStrategy,
} from './codeStrategies';
export type {
  ExternalCodeStrategyOptions,
  StaticCodeStrategyOptions,
} from './codeStrategies';
export {
  manualPasteStrategy,
  manualSamlResponseStrategy,
} from './manualStrategies';
export type { ManualStrategyOptions } from './manualStrategies';
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
npm test -- src/__tests__/strategies/
```

Expected: PASS across all three strategy test files.

- [ ] **Step 6: Commit**

```bash
npm run lint:check
git add src/strategies/asOidcResult.ts src/strategies/index.ts src/__tests__/strategies/asOidcResult.test.ts
git commit -m "feat: adapt code strategies to the OIDC payload type"
```

---

### Task 13: `AuthorizationCodeProvider` takes a strategy

**Files:**
- Modify: `src/providers/AuthorizationCodeProvider.ts` (whole file)
- Modify: `src/auth/browserAuth.ts` (delete `startBrowserAuth` and the stdin reader)
- Test: `src/__tests__/providers/AuthorizationCodeProvider.test.ts:310-344`

**Interfaces:**
- Consumes: `browserCallbackStrategy`, `DEFAULT_LOGIN_TIMEOUT_MS` (Task 10); `getJwtAuthorizationUrl`, `exchangeCodeForToken` (Task 9).
- Produces: `AuthorizationCodeProviderConfig` without `browser`/`redirectPort`, with `authorization?: IAuthorizationStrategy<string>`.

- [ ] **Step 1: Write the failing tests**

Replace the `AuthorizationCodeProvider timeout ownership` describe block at `:310-344` with:

```ts
/**
 * The provider no longer owns a socket, a browser or a timeout — it owns a URL
 * builder and an exchange. These pin the two consequences that are easy to
 * regress: the guard must fire before anything is opened, and the port must be
 * free the moment the failure surfaces.
 */
describe('AuthorizationCodeProvider with strategies', () => {
  const PORT = 7875;

  function portIsFree(port: number): Promise<boolean> {
    return new Promise((resolve) => {
      const s = netModule.createServer();
      s.once('error', () => resolve(false));
      s.listen(port, () => s.close(() => resolve(true)));
    });
  }

  it('leaves the callback port free the moment a login times out', async () => {
    const provider = new AuthorizationCodeProvider({
      uaaUrl: 'http://127.0.0.1:9',
      clientId: 'client',
      clientSecret: 'secret',
      authorization: browserCallbackStrategy({
        port: PORT,
        timeoutMs: 1000,
        openUrl: async () => undefined,
      }),
    });

    await expect(provider.getTokens()).rejects.toThrow(/timeout/i);
    expect(await portIsFree(PORT)).toBe(true);
  }, 30000);

  it('rejects a pre-built URL whose redirect does not match, before opening a browser', async () => {
    const openUrl = jest.fn(async () => undefined);
    const provider = new AuthorizationCodeProvider({
      uaaUrl: 'http://127.0.0.1:9',
      clientId: 'client',
      clientSecret: 'secret',
      authorizationUrl:
        'https://uaa.example/oauth/authorize?client_id=c&redirect_uri=http%3A%2F%2Flocalhost%3A3001%2Fcallback&response_type=code',
      authorization: browserCallbackStrategy({
        port: PORT,
        timeoutMs: 30000,
        openUrl,
      }),
    });

    const started = Date.now();
    await expect(provider.getTokens()).rejects.toThrow(
      /redirect_uri.*does not match/i,
    );
    // Not "eventually" — the point of building-time validation is that it does
    // not wait for a callback that can never arrive.
    expect(Date.now() - started).toBeLessThan(5000);
    expect(openUrl).not.toHaveBeenCalled();
    expect(await portIsFree(PORT)).toBe(true);
  }, 30000);
});
```

Add to the file's imports: `import { jest } from '@jest/globals';` (if absent) and `import { browserCallbackStrategy } from '../../strategies';`.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
npm test -- src/__tests__/providers/AuthorizationCodeProvider.test.ts -t "with strategies"
```

Expected: FAIL — `authorization` is not a known config property.

- [ ] **Step 3: Rewrite the provider's login path**

In `src/providers/AuthorizationCodeProvider.ts`, replace the imports, the config interface and `performLogin`:

```ts
import type {
  IAuthorizationConfig,
  IAuthorizationStrategy,
  ILogger,
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces';
import { AUTH_TYPE_AUTHORIZATION_CODE } from '@mcp-abap-adt/interfaces';
import {
  exchangeCodeForToken,
  getJwtAuthorizationUrl,
} from '../auth/browserAuth';
import { refreshJwtToken } from '../auth/tokenRefresher';
import { browserCallbackStrategy } from '../strategies';
import { BaseTokenProvider } from './BaseTokenProvider';
```

```ts
export interface AuthorizationCodeProviderConfig {
  // Required for building the authorization URL and for the token exchange
  uaaUrl: string;
  clientId: string;
  clientSecret: string;

  /** Pre-built authorization URL. Carries its own redirect; see the guard below. */
  authorizationUrl?: string;

  /**
   * How the login is conducted. Omitted means a browser callback on the default
   * port — the package's own transport, which a consumer may replace wholesale.
   */
  authorization?: IAuthorizationStrategy<string>;

  // Optional: existing tokens (for the refresh scenario)
  accessToken?: string;
  refreshToken?: string;

  logger?: ILogger;
}
```

Replace the whole of `performLogin` and drop the `LOGIN_TIMEOUT_MS` constant:

```ts
  protected async performLogin(): Promise<ITokenResult> {
    const authConfig: IAuthorizationConfig = {
      uaaUrl: this.config.uaaUrl,
      uaaClientId: this.config.clientId,
      uaaClientSecret: this.config.clientSecret,
    };

    const prebuilt = this.config.authorizationUrl;

    // The provider owns the URL; the strategy owns where it is answered. The
    // guard lives here rather than after the fact because a mismatched redirect
    // produces no callback at all — checking the outcome would mean waiting for
    // a timeout that explains nothing.
    const request = {
      logger: this.logger,
      buildAuthorizationUrl: async (redirectUri: string): Promise<string> => {
        if (prebuilt) {
          const declared = new URL(prebuilt).searchParams.get('redirect_uri');
          if (declared && declared !== redirectUri) {
            throw new Error(
              `Pre-built authorizationUrl declares redirect_uri ${declared}, ` +
                `but the authorization strategy is listening on ${redirectUri}. ` +
                'They must match; an ephemeral port cannot be used with a pre-built URL.',
            );
          }
          return prebuilt;
        }
        return getJwtAuthorizationUrl(authConfig, redirectUri);
      },
    };

    // Constructed here means disposed here: whoever constructs, disposes.
    const supplied = this.config.authorization;
    const strategy = supplied ?? browserCallbackStrategy();

    let outcome: { payload: string; redirectUri: string };
    try {
      outcome = await strategy.authorize(request);
    } finally {
      if (!supplied) {
        // A cleanup failure must not replace the reason the login failed.
        await strategy.dispose?.().catch((error: unknown) => {
          this.logger?.warn('[AuthorizationCodeProvider] dispose failed', {
            error: error instanceof Error ? error.message : String(error),
          });
        });
      }
    }

    this.logger?.info('[AuthorizationCodeProvider] Code received', {
      redirectUri: outcome.redirectUri,
    });

    const result = await exchangeCodeForToken(
      authConfig,
      outcome.payload,
      outcome.redirectUri,
      this.logger,
    );

    return {
      authorizationToken: result.accessToken,
      refreshToken: result.refreshToken,
      authType: AUTH_TYPE_AUTHORIZATION_CODE,
      expiresIn: this.calculateExpiresIn(result.accessToken),
    };
  }
```

Also remove `browser` and `redirectPort` from the constructor's logging block near `:57-66`.

- [ ] **Step 4: Delete `startBrowserAuth`**

In `src/auth/browserAuth.ts`, delete `startBrowserAuth` (`:290-395`) together with its `readline` import and the `isPortAvailable` helper if nothing else references it. Check first:

```bash
grep -rn "startBrowserAuth\|isPortAvailable" src --include=*.ts
```

`oidcBrowserAuth.ts` and `saml2Auth.ts` have their own `isPortAvailable`; leave those. The stdin paste path disappears with `startBrowserAuth` — it now lives only in `manualPasteStrategy`.

- [ ] **Step 5: Run the tests to verify they pass**

```bash
npm test -- src/__tests__/providers/AuthorizationCodeProvider.test.ts
```

Expected: PASS. The suite is also about 30 s faster: the timeout case now runs with `timeoutMs: 1000` instead of a hard-wired 30 s.

- [ ] **Step 6: Commit**

```bash
npm run lint:check && npm run build
git add src/providers/AuthorizationCodeProvider.ts src/auth/browserAuth.ts src/__tests__/providers/AuthorizationCodeProvider.test.ts
git commit -m "feat!: AuthorizationCodeProvider takes an authorization strategy"
```

---

### Task 14: `OidcBrowserProvider` takes a strategy and discovers lazily

**Files:**
- Modify: `src/providers/OidcBrowserProvider.ts` (whole file)
- Test: `src/__tests__/sso/SsoProviders.test.ts`

**Interfaces:**
- Consumes: `oidcCallbackStrategy`, `asOidcResult`, `staticCodeStrategy`.
- Produces: `OidcBrowserProviderConfig` without `browser`, `redirectPort`, `redirectUri`, `authorizationCode`, `authorizationCodeProvider`; with `authorization?: IAuthorizationStrategy<OidcCallbackResult>`.

- [ ] **Step 1: Write the failing tests**

In `src/__tests__/sso/SsoProviders.test.ts`, replace the existing `authorizationCode` / `authorizationCodeProvider` / `redirectUri` cases with:

```ts
  it('OidcBrowserProvider performs no discovery when it holds a code and a token endpoint', async () => {
    const discovery = jest.fn();
    mockedAxios.get.mockImplementation(async (url: string) => {
      discovery(url);
      throw new Error('discovery must not be attempted');
    });
    mockedAxios.post.mockResolvedValueOnce({
      data: { access_token: 'AT', expires_in: 3600 },
    });

    const provider = new OidcBrowserProvider({
      clientId: 'cid',
      tokenEndpoint: 'https://idp.example/token',
      authorization: asOidcResult(
        staticCodeStrategy({
          redirectUri: 'http://localhost:61001/callback',
          payload: 'held-code',
        }),
      ),
      // deliberately no issuerUrl
    });

    const tokens = await provider.getTokens();
    expect(tokens.authorizationToken).toBe('AT');
    expect(discovery).not.toHaveBeenCalled();
  });

  it('OidcBrowserProvider discovers once when it needs both endpoints', async () => {
    const discovery = jest.fn();
    mockedAxios.get.mockImplementation(async (url: string) => {
      discovery(url);
      return {
        data: {
          authorization_endpoint: 'https://idp.example/authorize',
          token_endpoint: 'https://idp.example/token',
        },
      };
    });
    mockedAxios.post.mockResolvedValueOnce({
      data: { access_token: 'AT2', expires_in: 3600 },
    });

    const provider = new OidcBrowserProvider({
      clientId: 'cid',
      issuerUrl: 'https://idp.example',
      authorization: asOidcResult(
        externalCodeStrategy({
          redirectUri: 'http://localhost:61001/callback',
          provide: async (url) => {
            expect(url).toContain('code_challenge=');
            return 'external-code';
          },
        }),
      ),
    });

    const tokens = await provider.getTokens();
    expect(tokens.authorizationToken).toBe('AT2');
    expect(discovery).toHaveBeenCalledTimes(1);
  });
```

Add `asOidcResult`, `staticCodeStrategy` and `externalCodeStrategy` to the file's imports from `../../strategies`. Match the axios mock style already used in this file; if it mocks a default export rather than named `get`/`post`, follow that.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
npm test -- src/__tests__/sso/SsoProviders.test.ts -t "OidcBrowserProvider"
```

Expected: FAIL — `authorization` is not a known property.

- [ ] **Step 3: Rewrite the provider**

Replace the config interface and `performLogin` in `src/providers/OidcBrowserProvider.ts`:

```ts
export interface OidcBrowserProviderConfig {
  issuerUrl?: string;
  clientId: string;
  clientSecret?: string;
  scopes?: string[];
  authorizationEndpoint?: string;
  tokenEndpoint?: string;
  /** How the login is conducted. Omitted means a browser callback on the default port. */
  authorization?: IAuthorizationStrategy<OidcCallbackResult>;
  accessToken?: string;
  refreshToken?: string;
  logger?: ILogger;
}
```

```ts
  protected async performLogin(): Promise<ITokenResult> {
    // One memoised discovery per login, started on first use rather than up
    // front: a strategy that already holds a code must not drag in a request —
    // nor the `issuerUrl` requirement that comes with it.
    let discovery: Promise<Awaited<ReturnType<typeof discoverOidc>>> | null =
      null;
    const discover = () => {
      if (!discovery) {
        if (!this.config.issuerUrl) {
          throw new Error('OIDC issuerUrl is required when discovery is used');
        }
        discovery = discoverOidc(this.config.issuerUrl, this.logger);
      }
      return discovery;
    };

    const verifier = generatePkceVerifier();
    const challenge = generatePkceChallenge(verifier);
    const scope = (
      this.config.scopes && this.config.scopes.length > 0
        ? this.config.scopes
        : ['openid', 'profile', 'email']
    ).join(' ');

    const request = {
      logger: this.logger,
      buildAuthorizationUrl: async (redirectUri: string): Promise<string> => {
        const endpoint =
          this.config.authorizationEndpoint ??
          (await discover()).authorization_endpoint;
        if (!endpoint) {
          throw new Error(
            'OIDC authorization endpoint is required (authorizationEndpoint or discovery)',
          );
        }
        const params = new URLSearchParams();
        params.append('response_type', 'code');
        params.append('client_id', this.config.clientId);
        params.append('redirect_uri', redirectUri);
        params.append('scope', scope);
        params.append('code_challenge', challenge);
        params.append('code_challenge_method', 'S256');
        return `${endpoint}?${params.toString()}`;
      },
    };

    const supplied = this.config.authorization;
    const strategy = supplied ?? oidcCallbackStrategy();

    let outcome: { payload: OidcCallbackResult; redirectUri: string };
    try {
      outcome = await strategy.authorize(request);
    } finally {
      if (!supplied) {
        await strategy.dispose?.().catch((error: unknown) => {
          this.logger?.warn('[OidcBrowserProvider] dispose failed', {
            error: error instanceof Error ? error.message : String(error),
          });
        });
      }
    }

    const tokenEndpoint =
      this.config.tokenEndpoint ?? (await discover()).token_endpoint;
    if (!tokenEndpoint) {
      throw new Error(
        'OIDC token endpoint is required (tokenEndpoint or discovery)',
      );
    }

    const tokens = await exchangeAuthorizationCode(
      tokenEndpoint,
      this.config.clientId,
      this.config.clientSecret,
      outcome.payload.code,
      outcome.redirectUri,
      verifier,
      this.logger,
    );

    return {
      authorizationToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      authType: AUTH_TYPE_AUTHORIZATION_CODE_PKCE,
      expiresIn: tokens.expiresIn,
      tokenType: 'jwt',
    };
  }
```

Delete `resolveAuthorizationCode` entirely. Add `oidcCallbackStrategy` to the imports from `../strategies` and `IAuthorizationStrategy` to the type imports.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
npm test -- src/__tests__/sso/SsoProviders.test.ts
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
npm run lint:check && npm run build
git add src/providers/OidcBrowserProvider.ts src/__tests__/sso/SsoProviders.test.ts
git commit -m "feat!: OidcBrowserProvider takes a strategy and discovers lazily"
```

---

### Task 15: The SAML providers take a strategy

**Files:**
- Modify: `src/providers/saml2Utils.ts`, `src/providers/Saml2BearerProvider.ts`, `src/providers/Saml2PureProvider.ts`
- Test: `src/__tests__/sso/SsoProviders.test.ts`

**Interfaces:**
- Produces: `Saml2CommonConfig` without `browser`/`redirectPort`; `Saml2AssertionConfig` without `assertionFlow`/`assertionProvider`/`manualInput`; both gain `authorization?: IAuthorizationStrategy<string>`; `acsUrl` becomes required when `authorizationUrl` is set.

- [ ] **Step 1: Write the failing test**

Add to `src/__tests__/sso/SsoProviders.test.ts`:

```ts
  it('Saml2PureProvider rejects a pre-built URL without a declared acsUrl', () => {
    expect(
      () =>
        new Saml2PureProvider({
          idpSsoUrl: 'https://idp.example/sso',
          spEntityId: 'sp',
          authorizationUrl: 'https://idp.example/sso?SAMLRequest=abc',
          cookieProvider: async (saml) => saml,
        }),
    ).toThrow(/acsUrl is required/i);
  });

  it('Saml2PureProvider takes an assertion from a strategy', async () => {
    const seen: string[] = [];
    const provider = new Saml2PureProvider({
      idpSsoUrl: 'https://idp.example/sso',
      spEntityId: 'sp',
      acsUrl: 'http://localhost:61001/callback',
      authorization: staticCodeStrategy({
        redirectUri: 'http://localhost:61001/callback',
        payload: 'PHNhbWw+',
      }),
      // The pure provider exchanges the assertion for session cookies; echo it
      // so the assertion under test is the one the strategy delivered.
      cookieProvider: async (saml) => {
        seen.push(saml);
        return saml;
      },
    });
    const tokens = await provider.getTokens();
    expect(seen).toEqual(['PHNhbWw+']);
    expect(tokens.authorizationToken).toBe('PHNhbWw+');
  });
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
npm test -- src/__tests__/sso/SsoProviders.test.ts -t "Saml2PureProvider"
```

Expected: FAIL — `authorization` is not a known property; no validation exists.

- [ ] **Step 3: Rewrite the shared helper**

Replace `src/providers/saml2Utils.ts` with:

```ts
/**
 * SAML2 provider shared helpers.
 */

import type {
  IAuthorizationStrategy,
  ILogger,
} from '@mcp-abap-adt/interfaces';
import { buildSamlAuthorizationUrl } from '../auth/saml2Auth';
import { samlCallbackStrategy } from '../strategies';

export interface Saml2CommonConfig {
  idpSsoUrl: string;
  spEntityId: string;
  /**
   * Where the assertion is delivered. Required when `authorizationUrl` is set:
   * the ACS is then buried in a deflated `SAMLRequest` this package did not
   * build and cannot read, so it must be declared rather than inferred.
   */
  acsUrl?: string;
  relayState?: string;
  authorizationUrl?: string;
  /** How the login is conducted. Omitted means a browser callback. */
  authorization?: IAuthorizationStrategy<string>;
  logger?: ILogger;
}

export interface Saml2BearerExchangeConfig {
  tokenUrl?: string;
  uaaUrl?: string;
  clientId?: string;
  clientSecret?: string;
}

/** Throw at construction rather than half-verify at runtime. */
export function validateSamlConfig(config: Saml2CommonConfig): void {
  if (config.authorizationUrl && !config.acsUrl) {
    throw new Error(
      'acsUrl is required when authorizationUrl is set: the ACS inside a ' +
        'pre-built SAML request cannot be read, so it must be declared.',
    );
  }
}

export function resolveTokenUrl(config: Saml2BearerExchangeConfig): string {
  if (config.tokenUrl) {
    return config.tokenUrl;
  }
  if (config.uaaUrl) {
    return `${config.uaaUrl.replace(/\/+$/, '')}/oauth/token`;
  }
  throw new Error('Missing tokenUrl or uaaUrl for SAML bearer exchange');
}

export async function getSamlAssertion(
  config: Saml2CommonConfig,
): Promise<string> {
  const declaredAcs = config.acsUrl;

  const request = {
    logger: config.logger,
    buildAuthorizationUrl: async (redirectUri: string): Promise<string> => {
      // A declared ACS is registered with the IdP; the strategy must be
      // listening exactly there, and an ephemeral port cannot be.
      const acsUrl = declaredAcs ?? redirectUri;
      if (declaredAcs && declaredAcs !== redirectUri) {
        throw new Error(
          `SAML acsUrl is ${declaredAcs}, but the authorization strategy is ` +
            `listening on ${redirectUri}. They must match.`,
        );
      }
      return buildSamlAuthorizationUrl({
        idpSsoUrl: config.idpSsoUrl,
        spEntityId: config.spEntityId,
        acsUrl,
        relayState: config.relayState,
        authorizationUrl: config.authorizationUrl,
      });
    },
  };

  const supplied = config.authorization;
  const strategy = supplied ?? samlCallbackStrategy();
  try {
    const outcome = await strategy.authorize(request);
    return outcome.payload;
  } finally {
    if (!supplied) {
      await strategy.dispose?.().catch((error: unknown) => {
        config.logger?.warn('[SAML] dispose failed', {
          error: error instanceof Error ? error.message : String(error),
        });
      });
    }
  }
}
```

`resolveAcsUrl` is gone: the ACS is now either declared or is whatever the strategy bound.

- [ ] **Step 4: Wire the two providers**

`Saml2AssertionConfig` is gone — both providers now extend `Saml2CommonConfig`, and both validate in the constructor. In `Saml2PureProvider.ts`:

```ts
import type { Saml2CommonConfig } from './saml2Utils';
import { getSamlAssertion, validateSamlConfig } from './saml2Utils';

export interface Saml2PureProviderConfig extends Saml2CommonConfig {
  logger?: ILogger;
  cookieProvider: (samlResponse: string) => Promise<string>;
}

export class Saml2PureProvider extends BaseTokenProvider {
  private config: Saml2PureProviderConfig;

  constructor(config: Saml2PureProviderConfig) {
    super();
    // A pre-built URL with no declared ACS cannot be verified against whatever
    // the strategy binds, so it is refused here rather than at login time.
    validateSamlConfig(config);
    this.config = config;
    this.logger = config.logger;
    this.tokenType = 'saml';
  }
```

`performLogin` already calls `getSamlAssertion(this.config)` and needs no change. Apply the same two edits — `extends Saml2CommonConfig`, `validateSamlConfig(config)` in the constructor — to `Saml2BearerProvider.ts`, and delete any `browser` or `redirectPort` it forwards.

- [ ] **Step 5: Run the tests to verify they pass**

```bash
npm test -- src/__tests__/sso/
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
npm run lint:check && npm run build
git add src/providers/saml2Utils.ts src/providers/Saml2BearerProvider.ts src/providers/Saml2PureProvider.ts src/__tests__/sso/SsoProviders.test.ts
git commit -m "feat!: SAML providers take an authorization strategy"
```

---

### Task 16: Export the surface and prove the whole suite green

**Files:**
- Modify: `src/index.ts`
- Test: the whole suite

**Interfaces:**
- Produces: the package's public surface — strategies, the adapter, the three callback factories.

- [ ] **Step 1: Extend the public exports**

Append to `src/index.ts`:

```ts
// Callback server factories — "take the transport this package gives".
export { withBrowserCallbackServer } from './auth/callbackServer';
export { withOidcCallbackServer } from './auth/oidcBrowserAuth';
export type { OidcCallbackResult } from './auth/oidcBrowserAuth';
export { withSamlCallbackServer } from './auth/saml2Auth';
// Authorization strategies — or bring your own IAuthorizationStrategy.
export {
  asOidcResult,
  BrowserCallbackStrategy,
  browserCallbackStrategy,
  DEFAULT_CALLBACK_PORT,
  DEFAULT_LOGIN_TIMEOUT_MS,
  externalCodeStrategy,
  manualPasteStrategy,
  manualSamlResponseStrategy,
  oidcCallbackStrategy,
  samlCallbackStrategy,
  staticCodeStrategy,
} from './strategies';
export type {
  BrowserCallbackStrategyOptions,
  CallbackStrategyOptions,
  ExternalCodeStrategyOptions,
  ManualStrategyOptions,
  StaticCodeStrategyOptions,
} from './strategies';
```

- [ ] **Step 2: Run the whole suite**

```bash
npm run lint:check && npm run build && npm test
```

Expected: green. If `SsoProviderFactory` (`src/sso/SsoProviderFactory.ts`) still forwards `browser` or `redirectPort` into a provider config, fix it here — it is the last caller of the removed fields.

- [ ] **Step 3: Delete the orchestration the strategies replaced**

`startOidcBrowserAuth` (`src/auth/oidcBrowserAuth.ts:121-152`) and `startSamlBrowserAuth` (`src/auth/saml2Auth.ts:167-200`) each opened a browser, bound a port and waited — the job `BrowserCallbackStrategy` now does. After Tasks 14 and 15 nothing calls them. Confirm, then remove them along with each file's now-unused `isPortAvailable` and browser-opening helper:

```bash
grep -rn "startOidcBrowserAuth\|startSamlBrowserAuth" src --include=*.ts
```

Expected before deleting: matches only inside the two definitions themselves. Keep `withOidcCallbackServer`, `withSamlCallbackServer`, `buildSamlAuthorizationUrl` and `parseSamlNotOnOrAfter` — all are still used.

- [ ] **Step 4: Confirm nothing references what was deleted**

```bash
grep -rn "redirectPort\|assertionFlow\|assertionProvider\|manualInput\|startBrowserAuth\|startOidcBrowserAuth\|startSamlBrowserAuth\|authorizationCodeProvider\|resolveAcsUrl" src --include=*.ts
```

Expected: no matches outside comments.

- [ ] **Step 5: Re-run the whole suite after the deletions**

```bash
npm run lint:check && npm run build && npm test
```

Expected: green.

- [ ] **Step 6: Commit**

```bash
git add -A src
git commit -m "feat: export strategies and remove the orchestration they replaced"
```

---

### Task 17: Documentation and the 2.0.0 release

**Files:**
- Modify: `README.md`, `CHANGELOG.md`, `package.json`, `docs/REFACTORING_PROPOSAL.md`
- Delete: `docs/superpowers/plans/2026-07-29-authorization-strategies.md` and `docs/superpowers/specs/2026-07-29-authorization-strategies-design.md` once implemented (`CLAUDE.md` keeps only work in progress)

- [ ] **Step 1: Rewrite the README examples**

Every `browser:` / `redirectPort:` occurrence (lines 89, 159, 279, 295-296, 314, 344, 359) becomes a strategy. The shape to use:

```ts
import {
  AuthorizationCodeProvider,
  browserCallbackStrategy,
} from '@mcp-abap-adt/auth-providers';

const provider = new AuthorizationCodeProvider({
  uaaUrl, clientId, clientSecret,
  authorization: browserCallbackStrategy({ browser: 'system', port: 61001 }),
});
```

Replace the "browser modes" section with "choosing a strategy", covering: browser callback (default), manual paste, external code, static code, and bringing your own `IAuthorizationStrategy`. State the default port and that `port: 0` is available where the IdP accepts a loopback redirect with any port.

- [ ] **Step 2: Write the migration section**

Add to `README.md`:

```markdown
## Migrating from 1.x to 2.0

| 1.x field | 2.0 |
|---|---|
| `browser: 'system'`, `redirectPort: 4001` | `authorization: browserCallbackStrategy({ browser: 'system', port: 4001 })` |
| `authorizationCode: 'abc'` | `authorization: asOidcResult(staticCodeStrategy({ redirectUri, payload: 'abc' }))` |
| `authorizationCodeProvider: fn` | `authorization: asOidcResult(externalCodeStrategy({ redirectUri, provide: fn }))` |
| `assertionFlow: 'browser'` | `authorization: samlCallbackStrategy()` |
| `assertionFlow: 'manual'`, `manualInput: fn` | `authorization: manualSamlResponseStrategy({ read: fn })` |
| `assertionFlow: 'assertion'`, `assertionProvider: fn` | `authorization: externalCodeStrategy({ redirectUri, provide: fn })` |

The default callback port changed from **3001** to **61001**. If you relied on
the default and registered `http://localhost:3001/callback` with your identity
provider, either register the new URI or pass `port: 3001` explicitly —
otherwise the IdP rejects the redirect and the error you see comes from it, not
from this package.

`OidcBrowserProvider` takes `IAuthorizationStrategy<OidcCallbackResult>` while
the code-producing strategies yield a string; `asOidcResult` bridges the two. It
delegates `dispose`, so wrapping costs nothing in lifecycle terms.
```

- [ ] **Step 3: Changelog and version**

Set `"version": "2.0.0"` in `package.json` and prepend to `CHANGELOG.md`:

```markdown
## 2.0.0

### Breaking

- `browser` and `redirectPort` are removed from every provider config, along
  with `redirectUri`, `authorizationCode` and `authorizationCodeProvider`
  (OIDC) and `assertionFlow`, `assertionProvider` and `manualInput` (SAML).
  All are replaced by a single `authorization` strategy. See the migration
  table in the README.
- The default callback port is now 61001, was 3001.

### Added

- `IAuthorizationStrategy` support in all four interactive providers, with
  shipped strategies: `browserCallbackStrategy`, `oidcCallbackStrategy`,
  `samlCallbackStrategy`, `manualPasteStrategy`, `manualSamlResponseStrategy`,
  `externalCodeStrategy`, `staticCodeStrategy`, and the `asOidcResult` adapter.
- The three `CallbackServerFactory` implementations are exported, so a consumer
  can reuse the transport while replacing everything around it.
- Ephemeral callback ports (`port: 0`), where the identity provider accepts a
  loopback redirect on any port.

### Fixed

- A `/callback` carrying neither a code nor an error no longer ends the login;
  it is answered, counted, and reported in the timeout message.
- The OIDC callback route now distinguishes an IdP refusal from a stray
  request — it previously had no `error=` branch at all.
- The SAML callback route no longer shows a success page before checking
  whether an assertion arrived.
- Manual input prompts go to stderr; they went to stdout, which corrupts an
  MCP/LSP stdio transport.
- The token exchange sends the redirect URI that actually received the
  callback, rather than one rebuilt from an assumed port.
```

- [ ] **Step 4: Deal with the stale proposal**

`docs/REFACTORING_PROPOSAL.md` describes an `ITokenProvider` refactor that already shipped. Confirm and delete:

```bash
grep -n "ITokenProvider" src/providers/BaseTokenProvider.ts | head -3
git rm docs/REFACTORING_PROPOSAL.md
```

- [ ] **Step 5: Full verification, then PR**

```bash
npm run lint:check && npm run build && npm test
git add -A
git commit -m "release(2.0.0): authorization strategies"
git push -u origin feat/authorization-strategies
gh pr create --title "feat!: authorization strategies (closes #11)" --body "Closes #11

Callback reception moves behind \`IAuthorizationStrategy\`; ephemeral ports work; a code-less callback no longer ends a login.

Migration:
\`\`\`ts
// before
new AuthorizationCodeProvider({ uaaUrl, clientId, clientSecret, browser: 'system', redirectPort: 4001 })
// after
new AuthorizationCodeProvider({ uaaUrl, clientId, clientSecret,
  authorization: browserCallbackStrategy({ browser: 'system', port: 4001 }) })
\`\`\`

Consumer impact: proxy@1.7.0, auth-broker@1.0.9."
```

- [ ] **Step 6: Merge, tag, hand off the publish**

```bash
gh pr merge --squash --delete-branch
git checkout master && git pull --ff-only
git tag -a v2.0.0 -m "Authorization strategies"
git push --tags
```

Then tell the user:

> `auth-providers@2.0.0` is tagged and pushed. Next step is yours: `cd /home/okyslytsia/prj/mcp-abap-adt-auth-providers && npm publish`. Tell me when it is on the registry.

Wait for confirmation before Phase C.

---

# Phase C — `proxy@1.7.0`

### Task 18: Realign the proxy

**Files:**
- Modify: `/home/okyslytsia/prj/mcp-abap-adt-proxy/src/proxy/btpProxy.ts:295-298`, `package.json`, `CHANGELOG.md`

**Interfaces:**
- Consumes: `browserCallbackStrategy` from `@mcp-abap-adt/auth-providers@2.0.0`.

- [ ] **Step 1: Branch, bump, force-refresh**

```bash
cd /home/okyslytsia/prj/mcp-abap-adt-proxy
git checkout -b feat/authorization-strategies
rm -rf node_modules/@mcp-abap-adt/auth-providers
npm install @mcp-abap-adt/auth-providers@2.0.0 --save
grep '"version"' node_modules/@mcp-abap-adt/auth-providers/package.json
```

Expected: `2.0.0`.

- [ ] **Step 2: Run the build to see it break**

```bash
npm run build
```

Expected: FAIL on `browser` / `redirectPort` in the provider config literal.

- [ ] **Step 3: Move the port into a strategy**

In `src/proxy/btpProxy.ts`, replace the two config lines. Import at the top:

```ts
import {
  AuthorizationCodeProvider,
  browserCallbackStrategy,
} from '@mcp-abap-adt/auth-providers';
```

```ts
    const providerConfig: any = {
      // 3333 by default, away from the proxy's own 3001. The package default
      // (61001) is deliberately not inherited: this port is documented as
      // --browser-auth-port and may be registered with the identity provider.
      authorization: browserCallbackStrategy({
        browser: this.config.browser,
        port: this.config.browserAuthPort || 3333,
      }),
      logger: loggerAdapter,
      ...(authConfig
        ? {
            uaaUrl: authConfig.uaaUrl,
            clientId: authConfig.uaaClientId,
            clientSecret: authConfig.uaaClientSecret,
          }
        : {}),
    };
```

Also fix the second call site at `:1187` (`redirectPort: loadedConfig.browserAuthPort`) the same way.

- [ ] **Step 4: Verify, including the port lifecycle suite**

```bash
npm run build && npm test
```

`src/__tests__/bin/callbackPortLifecycle.test.ts` and `signalHandling.test.ts` exercise the real callback port through the CLI; both must stay green. They assert on `browserAuthPort` in a config file, which is unchanged.

- [ ] **Step 5: Update the docs and release**

Bump `package.json` to `1.7.0`, add a CHANGELOG entry, and check whether the `--browser-auth-port` documentation describes internal mechanics that changed:

```bash
grep -rn "browser-auth-port" README.md docs 2>/dev/null
```

```bash
git add -A
git commit -m "release(1.7.0): realign with auth-providers@2.0.0 — callback port moves into a strategy"
git push -u origin feat/authorization-strategies
gh pr create --title "release(1.7.0): realign with auth-providers@2.0.0" --body "auth-providers 2.0.0 replaces \`browser\`/\`redirectPort\` with an \`authorization\` strategy. \`--browser-auth-port\` keeps its meaning and its 3333 default."
gh pr merge --squash --delete-branch
git checkout master && git pull --ff-only
git tag -a v1.7.0 -m "Realign with auth-providers@2.0.0"
git push --tags
```

Then hand the publish to the user, as before.

---

# Phase D — `auth-broker@1.0.9`

### Task 19: Update the broker's integration tests

**Files:**
- Modify: `/home/okyslytsia/prj/mcp-abap-adt-auth-broker/src/__tests__/broker/AuthBroker.integration.test.ts:175,235,381,664,771`, `package.json`, `CHANGELOG.md`

The broker has no functional dependency on auth-providers — only its integration tests construct `AuthorizationCodeProvider` directly.

- [ ] **Step 1: Branch, bump, force-refresh**

```bash
cd /home/okyslytsia/prj/mcp-abap-adt-auth-broker
git checkout -b feat/authorization-strategies
rm -rf node_modules/@mcp-abap-adt/auth-providers
npm install @mcp-abap-adt/auth-providers@2.0.0 --save-dev
grep '"version"' node_modules/@mcp-abap-adt/auth-providers/package.json
```

- [ ] **Step 2: Run the type check to see the breakage**

```bash
npm run test:check
```

Expected: FAIL at each `redirectPort:` line.

- [ ] **Step 3: Convert each construction**

At every listed line, replace the field:

```ts
// before
redirectPort: port1,
// after
authorization: browserCallbackStrategy({ port: port1 }),
```

with `browserCallbackStrategy` added to the file's import from `@mcp-abap-adt/auth-providers`. Where a test picks a port via `getAvailablePort()`, keep that: these tests bind real sockets and rely on knowing the port.

- [ ] **Step 4: Verify**

```bash
npm run lint:check && npm run build && npm test
```

Integration tests skip without `tests/test-config.yaml`; that is expected and fine.

- [ ] **Step 5: Release**

Bump to `1.0.9`, add a CHANGELOG entry noting that only test wiring changed, then branch → PR → merge → tag → hand the publish to the user.

---

# Closing out

- [ ] **Step 1: Close the issue**

```bash
cd /home/okyslytsia/prj/mcp-abap-adt-auth-providers
gh issue close 11 --comment "Closed by auth-providers@2.0.0. All three deferred items are done: callback reception is behind \`IAuthorizationStrategy\` with the transport factories exported, ephemeral ports work where the IdP allows a loopback redirect on any port, and a code-less callback is answered, counted and reported rather than ending the login. Realigned: interfaces@11.5.0, proxy@1.7.0, auth-broker@1.0.9."
```

- [ ] **Step 2: Delete the implemented spec and plan**

`CLAUDE.md` keeps `docs/superpowers/` for work in progress only; git holds the history.

```bash
git rm docs/superpowers/specs/2026-07-29-authorization-strategies-design.md \
       docs/superpowers/plans/2026-07-29-authorization-strategies.md
git commit -m "docs: remove the implemented spec and plan"
git push
```
