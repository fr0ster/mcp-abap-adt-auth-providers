# Callback Server Contract Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make it impossible for a callback server in this package to hold its port after it is no longer needed, by giving every flow one factory-scoped lifetime with a mandatory timeout and cancellation.

**Architecture:** Three independently written callback servers each tie the release of their socket to a promise settling. A new contract in `@mcp-abap-adt/interfaces` inverts that: the server handle is borrowed inside a factory callback, and the factory releases the port on the first terminal outcome — the callback returning or throwing, an explicit failure, the timeout, or an abort. Each existing flow becomes one factory.

**Tech Stack:** TypeScript, Express + `node:http`, Jest (`NODE_OPTIONS=--experimental-vm-modules`), Biome. Two repositories.

**Requirements source:** `docs/superpowers/specs/2026-07-28-callback-server-contract-design.md`, and issue https://github.com/fr0ster/mcp-abap-adt-auth-providers/issues/11. Read the spec before Task 1 — it carries the measured failures, the eight contract rules and the shutdown algorithm this plan implements.

## Global Constraints

- **Public API of `auth-providers` does not change.** `AuthorizationCodeProviderConfig` keeps `browser?: string` and `redirectPort?: number` with the existing default of `3001`. Both releases are minor.
- The three factories stay **internal** to `auth-providers`. Exporting them is part of moving reception to the consumer (issue #11) and is out of scope.
- Assertions about a port must **bind the socket**. `browserAuth.ts` logs `port ${PORT} freed` on a path that never calls `close()`, so log output proves nothing.
- Do not change the shape of what `startBrowserAuth`, `startOidcBrowserAuth` or `startSamlBrowserAuth` resolve to. `@mcp-abap-adt/auth-broker` depends on all three.
- `port: 0` is **not supported** and must not be passed. The browser flow could take it, since it builds its URL inside the scope from `srv.redirectUri`; OIDC and SAML receive a URL built before the bind, so the redirect would carry `:0`. Restructuring those flows is a separate change.
- A callback carrying neither `code` nor `error` keeps ending the login with an error. Only the leaked socket is being fixed here, not the termination.
- Two tests in `src/__tests__/providers/AuthorizationCodeProvider.test.ts` already fail in a full-suite run on `master` (they pass in isolation). They are expected to go green in Task 5. Until then, judge a suite run by comparing against that baseline, not against zero failures.

---

### Task 1: Add the contract to `@mcp-abap-adt/interfaces`

**Repository:** `/home/okyslytsia/prj/mcp-abap-adt-interfaces` (branch from `master`)

**Files:**
- Create: `src/auth/ICallbackServer.ts`
- Modify: `src/index.ts`
- Modify: `CHANGELOG.md`, `package.json`

**Interfaces:**
- Consumes: nothing.
- Produces: `ICallbackServerOptions`, `ICallbackServerHandle<TResult>`, `CallbackServerFactory<TResult>` — every later task depends on these exact names.

- [ ] **Step 1: Write the contract**

Create `src/auth/ICallbackServer.ts`. Follow the file style of `src/connection/IWebSocketTransport.ts`: a file-level comment stating the contract is domain-agnostic, and JSDoc on every member.

```ts
/**
 * Local callback server used by interactive authorization flows.
 *
 * The handle is borrowed: it exists only for the duration of the factory's
 * callback, and the port is released on the first terminal outcome — that
 * callback returning or throwing, an explicit failure, the timeout, or an
 * abort. Release is therefore never a consequence of a wait settling, which is
 * what lets an abandoned login hold a port.
 */

export interface ICallbackServerOptions {
  /**
   * Port for the local listener. Must be an integer in 1..65535 —
   * `Number.isInteger(port)` included, since `3001.5` satisfies the range.
   *
   * `0` is rejected rather than treated as "pick one for me": the OIDC and SAML
   * flows build their authorization URL before the server binds, so an
   * ephemeral port would be advertised to the IdP as `:0`.
   */
  readonly port: number;
  /**
   * Mandatory: how long to wait for the callback. Must satisfy
   * `Number.isFinite(timeoutMs) && timeoutMs > 0 && timeoutMs <= 2_147_483_647`.
   *
   * `Infinity` is rejected — "wait forever" is the defect this option exists to
   * remove. The upper bound is Node's: `setTimeout` takes a 32-bit signed delay,
   * and measured, `2_147_483_648` fires after 1 ms with a
   * `TimeoutOverflowWarning`. A generous-looking timeout would otherwise end the
   * login almost instantly. Rejected rather than clamped — clamping hides it.
   */
  readonly timeoutMs: number;
  /** External cancellation — "this login is no longer needed". */
  readonly signal?: AbortSignal;
}

/**
 * Borrowed handle. Valid only while the factory's `use` callback is running;
 * every member throws once the scope has ended.
 */
export interface ICallbackServerHandle<TResult> {
  /** The port actually bound. */
  readonly port: number;
  /** Redirect URI the authorization request must use. */
  readonly redirectUri: string;
  /**
   * Resolves with the callback's result. Rejects on timeout, on cancellation,
   * on `fail`, or when the scope ends while it is still pending.
   */
  waitForResult(): Promise<TResult>;
  /** End the wait with an error — e.g. the browser could not be launched. */
  fail(error: Error): void;
}

/**
 * The only way to obtain a callback server. There is deliberately no `close`
 * on the handle: closing belongs to the factory, so it cannot be forgotten.
 *
 * Settles on the first terminal outcome — `use` returning or throwing, `fail`,
 * the timeout, or an abort — and only after the listening socket has been
 * released, so a settled result always means the port is free. It does not
 * promise to stop `use`; an arbitrary async function cannot be force-terminated.
 *
 * The type parameter is on the alias rather than the call signature: a factory
 * for a given flow always produces that flow's result. Were it generic per call,
 * `withBrowserCallbackServer<number>(...)` would type-check against a handler
 * that can only ever yield a string.
 */
export type CallbackServerFactory<TResult> = (
  options: ICallbackServerOptions,
  use: (server: ICallbackServerHandle<TResult>) => Promise<TResult>,
) => Promise<TResult>;
```

- [ ] **Step 2: Export it**

In `src/index.ts`, next to the other `./auth/...` exports (around line 304-312), add in alphabetical position:

```ts
export type {
  CallbackServerFactory,
  ICallbackServerHandle,
  ICallbackServerOptions,
} from './auth/ICallbackServer';
```

- [ ] **Step 3: Verify it compiles and is reachable**

```bash
npm run build && npx tsc --noEmit
node -e "const t=require('./dist/index.js'); console.log('build ok')"
grep -c "ICallbackServerOptions" dist/index.d.ts
```
Expected: build passes, and the grep returns at least 1. This is a types-only addition, so there is nothing to assert at runtime beyond the module loading.

- [ ] **Step 4: Changelog and version**

Bump `version` to `11.4.0` in `package.json` (additive → minor). Add to `CHANGELOG.md` above the previous entry:

```markdown
## [11.4.0] - YYYY-MM-DD

### Added
- `ICallbackServerOptions`, `ICallbackServerHandle<TResult>` and `CallbackServerFactory` — a contract for the local callback server used by interactive authorization flows. The handle is borrowed for the duration of a factory callback and the port is released on the first terminal outcome, so releasing a socket is never a consequence of a wait settling. `timeoutMs` is mandatory and cancellation is supported through an `AbortSignal`.
```

Use the date of the release commit in place of `YYYY-MM-DD`.

- [ ] **Step 5: Commit**

```bash
git add src/auth/ICallbackServer.ts src/index.ts package.json CHANGELOG.md
git commit -m "feat(11.4.0): add the callback server contract

A borrowed handle inside a factory scope, with a mandatory timeout and an
AbortSignal. Releasing the socket stops being a consequence of the wait
settling, which is what lets an abandoned login hold a port."
```

- [ ] **Step 6: PR, merge, tag**

Open a PR against `master`, merge it squashed, sync `master`, then `git tag -a v11.4.0` and push the tag.

---

### GATE: the maintainer publishes `@mcp-abap-adt/interfaces@11.4.0`

**Do not run `npm publish`.** Report that Task 1 is merged and tagged, and wait for confirmation that the package is on npm. Nothing in Task 2 onwards compiles until it is — `auth-providers` cannot import a type that has not shipped.

After confirmation, in `auth-providers`:

```bash
rm -rf node_modules/@mcp-abap-adt/interfaces
npm install @mcp-abap-adt/interfaces@^11.4.0 --save
cat node_modules/@mcp-abap-adt/interfaces/package.json | grep '"version"'
```

Check the installed copy directly — `npm view` reports the registry, not what landed on disk. The jump from `^2.3.0` has been measured against `11.3.0`: zero type errors and no change in test results.

---

### Task 2: Browser callback factory

**Repository:** `/home/okyslytsia/prj/mcp-abap-adt-auth-providers` (branch `feat/callback-server-contract`)

**Files:**
- Create: `src/auth/callbackServer.ts`
- Create: `src/__tests__/auth/callbackServer.test.ts`

**Interfaces:**
- Consumes: `CallbackServerFactory`, `ICallbackServerHandle`, `ICallbackServerOptions` from Task 1.
- Produces: `withBrowserCallbackServer` and the shared internal helper `runCallbackScope`, both used by Tasks 3 and 4.

- [ ] **Step 1: Write the failing tests**

Create `src/__tests__/auth/callbackServer.test.ts`:

```ts
import { describe, it, expect, afterEach } from '@jest/globals';
import * as http from 'node:http';
import * as net from 'node:net';
import { withBrowserCallbackServer } from '../../auth/callbackServer';

const PORT = 7871;

// Bind to check. The property under test is that a later login can take the
// port back, and only an actual bind proves that.
function portIsFree(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.once('error', () => resolve(false));
    s.listen(port, () => s.close(() => resolve(true)));
  });
}

const deliver = (query: string) =>
  fetch(`http://127.0.0.1:${PORT}/callback${query}`).catch(() => undefined);

afterEach(async () => {
  expect(await portIsFree(PORT)).toBe(true);
});

describe('withBrowserCallbackServer', () => {
  it('binds while the scope runs and yields the code', async () => {
    const code = await withBrowserCallbackServer(
      { port: PORT, timeoutMs: 5000 },
      async (srv) => {
        expect(srv.port).toBe(PORT);
        expect(srv.redirectUri).toBe(`http://localhost:${PORT}/callback`);
        expect(await portIsFree(PORT)).toBe(false);
        const waiting = srv.waitForResult();
        void deliver('?code=abc123');
        return await waiting;
      },
    );
    expect(code).toBe('abc123');
  });

  // The OIDC/SAML regression: an abandoned login must not hold the port.
  it('releases the port when the login is abandoned', async () => {
    await expect(
      withBrowserCallbackServer(
        { port: PORT, timeoutMs: 300 },
        async (srv) => await srv.waitForResult(),
      ),
    ).rejects.toThrow(/timeout/i);
  });

  it('releases the port when cancelled', async () => {
    const ac = new AbortController();
    const scope = withBrowserCallbackServer(
      { port: PORT, timeoutMs: 30000, signal: ac.signal },
      async (srv) => await srv.waitForResult(),
    );
    setTimeout(() => ac.abort(), 100);
    await expect(scope).rejects.toThrow();
  });

  it('releases the port when the body throws', async () => {
    await expect(
      withBrowserCallbackServer({ port: PORT, timeoutMs: 5000 }, async () => {
        throw new Error('boom');
      }),
    ).rejects.toThrow('boom');
  });

  it('releases the port when fail() ends the wait', async () => {
    await expect(
      withBrowserCallbackServer({ port: PORT, timeoutMs: 5000 }, async (srv) => {
        const waiting = srv.waitForResult();
        srv.fail(new Error('browser launch failed'));
        return await waiting;
      }),
    ).rejects.toThrow('browser launch failed');
  });

  // Rule 4: a body that returns without awaiting must leave nothing dangling.
  it('rejects a pending wait when the scope ends', async () => {
    let dangling: Promise<string> | undefined;
    await withBrowserCallbackServer(
      { port: PORT, timeoutMs: 5000 },
      async (srv) => {
        dangling = srv.waitForResult();
        return 'returned without awaiting';
      },
    );
    await expect(dangling).rejects.toThrow();
  });

  // Rule 6: the handle is dead afterwards.
  it('gives a dead handle per-member behaviour, not a uniform throw', async () => {
    let escaped!: {
      port: number;
      redirectUri: string;
      waitForResult: () => Promise<string>;
      fail: (e: Error) => void;
    };
    await withBrowserCallbackServer(
      { port: PORT, timeoutMs: 5000 },
      async (srv) => {
        escaped = srv;
        return 'done';
      },
    );
    expect(() => escaped.fail(new Error('late'))).not.toThrow();   // silent no-op
    await expect(escaped.waitForResult()).rejects.toThrow();       // rejects, never throws
    expect(escaped.port).toBe(PORT);                               // values stay readable
    expect(escaped.redirectUri).toContain(String(PORT));
  });

  // A delivered callback is not itself terminal, so fail() still wins if it
  // lands before `use` fulfils.
  it('lets a fail before the body returns beat a delivered callback', async () => {
    await expect(
      withBrowserCallbackServer({ port: PORT, timeoutMs: 5000 }, async (srv) => {
        const waiting = srv.waitForResult();
        void deliver('?code=first');
        const value = await waiting;
        srv.fail(new Error('too late for the payload'));
        await new Promise((r) => setTimeout(r, 50));
        return value;
      }),
    ).rejects.toThrow('too late for the payload');
  });

  it('ignores a fail once the body has already returned', async () => {
    let escaped!: { fail: (e: Error) => void; waitForResult: () => Promise<string> };
    const code = await withBrowserCallbackServer(
      { port: PORT, timeoutMs: 5000 },
      async (srv) => {
        escaped = srv;
        const waiting = srv.waitForResult();
        void deliver('?code=first');
        return await waiting;
      },
    );
    expect(code).toBe('first');
    // Silent no-op, not a throw: this is what a late launcher rejection calls.
    expect(() => escaped.fail(new Error('way too late'))).not.toThrow();
    await expect(escaped.waitForResult()).rejects.toThrow();
  });

  it('survives a launcher that rejects after the timeout', async () => {
    let reportLate: ((e: Error) => void) | undefined;
    const launcher = new Promise<void>((_, rej) => {
      reportLate = (e) => rej(e);
    });
    await expect(
      withBrowserCallbackServer({ port: PORT, timeoutMs: 300 }, async (srv) => {
        launcher.catch((e) => srv.fail(e));
        return await srv.waitForResult();
      }),
    ).rejects.toThrow(/timeout/i);
    reportLate?.(new Error('launcher died late'));
    await new Promise((r) => setTimeout(r, 100));
  });

  it('honours an abort that arrives during the bind', async () => {
    const ac = new AbortController();
    let ran = false;
    const scope = withBrowserCallbackServer(
      { port: PORT, timeoutMs: 5000, signal: ac.signal },
      async () => {
        ran = true;
        return 'unreachable';
      },
    );
    ac.abort();
    await expect(scope).rejects.toThrow();
    expect(ran).toBe(false);
  });

  it('rejects a timeoutMs outside 0 < t <= 2_147_483_647', async () => {
    for (const bad of [0, -1, Number.NaN, Number.POSITIVE_INFINITY, 2_147_483_648]) {
      await expect(
        withBrowserCallbackServer({ port: PORT, timeoutMs: bad }, async () => 'unreachable'),
      ).rejects.toThrow();
    }
    // The boundary itself is valid: accepted, and the scope still ends on its
    // own terms rather than on a timer that would overflow.
    await expect(
      withBrowserCallbackServer(
        { port: PORT, timeoutMs: 2_147_483_647 },
        async () => 'accepted',
      ),
    ).resolves.toBe('accepted');
  });

  it('rejects a port that is not an integer in 1..65535, without binding', async () => {
    for (const bad of [0, -1, 65536, 3001.5]) {
      await expect(
        withBrowserCallbackServer({ port: bad, timeoutMs: 5000 }, async () => 'unreachable'),
      ).rejects.toThrow();
    }
  });

  it('rejects a pre-aborted signal without binding and without running the body', async () => {
    const ac = new AbortController();
    ac.abort();
    let ran = false;
    await expect(
      withBrowserCallbackServer({ port: PORT, timeoutMs: 5000, signal: ac.signal }, async () => {
        ran = true;
        return 'unreachable';
      }),
    ).rejects.toThrow();
    expect(ran).toBe(false);
  });

  it('fails cleanly when the port is already held', async () => {
    const squatter = net.createServer();
    await new Promise<void>((r) => squatter.listen(PORT, () => r()));
    let ran = false;
    try {
      await expect(
        withBrowserCallbackServer({ port: PORT, timeoutMs: 5000 }, async () => {
          ran = true;
          return 'unreachable';
        }),
      ).rejects.toThrow();
      expect(ran).toBe(false);
    } finally {
      await new Promise<void>((r) => squatter.close(() => r()));
    }
  });

  // The browserAuth leak, at the level of the new unit.
  it('ends the login and releases the port on a callback with no code', async () => {
    await expect(
      withBrowserCallbackServer({ port: PORT, timeoutMs: 5000 }, async (srv) => {
        const waiting = srv.waitForResult();
        void deliver('');
        return await waiting;
      }),
    ).rejects.toThrow(/code/i);
  });

  // The contradiction the contract had to resolve: an arbitrary `use` cannot be
  // cancelled, so the timeout must win the race and free the port anyway.
  it('releases the port when the body never settles', async () => {
    await expect(
      withBrowserCallbackServer({ port: PORT, timeoutMs: 300 }, () => new Promise<string>(() => {})),
    ).rejects.toThrow(/timeout/i);
  });

  // Shutdown must be bounded even with a client holding an idle connection.
  // A bare fetch does not exercise this.
  it('releases the port with an idle keep-alive client attached', async () => {
    const agent = new http.Agent({ keepAlive: true });
    await new Promise<void>((resolve) => {
      const scope = withBrowserCallbackServer({ port: PORT, timeoutMs: 2000 }, async (srv) => {
        await new Promise<void>((ready) => {
          http.get({ host: '127.0.0.1', port: PORT, path: '/', agent }, (r) => {
            r.resume();
            r.on('end', () => ready());
          });
        });
        return await srv.waitForResult();
      });
      void scope.catch(() => undefined).then(() => resolve());
    });
    agent.destroy();
  }, 30000);

  // The success page must survive shutdown: settle only after the response has
  // flushed, and do not destroy active connections in the first shutdown step.
  it('delivers the success page in full before releasing the port', async () => {
    const body = await withBrowserCallbackServer({ port: PORT, timeoutMs: 5000 }, async (srv) => {
      const waiting = srv.waitForResult();
      const page = await fetch(`http://127.0.0.1:${PORT}/callback?code=flushed`).then((r) =>
        r.text(),
      );
      expect(page.length).toBeGreaterThan(0);
      await waiting;
      return page;
    });
    expect(body).toContain('<');
  }, 30000);

  it('reports an OAuth error immediately rather than timing out', async () => {
    const started = Date.now();
    await expect(
      withBrowserCallbackServer({ port: PORT, timeoutMs: 30000 }, async (srv) => {
        const waiting = srv.waitForResult();
        void deliver('?error=access_denied&error_description=User%20said%20no');
        return await waiting;
      }),
    ).rejects.toThrow(/access_denied/);
    expect(Date.now() - started).toBeLessThan(5000);
  });
});
```

The `afterEach` asserting the port is free runs after **every** test, so any path that leaks fails the suite without needing its own case.

- [ ] **Step 2: Run them to verify they fail**

Run: `npm test -- src/__tests__/auth/callbackServer.test.ts`
Expected: FAIL — `Cannot find module '../../auth/callbackServer'`.

- [ ] **Step 3: Implement `src/auth/callbackServer.ts`**

Write one internal helper that owns the lifetime, and a thin per-flow factory on top:

```ts
import express, { type Express } from 'express';
import * as http from 'node:http';
import type {
  CallbackServerFactory,
  ICallbackServerHandle,
  ICallbackServerOptions,
} from '@mcp-abap-adt/interfaces';

/**
 * Owns the socket for the duration of `use`. Every route registered by a flow
 * settles through `settle`, which is the only place an outcome is produced.
 */
async function runCallbackScope<TResult>(
  options: ICallbackServerOptions,
  routes: (app: Express, settle: Settle<TResult>) => void,
  use: (server: ICallbackServerHandle<TResult>) => Promise<TResult>,
): Promise<TResult>;
```

Requirements, each mapped to a test above:

1. Validate before binding: `Number.isInteger(options.port)` and `1 <= port <= 65535`, and `Number.isFinite(options.timeoutMs) && options.timeoutMs > 0 && options.timeoutMs <= 2_147_483_647` — above that Node's `setTimeout` overflows its 32-bit delay and fires after 1 ms, so a large timeout would end the login instantly. Reject immediately, without binding and without calling `use`, when `options.signal?.aborted` is already true. Register the `signal` listener **before** calling `listen`, so an abort arriving during the bind is not dropped; if it fires then, tear the server down whether or not it reached `listening`, remove the listener and any timer, and reject without calling `use`. On a `listen` error such as `EADDRINUSE`, reject with that error and leave nothing registered. Call `use` from the `listen` callback and arm the timeout there, so a slow bind does not eat the login window.
2. Register routes and create the internal promise **before** `listen` resolves, so a callback arriving immediately is not lost.
3. `settle` produces the outcome exactly once; later calls are no-ops. A route may only settle **after its response has flushed** — bind it to the response's `finish` event or the `res.end()` callback. `res.send()` returning does not mean the bytes have left, and settling earlier races the shutdown against the success page.
4. A delivered callback settles `waitForResult()` only — it does **not** end the scope. The scope ends when `use` fulfils (the factory resolves with `use`'s value, so `transform(await waitForResult())` works), when `use` throws, or on `fail`/timeout/abort. Failures end it without waiting for `use`.
5. Arm the timeout from `timeoutMs` when the scope starts, not when `waitForResult()` is called.
6. Subscribe to `options.signal`; on abort, settle with an error. Remove the listener when the scope ends.
7. Race `use` against the terminal outcomes. Whichever settles first decides; a later settlement from the losing `use` — value or rejection — is discarded, so an abandoned body cannot surface as an unhandled rejection. Do **not** attempt to cancel `use`: it cannot be done, and pretending otherwise is what made the first draft of this contract self-contradictory.
8. Shut down on that outcome, in this order, and resolve only when it is finished:
   1. `server.close()` to stop accepting;
   2. `closeIdleConnections()` — **idle only**. `closeAllConnections()` must not run here: it destroys active connections too, and the one delivering the success page is active. In the consuming proxy's suite a client fetching `/callback` intermittently got `ECONNRESET` instead of the page for exactly this reason;
   3. wait for `close`, bounded by a 500 ms grace;
   4. on grace expiry, destroy what remains — `closeAllConnections()` plus the sockets tracked from the `connection` event — and stop waiting;
   5. resolve. Shutdown is bounded, so a timeout can never hang on its own cleanup.
9. Do not set `server.keepAliveTimeout = 0`. Per the Node documentation `0` *disables* the keep-alive timeout, the opposite of what the current comment claims, and measurement on Node 25 shows `close()` completing in 0-3 ms whether it is 0, 5000 or 72000. It is noise.
10. Mark the handle dead when the scope ends; its members throw afterwards. A `use` that lost the race and keeps running hits this.
11. Settle any still-pending `waitForResult()` with an error as part of shutdown.

Then the browser flow, moving the routes across from `browserAuth.ts` unchanged — `/callback`, the paste form `/` and `/submit`, and the success/error/paste HTML:

```ts
export const withBrowserCallbackServer: CallbackServerFactory = (options, use) =>
  runCallbackScope(options, (app, settle) => {
    app.get('/callback', (req, res) => { /* code → settle.ok, error → settle.err, neither → 400 + settle.err */ });
    app.get('/', (_req, res) => res.send(pasteFormHtml()));
    app.get('/submit', (req, res) => { /* extractCode → settle.ok, else re-render */ });
  }, use);
```

- [ ] **Step 4: Run them to verify they pass**

Run: `npm test -- src/__tests__/auth/callbackServer.test.ts`
Expected: PASS, all ten, including every `afterEach` port check.

- [ ] **Step 5: Lint, build, full suite**

Run: `npm run lint:check && npm run build && npm test`
Expected: build and lint clean. The suite still shows the two pre-existing `AuthorizationCodeProvider` failures and no others — `browserAuth.ts` is untouched so far.

- [ ] **Step 6: Commit**

```bash
git add src/auth/callbackServer.ts src/__tests__/auth/callbackServer.test.ts
git commit -m "feat: browser callback factory with a scoped socket lifetime

The port is released when the scope ends — success, error, timeout, abort or a
throwing body — instead of when a promise happens to settle. Not wired up yet."
```

---

### Task 3: Rewire `startBrowserAuth` onto the factory

**Files:**
- Modify: `src/auth/browserAuth.ts:170-790`
- Modify: `src/__tests__/auth/browserAuth.test.ts`

**Interfaces:**
- Consumes: `withBrowserCallbackServer` from Task 2.
- Produces: `startBrowserAuth` with its existing signature and resolved shape, minus the `port = 3001` parameter default.

- [ ] **Step 1: Write the failing test**

Add to `src/__tests__/auth/browserAuth.test.ts`, with the same bind-based `portIsFree` helper:

```ts
describe('startBrowserAuth port lifetime', () => {
  const PORT = 7872;

  it('releases the port when a callback carries no code', async () => {
    const cfg = { uaaUrl: 'http://127.0.0.1:9', uaaClientId: 'c', uaaClientSecret: 's' };
    const login = startBrowserAuth(cfg as never, 'none', null, PORT);
    await new Promise((r) => setTimeout(r, 300));
    await fetch(`http://127.0.0.1:${PORT}/callback`).catch(() => undefined);

    await expect(login).rejects.toThrow();
    // No sleep: a settled promise must mean a free port.
    expect(await portIsFree(PORT)).toBe(true);
  }, 30000);
});
```

- [ ] **Step 2: Run it to verify it fails**

Run: `npm test -- src/__tests__/auth/browserAuth.test.ts`
Expected: FAIL on `expect(await portIsFree(PORT)).toBe(true)` — the socket is still bound, which is the defect from issue #11.

- [ ] **Step 3: Rewrite the body**

Replace the promise executor after the `isPortAvailable` guard with the factory call:

```ts
const code = await withBrowserCallbackServer(
  { port, timeoutMs },
  async (srv) => {
    const authorizationUrl =
      authConfig.authorizationUrl ?? getJwtAuthorizationUrl(authConfig, srv.port);
    const waiting = srv.waitForResult();
    launchBrowser(authorizationUrl, browser, announce, log).catch((e) =>
      srv.fail(
        new Error(
          `Browser opening failed for destination authentication. Please open manually: ${authorizationUrl}`,
          { cause: e },
        ),
      ),
    );
    return await waiting;
  },
);
return await exchangeCodeForToken(authConfig, code, port, log);
```

Extract the browser-opening block — `BROWSER_MAP`, the `open` import with its `child_process` fallback, the `none`/`headless` announce path, the Linux `DISPLAY` default — into `launchBrowser` in the same file. It must not be awaited on the critical path: a launcher that hangs must not delay the timeout or the release, and one that fails routes into `fail`.

The stdin paste reader moves into the same scope, registered for `none`/`headless` when `process.stdin.isTTY`, and torn down by the scope like everything else.

Two signature changes, both additive:

- Add a `timeoutMs` parameter with a default of `30_000`, so existing callers keep
  compiling and keep today's behaviour. Task 5 makes the provider pass it explicitly; the
  same parameter is what lets the provider stop running a timer of its own.
- Drop the `port = 3001` parameter default. Task 5 makes the provider always pass a
  resolved value, and two different defaults for one thing is how they drift apart.

```ts
export async function startBrowserAuth(
  authConfig: IAuthorizationConfig,
  browser: string = 'system',
  logger?: ILogger,
  port: number,              // no default — the caller resolves it
  timeoutMs: number = 30_000,
): Promise<{ accessToken: string; refreshToken?: string }>
```

TypeScript does not allow a required parameter after an optional one, so `browser` and
`logger` keep their defaults only if `port` moves ahead of them or they become explicitly
`| undefined`. Keep the existing order and mark the earlier ones `?: T | undefined` rather
than reordering — `@mcp-abap-adt/auth-broker` calls this positionally.

- [ ] **Step 4: Run the browserAuth tests**

Run: `npm test -- src/__tests__/auth/browserAuth.test.ts`
Expected: PASS, including the existing browser-mode and `extractCode` cases. If a test asserted on an internal timer or on log text that no longer exists, update it to the new contract — do not `it.skip` it.

- [ ] **Step 5: Lint, build, full suite**

Run: `npm run lint:check && npm run build && npm test`
Expected: clean apart from the two known `AuthorizationCodeProvider` failures.

- [ ] **Step 6: Commit**

```bash
git add src/auth/browserAuth.ts src/__tests__/auth/browserAuth.test.ts
git commit -m "fix: release the browser callback port on every exit path

A callback carrying neither code nor error left the socket bound for the life
of the process. The scope now owns the port, so it comes back whatever ends
the login, and the promise settles only once it has."
```

---

### Task 4: OIDC and SAML factories

**Files:**
- Modify: `src/auth/oidcBrowserAuth.ts`, `src/auth/saml2Auth.ts`
- Create: `src/__tests__/auth/ssoCallbackLifetime.test.ts`

**Interfaces:**
- Consumes: `runCallbackScope` from Task 2.
- Produces: `withOidcCallbackServer`, `withSamlCallbackServer`; `startOidcBrowserAuth` and `startSamlBrowserAuth` keep their signatures and resolved shapes.

- [ ] **Step 1: Write the failing tests**

Create `src/__tests__/auth/ssoCallbackLifetime.test.ts` with the bind-based `portIsFree`:

```ts
// Neither flow has a timeout today: an abandoned login holds the port forever.
// These are the regressions.
describe('SSO callback lifetime', () => {
  it('releases the OIDC port when the login is abandoned', async () => {
    const PORT = 7873;
    await expect(
      startOidcBrowserAuth('http://127.0.0.1:9/authorize', 'none', null, PORT, 300),
    ).rejects.toThrow(/timeout/i);
    expect(await portIsFree(PORT)).toBe(true);
  }, 30000);

  it('releases the SAML port when the login is abandoned', async () => {
    const PORT = 7874;
    await expect(
      startSamlBrowserAuth('http://127.0.0.1:9/sso', 'none', null, PORT, 300),
    ).rejects.toThrow(/timeout/i);
    expect(await portIsFree(PORT)).toBe(true);
  }, 30000);
});
```

Both functions gain a `timeoutMs` parameter. Give it a default of `30_000` so existing callers keep compiling and behave as documented, and check the current call sites in `src/providers/OidcBrowserProvider.ts` and `src/providers/saml2Utils.ts` for whether they should pass it explicitly.

- [ ] **Step 2: Run them to verify they fail**

Run: `npm test -- src/__tests__/auth/ssoCallbackLifetime.test.ts`
Expected: FAIL — each test hits Jest's own timeout because the promise never settles. That is precisely the defect.

- [ ] **Step 3: Move both onto the scope**

Replace each hand-rolled `new Promise` + `cleanup()` with `runCallbackScope`, keeping each flow's routes and payload:

- OIDC: `GET /callback` → `{ code, state }`; missing code ends the login with an error, as today.
- SAML: `POST` and `GET /callback` → the `SAMLResponse` string; missing response ends the login with an error, as today.

Delete the `let resolved` / `cleanup()` pairs and the `server.keepAliveTimeout = 0` lines; the scope owns all of it now.

- [ ] **Step 4: Run them to verify they pass**

Run: `npm test -- src/__tests__/auth/ssoCallbackLifetime.test.ts`
Expected: PASS, both, in well under the 30 s test timeout.

- [ ] **Step 5: Lint, build, full suite**

Run: `npm run lint:check && npm run build && npm test`
Expected: clean apart from the two known `AuthorizationCodeProvider` failures.

- [ ] **Step 6: Commit**

```bash
git add src/auth/oidcBrowserAuth.ts src/auth/saml2Auth.ts src/__tests__/auth/ssoCallbackLifetime.test.ts
git commit -m "fix: give the OIDC and SAML callback servers a lifetime

Neither had a timeout, so an abandoned login never settled and the port was
held for the life of the process. Both now run inside the same scope as the
browser flow."
```

---

### Task 5: One timeout, owned by the scope

**Files:**
- Modify: `src/providers/AuthorizationCodeProvider.ts:153-172`
- Modify: `src/__tests__/providers/AuthorizationCodeProvider.test.ts`

**Interfaces:**
- Consumes: `startBrowserAuth` from Task 3.
- Produces: no signature change. `redirectPort` stays optional with its 3001 default.

- [ ] **Step 1: Write the failing test**

Add to `src/__tests__/providers/AuthorizationCodeProvider.test.ts`, with the bind-based `portIsFree`:

```ts
it('leaves the callback port free the moment a login times out', async () => {
  const provider = new AuthorizationCodeProvider({
    uaaUrl: 'http://127.0.0.1:9',
    clientId: 'client',
    clientSecret: 'secret',
    browser: 'none',
    redirectPort: 7875,
  });

  await expect(provider.getTokens()).rejects.toThrow(/timeout/i);
  // No sleep. With the outer Promise.race still in place this fails about half
  // the time, which is why it is asserted rather than reasoned about.
  expect(await portIsFree(7875)).toBe(true);
}, 60000);
```

- [ ] **Step 2: Run it to verify it fails**

Run: `npm test -- src/__tests__/providers/AuthorizationCodeProvider.test.ts`
Expected: FAIL, intermittently but demonstrably — when the outer timer wins the race the provider rejects while the socket is still bound. Run it several times; a single green run proves nothing here.

- [ ] **Step 3: Delete the competing timer**

Remove `timeoutMs`, `timeoutPromise` and the `Promise.race` wrapper. Await `startBrowserAuth` directly and pass the login timeout down to it, so the only timer lives in the scope that owns the socket.

- [ ] **Step 4: Run it to verify it passes**

Run: `npm test -- src/__tests__/providers/AuthorizationCodeProvider.test.ts` — several times.
Expected: PASS consistently.

- [ ] **Step 5: The full suite must now be green**

Run: `npm run lint:check && npm run build && npm test`
Expected: **zero failures.** The two `AuthorizationCodeProvider` tests that fail on `master` in a full run should now pass: they were losing 30 s each to competing timers and contending sockets. Jest should also stop printing `Force exiting Jest: ... async operations that kept running` — the uncleared timer is gone.

If either symptom survives, stop and investigate rather than adjusting the test. It would mean something still outlives its scope.

- [ ] **Step 6: Commit**

```bash
git add src/providers/AuthorizationCodeProvider.ts src/__tests__/providers/AuthorizationCodeProvider.test.ts
git commit -m "fix: single login timeout, owned by the callback scope

The provider raced startBrowserAuth against its own 30s timer — the same
duration as the internal one — so which fired was down to scheduling, and when
the outer one won the provider rejected while the socket was still bound. The
timer was also never cleared, keeping the event loop alive after a fast login."
```

---

### Task 6: Release 1.2.0

**Files:**
- Modify: `package.json`, `CHANGELOG.md`

- [ ] **Step 1: Version, engines and changelog**

Set `"version": "1.2.0"` and `"engines": { "node": ">=18.2.0" }` (was `>=18.0.0`) — `closeAllConnections()` landed in 18.2.0 and the shutdown algorithm calls it unconditionally. Minor: no exported signature changes, and `AuthorizationCodeProviderConfig` is untouched. Add above `## [1.1.0]`, using the release commit's date:

```markdown
## [1.2.0] - YYYY-MM-DD

### Fixed
- **A callback server could hold its port after the login it was opened for had ended.** Three flows, three shapes of the same defect: `browserAuth` leaked the socket when a callback carried neither `code` nor `error`, and neither `oidcBrowserAuth` nor `saml2Auth` had any timeout, so an abandoned login never settled and the port was never released. (#11)
- **A rejected login could report a port that was not yet free.** Five exit paths closed the socket asynchronously *after* the promise had settled, leaving a ~100 ms window in which "already in use" was untrue.
- **`AuthorizationCodeProvider` raced `startBrowserAuth` against a second 30-second timer** of its own, so when the outer one won it rejected while the socket was still bound. That timer was never cleared, keeping the event loop alive for the rest of the 30 seconds after a fast login.
- A hung browser launcher could delay the timeout and the release; the launch is no longer awaited on the critical path.

### Changed
- All three flows now run inside a factory scope implementing `CallbackServerFactory` from `@mcp-abap-adt/interfaces`. The port is released when the scope ends — by success, error, timeout, cancellation or a throwing body — instead of when a promise happens to settle. `timeoutMs` is mandatory and cancellation is available through an `AbortSignal`.
- Requires `@mcp-abap-adt/interfaces` `^11.4.0` (was `^2.3.0`).
- **`engines.node` is now `>=18.2.0`** (was `>=18.0.0`), for `server.closeAllConnections()`.

### Notes
- Public API unchanged: `AuthorizationCodeProviderConfig` keeps `browser` and `redirectPort`, still defaulting to 3001.
- The factories stay internal. Exposing them so a consumer can supply its own callback receiver is issue #11 and is not part of this release.
- A callback carrying neither `code` nor `error` still ends the login with an error. Only the leaked socket was fixed, not the termination.
```

- [ ] **Step 2: Verify the release commit**

Run: `npm run lint:check && npm run build && npm test`
Expected: zero failures, and `ls dist/auth/callbackServer.js` exists.

- [ ] **Step 3: Commit**

```bash
git add package.json CHANGELOG.md
git commit -m "release(1.2.0): scoped callback server lifetime"
```

---

## After this plan

1. Open a PR against `master` referencing `Closes #11` — or, if issue #11's boundary question is still open, referencing it without closing, since this plan fixes the hangs and introduces the seam but does not move reception to the consumer.
2. Merge, sync `master`, tag `v1.2.0`, push the tag.
3. **The maintainer publishes to npm.** Do not run `npm publish`.
4. `@mcp-abap-adt/auth-broker` and `@mcp-abap-adt/proxy` need no code change — the public API did not move — but both should be re-tested against the published build before their next release.
5. Delete this plan and the spec. Per `CLAUDE.md`, those directories hold only work in progress.
