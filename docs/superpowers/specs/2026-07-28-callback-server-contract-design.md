# Callback server contract

Date: 2026-07-28
Status: approved, not yet implemented
Issue: https://github.com/fr0ster/mcp-abap-adt-auth-providers/issues/11

## Problem

This package contains three OAuth/SAML callback servers, written independently, each of
which can hold its port after it is no longer needed:

| file | lines | what it does | how it hangs |
|---|---|---|---|
| `src/auth/browserAuth.ts` | 790 | `/callback`, paste form (`/`, `/submit`), stdin reader, browser launch | a callback carrying neither `code` nor `error` rejects through a `reject` that closes nothing; the socket is held for the lifetime of the process |
| `src/auth/oidcBrowserAuth.ts` | 124 | `/callback` with `code` + `state` | **no timeout at all** — an abandoned login never settles, and the port is held forever |
| `src/auth/saml2Auth.ts` | 205 | `POST`/`GET /callback` with `SAMLResponse` | same: no timeout, no release |

Measured, by binding the socket rather than reading log output:

```
browserAuth, callback with neither code nor error:
  promise: rejected — Authorization code missing
  +5s / +20s / +35s / +45s — port still bound
```

The 30-second timer that would otherwise have released it is cleared inside `reject`
(`browserAuth.ts:274-278`), which also removes the `exit`/`SIGTERM`/`SIGINT`/`SIGHUP`
cleanup listeners. Five other exit paths do close, but asynchronously *after* the promise
has already settled, so for ~100 ms a rejected login reports a port that is not yet free.

`AuthorizationCodeProvider.ts:153-172` adds a second 30-second timer racing the first via
`Promise.race`. Which fires is down to scheduling; when the outer one wins the provider
rejects while the socket is still bound. That timer is never cleared — `clearTimeout`
appears nowhere in the file — so a login that succeeds in a second leaves it armed for the
remaining 29.

The symptom is visible in this package's own suite:

```
src/__tests__/providers/AuthorizationCodeProvider.test.ts alone:  3/3 pass, 3.2 s
the same file in the full suite:                                  2 fail, 61 s
Jest: "Force exiting Jest: ... async operations that kept running"
```

61 seconds is two 30-second timeouts.

## The root shape

All three bind the release of the socket to a promise settling. When the promise does not
settle, nothing is released; when it settles on a path that forgot to close, nothing is
released either. And a bare promise offers no way for a caller to say *"I no longer need
this"* — there is no cancellation anywhere in the three files.

So the contract must not make release a consequence of success. Release has to be an
always-available action that does not depend on how, or whether, the wait ended.

## Design

A factory-scoped contract. The server handle exists only for the duration of a callback,
and the factory releases the port when that callback returns — by any means.

New file in `@mcp-abap-adt/interfaces`, `src/auth/ICallbackServer.ts`:

```ts
export interface ICallbackServerOptions {
  /** Port for the local listener. */
  readonly port: number;
  /** Mandatory. There is no such thing as waiting forever. */
  readonly timeoutMs: number;
  /** External cancellation: "no longer needed". */
  readonly signal?: AbortSignal;
}

/** Borrowed handle. Valid only while `use` is running. */
export interface ICallbackServerHandle<TResult> {
  readonly port: number;
  readonly redirectUri: string;
  waitForResult(): Promise<TResult>;
  fail(error: Error): void;
}

/** The only way to obtain a server. */
export type CallbackServerFactory = <TResult>(
  options: ICallbackServerOptions,
  use: (server: ICallbackServerHandle<TResult>) => Promise<TResult>,
) => Promise<TResult>;
```

`close()` is deliberately absent from the handle. Closing belongs to the factory, so it
cannot be forgotten — nobody calls it by hand.

### Rules

Each of these closes one of the observed failures:

1. **The port is released when `use` returns** — by success, error, timeout or abort. Not
   when the wait settles.
2. **The factory settles only after the socket is released.** An error always means the
   port is already free, which removes the ~100 ms window in which the current code lies.
3. **Exactly one outcome.** The first of {result, `fail`, timeout, abort} wins; everything
   later is a no-op — no second settlement, no double close, no unhandled rejection.
4. **A pending `waitForResult()` is rejected when the scope ends**, so a `use` body that
   returns without awaiting leaves nothing dangling.
5. **`timeoutMs` is required.** Its absence is exactly what holds the port forever in the
   OIDC and SAML flows.
6. **The handle is dead after the scope ends** — calling it throws rather than silently
   operating on a closed socket.

### Usage

```ts
const code = await withBrowserCallbackServer<string>(
  { port, timeoutMs, signal },
  async (srv) => {
    const waiting = srv.waitForResult();          // Promise<string>: TResult comes from the factory call
    launchBrowser(buildAuthUrl(srv.redirectUri)).catch((e) => srv.fail(e));
    return await waiting;
  },
);
// reached only once the port is free — whatever the outcome
```

The type parameter belongs to the factory call, not to `waitForResult()`. Each flow in
`auth-providers` exports its own factory conforming to `CallbackServerFactory`:
`withBrowserCallbackServer`, `withOidcCallbackServer`, `withSamlCallbackServer`.

The browser launch is deliberately not awaited on the critical path: a launcher that hangs
must not delay the timeout or the release, and one that fails routes into `fail`, which is
just another way for the scope to end.

### Implementations

Three factories in `auth-providers`, one per existing flow, each keeping the payload type
it already produces:

| factory | `TResult` | replaces |
|---|---|---|
| `withBrowserCallbackServer` | `string` — the authorization code | the server inside `startBrowserAuth` |
| `withOidcCallbackServer` | `{ code: string; state?: string }` | the server inside `startOidcBrowserAuth` |
| `withSamlCallbackServer` | `string` — the `SAMLResponse` | the server inside `startSamlBrowserAuth` |

Each stays internal to the package for now — the seam exists so the code has one shape and
one release point, not because a consumer is expected to plug into it today. Exporting them
is part of moving reception to the consumer, which is issue #11 and out of scope here.

The contract is typed per flow rather than transport-only. A transport-only server that
knew nothing of OAuth would need a three-state predicate to distinguish "this is the
result", "this is an error" and "ignore this" — otherwise `?error=access_denied` degrades
into a timeout. That cost is not worth paying while no consumer writes its own
implementation; if one ever does, a transport-level interface can be introduced below this
one without breaking it.

### What changes in the provider

`AuthorizationCodeProvider` loses the `Promise.race` wrapper and its timer. The login
timeout travels into `ICallbackServerOptions.timeoutMs`, so there is one timer, owned by
the party that owns the socket.

Nothing else in the provider changes. `browser` and `redirectPort` keep their meaning and
their defaults; they now configure the default factory instead of a hardwired server.

## Public API

Unchanged. `AuthorizationCodeProviderConfig` keeps `browser?: string` and
`redirectPort?: number` with the existing default of 3001. No exported signature changes,
so both releases are minor:

- `@mcp-abap-adt/interfaces` — additive: one new file, exported from `src/index.ts`.
- `@mcp-abap-adt/auth-providers` — internal restructuring plus the dependency bump.

The dependency bump is from `^2.3.0` to the new interfaces release. Measured against
`11.3.0`: zero type errors (`tsc --noEmit`), and the test suite produces the same result as
on `2.3.0` — the same two pre-existing failures described above, no new ones.

## Testing

Assertions about a port must bind the socket. The current code logs `port ${PORT} freed` on
a path that never calls `close()`, so log output proves nothing.

For each factory:

- the port is bound while `use` runs, and free once the factory settles — for success,
  `fail`, timeout, abort, and a `use` body that throws;
- an abandoned login is released by the timeout rather than held (the OIDC and SAML
  regression);
- a `use` body that returns without awaiting `waitForResult()` leaves no pending promise;
- the handle throws after the scope ends;
- first-outcome-wins: a result followed by `fail` still yields the result.

For the provider:

- a login driven past `timeoutMs` leaves the port bindable at the moment the provider's
  promise rejects. With the `Promise.race` still in place this fails about half the time,
  which is why it is asserted rather than reasoned about.

The two `AuthorizationCodeProvider` tests that already fail in the full suite are expected
to go green once the timers stop competing and the sockets are released; if they do not,
that is a finding, not a flake to work around.

## Out of scope

- **Moving callback reception to the consumer.** Issue #11 records that the transport does
  not belong in an authorization library. This spec fixes the hangs and introduces the seam;
  it does not move the code between packages.
- **Ephemeral ports.** `port: 0` must work if passed, but nothing passes it here.
- **Making a code-less callback non-terminal.** Today such a request ends the login with an
  error; that behaviour is preserved. The defect being fixed is the leaked socket, not the
  termination. Letting a stray request be ignored instead is a cheap follow-up, deliberately
  not bundled.
