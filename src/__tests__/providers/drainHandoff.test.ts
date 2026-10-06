/**
 * Drain handoff (spec §6b): an aborted attempt is non-joinable at once, but
 * not yet released — its strategy may still be closing its callback socket.
 * A replacement attempt waits for the release before it starts its own
 * authorization, raced only against its own signal. Here the callback
 * server's shutdown is held open by a test gate on a fixed port: without
 * the handoff the replacement would meet a strategy still authorizing
 * (`busy`) or a port still bound (`port-in-use`).
 */

import * as http from 'node:http';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { readFailure } from '@mcp-abap-adt/auth-errors';
import type {
  AuthorizationRequest,
  CallbackServerFactory,
  IAuthorizationStrategy,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { AuthorizationCodeProvider } from '../../providers/AuthorizationCodeProvider';
import { BrowserCallbackStrategy } from '../../strategies/BrowserCallbackStrategy';
import {
  Arrivals,
  type Deferred,
  deferred,
  jwt,
  quiet,
  rejectionOf,
  startTokenServer,
  type TokenServer,
} from '../helpers/attemptHarness';
import { getAvailablePort } from '../helpers/netHelpers';

const silent: ILogger = {
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
};
const refused = { at: 'request' as const, status: 401, error: {} };

function isAborted(error: unknown): boolean {
  const read = readFailure(error, 'unfamiliar-error');
  return (
    read.kind === 'interactive-login' &&
    (read.facts as { outcome?: string }).outcome === 'aborted'
  );
}

/** One scope of the held-shutdown callback server. */
interface Scope {
  /** Delivers the authorization code. */
  deliver(code: string): void;
  /** Releases the socket's close, held after the scope ended. */
  readonly gate: Deferred<void>;
  /** Resolves once the socket is closed. */
  readonly closed: Promise<void>;
}

/**
 * A callback server factory that binds `port` for real and, once its scope
 * ends, keeps the socket open until the test opens the scope's gate.
 */
function heldShutdown(scopes: Arrivals<Scope>): CallbackServerFactory<string> {
  return (async (options, use) => {
    const server = http.createServer((_req, res) => res.end('ok'));
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(options.port, '127.0.0.1', () => resolve());
    });
    const result = deferred<string>();
    const gate = deferred<void>();
    const closed = deferred<void>();
    const onAbort = () => result.reject(new Error('aborted'));
    options.signal?.addEventListener('abort', onAbort, { once: true });
    if (options.signal?.aborted) onAbort();
    scopes.push({
      deliver: (code) => result.resolve(code),
      gate,
      closed: closed.promise,
    });
    try {
      return await use({
        port: options.port,
        redirectUri: `http://localhost:${options.port}/callback`,
        waitForResult: () => result.promise,
        fail: (error) => result.reject(error),
      });
    } finally {
      options.signal?.removeEventListener('abort', onAbort);
      await gate.promise;
      await new Promise<void>((resolve) => server.close(() => resolve()));
      closed.resolve();
    }
  }) as CallbackServerFactory<string>;
}

let server: TokenServer;
beforeEach(async () => {
  let n = 0;
  server = await startTokenServer((request) => {
    n += 1;
    request.answer(200, {
      access_token: jwt(`login-${n}`),
      refresh_token: `R-${n}`,
    });
  });
});
afterEach(async () => {
  await server.close();
});

async function setup() {
  const port = await getAvailablePort();
  const scopes = new Arrivals<Scope>();
  const inner = new BrowserCallbackStrategy<string>({
    port,
    browser: 'none',
    openUrl: async () => undefined,
    callbackServer: heldShutdown(scopes),
  });
  const failures: unknown[] = [];
  let calls = 0;
  const strategy: IAuthorizationStrategy<string> = {
    async authorize(request: AuthorizationRequest) {
      calls += 1;
      try {
        return await inner.authorize(request);
      } catch (error) {
        failures.push(error);
        throw error;
      }
    },
  };
  const provider = new AuthorizationCodeProvider({
    uaaUrl: server.url,
    clientId: 'cid',
    clientSecret: 'sec',
    authorization: strategy,
    logger: silent,
  });
  return { port, scopes, provider, failures, calls: () => calls };
}

/** Every failure a strategy call ended with names the abort, never busy or a port in use. */
function noBusyNoPortInUse(failures: unknown[]): void {
  for (const failure of failures) {
    const message = String((failure as Error).message);
    expect(message).not.toContain('already authorizing');
    expect(message).not.toContain('already in use');
  }
}

describe('drain handoff', () => {
  it('all waiters abort, a new getTokens arrives at once: the strategy waits for the old authorize, then a fresh login succeeds', async () => {
    const { scopes, provider, failures, calls } = await setup();
    const a = new AbortController();
    const first = rejectionOf(provider.getTokens({ signal: a.signal }));
    const old = await scopes.nth(1);
    a.abort();
    expect(isAborted(await first)).toBe(true);

    const next = provider.getTokens();
    // The strategy must NOT be called again yet: no event exists for that.
    await quiet();
    expect(calls()).toBe(1);
    old.gate.resolve();
    const fresh = await scopes.nth(2);
    expect(calls()).toBe(2);
    fresh.deliver('code-2');
    fresh.gate.resolve();
    await expect(next).resolves.toMatchObject({ refreshToken: 'R-1' });
    expect(server.requests.map((r) => r.params.get('code'))).toEqual([
      'code-2',
    ]);
    noBusyNoPortInUse(failures);
  });

  it('the same for a new rejected()', async () => {
    const { scopes, provider, failures, calls } = await setup();
    const a = new AbortController();
    const first = rejectionOf(provider.getTokens({ signal: a.signal }));
    const old = await scopes.nth(1);
    a.abort();
    await first;

    const outcome = provider.rejected(refused);
    // The strategy must NOT be called again yet: no event exists for that.
    await quiet();
    expect(calls()).toBe(1);
    old.gate.resolve();
    const fresh = await scopes.nth(2);
    fresh.deliver('code-2');
    fresh.gate.resolve();
    await expect(outcome).resolves.toEqual({ ok: true });
    noBusyNoPortInUse(failures);
  });

  it("aborting the new attempt's only waiter while it waits ends it aborted, no authorization started", async () => {
    const { scopes, provider, calls } = await setup();
    const a = new AbortController();
    const first = rejectionOf(provider.getTokens({ signal: a.signal }));
    const old = await scopes.nth(1);
    a.abort();
    await first;

    const b = new AbortController();
    const waiting = rejectionOf(provider.getTokens({ signal: b.signal }));
    // Let the new attempt reach its drain wait: inside the provider, with no
    // event a test can await.
    await quiet();
    b.abort();
    expect(isAborted(await waiting)).toBe(true);
    old.gate.resolve();
    await old.closed;
    // The strategy must NOT be called again yet: no event exists for that.
    await quiet();
    expect(calls()).toBe(1);
    expect(scopes.items).toHaveLength(1);
  });

  it('three attempts aborted in a row: each waits on the whole chain', async () => {
    const { scopes, provider, failures, calls } = await setup();
    const a = new AbortController();
    const first = rejectionOf(provider.getTokens({ signal: a.signal }));
    const old = await scopes.nth(1);
    a.abort();
    await first;
    // Two more, each aborted while it waits for the drain before it.
    for (let i = 0; i < 2; i++) {
      const c = new AbortController();
      const waiting = rejectionOf(provider.getTokens({ signal: c.signal }));
      // Let the new attempt reach its drain wait: inside the provider, with no
      // event a test can await.
      await quiet();
      c.abort();
      expect(isAborted(await waiting)).toBe(true);
    }
    // The fourth waits on all three: the first one's socket still holds.
    const last = provider.getTokens();
    // The strategy must NOT be called again yet: no event exists for that.
    await quiet();
    expect(calls()).toBe(1);
    old.gate.resolve();
    const fresh = await scopes.nth(2);
    fresh.deliver('code-4');
    fresh.gate.resolve();
    await expect(last).resolves.toMatchObject({ refreshToken: 'R-1' });
    expect(calls()).toBe(2);
    noBusyNoPortInUse(failures);
  });
});
