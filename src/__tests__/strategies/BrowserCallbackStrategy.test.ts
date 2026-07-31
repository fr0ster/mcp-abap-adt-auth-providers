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
  IAuthorizationStrategy,
  ICallbackServerHandle,
} from '@mcp-abap-adt/interfaces';
import { withBrowserCallbackServer } from '../../auth/callbackServer';
import {
  BrowserCallbackStrategy,
  browserCallbackStrategy,
  oidcCallbackStrategy,
  samlCallbackStrategy,
} from '../../strategies/BrowserCallbackStrategy';

/** A factory that hands over a handle whose result the test controls. */
function fakeFactory<T = string>(opts: {
  boundPort?: number;
  /** What the callback "delivers". Defaults to a string code. */
  payload?: T;
  deliver?: (handle: ICallbackServerHandle<T>) => void;
}): { factory: CallbackServerFactory<T>; released: () => boolean } {
  let released = false;
  const factory: CallbackServerFactory<T> = async (options, use) => {
    // `options.port` of 0 is what the caller asked for; `boundPort` is what the
    // OS would have handed back.
    const port = opts.boundPort ?? (options.port || 61001);
    let settle!: (v: T) => void;
    let fail!: (e: Error) => void;
    const result = new Promise<T>((res, rej) => {
      settle = res;
      fail = rej;
    });
    void result.catch(() => undefined);
    const handle: ICallbackServerHandle<T> = {
      port,
      redirectUri: `http://localhost:${port}/callback`,
      waitForResult: () => result,
      fail: (e) => fail(e),
    };
    // An abort ends the scope without waiting for the body — an arbitrary async
    // function cannot be force-terminated, so the real `runCallbackScope`
    // abandons it. A fake that awaits `use` instead would hang any test whose
    // body never settles, which is exactly the dispose case below.
    const aborted = new Promise<never>((_, rej) => {
      options.signal?.addEventListener(
        'abort',
        () => {
          fail(new Error('Callback server aborted'));
          rej(new Error('Callback server aborted'));
        },
        { once: true },
      );
    });
    void aborted.catch(() => undefined);
    opts.deliver?.({ ...handle, fail: (e) => fail(e) });
    setTimeout(
      () => settle(opts.payload ?? ('code-from-fake' as unknown as T)),
      0,
    );
    try {
      return await Promise.race([use(handle), aborted]);
    } finally {
      released = true;
    }
  };
  return { factory, released: () => released };
}

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

  // Two windows, two tests. `dispose` can land before the transport is entered
  // or after, and the fix for the race between them is only meaningful if both
  // are pinned.
  it('disposes idempotently and aborts before the transport is entered', async () => {
    const { factory, released } = fakeFactory({});
    const strategy = new BrowserCallbackStrategy<string>({
      callbackServer: factory,
      port: 0,
      openUrl: async () => undefined,
    });

    const inFlight = strategy.authorize({
      buildAuthorizationUrl: async () => 'https://idp.example/a',
    });
    const settled = inFlight.catch((e: Error) => e.message);

    // Synchronous inside dispose, so it lands while `authorize` is still
    // awaiting the port probe. If `inFlight` were assigned after that await
    // rather than before it, this would resolve against nulls and the login
    // would go on to bind behind it.
    await strategy.dispose();
    await strategy.dispose(); // idempotent

    expect(await settled).toMatch(/abort/i);
    // Never entered: no socket was bound, so there was nothing to release.
    expect(released()).toBe(false);
  });

  it('ends an authorize already inside the transport', async () => {
    let entered!: () => void;
    const hasEntered = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const { factory, released } = fakeFactory({ deliver: () => entered() });
    const strategy = new BrowserCallbackStrategy<string>({
      callbackServer: factory,
      port: 0,
      openUrl: async () => undefined,
    });

    const inFlight = strategy.authorize({
      // Never settles, so the scope is still open when dispose lands.
      buildAuthorizationUrl: () => new Promise<string>(() => undefined),
    });
    const settled = inFlight.catch((e: Error) => e.message);
    await hasEntered;

    await strategy.dispose();

    expect(await settled).toMatch(/abort/i);
    // Entered and left: dispose resolves only once the transport has settled,
    // which it does after releasing.
    expect(released()).toBe(true);
  });

  it('announces the URI it actually bound, never port 0', async () => {
    const infos: string[] = [];
    const logger = {
      debug: () => undefined,
      info: (msg: string) => {
        infos.push(msg);
      },
      warn: () => undefined,
      error: () => undefined,
    };
    const { factory } = fakeFactory({ boundPort: 49997 });
    // No `openUrl`: this exercises the real launcher, which for 'none' prints
    // and returns without opening anything.
    const strategy = browserCallbackStrategy({
      port: 0,
      browser: 'none',
      callbackServer: factory,
    });

    await strategy.authorize({
      buildAuthorizationUrl: async () => 'https://idp.example/authorize',
      logger,
    });

    const text = infos.join('\n');
    expect(text).toContain('http://localhost:49997/callback');
    expect(text).not.toContain(':0/');
  });

  it('offers the paste form only when it supplied the transport that has one', async () => {
    // Real transports here, not fakes: the claim under test is whether a `/`
    // route exists, which a fake cannot answer either way. Each binds an
    // ephemeral port and waits; a short timeout is what ends it.
    const announcedBy = async (
      strategy: IAuthorizationStrategy<unknown>,
    ): Promise<string> => {
      const infos: string[] = [];
      const logger = {
        debug: () => undefined,
        info: (msg: string) => {
          infos.push(msg);
        },
        warn: () => undefined,
        error: () => undefined,
      };
      await expect(
        strategy.authorize({
          buildAuthorizationUrl: async () => 'https://idp.example/authorize',
          logger,
        }),
      ).rejects.toThrow(/timeout/i);
      return infos.join('\n');
    };

    const shared = { port: 0, browser: 'none', timeoutMs: 300 } as const;

    // Ours, and it really serves a paste form.
    expect(await announcedBy(browserCallbackStrategy({ ...shared }))).toMatch(
      /paste it at http:\/\/localhost:\d+\//,
    );

    // The same transport — but supplied by the caller. The rule is about who
    // supplied it, not what it is: once a receiver is injected, the package no
    // longer knows which routes it serves, and a consumer that does can say so
    // through `remoteHint`.
    expect(
      await announcedBy(
        browserCallbackStrategy({
          ...shared,
          callbackServer: withBrowserCallbackServer,
        }),
      ),
    ).not.toMatch(/paste it at/i);

    // An injected transport that does serve a form can still say so.
    expect(
      await announcedBy(
        browserCallbackStrategy({
          ...shared,
          callbackServer: withBrowserCallbackServer,
          remoteHint: () => '   paste it at http://elsewhere.example/',
        }),
      ),
    ).toContain('paste it at http://elsewhere.example/');

    // The OIDC and SAML transports have no `/` route at all, and the stdin
    // invitation is gone — that is `manualPasteStrategy`'s job now.
    for (const strategy of [
      oidcCallbackStrategy({ ...shared }),
      samlCallbackStrategy({ ...shared }),
    ]) {
      const text = await announcedBy(strategy);
      expect(text).not.toMatch(/paste it at/i);
      expect(text).not.toMatch(/press Enter/i);
      expect(text).toMatch(/Waiting for callback on http:\/\/localhost:\d+\//);
    }
  }, 30000);

  /**
   * Without a logger the prompt still has to reach a human — on stderr, never
   * stdout, which a stdio RPC transport uses for protocol traffic. Asserted
   * through `startBrowserAuth` before it was deleted.
   */
  it('announces on stderr when no logger is supplied', async () => {
    const writes: string[] = [];
    const spy = jest
      .spyOn(process.stderr, 'write')
      .mockImplementation((chunk: unknown) => {
        writes.push(String(chunk));
        return true;
      });
    const { factory } = fakeFactory({ boundPort: 49998 });
    const strategy = browserCallbackStrategy({
      port: 0,
      browser: 'none',
      callbackServer: factory,
    });

    try {
      await strategy.authorize({
        buildAuthorizationUrl: async () =>
          'https://idp.example/oauth/authorize?client_id=c',
      });
    } finally {
      spy.mockRestore();
    }

    const all = writes.join('');
    expect(all).toContain('Open this URL');
    expect(all).toContain('oauth/authorize');
    expect(all).toContain('http://localhost:49998/callback');
  });

  it('honours a signal that was already aborted', async () => {
    const { factory, released } = fakeFactory({});
    const strategy = new BrowserCallbackStrategy<string>({
      callbackServer: factory,
      port: 0,
      openUrl: async () => undefined,
      signal: AbortSignal.abort(),
    });

    await expect(
      strategy.authorize({
        buildAuthorizationUrl: async () => 'https://idp.example/a',
      }),
    ).rejects.toThrow(/abort/i);
    expect(released()).toBe(false);
  });
});
