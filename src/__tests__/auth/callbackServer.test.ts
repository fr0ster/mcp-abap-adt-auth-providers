/**
 * Tests for the scoped callback server.
 *
 * Every assertion about a port binds the socket. The code being replaced logs
 * `port ${PORT} freed` on a path that never calls close(), so log output proves
 * nothing here.
 */

import http from 'node:http';
import net from 'node:net';
import { afterEach, describe, expect, it } from '@jest/globals';
import {
  runCallbackScope,
  withBrowserCallbackServer,
} from '../../auth/callbackServer';

const PORT = 7871;

function portIsFree(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.once('error', () => resolve(false));
    s.listen(port, () => s.close(() => resolve(true)));
  });
}

/**
 * One request, one fresh connection.
 *
 * `fetch` pools sockets per origin, and a scope that ends destroys whatever is
 * still attached — so the next test can be handed a dead socket from the pool
 * and fail with `other side closed`, which says nothing about the server. A
 * browser opens its own connection; so does this.
 */
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

const deliver = (query: string): Promise<unknown> =>
  httpGet(`/callback${query}`).catch(() => undefined);

// Runs after every test, so any path that leaks fails the suite without
// needing a case of its own.
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
  }, 30000);

  // The scope may return something other than the payload.
  it('resolves with whatever the body returned', async () => {
    const token = await withBrowserCallbackServer(
      { port: PORT, timeoutMs: 5000 },
      async (srv) => {
        const waiting = srv.waitForResult();
        void deliver('?code=raw');
        return { value: await waiting };
      },
    );
    expect(token).toEqual({ value: 'raw' });
  }, 30000);

  // The OIDC/SAML regression: an abandoned login must not hold the port.
  it('releases the port when the login is abandoned', async () => {
    await expect(
      withBrowserCallbackServer(
        { port: PORT, timeoutMs: 300 },
        async (srv) => await srv.waitForResult(),
      ),
    ).rejects.toThrow(/timeout/i);
  }, 30000);

  // An arbitrary body cannot be cancelled, so the timeout must win anyway.
  it('releases the port when the body never settles', async () => {
    await expect(
      withBrowserCallbackServer(
        { port: PORT, timeoutMs: 300 },
        () => new Promise<string>(() => undefined),
      ),
    ).rejects.toThrow(/timeout/i);
  }, 30000);

  it('releases the port when cancelled', async () => {
    const ac = new AbortController();
    const scope = withBrowserCallbackServer(
      { port: PORT, timeoutMs: 30000, signal: ac.signal },
      async (srv) => await srv.waitForResult(),
    );
    setTimeout(() => ac.abort(), 100);
    await expect(scope).rejects.toThrow();
  }, 30000);

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
  }, 30000);

  it('releases the port when the body throws', async () => {
    await expect(
      withBrowserCallbackServer({ port: PORT, timeoutMs: 5000 }, async () => {
        throw new Error('boom');
      }),
    ).rejects.toThrow('boom');
  }, 30000);

  it('releases the port when fail() ends the wait', async () => {
    await expect(
      withBrowserCallbackServer(
        { port: PORT, timeoutMs: 5000 },
        async (srv) => {
          const waiting = srv.waitForResult();
          srv.fail(new Error('browser launch failed'));
          return await waiting;
        },
      ),
    ).rejects.toThrow('browser launch failed');
  }, 30000);

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
  }, 30000);

  // Rejecting the abandoned promise must not become the unhandled rejection
  // the contract exists to prevent.
  it('raises no unhandledRejection when the body abandons the wait', async () => {
    const seen: unknown[] = [];
    const onUnhandled = (reason: unknown): void => {
      seen.push(reason);
    };
    process.on('unhandledRejection', onUnhandled);
    try {
      const result = await withBrowserCallbackServer(
        { port: PORT, timeoutMs: 5000 },
        async (srv) => {
          void srv.waitForResult();
          return 'done';
        },
      );
      expect(result).toBe('done');
      await new Promise((r) => setTimeout(r, 100));
      expect(seen).toEqual([]);
    } finally {
      process.off('unhandledRejection', onUnhandled);
    }
  }, 30000);

  it('returns the same promise from repeated waitForResult calls', async () => {
    const code = await withBrowserCallbackServer(
      { port: PORT, timeoutMs: 5000 },
      async (srv) => {
        const a = srv.waitForResult();
        const b = srv.waitForResult();
        expect(a).toBe(b);
        void deliver('?code=shared');
        return await a;
      },
    );
    expect(code).toBe('shared');
  }, 30000);

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
    expect(() => escaped.fail(new Error('late'))).not.toThrow();
    await expect(escaped.waitForResult()).rejects.toThrow();
    expect(escaped.port).toBe(PORT);
    expect(escaped.redirectUri).toContain(String(PORT));
  }, 30000);

  it('survives a launcher that rejects after the timeout', async () => {
    let reportLate: ((e: Error) => void) | undefined;
    const launcher = new Promise<void>((_resolve, reject) => {
      reportLate = (e): void => reject(e);
    });
    await expect(
      withBrowserCallbackServer({ port: PORT, timeoutMs: 300 }, async (srv) => {
        launcher.catch((e: Error) => srv.fail(e));
        return await srv.waitForResult();
      }),
    ).rejects.toThrow(/timeout/i);
    reportLate?.(new Error('launcher died late'));
    await new Promise((r) => setTimeout(r, 100));
  }, 30000);

  // A delivered callback is not itself terminal, so fail() still wins if it
  // lands before the body returns.
  it('lets a fail before the body returns beat a delivered callback', async () => {
    await expect(
      withBrowserCallbackServer(
        { port: PORT, timeoutMs: 5000 },
        async (srv) => {
          const waiting = srv.waitForResult();
          void deliver('?code=first');
          const value = await waiting;
          srv.fail(new Error('too late for the payload'));
          await new Promise((r) => setTimeout(r, 50));
          return value;
        },
      ),
    ).rejects.toThrow('too late for the payload');
  }, 30000);

  it('ignores an incomplete callback and times out', async () => {
    await expect(
      withBrowserCallbackServer(
        { port: PORT, timeoutMs: 1500 },
        async (srv) => {
          const waiting = srv.waitForResult();
          void deliver('');
          return await waiting;
        },
      ),
    ).rejects.toThrow(/incomplete request\(s\)/);
  }, 30000);

  it('reports an OAuth error immediately rather than timing out', async () => {
    const started = Date.now();
    await expect(
      withBrowserCallbackServer(
        { port: PORT, timeoutMs: 30000 },
        async (srv) => {
          const waiting = srv.waitForResult();
          void deliver(
            '?error=access_denied&error_description=User%20said%20no',
          );
          return await waiting;
        },
      ),
    ).rejects.toThrow(/access_denied/);
    expect(Date.now() - started).toBeLessThan(5000);
  }, 30000);

  // The success page must survive shutdown: settle only once the response has
  // flushed, and do not destroy active connections in the first step.
  it('delivers the success page in full before releasing the port', async () => {
    const body = await withBrowserCallbackServer(
      { port: PORT, timeoutMs: 5000 },
      async (srv) => {
        const waiting = srv.waitForResult();
        const { status, body } = await httpGet('/callback?code=flushed');
        expect(status).toBe(200);
        await waiting;
        return body;
      },
    );
    expect(body).toContain('<');
    expect(body.length).toBeGreaterThan(0);
  }, 30000);

  it('releases the port with an idle keep-alive client attached', async () => {
    const agent = new http.Agent({ keepAlive: true });
    try {
      await expect(
        withBrowserCallbackServer(
          { port: PORT, timeoutMs: 1000 },
          async (srv) => {
            await new Promise<void>((ready) => {
              http.get(
                { host: '127.0.0.1', port: PORT, path: '/', agent },
                (r) => {
                  r.resume();
                  r.on('end', () => ready());
                },
              );
            });
            return await srv.waitForResult();
          },
        ),
      ).rejects.toThrow(/timeout/i);
    } finally {
      agent.destroy();
    }
  }, 30000);

  it('rejects a port that is not an integer in 0..65535, without binding', async () => {
    for (const bad of [-1, 65536, 3001.5]) {
      await expect(
        withBrowserCallbackServer(
          { port: bad, timeoutMs: 5000 },
          async () => 'unreachable',
        ),
      ).rejects.toThrow();
    }
  }, 30000);

  it('rejects a timeoutMs outside 0 < t <= 2_147_483_647', async () => {
    for (const bad of [
      0,
      -1,
      Number.NaN,
      Number.POSITIVE_INFINITY,
      2_147_483_648,
    ]) {
      await expect(
        withBrowserCallbackServer(
          { port: PORT, timeoutMs: bad },
          async () => 'unreachable',
        ),
      ).rejects.toThrow();
    }
  }, 30000);

  it('rejects a pre-aborted signal without binding and without running the body', async () => {
    const ac = new AbortController();
    ac.abort();
    let ran = false;
    await expect(
      withBrowserCallbackServer(
        { port: PORT, timeoutMs: 5000, signal: ac.signal },
        async () => {
          ran = true;
          return 'unreachable';
        },
      ),
    ).rejects.toThrow();
    expect(ran).toBe(false);
  }, 30000);

  it('fails cleanly when the port is already held', async () => {
    const squatter = net.createServer();
    await new Promise<void>((r) => {
      squatter.listen(PORT, () => r());
    });
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
      await new Promise<void>((r) => {
        squatter.close(() => r());
      });
    }
  }, 30000);

  /**
   * The guarantee is "settle only once the response has flushed", and the
   * existing tests cannot see it break: they read the whole body inside the
   * body of the scope, so the response is long gone before the scope ends.
   *
   * This one uses a payload too large for the socket buffer and a client that
   * does not read until later, which is the only state in which `writableEnded`
   * and `writableFinished` disagree. With the check keyed off `writableEnded`
   * the scope settles while the body is still going out.
   */
  it('does not settle until a large response has actually flushed', async () => {
    const BIG_PORT = 7876;
    const size = 20_000_000;
    let finishedAt = 0;
    let settledAt = 0;

    const scope = runCallbackScope<string, string>(
      { port: BIG_PORT, timeoutMs: 10000 },
      (app, settle) => {
        app.get('/big', (_req, res) => {
          // Subscribed before end(), so the timestamp cannot be missed.
          res.once('finish', () => {
            finishedAt = Date.now();
          });
          res.writeHead(200, { 'Content-Type': 'text/plain' });
          res.end('x'.repeat(size));
          settle.ok('delivered', res);
        });
      },
      async (server) => await server.waitForResult(),
    );

    // Stamp the settlement the moment it happens, not after the read. Recording
    // it afterwards would date an early settle later than the response finished
    // and let the assertion pass against the defect it exists for.
    const settled = scope.then((value) => {
      settledAt = Date.now();
      return value;
    });

    // Resolves with however many bytes arrived, including none: a destroyed
    // connection must produce a failed assertion, not a hung test.
    const received = await new Promise<number>((resolve) => {
      const req = http.get(
        { host: '127.0.0.1', port: BIG_PORT, path: '/big', agent: false },
        (res) => {
          let bytes = 0;
          res.pause();
          setTimeout(() => {
            res.resume();
            res.on('data', (chunk: Buffer) => {
              bytes += chunk.length;
            });
            res.on('end', () => resolve(bytes));
            res.on('close', () => resolve(bytes));
            res.on('error', () => resolve(bytes));
          }, 300);
        },
      );
      req.on('error', () => resolve(0));
    });

    const value = await settled;

    expect(value).toBe('delivered');
    expect(received).toBe(size);
    expect(finishedAt).toBeGreaterThan(0);
    // The scope must not have settled before the response finished writing.
    expect(settledAt).toBeGreaterThanOrEqual(finishedAt);
  }, 60000);

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
});
