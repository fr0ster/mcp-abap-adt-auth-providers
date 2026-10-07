/**
 * Tests for the scoped callback server.
 *
 * Every assertion about a port binds the socket. The code being replaced logs
 * `port ${PORT} freed` on a path that never calls close(), so log output proves
 * nothing here.
 */

import http from 'node:http';
import net from 'node:net';
import { afterEach, describe, expect, it, jest } from '@jest/globals';
import { readFailure } from '@mcp-abap-adt/auth-errors';
import {
  runCallbackScope,
  withBrowserCallbackServer,
} from '../../auth/callbackServer';
import { formTokenIn } from '../helpers/callbackHttp';

const PORT = 7871;

/** An abort the test fires once the scope is waiting. */
function abortSoon(): AbortController {
  const ac = new AbortController();
  setTimeout(() => ac.abort(), 100);
  return ac;
}

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
      { port: PORT },
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
      { port: PORT },
      async (srv) => {
        const waiting = srv.waitForResult();
        void deliver('?code=raw');
        return { value: await waiting };
      },
    );
    expect(token).toEqual({ value: 'raw' });
  }, 30000);

  // The OIDC/SAML regression: an abandoned login must not hold the port.
  // K4 / §6a (6.0.0): no timer ends it — the consumer's abort does.
  it('releases the port when the login is abandoned', async () => {
    await expect(
      withBrowserCallbackServer(
        { port: PORT, signal: abortSoon().signal },
        async (srv) => await srv.waitForResult(),
      ),
    ).rejects.toThrow('the browser login was aborted');
  }, 30000);

  // An arbitrary body cannot be cancelled, so the abort must win anyway.
  it('releases the port when the body never settles', async () => {
    await expect(
      withBrowserCallbackServer(
        { port: PORT, signal: abortSoon().signal },
        () => new Promise<string>(() => undefined),
      ),
    ).rejects.toThrow('the browser login was aborted');
  }, 30000);

  it('releases the port when cancelled', async () => {
    const ac = new AbortController();
    const scope = withBrowserCallbackServer(
      { port: PORT, signal: ac.signal },
      async (srv) => await srv.waitForResult(),
    );
    setTimeout(() => ac.abort(), 100);
    await expect(scope).rejects.toThrow('the browser login was aborted');
  }, 30000);

  it('honours an abort that arrives during the bind', async () => {
    const ac = new AbortController();
    let ran = false;
    const scope = withBrowserCallbackServer(
      { port: PORT, signal: ac.signal },
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
      withBrowserCallbackServer({ port: PORT }, async () => {
        throw new Error('boom');
      }),
    ).rejects.toThrow('boom');
  }, 30000);

  it('releases the port when fail() ends the wait', async () => {
    await expect(
      withBrowserCallbackServer({ port: PORT }, async (srv) => {
        const waiting = srv.waitForResult();
        srv.fail(new Error('browser launch failed'));
        return await waiting;
      }),
    ).rejects.toThrow('browser launch failed');
  }, 30000);

  it('rejects a pending wait when the scope ends', async () => {
    let dangling: Promise<string> | undefined;
    await withBrowserCallbackServer({ port: PORT }, async (srv) => {
      dangling = srv.waitForResult();
      return 'returned without awaiting';
    });
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
        { port: PORT },
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
      { port: PORT },
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
    await withBrowserCallbackServer({ port: PORT }, async (srv) => {
      escaped = srv;
      return 'done';
    });
    expect(() => escaped.fail(new Error('late'))).not.toThrow();
    await expect(escaped.waitForResult()).rejects.toThrow();
    expect(escaped.port).toBe(PORT);
    expect(escaped.redirectUri).toContain(String(PORT));
  }, 30000);

  it('survives a launcher that rejects after the abort', async () => {
    let reportLate: ((e: Error) => void) | undefined;
    const launcher = new Promise<void>((_resolve, reject) => {
      reportLate = (e): void => reject(e);
    });
    await expect(
      withBrowserCallbackServer(
        { port: PORT, signal: abortSoon().signal },
        async (srv) => {
          launcher.catch((e: Error) => srv.fail(e));
          return await srv.waitForResult();
        },
      ),
    ).rejects.toThrow('the browser login was aborted');
    reportLate?.(new Error('launcher died late'));
    await new Promise((r) => setTimeout(r, 100));
  }, 30000);

  // A delivered callback is not itself terminal, so fail() still wins if it
  // lands before the body returns.
  it('lets a fail before the body returns beat a delivered callback', async () => {
    await expect(
      withBrowserCallbackServer({ port: PORT }, async (srv) => {
        const waiting = srv.waitForResult();
        void deliver('?code=first');
        const value = await waiting;
        srv.fail(new Error('too late for the payload'));
        await new Promise((r) => setTimeout(r, 50));
        return value;
      }),
    ).rejects.toThrow('too late for the payload');
  }, 30000);

  // K4 (6.0.0): the ignored request is counted in the abort's words.
  it('ignores an incomplete callback, and the abort reports it', async () => {
    const ac = new AbortController();
    await expect(
      withBrowserCallbackServer(
        { port: PORT, signal: ac.signal },
        async (srv) => {
          const waiting = srv.waitForResult();
          await deliver('');
          ac.abort();
          return await waiting;
        },
      ),
    ).rejects.toThrow(
      'the browser login was aborted; 1 request(s) to the callback server were refused and ignored',
    );
  }, 30000);

  it('reports an OAuth error immediately, without waiting for an abort', async () => {
    const started = Date.now();
    await expect(
      withBrowserCallbackServer({ port: PORT }, async (srv) => {
        const waiting = srv.waitForResult();
        void deliver('?error=access_denied&error_description=User%20said%20no');
        return await waiting;
      }),
    ).rejects.toThrow(/access_denied/);
    expect(Date.now() - started).toBeLessThan(5000);
  }, 30000);

  // The success page must survive shutdown: settle only once the response has
  // flushed, and do not destroy active connections in the first step.
  it('delivers the success page in full before releasing the port', async () => {
    const body = await withBrowserCallbackServer(
      { port: PORT },
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
          { port: PORT, signal: abortSoon().signal },
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
      ).rejects.toThrow('the browser login was aborted');
    } finally {
      agent.destroy();
    }
  }, 30000);

  it('rejects a port that is not an integer in 0..65535, without binding', async () => {
    for (const bad of [-1, 65536, 3001.5]) {
      await expect(
        withBrowserCallbackServer({ port: bad }, async () => 'unreachable'),
      ).rejects.toThrow();
    }
  }, 30000);

  it('rejects a pre-aborted signal without binding and without running the body', async () => {
    const ac = new AbortController();
    ac.abort();
    let ran = false;
    await expect(
      withBrowserCallbackServer({ port: PORT, signal: ac.signal }, async () => {
        ran = true;
        return 'unreachable';
      }),
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
      const thrown = await withBrowserCallbackServer(
        { port: PORT },
        async () => {
          ran = true;
          return 'unreachable';
        },
      ).then(
        () => undefined,
        (error: unknown) => error,
      );
      // K1 (Task 23 fix round 1): the scope's own EADDRINUSE is port-in-use
      // with the port, in K1's words.
      expect(readFailure(thrown, 'browser-login')).toMatchObject({
        kind: 'interactive-login',
        facts: { outcome: 'port-in-use', port: PORT },
        reason: `Port ${PORT} is already in use. Please specify a different port or free the port.`,
      });
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
      { port: BIG_PORT },
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
      const code = await withBrowserCallbackServer({ port: 0 }, async (srv) => {
        observed = srv.port;
        expect(observed).toBeGreaterThan(0);
        expect(srv.redirectUri).toBe(`http://localhost:${observed}/callback`);
        expect(await portIsFree(observed)).toBe(false);
        const waiting = srv.waitForResult();
        void httpGetOn(observed, '/callback?code=eph').catch(() => undefined);
        return await waiting;
      });
      expect(code).toBe('eph');
      expect(await portIsFree(observed)).toBe(true);
    }, 30000);
  });

  describe('incomplete callbacks', () => {
    it('answers 400 and keeps waiting when neither code nor error arrived', async () => {
      const code = await withBrowserCallbackServer(
        { port: PORT },
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

    // K4 (6.0.0): the tally moved from the timeout's words to the abort's.
    it('counts ignored requests in the aborted words', async () => {
      const ac = new AbortController();
      const attempt = withBrowserCallbackServer(
        { port: PORT, signal: ac.signal },
        async (srv) => await srv.waitForResult(),
      );
      const rejected = expect(attempt).rejects.toThrow(
        'the browser login was aborted; 2 request(s) to the callback server were refused and ignored',
      );
      await httpGet('/callback');
      await httpGet('/callback');
      ac.abort();
      await rejected;
    }, 30000);

    it('still ends the login at once on an explicit IdP error', async () => {
      const attempt = withBrowserCallbackServer(
        { port: PORT },
        async (srv) => await srv.waitForResult(),
      );
      void deliver('?error=access_denied&error_description=User%20said%20no');
      // The registered code only; the description is anyone's text.
      await expect(attempt).rejects.toThrow(
        'the identity provider refused the login (access_denied)',
      );
    }, 30000);
  });

  /**
   * The way in when the browser is on another machine. These assertions used to
   * reach the routes through `startBrowserAuth`, which no longer exists; the
   * routes belong to this transport, so they are pinned here.
   */
  describe('paste form', () => {
    it('serves a form at GET /', async () => {
      const code = await withBrowserCallbackServer(
        { port: PORT },
        async (srv) => {
          const waiting = srv.waitForResult();
          const { status, body } = await httpGet('/');
          expect(status).toBe(200);
          expect(body).toContain('<form');
          expect(body).toContain('/submit');
          void deliver('?code=after-form');
          return await waiting;
        },
      );
      expect(code).toBe('after-form');
    }, 30000);

    it('completes the login from a full redirected URL pasted at /submit', async () => {
      const code = await withBrowserCallbackServer(
        { port: PORT },
        async (srv) => {
          const waiting = srv.waitForResult();
          // The served form's token binds the paste to this login (§6a1).
          const token = formTokenIn((await httpGet('/')).body);
          void httpGet(
            `/submit?input=${encodeURIComponent(
              `http://localhost:${PORT}/callback?code=pasted-code`,
            )}&form_token=${token}`,
          ).catch(() => undefined);
          return await waiting;
        },
      );
      expect(code).toBe('pasted-code');
    }, 30000);

    // K16 (Task 23 fix round 1): a malformed escape is an unreadable paste —
    // the form again, never a thrown URIError or Express's error page.
    it('re-renders the form on a paste with a malformed escape (code=%ZZ)', async () => {
      const code = await withBrowserCallbackServer(
        { port: PORT },
        async (srv) => {
          const waiting = srv.waitForResult();
          const token = formTokenIn((await httpGet('/')).body);
          for (const input of [
            'code=%ZZ',
            'http://localhost/callback?code=%E0%A4%A',
          ]) {
            const { status, body } = await httpGet(
              `/submit?input=${encodeURIComponent(input)}&form_token=${token}`,
            );
            expect(status).toBe(400);
            expect(body).toContain('<form');
            expect(body).not.toContain('URIError');
            expect(body).not.toContain(process.cwd());
          }
          void deliver('?code=after-malformed');
          return await waiting;
        },
      );
      expect(code).toBe('after-malformed');
    }, 30000);

    it('re-renders the form (HTTP 400) on an unusable paste, without ending the login', async () => {
      const code = await withBrowserCallbackServer(
        { port: PORT },
        async (srv) => {
          const waiting = srv.waitForResult();
          const token = formTokenIn((await httpGet('/')).body);
          const { status, body } = await httpGet(
            `/submit?input=${encodeURIComponent('not a code')}&form_token=${token}`,
          );
          expect(status).toBe(400);
          expect(body).toContain('<form');
          // Still pending — a real code afterwards still lands.
          void deliver('?code=after-bad-paste');
          return await waiting;
        },
      );
      expect(code).toBe('after-bad-paste');
    }, 30000);
  });

  /**
   * No answer of the scope comes from Express's defaults (Task 23 fix
   * round 1): its error handler renders and prints the stack — absolute
   * paths and the thrown text. A route that throws gets a fixed page and
   * nothing is written anywhere; an unknown path gets fixed text.
   */
  describe("every answer is the scope's own", () => {
    it('a route that throws: a fixed 500 page, nothing of the error, nothing printed', async () => {
      const SECRET = 'REVIEW_TEST_ROUTE_SECRET_5e1';
      const printed = jest
        .spyOn(console, 'error')
        .mockImplementation(() => undefined);
      const written = jest
        .spyOn(process.stderr, 'write')
        .mockImplementation(() => true);
      try {
        const reply = await runCallbackScope<
          string,
          { status: number; body: string }
        >(
          { port: PORT },
          (app) => {
            app.get('/boom', () => {
              throw new Error(`${SECRET} at ${process.cwd()}/x.ts`);
            });
          },
          async () => await httpGet('/boom'),
        );
        expect(reply.status).toBe(500);
        expect(reply.body).toContain('The callback could not be handled.');
        expect(reply.body).not.toContain(SECRET);
        expect(reply.body).not.toContain(process.cwd());
        expect(printed).not.toHaveBeenCalled();
        expect(JSON.stringify(written.mock.calls)).not.toContain(SECRET);
      } finally {
        printed.mockRestore();
        written.mockRestore();
      }
    }, 30000);

    it('an unknown path: fixed text', async () => {
      const reply = await withBrowserCallbackServer(
        { port: PORT },
        async () => await httpGet('/nowhere/<b>'),
      );
      expect(reply).toEqual({ status: 404, body: 'Not found' });
    }, 30000);
  });
});
