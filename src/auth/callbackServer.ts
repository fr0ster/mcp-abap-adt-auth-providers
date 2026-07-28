/**
 * Scoped callback servers for interactive authorization flows.
 *
 * One owner, one release point. The socket belongs to the scope, not to the
 * promise a caller happens to be awaiting: it is released on the first terminal
 * outcome — the body returning or throwing, an explicit failure, the timeout, or
 * an abort — and the factory settles only once it is actually free.
 *
 * See `docs/superpowers/specs/2026-07-28-callback-server-contract-design.md`.
 */

import * as http from 'node:http';
import type { Socket } from 'node:net';
import type {
  CallbackServerFactory,
  ICallbackServerHandle,
  ICallbackServerOptions,
} from '@mcp-abap-adt/interfaces';
import express from 'express';
import { extractCode } from './browserAuth';

/** Node's `setTimeout` takes a 32-bit signed delay; above this it fires in 1 ms. */
const MAX_TIMEOUT_MS = 2_147_483_647;

/** How long shutdown waits for `close` before destroying what is left. */
const SHUTDOWN_GRACE_MS = 500;

/**
 * How a route reports an outcome. Settling is deferred until the response has
 * actually flushed — `res.send()` returning does not mean the bytes have left,
 * and settling earlier races the shutdown against the page being delivered.
 */
export interface Settle<TResult> {
  /** The callback delivered a result. Does not end the scope by itself. */
  ok(value: TResult, res?: express.Response): void;
  /** The callback reported a failure. Ends the scope. */
  err(error: Error, res?: express.Response): void;
}

export type RouteSetup<TResult> = (
  app: express.Express,
  settle: Settle<TResult>,
) => void;

function validate(options: ICallbackServerOptions): void {
  const { port, timeoutMs } = options;
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(
      `Invalid callback server port: ${String(port)}. Must be an integer in 1..65535.`,
    );
  }
  if (
    !Number.isFinite(timeoutMs) ||
    timeoutMs <= 0 ||
    timeoutMs > MAX_TIMEOUT_MS
  ) {
    throw new Error(
      `Invalid callback server timeoutMs: ${String(timeoutMs)}. ` +
        `Must be finite and within 1..${MAX_TIMEOUT_MS}.`,
    );
  }
}

/**
 * Owns the socket for the duration of `use`.
 *
 * Every flow registers its routes through `routes` and reports outcomes through
 * `settle`; nothing else touches the internal promise, which is what keeps the
 * "settles exactly once" guarantee in one place.
 */
export async function runCallbackScope<TResult, TReturn>(
  options: ICallbackServerOptions,
  routes: RouteSetup<TResult>,
  use: (server: ICallbackServerHandle<TResult>) => Promise<TReturn>,
): Promise<TReturn> {
  validate(options);
  if (options.signal?.aborted) {
    throw new Error('Callback server aborted before it started');
  }

  const app = express();
  const server = http.createServer(app);
  const sockets = new Set<Socket>();
  server.on('connection', (socket: Socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });

  let resultSettled = false;
  let resolveResult!: (value: TResult) => void;
  let rejectResult!: (error: Error) => void;
  const resultPromise = new Promise<TResult>((res, rej) => {
    resolveResult = res;
    rejectResult = rej;
  });
  // Marked handled at creation: a body may create this promise and walk away,
  // and rejecting it at scope end would otherwise raise unhandledRejection.
  void resultPromise.catch(() => undefined);

  let scopeSettled = false;
  let resolveScope!: (value: TReturn) => void;
  let rejectScope!: (error: Error) => void;
  const scopePromise = new Promise<TReturn>((res, rej) => {
    resolveScope = res;
    rejectScope = rej;
  });

  let timer: NodeJS.Timeout | null = null;
  let alive = false;

  const settleResult = (
    outcome: { value: TResult } | { error: Error },
  ): void => {
    if (resultSettled) return;
    resultSettled = true;
    if ('value' in outcome) resolveResult(outcome.value);
    else rejectResult(outcome.error);
  };

  /** The one place a scope ends. Everything after the first call is a no-op. */
  const endScope = (outcome: { value: TReturn } | { error: Error }): void => {
    if (scopeSettled) return;
    scopeSettled = true;
    alive = false;
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }
    options.signal?.removeEventListener('abort', onAbort);
    settleResult({
      error: new Error('Callback server closed before a result arrived'),
    });
    void shutdown().then(() => {
      if ('value' in outcome) resolveScope(outcome.value);
      else rejectScope(outcome.error);
    });
  };

  function onAbort(): void {
    endScope({ error: new Error('Callback server aborted') });
  }

  /**
   * Stop accepting, end idle connections, wait for `close` under a grace, then
   * destroy whatever is left. `closeAllConnections()` is deliberately not used
   * in the first step: it destroys active connections too, and the one carrying
   * the success page is active.
   */
  function shutdown(): Promise<void> {
    return new Promise((done) => {
      let finished = false;
      const finish = (): void => {
        if (finished) return;
        finished = true;
        done();
      };
      // `close()` alone, first. From Node 19 it ends idle connections itself,
      // and it does so gracefully — the client still reads what was written.
      // `closeIdleConnections()` destroys instead, which cuts the success page
      // off mid-read: `finish` on the response means "handed to the OS", not
      // "read by the client".
      server.close(() => finish());
      setTimeout(() => {
        if (finished) return;
        // Grace expired — on Node 18.x `close()` does not end idle connections,
        // and an active one may simply be stuck. Force it, bounded.
        server.closeIdleConnections?.();
        server.closeAllConnections?.();
        for (const socket of sockets) socket.destroy();
        finish();
      }, SHUTDOWN_GRACE_MS).unref?.();
    });
  }

  /**
   * Settle only once the response has actually flushed, so shutdown cannot cut
   * it off.
   *
   * The check is `writableFinished`, not `writableEnded`: the latter is true as
   * soon as `end()` has been called and says nothing about the data having
   * left. Measured on Node 25 with a paused client — an 800-byte body reports
   * both flags true at once, but a 20 MB body reports `writableEnded` true and
   * `writableFinished` false, with `finish` arriving 456 ms later. Keying off
   * `writableEnded` therefore made this deferral a no-op on the very path it
   * exists for.
   */
  const afterFlush = (
    res: express.Response | undefined,
    then: () => void,
  ): void => {
    if (!res || res.writableFinished) {
      then();
      return;
    }
    res.once('finish', then);
    res.once('close', then);
  };

  const settle: Settle<TResult> = {
    ok(value, res) {
      afterFlush(res, () => settleResult({ value }));
    },
    err(error, res) {
      afterFlush(res, () => {
        settleResult({ error });
        endScope({ error });
      });
    },
  };

  routes(app, settle);

  options.signal?.addEventListener('abort', onAbort, { once: true });

  const handle: ICallbackServerHandle<TResult> = {
    port: options.port,
    redirectUri: `http://localhost:${options.port}/callback`,
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

  server.once('error', (error: Error) => {
    endScope({ error });
  });

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

    void use(handle).then(
      (value) => endScope({ value }),
      (error: Error) => endScope({ error }),
    );
  });

  return await scopePromise;
}

const successHtml = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SAP BTP Authentication</title>
<style>body{font-family:'Segoe UI',Tahoma,sans-serif;text-align:center;padding:50px 20px;background:linear-gradient(135deg,#0070f3,#00d4ff);color:#fff;min-height:100vh;display:flex;flex-direction:column;justify-content:center;align-items:center}.container{background:rgba(255,255,255,.1);border-radius:20px;padding:40px;max-width:500px}.success-icon{font-size:4rem;margin-bottom:20px;color:#4ade80}h1{font-weight:300}</style>
</head><body><div class="container"><div class="success-icon">✓</div>
<h1>Authentication Successful!</h1>
<p>You have successfully authenticated with SAP BTP. You can close this window.</p>
</div></body></html>`;

const errorHtml = (message: string): string => `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Authentication Error</title>
<style>body{font-family:'Segoe UI',Tahoma,sans-serif;text-align:center;padding:50px 20px;background:linear-gradient(135deg,#dc2626,#ef4444);color:#fff;min-height:100vh;display:flex;flex-direction:column;justify-content:center;align-items:center}.container{background:rgba(255,255,255,.1);border-radius:20px;padding:40px;max-width:500px}.error-icon{font-size:4rem;margin-bottom:20px;color:#fbbf24}h1{font-weight:300}</style>
</head><body><div class="container"><div class="error-icon">✗</div>
<h1>Authentication Failed</h1>
<p>${message}</p>
<p>Please check your service key configuration and try again.</p>
</div></body></html>`;

// Manual paste form (GET /). Used when the automatic localhost callback cannot
// reach this server (browser on another machine). Accepts a bare code or a full
// redirected URL; re-renders with a message on a bad paste.
const pasteFormHtml = (message?: string): string => `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SAP BTP Authentication — paste code</title>
<style>body{font-family:'Segoe UI',Tahoma,sans-serif;text-align:center;padding:50px 20px;background:linear-gradient(135deg,#0070f3,#00d4ff);color:#fff;min-height:100vh;display:flex;flex-direction:column;justify-content:center;align-items:center}.container{background:rgba(255,255,255,.1);border-radius:20px;padding:40px;max-width:560px;width:100%}h1{font-weight:300}input{width:100%;padding:12px;border-radius:8px;border:none;font-size:1rem;box-sizing:border-box;margin:14px 0}button{padding:12px 24px;border-radius:8px;border:none;background:#fff;color:#0070f3;font-size:1rem;cursor:pointer}.msg{color:#fde68a;margin-bottom:10px}</style>
</head><body><div class="container">
<h1>Paste authorization code</h1>
${message ? `<p class="msg">${message}</p>` : ''}
<p>After signing in, copy the <code>code</code> from your browser's address bar
(or paste the whole redirected URL) and submit it here.</p>
<form action="/submit" method="get">
<input name="input" autofocus placeholder="code=... or http://localhost/callback?code=..." />
<button type="submit">Submit</button>
</form></div></body></html>`;

/**
 * Callback server for the UAA authorization-code flow.
 *
 * Delivers the authorization code. The paste form and `/submit` are kept for
 * the case where the browser runs on another machine.
 */
export const withBrowserCallbackServer: CallbackServerFactory<string> = (
  options,
  use,
) =>
  runCallbackScope<
    string,
    ReturnType<typeof use> extends Promise<infer R> ? R : never
  >(
    options,
    (app, settle) => {
      app.get('/callback', (req: express.Request, res: express.Response) => {
        const { error, error_description, error_uri } = req.query;
        if (error) {
          const message = error_description
            ? `${String(error)}: ${String(error_description)}`
            : String(error);
          res.status(400).send(errorHtml(message));
          settle.err(
            new Error(
              `OAuth2 authentication failed: ${message}` +
                (error_uri ? ` (${String(error_uri)})` : ''),
            ),
            res,
          );
          return;
        }

        const { code } = req.query;
        if (!code || typeof code !== 'string') {
          res.status(400).send('Error: Authorization code missing');
          settle.err(new Error('Authorization code missing'), res);
          return;
        }

        res.send(successHtml);
        settle.ok(code, res);
      });

      app.get('/', (_req: express.Request, res: express.Response) => {
        res.send(pasteFormHtml());
      });

      app.get('/submit', (req: express.Request, res: express.Response) => {
        const raw = req.query.input ?? req.query.code;
        const code = typeof raw === 'string' ? extractCode(raw) : null;
        if (!code) {
          res
            .status(400)
            .send(
              pasteFormHtml(
                'Could not read an authorization code from that input. Try again.',
              ),
            );
          return;
        }
        res.send(successHtml);
        settle.ok(code, res);
      });
    },
    use,
  );
