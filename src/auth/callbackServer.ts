/**
 * Scoped callback servers for interactive authorization flows.
 *
 * One owner, one release point. The socket belongs to the scope, not to the
 * promise a caller happens to be awaiting: it is released on the first terminal
 * outcome — the body returning or throwing, an explicit failure, the identity
 * provider's refusal, or an abort — and the factory settles only once the
 * listening socket is closed, so the port is free.
 *
 * No timer of this package's choosing bounds a scope (spec §6a): a login ends
 * on its result, the identity provider's refusal or the consumer's
 * `AbortSignal`. The 4.x `ICallbackServerOptions` still declares a bound in
 * milliseconds as required; the scope reads no such field (Decision D6,
 * removed from the call sites in Task 27).
 */

import * as http from 'node:http';
import type { AddressInfo, Socket } from 'node:net';
import { authError } from '@mcp-abap-adt/auth-errors';
import type {
  CallbackServerFactory,
  ICallbackServerHandle,
  ICallbackServerOptions,
} from '@mcp-abap-adt/interfaces-auth';
import express from 'express';
import { extractCode } from './browserAuth';
import { misconfigured } from './configuration';
import {
  abortedLogin,
  failedLogin,
  identityProviderRefused,
  loginFailure,
  portInUse,
} from './interactiveLogin';
import { logQuietly } from './tokenRequest';

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
  /**
   * This was not our redirect — a reloaded tab, a prefetch, a port scanner.
   * Answered and counted; the login keeps waiting until a result, the
   * identity provider's refusal or an abort, whose words report the count.
   * Ends nothing.
   */
  ignore(reason: string, res?: express.Response): void;
}

export type RouteSetup<TResult> = (
  app: express.Express,
  settle: Settle<TResult>,
) => void;

/** K6: a port no socket can bind — the value given is not echoed (L5). */
function validatePort(port: unknown): void {
  if (
    typeof port !== 'number' ||
    !Number.isInteger(port) ||
    port < 0 ||
    port > 65535
  ) {
    throw misconfigured(
      authError.configuration({
        case: 'callback-port-invalid',
        fields: ['port'],
      }),
    );
  }
}

/** K8: the scope ended before a result arrived. */
const callbackClosed = () => loginFailure({ outcome: 'callback-closed' });

/**
 * The bind failed: a port someone else holds is K1, with its words; any
 * other failure names only its allowlisted code (K11).
 */
function bindFailure(error: unknown, port: number): Error {
  if (
    error !== null &&
    typeof error === 'object' &&
    'code' in error &&
    error.code === 'EADDRINUSE' &&
    port > 0
  ) {
    return portInUse(port);
  }
  return failedLogin(error);
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
  const { port, signal, logger } = options;
  validatePort(port);
  if (signal?.aborted) throw abortedLogin('browser');

  const app = express();
  // Every response: no sniffing, and a policy that runs no script, loads
  // nothing and submits only to this server (the paste form). Inline style
  // is the pages' only need.
  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', CALLBACK_CSP);
    next();
  });
  const server = http.createServer(app);
  /** Every open connection, and how many responses each is still writing. */
  const sockets = new Map<Socket, number>();
  let released = false;
  server.on('connection', (socket: Socket) => {
    sockets.set(socket, 0);
    socket.on('close', () => sockets.delete(socket));
  });
  server.on(
    'request',
    (req: http.IncomingMessage, res: http.ServerResponse) => {
      const socket = req.socket;
      sockets.set(socket, (sockets.get(socket) ?? 0) + 1);
      res.once('close', () => {
        const left = (sockets.get(socket) ?? 1) - 1;
        if (sockets.has(socket)) sockets.set(socket, left);
        if (released && left <= 0) letGo(socket);
      });
    },
  );

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

  let alive = false;
  let ignored = 0;

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
    signal?.removeEventListener('abort', onAbort);
    settleResult({ error: callbackClosed() });
    release();
    if ('value' in outcome) resolveScope(outcome.value);
    else rejectScope(outcome.error);
  };

  function onAbort(): void {
    endScope({ error: abortedLogin('browser', ignored) });
  }

  /**
   * A connection the scope no longer needs: ended gracefully — the client
   * still reads what was written, which `destroy()` would cut off — and
   * unreferenced, so a client that never closes its side holds neither the
   * port (the listener is closed) nor the process.
   */
  function letGo(socket: Socket): void {
    socket.end();
    socket.unref();
  }

  /**
   * Close the listening socket — the port is free once it returns (the
   * handle's descriptor is closed synchronously) — and let every connection
   * go: at once when it is writing nothing, after its last response
   * otherwise. Waits on no timer: a stuck client cannot hold the scope open,
   * because nothing here waits for a connection to end.
   */
  function release(): void {
    released = true;
    if (server.listening) server.close();
    for (const [socket, responding] of sockets) {
      if (responding <= 0) letGo(socket);
    }
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
    ignore(reason) {
      ignored += 1;
      logQuietly(() =>
        logger?.warn(
          '[callbackServer] ignored an incomplete callback request',
          {
            reason,
            ignored,
          },
        ),
      );
    },
  };

  routes(app, settle);
  // Every answer is one of this scope's own pages: an unknown path gets fixed
  // text, and a route that throws gets a fixed page — never Express's default
  // handler, which renders and prints the stack (absolute paths, the thrown
  // text). Nothing of the error is logged.
  app.use((_req: express.Request, res: express.Response) => {
    sendText(res, 404, 'Not found');
  });
  app.use(
    (
      _error: unknown,
      _req: express.Request,
      res: express.Response,
      _next: express.NextFunction,
    ) => {
      if (res.headersSent) {
        res.end();
        return;
      }
      sendHtml(res, 500, errorHtml('The callback could not be handled.'));
    },
  );

  signal?.addEventListener('abort', onAbort, { once: true });

  server.once('error', (error: Error) => {
    endScope({ error: bindFailure(error, port) });
  });

  server.listen(port, () => {
    // Aborted while binding: `release()` has closed the listener already.
    if (scopeSettled) return;
    alive = true;

    // The requested port may be 0, in which case only the OS knows the answer.
    const bound = (server.address() as AddressInfo).port;
    const handle: ICallbackServerHandle<TResult> = {
      port: bound,
      redirectUri: `http://localhost:${bound}/callback`,
      waitForResult: () =>
        alive ? resultPromise : Promise.reject(callbackClosed()),
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

  return await scopePromise;
}

const CALLBACK_CSP =
  "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

/** `&`, `<`, `>`, `"` and `'` as entities: a value in a page is text, never markup. */
export function escapeHtml(value: string): string {
  // Plain code, no regex: the value is callback text, anyone's.
  let escaped = '';
  for (const character of value) escaped += ENTITIES[character] ?? character;
  return escaped;
}

const ENTITIES: Readonly<Record<string, string>> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

/** An HTML page, said to be one, in UTF-8. */
export function sendHtml(
  res: express.Response,
  status: number,
  html: string,
): void {
  res
    .status(status)
    .setHeader('Content-Type', 'text/html; charset=utf-8')
    .send(html);
}

/** Plain text, said to be plain text, in UTF-8: never rendered as markup. */
export function sendText(
  res: express.Response,
  status: number,
  text: string,
): void {
  res
    .status(status)
    .setHeader('Content-Type', 'text/plain; charset=utf-8')
    .send(text);
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

/** `message` may be the IdP's (attacker-controllable) text: escaped here. */
export const errorHtml = (message: string): string => `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Authentication Error</title>
<style>body{font-family:'Segoe UI',Tahoma,sans-serif;text-align:center;padding:50px 20px;background:linear-gradient(135deg,#dc2626,#ef4444);color:#fff;min-height:100vh;display:flex;flex-direction:column;justify-content:center;align-items:center}.container{background:rgba(255,255,255,.1);border-radius:20px;padding:40px;max-width:500px}.error-icon{font-size:4rem;margin-bottom:20px;color:#fbbf24}h1{font-weight:300}</style>
</head><body><div class="container"><div class="error-icon">✗</div>
<h1>Authentication Failed</h1>
<p>${escapeHtml(message)}</p>
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
${message ? `<p class="msg">${escapeHtml(message)}</p>` : ''}
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
        const { error, error_description } = req.query;
        if (error) {
          const message = error_description
            ? `${String(error)}: ${String(error_description)}`
            : String(error);
          sendHtml(res, 400, errorHtml(message));
          // The registered code only: the description and error_uri are
          // anyone's text (a link to the local callback carries them).
          settle.err(identityProviderRefused(error), res);
          return;
        }

        const { code } = req.query;
        if (!code || typeof code !== 'string') {
          sendText(res, 400, 'Error: not an authorization callback');
          settle.ignore('no code and no error in query', res);
          return;
        }

        sendHtml(res, 200, successHtml);
        settle.ok(code, res);
      });

      app.get('/', (_req: express.Request, res: express.Response) => {
        sendHtml(res, 200, pasteFormHtml());
      });

      app.get('/submit', (req: express.Request, res: express.Response) => {
        const raw = req.query.input ?? req.query.code;
        const code = typeof raw === 'string' ? extractCode(raw) : null;
        if (!code) {
          sendHtml(
            res,
            400,
            pasteFormHtml(
              'Could not read an authorization code from that input. Try again.',
            ),
          );
          return;
        }
        sendHtml(res, 200, successHtml);
        settle.ok(code, res);
      });
    },
    use,
  );
