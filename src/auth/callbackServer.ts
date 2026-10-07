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
 * `AbortSignal` — `ICallbackServerOptions.signal`, the only way a scope ends
 * without a result (interfaces-auth 6.0.0 declares no bound).
 *
 * Login CSRF (spec §6a1). The scope listens on loopback unless the consumer
 * names a `host`, and answers only a `Host` it serves for — loopback with the
 * bound port, or one of the consumer's `allowedHosts` — before any route
 * runs. Opened `gated`, it settles nothing until `expectState` arms it, and
 * then only a callback carrying the armed `state`; every other request is
 * answered `400`, counted and ignored, and the login keeps waiting.
 */

import * as http from 'node:http';
import type { AddressInfo, Socket } from 'node:net';
import { AuthProviderFailure, authError } from '@mcp-abap-adt/auth-errors';
import type {
  CallbackServerFactory,
  ICallbackServerHandle,
  ICallbackServerOptions,
} from '@mcp-abap-adt/interfaces-auth';
import express from 'express';
import { misconfigured, ownOptions } from './configuration';
import {
  abortedLogin,
  failedLogin,
  identityProviderRefused,
  loginFailure,
  portInUse,
} from './interactiveLogin';
import {
  mintSecret,
  type PasteReading,
  readPaste,
  sameSecret,
} from './loginState';
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
   * Ends nothing. The reason is one of this package's fixed sentences: it
   * is the only value of the request named in the warning line.
   */
  ignore(reason: IgnoredCallbackReason, res?: express.Response): void;
  /**
   * The gate (spec §6a1): whether a callback carrying `state` may settle
   * anything — the gate open (not `gated`, or armed with `null`), or armed
   * with exactly this `state` (constant time). When not, the request is
   * answered `400` in fixed words, counted and ignored here, and the route
   * returns. A payload and an explicit error pass through it alike.
   */
  admit(state: unknown, res: express.Response): boolean;
  /** This login's paste-form token; `undefined` while the gate is closed. */
  formToken(): string | undefined;
  /** Whether `token` is this login's form token (constant time). */
  admitsForm(token: unknown): boolean;
  /**
   * A pasted input read for this login (`readPaste`): a bare code as typed;
   * a redirected URL only with the armed `state` (any, when armed with
   * `null`). `undefined` while the gate is closed.
   */
  readPaste(input: string): PasteReading | undefined;
}

/** Why a request to the callback was ignored: fixed words only. */
export type IgnoredCallbackReason =
  | 'no code and no error in query'
  | 'no SAMLResponse in the request'
  | 'the login is not armed yet'
  | 'the state is not this login’s'
  | 'no form token of this login'
  | 'the pasted URL is not from this login'
  | 'a host this server does not answer for';

export type RouteSetup<TResult> = (
  app: express.Express,
  settle: Settle<TResult>,
) => void;

/**
 * K6: a port no socket can bind — an integer in 0..65535 only; a string is
 * not a port (Node would bind a UNIX socket at that path). The value given is
 * not echoed (L5). Checked before anything binds or probes: by the shipped
 * strategy at construction and before its probe, and here.
 */
export function validatePort(port: unknown): void {
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
  // Already decided (the second family's port taken): as it is.
  if (error instanceof AuthProviderFailure) return error;
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

/** An authority (`host` or `host:port`), its host lowercased. */
interface Authority {
  readonly host: string;
  readonly port: number | undefined;
}

/**
 * Reads `host[:port]` or `[v6]:port` by plain code — a `Host` header is
 * anyone's text. `undefined` for anything else: no host, a bare IPv6
 * address, a port that is not 0..65535 in digits.
 */
export function parseAuthority(value: unknown): Authority | undefined {
  if (typeof value !== 'string') return undefined;
  const text = value.toLowerCase();
  let host: string;
  let rest: string;
  if (text.startsWith('[')) {
    const close = text.indexOf(']');
    if (close < 0) return undefined;
    host = text.slice(0, close + 1);
    rest = text.slice(close + 1);
  } else {
    const colon = text.indexOf(':');
    if (colon !== text.lastIndexOf(':')) return undefined;
    host = colon < 0 ? text : text.slice(0, colon);
    rest = colon < 0 ? '' : text.slice(colon);
  }
  if (!hostCharacters(host)) return undefined;
  if (rest === '') return { host, port: undefined };
  const digits = rest.slice(1);
  if (
    !rest.startsWith(':') ||
    digits === '' ||
    digits.length > 5 ||
    [...digits].some((digit) => digit < '0' || digit > '9')
  ) {
    return undefined;
  }
  const port = Number(digits);
  return port > 65535 ? undefined : { host, port };
}

/**
 * A DNS name or IPv4 address (letters, digits, `.`, `-`), or a bracketed
 * IPv6 address (hex digits, `:`, `.`): nothing else is a host here.
 */
function hostCharacters(host: string): boolean {
  const bracketed = host.startsWith('[');
  const inner = bracketed ? host.slice(1, -1) : host;
  if (inner === '') return false;
  for (const character of inner) {
    const digit = character >= '0' && character <= '9';
    const allowed = bracketed
      ? digit ||
        (character >= 'a' && character <= 'f') ||
        character === ':' ||
        character === '.'
      : digit ||
        (character >= 'a' && character <= 'z') ||
        character === '.' ||
        character === '-';
    if (!allowed) return false;
  }
  return true;
}

/**
 * Whether a peer address is loopback: `127.0.0.0/8`, `::1`, or an
 * IPv4-mapped `::ffff:127.x.y.z`. Plain code over the dotted quad.
 */
export function isLoopbackPeer(address: unknown): boolean {
  if (typeof address !== 'string') return false;
  if (address === '::1') return true;
  const mapped = address.startsWith('::ffff:');
  const v4 = mapped ? address.slice('::ffff:'.length) : address;
  const parts = v4.split('.');
  if (parts.length !== 4) return false;
  for (const part of parts) {
    if (part === '' || part.length > 3) return false;
    for (const digit of part) if (digit < '0' || digit > '9') return false;
    if (Number(part) > 255) return false;
  }
  return parts[0] === '127';
}

/** The names a browser on this machine uses for the loopback transport. */
const LOOPBACK_NAMES: readonly string[] = ['localhost', '127.0.0.1', '[::1]'];

/**
 * Whether a request's `Host` names this transport: a loopback name with the
 * bound port, or one of the consumer's authorities (an entry without a port
 * meaning the bound port). A `Host` without a port is port 80, as HTTP has
 * it.
 */
export function answersFor(
  hostHeader: unknown,
  peer: unknown,
  boundPort: number,
  allowed: readonly Authority[],
): boolean {
  const asked = parseAuthority(hostHeader);
  if (!asked) return false;
  const askedPort = asked.port ?? 80;
  // A loopback name counts only from a loopback peer (spec §6a1): the
  // header is the client's to choose, so a machine on the network sending
  // `Host: localhost` to a wildcard bind is not this machine's browser.
  if (
    LOOPBACK_NAMES.includes(asked.host) &&
    isLoopbackPeer(peer) &&
    askedPort === boundPort
  ) {
    return true;
  }
  // A loopback name is never an allowed authority (spec §6a1): listed or
  // not, it counts only from a loopback peer, above.
  if (LOOPBACK_NAMES.includes(asked.host) || isLoopbackPeer(asked.host)) {
    return false;
  }
  return allowed.some(
    (entry) =>
      entry.host === asked.host && (entry.port ?? boundPort) === askedPort,
  );
}

/** The consumer's `allowedHosts`: entries that are not authorities match nothing. */
export function allowedAuthorities(value: unknown): Authority[] {
  if (!Array.isArray(value)) return [];
  const read: Authority[] = [];
  for (const entry of value as unknown[]) {
    const authority = parseAuthority(entry);
    if (authority) read.push(authority);
  }
  return read;
}

/**
 * Where the transport listens: the consumer's `host`, else loopback —
 * `127.0.0.1` and `::1`, the two addresses `localhost` resolves to.
 */
function bindAddresses(host: unknown): {
  first: string;
  more: readonly string[];
} {
  return typeof host === 'string' && host !== ''
    ? { first: host, more: [] }
    : { first: '127.0.0.1', more: ['::1'] };
}

/** A machine without IPv6 loopback: the `::1` half is skipped, not fatal. */
function unavailableAddress(error: unknown): boolean {
  if (error === null || typeof error !== 'object' || !('code' in error)) {
    return false;
  }
  return error.code === 'EADDRNOTAVAIL' || error.code === 'EAFNOSUPPORT';
}

/** The OS refused the address: it is in use. */
function addressInUse(error: unknown): boolean {
  return (
    error !== null &&
    typeof error === 'object' &&
    'code' in error &&
    error.code === 'EADDRINUSE'
  );
}

/** The gate's state: closed until armed, then bound to a state or not. */
type Gate =
  | { readonly open: false }
  | {
      readonly open: true;
      /** The armed `state`; `null` for an unbound URL. */
      readonly bound: string | null;
      readonly formToken: string;
    };

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
  // Read once as own data: a hostile object throws nothing of its own.
  const { port, signal, logger, host, allowedHosts, gated } =
    ownOptions<ICallbackServerOptions>(options);
  validatePort(port);
  if (signal?.aborted) throw abortedLogin('browser');
  const allowed = allowedAuthorities(allowedHosts);
  const addresses = bindAddresses(host);
  /** The port the OS gave; `0` until bound (no request arrives before). */
  let boundPort = 0;
  let gate: Gate =
    gated === true
      ? { open: false }
      : { open: true, bound: null, formToken: mintSecret() };

  const app = express();
  // Every response: no sniffing, and a policy that runs no script, loads
  // nothing and submits only to this server (the paste form). Inline style
  // is the pages' only need.
  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', CALLBACK_CSP);
    next();
  });
  /** One listener per bind address, all serving the same routes. */
  const servers: http.Server[] = [];
  /** Every open connection, and how many responses each is still writing. */
  const sockets = new Map<Socket, number>();
  /** The request each connection is serving, to tell an unfinished body. */
  const requests = new Map<Socket, http.IncomingMessage>();
  let released = false;
  const newServer = (): http.Server => {
    const server = http.createServer(app);
    server.on('connection', (socket: Socket) => {
      sockets.set(socket, 0);
      socket.on('close', () => {
        sockets.delete(socket);
        requests.delete(socket);
      });
    });
    server.on(
      'request',
      (req: http.IncomingMessage, res: http.ServerResponse) => {
        const socket = req.socket;
        sockets.set(socket, (sockets.get(socket) ?? 0) + 1);
        requests.set(socket, req);
        res.once('close', () => {
          const left = (sockets.get(socket) ?? 1) - 1;
          if (sockets.has(socket)) sockets.set(socket, left);
          if (released && left <= 0) letGo(socket);
        });
      },
    );
    servers.push(server);
    return server;
  };

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

  /**
   * Settles once every bind begun has finished: a listen still resolving
   * its address when the scope ends completes afterwards, and is closed
   * then — so a settled scope still means the port is free.
   */
  let binding: Promise<void> = Promise.resolve();

  /** The one place a scope ends. Everything after the first call is a no-op. */
  const endScope = (outcome: { value: TReturn } | { error: Error }): void => {
    if (scopeSettled) return;
    scopeSettled = true;
    alive = false;
    signal?.removeEventListener('abort', onAbort);
    settleResult({ error: callbackClosed() });
    release();
    void binding.then(() => {
      release();
      if ('value' in outcome) resolveScope(outcome.value);
      else rejectScope(outcome.error);
    });
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
    for (const server of servers) if (server.listening) server.close();
    for (const [socket, responding] of sockets) {
      if (responding <= 0) letGo(socket);
      else holdNothing(socket, requests.get(socket));
    }
  }

  /**
   * A connection still answering: referenced no longer, so it cannot keep the
   * process alive; and when its request body is unfinished — nothing will ever
   * answer it — destroyed. A finished request keeps its response, which
   * `letGo` ends after the last byte.
   */
  function holdNothing(
    socket: Socket,
    request: http.IncomingMessage | undefined,
  ): void {
    socket.unref();
    if (request && !request.complete) socket.destroy();
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
        logger?.warn('[callbackServer] ignored a callback request', {
          reason,
          ignored,
        }),
      );
    },
    admit(state, res) {
      if (!gate.open) {
        sendText(res, 400, NOT_THIS_LOGIN);
        settle.ignore('the login is not armed yet', res);
        return false;
      }
      if (gate.bound === null || sameSecret(gate.bound, state)) return true;
      sendText(res, 400, NOT_THIS_LOGIN);
      settle.ignore('the state is not this login’s', res);
      return false;
    },
    formToken: () => (gate.open ? gate.formToken : undefined),
    admitsForm: (token) => gate.open && sameSecret(gate.formToken, token),
    readPaste: (input) =>
      gate.open ? readPaste(gate.bound, input) : undefined,
  };

  // Before any route, page or token: a request through a name this
  // transport does not answer for (DNS rebinding) reads and settles nothing.
  app.use(
    (
      req: express.Request,
      res: express.Response,
      next: express.NextFunction,
    ) => {
      if (
        answersFor(
          req.headers.host,
          req.socket.remoteAddress,
          boundPort,
          allowed,
        )
      ) {
        next();
        return;
      }
      sendText(res, 400, 'Error: this server does not answer for that host');
      settle.ignore('a host this server does not answer for', res);
    },
  );

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

  /** Listens on one address; settles once bound or refused. */
  const listenOn = (address: string, onPort: number): Promise<void> =>
    new Promise<void>((resolve, reject) => {
      const server = newServer();
      const refused = (error: Error) => {
        servers.splice(servers.indexOf(server), 1);
        reject(error);
      };
      server.once('error', refused);
      server.listen({ port: onPort, host: address }, () => {
        server.removeListener('error', refused);
        // A listener's later failure ends the scope in fixed words.
        server.on('error', (error: Error) => {
          endScope({ error: failedLogin(error) });
        });
        resolve();
      });
    });

  signal?.addEventListener('abort', onAbort, { once: true });

  const bindAll = async (): Promise<number> => {
    await listenOn(addresses.first, port);
    // The requested port may be 0, in which case only the OS knows the answer.
    const first = servers[0]?.address() as AddressInfo | null | undefined;
    const onPort = first?.port ?? port;
    for (const address of addresses.more) {
      if (scopeSettled) break;
      try {
        await listenOn(address, onPort);
      } catch (error) {
        if (unavailableAddress(error)) continue;
        // Taken on ::1 — an ephemeral port as much as a fixed one: the
        // redirect URI says `localhost`, which resolves to ::1 first, so
        // staying on 127.0.0.1 alone would hand its holder the code and the
        // state. The login fails `port-in-use` (spec §6a1); retrying is the
        // consumer's.
        if (addressInUse(error)) throw portInUse(onPort);
        throw error;
      }
    }
    return onPort;
  };

  const bindingPort = bindAll();
  binding = bindingPort.then(
    () => undefined,
    () => undefined,
  );

  bindingPort.then(
    (onPort) => {
      // Aborted while binding: `endScope` closes what was bound.
      if (scopeSettled) return;
      alive = true;
      boundPort = onPort;

      const handle: ICallbackServerHandle<TResult> = {
        port: onPort,
        redirectUri: `http://localhost:${onPort}/callback`,
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
        // Arms the gate (spec §6a1): a string binds every callback to it,
        // `null` declares an unbound URL. A new form token each time. Read
        // as the contract types it: anything else changes nothing.
        expectState: (state: string | null) => {
          if (!alive) return;
          if (state !== null && typeof state !== 'string') return;
          gate = { open: true, bound: state, formToken: mintSecret() };
        },
      };

      void use(handle).then(
        (value) => endScope({ value }),
        (error: Error) => endScope({ error }),
      );
    },
    (error: unknown) => {
      endScope({ error: bindFailure(error, port) });
    },
  );

  return await scopePromise;
}

/** The fixed answer to a callback the gate does not admit. */
const NOT_THIS_LOGIN = 'Error: not a callback of this login';

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
// redirected URL; re-renders with a message on a bad paste. Carries this
// login's form token (spec §6a1): `/submit` settles only with it, and another
// origin cannot read the page (no CORS, the CSP) to learn it.
const pasteFormHtml = (
  formToken: string,
  message?: string,
): string => `<!DOCTYPE html>
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
<input type="hidden" name="form_token" value="${escapeHtml(formToken)}" />
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
        // The gate first: a forged code and a forged error alike stop here.
        if (!settle.admit(req.query.state, res)) return;
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
        const formToken = settle.formToken();
        if (formToken === undefined) {
          // Closed until armed: no form, so no token, exists yet.
          sendText(res, 400, 'Error: the login is not ready yet');
          settle.ignore('the login is not armed yet', res);
          return;
        }
        sendHtml(res, 200, pasteFormHtml(formToken));
      });

      app.get('/submit', (req: express.Request, res: express.Response) => {
        const formToken = settle.formToken();
        if (formToken === undefined) {
          sendText(res, 400, NOT_THIS_LOGIN);
          settle.ignore('the login is not armed yet', res);
          return;
        }
        // A GET can be forged from any page; the served form's token cannot.
        if (!settle.admitsForm(req.query.form_token)) {
          sendText(res, 400, NOT_THIS_LOGIN);
          settle.ignore('no form token of this login', res);
          return;
        }
        const raw = req.query.input ?? req.query.code;
        const input = typeof raw === 'string' ? raw : '';
        const reading = settle.readPaste(input);
        if (reading === undefined) {
          sendText(res, 400, NOT_THIS_LOGIN);
          settle.ignore('the login is not armed yet', res);
          return;
        }
        if ('refused' in reading && reading.refused === 'state') {
          sendHtml(
            res,
            400,
            pasteFormHtml(
              formToken,
              'That URL is not from this login. Paste the code or URL this login returned.',
            ),
          );
          settle.ignore('the pasted URL is not from this login', res);
          return;
        }
        if (!('code' in reading)) {
          sendHtml(
            res,
            400,
            pasteFormHtml(
              formToken,
              'Could not read an authorization code from that input. Try again.',
            ),
          );
          return;
        }
        const { code } = reading;
        sendHtml(res, 200, successHtml);
        settle.ok(code, res);
      });
    },
    use,
  );
