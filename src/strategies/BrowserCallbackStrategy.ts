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

export interface CallbackStrategyOptions<TResult = string> {
  /** `0` binds an ephemeral port. Unusable where the IdP has a registered URI. */
  port?: number;
  timeoutMs?: number;
  /** 'none' | 'headless' print the URL; 'auto' | 'system' | 'chrome' | … open it. */
  browser?: string;
  /**
   * The transport. Omitted means the one this package ships for the flow; a
   * consumer that already runs an HTTP server passes its own here and keeps
   * everything else — which is the point of the ready constructors existing at
   * all rather than forcing everyone through the class.
   */
  callbackServer?: CallbackServerFactory<TResult>;
  /** Receives the bound redirect URI too, since with `port: 0` nobody knew it earlier. */
  openUrl?: (
    url: string,
    browser: string,
    redirectUri: string,
  ) => Promise<void>;
  /**
   * Extra guidance for 'none'/'headless', built from the URI actually bound —
   * "if your browser is elsewhere, do this instead".
   *
   * It describes a *route*, so it belongs to whoever supplied the transport. A
   * consumer injecting its own `callbackServer` states its own hint here; the
   * package supplies one only for the transport it ships, and never guesses on
   * behalf of an injected one.
   */
  remoteHint?: (redirectUri: string) => string;
  signal?: AbortSignal;
}

export interface BrowserCallbackStrategyOptions<TResult>
  extends CallbackStrategyOptions<TResult> {
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

    const controller = new AbortController();
    this.controller = controller;
    const relay = () => controller.abort();
    this.options.signal?.addEventListener('abort', relay, { once: true });
    // A signal that was already aborted fires no event, so registering a
    // listener for it is not enough — the login would proceed as if nobody had
    // cancelled it.
    if (this.options.signal?.aborted) controller.abort();

    const announce = announcer(request.logger);
    const browser = this.options.browser ?? 'none';

    // Wrapped in an immediately-invoked async function, and assigned to
    // `inFlight` in the same synchronous turn as the controller. The port probe
    // awaits, and a `dispose` landing in that window used to find both fields
    // still null: it resolved, reporting everything released, and the login
    // then went on to bind a socket behind it.
    const run = (async (): Promise<AuthorizationOutcome<TResult>> => {
      await assertPortAvailable(port);
      if (controller.signal.aborted) {
        throw new Error(
          'Authorization aborted before the callback server bound',
        );
      }
      return await this.options.callbackServer(
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
          // Built here, not earlier: the launcher's messages name the URI that is
          // actually bound, which with `port: 0` nothing knew until now.
          const open =
            this.options.openUrl ??
            ((u: string, which: string, redirectUri: string) =>
              launchBrowser(
                u,
                which,
                redirectUri,
                announce,
                request.logger ?? null,
                this.options.remoteHint?.(redirectUri),
              ));
          // Not awaited: a launcher that hangs must not delay the timeout or the
          // release, and one that fails ends the scope through `fail`.
          void open(url, browser, server.redirectUri).catch(
            (error: unknown) => {
              const message =
                error instanceof Error ? error.message : String(error);
              request.logger?.error(
                `Failed to open browser: ${message}. Open manually: ${url}`,
                { error: message, url },
              );
              server.fail(
                new Error(`Browser opening failed. Open manually: ${url}`),
              );
            },
          );
          return {
            payload: await waiting,
            redirectUri: server.redirectUri,
          } satisfies AuthorizationOutcome<TResult>;
        },
      );
    })();

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

// Each ready constructor defaults the transport rather than dictating it: a
// supplied `callbackServer` wins, which is what makes substitution reachable
// without dropping to the class.
/** The paste form `withBrowserCallbackServer` serves on `/` — and nothing else does. */
const uaaPasteHint = (redirectUri: string): string =>
  '   If your browser is on another machine, copy the `code` from the ' +
  `address bar after login and paste it at ${new URL(redirectUri).origin}/`;

export function browserCallbackStrategy(
  options: CallbackStrategyOptions<string> = {},
): IAuthorizationStrategy<string> {
  return new BrowserCallbackStrategy<string>({
    ...options,
    callbackServer: options.callbackServer ?? withBrowserCallbackServer,
    // An explicit hint always wins. Otherwise the default applies only when we
    // supplied the transport: an injected receiver may have no `/` route, and
    // the replaceable receiver is the whole point of this design, so assuming
    // one would advertise a 404 to exactly the consumers the design is for.
    remoteHint:
      options.remoteHint ?? (options.callbackServer ? undefined : uaaPasteHint),
  });
}

export function oidcCallbackStrategy(
  options: CallbackStrategyOptions<OidcCallbackResult> = {},
): IAuthorizationStrategy<OidcCallbackResult> {
  return new BrowserCallbackStrategy<OidcCallbackResult>({
    ...options,
    callbackServer: options.callbackServer ?? withOidcCallbackServer,
  });
}

export function samlCallbackStrategy(
  options: CallbackStrategyOptions<string> = {},
): IAuthorizationStrategy<string> {
  return new BrowserCallbackStrategy<string>({
    ...options,
    callbackServer: options.callbackServer ?? withSamlCallbackServer,
  });
}
