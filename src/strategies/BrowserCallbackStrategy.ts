/**
 * Reaching the authorization URL with a browser, receiving the redirect on a
 * local socket.
 *
 * The transport is injected rather than assumed: a consumer that already runs
 * an HTTP server can pass its own `CallbackServerFactory` and keep everything
 * else here.
 */

import * as net from 'node:net';
import {
  isAuthProviderFailure,
  logFields,
  readFailure,
} from '@mcp-abap-adt/auth-errors';
import type {
  AuthorizationOutcome,
  AuthorizationRequest,
  CallbackServerFactory,
  IAuthorizationStrategy,
  ICallbackServerOptions,
} from '@mcp-abap-adt/interfaces-auth';
import { announcer } from '../auth/announce';
import { launchBrowser } from '../auth/browserAuth';
import { withBrowserCallbackServer } from '../auth/callbackServer';
import { asContract } from '../auth/contractShape';
import {
  abortedLogin,
  browserLaunchFailed,
  failedLogin,
  loginFailure,
  portInUse,
} from '../auth/interactiveLogin';
import type { OidcCallbackResult } from '../auth/oidcBrowserAuth';
import { withOidcCallbackServer } from '../auth/oidcBrowserAuth';
import { withSamlCallbackServer } from '../auth/saml2Auth';
import { signalOf } from '../auth/signalledRequest';
import { logQuietly } from '../auth/tokenRequest';
import { TokenProviderError } from '../errors/TokenProviderErrors';

/**
 * Above Linux's `ip_local_port_range` (32768–60999), so an outbound connection
 * never squats on it, and far from the 3001/3333 range application servers use.
 */
export const DEFAULT_CALLBACK_PORT = 61001;

/**
 * TRANSITION (Decision D6): interfaces-auth 4.x declares the callback
 * server's bound in milliseconds as required. No login has a bound of this
 * package's choosing (spec §6a) — `runCallbackScope` reads no such field —
 * so the value handed over is "none". Task 27 drops it with the 5.0.0
 * contract.
 */
const NO_BOUND = Number.POSITIVE_INFINITY;

export interface CallbackStrategyOptions<TResult = string> {
  /** `0` binds an ephemeral port. Unusable where the IdP has a registered URI. */
  port?: number | undefined;
  /** 'none' | 'headless' print the URL; 'auto' | 'system' | 'chrome' | … open it. */
  browser?: string | undefined;
  /**
   * The transport. Omitted means the one this package ships for the flow; a
   * consumer that already runs an HTTP server passes its own here and keeps
   * everything else — which is the point of the ready constructors existing at
   * all rather than forcing everyone through the class.
   */
  callbackServer?: CallbackServerFactory<TResult> | undefined;
  /** Receives the bound redirect URI too, since with `port: 0` nobody knew it earlier. */
  openUrl?:
    | ((url: string, browser: string, redirectUri: string) => Promise<void>)
    | undefined;
  /**
   * Extra guidance for 'none'/'headless', built from the URI actually bound —
   * "if your browser is elsewhere, do this instead".
   *
   * It describes a *route*, so it belongs to whoever supplied the transport. A
   * consumer injecting its own `callbackServer` states its own hint here; the
   * package supplies one only for the transport it ships, and never guesses on
   * behalf of an injected one.
   */
  remoteHint?: ((redirectUri: string) => string) | undefined;
  /**
   * Ends every login of this strategy, beside the request's own signal (the
   * attempt's, spec §6b): either one aborting ends it `aborted`. There is no
   * other bound — a login waits for its result, the identity provider's
   * refusal or an abort; compose `AbortSignal.timeout(ms)` for a deadline.
   */
  signal?: AbortSignal | undefined;
}

export interface BrowserCallbackStrategyOptions<TResult>
  extends CallbackStrategyOptions<TResult> {
  callbackServer: CallbackServerFactory<TResult>;
}

/**
 * K1, kept for its wording, not its certainty: "already in use" stays for any
 * consumer that may match it to tell a busy port from every other failure
 * (the bind error Node raises says `EADDRINUSE` instead). Skipped entirely
 * for an ephemeral port: there is nothing to check, and the answer would be
 * about a port we are not going to get.
 */
async function assertPortAvailable(port: number): Promise<void> {
  if (port === 0) return;
  const free = await new Promise<boolean>((resolve) => {
    const probe = net.createServer();
    probe.once('error', () => resolve(false));
    probe.listen(port, () => probe.close(() => resolve(true)));
  });
  if (!free) throw portInUse(port);
}

/** Whether a thrown value is an `interactive-login` `aborted` failure. */
function isAbortedFailure(error: unknown): boolean {
  const read = readFailure(error, 'browser-login');
  return read.kind === 'interactive-login' && read.facts.outcome === 'aborted';
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

  /**
   * Settles only once the callback factory has settled — which the shipped
   * one does once its socket is closed — so a login that follows never
   * meets this one's port or its `inFlight` (spec §6b, drain handoff).
   */
  async authorize(
    request: AuthorizationRequest,
  ): Promise<AuthorizationOutcome<TResult>> {
    if (this.disposed) {
      throw loginFailure({ outcome: 'disposed', strategy: 'browser' });
    }
    if (this.inFlight) throw loginFailure({ outcome: 'busy' });

    const port = this.options.port ?? DEFAULT_CALLBACK_PORT;

    const controller = new AbortController();
    this.controller = controller;
    const relay = () => controller.abort();
    // Either signal ends the login: the strategy's own option, and the
    // request's — the attempt's, aborted when every waiter of the login has
    // gone (spec §6b).
    const requestSignal = signalOf(request);
    this.options.signal?.addEventListener('abort', relay, { once: true });
    requestSignal?.addEventListener('abort', relay, { once: true });
    // A signal that was already aborted fires no event, so registering a
    // listener for it is not enough — the login would proceed as if nobody had
    // cancelled it.
    if (this.options.signal?.aborted || requestSignal?.aborted) {
      controller.abort();
    }

    const announce = announcer(request.logger);
    const browser = this.options.browser ?? 'none';

    // Wrapped in an immediately-invoked async function, and assigned to
    // `inFlight` in the same synchronous turn as the controller. The port probe
    // awaits, and a `dispose` landing in that window used to find both fields
    // still null: it resolved, reporting everything released, and the login
    // then went on to bind a socket behind it.
    const run = (async (): Promise<AuthorizationOutcome<TResult>> => {
      await assertPortAvailable(port);
      if (controller.signal.aborted) throw abortedLogin('browser');
      return await this.options.callbackServer(
        asContract<ICallbackServerOptions>({
          port,
          timeoutMs: NO_BOUND,
          signal: controller.signal,
          logger: request.logger,
        }),
        async (server) => {
          // Thrown before anything is opened: a redirect the provider cannot
          // honour must fail here, not as a callback that never arrives.
          const url = await request.buildAuthorizationUrl(server.redirectUri);
          // Aborted while the URL was built: nothing is opened.
          if (controller.signal.aborted) throw abortedLogin('browser');
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
          // Not awaited: a launcher that hangs must not delay the result or
          // the release, and one that fails ends the scope through `fail`.
          void open(url, browser, server.redirectUri).catch(
            (error: unknown) => {
              // H7: the launcher is the consumer's, its text foreign — the
              // line carries `logFields` of its failure and the URL this
              // strategy announces anyway.
              const fields = logFields(readFailure(error, 'opening-browser'));
              logQuietly(() =>
                request.logger?.error(
                  `Failed to open browser: ${fields.error}. Open manually: ${url}`,
                  { ...fields, url },
                ),
              );
              server.fail(browserLaunchFailed(error));
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
    } catch (error) {
      // Everything that ends a browser login here is an `interactive-login`
      // failure (K1–K5, K8, K10, K11). An error that already has a type (a
      // ValidationError from building the URL) is not one of these.
      if (error instanceof TokenProviderError) throw error;
      if (controller.signal.aborted) {
        // Disposal ended it (K2); else the consumer's or the attempt's abort
        // (K4) — the callback server's own failure keeps its tally.
        if (this.disposed && !this.signalled(requestSignal)) {
          throw loginFailure({ outcome: 'disposed', strategy: 'browser' });
        }
        throw isAbortedFailure(error) ? error : abortedLogin('browser');
      }
      // A failure already built — this strategy's, the callback server's,
      // or one the URL builder threw (OIDC discovery) — is relayed as it is.
      if (isAuthProviderFailure(error)) throw error;
      // Anything else — a consumer's transport, a foreign rejection — names
      // only its status, a registered OAuth `error` and an allowlisted code.
      throw failedLogin(error);
    } finally {
      this.options.signal?.removeEventListener('abort', relay);
      requestSignal?.removeEventListener('abort', relay);
      this.controller = null;
      this.inFlight = null;
    }
  }

  /** Whether one of the login's own signals — not `dispose()` — aborted. */
  private signalled(requestSignal: AbortSignal | undefined): boolean {
    return (
      this.options.signal?.aborted === true || requestSignal?.aborted === true
    );
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
/**
 * The paste form `withBrowserCallbackServer` serves on `/` — and nothing else
 * does. Since the terminal-paste channel left with `startBrowserAuth`, this
 * form is the only remaining way in for a browser on another machine, so the
 * address it names has to be one that machine can actually reach.
 *
 * Which is why the host is left as a placeholder rather than taken from
 * `redirectUri`. That URI is bound for *this* process, so its origin is
 * `http://localhost:<port>` — precisely the address that does not work from
 * anywhere else, addressed to the one reader who is not here. The port is real
 * and is kept; the host is the reader's to fill in.
 */
const uaaPasteHint = (redirectUri: string): string => {
  const { protocol, port } = new URL(redirectUri);
  return (
    '   If your browser is on another machine, copy the `code` from the ' +
    `address bar after login and paste it at ${protocol}//<this-host>:${port}/`
  );
};

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
