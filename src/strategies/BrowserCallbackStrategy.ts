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
  authError,
  isAuthProviderFailure,
  logFields,
  readFailure,
} from '@mcp-abap-adt/auth-errors';
import type {
  AuthorizationOutcome,
  AuthorizationRequest,
  CallbackServerFactory,
  IAuthorizationStrategy,
} from '@mcp-abap-adt/interfaces-auth';
import { announcer, promptableUrl } from '../auth/announce';
import { launchBrowser, promptForUrl } from '../auth/browserAuth';
import {
  parseAuthority,
  validatePort,
  withBrowserCallbackServer,
} from '../auth/callbackServer';
import { misconfigured, ownOptions } from '../auth/configuration';
import { markHandled, onAnswerRejection } from '../auth/handled';
import {
  abortedLogin,
  failedLogin,
  loginFailure,
  portInUse,
} from '../auth/interactiveLogin';
import { urlState } from '../auth/loginState';
import type { OidcCallbackResult } from '../auth/oidcBrowserAuth';
import { withOidcCallbackServer } from '../auth/oidcBrowserAuth';
import { withSamlCallbackServer } from '../auth/saml2Auth';
import { signalOf } from '../auth/signalledRequest';
import { logQuietly } from '../auth/tokenRequest';

/**
 * Above Linux's `ip_local_port_range` (32768–60999), so an outbound connection
 * never squats on it, and far from the 3001/3333 range application servers use.
 */
export const DEFAULT_CALLBACK_PORT = 61001;

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
   * The address the transport binds. Not given: loopback (`127.0.0.1`, and
   * `::1`). Passed to the transport as `ICallbackServerOptions.host`. A
   * wildcard or an interface address makes the transport reachable from
   * the network — name the authorities a browser will use in `allowedHosts`.
   *
   * **Warning:** with `allowedHosts`, every client that can reach an allowed
   * authority gets the paste page and its form token and can settle the
   * login with a code of its own. Prefer an SSH tunnel to the loopback
   * default (`ssh -L <port>:localhost:<port> <this machine>`).
   */
  host?: string | undefined;
  /**
   * The authorities (`host` or `host:port`; no port means the bound one) a
   * browser may use to reach the transport besides loopback — every other
   * `Host` is refused before anything is served. Passed to the transport as
   * `ICallbackServerOptions.allowedHosts`; the paste hint names the first.
   * A loopback name (`localhost`, `127.0.0.1`, `[::1]`) is never an allowed
   * authority: it counts only from a loopback peer, listed or not.
   *
   * **Warning:** every client that can reach an allowed authority gets the
   * paste page and its form token and can settle the login with a code of
   * its own. Prefer an SSH tunnel to the loopback default.
   */
  allowedHosts?: readonly string[] | undefined;
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
  /**
   * Login CSRF (spec §6a1). `true` — an OAuth redirect, as
   * `browserCallbackStrategy` and `oidcCallbackStrategy` build it: the
   * transport is opened `gated`, armed with the URL's `state` (or `null`
   * for a URL without one) once it is built and before the browser is
   * opened, and a transport without `expectState` is refused before
   * anything is opened (`configuration` `invalid-value`, `callbackServer`).
   * `false` — a redirect bound otherwise, as `samlCallbackStrategy`'s is
   * (by `InResponseTo` and the assertion validator): no gate. Required: the
   * strategy does not guess which one a transport is.
   */
  stateGate: boolean;
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
  private readonly options: BrowserCallbackStrategyOptions<TResult>;

  constructor(options: BrowserCallbackStrategyOptions<TResult>) {
    // Read once as own data, like every option: a hostile object throws
    // nothing of its own.
    this.options = ownOptions<BrowserCallbackStrategyOptions<TResult>>(options);
    // K6 at construction (a constructor may throw, spec §8.1).
    if (this.options.port !== undefined) validatePort(this.options.port);
  }

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
    // K6 again before the probe binds anything (the default included).
    validatePort(port);

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
      // Anything but an explicit `false` (a JavaScript caller that left it
      // out) keeps the gate.
      const gate = this.options.stateGate !== false;
      const { host, allowedHosts } = this.options;
      return await this.options.callbackServer(
        {
          port,
          signal: controller.signal,
          logger: request.logger,
          ...(host === undefined ? {} : { host }),
          ...(allowedHosts === undefined ? {} : { allowedHosts }),
          // Closed from the bind on: nothing settles while the URL is built.
          ...(gate ? { gated: true } : {}),
        },
        async (server) => {
          // A transport that cannot be armed cannot keep forged callbacks
          // out: refused before the URL is built or anything opened, and
          // nothing it may have settled is used (spec §6a1).
          const arm = server.expectState;
          if (gate && typeof arm !== 'function') {
            throw misconfigured(
              authError.configuration({
                case: 'invalid-value',
                fields: ['callbackServer'],
              }),
            );
          }
          // Thrown before anything is opened: a redirect the provider cannot
          // honour must fail here, not as a callback that never arrives.
          const url = await request.buildAuthorizationUrl(server.redirectUri);
          // Aborted while the URL was built: nothing is opened.
          if (controller.signal.aborted) throw abortedLogin('browser');
          if (gate) {
            // Parsed with `URL`: its `state`, or `null` for a URL without
            // one (a configured URL, unbound). A URL that does not parse
            // is not opened.
            const state = urlState(url);
            if (state === undefined) {
              throw misconfigured(
                authError.configuration({
                  case: 'invalid-value',
                  fields: ['authorizationUrl'],
                }),
              );
            }
            arm?.call(server, state);
          }
          const waiting = server.waitForResult();
          // Held before it is awaited: a launcher that throws at once leaves
          // it behind, and a consumer's server may not have marked it
          // handled (controller addition after Task 23).
          markHandled(waiting);
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
          // A launch failure: H7's line, then the prompt — and the login
          // goes on waiting (spec §6a0). Where no browser can be opened the
          // URL shown is the only way to finish the login, so the callback
          // must still listen for it; the login ends on its result, the
          // IdP's refusal or the consumer's signal, never on this.
          const launchFailed = (error: unknown) => {
            // H7: the launcher is the consumer's, its text foreign — the
            // line carries `logFields` of its failure and no URL (one from
            // discovery or configuration is no fixed fact).
            const fields = logFields(readFailure(error, 'opening-browser'));
            logQuietly(() =>
              request.logger?.error(
                `Failed to open browser: ${fields.error}`,
                fields,
              ),
            );
            // The URL goes to the user as a prompt — the announcer (the
            // logger's `info`, else stderr; never stdout), only as
            // `promptableUrl` admits it — with the callback still waiting.
            promptForUrl(
              announce,
              '🔗 The browser could not be opened. The authorization URL:',
              url,
              server.redirectUri,
            );
          };
          // Not awaited: a launcher that hangs must not delay the result or
          // the release. A synchronous throw is a launch failure, and so is a
          // rejection of what the launcher answered — the consumer's own
          // code, adopted as `await` would adopt it: a native promise or any
          // Promises/A+ thenable (the user's decision, 2026-10-07).
          let launched: unknown;
          try {
            launched = open(url, browser, server.redirectUri);
          } catch (error) {
            launchFailed(error);
          }
          onAnswerRejection(launched, launchFailed);
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
      // failure (K1–K5, K8, K10, K11) — or a failure already built, relayed
      // as it is below (a configuration error from building the URL, E7,
      // E8, E12).
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
/**
 * Since 6.0.0 the transport answers only loopback and the consumer's
 * `allowedHosts` (spec §6a1), so the hint names one of those, never a
 * guessed hostname: the consumer's first allowed authority (its port, or the
 * bound one), else an SSH tunnel — which arrives on loopback and works with
 * the default bind.
 */
const uaaPasteHint =
  (allowedHosts: unknown) =>
  (redirectUri: string): string => {
    const { protocol, port } = new URL(redirectUri);
    const allowed = Array.isArray(allowedHosts)
      ? (allowedHosts as unknown[]).find(
          (entry): entry is string => parseAuthority(entry) !== undefined,
        )
      : undefined;
    const authority =
      allowed === undefined
        ? undefined
        : parseAuthority(allowed)?.port === undefined
          ? `${allowed}:${port}`
          : allowed;
    // Shown only as `promptableUrl` admits it, like every URL in a prompt.
    const shownAllowed =
      authority === undefined
        ? undefined
        : promptableUrl(`${protocol}//${authority}/`);
    if (shownAllowed !== undefined) {
      return (
        '   If your browser is on another machine, copy the `code` from the ' +
        `address bar after login and paste it at ${shownAllowed}`
      );
    }
    const shownLocal = promptableUrl(`${protocol}//localhost:${port}/`);
    return (
      '   If your browser is on another machine, open an SSH tunnel to this ' +
      `one (ssh -L ${port}:localhost:${port} <this machine>), then copy ` +
      'the `code` from the address bar after login and paste it at ' +
      `${shownLocal ?? 'the callback port on localhost'}`
    );
  };

export function browserCallbackStrategy(
  options: CallbackStrategyOptions<string> = {},
): IAuthorizationStrategy<string> {
  const own = ownOptions<CallbackStrategyOptions<string>>(options);
  return new BrowserCallbackStrategy<string>({
    ...own,
    callbackServer: own.callbackServer ?? withBrowserCallbackServer,
    // An OAuth redirect: bound by `state` (spec §6a1).
    stateGate: true,
    // An explicit hint always wins. Otherwise the default applies only when we
    // supplied the transport: an injected receiver may have no `/` route, and
    // the replaceable receiver is the whole point of this design, so assuming
    // one would advertise a 404 to exactly the consumers the design is for.
    remoteHint:
      own.remoteHint ??
      (own.callbackServer ? undefined : uaaPasteHint(own.allowedHosts)),
  });
}

export function oidcCallbackStrategy(
  options: CallbackStrategyOptions<OidcCallbackResult> = {},
): IAuthorizationStrategy<OidcCallbackResult> {
  const own = ownOptions<CallbackStrategyOptions<OidcCallbackResult>>(options);
  return new BrowserCallbackStrategy<OidcCallbackResult>({
    ...own,
    callbackServer: own.callbackServer ?? withOidcCallbackServer,
    // An OAuth redirect: bound by `state` (spec §6a1).
    stateGate: true,
  });
}

export function samlCallbackStrategy(
  options: CallbackStrategyOptions<string> = {},
): IAuthorizationStrategy<string> {
  const own = ownOptions<CallbackStrategyOptions<string>>(options);
  return new BrowserCallbackStrategy<string>({
    ...own,
    callbackServer: own.callbackServer ?? withSamlCallbackServer,
    // Bound by `InResponseTo` and the assertion validator, not `state`.
    stateGate: false,
  });
}
