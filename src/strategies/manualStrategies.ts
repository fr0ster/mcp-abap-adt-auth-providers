/**
 * Strategies where a human moves the payload.
 *
 * There are two because the payload is not acquired the same way. An
 * authorization code lands in the browser's address bar; a `SAMLResponse` does
 * not — our `AuthnRequest` declares the HTTP-POST binding, so the IdP posts it
 * in a form body and the user must lift it from there.
 */

import { createInterface } from 'node:readline';
import type {
  AuthorizationOutcome,
  AuthorizationRequest,
  IAuthorizationStrategy,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { announcer, promptableUrl } from '../auth/announce';
import { extractCode } from '../auth/browserAuth';
import { ownOptions } from '../auth/configuration';
import { abortedLogin, loginFailure } from '../auth/interactiveLogin';
import { signalOf } from '../auth/signalledRequest';
import { DEFAULT_CALLBACK_PORT } from './BrowserCallbackStrategy';

export interface ManualStrategyOptions {
  /** Must match what the authorization request advertises and the exchange sends. */
  redirectUri?: string | undefined;
  /**
   * Where the pasted value comes from. Defaults to an interactive stdin read.
   * The signal aborts when the login is aborted or the strategy disposed; the
   * reader must then stop and release what it holds — the strategy settles
   * only once the reader has, so a reader that ignores it blocks the next
   * login (spec §6b).
   */
  read?: ((prompt: string, signal: AbortSignal) => Promise<string>) | undefined;
  /**
   * Ends every login of this strategy, beside the request's own signal (the
   * attempt's): either one aborting ends it `aborted`. There is no other
   * bound — compose `AbortSignal.timeout(ms)` for a deadline.
   */
  signal?: AbortSignal | undefined;
}

const defaultRedirectUri = () =>
  `http://localhost:${DEFAULT_CALLBACK_PORT}/callback`;

/**
 * Reads one line from stdin.
 *
 * The prompt goes to stderr, never stdout, and stdin is touched only when it is
 * a terminal: under a stdio RPC transport those streams carry the protocol.
 * Closes its `readline` when the signal aborts, and settles only once the
 * interface has closed — its listeners gone from stdin — so the next login's
 * reader never shares stdin with this one.
 */
export async function readFromTerminal(
  prompt: string,
  signal: AbortSignal,
): Promise<string> {
  // Aborted before the read began (while the URL was built): no readline, so
  // stdin is never held for a line nobody awaits (K12).
  if (signal.aborted) throw loginFailure({ outcome: 'input-abandoned' });
  if (!process.stdin.isTTY) throw loginFailure({ outcome: 'no-terminal' });
  process.stderr.write(prompt);
  const rl = createInterface({ input: process.stdin });
  const closed = new Promise<void>((resolve) => {
    rl.once('close', () => resolve());
  });
  const abort = () => rl.close();
  signal.addEventListener('abort', abort, { once: true });
  try {
    for await (const line of rl) return line.trim();
  } finally {
    signal.removeEventListener('abort', abort);
    rl.close();
    await closed;
  }
  throw loginFailure({ outcome: 'no-input' });
}

/**
 * A manual strategy with a `dispose()`: the read gets a signal that either
 * signal — the strategy's option or the request's — or `dispose()` aborts.
 * Settles only once the read has settled (the reader closed), never at the
 * abort alone: the next login waits for that release (spec §6b).
 */
function manualStrategy(
  options: ManualStrategyOptions,
  run: (
    request: AuthorizationRequest,
    read: (prompt: string) => Promise<string>,
  ) => Promise<AuthorizationOutcome<string>>,
): IAuthorizationStrategy<string> {
  const read = options.read ?? readFromTerminal;
  let disposed = false;
  // Every authorize in flight, not only the last: concurrent calls each hold a
  // read, and dispose() must end and await all of them.
  const inFlight = new Map<AbortController, Promise<void>>();
  const disposedCalls = new WeakSet<AbortController>();
  return {
    async authorize(request) {
      if (disposed) {
        throw loginFailure({ outcome: 'disposed', strategy: 'manual' });
      }
      const controller = new AbortController();
      // The request's signal — the attempt's (spec §6b) — and the strategy's
      // own both end the read; an already-aborted one is honoured.
      const requestSignal = signalOf(request);
      const signals = [options.signal, requestSignal];
      const relay = () => controller.abort();
      for (const signal of signals) {
        signal?.addEventListener('abort', relay, { once: true });
      }
      if (signals.some((signal) => signal?.aborted)) controller.abort();
      const working = (async () => {
        if (controller.signal.aborted) throw abortedLogin('manual');
        return await run(request, (prompt) => read(prompt, controller.signal));
      })();
      inFlight.set(
        controller,
        working.then(
          () => undefined,
          () => undefined,
        ),
      );
      try {
        const outcome = await working;
        if (!controller.signal.aborted) return outcome;
      } catch (error) {
        if (!controller.signal.aborted) throw error;
      } finally {
        for (const signal of signals) {
          signal?.removeEventListener('abort', relay);
        }
        inFlight.delete(controller);
      }
      // Aborted: by dispose() (K15), else by a signal (K4).
      throw disposedCalls.has(controller) &&
        !signals.some((signal) => signal?.aborted)
        ? loginFailure({ outcome: 'disposed', strategy: 'manual' })
        : abortedLogin('manual');
    },
    // Idempotent; ends every authorization in flight and resolves only once
    // each call's read has settled — whatever the reader holds released.
    async dispose() {
      disposed = true;
      const calls = [...inFlight];
      for (const [controller] of calls) {
        disposedCalls.add(controller);
        controller.abort();
      }
      await Promise.all(calls.map(([, done]) => done));
    },
  };
}

/**
 * Sends the user to the authorization URL: shown only as `promptableUrl`
 * admits it (it may come from discovery or configuration), else named in
 * fixed words. One line per prompt: no line break inside a line.
 */
function promptForUrl(logger: ILogger | undefined, url: string): void {
  const announce = announcer(logger);
  const shownUrl = promptableUrl(url);
  if (shownUrl === undefined) {
    announce('The authorization URL is not an http(s) URL that can be shown.');
    return;
  }
  announce('Open this URL to authenticate:');
  announce(shownUrl);
}

/** The user copies the `code` out of the address bar after the redirect. */
export function manualPasteStrategy(
  options: ManualStrategyOptions = {},
): IAuthorizationStrategy<string> {
  // Read once as own data: a hostile object throws nothing of its own.
  const own = ownOptions<ManualStrategyOptions>(options);
  const redirectUri = own.redirectUri ?? defaultRedirectUri();
  return manualStrategy(own, async (request, read) => {
    const url = await request.buildAuthorizationUrl(redirectUri);
    promptForUrl(request.logger, url);
    const raw = await read(
      'Paste the authorization code (or the whole redirected URL): ',
    );
    const code = extractCode(raw);
    if (!code) {
      throw loginFailure({ outcome: 'unreadable-input' });
    }
    return { payload: code, redirectUri };
  });
}

/** The user lifts `SAMLResponse` from the POST body — it never reaches the URL. */
export function manualSamlResponseStrategy(
  options: ManualStrategyOptions = {},
): IAuthorizationStrategy<string> {
  // Read once as own data: a hostile object throws nothing of its own.
  const own = ownOptions<ManualStrategyOptions>(options);
  const redirectUri = own.redirectUri ?? defaultRedirectUri();
  return manualStrategy(own, async (request, read) => {
    const url = await request.buildAuthorizationUrl(redirectUri);
    promptForUrl(request.logger, url);
    const raw = await read(
      'Paste the SAMLResponse (from the POST body — it is not in the address bar): ',
    );
    const assertion = raw.trim();
    if (!assertion) throw loginFailure({ outcome: 'no-input' });
    return { payload: assertion, redirectUri };
  });
}

/**
 * The UAA passcode, typed in by the user: shows where to fetch it —
 * `<uaa>/passcode`, opened in any browser, on any machine — and reads the
 * code they copy from that page. The default for `UaaPasscodeProvider`, so a
 * login works on a machine with no browser at all, as `cf login --sso` does.
 */
export function manualPasscodeStrategy(
  options: ManualStrategyOptions = {},
): IAuthorizationStrategy<string> {
  // Read once as own data: a hostile object throws nothing of its own.
  const own = ownOptions<ManualStrategyOptions>(options);
  const redirectUri = own.redirectUri ?? defaultRedirectUri();
  return manualStrategy(own, async (request, read) => {
    const url = await request.buildAuthorizationUrl(redirectUri);
    promptForUrl(request.logger, url);
    const code = (
      await read('Paste the Temporary Authentication Code (passcode): ')
    ).trim();
    if (!code) throw loginFailure({ outcome: 'no-input' });
    return { payload: code, redirectUri };
  });
}
