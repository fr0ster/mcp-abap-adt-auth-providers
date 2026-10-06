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
import { extractCode } from '../auth/browserAuth';
import { signalOf } from '../auth/signalledRequest';
import { BrowserAuthError } from '../errors/TokenProviderErrors';
import { DEFAULT_CALLBACK_PORT } from './BrowserCallbackStrategy';

export interface ManualStrategyOptions {
  /** Must match what the authorization request advertises and the exchange sends. */
  redirectUri?: string | undefined;
  /**
   * Where the pasted value comes from. Defaults to an interactive stdin read.
   * The signal aborts when the timeout expires or the strategy is disposed.
   */
  read?: ((prompt: string, signal: AbortSignal) => Promise<string>) | undefined;
  /** Milliseconds before the read is abandoned. Absent: no deadline — the consumer's choice. */
  timeoutMs?: number | undefined;
}

const defaultRedirectUri = () =>
  `http://localhost:${DEFAULT_CALLBACK_PORT}/callback`;

/**
 * Reads one line from stdin.
 *
 * The prompt goes to stderr, never stdout, and stdin is touched only when it is
 * a terminal: under a stdio RPC transport those streams carry the protocol.
 * Closes its `readline` when the signal aborts, so a timeout or dispose() ends
 * the wait at once instead of leaving stdin held open.
 */
async function readFromTerminal(
  prompt: string,
  signal: AbortSignal,
): Promise<string> {
  // Aborted before the read began (the deadline passed while the URL was
  // built): no readline, so stdin is never held for a line nobody awaits.
  if (signal.aborted) {
    throw new BrowserAuthError(
      'the manual input was abandoned before it began',
    );
  }
  if (!process.stdin.isTTY) {
    throw new Error(
      'Manual input needs an interactive terminal. Supply `read` to source the value elsewhere.',
    );
  }
  process.stderr.write(prompt);
  const rl = createInterface({ input: process.stdin });
  const abort = () => rl.close();
  signal.addEventListener('abort', abort, { once: true });
  try {
    for await (const line of rl) return line.trim();
  } finally {
    signal.removeEventListener('abort', abort);
    rl.close();
  }
  throw new Error('No input received');
}

function announce(request: AuthorizationRequest, url: string): void {
  const message = `Open this URL to authenticate:\n${url}`;
  if (request.logger) request.logger.info(message);
  else process.stderr.write(`${message}\n`);
}

/**
 * A manual strategy with a deadline and a dispose(): the read gets a signal,
 * and the race settles even when a custom reader ignores it.
 */
function boundedManual(
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
  const inFlight = new Map<
    AbortController,
    Promise<AuthorizationOutcome<string>>
  >();
  return {
    async authorize(request) {
      if (disposed)
        throw new BrowserAuthError('the manual strategy was disposed');
      const controller = new AbortController();
      const timer =
        options.timeoutMs === undefined
          ? undefined
          : setTimeout(() => controller.abort(), options.timeoutMs);
      const abandoned = new Promise<never>((_, reject) => {
        controller.signal.addEventListener(
          'abort',
          () =>
            reject(
              new BrowserAuthError(
                'the manual input did not arrive in time, or the strategy was disposed',
              ),
            ),
          { once: true },
        );
      });
      // The request's signal — the attempt's (spec §6b) — ends the read too;
      // relayed once `abandoned` listens, so an aborted one is honoured.
      const requestSignal = signalOf(request);
      const relay = () => controller.abort();
      requestSignal?.addEventListener('abort', relay, { once: true });
      if (requestSignal?.aborted) controller.abort();
      const working = run(request, (prompt) => read(prompt, controller.signal));
      working.catch(() => {}); // a loser of the race must not surface as unhandled
      const race = Promise.race([working, abandoned]);
      inFlight.set(controller, race);
      try {
        return await race;
      } finally {
        if (timer) clearTimeout(timer);
        requestSignal?.removeEventListener('abort', relay);
        inFlight.delete(controller);
      }
    },
    // Idempotent; ends every authorization in flight and resolves only once
    // each call's own finally — timer, controller, and whatever the reader
    // holds open — has actually run.
    async dispose() {
      disposed = true;
      const calls = [...inFlight];
      for (const [controller] of calls) controller.abort();
      await Promise.all(calls.map(([, race]) => race.catch(() => undefined)));
    },
  };
}

/** The user copies the `code` out of the address bar after the redirect. */
export function manualPasteStrategy(
  options: ManualStrategyOptions = {},
): IAuthorizationStrategy<string> {
  const redirectUri = options.redirectUri ?? defaultRedirectUri();
  return boundedManual(options, async (request, read) => {
    const url = await request.buildAuthorizationUrl(redirectUri);
    announce(request, url);
    const raw = await read(
      'Paste the authorization code (or the whole redirected URL): ',
    );
    const code = extractCode(raw);
    if (!code) {
      throw new Error('Could not read an authorization code from that input');
    }
    return { payload: code, redirectUri };
  });
}

/** The user lifts `SAMLResponse` from the POST body — it never reaches the URL. */
export function manualSamlResponseStrategy(
  options: ManualStrategyOptions = {},
): IAuthorizationStrategy<string> {
  const redirectUri = options.redirectUri ?? defaultRedirectUri();
  return boundedManual(options, async (request, read) => {
    const url = await request.buildAuthorizationUrl(redirectUri);
    announce(request, url);
    const raw = await read(
      'Paste the SAMLResponse (from the POST body — it is not in the address bar): ',
    );
    const assertion = raw.trim();
    if (!assertion) throw new Error('No SAMLResponse was provided');
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
  const redirectUri = options.redirectUri ?? defaultRedirectUri();
  return boundedManual(options, async (request, read) => {
    const url = await request.buildAuthorizationUrl(redirectUri);
    announce(request, url);
    const code = (
      await read('Paste the Temporary Authentication Code (passcode): ')
    ).trim();
    if (!code) throw new Error('No passcode was provided');
    return { payload: code, redirectUri };
  });
}
