/**
 * The terminal compositions: the URL shown on stderr, the
 * answer pasted at a prompt. Each returns `composeAuthorization(…)`.
 *
 * | Name | Transport | Protocol |
 * |---|---|---|
 * | `manualPasteStrategy` | `terminalPaste({ redirectUri, read })` | `oauthCode()` |
 * | `manualSamlResponseStrategy` | `terminalPaste({ redirectUri, read })` | `samlResponse()` |
 * | `manualPasscodeStrategy` | `terminalPaste({ read })` | `passcode()` |
 *
 * A transport with no socket advertises no redirect of its own: the
 * code and SAML ones require the redirect registered with the identity
 * provider; the passcode page takes none.
 */

import { ownOptions, requiredFieldsMissing } from '../auth/configuration';
import { asAbortSignal } from '../auth/signalledRequest';
import {
  type ComposedStrategy,
  composeAuthorization,
} from '../authorization/compose';
import { showUrl } from '../authorization/presentation';
import { oauthCode, passcode, samlResponse } from '../authorization/protocol';
import {
  readFromTerminal,
  type TerminalRead,
  terminalPaste,
} from '../authorization/transport';
import { CALLBACK_ENDPOINT } from './defaults';

export { readFromTerminal };

export interface ManualPasscodeStrategyOptions {
  /**
   * Where the pasted value comes from. Defaults to an interactive stdin read.
   * The signal aborts when the login is aborted or the strategy disposed; the
   * reader must then stop and release what it holds — the strategy settles
   * only once the reader has, so a reader that ignores it blocks the next
   * login.
   */
  read?: TerminalRead | undefined;
  /**
   * Ends every login of this strategy, beside the request's own signal (the
   * attempt's): either one aborting ends it `aborted`. There is no other
   * bound — compose `AbortSignal.timeout(ms)` for a deadline.
   */
  signal?: AbortSignal | undefined;
}

export interface ManualStrategyOptions extends ManualPasscodeStrategyOptions {
  /**
   * Required: the redirect registered with the identity provider (the ACS
   * for SAML) — the authorization request advertises it and the exchange
   * sends it.
   */
  redirectUri: string;
}

type Own = Partial<Record<keyof ManualStrategyOptions, unknown>>;

/** The consumer's redirect: required. */
function registeredRedirect(own: Own): string {
  if (own.redirectUri === undefined) {
    throw requiredFieldsMissing(['redirectUri']);
  }
  return own.redirectUri as string;
}

const signalOf = (own: Own) => asAbortSignal(own.signal);

/** The user copies the `code` out of the address bar after the redirect. */
export function manualPasteStrategy(
  options: ManualStrategyOptions,
): ComposedStrategy<string> {
  // Read once as own data: a hostile object throws nothing of its own.
  const own = ownOptions<Own>(options);
  return composeAuthorization({
    presentation: showUrl(),
    transport: terminalPaste({
      redirectUri: registeredRedirect(own),
      read: own.read as TerminalRead | undefined,
    }),
    protocol: oauthCode(),
    endpoint: CALLBACK_ENDPOINT,
    signal: signalOf(own),
  });
}

/** The user lifts `SAMLResponse` from the POST body — it never reaches the URL. */
export function manualSamlResponseStrategy(
  options: ManualStrategyOptions,
): ComposedStrategy<string> {
  const own = ownOptions<Own>(options);
  return composeAuthorization({
    presentation: showUrl(),
    transport: terminalPaste({
      redirectUri: registeredRedirect(own),
      read: own.read as TerminalRead | undefined,
    }),
    protocol: samlResponse(),
    endpoint: CALLBACK_ENDPOINT,
    signal: signalOf(own),
  });
}

/**
 * The UAA passcode, typed in by the user: shows where to fetch it —
 * `<uaa>/passcode`, opened in any browser, on any machine — and reads the
 * code they copy from that page. `UaaPasscodeProvider.fromTerminal` composes
 * it (no provider has a default strategy), so a login works on a machine with
 * no browser at all, as `cf login --sso` does.
 */
export function manualPasscodeStrategy(
  options: ManualPasscodeStrategyOptions = {},
): ComposedStrategy<string> {
  const own = ownOptions<Own>(options);
  return composeAuthorization({
    presentation: showUrl(),
    transport: terminalPaste({ read: own.read as TerminalRead | undefined }),
    protocol: passcode(),
    endpoint: CALLBACK_ENDPOINT,
    signal: signalOf(own),
  });
}
