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
} from '@mcp-abap-adt/interfaces';
import { extractCode } from '../auth/browserAuth';
import { DEFAULT_CALLBACK_PORT } from './BrowserCallbackStrategy';

export interface ManualStrategyOptions {
  /** Must match what the authorization request advertises and the exchange sends. */
  redirectUri?: string;
  /** Where the pasted value comes from. Defaults to an interactive stdin read. */
  read?: (prompt: string) => Promise<string>;
}

const defaultRedirectUri = () =>
  `http://localhost:${DEFAULT_CALLBACK_PORT}/callback`;

/**
 * Reads one line from stdin.
 *
 * The prompt goes to stderr, never stdout, and stdin is touched only when it is
 * a terminal: under a stdio RPC transport those streams carry the protocol.
 */
async function readFromTerminal(prompt: string): Promise<string> {
  if (!process.stdin.isTTY) {
    throw new Error(
      'Manual input needs an interactive terminal. Supply `read` to source the value elsewhere.',
    );
  }
  process.stderr.write(prompt);
  const rl = createInterface({ input: process.stdin });
  try {
    for await (const line of rl) return line.trim();
  } finally {
    rl.close();
  }
  throw new Error('No input received');
}

function announce(request: AuthorizationRequest, url: string): void {
  const message = `Open this URL to authenticate:\n${url}`;
  if (request.logger) request.logger.info(message);
  else process.stderr.write(`${message}\n`);
}

/** The user copies the `code` out of the address bar after the redirect. */
export function manualPasteStrategy(
  options: ManualStrategyOptions = {},
): IAuthorizationStrategy<string> {
  const redirectUri = options.redirectUri ?? defaultRedirectUri();
  const read = options.read ?? readFromTerminal;
  return {
    async authorize(
      request: AuthorizationRequest,
    ): Promise<AuthorizationOutcome<string>> {
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
    },
  };
}

/** The user lifts `SAMLResponse` from the POST body — it never reaches the URL. */
export function manualSamlResponseStrategy(
  options: ManualStrategyOptions = {},
): IAuthorizationStrategy<string> {
  const redirectUri = options.redirectUri ?? defaultRedirectUri();
  const read = options.read ?? readFromTerminal;
  return {
    async authorize(
      request: AuthorizationRequest,
    ): Promise<AuthorizationOutcome<string>> {
      const url = await request.buildAuthorizationUrl(redirectUri);
      announce(request, url);
      const raw = await read(
        'Paste the SAMLResponse (from the POST body — it is not in the address bar): ',
      );
      const assertion = raw.trim();
      if (!assertion) throw new Error('No SAMLResponse was provided');
      return { payload: assertion, redirectUri };
    },
  };
}
