/**
 * A token request that failed: what a caller may safely know of it, as
 * properties — the HTTP `status`, an allowlisted system or TLS `code`, and the
 * OAuth `error` when it is a registered code (`oauthError`). The server's
 * description, an unregistered code and the transport's text are never
 * properties; the message names only the status and a registered code, or
 * fixed words.
 *
 * The constructor keeps a fact only when it passes its allowlist — an integer
 * status, an allowlisted code, a registered OAuth / OIDC code — so the
 * object's own properties and its JSON can be trusted, whoever built it;
 * `refusal.ts` re-checks them anyway before naming them.
 */

import { allowlistedCode, integerStatus } from '../auth/knownCodes';
import { registeredOAuthError } from '../auth/oauthErrorBody';

export class TokenEndpointError extends Error {
  readonly status?: number;
  readonly code?: string;
  readonly oauthError?: string;

  constructor(
    message: string,
    facts: { status?: unknown; code?: unknown; oauthError?: unknown },
    options?: { cause?: unknown },
  ) {
    super(message, options);
    this.name = 'TokenEndpointError';
    Object.setPrototypeOf(this, TokenEndpointError.prototype);
    const status = integerStatus(facts.status);
    if (status !== undefined) this.status = status;
    const code = allowlistedCode(facts.code);
    if (code) this.code = code;
    const oauthError = registeredOAuthError(facts.oauthError);
    if (oauthError) this.oauthError = oauthError;
  }
}
