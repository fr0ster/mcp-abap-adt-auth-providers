/**
 * A token request that failed: what a caller may safely know of it, as
 * properties — the HTTP `status`, an allowlisted system or TLS `code`, and the
 * OAuth `error` when it is a registered code (`oauthError`). The server's
 * description, an unregistered code and the transport's text are never
 * properties; the message names only the status and the OAuth summary the
 * site already redacted (`describeOAuthErrorBody`), or fixed words.
 *
 * A consumer can construct one, so `refusal.ts` re-checks every fact against
 * its allowlists before naming it; the constructor keeps only well-typed
 * values.
 */
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
    if (typeof facts.status === 'number' && Number.isInteger(facts.status)) {
      this.status = facts.status;
    }
    if (typeof facts.code === 'string') this.code = facts.code;
    if (typeof facts.oauthError === 'string') {
      this.oauthError = facts.oauthError;
    }
  }
}
