/**
 * The one thing of an OAuth error body this package reads: its `error`, and
 * only when it is a registered code. Nothing scans a body for secrets — the
 * server's free text (`error_description`, `error_uri`) is never read, never
 * logged and never kept; a
 * secret reaches a log line only through `prepareSecret` (`tokenRequest.ts`).
 */

/**
 * The registered OAuth error codes a token endpoint (or the device
 * authorization endpoint) answers with: RFC 6749 §5.2 and §4.1.2.1, RFC 8628
 * §3.5, RFC 6750 §3.1, RFC 8693 §2.2.2, OpenID Connect Core 1.0 §3.1.2.6.
 * Each is a fixed protocol word, never a secret, and control flow reads it
 * (the device poll continues on `authorization_pending` and `slow_down`).
 */
const REGISTERED_ERROR_CODES: ReadonlySet<string> = new Set([
  // RFC 6749 §5.2 — token endpoint
  'invalid_request',
  'invalid_client',
  'invalid_grant',
  'unauthorized_client',
  'unsupported_grant_type',
  'invalid_scope',
  // RFC 6749 §4.1.2.1 — authorization endpoint, also seen from token endpoints
  'access_denied',
  'unsupported_response_type',
  'server_error',
  'temporarily_unavailable',
  // RFC 8628 §3.5 — device access token response
  'authorization_pending',
  'slow_down',
  'expired_token',
  // RFC 6750 §3.1 — bearer token usage
  'invalid_token',
  'insufficient_scope',
  // RFC 8693 §2.2.2 — token exchange
  'invalid_target',
  // OpenID Connect Core 1.0 §3.1.2.6 — authentication error response
  'interaction_required',
  'login_required',
  'account_selection_required',
  'consent_required',
  'invalid_request_uri',
  'invalid_request_object',
  'request_not_supported',
  'request_uri_not_supported',
  'registration_not_supported',
]);

/** The value when it is a registered OAuth / OIDC error code, else undefined. Exact match, no regex. */
export function registeredOAuthError(value: unknown): string | undefined {
  return typeof value === 'string' && REGISTERED_ERROR_CODES.has(value)
    ? value
    : undefined;
}
