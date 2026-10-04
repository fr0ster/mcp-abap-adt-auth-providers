/**
 * What of an OAuth error response may reach a log line or an error message.
 *
 * Only RFC 6749 §5.2's `error` and `error_description`, each quoted and capped.
 * A token endpoint's body is otherwise untrusted: a misbehaving server can echo
 * the request or return tokens in it, so it is never serialised whole.
 * `error_description` is the server's human-readable diagnosis, so it keeps a
 * cap long enough to stay useful (UAA explains assertion refusals in it).
 */

const ERROR_CAP = 64;
const DESCRIPTION_CAP = 512;

const quote = (value: string, cap: number): string =>
  JSON.stringify(value.length > cap ? `${value.slice(0, cap)}…` : value);

/** Anything shaped like a JWT: three base64url segments, the first a header. */
const JWT_SHAPE = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g;

/**
 * A value as a server reading it `application/x-www-form-urlencoded` decodes
 * it (RFC 6749 §2.3.1): `+` a space, `%XX` its byte, the whole value — `&`
 * and `=` are part of it, never a separator. Never throws: a malformed escape
 * stays as it is (WHATWG percent-decoding).
 */
const formDecoded = (value: string): string =>
  new URLSearchParams(`v=${value.replace(/&/g, '%26')}`).get('v') ?? value;

/**
 * Every form a server may echo a secret in: as sent; as a request body
 * encodes it (URLSearchParams: + / = become %2B %2F %3D); percent-encoded;
 * and form-decoded — what a server decoding a raw `Basic` secret read
 * (UAA, Keycloak), and the original of a `'form'`-encoded one.
 */
function echoedForms(secret: string): string[] {
  return [
    secret,
    new URLSearchParams({ s: secret }).toString().slice(2),
    encodeURIComponent(secret),
    formDecoded(secret),
  ];
}

/**
 * Replaces every secret the request itself sent (a refresh token, an
 * assertion, a client secret), in each form it may come back in.
 * Every known secret is redacted, however short: nothing guarantees a client
 * secret is long, and dropping a matching word from a diagnosis is the lesser
 * harm.
 */
function redactKnownSecrets(
  text: string,
  secrets: readonly (string | undefined)[],
): string {
  // Every form of every secret, longest first: a short one (a password, a
  // decoded secret) redacted inside a longer one (an assertion, the secret as
  // sent) would leave the rest of the longer one unrecognisable.
  const forms = [
    ...new Set(
      secrets
        .filter((secret): secret is string => !!secret)
        .flatMap(echoedForms)
        .filter((form) => form !== ''),
    ),
  ].sort((a, b) => b.length - a.length);
  if (forms.length === 0) return text;
  // One pass over the original text: an alternation tries the longest form
  // first at each position, and a marker it writes is never scanned again —
  // replaced one form after another, a short form (`ed`) would be redacted
  // inside the markers the longer ones left, and the text would grow per form.
  const anyForm = new RegExp(forms.map(escapeRegExp).join('|'), 'g');
  return text.replace(anyForm, '<redacted>');
}

const escapeRegExp = (value: string): string =>
  value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * The registered OAuth error codes a token endpoint (or the device
 * authorization endpoint) answers with: RFC 6749 §5.2 and §4.1.2.1, RFC 8628
 * §3.5, RFC 6750 §3.1, RFC 8693 §2.2.2. Each is a fixed protocol word, never
 * a secret, and control flow reads it (the device poll continues on
 * `authorization_pending` and `slow_down`): an `error` exactly equal to one is
 * kept verbatim, because redacting a secret that happens to be a substring
 * (`a` in `authorization_pending`) would rewrite the code itself. Any other
 * `error` value is redacted like every other field.
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

/** The value when it is a registered OAuth / OIDC error code, else undefined. */
export function registeredOAuthError(value: unknown): string | undefined {
  return typeof value === 'string' && REGISTERED_ERROR_CODES.has(value)
    ? value
    : undefined;
}

/** `error` as it may stay: a registered code verbatim, anything else redacted. */
function errorCode(
  value: string,
  secrets: readonly (string | undefined)[],
): string {
  return REGISTERED_ERROR_CODES.has(value) ? value : redact(value, secrets);
}

/** Removes what a server might echo back: every known secret, and any JWT. */
function redact(
  text: string,
  secrets: readonly (string | undefined)[],
): string {
  return redactKnownSecrets(text, secrets).replace(JWT_SHAPE, '<redacted jwt>');
}

/**
 * @param knownSecrets what the request sent that must never come back out:
 *   the refresh token, the assertion, the client secret.
 */
export function describeOAuthErrorBody(
  data: unknown,
  knownSecrets: readonly (string | undefined)[] = [],
): string {
  if (!data || typeof data !== 'object') return 'no error given';
  const { error, error_description } = data as {
    error?: unknown;
    error_description?: unknown;
  };
  const parts: string[] = [];
  if (typeof error === 'string')
    parts.push(quote(errorCode(error, knownSecrets), ERROR_CAP));
  if (typeof error_description === 'string') {
    parts.push(quote(redact(error_description, knownSecrets), DESCRIPTION_CAP));
  }
  return parts.length > 0 ? parts.join(': ') : 'no error given';
}

/** RFC 6749 §5.2's fields of an error response, the only ones kept. */
export interface OAuthErrorFields {
  error?: string;
  error_description?: string;
  error_uri?: string;
}

/**
 * An error body reduced to `error`, `error_description` and `error_uri` (each
 * only when a string), every known secret and any JWT redacted — except an
 * `error` that is a registered code, kept verbatim — what may stay
 * on a thrown error. Anything else a server put in the body (a token, an echo
 * of the request) is dropped; a body that is not an object becomes undefined.
 */
export function oauthErrorFields(
  data: unknown,
  knownSecrets: readonly (string | undefined)[] = [],
): OAuthErrorFields | undefined {
  if (!data || typeof data !== 'object') return undefined;
  const out: OAuthErrorFields = {};
  for (const field of ['error', 'error_description', 'error_uri'] as const) {
    const value = (data as Record<string, unknown>)[field];
    if (typeof value !== 'string') continue;
    out[field] =
      field === 'error'
        ? errorCode(value, knownSecrets)
        : redact(value, knownSecrets);
  }
  return out;
}
