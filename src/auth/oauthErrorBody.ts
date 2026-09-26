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
 * Removes what a server might echo back: every secret the request itself
 * sent (a refresh token, an assertion, a client secret), in each form it may
 * come back in, and any JWT.
 * Every known secret is redacted, however short: nothing guarantees a client
 * secret is long, and dropping a matching word from a diagnosis is the lesser
 * harm.
 */
function redact(
  text: string,
  secrets: readonly (string | undefined)[],
): string {
  let out = text;
  for (const secret of secrets) {
    if (!secret) continue;
    // As sent, as the request body encoded it (URLSearchParams: + / = become
    // %2B %2F %3D), and percent-encoded: a server may echo any of these.
    const forms = new Set([
      secret,
      new URLSearchParams({ s: secret }).toString().slice(2),
      encodeURIComponent(secret),
    ]);
    for (const form of forms) out = out.split(form).join('<redacted>');
  }
  return out.replace(JWT_SHAPE, '<redacted jwt>');
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
    parts.push(quote(redact(error, knownSecrets), ERROR_CAP));
  if (typeof error_description === 'string') {
    parts.push(quote(redact(error_description, knownSecrets), DESCRIPTION_CAP));
  }
  return parts.length > 0 ? parts.join(': ') : 'no error given';
}
