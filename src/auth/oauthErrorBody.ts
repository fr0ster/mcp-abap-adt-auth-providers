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

export function describeOAuthErrorBody(data: unknown): string {
  if (!data || typeof data !== 'object') return 'no error given';
  const { error, error_description } = data as {
    error?: unknown;
    error_description?: unknown;
  };
  const parts: string[] = [];
  if (typeof error === 'string') parts.push(quote(error, ERROR_CAP));
  if (typeof error_description === 'string') {
    parts.push(quote(error_description, DESCRIPTION_CAP));
  }
  return parts.length > 0 ? parts.join(': ') : 'no error given';
}
