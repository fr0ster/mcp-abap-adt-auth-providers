/**
 * What of an OAuth error response may reach a log line or an error message.
 *
 * Only RFC 6749 §5.2's `error` and `error_description`, each quoted and capped.
 * A token endpoint's body is otherwise untrusted: a misbehaving server can echo
 * the request or return tokens in it, so it is never serialised whole.
 */

import { quoteUntrusted } from '../validation/signedNode';

export function describeOAuthErrorBody(data: unknown): string {
  if (!data || typeof data !== 'object') return 'no error given';
  const { error, error_description } = data as {
    error?: unknown;
    error_description?: unknown;
  };
  const parts: string[] = [];
  if (typeof error === 'string') parts.push(quoteUntrusted(error));
  if (typeof error_description === 'string') {
    parts.push(quoteUntrusted(error_description));
  }
  return parts.length > 0 ? parts.join(': ') : 'no error given';
}
