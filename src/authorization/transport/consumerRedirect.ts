/**
 * The redirect a transport without a socket advertises: the
 * consumer's, as given — the one registered with the identity provider —
 * or none. It is never made up here.
 */

import { authError } from '@mcp-abap-adt/auth-errors';
import { misconfigured } from '../../auth/configuration';

/** Not given: `undefined`. Given: an absolute http(s) URL, else refused. */
export function consumerRedirect(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value === 'string') {
    try {
      const { protocol } = new URL(value);
      if (protocol === 'http:' || protocol === 'https:') return value;
    } catch {
      // Not a URL: refused below.
    }
  }
  throw misconfigured(
    authError.configuration({ case: 'invalid-value', fields: ['redirectUri'] }),
  );
}
