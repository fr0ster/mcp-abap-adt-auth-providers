/**
 * The endpoint path a redirect arrives at: the one
 * string a listener serves the redirect at and advertises, so the two
 * cannot differ. It must survive URL parsing unchanged — no encoded dot
 * segment, backslash, space, control character, `?` or `#` — and it is
 * not one of the listener's own routes.
 */

import { authError } from '@mcp-abap-adt/auth-errors';
import { misconfigured } from '../../auth/configuration';

/** The listener's own routes beside the endpoint. */
export const PASTE_PAGE = '/';
export const PASTE_SUBMIT = '/submit';

const BASE = 'http://localhost';

/** Whether `endpoint` is a path a listener can serve exactly as given. */
export function usableEndpoint(endpoint: unknown): endpoint is string {
  if (typeof endpoint !== 'string' || !endpoint.startsWith('/')) return false;
  if (endpoint === PASTE_PAGE || endpoint === PASTE_SUBMIT) return false;
  let url: URL;
  try {
    url = new URL(endpoint, BASE);
  } catch {
    return false;
  }
  return (
    url.origin === BASE &&
    url.pathname === endpoint &&
    url.search === '' &&
    url.hash === ''
  );
}

/** `endpoint`, or `configuration` `invalid-value` `endpoint`. */
export function checkedEndpoint(endpoint: unknown): string {
  if (usableEndpoint(endpoint)) return endpoint;
  throw misconfigured(
    authError.configuration({ case: 'invalid-value', fields: ['endpoint'] }),
  );
}
