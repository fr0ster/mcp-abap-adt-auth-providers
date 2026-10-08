/**
 * Reading what binds an answer to its login: the
 * `state` of an authorization URL, one parameter of an answer, and a pasted
 * input — with `URL` / `URLSearchParams` and plain string code, never a
 * regular expression. Nothing read here is logged or put in an error.
 */

import type { AnswerParameters } from '@mcp-abap-adt/interfaces-auth';
import { extractCode } from '../../auth/browserAuth';
import { sameSecret } from '../secrets';

/**
 * The value of `name` when it is present exactly once; `undefined` when it
 * is absent or repeated (a repeated `state` or `code` is no
 * value — never its first).
 */
export function oneValue(
  params: AnswerParameters,
  name: string,
): string | undefined {
  const values = params.getAll(name);
  return values.length === 1 ? values[0] : undefined;
}

/**
 * The `state` an authorization URL carries: a string when it carries exactly
 * one non-empty `state`; `null` when it carries none; `undefined` when the
 * URL does not parse or its `state` is repeated or empty — no state a
 * redirect could be bound to.
 */
export function urlState(url: string): string | null | undefined {
  let params: URLSearchParams;
  try {
    params = new URL(url).searchParams;
  } catch {
    return undefined;
  }
  if (!params.has('state')) return null;
  const state = oneValue(params, 'state');
  return state === undefined || state === '' ? undefined : state;
}

/**
 * What a pasted input yields: a code, or why none is taken.
 * `state` — a redirected URL whose `state` is not the expected one;
 * `unreadable` — no code could be read.
 */
export type PasteReading =
  | { readonly code: string }
  | { readonly refused: 'state' | 'unreadable' };

/** A character that makes a pasted input more than a bare code. */
const NOT_BARE = new Set(['?', '&', '=', '/', '#']);

/**
 * Reads a pasted input for a login whose URL carried `expected` (always one,
 * because a provider adds its own when a configured URL has none). A bare code
 * — none of `?`, `&`, `=`, `/`, `#` — is taken as typed. Anything else is a
 * redirected URL, parsed with `URL`: its query must carry the expected `state`
 * exactly once, and its code is its query's one `code` (never a fragment's).
 */
export function readPaste(expected: string, input: string): PasteReading {
  const trimmed = input.trim();
  if (![...trimmed].some((character) => NOT_BARE.has(character))) {
    const code = extractCode(trimmed);
    return code === null ? { refused: 'unreadable' } : { code };
  }
  let url: URL;
  try {
    // A relative paste (`/callback?code=…`, `?code=…`) resolves against a
    // base that is never used for anything else.
    url = new URL(trimmed, 'http://pasted.invalid/');
  } catch {
    return { refused: 'state' };
  }
  if (!sameSecret(expected, oneValue(url.searchParams, 'state'))) {
    return { refused: 'state' };
  }
  const code = oneValue(url.searchParams, 'code');
  return code === undefined || code === ''
    ? { refused: 'unreadable' }
    : { code };
}
