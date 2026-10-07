/**
 * Login CSRF (spec §6a1): the secrets that bind a callback to the login that
 * asked for it — the OAuth `state` and the paste form's token — minted here,
 * compared here in constant time, and read from URLs with `URL` /
 * `URLSearchParams`, never a regular expression. None of them is logged or
 * put in a refusal.
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { codeFromQuery, extractCode } from './browserAuth';

/** 32 random bytes, base64url: a `state` or a form token, new every call. */
export function mintSecret(): string {
  return randomBytes(32).toString('base64url');
}

const digest = (value: string): Buffer =>
  createHash('sha256').update(value, 'utf8').digest();

/**
 * Whether `given` is the `expected` secret. Both are hashed first, so the
 * comparison runs over two equal-length buffers whatever was sent, and
 * `timingSafeEqual` takes the same time wherever they differ. Anything but a
 * string (absent, repeated as an array) is not the secret.
 */
export function sameSecret(expected: string, given: unknown): boolean {
  if (typeof given !== 'string') return false;
  return timingSafeEqual(digest(expected), digest(given));
}

/**
 * The `state` an authorization URL carries: a string, `null` when it carries
 * none, `undefined` when the URL does not parse.
 */
export function urlState(url: string): string | null | undefined {
  try {
    return new URL(url).searchParams.get('state');
  } catch {
    return undefined;
  }
}

/**
 * What a pasted input yields (spec §6a1): a code, or why none is taken.
 * `state` — a redirected URL whose `state` is not the expected one;
 * `unreadable` — no code could be read.
 */
export type PasteReading =
  | { readonly code: string }
  | { readonly refused: 'state' | 'unreadable' };

/** A character that makes a pasted input more than a bare code. */
const NOT_BARE = new Set(['?', '&', '=', '/', '#']);

/**
 * Reads a pasted input for a login whose URL carried `expected` (`null` or
 * `undefined`: no `state`, nothing to compare). A bare code — none of `?`,
 * `&`, `=`, `/`, `#` — is taken as typed. Anything else is a redirected URL,
 * parsed with `URL`: its query's `state` must be the expected one, and its
 * code is read from the query alone (never a fragment). Only for a URL
 * without `state` does the lenient reading of 5.x (`code=…` and the like)
 * still apply.
 */
export function readPaste(
  expected: string | null | undefined,
  input: string,
): PasteReading {
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
    return { refused: typeof expected === 'string' ? 'state' : 'unreadable' };
  }
  if (typeof expected === 'string') {
    if (!sameSecret(expected, url.searchParams.get('state'))) {
      return { refused: 'state' };
    }
    const code = codeFromQuery(url.search);
    return typeof code === 'string' ? { code } : { refused: 'unreadable' };
  }
  const code = extractCode(trimmed);
  return code === null ? { refused: 'unreadable' } : { code };
}
