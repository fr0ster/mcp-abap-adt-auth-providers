/**
 * Login CSRF (spec §6a1): the secrets that bind a callback to the login that
 * asked for it — the OAuth `state` and the paste form's token — minted here,
 * compared here in constant time, and read from URLs with `URL` /
 * `URLSearchParams`, never a regular expression. None of them is logged or
 * put in a refusal.
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

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
 * What a pasted input says about `state`: a bare code (no `?`) carries none
 * and is not a redirect; anything with a query is a redirected URL, and its
 * query's `state` (or `null`) is what must match.
 */
export type PastedState =
  | { readonly redirect: false }
  | { readonly redirect: true; readonly state: string | null };

export function pastedState(input: string): PastedState {
  const trimmed = input.trim();
  const query = trimmed.indexOf('?');
  if (query < 0) return { redirect: false };
  const fragment = trimmed.indexOf('#', query);
  const search = trimmed.slice(query + 1, fragment < 0 ? undefined : fragment);
  return { redirect: true, state: new URLSearchParams(search).get('state') };
}

/** Whether a pasted input may be taken for a login whose URL had `expected`. */
export function pasteMatches(
  expected: string | null | undefined,
  input: string,
): boolean {
  if (typeof expected !== 'string') return true;
  const pasted = pastedState(input);
  return !pasted.redirect || sameSecret(expected, pasted.state);
}
