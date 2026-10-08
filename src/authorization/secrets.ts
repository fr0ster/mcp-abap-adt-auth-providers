/**
 * The secrets that bind an answer to the login that asked for it (spec
 * §6a1, §6d.3): the OAuth `state` a provider mints and the paste form's
 * token a listener mints — minted here and compared here in constant time.
 * None of them is logged or put in an error.
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
