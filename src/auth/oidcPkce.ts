/**
 * PKCE helpers (RFC 7636, S256): OIDC's and, since 6.0.0, UAA's
 */

import { createHash, randomBytes } from 'node:crypto';

function base64UrlEncode(buffer: Buffer): string {
  return buffer.toString('base64url');
}

export function generatePkceVerifier(length: number = 32): string {
  return base64UrlEncode(randomBytes(length));
}

export function generatePkceChallenge(verifier: string): string {
  const hash = createHash('sha256').update(verifier).digest();
  return base64UrlEncode(hash);
}
