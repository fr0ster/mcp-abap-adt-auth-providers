/**
 * No token request carries a Basic credential the redaction does not know:
 * outside `legacyBasic` (`tokenRequest.ts`) and `clientSecretBasic`
 * (`clientSecret.ts`), no file in `src` writes a `Basic ` header or
 * base64-encodes a value. `BasicAuthProvider` is a user's credential presented
 * to the ABAP system, not a token request; the SAML AuthnRequest and PKCE
 * encode no secret of the client.
 */

import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { describe, expect, it } from '@jest/globals';

const SRC = join(__dirname, '..', '..');

function sources(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory())
      return entry.name === '__tests__' ? [] : sources(path);
    return entry.name.endsWith('.ts') ? [path] : [];
  });
}

/** The code without its comments: a comment may quote a header. */
function code(text: string): string {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split('\n')
    .filter((line) => !line.trim().startsWith('//'))
    .join('\n');
}

const BASIC_HEADER = /[`'"]Basic\s/;
const BASE64 = /toString\(\s*['"]base64['"]\s*\)/;

/** Where each is allowed, and why. */
const BASIC_ALLOWED = new Set([
  'clientAuthentication/clientSecret.ts', // clientSecretBasic
  'credentials/BasicAuthProvider.ts', // not a token request
]);
const BASE64_ALLOWED = new Set([
  ...BASIC_ALLOWED,
  'auth/saml2Auth.ts', // the AuthnRequest
  'auth/oidcPkce.ts', // random bytes and their hash
]);

const LEGACY_BASIC = /export function legacyBasic\([\s\S]*?\n}\n/;

const files = sources(SRC).map((path) => ({
  name: relative(SRC, path).split(sep).join('/'),
  text: code(readFileSync(path, 'utf8')),
}));

describe('a Basic header is built only where its secrets are known', () => {
  it('legacyBasic and clientSecretBasic build one (the scan is not vacuous)', () => {
    const tokenRequest = files.find((f) => f.name === 'auth/tokenRequest.ts');
    const body = tokenRequest?.text.match(LEGACY_BASIC)?.[0] ?? '';
    expect(BASIC_HEADER.test(body)).toBe(true);
    expect(BASE64.test(body)).toBe(true);
    const clientSecret = files.find(
      (f) => f.name === 'clientAuthentication/clientSecret.ts',
    );
    expect(BASIC_HEADER.test(clientSecret?.text ?? '')).toBe(true);
  });

  it('no other file writes a Basic header or base64-encodes a value', () => {
    const offenders = files.flatMap(({ name, text }) => {
      const rest =
        name === 'auth/tokenRequest.ts' ? text.replace(LEGACY_BASIC, '') : text;
      return [
        ...(BASIC_HEADER.test(rest) && !BASIC_ALLOWED.has(name)
          ? [`${name}: a Basic header`]
          : []),
        ...(BASE64.test(rest) && !BASE64_ALLOWED.has(name)
          ? [`${name}: base64`]
          : []),
      ];
    });
    expect(offenders).toEqual([]);
  });
});
