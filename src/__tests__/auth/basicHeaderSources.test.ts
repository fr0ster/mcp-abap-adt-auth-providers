/**
 * No token request carries a Basic credential its `sent` does not name:
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

/**
 * Shape rule 8 (spec §8.2, C12; enforced again by the shape-check script in
 * Task 28), scoped to `src/auth` and `src/providers` only: outside
 * `legacyBasic`, no `Basic ` header value (any case, at the start of a
 * string or template) and no base64 encoding of a value whose expression
 * names a secret. `clientSecretBasic` lives outside the scope;
 * `BasicAuthProvider` presents a credential to the ABAP system, not a token
 * request, and is out of scope.
 */
describe('shape rule 8 in src/auth and src/providers', () => {
  const scoped = files.filter(
    ({ name }) => name.startsWith('auth/') || name.startsWith('providers/'),
  );
  const BASIC_VALUE = /[`'"]basic\s/i;
  const SECRET_ENCODED =
    /Buffer\.from\(([^)]*)\)\s*\.toString\(\s*['"]base64(?:url)?['"]\s*\)/g;
  const NAMES_A_SECRET = /secret|password|passcode|credential/i;

  it('the scan sees legacyBasic encode the client secret (not vacuous)', () => {
    const tokenRequest = scoped.find((f) => f.name === 'auth/tokenRequest.ts');
    const body = tokenRequest?.text.match(LEGACY_BASIC)?.[0] ?? '';
    expect(BASIC_VALUE.test(body)).toBe(true);
    const encoded = [...body.matchAll(SECRET_ENCODED)].map((m) => m[1] ?? '');
    expect(encoded.some((argument) => NAMES_A_SECRET.test(argument))).toBe(
      true,
    );
  });

  it('no other place writes a Basic header or base64-encodes a secret', () => {
    expect(scoped.length).toBeGreaterThan(10);
    const offenders = scoped.flatMap(({ name, text }) => {
      const rest =
        name === 'auth/tokenRequest.ts' ? text.replace(LEGACY_BASIC, '') : text;
      const encodedSecrets = [...rest.matchAll(SECRET_ENCODED)]
        .map((m) => m[1] ?? '')
        .filter((argument) => NAMES_A_SECRET.test(argument));
      return [
        ...(BASIC_VALUE.test(rest) ? [`${name}: a Basic header`] : []),
        ...encodedSecrets.map((argument) => `${name}: base64 of ${argument}`),
      ];
    });
    expect(offenders).toEqual([]);
  });
});

/**
 * `TokenEndpointError` is gone with the classes (Task 27, spec §6): neither
 * the class nor a construction of it is anywhere in src.
 */
describe('TokenEndpointError', () => {
  it('nothing in src declares or constructs it', () => {
    const naming = files
      .filter(({ text }) => text.includes('TokenEndpointError'))
      .map(({ name }) => name);
    expect(naming).toEqual([]);
    // Not vacuous: the scan reads src.
    expect(files.length).toBeGreaterThan(10);
  });
});
