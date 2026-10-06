/**
 * Two regexes over foreign input replaced by plain code (the user's rule: no
 * regex in code that reads untrusted input), each pinned against the regex it
 * replaced, run here as the oracle: the JWT payload's base64url → base64 in
 * `BaseTokenProvider.parseExpirationFromJWT`, and the trailing-slash trim of
 * `UaaPasscodeProvider`'s base URL.
 */

import { describe, expect, it } from '@jest/globals';
import { ClientCredentialsProvider } from '../../providers/ClientCredentialsProvider';
import { UaaPasscodeProvider } from '../../providers/UaaPasscodeProvider';
import { staticCodeStrategy } from '../../strategies';

/** The pre-6.0.0 parser, verbatim but for its name: the oracle. */
function parseWithRegex(token: string): number | undefined {
  try {
    const parts = token.split('.');
    const payload = parts[1];
    if (parts.length !== 3 || payload === undefined) return undefined;
    const base64 = payload.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64 + '=='.substring(0, (4 - (base64.length % 4)) % 4);
    const claims = JSON.parse(Buffer.from(padded, 'base64').toString('utf8'));
    if (typeof claims.exp === 'number' && Number.isFinite(claims.exp)) {
      return claims.exp * 1000;
    }
  } catch {
    // undefined
  }
  return undefined;
}

class Probe extends ClientCredentialsProvider {
  parse(token: string): number | undefined {
    return this.parseExpirationFromJWT(token);
  }
}

const jwtOf = (claims: object): string =>
  `e30.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.sig`;

describe('parseExpirationFromJWT without a regex', () => {
  const probe = new Probe({
    uaaUrl: 'https://uaa',
    clientId: 'cid',
    clientSecret: 'secret',
  });
  it.each([
    // '-' and '_' in the payload: `>?` and `??~` encode to them.
    ['url-safe characters', jwtOf({ exp: 1_700_000_000, note: '>>>???~~~' })],
    ['padding of 1', jwtOf({ exp: 1 })],
    ['padding of 2', jwtOf({ exp: 12 })],
    ['no padding', jwtOf({ exp: 123 })],
    ['exp 0', jwtOf({ exp: 0 })],
    ['no exp', jwtOf({ sub: 'x' })],
    ['a string exp', jwtOf({ exp: '1' })],
    ['two parts', 'a.b'],
    ['garbage payload', 'a.!!!.c'],
    ['raw - and _', 'a.-_-_.c'],
    ['empty', ''],
  ])('%s: the same as the regex', (_name, token) => {
    expect(probe.parse(token)).toBe(parseWithRegex(token));
  });
});

describe("UaaPasscodeProvider's base URL without a regex", () => {
  it.each([
    'https://uaa',
    'https://uaa/',
    'https://uaa///',
    'https://uaa/path/',
    'https://uaa/a//b//',
    '/',
    '',
  ])('%p: the same as the regex', (uaaUrl) => {
    const provider = new UaaPasscodeProvider({
      uaaUrl,
      clientId: 'cf',
      authorization: staticCodeStrategy({ payload: 'p' }),
    });
    expect((provider as unknown as { baseUrl: string }).baseUrl).toBe(
      uaaUrl.replace(/\/+$/, ''),
    );
  });
});
