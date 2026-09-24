/**
 * The UAA-flavoured providers against a real Cloud Foundry UAA, started by
 * tests/stand/up.sh with the clients and user in tests/stand/uaa.
 *
 * Runs only when UAA_URL is set (`npm run test:stand`). The authorization-code
 * login goes through UAA's own login form, played by formLogin.ts.
 */

import { describe, expect, it, jest } from '@jest/globals';
import type { IAuthorizationStrategy } from '@mcp-abap-adt/interfaces-auth';
import { AuthorizationCodeProvider } from '../../../providers/AuthorizationCodeProvider';
import { ClientCredentialsProvider } from '../../../providers/ClientCredentialsProvider';
import { externalCodeStrategy } from '../../../strategies';
import { authorizeByForm } from './formLogin';

const UAA_URL = process.env.UAA_URL?.replace(/\/+$/, '');
const describeUaa = UAA_URL ? describe : describe.skip;

const USER = { username: 'tester', password: 'tester' };
const CALLBACK = 'http://localhost/callback';

const claims = (jwt: string): Record<string, unknown> =>
  JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString('utf8'));

/** Unsigned, never sent: only its `exp` is read, to force a refresh. */
const expiredJwt = (): string => {
  const encode = (value: object) =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode({ alg: 'none' })}.${encode({ exp: Math.floor(Date.now() / 1000) - 3600 })}.sig`;
};

describeUaa('UAA providers against Cloud Foundry UAA', () => {
  it('ClientCredentialsProvider gets a client token', async () => {
    const tokens = await new ClientCredentialsProvider({
      uaaUrl: UAA_URL as string,
      clientId: 'cc_client',
      clientSecret: 'secret',
    }).getTokens();

    const token = claims(tokens.authorizationToken);
    expect(token.iss).toBe(`${UAA_URL}/oauth/token`);
    expect(token.grant_type).toBe('client_credentials');
    expect(token.client_id).toBe('cc_client');
  });

  describe('AuthorizationCodeProvider', () => {
    const loginThroughUaa = () =>
      externalCodeStrategy({
        redirectUri: CALLBACK,
        provide: async (url) => {
          const back = await authorizeByForm(url, CALLBACK, USER);
          return back.searchParams.get('code') ?? '';
        },
      });

    it('logs the user in through UAA’s login form', async () => {
      const tokens = await new AuthorizationCodeProvider({
        uaaUrl: UAA_URL as string,
        clientId: 'authcode',
        clientSecret: 'secret',
        authorization: loginThroughUaa(),
      }).getTokens();

      const token = claims(tokens.authorizationToken);
      expect(token.iss).toBe(`${UAA_URL}/oauth/token`);
      expect(token.grant_type).toBe('authorization_code');
      expect(token.user_name).toBe('tester');
      expect(tokens.refreshToken).toEqual(expect.any(String));
    });

    it('refreshes without logging in again', async () => {
      const first = await new AuthorizationCodeProvider({
        uaaUrl: UAA_URL as string,
        clientId: 'authcode',
        clientSecret: 'secret',
        authorization: loginThroughUaa(),
      }).getTokens();

      const authorize = jest.fn(async () => {
        throw new Error(
          'the refresh must not reach the authorization strategy',
        );
      });
      const refreshed = await new AuthorizationCodeProvider({
        uaaUrl: UAA_URL as string,
        clientId: 'authcode',
        clientSecret: 'secret',
        accessToken: expiredJwt(),
        refreshToken: first.refreshToken,
        authorization: {
          authorize,
        } as unknown as IAuthorizationStrategy<string>,
      }).getTokens();

      expect(authorize).not.toHaveBeenCalled();
      // UAA keeps the original grant_type in a refreshed token, so the new
      // token is told apart by being new, not by its grant type.
      expect(refreshed.authorizationToken).not.toBe(first.authorizationToken);
      expect(claims(refreshed.authorizationToken).jti).not.toBe(
        claims(first.authorizationToken).jti,
      );
      expect(claims(refreshed.authorizationToken).user_name).toBe('tester');
    });
  });
});
