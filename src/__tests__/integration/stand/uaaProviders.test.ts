/**
 * The UAA-flavoured providers against a real Cloud Foundry UAA, started by
 * tests/stand/up.sh with the clients and user in tests/stand/uaa.
 *
 * Runs only when UAA_URL is set (`npm run test:stand`). The authorization-code
 * login goes through UAA's own login form, played by formLogin.ts.
 */

import { beforeAll, describe, expect, it, jest } from '@jest/globals';
import { readFailure } from '@mcp-abap-adt/auth-errors';
import type { IAuthorizationStrategy } from '@mcp-abap-adt/interfaces-auth';
import {
  exchangeCodeForToken,
  getJwtAuthorizationUrl,
} from '../../../auth/browserAuth';
import {
  generatePkceChallenge,
  generatePkceVerifier,
} from '../../../auth/oidcPkce';
import { mintSecret } from '../../../authorization/secrets';
import { AuthorizationCodeProvider } from '../../../providers/AuthorizationCodeProvider';
import { ClientCredentialsProvider } from '../../../providers/ClientCredentialsProvider';
import { refreshThenLogin } from '../../../renewal';
import { externalCodeStrategy } from '../../../strategies';
import { authorizeByForm } from './formLogin';

const UAA_URL = process.env.UAA_URL?.replace(/\/+$/, '');
const describeUaa = UAA_URL ? describe : describe.skip;

/**
 * The issuer UAA puts in its tokens, as its own discovery document states it —
 * not derived from UAA_URL, which may use another port than the committed
 * configuration names.
 */
let uaaIssuer = '';
beforeAll(async () => {
  if (!UAA_URL) return;
  const discovery = await fetch(`${UAA_URL}/.well-known/openid-configuration`);
  uaaIssuer = ((await discovery.json()) as { issuer: string }).issuer;
});

const USER = { username: 'tester', password: 'tester' };
const CALLBACK = 'http://localhost/callback';

const claims = (jwt: string): Record<string, unknown> =>
  JSON.parse(Buffer.from(jwt.split('.')[1]!, 'base64url').toString('utf8'));

/** Unsigned, never sent: only its `exp` is read, to force a refresh. */
const expiredJwt = (): string => {
  const encode = (value: object) =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode({ alg: 'none' })}.${encode({ exp: Math.floor(Date.now() / 1000) - 3600 })}.sig`;
};

describeUaa('UAA providers against Cloud Foundry UAA', () => {
  it('ClientCredentialsProvider gets a client token', async () => {
    const tokens = await new ClientCredentialsProvider({
      renewal: refreshThenLogin(),
      uaaUrl: UAA_URL as string,
      clientId: 'cc_client',
      clientSecret: 'secret',
    }).getTokens();

    const token = claims(tokens.authorizationToken);
    expect(token.iss).toBe(uaaIssuer);
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
      // Spec §6a1: the URL the provider builds carries state and a PKCE
      // challenge, UAA returns the state, and accepts the exchange's verifier.
      const states: Array<{ sent: string | null; back: string | null }> = [];
      const tokens = await new AuthorizationCodeProvider({
        renewal: refreshThenLogin(),
        uaaUrl: UAA_URL as string,
        clientId: 'authcode',
        clientSecret: 'secret',
        authorization: externalCodeStrategy({
          redirectUri: CALLBACK,
          provide: async (url) => {
            const sent = new URL(url);
            expect(sent.searchParams.get('code_challenge_method')).toBe('S256');
            expect(sent.searchParams.get('code_challenge')).toEqual(
              expect.any(String),
            );
            const back = await authorizeByForm(url, CALLBACK, USER);
            states.push({
              sent: sent.searchParams.get('state'),
              back: back.searchParams.get('state'),
            });
            return back.searchParams.get('code') ?? '';
          },
        }),
      }).getTokens();
      expect(states).toHaveLength(1);
      expect(states[0]?.sent).toEqual(expect.any(String));
      expect(states[0]?.back).toBe(states[0]?.sent);

      const token = claims(tokens.authorizationToken);
      expect(token.iss).toBe(uaaIssuer);
      expect(token.grant_type).toBe('authorization_code');
      expect(token.user_name).toBe('tester');
      expect(tokens.refreshToken).toEqual(expect.any(String));
    });

    describe('PKCE (spec §6a1)', () => {
      const config = () =>
        ({
          uaaUrl: UAA_URL as string,
          uaaClientId: 'authcode',
          uaaClientSecret: 'secret',
        }) as Parameters<typeof getJwtAuthorizationUrl>[0];

      /** A code UAA issued for a URL bound to `verifier`'s challenge. */
      const codeFor = async (verifier: string): Promise<string> => {
        const url = getJwtAuthorizationUrl(config(), CALLBACK, {
          state: mintSecret(),
          codeChallenge: generatePkceChallenge(verifier),
        });
        const back = await authorizeByForm(url, CALLBACK, USER);
        return back.searchParams.get('code') ?? '';
      };

      it('accepts the code with its own verifier', async () => {
        const verifier = generatePkceVerifier();
        const tokens = await exchangeCodeForToken(
          config(),
          await codeFor(verifier),
          CALLBACK,
          undefined,
          undefined,
          undefined,
          verifier,
        );
        expect(claims(tokens.accessToken).user_name).toBe('tester');
      });

      // Through the provider, as a login runs: the strategy builds two URLs
      // and answers the code of the first, so the provider exchanges it with
      // the second one's verifier. Without PKCE that code would be taken.
      it('refuses the code exchanged with a wrong verifier', async () => {
        const thrown = await new AuthorizationCodeProvider({
          renewal: refreshThenLogin(),
          uaaUrl: UAA_URL as string,
          clientId: 'authcode',
          clientSecret: 'secret',
          authorization: {
            async authorize(request) {
              const first = await request.buildAuthorizationUrl(CALLBACK);
              await request.buildAuthorizationUrl(CALLBACK);
              const back = await authorizeByForm(first, CALLBACK, USER);
              return {
                payload: back.searchParams.get('code') ?? '',
                redirectUri: CALLBACK,
              };
            },
          },
        })
          .getTokens()
          .catch((e: unknown) => e);
        expect(readFailure(thrown, 'code-exchange')).toMatchObject({
          kind: 'request-failed',
          facts: { problem: 'refused' },
        });
      });

      it('refuses the code exchanged without a verifier', async () => {
        const code = await codeFor(generatePkceVerifier());
        const thrown = await exchangeCodeForToken(
          config(),
          code,
          CALLBACK,
        ).catch((e: unknown) => e);
        expect(readFailure(thrown, 'code-exchange')).toMatchObject({
          kind: 'request-failed',
          facts: { problem: 'refused' },
        });
      });
    });

    it('refreshes without logging in again', async () => {
      const first = await new AuthorizationCodeProvider({
        renewal: refreshThenLogin(),
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
        renewal: refreshThenLogin(),
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
