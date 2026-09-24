/**
 * UaaPasscodeProvider against a real Cloud Foundry UAA — the one-time
 * "Temporary Authentication Code" `cf login --sso` uses, which XSUAA inherits.
 *
 * Runs only when UAA_URL is set (`npm run test:stand`). The user's part —
 * logging in at /passcode in a browser and copying the code — is played by
 * formLogin.ts.
 */

import { describe, expect, it, jest } from '@jest/globals';
import type { IAuthorizationStrategy } from '@mcp-abap-adt/interfaces-auth';
import { UaaPasscodeProvider } from '../../../providers/UaaPasscodeProvider';
import { externalCodeStrategy, staticCodeStrategy } from '../../../strategies';
import { FormBrowser } from './formLogin';

const UAA_URL = process.env.UAA_URL?.replace(/\/+$/, '');
const describeUaa = UAA_URL ? describe : describe.skip;

const USER = { username: 'tester', password: 'tester' };

const claims = (jwt: string): Record<string, unknown> =>
  JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString('utf8'));

/** Unsigned, never sent: only its `exp` is read, to force a refresh. */
const expiredJwt = (): string => {
  const encode = (value: object) =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode({ alg: 'none' })}.${encode({ exp: Math.floor(Date.now() / 1000) - 3600 })}.sig`;
};

/** What the user does: open the page, log in, read the code off it. */
async function passcodeFrom(url: string): Promise<string> {
  const browser = new FormBrowser();
  const page = await browser.submitLogin(await browser.open(url), USER);
  const code = /<samp id="passcode">([^<]+)<\/samp>/.exec(page.html ?? '')?.[1];
  if (!code) throw new Error(`no passcode on ${page.url}`);
  return code;
}

const config = () => ({
  uaaUrl: UAA_URL as string,
  clientId: 'passcode_client',
  clientSecret: 'secret',
});

describeUaa('UaaPasscodeProvider against Cloud Foundry UAA', () => {
  it('sends the user to /passcode and exchanges the code they bring back', async () => {
    const seen: string[] = [];
    const tokens = await new UaaPasscodeProvider({
      ...config(),
      authorization: externalCodeStrategy({
        provide: async (url) => {
          seen.push(url);
          return passcodeFrom(url);
        },
      }),
    }).getTokens();

    expect(seen).toEqual([`${UAA_URL}/passcode`]);
    const token = claims(tokens.authorizationToken);
    expect(token.user_name).toBe('tester');
    expect(token.grant_type).toBe('password');
    expect(tokens.refreshToken).toEqual(expect.any(String));
  });

  it('refreshes without asking the user for another code', async () => {
    const first = await new UaaPasscodeProvider({
      ...config(),
      authorization: externalCodeStrategy({ provide: passcodeFrom }),
    }).getTokens();

    const authorize = jest.fn(async () => {
      throw new Error('the refresh must not ask for a passcode');
    });
    const refreshed = await new UaaPasscodeProvider({
      ...config(),
      accessToken: expiredJwt(),
      refreshToken: first.refreshToken,
      authorization: { authorize } as unknown as IAuthorizationStrategy<string>,
    }).getTokens();

    expect(authorize).not.toHaveBeenCalled();
    expect(refreshed.authorizationToken).not.toBe(first.authorizationToken);
    expect(claims(refreshed.authorizationToken).user_name).toBe('tester');
  });

  it('refuses a code that was already spent', async () => {
    const code = await passcodeFrom(`${UAA_URL}/passcode`);
    await new UaaPasscodeProvider({
      ...config(),
      authorization: staticCodeStrategy({ payload: code }),
    }).getTokens();

    await expect(
      new UaaPasscodeProvider({
        ...config(),
        authorization: staticCodeStrategy({ payload: code }),
      }).getTokens(),
    ).rejects.toThrow(/Invalid passcode/);
  });
});
