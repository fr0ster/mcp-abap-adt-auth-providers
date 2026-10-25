/**
 * The OIDC providers against a real Keycloak, started by tests/stand/up.sh
 * with the `test` realm from tests/stand/keycloak/realm-test.json.
 *
 * Runs only when KEYCLOAK_URL is set (`npm run test:stand`); a plain
 * `npm test` skips it. Interactive logins are performed through Keycloak's own
 * login and consent pages by formLogin.ts, playing the user.
 */

import { describe, expect, it } from '@jest/globals';
import { readFailure } from '@mcp-abap-adt/auth-errors';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { discoverOidc } from '../../../auth/oidcDiscovery';
import {
  initiateDeviceAuthorization,
  pollDeviceTokens,
} from '../../../auth/oidcToken';
import { OidcBrowserProvider } from '../../../providers/OidcBrowserProvider';
import { OidcDeviceFlowProvider } from '../../../providers/OidcDeviceFlowProvider';
import { OidcPasswordProvider } from '../../../providers/OidcPasswordProvider';
import { OidcTokenExchangeProvider } from '../../../providers/OidcTokenExchangeProvider';
import { refreshThenLogin } from '../../../renewal';
import { asOidcResult, externalCodeStrategy } from '../../../strategies';
import { approveDevice, authorizeByForm, denyDevice } from './formLogin';

const KEYCLOAK_URL = process.env.KEYCLOAK_URL?.replace(/\/+$/, '');
const describeKeycloak = KEYCLOAK_URL ? describe : describe.skip;

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

const silentLogger = (onInfo?: (message: string) => void): ILogger => ({
  info: (message: string) => onInfo?.(message),
  error: () => {},
  warn: () => {},
  debug: () => {},
});

describeKeycloak('OIDC providers against Keycloak', () => {
  describe('OidcPasswordProvider', () => {
    it('logs in with the password grant, found through discovery', async () => {
      const tokens = await new OidcPasswordProvider({
        renewal: refreshThenLogin(),
        issuerUrl: KEYCLOAK_URL,
        clientId: 'oidc-password',
        clientSecret: 'secret',
        ...USER,
        scopes: ['openid'],
      }).getTokens();

      expect(claims(tokens.authorizationToken).iss).toBe(KEYCLOAK_URL);
      expect(claims(tokens.authorizationToken).preferred_username).toBe(
        'tester',
      );
      expect(tokens.refreshToken).toEqual(expect.any(String));
    });

    it('refreshes with the refresh token rather than the password', async () => {
      const first = await new OidcPasswordProvider({
        renewal: refreshThenLogin(),
        issuerUrl: KEYCLOAK_URL,
        clientId: 'oidc-password',
        clientSecret: 'secret',
        ...USER,
        scopes: ['openid'],
      }).getTokens();

      // A wrong password: a fall back to the password grant would fail, so
      // only a refresh can produce a token here.
      const refreshed = await new OidcPasswordProvider({
        renewal: refreshThenLogin(),
        issuerUrl: KEYCLOAK_URL,
        clientId: 'oidc-password',
        clientSecret: 'secret',
        username: 'tester',
        password: 'not-the-password',
        scopes: ['openid'],
        accessToken: expiredJwt(),
        refreshToken: first.refreshToken,
      }).getTokens();

      expect(claims(refreshed.authorizationToken).iss).toBe(KEYCLOAK_URL);
      expect(refreshed.authorizationToken).not.toBe(first.authorizationToken);
    });
  });

  describe('OidcBrowserProvider', () => {
    it('completes authorization code with PKCE through Keycloak’s login page', async () => {
      // oidc-browser is a public client that Keycloak requires to use S256
      // PKCE: a missing or wrong verifier fails the exchange.
      const tokens = await new OidcBrowserProvider({
        renewal: refreshThenLogin(),
        issuerUrl: KEYCLOAK_URL,
        clientId: 'oidc-browser',
        scopes: ['openid'],
        authorization: asOidcResult(
          externalCodeStrategy({
            redirectUri: CALLBACK,
            provide: async (url) => {
              expect(
                new URL(url).searchParams.get('code_challenge_method'),
              ).toBe('S256');
              const back = await authorizeByForm(url, CALLBACK, USER);
              return back.searchParams.get('code') ?? '';
            },
          }),
        ),
      }).getTokens();

      expect(claims(tokens.authorizationToken).iss).toBe(KEYCLOAK_URL);
      expect(claims(tokens.authorizationToken).azp).toBe('oidc-browser');
      expect(tokens.refreshToken).toEqual(expect.any(String));
    });
  });

  describe('OidcDeviceFlowProvider', () => {
    it('gets a token once the user approves the device on Keycloak’s pages', async () => {
      let approval: Promise<void> | undefined;
      const logger = silentLogger((message) => {
        // The provider announces the verification URI through the logger —
        // the same line a user would read.
        const complete = /^Or use: (\S+)/.exec(message)?.[1];
        if (complete && !approval) {
          approval = approveDevice(complete, USER);
        }
      });

      const tokens = await OidcDeviceFlowProvider.toConsole({
        renewal: refreshThenLogin(),
        issuerUrl: KEYCLOAK_URL,
        clientId: 'oidc-device',
        scopes: ['openid'],
        logger,
      }).getTokens();

      await approval;
      expect(approval).toBeDefined();
      expect(claims(tokens.authorizationToken).iss).toBe(KEYCLOAK_URL);
      expect(claims(tokens.authorizationToken).azp).toBe('oidc-device');
    }, 60_000);
  });

  describe('OidcTokenExchangeProvider', () => {
    it('exchanges another client’s access token for its own (RFC 8693)', async () => {
      const subject = await new OidcPasswordProvider({
        renewal: refreshThenLogin(),
        issuerUrl: KEYCLOAK_URL,
        clientId: 'te-subject',
        clientSecret: 'secret',
        ...USER,
      }).getTokens();
      expect(claims(subject.authorizationToken).azp).toBe('te-subject');

      const exchanged = await new OidcTokenExchangeProvider({
        renewal: refreshThenLogin(),
        issuerUrl: KEYCLOAK_URL,
        clientId: 'te-requester',
        clientSecret: 'secret',
        subjectToken: subject.authorizationToken,
        subjectTokenType: 'urn:ietf:params:oauth:token-type:access_token',
      }).getTokens();

      expect(claims(exchanged.authorizationToken).iss).toBe(KEYCLOAK_URL);
      expect(claims(exchanged.authorizationToken).azp).toBe('te-requester');
      expect(claims(exchanged.authorizationToken).preferred_username).toBe(
        'tester',
      );
    });
  });
});

/**
 * Device polling against Keycloak's own device endpoint: the poll reads the
 * failure's classified facts — `authorization_pending` and `slow_down` keep it
 * waiting (`slow_down` adding 5 s), anything else ends it with that failure.
 * Where the stand can produce the answer: pending, slow_down and access_denied;
 * an expired device code (600 s) and a 400 without a body are covered on the
 * axios mock (`devicePoll.test.ts`).
 */
describeKeycloak('device polling against Keycloak', () => {
  /** A device authorization and a logger that approves (or denies) on the first wait. */
  async function polling(
    answer: 'approve' | 'deny',
    interval?: number,
  ): Promise<{ result: Promise<unknown>; waits: number[] }> {
    const discovery = await discoverOidc(KEYCLOAK_URL as string);
    const deviceEndpoint = discovery.device_authorization_endpoint;
    if (deviceEndpoint === undefined) throw new Error('no device endpoint');
    const device = await initiateDeviceAuthorization(
      deviceEndpoint,
      'oidc-device',
      'openid',
    );
    const complete = device.verificationUriComplete;
    if (complete === undefined) throw new Error('no complete verification URI');
    const waits: number[] = [];
    let user: Promise<void> | undefined;
    const logger: ILogger = {
      info: () => {},
      warn: () => {},
      error: () => {},
      debug: (message: string, meta?: unknown) => {
        if (message !== '[OIDC] Device authorization pending') return;
        waits.push((meta as { wait: number }).wait);
        // The user acts once the poll has seen what the case is about.
        const ready = interval === 0 ? waits.includes(5) : true;
        if (ready && !user) {
          user =
            answer === 'approve'
              ? approveDevice(complete, USER)
              : denyDevice(complete, USER);
        }
      },
    };
    const result = pollDeviceTokens(
      discovery.token_endpoint,
      'oidc-device',
      undefined,
      device.deviceCode,
      interval ?? device.interval ?? 5,
      logger,
    ).finally(() => user);
    return { result, waits };
  }

  it('authorization_pending, then the user approves: a token', async () => {
    const { result, waits } = await polling('approve');
    const tokens = (await result) as { accessToken: string };
    expect(claims(tokens.accessToken).azp).toBe('oidc-device');
    expect(waits.length).toBeGreaterThan(0);
  }, 60_000);

  it('slow_down when polled faster than the interval: the next wait is 5 s longer', async () => {
    const { result, waits } = await polling('approve', 0);
    const tokens = (await result) as { accessToken: string };
    expect(claims(tokens.accessToken).azp).toBe('oidc-device');
    // Interval 0: pending waits 0; Keycloak's slow_down makes it 0 + 5.
    expect(waits).toContain(5);
  }, 60_000);

  it('access_denied when the user refuses: request-failed carrying it, at once', async () => {
    const { result } = await polling('deny');
    const thrown = await result.then(
      () => undefined,
      (error: unknown) => error,
    );
    expect(readFailure(thrown, 'unfamiliar-error').facts).toEqual({
      operation: 'device-poll',
      problem: 'refused',
      status: 400,
      oauthError: 'access_denied',
    });
  }, 60_000);
});
