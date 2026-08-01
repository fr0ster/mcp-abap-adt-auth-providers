/**
 * Integration tests for AuthorizationCodeProvider
 * Tests with real service keys and session files from test-config.yaml
 *
 * Test scenarios:
 * 1. Only service key (no session) - should login via browser
 * 2. Service key + fresh session - should use token from session
 * 3. Service key + expired session + expired refresh token - should login via browser
 */

import * as dns from 'node:dns/promises';
import * as fs from 'node:fs';
import httpModule from 'node:http';
import netModule from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import { jest } from '@jest/globals';
import {
  AbapServiceKeyStore,
  AbapSessionStore,
} from '@mcp-abap-adt/auth-stores';
import type { IAuthorizationStrategy, ILogger } from '@mcp-abap-adt/interfaces';
import { AUTH_TYPE_AUTHORIZATION_CODE } from '@mcp-abap-adt/interfaces';
import { DefaultLogger, LogLevel } from '@mcp-abap-adt/logger';
import { AuthorizationCodeProvider } from '../../providers/AuthorizationCodeProvider';
import {
  BrowserCallbackStrategy,
  browserCallbackStrategy,
  DEFAULT_CALLBACK_PORT,
  staticCodeStrategy,
} from '../../strategies';
import {
  getDestination,
  getServiceKeysDir,
  getSessionsDir,
  hasRealConfig,
  loadTestConfig,
} from '../helpers/configHelpers';
import {
  canListenOnLocalhost,
  canOwnPort,
  getAvailablePort,
} from '../helpers/netHelpers';

// Helper to create logger if DEBUG_PROVIDER is enabled
function createTestLogger(): ILogger | undefined {
  if (process.env.DEBUG_PROVIDER === 'true') {
    return new DefaultLogger(LogLevel.DEBUG);
  }
  return undefined;
}

// Helper to create expired JWT token
const createExpiredJWT = (): string => {
  const header = Buffer.from(
    JSON.stringify({ alg: 'RS256', typ: 'JWT' }),
  ).toString('base64url');
  const payload = Buffer.from(
    JSON.stringify({ exp: Math.floor(Date.now() / 1000) - 3600 }), // Expired 1 hour ago
  ).toString('base64url');
  return `${header}.${payload}.signature`;
};

// Helper to create valid JWT token
const createValidJWT = (): string => {
  const header = Buffer.from(
    JSON.stringify({ alg: 'RS256', typ: 'JWT' }),
  ).toString('base64url');
  const payload = Buffer.from(
    JSON.stringify({ exp: Math.floor(Date.now() / 1000) + 3600 }), // Valid for 1 hour
  ).toString('base64url');
  return `${header}.${payload}.signature`;
};

// Helper to validate token expiration
// Returns true if token is valid (not expired), false otherwise
const validateTokenExpiration = (token: string): boolean => {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return false;
    }

    // Decode payload
    const payload = parts[1];
    const base64 = payload.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64 + '=='.substring(0, (4 - (base64.length % 4)) % 4);
    const decoded = Buffer.from(padded, 'base64').toString('utf8');
    const claims = JSON.parse(decoded);

    if (!claims.exp) {
      return false;
    }

    // Add 60 second buffer to account for clock skew and network latency
    const bufferMs = 60 * 1000;
    const expiresAt = claims.exp * 1000; // Convert to milliseconds
    return Date.now() < expiresAt - bufferMs;
  } catch {
    return false;
  }
};

const canResolveHost = async (url: string): Promise<boolean> => {
  try {
    const hostname = new URL(url).hostname;
    await dns.lookup(hostname);
    return true;
  } catch {
    return false;
  }
};

describe('AuthorizationCodeProvider', () => {
  const config = loadTestConfig();
  const destination = getDestination(config);
  const serviceKeysDir = getServiceKeysDir(config);
  const sessionsDir = getSessionsDir(config);
  const hasRealConfigValue = hasRealConfig(config);

  describe('Scenario 1 & 2: Token lifecycle', () => {
    it('should login via browser and reuse token from Scenario 1', async () => {
      if (!hasRealConfigValue) {
        console.warn('⚠️  Skipping integration test - no real config');
        return;
      }

      if (!destination || !serviceKeysDir) {
        console.warn('⚠️  Skipping integration test - missing required config');
        return;
      }

      // Use temporary session directory to avoid affecting real sessions
      const tempSessionsDir = path.join(
        os.tmpdir(),
        `test-sessions-${Date.now()}`,
      );
      fs.mkdirSync(tempSessionsDir, { recursive: true });

      try {
        const serviceKeyStore = new AbapServiceKeyStore(serviceKeysDir);
        const sessionStore = new AbapSessionStore(tempSessionsDir);

        // Ensure no session exists
        try {
          await sessionStore.deleteSession(destination);
        } catch {
          // Session doesn't exist, that's fine
        }

        const authConfig =
          await serviceKeyStore.getAuthorizationConfig(destination);
        if (!authConfig) {
          throw new Error(
            'Failed to load authorization config from service key',
          );
        }
        if (!(await canResolveHost(authConfig.uaaUrl!))) {
          console.warn(
            '⚠️  Skipping integration test - UAA host not resolvable',
          );
          return;
        }
        if (!(await canListenOnLocalhost())) {
          console.warn(
            '⚠️  Skipping integration test - cannot bind to localhost',
          );
          return;
        }

        // Create provider with only service key (no session tokens)
        // Use unique port for this test to avoid conflicts
        const logger = createTestLogger();
        const port1 = await getAvailablePort();
        const port2 = await getAvailablePort();
        const provider = new AuthorizationCodeProvider({
          uaaUrl: authConfig.uaaUrl!,
          clientId: authConfig.uaaClientId!,
          clientSecret: authConfig.uaaClientSecret!,
          // Use the system browser for authentication
          authorization: browserCallbackStrategy({
            browser: 'system',
            port: port1,
          }),
          logger,
        });

        // Provider should attempt login via browser
        const tokens1 = await provider.getTokens();
        expect(tokens1.authorizationToken).toBeDefined();
        expect(tokens1.authType).toBe(AUTH_TYPE_AUTHORIZATION_CODE);

        // Validate that new token is valid and not expired
        const isValid1 = validateTokenExpiration(tokens1.authorizationToken);
        expect(isValid1).toBe(true);

        // Wait a bit for server to fully close and port to be freed
        await new Promise((resolve) => setTimeout(resolve, 500));

        // Scenario 2: Use token from Scenario 1 - should use cached token
        const provider2 = new AuthorizationCodeProvider({
          uaaUrl: authConfig.uaaUrl!,
          clientId: authConfig.uaaClientId!,
          clientSecret: authConfig.uaaClientSecret!,
          refreshToken: tokens1.refreshToken,
          accessToken: tokens1.authorizationToken, // Use token from Scenario 1
          // Use the system browser if token refresh/login is needed
          authorization: browserCallbackStrategy({
            browser: 'system',
            port: port2,
          }),
          logger,
        });

        const tokens2 = await provider2.getTokens();
        expect(tokens2.authorizationToken).toBeDefined();
        expect(tokens2.authType).toBe(AUTH_TYPE_AUTHORIZATION_CODE);
        // Should use cached token from Scenario 1
        expect(tokens2.authorizationToken).toBe(tokens1.authorizationToken);
        const isValid2 = validateTokenExpiration(tokens2.authorizationToken);
        expect(isValid2).toBe(true);
      } finally {
        // Cleanup
        try {
          fs.rmSync(tempSessionsDir, { recursive: true, force: true });
        } catch {
          // Ignore cleanup errors
        }
      }
    }, 300000); // 5 minutes timeout for manual browser authentication
  });

  describe('Scenario 3: Service key + expired session + expired refresh token', () => {
    it('should login via browser when refresh token is also expired', async () => {
      if (!hasRealConfigValue) {
        console.warn('⚠️  Skipping integration test - no real config');
        return;
      }

      if (!destination || !serviceKeysDir) {
        console.warn('⚠️  Skipping integration test - missing required config');
        return;
      }

      const serviceKeyStore = new AbapServiceKeyStore(serviceKeysDir);

      const authConfig =
        await serviceKeyStore.getAuthorizationConfig(destination);
      if (!authConfig) {
        throw new Error('Failed to load authorization config from service key');
      }
      if (!(await canResolveHost(authConfig.uaaUrl!))) {
        console.warn('⚠️  Skipping integration test - UAA host not resolvable');
        return;
      }
      if (!(await canListenOnLocalhost())) {
        console.warn('⚠️  Skipping integration test - cannot bind to localhost');
        return;
      }

      // Create provider with expired token and invalid refresh token
      const logger = createTestLogger();
      const expiredToken = createExpiredJWT();
      const redirectPort = await getAvailablePort();
      const provider = new AuthorizationCodeProvider({
        uaaUrl: authConfig.uaaUrl!,
        clientId: authConfig.uaaClientId!,
        clientSecret: authConfig.uaaClientSecret!,
        refreshToken: 'invalid-expired-refresh-token', // Invalid refresh token
        accessToken: expiredToken, // Expired token
        // Use the system browser for authentication
        authorization: browserCallbackStrategy({
          browser: 'system',
          port: redirectPort,
        }),
        logger,
      });

      // Provider should attempt refresh, fail, then attempt login via browser
      const tokens = await provider.getTokens();
      expect(tokens.authorizationToken).toBeDefined();
      expect(tokens.authType).toBe(AUTH_TYPE_AUTHORIZATION_CODE);

      // Validate that new token is valid and not expired
      const isValid = validateTokenExpiration(tokens.authorizationToken);
      expect(isValid).toBe(true);
    }, 300000); // 5 minutes timeout for manual browser authentication
  });

  describe('Token validation', () => {
    it('should validate token expiration correctly', async () => {
      if (!hasRealConfigValue) {
        console.warn('⚠️  Skipping integration test - no real config');
        return;
      }

      if (!destination || !serviceKeysDir) {
        console.warn('⚠️  Skipping integration test - missing required config');
        return;
      }

      const serviceKeyStore = new AbapServiceKeyStore(serviceKeysDir);

      const authConfig =
        await serviceKeyStore.getAuthorizationConfig(destination);
      if (!authConfig) {
        throw new Error('Failed to load authorization config from service key');
      }

      const logger = createTestLogger();
      const provider = new AuthorizationCodeProvider({
        uaaUrl: authConfig.uaaUrl!,
        clientId: authConfig.uaaClientId!,
        clientSecret: authConfig.uaaClientSecret!,
        logger,
      });

      // Test validation of expired token
      const expiredToken = createExpiredJWT();
      const isValidExpired = await provider.validateToken?.(expiredToken);
      expect(isValidExpired).toBe(false);

      // Test validation of valid token
      const validToken = createValidJWT();
      const isValidValid = await provider.validateToken?.(validToken);
      expect(isValidValid).toBe(true);
    }, 30000);
  });
});

/**
 * The provider no longer owns a socket, a browser or a timeout — it owns a URL
 * builder and an exchange. These pin the two consequences that are easy to
 * regress: the guard must fire before anything is opened, and the port must be
 * free the moment the failure surfaces.
 */
describe('AuthorizationCodeProvider with strategies', () => {
  const PORT = 7875;

  function portIsFree(port: number): Promise<boolean> {
    return new Promise((resolve) => {
      const s = netModule.createServer();
      s.once('error', () => resolve(false));
      s.listen(port, () => s.close(() => resolve(true)));
    });
  }

  it('leaves the callback port free the moment a login times out', async () => {
    const provider = new AuthorizationCodeProvider({
      uaaUrl: 'http://127.0.0.1:9',
      clientId: 'client',
      clientSecret: 'secret',
      authorization: browserCallbackStrategy({
        port: PORT,
        timeoutMs: 1000,
        openUrl: async () => undefined,
      }),
    });

    await expect(provider.getTokens()).rejects.toThrow(/timeout/i);
    expect(await portIsFree(PORT)).toBe(true);
  }, 30000);

  it('rejects a pre-built URL whose redirect does not match, before opening a browser', async () => {
    const openUrl = jest.fn(async () => undefined);
    const provider = new AuthorizationCodeProvider({
      uaaUrl: 'http://127.0.0.1:9',
      clientId: 'client',
      clientSecret: 'secret',
      authorizationUrl:
        'https://uaa.example/oauth/authorize?client_id=c&redirect_uri=http%3A%2F%2Flocalhost%3A3001%2Fcallback&response_type=code',
      authorization: browserCallbackStrategy({
        port: PORT,
        timeoutMs: 30000,
        openUrl,
      }),
    });

    const started = Date.now();
    await expect(provider.getTokens()).rejects.toThrow(
      /redirect_uri.*does not match/i,
    );
    // Not "eventually" — the point of building-time validation is that it does
    // not wait for a callback that can never arrive.
    expect(Date.now() - started).toBeLessThan(5000);
    expect(openUrl).not.toHaveBeenCalled();
    expect(await portIsFree(PORT)).toBe(true);
  }, 30000);

  it('catches the mismatch even from a strategy that never builds a URL', async () => {
    const provider = new AuthorizationCodeProvider({
      uaaUrl: 'http://127.0.0.1:9',
      clientId: 'client',
      clientSecret: 'secret',
      authorizationUrl:
        'https://uaa.example/oauth/authorize?client_id=c&redirect_uri=http%3A%2F%2Flocalhost%3A3001%2Fcallback&response_type=code',
      // Holds its code already, so the builder — and the check inside it —
      // never runs. Without the second net this would reach the exchange and
      // come back as an opaque `invalid_grant`.
      authorization: staticCodeStrategy({
        redirectUri: 'http://localhost:61001/callback',
        payload: 'held-code',
      }),
    });

    await expect(provider.getTokens()).rejects.toThrow(
      /redirect_uri.*but the authorization strategy used/i,
    );
  }, 30000);
});

/**
 * Whoever constructs, disposes.
 *
 * A consumer-supplied strategy may be a long-lived receiver that outlives many
 * logins, so the provider must never destroy it; a default the provider built
 * itself holds a callback port, so it must always be released. Both halves are
 * one `if (!supplied)` away from being silently reversed, which is why they are
 * asserted rather than reasoned about.
 */
describe('AuthorizationCodeProvider strategy lifecycle', () => {
  function portIsFree(port: number): Promise<boolean> {
    return new Promise((resolve) => {
      const s = netModule.createServer();
      s.once('error', () => resolve(false));
      s.listen(port, () => s.close(() => resolve(true)));
    });
  }

  /**
   * A real UAA for the token exchange, so the success path is reached without
   * mocking a module: the exchange is a plain HTTP POST and this answers it.
   */
  function startUaaStub(
    body: Record<string, unknown>,
  ): Promise<{ url: string; close: () => Promise<void> }> {
    return new Promise((resolve) => {
      const server = httpModule.createServer((req, res) => {
        req.resume();
        req.on('end', () => {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(body));
        });
      });
      server.listen(0, '127.0.0.1', () => {
        const { port } = server.address() as netModule.AddressInfo;
        resolve({
          url: `http://127.0.0.1:${port}`,
          close: () =>
            new Promise<void>((done) => {
              server.close(() => done());
            }),
        });
      });
    });
  }

  /** A pre-built URL naming a port the default strategy will not bind. */
  const MISMATCHED_URL =
    'https://uaa.example/oauth/authorize?client_id=c&redirect_uri=http%3A%2F%2Flocalhost%3A3001%2Fcallback&response_type=code';

  /**
   * The failure the mismatch guard produces — or, if this machine happens to
   * hold 61001, the one the port probe produces first. Either ends the login
   * through the same `finally`, which is what these tests are about.
   */
  const DEFAULT_LOGIN_FAILURE = /does not match|already in use/i;

  const reasonFor = (p: Promise<unknown>): Promise<Error | null> =>
    p.then(
      () => null,
      (error: Error) => error,
    );

  it('never disposes a strategy the consumer supplied', async () => {
    const uaa = await startUaaStub({
      access_token: createValidJWT(),
      refresh_token: 'refresh-from-stub',
    });
    // Nothing here should construct a default at all; the class-level spy says
    // so without needing to mock the module the provider imports.
    const defaultDispose = jest.spyOn(
      BrowserCallbackStrategy.prototype,
      'dispose',
    );
    const dispose = jest.fn(async () => undefined);
    const redirectUri = 'http://localhost:61001/callback';
    const supplied: IAuthorizationStrategy<string> = {
      authorize: async (request) => {
        await request.buildAuthorizationUrl(redirectUri);
        return { payload: 'held-code', redirectUri };
      },
      dispose,
    };

    try {
      const provider = new AuthorizationCodeProvider({
        uaaUrl: uaa.url,
        clientId: 'client',
        clientSecret: 'secret',
        authorization: supplied,
      });

      const tokens = await provider.getTokens();
      expect(tokens.authorizationToken).toBeDefined();
      // A receiver the consumer owns must survive the login it served.
      expect(dispose).not.toHaveBeenCalled();
      expect(defaultDispose).not.toHaveBeenCalled();
    } finally {
      defaultDispose.mockRestore();
      await uaa.close();
    }
  }, 30000);

  it('leaves a supplied strategy alone when the login fails too', async () => {
    const dispose = jest.fn(async () => undefined);
    const supplied: IAuthorizationStrategy<string> = {
      authorize: async () => {
        throw new Error('consumer flow cancelled');
      },
      dispose,
    };
    const provider = new AuthorizationCodeProvider({
      uaaUrl: 'http://127.0.0.1:9',
      clientId: 'client',
      clientSecret: 'secret',
      authorization: supplied,
    });

    await expect(provider.getTokens()).rejects.toThrow(
      /consumer flow cancelled/,
    );
    expect(dispose).not.toHaveBeenCalled();
  }, 30000);

  it('disposes the default it constructed, per login, leaving the port free', async () => {
    const defaultDispose = jest.spyOn(
      BrowserCallbackStrategy.prototype,
      'dispose',
    );
    // No `authorization`: the provider builds a browser callback on
    // DEFAULT_CALLBACK_PORT. The pre-built URL names another port, so the guard
    // ends the login in milliseconds rather than after the default 30 s.
    const provider = new AuthorizationCodeProvider({
      uaaUrl: 'http://127.0.0.1:9',
      clientId: 'client',
      clientSecret: 'secret',
      authorizationUrl: MISMATCHED_URL,
    });

    // Probed before the first login: if an unrelated process holds 61001, this
    // login never binds it and cannot release it, so the socket assertions
    // below would be about that process rather than about this code.
    const ownsPort = await canOwnPort(
      DEFAULT_CALLBACK_PORT,
      'AuthorizationCodeProvider disposes the default it constructed',
    );

    try {
      const first = await reasonFor(provider.getTokens());
      expect(first?.message).toMatch(DEFAULT_LOGIN_FAILURE);
      expect(defaultDispose).toHaveBeenCalledTimes(1);
      // The claim that matters is about the socket, not the mock: a settled
      // promise must mean the callback port is genuinely released.
      if (ownsPort) expect(await portIsFree(DEFAULT_CALLBACK_PORT)).toBe(true);

      // `dispose` disables an instance permanently, so a provider holding one
      // default would fail the second login with "has been disposed".
      const second = await reasonFor(provider.getTokens());
      expect(second?.message).toMatch(DEFAULT_LOGIN_FAILURE);
      expect(second?.message).not.toMatch(/disposed/i);
      expect(defaultDispose).toHaveBeenCalledTimes(2);
      if (ownsPort) expect(await portIsFree(DEFAULT_CALLBACK_PORT)).toBe(true);
    } finally {
      defaultDispose.mockRestore();
    }
  }, 30000);

  it('reports the login failure, not the cleanup failure, when dispose throws', async () => {
    const warn = jest.fn();
    const logger = {
      debug: jest.fn(),
      info: jest.fn(),
      warn,
      error: jest.fn(),
    } as unknown as ILogger;
    const defaultDispose = jest
      .spyOn(BrowserCallbackStrategy.prototype, 'dispose')
      .mockImplementation(async () => {
        throw new Error('dispose exploded');
      });
    const provider = new AuthorizationCodeProvider({
      uaaUrl: 'http://127.0.0.1:9',
      clientId: 'client',
      clientSecret: 'secret',
      authorizationUrl: MISMATCHED_URL,
      logger,
    });

    try {
      const error = await reasonFor(provider.getTokens());
      // The reason the login failed survives; the cleanup failure is logged.
      expect(error?.message).toMatch(DEFAULT_LOGIN_FAILURE);
      expect(error?.message).not.toContain('dispose exploded');
      expect(defaultDispose).toHaveBeenCalledTimes(1);
      expect(JSON.stringify(warn.mock.calls)).toContain('dispose exploded');
    } finally {
      defaultDispose.mockRestore();
    }
  }, 30000);
});
