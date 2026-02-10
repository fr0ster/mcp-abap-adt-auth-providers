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
import * as os from 'node:os';
import * as path from 'node:path';
import {
  AbapServiceKeyStore,
  AbapSessionStore,
} from '@mcp-abap-adt/auth-stores';
import type { ILogger } from '@mcp-abap-adt/interfaces';
import { AUTH_TYPE_AUTHORIZATION_CODE } from '@mcp-abap-adt/interfaces';
import { DefaultLogger, LogLevel } from '@mcp-abap-adt/logger';
import { AuthorizationCodeProvider } from '../../providers/AuthorizationCodeProvider';
import {
  getDestination,
  getServiceKeysDir,
  getSessionsDir,
  hasRealConfig,
  loadTestConfig,
} from '../helpers/configHelpers';
import { canListenOnLocalhost, getAvailablePort } from '../helpers/netHelpers';

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
          browser: 'system', // Use system browser for authentication
          redirectPort: port1,
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
          browser: 'system', // Use system browser if token refresh/login needed
          redirectPort: port2,
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
        browser: 'system', // Use system browser for authentication
        redirectPort,
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
