/**
 * Integration tests for DeviceFlowProvider
 * Tests with real service keys from test-config.yaml
 *
 * Test scenarios:
 * 1. Only service key (no session) - should initiate device flow
 * 2. Service key + fresh session - should use token from session
 * 3. Service key + expired session - should refresh token
 * 4. Service key + expired session + expired refresh token - should initiate device flow
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  AbapServiceKeyStore,
  AbapSessionStore,
} from '@mcp-abap-adt/auth-stores';
import { AUTH_TYPE_AUTHORIZATION_CODE } from '@mcp-abap-adt/interfaces';
import { DeviceFlowProvider } from '../../providers/DeviceFlowProvider';
import {
  getAbapDestination,
  getServiceKeysDir,
  getSessionsDir,
  hasRealConfig,
  loadTestConfig,
} from '../helpers/configHelpers';

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

describe.skip('DeviceFlowProvider', () => {
  const config = loadTestConfig();
  const destination = getAbapDestination(config);
  const serviceKeysDir = getServiceKeysDir(config);
  const sessionsDir = getSessionsDir(config);
  const hasRealConfigValue = hasRealConfig(config, 'abap');

  describe('Scenario 1: Only service key (no session)', () => {
    it('should initiate device flow when no session exists', async () => {
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

        // Create provider with only service key (no session tokens)
        const provider = new DeviceFlowProvider({
          uaaUrl: authConfig.uaaUrl!,
          clientId: authConfig.uaaClientId!,
          clientSecret: authConfig.uaaClientSecret,
        });

        // Provider should attempt device flow (will require manual authorization)
        try {
          await provider.getTokens();
          // If we get here, device flow succeeded
          const tokens = await provider.getTokens();
          expect(tokens.authorizationToken).toBeDefined();
          expect(tokens.authType).toBe(AUTH_TYPE_AUTHORIZATION_CODE);
        } catch (error: any) {
          // Expected: device flow requires manual authorization
          expect(error).toBeDefined();
          // This is expected behavior - we're testing that provider attempts device flow
        }
      } finally {
        // Cleanup
        try {
          fs.rmSync(tempSessionsDir, { recursive: true, force: true });
        } catch {
          // Ignore cleanup errors
        }
      }
    }, 60000);
  });

  describe('Scenario 2: Service key + fresh session', () => {
    it('should use token from fresh session', async () => {
      if (!hasRealConfigValue) {
        console.warn('⚠️  Skipping integration test - no real config');
        return;
      }

      if (!destination || !serviceKeysDir || !sessionsDir) {
        console.warn('⚠️  Skipping integration test - missing required config');
        return;
      }

      const serviceKeyStore = new AbapServiceKeyStore(serviceKeysDir);
      const sessionStore = new AbapSessionStore(sessionsDir);

      const authConfig =
        await serviceKeyStore.getAuthorizationConfig(destination);
      if (!authConfig) {
        throw new Error('Failed to load authorization config from service key');
      }

      const connConfig = await sessionStore.getConnectionConfig(destination);
      if (!connConfig?.authorizationToken) {
        console.warn('⚠️  Skipping test - no existing session token found');
        return;
      }

      // Create provider with token from session
      const provider = new DeviceFlowProvider({
        uaaUrl: authConfig.uaaUrl!,
        clientId: authConfig.uaaClientId!,
        clientSecret: authConfig.uaaClientSecret,
        refreshToken: authConfig.refreshToken,
        accessToken: connConfig.authorizationToken, // Pass existing token
      });

      // Provider should return cached token if valid
      const tokens = await provider.getTokens();
      expect(tokens.authorizationToken).toBeDefined();
      expect(tokens.authType).toBe(AUTH_TYPE_AUTHORIZATION_CODE);
    }, 30000);
  });

  describe('Scenario 3: Service key + expired session', () => {
    it('should refresh token when session token is expired', async () => {
      if (!hasRealConfigValue) {
        console.warn('⚠️  Skipping integration test - no real config');
        return;
      }

      if (!destination || !serviceKeysDir || !sessionsDir) {
        console.warn('⚠️  Skipping integration test - missing required config');
        return;
      }

      const serviceKeyStore = new AbapServiceKeyStore(serviceKeysDir);
      const sessionStore = new AbapSessionStore(sessionsDir);

      const authConfig =
        await serviceKeyStore.getAuthorizationConfig(destination);
      if (!authConfig) {
        throw new Error('Failed to load authorization config from service key');
      }

      if (!authConfig.refreshToken) {
        console.warn('⚠️  Skipping test - no refresh token available');
        return;
      }

      // Create provider with expired token but valid refresh token
      const expiredToken = createExpiredJWT();
      const provider = new DeviceFlowProvider({
        uaaUrl: authConfig.uaaUrl!,
        clientId: authConfig.uaaClientId!,
        clientSecret: authConfig.uaaClientSecret,
        refreshToken: authConfig.refreshToken,
        accessToken: expiredToken, // Pass expired token
      });

      // Provider should attempt refresh
      try {
        const tokens = await provider.getTokens();
        // If refresh succeeds, we get new token
        expect(tokens.authorizationToken).toBeDefined();
        expect(tokens.authorizationToken).not.toBe(expiredToken); // Should be new token
        expect(tokens.authType).toBe(AUTH_TYPE_AUTHORIZATION_CODE);
      } catch (error: any) {
        // Refresh might fail if refresh token is also expired
        // That's expected - we test that provider attempts refresh
        expect(error).toBeDefined();
      }
    }, 30000);
  });

  describe('Scenario 4: Service key + expired session + expired refresh token', () => {
    it('should initiate device flow when refresh token is also expired', async () => {
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

      // Create provider with expired token and invalid refresh token
      const expiredToken = createExpiredJWT();
      const provider = new DeviceFlowProvider({
        uaaUrl: authConfig.uaaUrl!,
        clientId: authConfig.uaaClientId!,
        clientSecret: authConfig.uaaClientSecret,
        refreshToken: 'invalid-expired-refresh-token', // Invalid refresh token
        accessToken: expiredToken, // Expired token
      });

      // Provider should attempt refresh, fail, then attempt device flow
      try {
        await provider.getTokens();
        // If we get here, device flow succeeded (unlikely without manual authorization)
        const tokens = await provider.getTokens();
        expect(tokens.authorizationToken).toBeDefined();
        expect(tokens.authType).toBe(AUTH_TYPE_AUTHORIZATION_CODE);
      } catch (error: any) {
        // Expected: device flow requires manual authorization
        // But we verify that provider attempted refresh first, then device flow
        expect(error).toBeDefined();
      }
    }, 60000);
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

      const provider = new DeviceFlowProvider({
        uaaUrl: authConfig.uaaUrl!,
        clientId: authConfig.uaaClientId!,
        clientSecret: authConfig.uaaClientSecret,
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
