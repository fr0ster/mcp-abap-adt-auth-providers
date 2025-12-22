/**
 * Integration tests for BtpTokenProvider
 *
 * Real tests using YAML configuration and actual service keys
 * Tests browser-based authentication and token acquisition
 */

import {
  AbapServiceKeyStore,
  BtpSessionStore,
} from '@mcp-abap-adt/auth-stores';
import type { IAuthorizationConfig } from '@mcp-abap-adt/interfaces';
import { defaultLogger } from '@mcp-abap-adt/logger';
import { BtpTokenProvider } from '../../providers/BtpTokenProvider';
import {
  getAbapDestination,
  getServiceKeysDir,
  getSessionsDir,
  hasRealConfig,
  loadTestConfig,
} from '../helpers/configHelpers';

describe('BtpTokenProvider Integration', () => {
  const config = loadTestConfig();
  const btpDestination = getAbapDestination(config); // BTP uses ABAP destination (same as ABAP)
  const serviceKeysDir = getServiceKeysDir(config);
  const sessionsDir = getSessionsDir(config);

  const hasRealBtpConfig = hasRealConfig(config, 'abap'); // BTP uses ABAP config (same as ABAP)

  describe('Browser authentication', () => {
    it('should authenticate via browser and get tokens', async () => {
      if (!hasRealBtpConfig) {
        console.warn('⚠️  Skipping BTP integration test - no real config');
        return;
      }

      if (!btpDestination || !serviceKeysDir || !sessionsDir) {
        console.warn(
          '⚠️  Skipping BTP integration test - missing required config',
        );
        return;
      }

      // Create stores with real paths
      // BTP uses AbapServiceKeyStore (same format as ABAP) and BtpSessionStore (without sapUrl)
      const serviceKeyStore = new AbapServiceKeyStore(serviceKeysDir);
      const sessionStore = new BtpSessionStore(sessionsDir);
      const tokenProvider = new BtpTokenProvider();

      // Load service key
      const serviceKey = await serviceKeyStore.getServiceKey(btpDestination);
      if (!serviceKey) {
        throw new Error(
          `Service key not found for destination "${btpDestination}" in directory "${serviceKeysDir}". Please ensure the service key file exists.`,
        );
      }
      expect(serviceKey.uaaUrl).toBeDefined();
      expect(serviceKey.uaaClientId).toBeDefined();
      expect(serviceKey.uaaClientSecret).toBeDefined();
      // BTP service key may not have serviceUrl (base BTP without sapUrl)

      // Get authorization config from service key
      const authConfig: IAuthorizationConfig = {
        uaaUrl: serviceKey.uaaUrl!,
        uaaClientId: serviceKey.uaaClientId!,
        uaaClientSecret: serviceKey.uaaClientSecret!,
      };

      // Check if there's an existing session with refresh token
      // Refresh token is obtained AFTER browser authentication
      const existingSession = await sessionStore.loadSession(btpDestination);
      if (existingSession?.refreshToken) {
        // Use existing refresh token
        authConfig.refreshToken = existingSession.refreshToken;
      }
      // If no refresh token, provider will start browser auth automatically to get both access and refresh tokens

      // Get token from provider
      // Will use refresh token if available, otherwise will start browser auth to get tokens
      const result = await tokenProvider.getConnectionConfig(authConfig, {
        logger: defaultLogger,
        browser: 'system', // Allow browser to open for authentication if needed
      });

      expect(result.connectionConfig).toBeDefined();
      expect(result.connectionConfig.authorizationToken).toBeDefined();
      expect(
        result.connectionConfig.authorizationToken?.length,
      ).toBeGreaterThan(0);

      // Save session using IConfig format
      // BTP doesn't have sapUrl, so don't pass serviceUrl
      await sessionStore.saveSession(btpDestination, {
        authorizationToken: result.connectionConfig.authorizationToken,
        refreshToken: result.refreshToken || authConfig.refreshToken,
        uaaUrl: authConfig.uaaUrl,
        uaaClientId: authConfig.uaaClientId,
        uaaClientSecret: authConfig.uaaClientSecret,
      });

      // Verify session was saved
      const savedSession = await sessionStore.loadSession(btpDestination);
      expect(savedSession).toBeDefined();
      expect(savedSession?.uaaUrl).toBe(authConfig.uaaUrl);
      expect(savedSession?.authorizationToken).toBe(
        result.connectionConfig.authorizationToken,
      );
    }, 300000); // 5 minute timeout for browser auth if needed

    it('should validate token', async () => {
      if (!hasRealBtpConfig) {
        console.warn('⚠️  Skipping BTP token validation test - no real config');
        return;
      }

      if (!btpDestination || !serviceKeysDir) {
        console.warn(
          '⚠️  Skipping BTP token validation test - missing required config',
        );
        return;
      }

      // BTP uses AbapServiceKeyStore (same format as ABAP) and BtpSessionStore (without sapUrl)
      const serviceKeyStore = new AbapServiceKeyStore(serviceKeysDir);
      const sessionStore = new BtpSessionStore(sessionsDir || serviceKeysDir);
      const tokenProvider = new BtpTokenProvider();

      // Load service key
      const serviceKey = await serviceKeyStore.getServiceKey(btpDestination);
      if (
        !serviceKey ||
        !serviceKey.uaaUrl ||
        !serviceKey.uaaClientId ||
        !serviceKey.uaaClientSecret
      ) {
        throw new Error(
          `Service key not found or incomplete for destination "${btpDestination}" in directory "${serviceKeysDir}". Please ensure the service key file exists and contains valid UAA credentials.`,
        );
      }

      const authConfig: IAuthorizationConfig = {
        uaaUrl: serviceKey.uaaUrl,
        uaaClientId: serviceKey.uaaClientId,
        uaaClientSecret: serviceKey.uaaClientSecret,
      };

      // Check for existing refresh token
      // Refresh token is obtained AFTER browser authentication
      const existingSession = await sessionStore.loadSession(btpDestination);
      if (existingSession?.refreshToken) {
        // Use existing refresh token
        authConfig.refreshToken = existingSession.refreshToken;
      }
      // If no refresh token, provider will start browser auth automatically to get both access and refresh tokens

      const result = await tokenProvider.getConnectionConfig(authConfig, {
        logger: defaultLogger,
        browser: 'system', // Allow browser to open for authentication if needed
      });

      const token = result.connectionConfig.authorizationToken;
      expect(token).toBeDefined();

      // Validate token (BTP may not have serviceUrl, skip validation if not available)
      const isValid = serviceKey.serviceUrl
        ? await tokenProvider.validateToken(token!, serviceKey.serviceUrl)
        : true; // Skip validation if no serviceUrl (base BTP)
      expect(isValid).toBe(true);
    }, 300000);
  });
});
