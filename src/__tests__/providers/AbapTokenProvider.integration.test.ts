/**
 * Integration tests for ABAP token provider (using BtpTokenProvider)
 * 
 * Real tests using YAML configuration and actual service keys
 * Tests conversion of ABAP service key to session via token provider
 */

import { BtpTokenProvider } from '../../providers/BtpTokenProvider';
import { AbapServiceKeyStore, AbapSessionStore } from '@mcp-abap-adt/auth-stores';
import type { IAuthorizationConfig } from '@mcp-abap-adt/interfaces';
import { defaultLogger } from '@mcp-abap-adt/logger';
import {
  loadTestConfig,
  hasRealConfig,
  getAbapDestination,
  getServiceKeysDir,
  getSessionsDir,
} from '../helpers/configHelpers';

describe('AbapTokenProvider Integration', () => {
  const config = loadTestConfig();
  const abapDestination = getAbapDestination(config);
  const serviceKeysDir = getServiceKeysDir(config);
  const sessionsDir = getSessionsDir(config);

  const hasRealAbapConfig = hasRealConfig(config, 'abap');

  describe('Service key to session conversion', () => {
    it('should convert ABAP service key to session', async () => {
      if (!hasRealAbapConfig) {
        console.warn('⚠️  Skipping ABAP integration test - no real config');
        return;
      }

      if (!abapDestination || !serviceKeysDir || !sessionsDir) {
        console.warn('⚠️  Skipping ABAP integration test - missing required config');
        return;
      }

      // Create stores with real paths
      const serviceKeyStore = new AbapServiceKeyStore(serviceKeysDir);
      const sessionStore = new AbapSessionStore(sessionsDir);
      const tokenProvider = new BtpTokenProvider(); // BtpTokenProvider works for ABAP too

      // Load service key
      const serviceKey = await serviceKeyStore.getServiceKey(abapDestination);
      if (!serviceKey) {
        throw new Error(`Service key not found for destination "${abapDestination}" in directory "${serviceKeysDir}". Please ensure the service key file exists.`);
      }
      expect(serviceKey.uaaUrl).toBeDefined();
      expect(serviceKey.uaaClientId).toBeDefined();
      expect(serviceKey.uaaClientSecret).toBeDefined();
      expect(serviceKey.serviceUrl).toBeDefined();

      // Get authorization config from service key
      const authConfig: IAuthorizationConfig = {
        uaaUrl: serviceKey.uaaUrl!,
        uaaClientId: serviceKey.uaaClientId!,
        uaaClientSecret: serviceKey.uaaClientSecret!,
      };

      // Check if there's an existing session with refresh token
      // Refresh token is obtained AFTER browser authentication
      const existingSession = await sessionStore.loadSession(abapDestination);
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
      expect(result.connectionConfig.authorizationToken.length).toBeGreaterThan(0);

      // Save session with refresh token if available
      // AbapSessionStore accepts IConfig format (serviceUrl, authorizationToken)
      // BtpTokenProvider doesn't return serviceUrl in connectionConfig, so use serviceUrl from service key
      await sessionStore.saveSession(abapDestination, {
        serviceUrl: serviceKey.serviceUrl!, // Use serviceUrl from service key (BtpTokenProvider doesn't return it)
        authorizationToken: result.connectionConfig.authorizationToken,
        refreshToken: result.refreshToken || authConfig.refreshToken,
        uaaUrl: authConfig.uaaUrl,
        uaaClientId: authConfig.uaaClientId,
        uaaClientSecret: authConfig.uaaClientSecret,
        sapClient: serviceKey.sapClient, // Use sapClient from service key
        language: serviceKey.language, // Use language from service key
      });

      // Verify session was saved
      const savedSession = await sessionStore.loadSession(abapDestination);
      expect(savedSession).toBeDefined();
      expect(savedSession?.uaaUrl).toBe(authConfig.uaaUrl);
      expect(savedSession?.authorizationToken).toBe(
        result.connectionConfig.authorizationToken
      );
    }, 300000); // 5 minute timeout for browser auth if needed

    it('should validate token', async () => {
      if (!hasRealAbapConfig) {
        console.warn('⚠️  Skipping ABAP token validation test - no real config');
        return;
      }

      if (!abapDestination || !serviceKeysDir) {
        console.warn('⚠️  Skipping ABAP token validation test - missing required config');
        return;
      }

      const serviceKeyStore = new AbapServiceKeyStore(serviceKeysDir);
      const sessionStore = new AbapSessionStore(sessionsDir || serviceKeysDir);
      const tokenProvider = new BtpTokenProvider();

      // Load service key
      const serviceKey = await serviceKeyStore.getServiceKey(abapDestination);
      if (!serviceKey || !serviceKey.uaaUrl || !serviceKey.uaaClientId || !serviceKey.uaaClientSecret || !serviceKey.serviceUrl) {
        throw new Error(`Service key not found or incomplete for destination "${abapDestination}" in directory "${serviceKeysDir}". Please ensure the service key file exists and contains valid UAA credentials and service URL.`);
      }

      const authConfig: IAuthorizationConfig = {
        uaaUrl: serviceKey.uaaUrl,
        uaaClientId: serviceKey.uaaClientId,
        uaaClientSecret: serviceKey.uaaClientSecret,
      };

      // Check for existing refresh token
      // Refresh token is obtained AFTER browser authentication
      const existingSession = await sessionStore.loadSession(abapDestination);
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

      // Validate token
      const isValid = await tokenProvider.validateToken(token, serviceKey.serviceUrl);
      expect(isValid).toBe(true);
    }, 300000);
  });
});

