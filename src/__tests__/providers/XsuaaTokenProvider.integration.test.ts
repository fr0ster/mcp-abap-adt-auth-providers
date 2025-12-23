/**
 * Integration tests for XsuaaTokenProvider
 *
 * Real tests using YAML configuration and actual service keys
 * Tests conversion of service key to session via token provider
 */

import {
  XsuaaServiceKeyStore,
  XsuaaSessionStore,
} from '@mcp-abap-adt/auth-stores';
import type { IAuthorizationConfig } from '@mcp-abap-adt/interfaces';
import { defaultLogger } from '@mcp-abap-adt/logger';
import { XsuaaTokenProvider } from '../../providers/XsuaaTokenProvider';
import {
  getServiceKeysDir,
  getSessionsDir,
  getXsuaaDestinations,
  hasRealConfig,
  loadTestConfig,
} from '../helpers/configHelpers';

describe('XsuaaTokenProvider Integration', () => {
  const config = loadTestConfig();
  const xsuaaConfig = getXsuaaDestinations(config);
  const serviceKeysDir = getServiceKeysDir(config);
  const sessionsDir = getSessionsDir(config);

  const hasRealXsuaaConfig = hasRealConfig(config, 'xsuaa');

  describe('Service key to session conversion', () => {
    it('should convert XSUAA service key to session', async () => {
      if (!hasRealXsuaaConfig) {
        console.warn('⚠️  Skipping XSUAA integration test - no real config');
        return;
      }

      if (!xsuaaConfig.btp_destination || !serviceKeysDir || !sessionsDir) {
        console.warn(
          '⚠️  Skipping XSUAA integration test - missing required config',
        );
        return;
      }

      // Create stores with real paths
      const serviceKeyStore = new XsuaaServiceKeyStore(serviceKeysDir);
      const sessionStore = new XsuaaSessionStore(sessionsDir, '');
      const tokenProvider = new XsuaaTokenProvider();

      // Load service key
      const serviceKey = await serviceKeyStore.getServiceKey(
        xsuaaConfig.btp_destination,
      );
      if (!serviceKey) {
        throw new Error(
          `Service key not found for destination "${xsuaaConfig.btp_destination}" in directory "${serviceKeysDir}". Please ensure the service key file exists.`,
        );
      }
      expect(serviceKey.uaaUrl).toBeDefined();
      expect(serviceKey.uaaClientId).toBeDefined();
      expect(serviceKey.uaaClientSecret).toBeDefined();

      // Get authorization config from service key
      // XsuaaServiceKeyParser prioritizes apiurl over url for UAA
      const authConfig: IAuthorizationConfig = {
        uaaUrl: serviceKey.uaaUrl!,
        uaaClientId: serviceKey.uaaClientId!,
        uaaClientSecret: serviceKey.uaaClientSecret!,
      };

      // Log for debugging
      if (process.env.TEST_VERBOSE) {
        console.log(`[XsuaaTokenProvider] Using UAA URL: ${authConfig.uaaUrl}`);
      }

      // Get token from provider (XSUAA uses client_credentials - one POST request, no browser needed)
      const result = await tokenProvider.getConnectionConfig(authConfig, {
        logger: defaultLogger,
      });

      expect(result.connectionConfig).toBeDefined();
      expect(result.connectionConfig.authorizationToken).toBeDefined();
      expect(
        result.connectionConfig.authorizationToken?.length,
      ).toBeGreaterThan(0);

      // Save session
      await sessionStore.saveSession(xsuaaConfig.btp_destination, {
        ...authConfig,
        ...result.connectionConfig,
      });

      // Verify session was saved
      const savedSession = await sessionStore.loadSession(
        xsuaaConfig.btp_destination,
      );
      expect(savedSession).toBeDefined();
      expect(savedSession?.uaaUrl).toBe(authConfig.uaaUrl);
      expect(savedSession?.authorizationToken).toBe(
        result.connectionConfig.authorizationToken,
      );
    }, 60000); // 60 second timeout for real authentication

    it('should validate token', async () => {
      if (!hasRealXsuaaConfig) {
        console.warn(
          '⚠️  Skipping XSUAA token validation test - no real config',
        );
        return;
      }

      if (
        !xsuaaConfig.btp_destination ||
        !xsuaaConfig.mcp_url ||
        !serviceKeysDir
      ) {
        console.warn(
          '⚠️  Skipping XSUAA token validation test - missing required config',
        );
        return;
      }

      const serviceKeyStore = new XsuaaServiceKeyStore(serviceKeysDir);
      const tokenProvider = new XsuaaTokenProvider();

      // Load service key and get token
      const serviceKey = await serviceKeyStore.getServiceKey(
        xsuaaConfig.btp_destination,
      );
      if (
        !serviceKey ||
        !serviceKey.uaaUrl ||
        !serviceKey.uaaClientId ||
        !serviceKey.uaaClientSecret
      ) {
        throw new Error(
          `Service key not found or incomplete for destination "${xsuaaConfig.btp_destination}" in directory "${serviceKeysDir}". Please ensure the service key file exists and contains valid UAA credentials.`,
        );
      }

      const authConfig: IAuthorizationConfig = {
        uaaUrl: serviceKey.uaaUrl,
        uaaClientId: serviceKey.uaaClientId,
        uaaClientSecret: serviceKey.uaaClientSecret,
      };

      // Get token from provider (XSUAA uses client_credentials - one POST request, no browser needed)
      const result = await tokenProvider.getConnectionConfig(authConfig, {
        logger: defaultLogger,
      });

      const token = result.connectionConfig.authorizationToken;
      expect(token).toBeDefined();

      // Validate token
      const isValid = await tokenProvider.validateToken(
        token!,
        xsuaaConfig.mcp_url,
      );
      expect(isValid).toBe(true);
    }, 60000);
  });
});
