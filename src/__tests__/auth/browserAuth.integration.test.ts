/**
 * Integration tests for browserAuth
 *
 * Real tests using service keys and actual OAuth flow
 */

import * as dns from 'node:dns/promises';
import { AbapServiceKeyStore } from '@mcp-abap-adt/auth-stores';
import type { IAuthorizationConfig } from '@mcp-abap-adt/interfaces';
import {
  exchangeCodeForToken,
  getJwtAuthorizationUrl,
} from '../../auth/browserAuth';
import { browserCallbackStrategy } from '../../strategies';
import {
  getAbapDestination,
  getServiceKeysDir,
  loadTestConfig,
} from '../helpers/configHelpers';
import { canListenOnLocalhost, getAvailablePort } from '../helpers/netHelpers';
import { createTestLogger } from '../helpers/testLogger';

describe('browserAuth Integration', () => {
  const canResolveHost = async (url: string): Promise<boolean> => {
    try {
      const hostname = new URL(url).hostname;
      await dns.lookup(hostname);
      return true;
    } catch {
      return false;
    }
  };

  const config = loadTestConfig();
  const destination = getAbapDestination(config);
  const serviceKeysDir = getServiceKeysDir(config);

  it('should exchange code for tokens with real OAuth flow', async () => {
    if (!destination || !serviceKeysDir) {
      console.warn('⚠️  Skipping integration test - missing config');
      return;
    }

    const serviceKeyStore = new AbapServiceKeyStore(serviceKeysDir);
    const serviceKey = await serviceKeyStore.getServiceKey(destination);

    if (
      !serviceKey?.uaaUrl ||
      !serviceKey?.uaaClientId ||
      !serviceKey?.uaaClientSecret
    ) {
      console.warn('⚠️  Skipping integration test - no service key');
      return;
    }

    const authConfig: IAuthorizationConfig = {
      uaaUrl: serviceKey.uaaUrl,
      uaaClientId: serviceKey.uaaClientId,
      uaaClientSecret: serviceKey.uaaClientSecret,
    };
    if (!(await canResolveHost(authConfig.uaaUrl!))) {
      console.warn('⚠️  Skipping integration test - UAA host not resolvable');
      return;
    }
    if (!(await canListenOnLocalhost())) {
      console.warn('⚠️  Skipping integration test - cannot bind to localhost');
      return;
    }

    // Logging enabled via environment variable: DEBUG_AUTH_PROVIDERS=true
    const logger = createTestLogger('INTEGRATION');
    const port = await getAvailablePort();

    logger.info(`Starting browser authentication: ${authConfig.uaaUrl}`);

    // The strategy owns the socket, the browser and the timeout; the exchange
    // stays with the caller — the same split `AuthorizationCodeProvider` uses.
    const strategy = browserCallbackStrategy({
      browser: 'system', // Use the system default browser
      port,
      timeoutMs: 290000,
    });
    const outcome = await strategy.authorize({
      logger,
      buildAuthorizationUrl: async (redirectUri) =>
        getJwtAuthorizationUrl(authConfig, redirectUri),
    });
    const result = await exchangeCodeForToken(
      authConfig,
      outcome.payload,
      outcome.redirectUri,
      logger,
    );

    expect(result).toBeDefined();
    expect(result.accessToken).toBeDefined();
    expect(result.accessToken.length).toBeGreaterThan(0);

    logger.info(
      `Authentication successful: accessToken(${result.accessToken.length} chars), refreshToken(${result.refreshToken?.length || 0} chars)`,
    );

    if (result.refreshToken) {
      expect(result.refreshToken.length).toBeGreaterThan(0);
    }
  }, 300000); // 5 minute timeout for browser auth
});
