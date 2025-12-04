/**
 * XSUAA Token Provider
 * 
 * Uses client_credentials grant type to obtain tokens (no browser required).
 * For XSUAA service keys with reduced scope access.
 */

import type { ITokenProvider, ITokenProviderOptions, ITokenProviderResult, IAuthorizationConfig } from '@mcp-abap-adt/interfaces';
import { getTokenWithClientCredentials } from '../auth/clientCredentialsAuth';
import axios from 'axios';

/**
 * XSUAA token provider implementation
 * 
 * Uses client_credentials grant type - no browser, no refresh token needed.
 */
export class XsuaaTokenProvider implements ITokenProvider {
  async getConnectionConfig(
    authConfig: IAuthorizationConfig,
    options?: ITokenProviderOptions
  ): Promise<ITokenProviderResult> {
    const logger = options?.logger;
    
    if (logger) {
      logger.debug('Using client_credentials grant type for XSUAA...');
    }

    // XSUAA uses client_credentials - no refresh token needed
    const result = await getTokenWithClientCredentials(
      authConfig.uaaUrl,
      authConfig.uaaClientId,
      authConfig.uaaClientSecret
    );

    // XSUAA doesn't provide serviceUrl in authorization config
    // It's provided separately (from YAML, parameter, or request header)
    return {
      connectionConfig: {
        authorizationToken: result.accessToken,
        // serviceUrl is undefined for XSUAA - provided separately
      },
      // XSUAA client_credentials doesn't provide refresh token
    };
  }

  async validateToken(token: string, serviceUrl?: string): Promise<boolean> {
    // XSUAA tokens are validated by the service itself when making requests
    // If serviceUrl is provided, we can test the connection
    if (!token) {
      return false;
    }

    // If no serviceUrl, we can't validate - assume valid (service will reject if invalid)
    if (!serviceUrl) {
      return true;
    }

    try {
      // Test connection to service endpoint
      const response = await axios.get(serviceUrl, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
        timeout: 5000,
        validateStatus: (status) => {
          // Any response means service is reachable
          return status < 500;
        },
      });

      // 200-299: token is valid
      if (response.status >= 200 && response.status < 300) {
        return true;
      }

      // 401/403: token is expired or invalid
      if (response.status === 401 || response.status === 403) {
        return false;
      }

      // Other status codes: service is reachable, token might be valid
      return true;
    } catch (error: any) {
      // Network errors, timeouts, etc. - can't validate, assume valid
      // (service will reject if token is actually invalid)
      if (error.code === 'ECONNREFUSED' || error.code === 'ETIMEDOUT' || error.code === 'ENOTFOUND') {
        // Connection errors - can't validate, assume valid (service will reject if invalid)
        return true;
      }
      // Other errors - assume valid (service will reject if invalid)
      return true;
    }
  }
}
