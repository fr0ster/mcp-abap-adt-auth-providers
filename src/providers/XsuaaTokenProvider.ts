/**
 * XSUAA Token Provider
 * 
 * Uses client_credentials grant type to obtain tokens (no browser required).
 * For XSUAA service keys with reduced scope access.
 */

import type { ITokenProvider, ITokenProviderOptions, ITokenProviderResult, IAuthorizationConfig } from '@mcp-abap-adt/interfaces';
import { ValidationError, RefreshError } from '../errors/TokenProviderErrors';
import axios from 'axios';

// Import internal function (not exported)
import { getTokenWithClientCredentials } from '../auth/clientCredentialsAuth';

/**
 * XSUAA token provider implementation
 * 
 * Uses client_credentials grant type - no browser, no refresh token needed.
 */
export class XsuaaTokenProvider implements ITokenProvider {
  /**
   * Private method wrapper for client credentials authentication
   */
  private async getTokenWithClientCredentials(
    uaaUrl: string,
    clientId: string,
    clientSecret: string
  ): Promise<{ accessToken: string; expiresIn?: number }> {
    return getTokenWithClientCredentials(uaaUrl, clientId, clientSecret);
  }

  async getConnectionConfig(
    authConfig: IAuthorizationConfig,
    options?: ITokenProviderOptions
  ): Promise<ITokenProviderResult> {
    const logger = options?.logger;
    
    if (logger) {
      logger.debug('Using client_credentials grant type for XSUAA...');
    }

    // XSUAA uses client_credentials - no refresh token needed
    const result = await this.getTokenWithClientCredentials(
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

  async refreshTokenFromSession(
    authConfig: IAuthorizationConfig,
    options?: ITokenProviderOptions
  ): Promise<ITokenProviderResult> {
    const logger = options?.logger;
    
    // Validate authConfig
    const missingFields: string[] = [];
    if (!authConfig.uaaUrl) missingFields.push('uaaUrl');
    if (!authConfig.uaaClientId) missingFields.push('uaaClientId');
    if (!authConfig.uaaClientSecret) missingFields.push('uaaClientSecret');
    
    if (missingFields.length > 0) {
      throw new ValidationError(
        `XSUAA refreshTokenFromSession: authConfig missing required fields: ${missingFields.join(', ')}`,
        missingFields
      );
    }
    
    if (logger) {
      logger.debug('XSUAA: Refreshing token from session using client_credentials...');
    }

    // XSUAA refresh from session uses client_credentials (clientId/clientSecret)
    try {
      const result = await this.getTokenWithClientCredentials(
        authConfig.uaaUrl,
        authConfig.uaaClientId,
        authConfig.uaaClientSecret
      );

      return {
        connectionConfig: {
          authorizationToken: result.accessToken,
        },
        // XSUAA client_credentials doesn't provide refresh token
      };
    } catch (error: any) {
      throw new RefreshError(
        `XSUAA refreshTokenFromSession failed: ${error.message}`,
        error
      );
    }

  }

  async refreshTokenFromServiceKey(
    authConfig: IAuthorizationConfig,
    options?: ITokenProviderOptions
  ): Promise<ITokenProviderResult> {
    const logger = options?.logger;
    const browser = options?.browser || 'system';

    // Validate authConfig
    const missingFields: string[] = [];
    if (!authConfig.uaaUrl) missingFields.push('uaaUrl');
    if (!authConfig.uaaClientId) missingFields.push('uaaClientId');
    if (!authConfig.uaaClientSecret) missingFields.push('uaaClientSecret');
    
    if (missingFields.length > 0) {
      throw new ValidationError(
        `XSUAA refreshTokenFromServiceKey: authConfig missing required fields: ${missingFields.join(', ')}`,
        missingFields
      );
    }

    if (logger) {
      logger.debug('XSUAA: Refreshing token from service key using browser authentication...');
    }

    // XSUAA refresh from service key uses browser authentication
    try {
      const { startBrowserAuth } = await import('../auth/browserAuth');
      const result = await startBrowserAuth(authConfig, browser, logger);

      return {
        connectionConfig: {
          authorizationToken: result.accessToken,
        },
        refreshToken: result.refreshToken,
      };
    } catch (error: any) {
      throw new RefreshError(
        `XSUAA refreshTokenFromServiceKey failed: ${error.message}`,
        error
      );
    }
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
