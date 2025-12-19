/**
 * BTP/ABAP Token Provider
 * 
 * Uses browser-based OAuth2 or refresh token to obtain tokens.
 * For ABAP and full-scope BTP connections.
 */

import type { ITokenProvider, ITokenProviderOptions, ITokenProviderResult, IAuthorizationConfig, ILogger } from '@mcp-abap-adt/interfaces';
import { ValidationError, RefreshError } from '../errors/TokenProviderErrors';
import axios from 'axios';

// Import internal functions (not exported)
import { startBrowserAuth } from '../auth/browserAuth';
import { refreshJwtToken } from '../auth/tokenRefresher';

/**
 * BTP/ABAP token provider implementation
 * 
 * Uses browser-based OAuth2 (if no refresh token) or refresh token flow.
 */
export class BtpTokenProvider implements ITokenProvider {
  private readonly browserAuthPort: number;

  constructor(browserAuthPort?: number) {
    // Default to 3001 if not specified
    this.browserAuthPort = browserAuthPort ?? 3001;
  }

  /**
   * Private method wrapper for browser authentication
   * Proxies port from constructor to internal function
   */
  private async startBrowserAuth(
    authConfig: IAuthorizationConfig,
    browser: string,
    logger?: ILogger
  ): Promise<{ accessToken: string; refreshToken?: string }> {
    return startBrowserAuth(authConfig, browser, logger, this.browserAuthPort);
  }

  /**
   * Private method wrapper for token refresh
   */
  private async refreshJwtToken(
    refreshToken: string,
    uaaUrl: string,
    clientId: string,
    clientSecret: string
  ): Promise<{ accessToken: string; refreshToken?: string }> {
    return refreshJwtToken(refreshToken, uaaUrl, clientId, clientSecret);
  }

  async getConnectionConfig(
    authConfig: IAuthorizationConfig,
    options?: ITokenProviderOptions
  ): Promise<ITokenProviderResult> {
    const logger = options?.logger;
    const browser = options?.browser || 'system';
    
    let result: { accessToken: string; refreshToken?: string };

    if (!authConfig.refreshToken) {
      // No refresh token - start browser authentication flow
      if (logger) {
        logger.debug('No refresh token found. Starting browser authentication...');
      }
      result = await this.startBrowserAuth(authConfig, browser, logger);
    } else {
      // Use refresh token to get new access token
      if (logger) {
        logger.debug('Refreshing token using refresh token...');
      }
      result = await this.refreshJwtToken(
        authConfig.refreshToken,
        authConfig.uaaUrl,
        authConfig.uaaClientId,
        authConfig.uaaClientSecret
      );
    }

    return {
      connectionConfig: {
        authorizationToken: result.accessToken,
        // serviceUrl, sapClient, language are not part of authorization config
        // They come from service key or session store separately
      },
      refreshToken: result.refreshToken,
    };
  }

  async refreshTokenFromSession(
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
        `BTP refreshTokenFromSession: authConfig missing required fields: ${missingFields.join(', ')}`,
        missingFields
      );
    }

    if (logger) {
      logger.debug('BTP: Refreshing token from session using browser authentication (UAA_URL)...');
    }

    // BTP refresh from session uses browser authentication through UAA_URL
    try {
      const result = await this.startBrowserAuth(authConfig, browser, logger);

      return {
        connectionConfig: {
          authorizationToken: result.accessToken,
        },
        refreshToken: result.refreshToken,
      };
    } catch (error: any) {
      throw new RefreshError(
        `BTP refreshTokenFromSession failed: ${error.message}`,
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
        `BTP refreshTokenFromServiceKey: authConfig missing required fields: ${missingFields.join(', ')}`,
        missingFields
      );
    }

    if (logger) {
      logger.debug('BTP: Refreshing token from service key using browser authentication...');
    }

    // BTP refresh from service key uses browser authentication
    try {
      const result = await this.startBrowserAuth(authConfig, browser, logger);

      return {
        connectionConfig: {
          authorizationToken: result.accessToken,
        },
        refreshToken: result.refreshToken,
      };
    } catch (error: any) {
      throw new RefreshError(
        `BTP refreshTokenFromServiceKey failed: ${error.message}`,
        error
      );
    }
  }

  async validateToken(token: string, serviceUrl?: string): Promise<boolean> {
    if (!token || !serviceUrl) {
      return false;
    }

    try {
      // Test connection to SAP ADT discovery endpoint
      const response = await axios.get(`${serviceUrl}/sap/bc/adt/discovery`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
        timeout: 5000,
        validateStatus: (status) => {
          // 200-299: valid token
          // 401/403: expired/invalid token
          // Other: network/connection error (treat as invalid)
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

      // Other status codes: treat as invalid
      return false;
    } catch (error: any) {
      // Network errors, timeouts, etc. - treat as invalid
      if (error.code === 'ECONNREFUSED' || error.code === 'ETIMEDOUT' || error.code === 'ENOTFOUND') {
        // Connection errors - can't validate, assume invalid
        return false;
      }
      // Other errors - assume invalid
      return false;
    }
  }
}

