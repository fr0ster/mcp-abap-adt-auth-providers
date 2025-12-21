/**
 * BTP/ABAP Token Provider
 * 
 * Uses browser-based OAuth2 or refresh token to obtain tokens.
 * For ABAP and full-scope BTP connections.
 */

import type { ITokenProvider, ITokenProviderOptions, ITokenProviderResult, IAuthorizationConfig, ILogger } from '@mcp-abap-adt/interfaces';
import { ValidationError, RefreshError } from '../errors/TokenProviderErrors';

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

  /**
   * Validate JWT token locally by checking exp claim.
   * Does NOT make HTTP requests - validation is purely local.
   * 
   * HTTP validation (401/403) is handled by retry mechanism in makeAdtRequest wrapper.
   * This approach prevents unnecessary browser auth when server is unreachable.
   * 
   * @param token JWT token to validate
   * @param _serviceUrl Service URL (unused - kept for interface compatibility)
   * @returns true if token is not expired, false otherwise
   */
  async validateToken(token: string, _serviceUrl?: string): Promise<boolean> {
    if (!token) {
      return false;
    }

    try {
      // JWT structure: header.payload.signature
      const parts = token.split('.');
      if (parts.length !== 3) {
        // Not a valid JWT format
        return false;
      }

      // Decode payload (base64url)
      const payload = parts[1];
      // Convert base64url to base64
      const base64 = payload.replace(/-/g, '+').replace(/_/g, '/');
      // Add padding if needed
      const padded = base64 + '=='.substring(0, (4 - base64.length % 4) % 4);
      
      const decoded = Buffer.from(padded, 'base64').toString('utf8');
      const claims = JSON.parse(decoded);

      // Check exp claim
      if (!claims.exp) {
        // No expiration - assume valid
        return true;
      }

      const expirationTime = claims.exp * 1000; // Convert to milliseconds
      const now = Date.now();
      
      // Add 60 second buffer to account for clock skew and network latency
      const bufferMs = 60 * 1000;
      
      if (now >= expirationTime - bufferMs) {
        // Token is expired or about to expire
        return false;
      }

      // Token is valid
      return true;
    } catch {
      // Failed to parse JWT - assume invalid
      return false;
    }
  }
}

