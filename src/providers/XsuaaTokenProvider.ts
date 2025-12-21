/**
 * XSUAA Token Provider
 * 
 * Uses client_credentials grant type to obtain tokens (no browser required).
 * For XSUAA service keys with reduced scope access.
 */

import type { ITokenProvider, ITokenProviderOptions, ITokenProviderResult, IAuthorizationConfig } from '@mcp-abap-adt/interfaces';
import { ValidationError, RefreshError } from '../errors/TokenProviderErrors';

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

  /**
   * Validate JWT token locally by checking exp claim.
   * Does NOT make HTTP requests - validation is purely local.
   * 
   * HTTP validation (401/403) is handled by retry mechanism in makeAdtRequest wrapper.
   * This approach is consistent with BtpTokenProvider and prevents unnecessary token refresh.
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
