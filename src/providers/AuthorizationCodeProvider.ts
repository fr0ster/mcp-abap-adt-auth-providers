/**
 * Authorization Code Token Provider
 *
 * Uses authorization_code grant type with browser-based OAuth2 flow.
 * Supports pre-built authorization URLs and automatic refresh.
 */

import type {
  IAuthorizationConfig,
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces';
import { AUTH_TYPE_AUTHORIZATION_CODE } from '@mcp-abap-adt/interfaces';
import { startBrowserAuth } from '../auth/browserAuth';
import { refreshJwtToken } from '../auth/tokenRefresher';
import { BaseTokenProvider } from './BaseTokenProvider';

export interface AuthorizationCodeProviderConfig {
  // Required for building authorization URL and token exchange
  uaaUrl: string;
  clientId: string;
  clientSecret: string;

  // Optional: pre-built authorization URL (if not provided, will be built from uaaUrl + clientId)
  authorizationUrl?: string;
  // Optional: browser type ('auto', 'system', 'chrome', 'none', etc.)
  // If not provided, defaults to 'none' (prints URL to console)
  browser?: string;
  redirectPort?: number; // default: 3001

  // Optional: existing tokens (for refresh scenario)
  accessToken?: string;
  refreshToken?: string;
}

/**
 * Authorization Code token provider
 *
 * Uses authorization_code grant type with browser-based OAuth2 flow.
 * Supports pre-built authorization URLs and automatic token refresh.
 */
export class AuthorizationCodeProvider extends BaseTokenProvider {
  private config: AuthorizationCodeProviderConfig;

  constructor(config: AuthorizationCodeProviderConfig) {
    super();
    this.config = config;

    // Initialize from provided tokens if available
    if (config.accessToken) {
      this.authorizationToken = config.accessToken;
      // Parse expiration from JWT
      this.expiresAt = this.parseExpirationFromJWT(config.accessToken);
    }
    if (config.refreshToken) {
      this.refreshToken = config.refreshToken;
    }
  }

  protected getAuthType(): OAuth2GrantType {
    return AUTH_TYPE_AUTHORIZATION_CODE;
  }

  protected async performLogin(): Promise<ITokenResult> {
    // Build authorization config
    // If authorizationUrl is provided, use it; otherwise startBrowserAuth will build it from uaaUrl + clientId
    const authConfig: IAuthorizationConfig & { authorizationUrl?: string } = {
      uaaUrl: this.config.uaaUrl,
      uaaClientId: this.config.clientId,
      uaaClientSecret: this.config.clientSecret,
    };

    // If pre-built URL provided, use it
    if (this.config.authorizationUrl) {
      authConfig.authorizationUrl = this.config.authorizationUrl;
    }

    // Use provided browser or default to 'none' (prints URL to console)
    const browser = this.config.browser || 'none';

    const result = await startBrowserAuth(
      authConfig,
      browser,
      undefined, // logger
      this.config.redirectPort || 3001,
    );

    // Parse expiration from JWT
    const expiresIn = this.calculateExpiresIn(result.accessToken);

    return {
      authorizationToken: result.accessToken,
      refreshToken: result.refreshToken,
      authType: AUTH_TYPE_AUTHORIZATION_CODE,
      expiresIn,
    };
  }

  protected async performRefresh(): Promise<ITokenResult> {
    if (!this.refreshToken) {
      throw new Error('Refresh token is required for refresh');
    }

    // Try refresh first
    try {
      const result = await refreshJwtToken(
        this.refreshToken,
        this.config.uaaUrl,
        this.config.clientId,
        this.config.clientSecret,
      );

      const expiresIn = this.calculateExpiresIn(result.accessToken);

      return {
        authorizationToken: result.accessToken,
        refreshToken: result.refreshToken || this.refreshToken, // Keep old if new not provided
        authType: AUTH_TYPE_AUTHORIZATION_CODE,
        expiresIn,
      };
    } catch (_error) {
      // Refresh failed - try login (will use uaaUrl + clientId to build URL)
      return await this.performLogin();
    }
  }
}
