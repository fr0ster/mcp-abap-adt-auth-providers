/**
 * Authorization Code Token Provider
 *
 * Uses authorization_code grant type with browser-based OAuth2 flow.
 * Supports pre-built authorization URLs and automatic refresh.
 */

import type {
  IAuthorizationConfig,
  ILogger,
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

  // Optional: logger for debugging
  logger?: ILogger;
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
    this.logger = config.logger;

    this.logger?.info('[AuthorizationCodeProvider] Provider created', {
      uaaUrl: config.uaaUrl,
      clientId: config.clientId,
      hasAccessToken: !!config.accessToken,
      hasRefreshToken: !!config.refreshToken,
      accessToken: this.formatToken(config.accessToken),
      refreshToken: this.formatToken(config.refreshToken),
      browser: config.browser || 'none',
      redirectPort: config.redirectPort || 3001,
    });

    const missingFields: string[] = [];
    if (!config.uaaUrl) {
      missingFields.push('uaaUrl');
    }
    if (!config.clientId) {
      missingFields.push('clientId');
    }
    if (!config.clientSecret) {
      missingFields.push('clientSecret');
    }
    if (missingFields.length > 0) {
      const error = new Error(
        `Missing required fields: ${missingFields.join(', ')}`,
      ) as Error & { code: string; missingFields: string[] };
      error.code = 'VALIDATION_ERROR';
      error.missingFields = missingFields;
      throw error;
    }

    // Initialize from provided tokens if available
    if (config.accessToken) {
      this.authorizationToken = config.accessToken;
      // Parse expiration from JWT
      this.expiresAt = this.parseExpirationFromJWT(config.accessToken);
      this.logger?.info(
        '[AuthorizationCodeProvider] Initialized with access token',
        {
          accessToken: this.formatToken(config.accessToken),
          hasExpiresAt: !!this.expiresAt,
          expiresAt: this.expiresAt
            ? this.formatExpirationDate(this.expiresAt)
            : undefined,
        },
      );
    }
    if (config.refreshToken) {
      this.refreshToken = config.refreshToken;
      this.logger?.info(
        '[AuthorizationCodeProvider] Initialized with refresh token',
        {
          refreshToken: this.formatToken(config.refreshToken),
        },
      );
    }
  }

  async getTokens(): Promise<ITokenResult> {
    return super.getTokens();
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
    const redirectPort = this.config.redirectPort || 3001;

    // Build authorization URL for logging (same logic as in startBrowserAuth)
    const authorizationUrl =
      authConfig.authorizationUrl ??
      `${authConfig.uaaUrl}/oauth/authorize?client_id=${encodeURIComponent(authConfig.uaaClientId)}&redirect_uri=${encodeURIComponent(`http://localhost:${redirectPort}/callback`)}&response_type=code`;

    this.logger?.info(
      '[AuthorizationCodeProvider] Performing login via browser',
      {
        browser,
        redirectPort,
        authorizationUrl,
        uaaUrl: authConfig.uaaUrl,
        clientId: authConfig.uaaClientId,
      },
    );

    // Wrap startBrowserAuth with timeout
    const timeoutMs = 30 * 1000; // 30 seconds
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => {
        reject(
          new Error(
            `Authentication timeout after ${timeoutMs / 1000} seconds. Please try again.`,
          ),
        );
      }, timeoutMs);
    });

    const result = await Promise.race([
      startBrowserAuth(
        authConfig,
        browser,
        this.logger || undefined, // Pass logger to browserAuth
        redirectPort,
      ),
      timeoutPromise,
    ]);

    this.logger?.info('[AuthorizationCodeProvider] Login completed', {
      hasAccessToken: !!result.accessToken,
      hasRefreshToken: !!result.refreshToken,
      accessToken: this.formatToken(result.accessToken),
      refreshToken: this.formatToken(result.refreshToken),
      accessTokenLength: result.accessToken?.length || 0,
    });

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

    this.logger?.info('[AuthorizationCodeProvider] Refreshing token');
    // Try refresh first
    try {
      const result = await refreshJwtToken(
        this.refreshToken,
        this.config.uaaUrl,
        this.config.clientId,
        this.config.clientSecret,
      );

      this.logger?.info('[AuthorizationCodeProvider] Token refresh completed', {
        hasAccessToken: !!result.accessToken,
        hasRefreshToken: !!result.refreshToken,
        newAccessToken: this.formatToken(result.accessToken),
        newRefreshToken: this.formatToken(result.refreshToken),
        oldRefreshToken: this.formatToken(this.refreshToken),
      });

      const expiresIn = this.calculateExpiresIn(result.accessToken);

      return {
        authorizationToken: result.accessToken,
        refreshToken: result.refreshToken || this.refreshToken, // Keep old if new not provided
        authType: AUTH_TYPE_AUTHORIZATION_CODE,
        expiresIn,
      };
    } catch (error) {
      this.logger?.warn(
        '[AuthorizationCodeProvider] Token refresh failed, falling back to login',
        {
          error: error instanceof Error ? error.message : String(error),
        },
      );
      // Refresh failed - try login (will use uaaUrl + clientId to build URL)
      return await this.performLogin();
    }
  }
}
