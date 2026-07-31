/**
 * Authorization Code Token Provider
 *
 * Uses authorization_code grant type with browser-based OAuth2 flow.
 * Supports pre-built authorization URLs and automatic refresh.
 */

import type {
  IAuthorizationConfig,
  IAuthorizationStrategy,
  ILogger,
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces';
import { AUTH_TYPE_AUTHORIZATION_CODE } from '@mcp-abap-adt/interfaces';
import {
  exchangeCodeForToken,
  getJwtAuthorizationUrl,
} from '../auth/browserAuth';
import { refreshJwtToken } from '../auth/tokenRefresher';
import { browserCallbackStrategy } from '../strategies';
import { BaseTokenProvider } from './BaseTokenProvider';

export interface AuthorizationCodeProviderConfig {
  // Required for building the authorization URL and for the token exchange
  uaaUrl: string;
  clientId: string;
  clientSecret: string;

  /** Pre-built authorization URL. Carries its own redirect; see the guard below. */
  authorizationUrl?: string;

  /**
   * How the login is conducted. Omitted means a browser callback on the default
   * port — the package's own transport, which a consumer may replace wholesale.
   */
  authorization?: IAuthorizationStrategy<string>;

  // Optional: existing tokens (for the refresh scenario)
  accessToken?: string;
  refreshToken?: string;

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
    const authConfig: IAuthorizationConfig = {
      uaaUrl: this.config.uaaUrl,
      uaaClientId: this.config.clientId,
      uaaClientSecret: this.config.clientSecret,
    };

    const prebuilt = this.config.authorizationUrl;
    const declaredRedirect = prebuilt
      ? new URL(prebuilt).searchParams.get('redirect_uri')
      : null;

    const mismatch = (redirectUri: string): string =>
      `Pre-built authorizationUrl declares redirect_uri ${declaredRedirect}, ` +
      `but the authorization strategy used ${redirectUri}, which does not match. ` +
      'An ephemeral port cannot be used with a pre-built URL.';

    // The provider owns the URL; the strategy owns where it is answered. The
    // guard lives here rather than after the fact because a mismatched redirect
    // produces no callback at all — checking the outcome would mean waiting for
    // a timeout that explains nothing.
    const request = {
      logger: this.logger,
      buildAuthorizationUrl: async (redirectUri: string): Promise<string> => {
        if (prebuilt) {
          if (declaredRedirect && declaredRedirect !== redirectUri) {
            throw new Error(mismatch(redirectUri));
          }
          return prebuilt;
        }
        return getJwtAuthorizationUrl(authConfig, redirectUri);
      },
    };

    // Constructed here means disposed here: whoever constructs, disposes.
    const supplied = this.config.authorization;
    const strategy = supplied ?? browserCallbackStrategy();

    let outcome: { payload: string; redirectUri: string };
    try {
      outcome = await strategy.authorize(request);
    } finally {
      if (!supplied) {
        // A cleanup failure must not replace the reason the login failed.
        await strategy.dispose?.().catch((error: unknown) => {
          this.logger?.warn('[AuthorizationCodeProvider] dispose failed', {
            error: error instanceof Error ? error.message : String(error),
          });
        });
      }
    }

    // The second net. A strategy that never called the builder — `staticCodeStrategy`
    // holds its payload already — passed the first check by not participating in
    // it, and would otherwise reach the exchange with a redirect_uri the
    // pre-built URL never advertised, earning an opaque `invalid_grant`.
    if (declaredRedirect && declaredRedirect !== outcome.redirectUri) {
      throw new Error(mismatch(outcome.redirectUri));
    }

    this.logger?.info('[AuthorizationCodeProvider] Code received', {
      redirectUri: outcome.redirectUri,
    });

    const result = await exchangeCodeForToken(
      authConfig,
      outcome.payload,
      outcome.redirectUri,
      this.logger,
    );

    return {
      authorizationToken: result.accessToken,
      refreshToken: result.refreshToken,
      authType: AUTH_TYPE_AUTHORIZATION_CODE,
      expiresIn: this.calculateExpiresIn(result.accessToken),
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
