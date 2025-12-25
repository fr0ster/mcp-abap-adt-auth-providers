/**
 * Base Token Provider
 *
 * Abstract base class for all token providers.
 * Implements common token lifecycle management:
 * - Token caching
 * - Expiration checking
 * - Automatic refresh/relogin
 */

import type {
  ILogger,
  ITokenProvider,
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces';

/**
 * Abstract base class for token providers
 *
 * Provides common functionality for token lifecycle management:
 * - Caches tokens internally
 * - Checks expiration before returning tokens
 * - Automatically refreshes expired tokens
 * - Falls back to login if refresh fails
 */
export abstract class BaseTokenProvider implements ITokenProvider {
  protected authorizationToken?: string;
  protected refreshToken?: string;
  protected expiresAt?: number; // timestamp in milliseconds
  protected logger?: ILogger;

  /**
   * Format timestamp to readable date/time string
   * @param timestamp Timestamp in milliseconds
   * @returns Formatted date string (e.g., "2025-12-25 19:21:27 UTC")
   */
  protected formatExpirationDate(timestamp: number): string {
    const date = new Date(timestamp);
    const year = date.getUTCFullYear();
    const month = String(date.getUTCMonth() + 1).padStart(2, '0');
    const day = String(date.getUTCDate()).padStart(2, '0');
    const hours = String(date.getUTCHours()).padStart(2, '0');
    const minutes = String(date.getUTCMinutes()).padStart(2, '0');
    const seconds = String(date.getUTCSeconds()).padStart(2, '0');
    return `${year}-${month}-${day} ${hours}:${minutes}:${seconds} UTC`;
  }

  /**
   * Format token for logging (start...end)
   */
  protected formatToken(token?: string): string | undefined {
    if (!token) return undefined;
    if (token.length <= 50) return token;
    return `${token.substring(0, 25)}...${token.substring(token.length - 25)}`;
  }

  /**
   * Check if current token is valid (not expired)
   * @returns true if token exists and is not expired, false otherwise
   */
  protected isTokenValid(): boolean {
    if (!this.authorizationToken || !this.expiresAt) {
      this.logger?.debug(
        '[BaseTokenProvider] Token invalid: missing token or expiration',
        {
          hasToken: !!this.authorizationToken,
          hasExpiresAt: !!this.expiresAt,
        },
      );
      return false;
    }
    // Add 60 second buffer to account for clock skew and network latency
    const bufferMs = 60 * 1000;
    const now = Date.now();
    const isValid = now < this.expiresAt - bufferMs;
    this.logger?.debug('[BaseTokenProvider] Token validation check', {
      now: this.formatExpirationDate(now),
      expiresAt: this.formatExpirationDate(this.expiresAt),
      expiresIn: Math.floor((this.expiresAt - now) / 1000),
      isValid,
      bufferMs,
    });
    return isValid;
  }

  /**
   * Abstract method to perform initial login/authorization
   * Must be implemented by concrete providers
   */
  protected abstract performLogin(): Promise<ITokenResult>;

  /**
   * Abstract method to refresh token
   * Must be implemented by concrete providers
   */
  protected abstract performRefresh(): Promise<ITokenResult>;

  /**
   * Abstract method to get authentication type
   * Must be implemented by concrete providers
   */
  protected abstract getAuthType(): OAuth2GrantType;

  /**
   * Main method - handles token lifecycle
   *
   * 1. If token is valid, return cached token
   * 2. If token expired and refresh token available, try refresh
   * 3. If refresh fails or no refresh token, perform login
   *
   * @returns Promise that resolves to token result
   */
  async getTokens(): Promise<ITokenResult> {
    this.logger?.debug('[BaseTokenProvider] getTokens called', {
      hasToken: !!this.authorizationToken,
      hasExpiresAt: !!this.expiresAt,
      hasRefreshToken: !!this.refreshToken,
      currentToken: this.formatToken(this.authorizationToken),
    });
    // If token is valid, return cached
    const isValid = this.isTokenValid();
    if (isValid) {
      const authorizationToken = this.authorizationToken;
      if (!authorizationToken) {
        throw new Error('Authorization token is missing.');
      }
      this.logger?.info('[BaseTokenProvider] Returning cached valid token', {
        token: this.formatToken(authorizationToken),
        expiresIn: this.expiresAt
          ? Math.floor((this.expiresAt - Date.now()) / 1000)
          : undefined,
      });
      return {
        authorizationToken,
        refreshToken: this.refreshToken,
        authType: this.getAuthType(),
        expiresIn: this.expiresAt
          ? Math.floor((this.expiresAt - Date.now()) / 1000)
          : undefined,
      };
    }

    // Try refresh if we have refresh token
    if (this.refreshToken) {
      this.logger?.info(
        '[BaseTokenProvider] Token invalid, attempting refresh',
        {
          oldToken: this.formatToken(this.authorizationToken),
          refreshToken: this.formatToken(this.refreshToken),
        },
      );
      try {
        const result = await this.performRefresh();
        this.updateTokens(result);
        this.logger?.info('[BaseTokenProvider] Token refreshed successfully', {
          newToken: this.formatToken(result.authorizationToken),
          newRefreshToken: this.formatToken(result.refreshToken),
        });
        return result;
      } catch (error) {
        this.logger?.warn('[BaseTokenProvider] Refresh failed', {
          error: error instanceof Error ? error.message : String(error),
        });
        // Refresh failed - need to login
        // Clear refresh token as it's invalid
        this.refreshToken = undefined;
        // Fall through to login
      }
    }

    // Perform login
    this.logger?.info(
      '[BaseTokenProvider] Token invalid and no refresh token, performing login',
    );
    const result = await this.performLogin();
    this.updateTokens(result);
    this.logger?.info('[BaseTokenProvider] Login completed', {
      newToken: this.formatToken(result.authorizationToken),
      newRefreshToken: this.formatToken(result.refreshToken),
    });
    return result;
  }

  async validateToken(_token: string, _serviceUrl?: string): Promise<boolean> {
    this.logger?.debug('[BaseTokenProvider] Validating token');
    const expiresAt = this.parseExpirationFromJWT(_token);
    if (!expiresAt) {
      this.logger?.warn(
        '[BaseTokenProvider] Token validation failed: cannot parse expiration',
      );
      return false;
    }
    const bufferMs = 60 * 1000;
    const isValid = Date.now() < expiresAt - bufferMs;
    this.logger?.info('[BaseTokenProvider] Token validation result', {
      isValid,
      expiresAt: this.formatExpirationDate(expiresAt),
      expiresIn: Math.floor((expiresAt - Date.now()) / 1000),
    });
    return isValid;
  }

  /**
   * Update internal token cache from result
   * @param result Token result to cache
   */
  protected updateTokens(result: ITokenResult): void {
    const oldToken = this.formatToken(this.authorizationToken);
    this.authorizationToken = result.authorizationToken;
    this.refreshToken = result.refreshToken;
    if (result.expiresIn) {
      this.expiresAt = Date.now() + result.expiresIn * 1000;
    } else {
      // Try to parse expiration from JWT if expiresIn not provided
      this.expiresAt = this.parseExpirationFromJWT(result.authorizationToken);
    }
    this.logger?.info('[BaseTokenProvider] Tokens updated', {
      oldToken,
      newToken: this.formatToken(result.authorizationToken),
      newRefreshToken: this.formatToken(result.refreshToken),
      expiresAt: this.expiresAt
        ? this.formatExpirationDate(this.expiresAt)
        : undefined,
    });
  }

  /**
   * Parse expiration time from JWT token
   * @param token JWT token string
   * @returns Expiration timestamp in milliseconds, or undefined if cannot parse
   */
  protected parseExpirationFromJWT(token: string): number | undefined {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        return undefined;
      }

      const payload = parts[1];
      // Convert base64url to base64
      const base64 = payload.replace(/-/g, '+').replace(/_/g, '/');
      // Add padding if needed
      const padded = base64 + '=='.substring(0, (4 - (base64.length % 4)) % 4);

      const decoded = Buffer.from(padded, 'base64').toString('utf8');
      const claims = JSON.parse(decoded);

      if (claims.exp) {
        // Convert to milliseconds
        return claims.exp * 1000;
      }
    } catch {
      // Failed to parse - return undefined
    }
    return undefined;
  }

  /**
   * Calculate expiresIn from JWT token
   * @param token JWT token string
   * @returns Expiration time in seconds, or undefined if cannot parse
   */
  protected calculateExpiresIn(token: string): number | undefined {
    const expiresAt = this.parseExpirationFromJWT(token);
    if (!expiresAt) {
      return undefined;
    }
    const now = Date.now();
    const expiresIn = Math.floor((expiresAt - now) / 1000);
    return expiresIn > 0 ? expiresIn : undefined;
  }
}
