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
  AuthOutcome,
  IAuthProvider,
  IAuthRejection,
  ILogonTarget,
  IRefreshableTokenProvider,
  IRequestTarget,
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { OK, oops, ownLabel, safely } from '../auth/refusal';
import { readRejection } from '../auth/rejection';

/** What every token provider's config may carry beside its own fields. */
export interface TokenProviderHooks {
  /**
   * Called after every NEW token — a login or a refresh, never a cache hit —
   * and awaited before the provider answers. The broker persists through it.
   * Best effort: a failure is logged by class name and does not fail the
   * authentication.
   */
  onTokens?: (result: ITokenResult) => Promise<void>;
}

/**
 * Abstract base class for token providers
 *
 * Provides common functionality for token lifecycle management:
 * - Caches tokens internally
 * - Checks expiration before returning tokens
 * - Automatically refreshes expired tokens
 * - Falls back to one login if refresh fails — the base decides it, never
 *   a provider's own performRefresh
 * - Shares one in-flight renewal among concurrent callers
 */
export abstract class BaseTokenProvider
  implements IRefreshableTokenProvider, IAuthProvider
{
  protected authorizationToken?: string;
  protected refreshToken?: string;
  protected expiresAt?: number; // timestamp in milliseconds
  protected tokenType?: 'jwt' | 'saml' | 'opaque';
  protected logger?: ILogger;
  private readonly onTokens?: TokenProviderHooks['onTokens'];
  /** The token last put on a request, so rejected() can tell a renewal from a repeat. */
  private presented?: string;
  /** The renewal in flight; concurrent callers share it (one refresh, at most one login). */
  private renewal?: Promise<ITokenResult>;

  constructor(hooks: TokenProviderHooks = {}) {
    this.onTokens = hooks.onTokens;
  }

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
   * What a log line may say about a token: that it is there, and its length.
   * Never any of its characters — a UAA refresh token is about 34 characters,
   * so even "the first and last 25" is the whole secret.
   */
  protected formatToken(token?: string): string | undefined {
    if (!token) return undefined;
    return `<redacted, ${token.length} chars>`;
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
   * Must be implemented by concrete providers. It never logs in: a failed
   * refresh throws, and the base runs the single login.
   */
  protected abstract performRefresh(): Promise<ITokenResult>;

  /** False for a grant with no refresh: the base then skips performRefresh and logs in once. */
  protected hasRefreshGrant(): boolean {
    return true;
  }

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
    // A renewal in flight is replacing the cache: wait for it, not the old token
    if (this.renewal) return this.renewal;
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
        tokenType: this.tokenType ?? 'jwt',
        expiresAt: this.expiresAt,
        expiresIn: this.expiresAt
          ? Math.floor((this.expiresAt - Date.now()) / 1000)
          : undefined,
      };
    }

    return this.refreshTokens();
  }

  /**
   * A new token, never the cached one: the refresh token when there is one,
   * the login flow when there is none or the refresh is refused.
   *
   * `getTokens()` answers the cache while the token looks valid, so a caller
   * holding a 401 — the server refused a token the clock still accepts — has
   * no other way to get a different one. What this obtains replaces the cache.
   */
  async refreshTokens(): Promise<ITokenResult> {
    if (!this.renewal) {
      this.renewal = this.renew().finally(() => {
        this.renewal = undefined;
      });
    }
    return this.renewal;
  }

  /** One renewal: one refresh, then — only if it is refused or impossible — one login. */
  private async renew(): Promise<ITokenResult> {
    const spent = this.refreshToken;
    if (spent && this.hasRefreshGrant()) {
      this.logger?.info(
        '[BaseTokenProvider] Obtaining a new token by refresh',
        {
          oldToken: this.formatToken(this.authorizationToken),
          refreshToken: this.formatToken(spent),
        },
      );
      try {
        const result = await this.performRefresh();
        this.updateTokens(result);
        await this.obtained(result);
        this.logger?.info('[BaseTokenProvider] Token refreshed successfully', {
          newToken: this.formatToken(result.authorizationToken),
          newRefreshToken: this.formatToken(result.refreshToken),
        });
        return result;
      } catch (error) {
        this.logger?.warn('[BaseTokenProvider] Refresh failed', {
          error: error instanceof Error ? error.message : String(error),
        });
        // The refresh token was refused: it is spent, so a login follows.
        // Only that one — never a token something else stored meanwhile.
        if (this.refreshToken === spent) this.refreshToken = undefined;
      }
    }

    this.logger?.info(
      '[BaseTokenProvider] No usable refresh token, performing login',
    );
    const result = await this.performLogin();
    this.updateTokens(result);
    await this.obtained(result);
    this.logger?.info('[BaseTokenProvider] Login completed', {
      newToken: this.formatToken(result.authorizationToken),
      newRefreshToken: this.formatToken(result.refreshToken),
    });
    return result;
  }

  async validateToken(_token: string, _serviceUrl?: string): Promise<boolean> {
    this.logger?.debug('[BaseTokenProvider] Validating token');
    if (this.tokenType && this.tokenType !== 'jwt') {
      if (!this.expiresAt) {
        this.logger?.warn(
          '[BaseTokenProvider] Token validation failed: missing expiresAt for non-JWT token',
        );
        return false;
      }
      const bufferMs = 60 * 1000;
      const isValid = Date.now() < this.expiresAt - bufferMs;
      this.logger?.info('[BaseTokenProvider] Token validation result', {
        isValid,
        tokenType: this.tokenType,
        expiresAt: this.formatExpirationDate(this.expiresAt),
        expiresIn: Math.floor((this.expiresAt - Date.now()) / 1000),
      });
      return isValid;
    }
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
    this.tokenType = result.tokenType ?? 'jwt';
    if (result.expiresAt) {
      this.expiresAt = result.expiresAt;
    } else if (result.expiresIn) {
      this.expiresAt = Date.now() + result.expiresIn * 1000;
    } else if (this.tokenType === 'jwt') {
      // Try to parse expiration from JWT if expiresIn not provided
      this.expiresAt = this.parseExpirationFromJWT(result.authorizationToken);
    } else {
      this.expiresAt = undefined;
    }
    this.logger?.info('[BaseTokenProvider] Tokens updated', {
      oldToken,
      newToken: this.formatToken(result.authorizationToken),
      newRefreshToken: this.formatToken(result.refreshToken),
      tokenType: this.tokenType,
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

  private async obtained(result: ITokenResult): Promise<void> {
    if (!this.onTokens) return;
    try {
      await this.onTokens(result);
    } catch (error) {
      // Class name only: the hook holds the tokens, its message is foreign text.
      this.logger?.warn(
        '[BaseTokenProvider] onTokens failed; the token stands',
        {
          error: ownLabel(error),
        },
      );
    }
  }

  // ---- IAuthProvider: the process calls these, the same for every provider.

  /** The grant type, so a log line says which way in ran. */
  get kind(): string {
    return this.getAuthType();
  }

  /** The subject of a fixed refusal: "<grant type> token request failed". */
  private get obtaining(): string {
    return `${this.kind} token request`;
  }

  async prepare(): Promise<AuthOutcome> {
    return safely(this.obtaining, async () => {
      await this.getTokens();
      return OK;
    });
  }

  /** A token is presented per request; a logon needs nothing from it. */
  async establish(_logon: ILogonTarget): Promise<AuthOutcome> {
    return OK;
  }

  /** Per attempt: getTokens() renews an expired token here. */
  async authorize(request: IRequestTarget): Promise<AuthOutcome> {
    return safely(this.obtaining, async () => {
      const result = await this.getTokens();
      this.applyToken(request, result);
      this.presented = result.authorizationToken;
      return OK;
    });
  }

  /**
   * A new token — refresh, else login. Ok only if it differs; retrying is the
   * caller's. A renewal in flight is joined; a presented token already
   * superseded by a renewal answers Ok without renewing again.
   */
  async rejected(rejection: IAuthRejection): Promise<AuthOutcome> {
    return safely(this.obtaining, async () => {
      // A 403, a redirect, a 5xx: a new token would be refused the same way.
      const read = readRejection(rejection);
      if (read.verdict === 'not-credential') {
        return { ok: false, refusal: read.refusal };
      }
      // Nothing presented yet (a rejection before any authorize): the token
      // held — from a login or from config — is the one taken as refused.
      const refused = this.presented ?? this.authorizationToken;
      if (
        !this.renewal &&
        refused !== undefined &&
        this.authorizationToken !== undefined &&
        this.authorizationToken !== refused
      ) {
        return OK;
      }
      const result = await this.refreshTokens();
      if (refused !== undefined && result.authorizationToken === refused) {
        return oops(
          'the renewal returned the credential that was refused',
          'the token source must issue a new token; log in again',
        );
      }
      return OK;
    });
  }

  /** How this provider's token rides on a request. Bearer by default. */
  protected applyToken(request: IRequestTarget, result: ITokenResult): void {
    request.header('Authorization', `Bearer ${result.authorizationToken}`);
  }
}
