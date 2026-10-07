/**
 * Authorization Code Token Provider
 *
 * Uses authorization_code grant type with browser-based OAuth2 flow.
 * Supports pre-built authorization URLs and automatic refresh.
 */

import { type AttemptContext, authError } from '@mcp-abap-adt/auth-errors';
import type {
  AuthorizationRequest,
  IAuthorizationStrategy,
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces-auth';
import { AUTH_TYPE_AUTHORIZATION_CODE } from '@mcp-abap-adt/interfaces-auth';
import type { IAuthorizationConfig } from '@mcp-abap-adt/interfaces-auth-sap';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import {
  exchangeCodeForToken,
  getJwtAuthorizationUrl,
} from '../auth/browserAuth';
import {
  misconfigured,
  ownOptions,
  requiredFieldsMissing,
} from '../auth/configuration';
import { refreshJwtToken } from '../auth/tokenRefresher';
import { logQuietly } from '../auth/tokenRequest';
import { browserCallbackStrategy } from '../strategies';
import {
  BaseTokenProvider,
  type ClientAuthenticationConfig,
  refreshTokenRefused,
  type TokenProviderHooks,
} from './BaseTokenProvider';
import type { LoginFactoryOptions } from './LoginFactoryOptions';

export interface AuthorizationCodeProviderConfig
  extends TokenProviderHooks,
    ClientAuthenticationConfig {
  // Required for building the authorization URL and for the token exchange
  uaaUrl: string;
  clientId: string;
  /** Required, unless `clientAuthentication` is given — never both. */
  clientSecret?: string | undefined;

  /** Pre-built authorization URL. Carries its own redirect; see the guard below. */
  authorizationUrl?: string | undefined;

  /**
   * How the login is conducted. Required — see the static factories for the
   * usual choice.
   */
  authorization: IAuthorizationStrategy<string>;

  // Optional: existing tokens (for the refresh scenario)
  accessToken?: string | undefined;
  refreshToken?: string | undefined;
  /**
   * When `accessToken` expires (epoch ms), for a token that carries no `exp`
   * of its own. A JWT's `exp` wins; without either the seed counts as expired.
   */
  expiresAt?: number | undefined;

  logger?: ILogger | undefined;
}

/**
 * Authorization Code token provider
 *
 * Uses authorization_code grant type with browser-based OAuth2 flow.
 * Supports pre-built authorization URLs and automatic token refresh.
 */
/**
 * The `redirect_uri` a pre-built `authorizationUrl` declares, or `null`. A URL
 * that does not parse is a configuration error naming `authorizationUrl` —
 * never the value. Known limit (Task 26 ruling): interfaces-auth 6.0.0's
 * `CONFIG_CASES` has no "invalid value" case, so it is
 * `required-fields-missing` (a usable `authorizationUrl` is missing) until a
 * later interfaces-auth major names one.
 */
function declaredRedirectOf(prebuilt: string): string | null {
  let url: URL;
  try {
    url = new URL(prebuilt);
  } catch {
    throw requiredFieldsMissing(['authorizationUrl']);
  }
  return url.searchParams.get('redirect_uri');
}

export class AuthorizationCodeProvider extends BaseTokenProvider {
  private config: AuthorizationCodeProviderConfig;

  constructor(options: AuthorizationCodeProviderConfig) {
    // Read once as own data (a hostile object throws nothing of its own).
    const config = ownOptions<AuthorizationCodeProviderConfig>(options);
    super(config);
    this.config = config;
    this.logger = config.logger;

    logQuietly(() =>
      this.logger?.info('[AuthorizationCodeProvider] Provider created', {
        hasAccessToken: !!config.accessToken,
        hasRefreshToken: !!config.refreshToken,
        accessToken: this.formatToken(config.accessToken),
        refreshToken: this.formatToken(config.refreshToken),
      }),
    );

    const missingFields: string[] = [];
    if (!config.uaaUrl) {
      missingFields.push('uaaUrl');
    }
    if (!config.clientId) {
      missingFields.push('clientId');
    }
    // A strategy authenticates the client instead (never both: the base).
    if (!config.clientSecret && !config.clientAuthentication) {
      missingFields.push('clientSecret');
    }
    if (missingFields.length > 0) {
      // E1: the names of what is missing, never a value.
      throw requiredFieldsMissing(missingFields);
    }
    // A pre-built URL that cannot be read is refused here, not at login.
    if (config.authorizationUrl) declaredRedirectOf(config.authorizationUrl);

    // Initialize from provided tokens if available
    if (config.accessToken) {
      this.authorizationToken = config.accessToken;
      // The JWT's exp, else the stated expiresAt
      this.expiresAt = this.seededExpiry(config.accessToken, config.expiresAt);
      logQuietly(() =>
        this.logger?.info(
          '[AuthorizationCodeProvider] Initialized with access token',
          {
            accessToken: this.formatToken(config.accessToken),
            hasExpiresAt: !!this.expiresAt,
            expiresAt: this.expiresAt
              ? this.formatExpirationDate(this.expiresAt)
              : undefined,
          },
        ),
      );
    }
    if (config.refreshToken) {
      this.refreshToken = config.refreshToken;
      logQuietly(() =>
        this.logger?.info(
          '[AuthorizationCodeProvider] Initialized with refresh token',
          {
            refreshToken: this.formatToken(config.refreshToken),
          },
        ),
      );
    }
  }

  /** The usual choice: a browser login answered on a local callback. */
  static inBrowser(
    config: Omit<AuthorizationCodeProviderConfig, 'authorization'>,
    options: LoginFactoryOptions = {},
  ): AuthorizationCodeProvider {
    return new AuthorizationCodeProvider({
      ...ownOptions<typeof config>(config),
      authorization: browserCallbackStrategy({
        signal: ownOptions<LoginFactoryOptions>(options).signal,
      }),
    });
  }

  protected getAuthType(): OAuth2GrantType {
    return AUTH_TYPE_AUTHORIZATION_CODE;
  }

  protected async performLogin(attempt: AttemptContext): Promise<ITokenResult> {
    const authConfig: IAuthorizationConfig = {
      uaaUrl: this.config.uaaUrl,
      uaaClientId: this.config.clientId,
      // Required without a strategy (constructor); unused with one.
      uaaClientSecret: this.config.clientSecret ?? '',
    };

    const prebuilt = this.config.authorizationUrl;
    const declaredRedirect = prebuilt ? declaredRedirectOf(prebuilt) : null;

    // E12: the two addresses are diagnostics, never in the words (L9).
    const mismatch = (redirectUri: string) =>
      misconfigured(
        authError.configuration(
          { case: 'redirect-mismatch', fields: ['authorizationUrl'] },
          { configuredUri: declaredRedirect, strategyUri: redirectUri },
        ),
      );

    // The provider owns the URL; the strategy owns where it is answered. The
    // guard lives here rather than after the fact because a mismatched redirect
    // produces no callback at all — checking the outcome would mean waiting
    // for a callback that never comes.
    const request: AuthorizationRequest = {
      logger: this.logger,
      // The attempt's signal: every waiter gone ends the login (spec §6b).
      signal: attempt.signal,
      buildAuthorizationUrl: async (redirectUri: string): Promise<string> => {
        if (prebuilt) {
          if (declaredRedirect && declaredRedirect !== redirectUri) {
            throw mismatch(redirectUri);
          }
          return prebuilt;
        }
        return getJwtAuthorizationUrl(authConfig, redirectUri);
      },
    };

    const strategy = this.config.authorization;

    // The strategy holds a socket or a reader: it starts only once the
    // previous attempt has released its own (the drain, spec §6b).
    const outcome = await attempt.exclusive(() => strategy.authorize(request));

    // The second net. A strategy that never called the builder — `staticCodeStrategy`
    // holds its payload already — passed the first check by not participating in
    // it, and would otherwise reach the exchange with a redirect_uri the
    // pre-built URL never advertised, earning an opaque `invalid_grant`.
    if (declaredRedirect && declaredRedirect !== outcome.redirectUri) {
      throw mismatch(outcome.redirectUri);
    }

    logQuietly(() =>
      this.logger?.info('[AuthorizationCodeProvider] Code received'),
    );

    const result = await exchangeCodeForToken(
      authConfig,
      outcome.payload,
      outcome.redirectUri,
      this.logger,
      await this.requestAuth(),
      this.siteOptions(attempt.signal),
    );

    return {
      authorizationToken: result.accessToken,
      refreshToken: result.refreshToken,
      authType: AUTH_TYPE_AUTHORIZATION_CODE,
      expiresIn: this.calculateExpiresIn(result.accessToken),
    };
  }

  protected async performRefresh(
    refreshToken: string,
    _signal?: AbortSignal,
  ): Promise<ITokenResult> {
    if (!refreshToken) {
      throw refreshTokenRefused();
    }

    logQuietly(() =>
      this.logger?.info('[AuthorizationCodeProvider] Refreshing token'),
    );
    // A failure throws: the base decides the one login (rule 6).
    const result = await refreshJwtToken(
      refreshToken,
      this.config.uaaUrl,
      this.config.clientId,
      this.config.clientSecret,
      await this.requestAuth(),
      this.logger,
      this.siteOptions(),
    );

    logQuietly(() =>
      this.logger?.info('[AuthorizationCodeProvider] Token refresh completed', {
        hasAccessToken: !!result.accessToken,
        hasRefreshToken: !!result.refreshToken,
        newAccessToken: this.formatToken(result.accessToken),
        newRefreshToken: this.formatToken(result.refreshToken),
        oldRefreshToken: this.formatToken(refreshToken),
      }),
    );

    const expiresIn = this.calculateExpiresIn(result.accessToken);

    return {
      authorizationToken: result.accessToken,
      refreshToken: result.refreshToken || refreshToken, // Keep old if new not provided
      authType: AUTH_TYPE_AUTHORIZATION_CODE,
      expiresIn,
    };
  }
}
