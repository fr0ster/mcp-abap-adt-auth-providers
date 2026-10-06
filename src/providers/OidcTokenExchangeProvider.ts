/**
 * OIDC Token Exchange Provider
 */

import type { AttemptContext } from '@mcp-abap-adt/auth-errors';
import type {
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces-auth';
import { AUTH_TYPE_USER_TOKEN } from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { oidcEndpointMissing, oidcIssuerRequired } from '../auth/configuration';
import { discoverOidc, mtlsAlias } from '../auth/oidcDiscovery';
import { tokenExchange } from '../auth/oidcToken';
import {
  BaseTokenProvider,
  type ClientAuthenticationConfig,
  refreshTokenRefused,
  type TokenProviderHooks,
} from './BaseTokenProvider';

export interface OidcTokenExchangeProviderConfig
  extends TokenProviderHooks,
    ClientAuthenticationConfig {
  issuerUrl?: string | undefined;
  clientId: string;
  clientSecret?: string | undefined;
  subjectToken: string;
  subjectTokenType: string;
  scope?: string | undefined;
  audience?: string | undefined;
  actorToken?: string | undefined;
  actorTokenType?: string | undefined;
  tokenEndpoint?: string | undefined;
  accessToken?: string | undefined;
  refreshToken?: string | undefined;
  /**
   * When `accessToken` expires (epoch ms), for a token that carries no `exp`
   * of its own. A JWT's `exp` wins; without either the seed counts as expired.
   */
  expiresAt?: number | undefined;
  logger?: ILogger | undefined;
}

export class OidcTokenExchangeProvider extends BaseTokenProvider {
  private config: OidcTokenExchangeProviderConfig;

  constructor(config: OidcTokenExchangeProviderConfig) {
    super(config);
    this.config = config;
    this.logger = config.logger;

    if (config.accessToken) {
      this.authorizationToken = config.accessToken;
      this.expiresAt = this.seededExpiry(config.accessToken, config.expiresAt);
    }
    if (config.refreshToken) {
      this.refreshToken = config.refreshToken;
    }
  }

  protected getAuthType(): OAuth2GrantType {
    return AUTH_TYPE_USER_TOKEN;
  }

  protected async performLogin(attempt: AttemptContext): Promise<ITokenResult> {
    if (!this.config.tokenEndpoint && !this.config.issuerUrl) {
      throw oidcIssuerRequired();
    }
    let discovery: Awaited<ReturnType<typeof discoverOidc>> | null = null;
    // A token endpoint not given ('' included) comes from discovery.
    if (!this.config.tokenEndpoint) {
      if (!this.config.issuerUrl) {
        throw oidcIssuerRequired();
      }
      discovery = await discoverOidc(
        this.config.issuerUrl,
        this.logger,
        attempt.signal,
      );
    }
    const tokenEndpoint =
      this.config.tokenEndpoint || discovery?.token_endpoint;
    if (!tokenEndpoint) {
      throw oidcEndpointMissing('tokenEndpoint');
    }
    const tokens = await tokenExchange(
      tokenEndpoint,
      this.config.clientId,
      this.config.clientSecret,
      this.config.subjectToken,
      this.config.subjectTokenType,
      this.config.scope,
      this.config.audience,
      this.config.actorToken,
      this.config.actorTokenType,
      this.logger,
      await this.requestAuth(
        this.config.tokenEndpoint
          ? undefined
          : mtlsAlias(discovery, 'token_endpoint'),
      ),
      this.siteOptions(attempt.signal),
    );

    return {
      authorizationToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      authType: AUTH_TYPE_USER_TOKEN,
      expiresIn: tokens.expiresIn,
      tokenType: 'jwt',
    };
  }

  /** No refresh grant: the base logs in once instead of refreshing. */
  protected override hasRefreshGrant(): boolean {
    return false;
  }

  protected async performRefresh(): Promise<ITokenResult> {
    throw refreshTokenRefused();
  }
}
