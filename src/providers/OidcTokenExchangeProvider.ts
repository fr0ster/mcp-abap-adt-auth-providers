/**
 * OIDC Token Exchange Provider
 */

import type {
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces-auth';
import { AUTH_TYPE_USER_TOKEN } from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { discoverOidc, mtlsAlias } from '../auth/oidcDiscovery';
import { tokenExchange } from '../auth/oidcToken';
import { RefreshError } from '../errors/TokenProviderErrors';
import {
  BaseTokenProvider,
  type ClientAuthenticationConfig,
  type TokenProviderHooks,
} from './BaseTokenProvider';

export interface OidcTokenExchangeProviderConfig
  extends TokenProviderHooks,
    ClientAuthenticationConfig {
  issuerUrl?: string;
  clientId: string;
  clientSecret?: string;
  subjectToken: string;
  subjectTokenType: string;
  scope?: string;
  audience?: string;
  actorToken?: string;
  actorTokenType?: string;
  tokenEndpoint?: string;
  accessToken?: string;
  refreshToken?: string;
  /**
   * When `accessToken` expires (epoch ms), for a token that carries no `exp`
   * of its own. A JWT's `exp` wins; without either the seed counts as expired.
   */
  expiresAt?: number;
  logger?: ILogger;
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

  protected async performLogin(): Promise<ITokenResult> {
    if (!this.config.tokenEndpoint && !this.config.issuerUrl) {
      throw new Error('OIDC issuerUrl is required when discovery is used');
    }
    let discovery: Awaited<ReturnType<typeof discoverOidc>> | null = null;
    // A token endpoint not given ('' included) comes from discovery.
    if (!this.config.tokenEndpoint) {
      if (!this.config.issuerUrl) {
        throw new Error('OIDC issuerUrl is required when discovery is used');
      }
      discovery = await discoverOidc(this.config.issuerUrl, this.logger);
    }
    const tokenEndpoint =
      this.config.tokenEndpoint || discovery?.token_endpoint;
    if (!tokenEndpoint) {
      throw new Error(
        'OIDC token endpoint is required (tokenEndpoint or discovery)',
      );
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
    throw new RefreshError('token exchange has no refresh grant');
  }
}
