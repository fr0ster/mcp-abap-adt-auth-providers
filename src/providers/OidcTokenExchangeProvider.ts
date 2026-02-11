/**
 * OIDC Token Exchange Provider
 */

import type {
  ILogger,
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces';
import { AUTH_TYPE_USER_TOKEN } from '@mcp-abap-adt/interfaces';
import { discoverOidc } from '../auth/oidcDiscovery';
import { tokenExchange } from '../auth/oidcToken';
import { BaseTokenProvider } from './BaseTokenProvider';

export interface OidcTokenExchangeProviderConfig {
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
  logger?: ILogger;
}

export class OidcTokenExchangeProvider extends BaseTokenProvider {
  private config: OidcTokenExchangeProviderConfig;

  constructor(config: OidcTokenExchangeProviderConfig) {
    super();
    this.config = config;
    this.logger = config.logger;

    if (config.accessToken) {
      this.authorizationToken = config.accessToken;
      this.expiresAt = this.parseExpirationFromJWT(config.accessToken);
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
    if (this.config.tokenEndpoint === undefined) {
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
    );

    return {
      authorizationToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      authType: AUTH_TYPE_USER_TOKEN,
      expiresIn: tokens.expiresIn,
      tokenType: 'jwt',
    };
  }

  protected async performRefresh(): Promise<ITokenResult> {
    return this.performLogin();
  }
}
