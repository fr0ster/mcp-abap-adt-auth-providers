/**
 * OIDC Password Grant Provider
 */

import type {
  ILogger,
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces';
import { AUTH_TYPE_PASSWORD } from '@mcp-abap-adt/interfaces';
import { discoverOidc } from '../auth/oidcDiscovery';
import { passwordGrant, refreshOidcToken } from '../auth/oidcToken';
import { BaseTokenProvider } from './BaseTokenProvider';

export interface OidcPasswordProviderConfig {
  issuerUrl: string;
  clientId: string;
  clientSecret?: string;
  username: string;
  password: string;
  scopes?: string[];
  accessToken?: string;
  refreshToken?: string;
  logger?: ILogger;
}

export class OidcPasswordProvider extends BaseTokenProvider {
  private config: OidcPasswordProviderConfig;

  constructor(config: OidcPasswordProviderConfig) {
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
    return AUTH_TYPE_PASSWORD;
  }

  protected async performLogin(): Promise<ITokenResult> {
    const discovery = await discoverOidc(this.config.issuerUrl, this.logger);
    const scope = this.config.scopes?.join(' ');
    const tokens = await passwordGrant(
      discovery.token_endpoint,
      this.config.clientId,
      this.config.clientSecret,
      this.config.username,
      this.config.password,
      scope,
      this.logger,
    );

    return {
      authorizationToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      authType: AUTH_TYPE_PASSWORD,
      expiresIn: tokens.expiresIn,
      tokenType: 'jwt',
    };
  }

  protected async performRefresh(): Promise<ITokenResult> {
    if (!this.refreshToken) {
      return this.performLogin();
    }

    const discovery = await discoverOidc(this.config.issuerUrl, this.logger);
    const tokens = await refreshOidcToken(
      discovery.token_endpoint,
      this.config.clientId,
      this.config.clientSecret,
      this.refreshToken,
      this.logger,
    );

    return {
      authorizationToken: tokens.accessToken,
      refreshToken: tokens.refreshToken || this.refreshToken,
      authType: AUTH_TYPE_PASSWORD,
      expiresIn: tokens.expiresIn,
      tokenType: 'jwt',
    };
  }
}
