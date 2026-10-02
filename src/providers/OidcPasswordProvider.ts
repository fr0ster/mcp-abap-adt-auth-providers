/**
 * OIDC Password Grant Provider
 */

import type {
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces-auth';
import { AUTH_TYPE_PASSWORD } from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { discoverOidc } from '../auth/oidcDiscovery';
import { passwordGrant, refreshOidcToken } from '../auth/oidcToken';
import { RefreshError } from '../errors/TokenProviderErrors';
import {
  BaseTokenProvider,
  type TokenProviderHooks,
} from './BaseTokenProvider';

export interface OidcPasswordProviderConfig extends TokenProviderHooks {
  issuerUrl?: string;
  clientId: string;
  clientSecret?: string;
  username: string;
  password: string;
  scopes?: string[];
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

export class OidcPasswordProvider extends BaseTokenProvider {
  private config: OidcPasswordProviderConfig;

  constructor(config: OidcPasswordProviderConfig) {
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
    return AUTH_TYPE_PASSWORD;
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
    const scope = this.config.scopes?.join(' ');
    const tokens = await passwordGrant(
      tokenEndpoint,
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
      throw new RefreshError('Refresh token is required for refresh');
    }

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
    const tokens = await refreshOidcToken(
      tokenEndpoint,
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
