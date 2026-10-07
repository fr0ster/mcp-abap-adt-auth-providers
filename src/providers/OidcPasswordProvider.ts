/**
 * OIDC Password Grant Provider
 */

import type { AttemptContext } from '@mcp-abap-adt/auth-errors';
import type {
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces-auth';
import { AUTH_TYPE_PASSWORD } from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { throwIfAborted } from '../auth/attempt';
import {
  oidcEndpointMissing,
  oidcIssuerRequired,
  ownOptions,
} from '../auth/configuration';
import { discoverOidc, mtlsAlias } from '../auth/oidcDiscovery';
import { passwordGrant, refreshOidcToken } from '../auth/oidcToken';
import {
  BaseTokenProvider,
  type ClientAuthenticationConfig,
  refreshTokenRefused,
  type TokenProviderHooks,
} from './BaseTokenProvider';

export interface OidcPasswordProviderConfig
  extends TokenProviderHooks,
    ClientAuthenticationConfig {
  issuerUrl?: string | undefined;
  clientId: string;
  clientSecret?: string | undefined;
  username: string;
  password: string;
  scopes?: string[] | undefined;
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

export class OidcPasswordProvider extends BaseTokenProvider {
  private config: OidcPasswordProviderConfig;

  constructor(options: OidcPasswordProviderConfig) {
    // Read once as own data (a hostile object throws nothing of its own).
    const config = ownOptions<OidcPasswordProviderConfig>(options);
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
    const scope = this.config.scopes?.join(' ');
    const tokens = await passwordGrant(
      tokenEndpoint,
      this.config.clientId,
      this.config.clientSecret,
      this.config.username,
      this.config.password,
      scope,
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
      authType: AUTH_TYPE_PASSWORD,
      expiresIn: tokens.expiresIn,
      tokenType: 'jwt',
    };
  }

  protected async performRefresh(
    refreshToken: string,
    signal: AbortSignal,
    dispatched: () => void,
  ): Promise<ITokenResult> {
    if (!refreshToken) {
      throw refreshTokenRefused();
    }

    if (!this.config.tokenEndpoint && !this.config.issuerUrl) {
      throw oidcIssuerRequired();
    }
    let discovery: Awaited<ReturnType<typeof discoverOidc>> | null = null;
    // As at login: a token endpoint not given ('' included) is discovered.
    if (!this.config.tokenEndpoint) {
      if (!this.config.issuerUrl) {
        throw oidcIssuerRequired();
      }
      discovery = await discoverOidc(
        this.config.issuerUrl,
        this.logger,
        signal,
      );
    }
    const tokenEndpoint =
      this.config.tokenEndpoint || discovery?.token_endpoint;
    if (!tokenEndpoint) {
      throw oidcEndpointMissing('tokenEndpoint');
    }
    // Nothing is sent once the attempt is aborted; once sent, the refresh
    // runs on (spec §6b).
    throwIfAborted(signal);
    const tokens = await refreshOidcToken(
      tokenEndpoint,
      this.config.clientId,
      this.config.clientSecret,
      refreshToken,
      this.logger,
      // The alias belongs to the discovered endpoint only.
      await this.requestAuth(
        this.config.tokenEndpoint
          ? undefined
          : mtlsAlias(discovery, 'token_endpoint'),
      ),
      this.refreshSiteOptions(dispatched),
    );

    return {
      authorizationToken: tokens.accessToken,
      refreshToken: tokens.refreshToken || refreshToken,
      authType: AUTH_TYPE_PASSWORD,
      expiresIn: tokens.expiresIn,
      tokenType: 'jwt',
    };
  }
}
