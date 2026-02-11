/**
 * OIDC Authorization Code Provider (with PKCE)
 */

import type {
  ILogger,
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces';
import { AUTH_TYPE_AUTHORIZATION_CODE_PKCE } from '@mcp-abap-adt/interfaces';
import { startOidcBrowserAuth } from '../auth/oidcBrowserAuth';
import { discoverOidc } from '../auth/oidcDiscovery';
import { generatePkceChallenge, generatePkceVerifier } from '../auth/oidcPkce';
import { exchangeAuthorizationCode, refreshOidcToken } from '../auth/oidcToken';
import { BaseTokenProvider } from './BaseTokenProvider';

export interface OidcBrowserProviderConfig {
  issuerUrl?: string;
  clientId: string;
  clientSecret?: string;
  scopes?: string[];
  browser?: string;
  redirectPort?: number;
  redirectUri?: string;
  authorizationCode?: string;
  authorizationCodeProvider?: () => Promise<string>;
  authorizationEndpoint?: string;
  tokenEndpoint?: string;
  accessToken?: string;
  refreshToken?: string;
  logger?: ILogger;
}

export class OidcBrowserProvider extends BaseTokenProvider {
  private config: OidcBrowserProviderConfig;

  constructor(config: OidcBrowserProviderConfig) {
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
    return AUTH_TYPE_AUTHORIZATION_CODE_PKCE;
  }

  protected async performLogin(): Promise<ITokenResult> {
    const needsAuthorizationEndpoint =
      !this.config.authorizationCode && !this.config.authorizationCodeProvider;

    const requiresDiscovery =
      (needsAuthorizationEndpoint && !this.config.authorizationEndpoint) ||
      !this.config.tokenEndpoint;
    let discovery: Awaited<ReturnType<typeof discoverOidc>> | null = null;
    if (requiresDiscovery) {
      if (!this.config.issuerUrl) {
        throw new Error('OIDC issuerUrl is required when discovery is used');
      }
      discovery = await discoverOidc(this.config.issuerUrl, this.logger);
    }
    const authorizationEndpoint = needsAuthorizationEndpoint
      ? this.config.authorizationEndpoint || discovery?.authorization_endpoint
      : undefined;
    const tokenEndpoint =
      this.config.tokenEndpoint || discovery?.token_endpoint;

    if (needsAuthorizationEndpoint && !authorizationEndpoint) {
      throw new Error(
        'OIDC authorization endpoint is required (authorizationEndpoint or discovery)',
      );
    }
    if (!tokenEndpoint) {
      throw new Error(
        'OIDC token endpoint is required (tokenEndpoint or discovery)',
      );
    }

    const redirectPort = this.config.redirectPort || 3001;
    const redirectUri =
      this.config.redirectUri || `http://localhost:${redirectPort}/callback`;
    if (needsAuthorizationEndpoint && this.config.redirectUri) {
      if (!redirectUri.startsWith('http://localhost:')) {
        throw new Error(
          'OIDC redirectUri must be localhost for browser callback flow',
        );
      }
    }
    const scope = (
      this.config.scopes && this.config.scopes.length > 0
        ? this.config.scopes
        : ['openid', 'profile', 'email']
    ).join(' ');

    const verifier = generatePkceVerifier();
    const challenge = generatePkceChallenge(verifier);

    const params = new URLSearchParams();
    params.append('response_type', 'code');
    params.append('client_id', this.config.clientId);
    params.append('redirect_uri', redirectUri);
    params.append('scope', scope);
    params.append('code_challenge', challenge);
    params.append('code_challenge_method', 'S256');

    const authorizationUrl = needsAuthorizationEndpoint
      ? `${authorizationEndpoint}?${params.toString()}`
      : undefined;

    const code = await this.resolveAuthorizationCode(
      authorizationUrl,
      redirectPort,
    );

    const tokens = await exchangeAuthorizationCode(
      tokenEndpoint,
      this.config.clientId,
      this.config.clientSecret,
      code,
      redirectUri,
      verifier,
      this.logger,
    );

    return {
      authorizationToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      authType: AUTH_TYPE_AUTHORIZATION_CODE_PKCE,
      expiresIn: tokens.expiresIn,
      tokenType: 'jwt',
    };
  }

  protected async performRefresh(): Promise<ITokenResult> {
    if (!this.refreshToken) {
      return this.performLogin();
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
      authType: AUTH_TYPE_AUTHORIZATION_CODE_PKCE,
      expiresIn: tokens.expiresIn,
      tokenType: 'jwt',
    };
  }

  private async resolveAuthorizationCode(
    authorizationUrl: string | undefined,
    redirectPort: number,
  ): Promise<string> {
    if (this.config.authorizationCode) {
      return this.config.authorizationCode;
    }
    if (this.config.authorizationCodeProvider) {
      const code = await this.config.authorizationCodeProvider();
      if (!code) {
        throw new Error('Authorization code provider returned empty value');
      }
      return code;
    }

    if (!authorizationUrl) {
      throw new Error(
        'OIDC authorization URL is required when using browser flow',
      );
    }

    const browser = this.config.browser || 'auto';
    const { code } = await startOidcBrowserAuth(
      authorizationUrl,
      browser,
      this.logger,
      redirectPort,
    );
    return code;
  }
}
