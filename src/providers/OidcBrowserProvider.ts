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
  issuerUrl: string;
  clientId: string;
  clientSecret?: string;
  scopes?: string[];
  browser?: string;
  redirectPort?: number;
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
    const discovery = await discoverOidc(this.config.issuerUrl, this.logger);
    if (!discovery.authorization_endpoint) {
      throw new Error('OIDC discovery missing authorization_endpoint');
    }

    const redirectPort = this.config.redirectPort || 3001;
    const redirectUri = `http://localhost:${redirectPort}/callback`;
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

    const authorizationUrl = `${discovery.authorization_endpoint}?${params.toString()}`;

    const browser = this.config.browser || 'auto';
    const { code } = await startOidcBrowserAuth(
      authorizationUrl,
      browser,
      this.logger,
      redirectPort,
    );

    const tokens = await exchangeAuthorizationCode(
      discovery.token_endpoint,
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
      authType: AUTH_TYPE_AUTHORIZATION_CODE_PKCE,
      expiresIn: tokens.expiresIn,
      tokenType: 'jwt',
    };
  }
}
