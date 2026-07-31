/**
 * OIDC Authorization Code Provider (with PKCE)
 */

import type {
  IAuthorizationStrategy,
  ILogger,
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces';
import { AUTH_TYPE_AUTHORIZATION_CODE_PKCE } from '@mcp-abap-adt/interfaces';
import type { OidcCallbackResult } from '../auth/oidcBrowserAuth';
import { discoverOidc } from '../auth/oidcDiscovery';
import { generatePkceChallenge, generatePkceVerifier } from '../auth/oidcPkce';
import { exchangeAuthorizationCode, refreshOidcToken } from '../auth/oidcToken';
import { oidcCallbackStrategy } from '../strategies';
import { BaseTokenProvider } from './BaseTokenProvider';

export interface OidcBrowserProviderConfig {
  issuerUrl?: string;
  clientId: string;
  clientSecret?: string;
  scopes?: string[];
  authorizationEndpoint?: string;
  tokenEndpoint?: string;
  /** How the login is conducted. Omitted means a browser callback on the default port. */
  authorization?: IAuthorizationStrategy<OidcCallbackResult>;
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
    // One memoised discovery per login, started on first use rather than up
    // front: a strategy that already holds a code must not drag in a request —
    // nor the `issuerUrl` requirement that comes with it.
    let discovery: Promise<Awaited<ReturnType<typeof discoverOidc>>> | null =
      null;
    const discover = () => {
      if (!discovery) {
        if (!this.config.issuerUrl) {
          throw new Error('OIDC issuerUrl is required when discovery is used');
        }
        discovery = discoverOidc(this.config.issuerUrl, this.logger);
      }
      return discovery;
    };

    const verifier = generatePkceVerifier();
    const challenge = generatePkceChallenge(verifier);
    const scope = (
      this.config.scopes && this.config.scopes.length > 0
        ? this.config.scopes
        : ['openid', 'profile', 'email']
    ).join(' ');

    const request = {
      logger: this.logger,
      buildAuthorizationUrl: async (redirectUri: string): Promise<string> => {
        const endpoint =
          this.config.authorizationEndpoint ??
          (await discover()).authorization_endpoint;
        if (!endpoint) {
          throw new Error(
            'OIDC authorization endpoint is required (authorizationEndpoint or discovery)',
          );
        }
        const params = new URLSearchParams();
        params.append('response_type', 'code');
        params.append('client_id', this.config.clientId);
        params.append('redirect_uri', redirectUri);
        params.append('scope', scope);
        params.append('code_challenge', challenge);
        params.append('code_challenge_method', 'S256');
        return `${endpoint}?${params.toString()}`;
      },
    };

    const supplied = this.config.authorization;
    const strategy = supplied ?? oidcCallbackStrategy();

    let outcome: { payload: OidcCallbackResult; redirectUri: string };
    try {
      outcome = await strategy.authorize(request);
    } finally {
      if (!supplied) {
        await strategy.dispose?.().catch((error: unknown) => {
          this.logger?.warn('[OidcBrowserProvider] dispose failed', {
            error: error instanceof Error ? error.message : String(error),
          });
        });
      }
    }

    const tokenEndpoint =
      this.config.tokenEndpoint ?? (await discover()).token_endpoint;
    if (!tokenEndpoint) {
      throw new Error(
        'OIDC token endpoint is required (tokenEndpoint or discovery)',
      );
    }

    const tokens = await exchangeAuthorizationCode(
      tokenEndpoint,
      this.config.clientId,
      this.config.clientSecret,
      outcome.payload.code,
      outcome.redirectUri,
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
    // `??`, matching the `=== undefined` gate above and the login path: `||`
    // treated a configured-but-empty endpoint as absent while the gate had
    // already decided it was present, so the two disagreed about the same value.
    const tokenEndpoint =
      this.config.tokenEndpoint ?? discovery?.token_endpoint;
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
}
