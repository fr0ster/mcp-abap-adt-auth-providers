/**
 * OIDC Authorization Code Provider (with PKCE)
 */

import type { AttemptContext } from '@mcp-abap-adt/auth-errors';
import type {
  IAuthorizationStrategy,
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces-auth';
import { AUTH_TYPE_AUTHORIZATION_CODE_PKCE } from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { throwIfAborted } from '../auth/attempt';
import { asContract } from '../auth/contractShape';
import type { OidcCallbackResult } from '../auth/oidcBrowserAuth';
import { discoverOidc, mtlsAlias } from '../auth/oidcDiscovery';
import { generatePkceChallenge, generatePkceVerifier } from '../auth/oidcPkce';
import { exchangeAuthorizationCode, refreshOidcToken } from '../auth/oidcToken';
import type { SignalledAuthorizationRequest } from '../auth/signalledRequest';
import { ValidationError } from '../errors/TokenProviderErrors';
import { oidcCallbackStrategy } from '../strategies';
import {
  BaseTokenProvider,
  type ClientAuthenticationConfig,
  refreshTokenRefused,
  type TokenProviderHooks,
} from './BaseTokenProvider';

export interface OidcBrowserProviderConfig
  extends TokenProviderHooks,
    ClientAuthenticationConfig {
  issuerUrl?: string | undefined;
  clientId: string;
  clientSecret?: string | undefined;
  scopes?: string[] | undefined;
  authorizationEndpoint?: string | undefined;
  tokenEndpoint?: string | undefined;
  /**
   * How the login is conducted. Required — see the static factories for the
   * usual choice.
   */
  authorization: IAuthorizationStrategy<OidcCallbackResult>;
  accessToken?: string | undefined;
  refreshToken?: string | undefined;
  /**
   * When `accessToken` expires (epoch ms), for a token that carries no `exp`
   * of its own. A JWT's `exp` wins; without either the seed counts as expired.
   */
  expiresAt?: number | undefined;
  logger?: ILogger | undefined;
}

export class OidcBrowserProvider extends BaseTokenProvider {
  private config: OidcBrowserProviderConfig;

  constructor(config: OidcBrowserProviderConfig) {
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

  /** The usual choice: a browser login answered on a local callback. */
  static inBrowser(
    config: Omit<OidcBrowserProviderConfig, 'authorization'>,
    options: { timeoutMs?: number } = {},
  ): OidcBrowserProvider {
    return new OidcBrowserProvider({
      ...config,
      authorization: oidcCallbackStrategy({ timeoutMs: options.timeoutMs }),
    });
  }

  protected getAuthType(): OAuth2GrantType {
    return AUTH_TYPE_AUTHORIZATION_CODE_PKCE;
  }

  protected async performLogin(attempt: AttemptContext): Promise<ITokenResult> {
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
        discovery = discoverOidc(
          this.config.issuerUrl,
          this.logger,
          attempt.signal,
        );
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
      // The attempt's signal: every waiter gone ends the login (spec §6b).
      signal: attempt.signal,
      buildAuthorizationUrl: async (redirectUri: string): Promise<string> => {
        const endpoint =
          this.config.authorizationEndpoint ||
          (await discover()).authorization_endpoint;
        if (!endpoint) {
          throw new ValidationError(
            'OIDC authorization endpoint is required (authorizationEndpoint or discovery)',
            ['authorizationEndpoint'],
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

    const strategy = this.config.authorization;

    // The strategy holds a socket or a reader: it starts only once the
    // previous attempt has released its own (the drain, spec §6b).
    const outcome = await attempt.exclusive(() =>
      strategy.authorize(asContract<SignalledAuthorizationRequest>(request)),
    );

    const discovered = this.config.tokenEndpoint ? null : await discover();
    const tokenEndpoint =
      this.config.tokenEndpoint || discovered?.token_endpoint;
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
      // The alias belongs to the discovered endpoint only.
      await this.requestAuth(mtlsAlias(discovered, 'token_endpoint')),
      this.siteOptions(attempt.signal),
    );

    return asContract<ITokenResult>({
      authorizationToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      authType: AUTH_TYPE_AUTHORIZATION_CODE_PKCE,
      expiresIn: tokens.expiresIn,
      tokenType: 'jwt',
    });
  }

  protected async performRefresh(
    refreshToken: string,
    signal?: AbortSignal,
  ): Promise<ITokenResult> {
    if (!refreshToken) {
      throw refreshTokenRefused();
    }

    let discovery: Awaited<ReturnType<typeof discoverOidc>> | null = null;
    if (!this.config.tokenEndpoint) {
      if (!this.config.issuerUrl) {
        throw new Error('OIDC issuerUrl is required when discovery is used');
      }
      discovery = await discoverOidc(
        this.config.issuerUrl,
        this.logger,
        signal,
      );
    }
    // An endpoint not given ('' included) is discovered — the same rule as the
    // login path above and as every OIDC provider, at login and at refresh, so
    // no two paths disagree about the same value.
    const tokenEndpoint =
      this.config.tokenEndpoint || discovery?.token_endpoint;
    if (!tokenEndpoint) {
      throw new Error(
        'OIDC token endpoint is required (tokenEndpoint or discovery)',
      );
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
      this.siteOptions(),
    );

    return asContract<ITokenResult>({
      authorizationToken: tokens.accessToken,
      refreshToken: tokens.refreshToken || refreshToken,
      authType: AUTH_TYPE_AUTHORIZATION_CODE_PKCE,
      expiresIn: tokens.expiresIn,
      tokenType: 'jwt',
    });
  }
}
