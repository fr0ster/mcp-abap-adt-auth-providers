/**
 * UAA / XSUAA one-time passcode provider — the login `cf login --sso` uses.
 *
 * Nothing is opened and nothing listens on this machine: the user fetches a
 * code from `<uaaUrl>/passcode` in any browser, anywhere, logging in however
 * the identity zone asks (SSO through a corporate IdP, MFA), and hands it to
 * the strategy. The provider exchanges it for tokens and refreshes them
 * afterwards, so the user is asked again only when the refresh token is gone.
 */

import type {
  AuthorizationRequest,
  IAuthorizationStrategy,
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces-auth';
import { AUTH_TYPE_PASSWORD } from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { asContract } from '../auth/contractShape';
import { exchangePasscode } from '../auth/passcodeAuth';
import { refreshJwtToken } from '../auth/tokenRefresher';
import { manualPasscodeStrategy } from '../strategies/manualStrategies';
import {
  BaseTokenProvider,
  type ClientAuthenticationConfig,
  type TokenProviderHooks,
} from './BaseTokenProvider';

export interface UaaPasscodeProviderConfig
  extends TokenProviderHooks,
    ClientAuthenticationConfig {
  /** UAA / XSUAA base URL, e.g. `https://<subdomain>.authentication.<region>.hana.ondemand.com`. */
  uaaUrl: string;
  /** A client allowed the `password` grant; add `refresh_token` to keep the session. */
  clientId: string;
  /** Omitted for a public client, which authenticates with an empty secret. */
  clientSecret?: string | undefined;
  /**
   * How the user's code reaches the provider. The strategy is handed
   * `<uaaUrl>/passcode` as the URL to send the user to, and returns the code.
   * Required — see the static factories for the usual choice.
   */
  authorization: IAuthorizationStrategy<string>;
  accessToken?: string | undefined;
  refreshToken?: string | undefined;
  /**
   * When `accessToken` expires (epoch ms), for a token that carries no `exp`
   * of its own. A JWT's `exp` wins; without either the seed counts as expired.
   */
  expiresAt?: number | undefined;
  logger?: ILogger | undefined;
}

export class UaaPasscodeProvider extends BaseTokenProvider {
  private readonly config: UaaPasscodeProviderConfig;

  constructor(config: UaaPasscodeProviderConfig) {
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

  private get baseUrl(): string {
    return this.config.uaaUrl.replace(/\/+$/, '');
  }

  /** The usual choice: a passcode typed in a terminal; five minutes to paste it by default. */
  static fromTerminal(
    config: Omit<UaaPasscodeProviderConfig, 'authorization'>,
    options: { timeoutMs?: number } = {},
  ): UaaPasscodeProvider {
    return new UaaPasscodeProvider({
      ...config,
      authorization: manualPasscodeStrategy({
        timeoutMs: options.timeoutMs ?? 300_000,
      }),
    });
  }

  protected async performLogin(): Promise<ITokenResult> {
    const strategy = this.config.authorization;
    // The passcode page takes no redirect: the code travels by hand.
    const outcome = await strategy.authorize(
      asContract<AuthorizationRequest>({
        logger: this.logger,
        buildAuthorizationUrl: async () => `${this.baseUrl}/passcode`,
      }),
    );
    const passcode = outcome.payload;

    const tokens = await exchangePasscode(
      this.baseUrl,
      this.config.clientId,
      this.config.clientSecret,
      passcode,
      this.logger,
      await this.requestAuth(),
    );
    return asContract<ITokenResult>({
      authorizationToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      authType: AUTH_TYPE_PASSWORD,
      expiresIn: tokens.expiresIn,
      tokenType: 'jwt',
    });
  }

  /**
   * A failure is thrown, not handled: BaseTokenProvider drops the refresh
   * token and asks for a new passcode through performLogin().
   */
  protected async performRefresh(): Promise<ITokenResult> {
    if (!this.refreshToken) {
      throw new Error('Refresh token is required for refresh');
    }
    const result = await refreshJwtToken(
      this.refreshToken,
      this.baseUrl,
      this.config.clientId,
      this.config.clientSecret ?? '',
      await this.requestAuth(),
      this.logger,
    );
    return asContract<ITokenResult>({
      authorizationToken: result.accessToken,
      refreshToken: result.refreshToken || this.refreshToken,
      authType: AUTH_TYPE_PASSWORD,
      expiresIn: result.expiresIn,
      tokenType: 'jwt',
    });
  }
}
