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
  IAuthorizationStrategy,
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces-auth';
import { AUTH_TYPE_PASSWORD } from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { exchangePasscode } from '../auth/passcodeAuth';
import { refreshJwtToken } from '../auth/tokenRefresher';
import { manualPasscodeStrategy } from '../strategies/manualStrategies';
import { BaseTokenProvider } from './BaseTokenProvider';

export interface UaaPasscodeProviderConfig {
  /** UAA / XSUAA base URL, e.g. `https://<subdomain>.authentication.<region>.hana.ondemand.com`. */
  uaaUrl: string;
  /** A client allowed the `password` grant; add `refresh_token` to keep the session. */
  clientId: string;
  /** Omitted for a public client, which authenticates with an empty secret. */
  clientSecret?: string;
  /**
   * How the user's code reaches the provider. The strategy is handed
   * `<uaaUrl>/passcode` as the URL to send the user to, and returns the code.
   * Defaults to `manualPasscodeStrategy()`: announce the URL, read the code
   * from the terminal.
   */
  authorization?: IAuthorizationStrategy<string>;
  accessToken?: string;
  refreshToken?: string;
  logger?: ILogger;
}

export class UaaPasscodeProvider extends BaseTokenProvider {
  private readonly config: UaaPasscodeProviderConfig;

  constructor(config: UaaPasscodeProviderConfig) {
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

  private get baseUrl(): string {
    return this.config.uaaUrl.replace(/\/+$/, '');
  }

  protected async performLogin(): Promise<ITokenResult> {
    const supplied = this.config.authorization;
    const strategy = supplied ?? manualPasscodeStrategy();
    let passcode: string;
    try {
      // The passcode page takes no redirect: the code travels by hand.
      const outcome = await strategy.authorize({
        logger: this.logger,
        buildAuthorizationUrl: async () => `${this.baseUrl}/passcode`,
      });
      passcode = outcome.payload;
    } finally {
      if (!supplied) {
        await strategy.dispose?.().catch((error: unknown) => {
          this.logger?.warn('[UaaPasscodeProvider] dispose failed', {
            error: error instanceof Error ? error.message : String(error),
          });
        });
      }
    }

    const tokens = await exchangePasscode(
      this.baseUrl,
      this.config.clientId,
      this.config.clientSecret,
      passcode,
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
    );
    return {
      authorizationToken: result.accessToken,
      refreshToken: result.refreshToken || this.refreshToken,
      authType: AUTH_TYPE_PASSWORD,
      expiresIn: result.expiresIn,
      tokenType: 'jwt',
    };
  }
}
