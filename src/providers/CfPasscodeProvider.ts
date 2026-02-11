/**
 * CF Passcode (SSO) Provider
 */

import type {
  ILogger,
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces';
import { AUTH_TYPE_PASSWORD } from '@mcp-abap-adt/interfaces';
import { passwordGrant, refreshOidcToken } from '../auth/oidcToken';
import { BaseTokenProvider } from './BaseTokenProvider';

export interface CfPasscodeProviderConfig {
  uaaUrl: string;
  clientId: string;
  clientSecret?: string;
  passcode?: string;
  passcodeProvider?: () => Promise<string>;
  username?: string;
  scope?: string;
  accessToken?: string;
  refreshToken?: string;
  logger?: ILogger;
}

export class CfPasscodeProvider extends BaseTokenProvider {
  private config: CfPasscodeProviderConfig;

  constructor(config: CfPasscodeProviderConfig) {
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
    const passcode = await this.resolvePasscode();
    const tokenEndpoint = this.buildTokenEndpoint();
    const username = this.config.username || 'passcode';

    const tokens = await passwordGrant(
      tokenEndpoint,
      this.config.clientId,
      this.config.clientSecret,
      username,
      passcode,
      this.config.scope,
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

    const tokenEndpoint = this.buildTokenEndpoint();
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

  private buildTokenEndpoint(): string {
    const base = this.config.uaaUrl.replace(/\/$/, '');
    return `${base}/oauth/token`;
  }

  private async resolvePasscode(): Promise<string> {
    if (this.config.passcode) {
      return this.config.passcode;
    }
    if (this.config.passcodeProvider) {
      const code = await this.config.passcodeProvider();
      if (!code) {
        throw new Error('Passcode provider returned empty value');
      }
      return code;
    }
    throw new Error('Passcode is required for CF SSO flow');
  }
}
