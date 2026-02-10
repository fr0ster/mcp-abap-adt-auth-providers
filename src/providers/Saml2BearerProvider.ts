/**
 * SAML2 Bearer Provider
 *
 * Exchanges SAMLResponse for OAuth2 access token.
 */

import type {
  ILogger,
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces';
import { AUTH_TYPE_SAML2_BEARER } from '@mcp-abap-adt/interfaces';
import { exchangeSamlAssertion } from '../auth/saml2TokenExchange';
import { BaseTokenProvider } from './BaseTokenProvider';
import type {
  Saml2AssertionConfig,
  Saml2BearerExchangeConfig,
} from './saml2Utils';
import { getSamlAssertion, resolveTokenUrl } from './saml2Utils';

export interface Saml2BearerProviderConfig
  extends Saml2AssertionConfig,
    Saml2BearerExchangeConfig {
  logger?: ILogger;
  accessToken?: string;
  refreshToken?: string;
}

export class Saml2BearerProvider extends BaseTokenProvider {
  private config: Saml2BearerProviderConfig;

  constructor(config: Saml2BearerProviderConfig) {
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
    return AUTH_TYPE_SAML2_BEARER;
  }

  protected async performLogin(): Promise<ITokenResult> {
    const samlResponse = await getSamlAssertion(this.config);
    const tokenUrl = resolveTokenUrl(this.config);
    const tokens = await exchangeSamlAssertion(
      samlResponse,
      tokenUrl,
      this.config.clientId,
      this.config.clientSecret,
      this.logger,
    );

    return {
      authorizationToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      authType: AUTH_TYPE_SAML2_BEARER,
      expiresIn: tokens.expiresIn,
      tokenType: 'jwt',
    };
  }

  protected async performRefresh(): Promise<ITokenResult> {
    if (!this.refreshToken) {
      return this.performLogin();
    }
    return this.performLogin();
  }
}
