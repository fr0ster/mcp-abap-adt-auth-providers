/**
 * SAML2 Bearer Provider
 *
 * Exchanges SAMLResponse for OAuth2 access token.
 */

import type {
  IAssertionValidator,
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces-auth';
import { AUTH_TYPE_SAML2_BEARER } from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import {
  exchangeSamlAssertion,
  refreshSamlBearerToken,
} from '../auth/saml2TokenExchange';
import { toBearerAssertion } from '../auth/samlBearerAssertion';
import { BaseTokenProvider } from './BaseTokenProvider';
import type {
  Saml2BearerExchangeConfig,
  Saml2CommonConfig,
} from './saml2Utils';
import {
  getSamlAssertion,
  resolveAssertionValidator,
  resolveTokenUrl,
  validateSamlConfig,
} from './saml2Utils';

export interface Saml2BearerProviderConfig
  extends Saml2CommonConfig,
    Saml2BearerExchangeConfig {
  logger?: ILogger;
  accessToken?: string;
  refreshToken?: string;
}

export class Saml2BearerProvider extends BaseTokenProvider {
  private config: Saml2BearerProviderConfig;
  private readonly validator: IAssertionValidator;

  constructor(config: Saml2BearerProviderConfig) {
    super();
    // A pre-built URL with no declared ACS cannot be verified against whatever
    // the strategy binds, so it is refused here rather than at login time.
    validateSamlConfig(config);
    // Before anything reaches a browser or a network: a missing certificate is
    // the consumer's mistake, and finding it after a completed login wastes
    // theirs.
    this.validator = resolveAssertionValidator(config, 'bearer');
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
    const { payload, requestId, acsUrl } = await getSamlAssertion(this.config);
    // Validation establishes trust before anything reaches the token
    // endpoint; it does not change what is sent beyond toBearerAssertion's
    // conversion below.
    await this.validator.validate(payload, {
      expectedInResponseTo: requestId,
      audience: this.config.spEntityId,
      acsUrl,
      expectedIssuer: this.config.idpEntityId,
      logger: this.logger,
    });
    const tokenUrl = resolveTokenUrl(this.config);
    // RFC 7522 takes one base64url Assertion; a login delivers the whole
    // Response in standard base64, which a conforming endpoint refuses.
    const tokens = await exchangeSamlAssertion(
      toBearerAssertion(payload),
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

  /**
   * Spends the refresh token at the endpoint that issued it. A failure is
   * thrown rather than handled: `BaseTokenProvider.getTokens()` drops the
   * refresh token and falls back to `performLogin()`.
   */
  protected async performRefresh(): Promise<ITokenResult> {
    if (!this.refreshToken) {
      throw new Error('Refresh token is required for refresh');
    }

    const tokens = await refreshSamlBearerToken(
      this.refreshToken,
      resolveTokenUrl(this.config),
      this.config.clientId,
      this.config.clientSecret,
      this.logger,
    );

    return {
      authorizationToken: tokens.accessToken,
      refreshToken: tokens.refreshToken || this.refreshToken,
      authType: AUTH_TYPE_SAML2_BEARER,
      expiresIn: tokens.expiresIn,
      tokenType: 'jwt',
    };
  }
}
