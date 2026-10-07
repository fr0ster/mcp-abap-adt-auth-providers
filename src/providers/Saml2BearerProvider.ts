/**
 * SAML2 Bearer Provider
 *
 * Exchanges SAMLResponse for OAuth2 access token.
 */

import type { AttemptContext } from '@mcp-abap-adt/auth-errors';
import type {
  IAssertionValidator,
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces-auth';
import { AUTH_TYPE_SAML2_BEARER } from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { ownOptions } from '../auth/configuration';
import {
  exchangeSamlAssertion,
  refreshSamlBearerToken,
} from '../auth/saml2TokenExchange';
import { toBearerAssertion } from '../auth/samlBearerAssertion';
import { samlCallbackStrategy } from '../strategies';
import { createSignedAssertionValidator } from '../validation/assertionValidator';
import { validateAssertion } from '../validation/samlRefusal';
import {
  BaseTokenProvider,
  type ClientAuthenticationConfig,
  refreshTokenRefused,
  type TokenProviderHooks,
} from './BaseTokenProvider';
import type { LoginFactoryOptions } from './LoginFactoryOptions';
import type {
  Saml2BearerExchangeConfig,
  Saml2CommonConfig,
  SamlTrust,
} from './saml2Utils';
import {
  checkAssertionValidator,
  getSamlAssertion,
  resolveTokenUrl,
  samlTrustOf,
  validateSamlConfig,
} from './saml2Utils';

export interface Saml2BearerProviderConfig
  extends Saml2CommonConfig,
    Saml2BearerExchangeConfig,
    TokenProviderHooks,
    ClientAuthenticationConfig {
  logger?: ILogger | undefined;
  accessToken?: string | undefined;
  refreshToken?: string | undefined;
  /**
   * When `accessToken` expires (epoch ms), for a token that carries no `exp`
   * of its own. A JWT's `exp` wins; without either the seed counts as expired.
   */
  expiresAt?: number | undefined;
}

export class Saml2BearerProvider extends BaseTokenProvider {
  private config: Saml2BearerProviderConfig;
  private readonly validator: IAssertionValidator;

  constructor(options: Saml2BearerProviderConfig) {
    // Read once as own data (a hostile object throws nothing of its own).
    const config = ownOptions<Saml2BearerProviderConfig>(options);
    super(config);
    // A pre-built URL with no declared ACS cannot be verified against whatever
    // the strategy binds, so it is refused here rather than at login time.
    validateSamlConfig(config);
    // Before anything reaches a browser or a network: a missing certificate is
    // the consumer's mistake, and finding it after a completed login wastes
    // theirs.
    this.validator = checkAssertionValidator(config);
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
    config: Omit<
      Saml2BearerProviderConfig,
      'authorization' | 'assertionValidator'
    >,
    trust: SamlTrust,
    options: LoginFactoryOptions = {},
  ): Saml2BearerProvider {
    // Read once as own data, like every option (a hostile object throws
    // nothing of its own).
    return new Saml2BearerProvider({
      ...ownOptions<typeof config>(config),
      authorization: samlCallbackStrategy({
        signal: ownOptions<LoginFactoryOptions>(options).signal,
      }),
      assertionValidator: createSignedAssertionValidator({
        ...samlTrustOf(trust),
      }),
    });
  }

  protected getAuthType(): OAuth2GrantType {
    return AUTH_TYPE_SAML2_BEARER;
  }

  protected async performLogin(attempt: AttemptContext): Promise<ITokenResult> {
    const { payload, requestId, acsUrl } = await getSamlAssertion(
      this.config,
      attempt,
    );
    // Validation establishes trust before anything reaches the token
    // endpoint; it does not change what is sent beyond toBearerAssertion's
    // conversion below.
    await validateAssertion(this.validator, payload, {
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
      await this.requestAuth(),
      this.siteOptions(attempt.signal),
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
  protected async performRefresh(
    refreshToken: string,
    _signal: AbortSignal,
    dispatched: () => void,
  ): Promise<ITokenResult> {
    if (!refreshToken) {
      throw refreshTokenRefused();
    }

    const tokens = await refreshSamlBearerToken(
      refreshToken,
      resolveTokenUrl(this.config),
      this.config.clientId,
      this.config.clientSecret,
      this.logger,
      await this.requestAuth(),
      this.refreshSiteOptions(dispatched),
    );

    return {
      authorizationToken: tokens.accessToken,
      refreshToken: tokens.refreshToken || refreshToken,
      authType: AUTH_TYPE_SAML2_BEARER,
      expiresIn: tokens.expiresIn,
      tokenType: 'jwt',
    };
  }
}
