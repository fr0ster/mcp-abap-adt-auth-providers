/**
 * SAML2 Pure Provider
 *
 * Returns SAMLResponse as authorizationToken (non-JWT).
 */

import type { AttemptContext } from '@mcp-abap-adt/auth-errors';
import type {
  IAssertionValidator,
  IRequestTarget,
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces-auth';
import { AUTH_TYPE_USER_TOKEN } from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { ownOptions } from '../auth/configuration';
import { markHandled } from '../auth/handled';
import { samlCallbackStrategy } from '../strategies';
import { createSignedResponseValidator } from '../validation/assertionValidator';
import { validateAssertion } from '../validation/samlRefusal';
import {
  BaseTokenProvider,
  refreshTokenRefused,
  storedExpiry,
  type TokenProviderHooks,
} from './BaseTokenProvider';
import type { LoginFactoryOptions } from './LoginFactoryOptions';
import type { Saml2CommonConfig, SamlTrust } from './saml2Utils';
import {
  checkAssertionValidator,
  getSamlAssertion,
  samlTrustOf,
  validateSamlConfig,
} from './saml2Utils';

export interface Saml2PureProviderConfig
  extends Saml2CommonConfig,
    TokenProviderHooks {
  logger?: ILogger | undefined;
  cookieProvider: (samlResponse: string) => Promise<string>;
  /**
   * Stored session cookies — what this provider answers as its token — to
   * present instead of logging in while they last. No refresh token: SAML has
   * none, so past `expiresAt` the provider logs in again.
   */
  accessToken?: string | undefined;
  /**
   * When `accessToken` stops being valid (epoch ms). Cookies carry no expiry
   * of their own, so without this the stored cookies count as expired and the
   * first getTokens() logs in.
   */
  expiresAt?: number | undefined;
}

export class Saml2PureProvider extends BaseTokenProvider {
  private config: Saml2PureProviderConfig;
  private readonly validator: IAssertionValidator;

  constructor(options: Saml2PureProviderConfig) {
    // Read once as own data (a hostile object throws nothing of its own).
    const config = ownOptions<Saml2PureProviderConfig>(options);
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
    this.tokenType = 'saml';
    if (config.accessToken) {
      this.authorizationToken = config.accessToken;
      this.expiresAt = storedExpiry(config.expiresAt);
    }
  }

  /** The usual choice: a browser login answered on a local callback. */
  static inBrowser(
    config: Omit<
      Saml2PureProviderConfig,
      'authorization' | 'assertionValidator'
    >,
    trust: SamlTrust,
    options: LoginFactoryOptions = {},
  ): Saml2PureProvider {
    // Read once as own data, like every option (a hostile object throws
    // nothing of its own).
    return new Saml2PureProvider({
      ...ownOptions<typeof config>(config),
      authorization: samlCallbackStrategy({
        signal: ownOptions<LoginFactoryOptions>(options).signal,
      }),
      assertionValidator: createSignedResponseValidator({
        ...samlTrustOf(trust),
      }),
    });
  }

  protected getAuthType(): OAuth2GrantType {
    return AUTH_TYPE_USER_TOKEN;
  }

  protected async performLogin(attempt: AttemptContext): Promise<ITokenResult> {
    const { payload, requestId, acsUrl } = await getSamlAssertion(
      this.config,
      attempt,
    );
    // acsUrl is where the strategy actually listened — with an ephemeral port
    // the configured value is usually absent and never authoritative.
    const validated = await validateAssertion(this.validator, payload, {
      expectedInResponseTo: requestId,
      audience: this.config.spEntityId,
      acsUrl,
      expectedIssuer: this.config.idpEntityId,
      logger: this.logger,
    });
    const sessionCookies = await this.config.cookieProvider(payload);

    return {
      authorizationToken: sessionCookies,
      authType: AUTH_TYPE_USER_TOKEN,
      tokenType: 'saml',
      // ITokenResult.expiresAt is an epoch-ms number, unlike
      // ValidatedAssertion.expiresAt, which is a Date.
      expiresAt: validated.expiresAt.getTime(),
    };
  }

  /** No refresh grant: the base logs in once instead of refreshing. */
  protected override hasRefreshGrant(): boolean {
    return false;
  }

  protected async performRefresh(): Promise<ITokenResult> {
    throw refreshTokenRefused();
  }

  /** Its "token" is the SAML session's cookies (tokenType 'saml'). */
  protected override applyToken(
    request: IRequestTarget,
    result: ITokenResult,
  ): void {
    // A target answering a rejecting promise raises nothing (rule 1).
    markHandled(request.cookies(result.authorizationToken));
  }
}
