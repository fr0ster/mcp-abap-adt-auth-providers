/**
 * SAML2 Pure Provider
 *
 * Returns SAMLResponse as authorizationToken (non-JWT).
 */

import type {
  IAssertionValidator,
  IRequestTarget,
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces-auth';
import { AUTH_TYPE_USER_TOKEN } from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { RefreshError } from '../errors/TokenProviderErrors';
import { samlCallbackStrategy } from '../strategies';
import { createSignedResponseValidator } from '../validation/assertionValidator';
import { defaultReplayStore } from '../validation/inMemoryReplayStore';
import {
  BaseTokenProvider,
  type TokenProviderHooks,
} from './BaseTokenProvider';
import type { Saml2CommonConfig, SamlTrust } from './saml2Utils';
import {
  checkAssertionValidator,
  getSamlAssertion,
  validateSamlConfig,
} from './saml2Utils';

export interface Saml2PureProviderConfig
  extends Saml2CommonConfig,
    TokenProviderHooks {
  logger?: ILogger;
  cookieProvider: (samlResponse: string) => Promise<string>;
  /**
   * Stored session cookies — what this provider answers as its token — to
   * present instead of logging in while they last. No refresh token: SAML has
   * none, so past `expiresAt` the provider logs in again.
   */
  accessToken?: string;
  /**
   * When `accessToken` stops being valid (epoch ms). Cookies carry no expiry
   * of their own, so without this the stored cookies count as expired and the
   * first getTokens() logs in.
   */
  expiresAt?: number;
}

export class Saml2PureProvider extends BaseTokenProvider {
  private config: Saml2PureProviderConfig;
  private readonly validator: IAssertionValidator;

  constructor(config: Saml2PureProviderConfig) {
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
      this.expiresAt = config.expiresAt;
    }
  }

  /** The usual choice: a browser login answered on a local callback. */
  static inBrowser(
    config: Omit<
      Saml2PureProviderConfig,
      'authorization' | 'assertionValidator'
    >,
    trust: SamlTrust,
    options: { timeoutMs?: number } = {},
  ): Saml2PureProvider {
    return new Saml2PureProvider({
      ...config,
      authorization: samlCallbackStrategy({ timeoutMs: options.timeoutMs }),
      assertionValidator: createSignedResponseValidator({
        idpCertificates: trust.idpCertificates,
        clockSkewMs: trust.clockSkewMs,
        replayStore: trust.replayStore ?? defaultReplayStore,
      }),
    });
  }

  protected getAuthType(): OAuth2GrantType {
    return AUTH_TYPE_USER_TOKEN;
  }

  protected async performLogin(): Promise<ITokenResult> {
    const { payload, requestId, acsUrl } = await getSamlAssertion(this.config);
    // acsUrl is where the strategy actually listened — with an ephemeral port
    // the configured value is usually absent and never authoritative.
    const validated = await this.validator.validate(payload, {
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
    throw new RefreshError('SAML2 pure has no refresh grant');
  }

  /** Its "token" is the SAML session's cookies (tokenType 'saml'). */
  protected override applyToken(
    request: IRequestTarget,
    result: ITokenResult,
  ): void {
    request.cookies(result.authorizationToken);
  }
}
