/**
 * SAML2 Pure Provider
 *
 * Returns SAMLResponse as authorizationToken (non-JWT).
 */

import type {
  IAssertionValidator,
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces-auth';
import { AUTH_TYPE_USER_TOKEN } from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { BaseTokenProvider } from './BaseTokenProvider';
import type { Saml2CommonConfig } from './saml2Utils';
import {
  getSamlAssertion,
  resolveAssertionValidator,
  validateSamlConfig,
} from './saml2Utils';

export interface Saml2PureProviderConfig extends Saml2CommonConfig {
  logger?: ILogger;
  cookieProvider: (samlResponse: string) => Promise<string>;
}

export class Saml2PureProvider extends BaseTokenProvider {
  private config: Saml2PureProviderConfig;
  private readonly validator: IAssertionValidator;

  constructor(config: Saml2PureProviderConfig) {
    super();
    // A pre-built URL with no declared ACS cannot be verified against whatever
    // the strategy binds, so it is refused here rather than at login time.
    validateSamlConfig(config);
    // Before anything reaches a browser or a network: a missing certificate is
    // the consumer's mistake, and finding it after a completed login wastes
    // theirs.
    this.validator = resolveAssertionValidator(config, 'pure');
    this.config = config;
    this.logger = config.logger;
    this.tokenType = 'saml';
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

  protected async performRefresh(): Promise<ITokenResult> {
    return this.performLogin();
  }
}
