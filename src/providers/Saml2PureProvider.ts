/**
 * SAML2 Pure Provider
 *
 * Returns SAMLResponse as authorizationToken (non-JWT).
 */

import type {
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces-auth';
import { AUTH_TYPE_USER_TOKEN } from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { BaseTokenProvider } from './BaseTokenProvider';
import type { Saml2CommonConfig } from './saml2Utils';
import { getSamlAssertion, validateSamlConfig } from './saml2Utils';

export interface Saml2PureProviderConfig extends Saml2CommonConfig {
  logger?: ILogger;
  cookieProvider: (samlResponse: string) => Promise<string>;
}

export class Saml2PureProvider extends BaseTokenProvider {
  private config: Saml2PureProviderConfig;

  constructor(config: Saml2PureProviderConfig) {
    super();
    // A pre-built URL with no declared ACS cannot be verified against whatever
    // the strategy binds, so it is refused here rather than at login time.
    validateSamlConfig(config);
    this.config = config;
    this.logger = config.logger;
    this.tokenType = 'saml';
  }

  protected getAuthType(): OAuth2GrantType {
    return AUTH_TYPE_USER_TOKEN;
  }

  protected async performLogin(): Promise<ITokenResult> {
    // Task 10 threads the payload through; the assertion is not yet
    // validated and `expiresAt` is not yet derived from it — Task 11 wires
    // both through the assertion validator.
    const { payload } = await getSamlAssertion(this.config);
    const sessionCookies = await this.config.cookieProvider(payload);

    return {
      authorizationToken: sessionCookies,
      authType: AUTH_TYPE_USER_TOKEN,
      tokenType: 'saml',
    };
  }

  protected async performRefresh(): Promise<ITokenResult> {
    return this.performLogin();
  }
}
