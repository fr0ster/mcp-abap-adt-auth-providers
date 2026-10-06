/**
 * Client Credentials Token Provider
 *
 * Uses client_credentials grant type for service-to-service authentication.
 * No browser required, no refresh token provided.
 */

import type { AttemptContext } from '@mcp-abap-adt/auth-errors';
import type {
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces-auth';
import { AUTH_TYPE_CLIENT_CREDENTIALS } from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { getTokenWithClientCredentials } from '../auth/clientCredentialsAuth';
import { asContract } from '../auth/contractShape';
import {
  BaseTokenProvider,
  type ClientAuthenticationConfig,
  refreshTokenRefused,
  type TokenProviderHooks,
} from './BaseTokenProvider';

export interface ClientCredentialsProviderConfig
  extends TokenProviderHooks,
    ClientAuthenticationConfig {
  uaaUrl: string;
  clientId: string;
  /** Required, unless `clientAuthentication` is given — never both. */
  clientSecret?: string | undefined;
  logger?: ILogger | undefined;
}

/**
 * Client Credentials token provider
 *
 * Uses client_credentials grant type - no browser, no refresh token.
 * Tokens are cached and automatically refreshed when expired.
 */
export class ClientCredentialsProvider extends BaseTokenProvider {
  private config: ClientCredentialsProviderConfig;

  constructor(config: ClientCredentialsProviderConfig) {
    super(config);
    this.config = config;
    this.logger = config.logger;
    const missingFields: string[] = [];
    if (!config.uaaUrl) {
      missingFields.push('uaaUrl');
    }
    if (!config.clientId) {
      missingFields.push('clientId');
    }
    // A strategy authenticates the client instead (never both: the base).
    if (!config.clientSecret && !config.clientAuthentication) {
      missingFields.push('clientSecret');
    }
    if (missingFields.length > 0) {
      const error = new Error(
        `Missing required fields: ${missingFields.join(', ')}`,
      ) as Error & { code: string; missingFields: string[] };
      error.code = 'VALIDATION_ERROR';
      error.missingFields = missingFields;
      throw error;
    }
  }

  protected getAuthType(): OAuth2GrantType {
    return AUTH_TYPE_CLIENT_CREDENTIALS;
  }

  protected async performLogin(attempt: AttemptContext): Promise<ITokenResult> {
    const result = await getTokenWithClientCredentials(
      this.config.uaaUrl,
      this.config.clientId,
      this.config.clientSecret,
      await this.requestAuth(),
      this.logger,
      this.siteOptions(attempt.signal),
    );

    return asContract<ITokenResult>({
      authorizationToken: result.accessToken,
      refreshToken: undefined, // client_credentials doesn't provide refresh token
      authType: AUTH_TYPE_CLIENT_CREDENTIALS,
      expiresIn: result.expiresIn,
    });
  }

  /** No refresh grant: the base logs in once instead of refreshing. */
  protected override hasRefreshGrant(): boolean {
    return false;
  }

  protected async performRefresh(): Promise<ITokenResult> {
    throw refreshTokenRefused();
  }
}
