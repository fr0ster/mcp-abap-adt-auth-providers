/**
 * Client Credentials Token Provider
 *
 * Uses client_credentials grant type for service-to-service authentication.
 * No browser required, no refresh token provided.
 */

import type {
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces-auth';
import { AUTH_TYPE_CLIENT_CREDENTIALS } from '@mcp-abap-adt/interfaces-auth';
import { getTokenWithClientCredentials } from '../auth/clientCredentialsAuth';
import { RefreshError } from '../errors/TokenProviderErrors';
import {
  BaseTokenProvider,
  type TokenProviderHooks,
} from './BaseTokenProvider';

export interface ClientCredentialsProviderConfig extends TokenProviderHooks {
  uaaUrl: string;
  clientId: string;
  clientSecret: string;
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
    const missingFields: string[] = [];
    if (!config.uaaUrl) {
      missingFields.push('uaaUrl');
    }
    if (!config.clientId) {
      missingFields.push('clientId');
    }
    if (!config.clientSecret) {
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

  async getTokens(): Promise<ITokenResult> {
    return super.getTokens();
  }

  protected getAuthType(): OAuth2GrantType {
    return AUTH_TYPE_CLIENT_CREDENTIALS;
  }

  protected async performLogin(): Promise<ITokenResult> {
    const result = await getTokenWithClientCredentials(
      this.config.uaaUrl,
      this.config.clientId,
      this.config.clientSecret,
    );

    return {
      authorizationToken: result.accessToken,
      refreshToken: undefined, // client_credentials doesn't provide refresh token
      authType: AUTH_TYPE_CLIENT_CREDENTIALS,
      expiresIn: result.expiresIn,
    };
  }

  /** No refresh grant: the base logs in once instead of refreshing. */
  protected override hasRefreshGrant(): boolean {
    return false;
  }

  protected async performRefresh(): Promise<ITokenResult> {
    throw new RefreshError('client_credentials has no refresh grant');
  }
}
