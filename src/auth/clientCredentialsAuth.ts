/**
 * Client Credentials authentication for XSUAA
 *
 * For XSUAA service keys, tokens are obtained via client_credentials grant type
 * using POST request to UAA token endpoint (no browser required)
 */

import axios from 'axios';
import { describeOAuthErrorBody } from './oauthErrorBody';
import { tlsTrustCode } from './refusal';
import { prepareTokenRequest, type TokenRequestAuth } from './tokenRequest';

export interface ClientCredentialsResult {
  accessToken: string;
  expiresIn?: number;
}

/**
 * Get access token using client_credentials grant type
 * @param uaaUrl UAA URL (e.g., https://your-account.authentication.eu10.hana.ondemand.com)
 * @param clientId UAA client ID
 * @param clientSecret UAA client secret; unused with `auth`
 * @param auth the client authentication and its pinned material; without it,
 *   `client_id` and `client_secret` go in the body, as always
 * @returns Promise that resolves to access token
 * @internal - Internal function, not exported from package
 */
export async function getTokenWithClientCredentials(
  uaaUrl: string,
  clientId: string,
  clientSecret: string | undefined,
  auth?: TokenRequestAuth,
): Promise<ClientCredentialsResult> {
  const tokenUrl = `${uaaUrl}/oauth/token`;
  const timeout = 30000; // 30 seconds timeout to prevent hanging
  // Asked before the try: what the strategy throws is not a token-endpoint failure.
  const prepared = auth
    ? await prepareTokenRequest(
        {
          endpoint: tokenUrl,
          clientId,
          grantType: 'client_credentials',
          parameters: new URLSearchParams({ grant_type: 'client_credentials' }),
          timeout,
        },
        auth,
      )
    : undefined;
  const secrets = [clientSecret, ...(prepared?.secrets ?? [])];

  /** Today's request: the secret in the body. */
  const sendAsToday = () => {
    const params = new URLSearchParams();
    params.append('grant_type', 'client_credentials');
    params.append('client_id', clientId);
    params.append('client_secret', clientSecret as string);
    return axios({
      method: 'post',
      url: tokenUrl,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      data: params.toString(),
      timeout,
    });
  };

  try {
    const response = prepared
      ? await axios(prepared.config)
      : await sendAsToday();

    if (response.data?.access_token) {
      return {
        accessToken: response.data.access_token,
        expiresIn: response.data.expires_in,
      };
    } else {
      throw new Error('Response does not contain access_token');
    }
  } catch (error: unknown) {
    if (
      error &&
      typeof error === 'object' &&
      'response' in error &&
      error.response &&
      typeof error.response === 'object' &&
      'status' in error.response &&
      'data' in error.response
    ) {
      const axiosError = error as {
        response: { status: number; data: unknown };
      };
      throw new Error(
        `Client credentials authentication failed (${axiosError.response.status}): ${describeOAuthErrorBody(axiosError.response.data, secrets)}`,
      );
    } else if (tlsTrustCode(error) !== undefined) {
      // Unwrapped, so the refusal can name the code and NODE_EXTRA_CA_CERTS.
      throw error;
    } else {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      throw new Error(
        `Client credentials authentication failed: ${errorMessage}`,
      );
    }
  }
}
