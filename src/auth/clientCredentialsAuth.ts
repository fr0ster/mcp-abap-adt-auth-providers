/**
 * Client Credentials authentication for XSUAA
 *
 * For XSUAA service keys, tokens are obtained via client_credentials grant type
 * using POST request to UAA token endpoint (no browser required)
 */

import axios, { type AxiosResponse } from 'axios';
import { describeOAuthErrorBody } from './oauthErrorBody';
import { loggedError, tlsFailureCode } from './refusal';
import {
  prepareTokenRequest,
  sendTokenRequest,
  type TokenRequestAuth,
} from './tokenRequest';

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
      // A redirect would re-send the secret: never followed.
      maxRedirects: 0,
    });
  };

  let response: AxiosResponse;
  try {
    response = await sendTokenRequest(prepared, sendAsToday, [clientSecret]);
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
    } else if (tlsFailureCode(error) !== undefined) {
      // Unwrapped, so the refusal can name the TLS code and its fixed hint.
      throw error;
    } else {
      // Fixed words only: what was thrown may hold a secret, and whoever
      // catches this logs its message. The original stays the cause.
      throw new Error(
        `Client credentials authentication failed: ${loggedError(error, 'the token request').error}`,
        { cause: error },
      );
    }
  }
  // Outside the try: this package's own words, not a failure to wrap.
  if (response.data?.access_token) {
    return {
      accessToken: response.data.access_token,
      expiresIn: response.data.expires_in,
    };
  }
  throw new Error(
    'Client credentials authentication failed: Response does not contain access_token',
  );
}
