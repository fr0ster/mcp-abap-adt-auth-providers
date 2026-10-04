/**
 * Token refresher - refreshes JWT tokens using refresh token
 */

import axios, { type AxiosResponse } from 'axios';
import { describeOAuthErrorBody } from './oauthErrorBody';
import { loggedError, tlsFailureCode } from './refusal';
import {
  grantSecrets,
  prepareTokenRequest,
  sendTokenRequest,
  type TokenRequestAuth,
} from './tokenRequest';

export interface TokenRefreshResult {
  accessToken: string;
  refreshToken?: string;
  expiresIn?: number;
}

/**
 * Refreshes the access token using refresh token
 * @param refreshToken Refresh token
 * @param uaaUrl UAA URL (e.g., https://your-account.authentication.eu10.hana.ondemand.com)
 * @param clientId UAA client ID
 * @param clientSecret UAA client secret; unused with `auth`
 * @param auth the client authentication and its pinned material; without it,
 *   Basic `id:secret`, as always
 * @returns Promise that resolves to new tokens
 * @internal - Internal function, not exported from package
 */
export async function refreshJwtToken(
  refreshToken: string,
  uaaUrl: string,
  clientId: string,
  clientSecret: string | undefined,
  auth?: TokenRequestAuth,
): Promise<TokenRefreshResult> {
  const tokenUrl = `${uaaUrl}/oauth/token`;
  const params = new URLSearchParams();
  params.append('grant_type', 'refresh_token');
  params.append('refresh_token', refreshToken);
  // Asked before the try: what the strategy throws is not a token-endpoint failure.
  const prepared = auth
    ? await prepareTokenRequest(
        {
          endpoint: tokenUrl,
          clientId,
          grantType: 'refresh_token',
          parameters: params,
        },
        auth,
      )
    : undefined;
  const secrets = [refreshToken, clientSecret, ...(prepared?.secrets ?? [])];

  /** Today's request: Basic `id:secret`. */
  const sendAsToday = () => {
    const authString = Buffer.from(`${clientId}:${clientSecret}`).toString(
      'base64',
    );
    return axios({
      method: 'post',
      url: tokenUrl,
      headers: {
        Authorization: `Basic ${authString}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      data: params.toString(),
      // A redirect would re-send the refresh token and the secret: never followed.
      maxRedirects: 0,
    });
  };

  let response: AxiosResponse;
  try {
    response = await sendTokenRequest(prepared, sendAsToday, [
      clientSecret,
      ...grantSecrets(params),
    ]);
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
        `Token refresh failed (${axiosError.response.status}): ${describeOAuthErrorBody(axiosError.response.data, secrets)}`,
      );
    } else if (tlsFailureCode(error) !== undefined) {
      // Unwrapped, so the refusal can name the TLS code and its fixed hint.
      throw error;
    } else {
      // Fixed words only: what was thrown may hold a secret, and whoever
      // catches this logs its message. The original stays the cause.
      throw new Error(
        `Token refresh failed: ${loggedError(error, 'the token request').error}`,
        { cause: error },
      );
    }
  }
  // Outside the try: this package's own words, not a failure to wrap.
  if (response.data?.access_token) {
    return {
      accessToken: response.data.access_token,
      refreshToken: response.data.refresh_token || refreshToken, // Use new refresh token if provided, otherwise keep old one
      expiresIn: response.data.expires_in,
    };
  }
  throw new Error(
    'Token refresh failed: Response does not contain access_token',
  );
}
