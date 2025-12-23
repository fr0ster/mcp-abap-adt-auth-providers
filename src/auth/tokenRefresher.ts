/**
 * Token refresher - refreshes JWT tokens using refresh token
 */

import axios from 'axios';

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
 * @param clientSecret UAA client secret
 * @returns Promise that resolves to new tokens
 * @internal - Internal function, not exported from package
 */
export async function refreshJwtToken(
  refreshToken: string,
  uaaUrl: string,
  clientId: string,
  clientSecret: string,
): Promise<TokenRefreshResult> {
  try {
    const tokenUrl = `${uaaUrl}/oauth/token`;

    const params = new URLSearchParams();
    params.append('grant_type', 'refresh_token');
    params.append('refresh_token', refreshToken);

    const authString = Buffer.from(`${clientId}:${clientSecret}`).toString(
      'base64',
    );

    const response = await axios({
      method: 'post',
      url: tokenUrl,
      headers: {
        Authorization: `Basic ${authString}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      data: params.toString(),
    });

    if (response.data?.access_token) {
      return {
        accessToken: response.data.access_token,
        refreshToken: response.data.refresh_token || refreshToken, // Use new refresh token if provided, otherwise keep old one
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
        `Token refresh failed (${axiosError.response.status}): ${JSON.stringify(axiosError.response.data)}`,
      );
    } else {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      throw new Error(`Token refresh failed: ${errorMessage}`);
    }
  }
}
