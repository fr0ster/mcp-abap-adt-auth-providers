/**
 * Token refresher - refreshes JWT tokens using refresh token
 */

import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import axios, { type AxiosResponse } from 'axios';
import { tlsFailureCode } from './refusal';
import {
  legacyBasic,
  prepareTokenRequest,
  sendTokenRequest,
  type TokenRequestAuth,
  tokenEndpointError,
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
 * @param logger where the server's own words about a failure go: one debug line
 * @returns Promise that resolves to new tokens
 * @internal - Internal function, not exported from package
 */
export async function refreshJwtToken(
  refreshToken: string,
  uaaUrl: string,
  clientId: string,
  clientSecret: string | undefined,
  auth?: TokenRequestAuth,
  logger?: ILogger,
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
  // Today's request: Basic `id:secret` — an absent secret sent as it always
  // was, the word in a template — built only through legacyBasic, so its
  // secrets join every redaction of the answer.
  const basic = prepared ? undefined : legacyBasic(clientId, `${clientSecret}`);

  const sendAsToday = () =>
    axios({
      method: 'post',
      url: tokenUrl,
      headers: {
        ...(basic ? { Authorization: basic.header } : {}),
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      data: params.toString(),
      // A redirect would re-send the refresh token and the secret: never followed.
      maxRedirects: 0,
    });

  let response: AxiosResponse;
  try {
    response = await sendTokenRequest(prepared, sendAsToday, {
      logger,
      label: 'Token refresh failed',
    });
  } catch (error: unknown) {
    // Unwrapped, so the refusal can name the TLS code and its fixed hint.
    if (tlsFailureCode(error) !== undefined) throw error;
    // The safe facts as properties, never the server's description or the
    // transport's text in a refusal or a log line; the original is the cause.
    throw tokenEndpointError('Token refresh failed', error);
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
