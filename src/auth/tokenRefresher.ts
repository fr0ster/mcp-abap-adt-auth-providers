/**
 * Token refresher - refreshes JWT tokens using refresh token
 */

import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import axios from 'axios';
import {
  legacyBasic,
  prepareTokenRequest,
  rejectMissingToken,
  sendTokenRequest,
  siteSecrets,
  type TokenRequestAuth,
  type TokenSiteOptions,
  tokenSite,
} from './tokenRequest';

export interface TokenRefreshResult {
  accessToken: string;
  refreshToken?: string | undefined;
  expiresIn?: number | undefined;
}

/**
 * Refreshes the access token using refresh token
 * @param refreshToken Refresh token
 * @param uaaUrl UAA URL (e.g., https://your-account.authentication.eu10.hana.ondemand.com)
 * @param clientId UAA client ID
 * @param clientSecret UAA client secret; unused with `auth`
 * @param auth the client authentication and its pinned material; without it,
 *   Basic `id:secret`, as always
 * @param logger where a failure's safe facts go: one debug line
 * @param options the provider's `authDebug` and grant (`TokenSiteOptions`)
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
  options?: TokenSiteOptions,
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
  // secrets are named in the `authDebug` line's `sent`.
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

  const site = tokenSite(
    'token-refresh',
    options,
    logger,
    siteSecrets(params, clientSecret),
    basic,
  );
  const response = await sendTokenRequest<{
    access_token?: string;
    refresh_token?: string;
    expires_in?: number;
  }>(prepared, sendAsToday, site);
  const data = response.data;
  if (!data.access_token) {
    rejectMissingToken(site, prepared, response, 'no-access-token', 'debug');
  }
  return {
    accessToken: data.access_token,
    // A new refresh token when the server sent one, else the one spent.
    refreshToken: data.refresh_token || refreshToken,
    expiresIn: data.expires_in,
  };
}
