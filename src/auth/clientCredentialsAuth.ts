/**
 * Client Credentials authentication for XSUAA
 *
 * For XSUAA service keys, tokens are obtained via client_credentials grant type
 * using POST request to UAA token endpoint (no browser required)
 */

import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import axios from 'axios';
import {
  attemptSite,
  prepareTokenRequest,
  rejectMissingToken,
  sendTokenRequest,
  siteSecrets,
  type TokenRequestAuth,
  type TokenSiteOptions,
} from './tokenRequest';

export interface ClientCredentialsResult {
  accessToken: string;
  expiresIn?: number | undefined;
}

/**
 * Get access token using client_credentials grant type
 * @param uaaUrl UAA URL (e.g., https://your-account.authentication.eu10.hana.ondemand.com)
 * @param clientId UAA client ID
 * @param clientSecret UAA client secret; unused with `auth`
 * @param auth the client authentication and its pinned material; without it,
 *   `client_id` and `client_secret` go in the body, as always
 * @param logger where a failure's safe facts go: one debug line
 * @param options the provider's `authDebug` and grant (`TokenSiteOptions`)
 * @returns Promise that resolves to access token
 * @internal - Internal function, not exported from package
 */
export async function getTokenWithClientCredentials(
  uaaUrl: string,
  clientId: string,
  clientSecret: string | undefined,
  auth?: TokenRequestAuth,
  logger?: ILogger,
  options?: TokenSiteOptions,
): Promise<ClientCredentialsResult> {
  const tokenUrl = `${uaaUrl}/oauth/token`;
  // Asked before the try: what the strategy throws is not a token-endpoint failure.
  const prepared = auth
    ? await prepareTokenRequest(
        {
          endpoint: tokenUrl,
          clientId,
          grantType: 'client_credentials',
          parameters: new URLSearchParams({ grant_type: 'client_credentials' }),
        },
        auth,
      )
    : undefined;
  /** Today's request: the secret in the body. */
  const sendAsToday = (signal: AbortSignal | undefined) => {
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
      // No timeout of this package's choosing: the consumer bounds a wait.
      // A redirect would re-send the secret: never followed.
      maxRedirects: 0,
      // The attempt's abort cuts the request (spec §6b).
      ...(signal === undefined ? {} : { signal }),
    });
  };

  // A failure — a TLS code, a refusal, no answer — is `client-credentials`'s,
  // with the safe facts only.
  const site = attemptSite(
    'client-credentials',
    options,
    logger,
    siteSecrets(new URLSearchParams(), clientSecret),
  );
  const response = await sendTokenRequest<{
    access_token?: string;
    expires_in?: number;
  }>(prepared, sendAsToday, site);
  const { access_token: accessToken, expires_in: expiresIn } = response.data;
  if (!accessToken) {
    rejectMissingToken(site, prepared, response, 'no-access-token', 'debug');
  }
  return { accessToken, expiresIn };
}
