/**
 * SAML 2.0 bearer assertion exchange
 */

import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import axios, { type AxiosResponse } from 'axios';
import { ValidationError } from '../errors/TokenProviderErrors';
import { describeOAuthErrorBody } from './oauthErrorBody';
import {
  type PreparedTokenRequest,
  prepareTokenRequest,
  sendTokenRequest,
  type TokenRequestAuth,
} from './tokenRequest';

export interface Saml2TokenExchangeResponse {
  accessToken: string;
  refreshToken?: string;
  expiresIn?: number;
  tokenType?: string;
}

function toBasicAuth(clientId: string, clientSecret: string): string {
  return Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
}

/** With a strategy: the grant parameters alone, authenticated by it. */
async function prepareWith(
  auth: TokenRequestAuth,
  tokenUrl: string,
  clientId: string | undefined,
  grantType: string,
  grant: URLSearchParams,
): Promise<PreparedTokenRequest> {
  if (!clientId) {
    throw new ValidationError(
      'clientId is required with a client authentication',
      ['clientId'],
    );
  }
  return prepareTokenRequest(
    { endpoint: tokenUrl, clientId, grantType, parameters: grant },
    auth,
  );
}

/** Today's request: `client_id` in the body when known, Basic when a secret is. */
function sendAsToday(
  tokenUrl: string,
  grant: URLSearchParams,
  clientId: string | undefined,
  clientSecret: string | undefined,
): Promise<AxiosResponse> {
  const params = new URLSearchParams(grant);
  if (clientId) {
    params.append('client_id', clientId);
  }
  const headers: Record<string, string> = {
    'Content-Type': 'application/x-www-form-urlencoded',
  };
  if (clientId && clientSecret) {
    headers.Authorization = `Basic ${toBasicAuth(clientId, clientSecret)}`;
  }
  return axios.post(tokenUrl, params.toString(), { headers });
}

export async function exchangeSamlAssertion(
  samlResponse: string,
  tokenUrl: string,
  clientId: string | undefined,
  clientSecret: string | undefined,
  logger?: ILogger,
  auth?: TokenRequestAuth,
): Promise<Saml2TokenExchangeResponse> {
  const grantType = 'urn:ietf:params:oauth:grant-type:saml2-bearer';
  const grant = new URLSearchParams();
  grant.append('grant_type', grantType);
  grant.append('assertion', samlResponse);
  const prepared = auth
    ? await prepareWith(auth, tokenUrl, clientId, grantType, grant)
    : undefined;

  logger?.info('[SAML] Exchanging assertion for token', {
    tokenUrl: prepared?.config.url ?? tokenUrl,
  });

  let response: AxiosResponse;
  try {
    response = await sendTokenRequest(prepared, () =>
      sendAsToday(tokenUrl, grant, clientId, clientSecret),
    );
  } catch (error) {
    if (axios.isAxiosError(error)) {
      logger?.error('[SAML] Token exchange failed', {
        status: error.response?.status,
        error: describeOAuthErrorBody(error.response?.data, [
          samlResponse,
          clientSecret,
          ...(prepared?.secrets ?? []),
        ]),
      });
    }
    throw error;
  }
  const data = response.data;
  if (!data?.access_token) {
    throw new Error('Token response missing access_token');
  }

  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    expiresIn: data.expires_in,
    tokenType: data.token_type,
  };
}

/**
 * Spends a refresh token obtained from a SAML bearer exchange.
 *
 * Sent to the same token endpoint, with the same client authentication, as the
 * exchange that issued it — so an explicit `tokenUrl` is honoured rather than
 * rebuilt from a UAA base URL.
 */
export async function refreshSamlBearerToken(
  refreshToken: string,
  tokenUrl: string,
  clientId: string | undefined,
  clientSecret?: string,
  logger?: ILogger,
  auth?: TokenRequestAuth,
): Promise<Saml2TokenExchangeResponse> {
  const grant = new URLSearchParams();
  grant.append('grant_type', 'refresh_token');
  grant.append('refresh_token', refreshToken);
  const prepared = auth
    ? await prepareWith(auth, tokenUrl, clientId, 'refresh_token', grant)
    : undefined;

  logger?.info('[SAML] Refreshing token', {
    tokenUrl: prepared?.config.url ?? tokenUrl,
  });

  let response: AxiosResponse;
  try {
    response = await sendTokenRequest(prepared, () =>
      sendAsToday(tokenUrl, grant, clientId, clientSecret),
    );
  } catch (error) {
    if (axios.isAxiosError(error)) {
      logger?.error('[SAML] Token refresh failed', {
        status: error.response?.status,
        error: describeOAuthErrorBody(error.response?.data, [
          refreshToken,
          clientSecret,
          ...(prepared?.secrets ?? []),
        ]),
      });
    }
    throw error;
  }
  const data = response.data;
  if (!data?.access_token) {
    throw new Error('Refresh response missing access_token');
  }

  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    expiresIn: data.expires_in,
    tokenType: data.token_type,
  };
}
