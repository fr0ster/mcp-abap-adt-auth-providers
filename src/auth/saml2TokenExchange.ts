/**
 * SAML 2.0 bearer assertion exchange
 */

import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import axios, { type AxiosResponse } from 'axios';
import { describeOAuthErrorBody } from './oauthErrorBody';

export interface Saml2TokenExchangeResponse {
  accessToken: string;
  refreshToken?: string;
  expiresIn?: number;
  tokenType?: string;
}

function toBasicAuth(clientId: string, clientSecret: string): string {
  return Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
}

export async function exchangeSamlAssertion(
  samlResponse: string,
  tokenUrl: string,
  clientId: string | undefined,
  clientSecret: string | undefined,
  logger?: ILogger,
): Promise<Saml2TokenExchangeResponse> {
  const params = new URLSearchParams();
  params.append('grant_type', 'urn:ietf:params:oauth:grant-type:saml2-bearer');
  params.append('assertion', samlResponse);
  if (clientId) {
    params.append('client_id', clientId);
  }

  logger?.info('[SAML] Exchanging assertion for token', { tokenUrl });

  const headers: Record<string, string> = {
    'Content-Type': 'application/x-www-form-urlencoded',
  };
  if (clientId && clientSecret) {
    headers.Authorization = `Basic ${toBasicAuth(clientId, clientSecret)}`;
  }

  let response: AxiosResponse;
  try {
    response = await axios.post(tokenUrl, params.toString(), { headers });
  } catch (error) {
    if (axios.isAxiosError(error)) {
      logger?.error('[SAML] Token exchange failed', {
        status: error.response?.status,
        error: describeOAuthErrorBody(error.response?.data, [
          samlResponse,
          clientSecret,
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
): Promise<Saml2TokenExchangeResponse> {
  const params = new URLSearchParams();
  params.append('grant_type', 'refresh_token');
  params.append('refresh_token', refreshToken);
  if (clientId) {
    params.append('client_id', clientId);
  }

  logger?.info('[SAML] Refreshing token', { tokenUrl });

  const headers: Record<string, string> = {
    'Content-Type': 'application/x-www-form-urlencoded',
  };
  if (clientId && clientSecret) {
    headers.Authorization = `Basic ${toBasicAuth(clientId, clientSecret)}`;
  }

  let response: AxiosResponse;
  try {
    response = await axios.post(tokenUrl, params.toString(), { headers });
  } catch (error) {
    if (axios.isAxiosError(error)) {
      logger?.error('[SAML] Token refresh failed', {
        status: error.response?.status,
        error: describeOAuthErrorBody(error.response?.data, [
          refreshToken,
          clientSecret,
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
