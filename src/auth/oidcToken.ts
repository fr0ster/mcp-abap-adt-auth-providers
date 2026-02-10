/**
 * OIDC token endpoint helpers
 */

import type { ILogger } from '@mcp-abap-adt/interfaces';
import axios from 'axios';

export interface OidcTokenResponse {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  expiresIn?: number;
  tokenType?: string;
}

function toBasicAuth(clientId: string, clientSecret: string): string {
  return Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
}

function buildAuthHeaders(
  clientId: string,
  clientSecret?: string,
): Record<string, string> {
  if (clientSecret) {
    return { Authorization: `Basic ${toBasicAuth(clientId, clientSecret)}` };
  }
  return {};
}

function mapTokenResponse(data: any): OidcTokenResponse {
  if (!data?.access_token) {
    throw new Error('Token response missing access_token');
  }
  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    idToken: data.id_token,
    expiresIn: data.expires_in,
    tokenType: data.token_type,
  };
}

export async function exchangeAuthorizationCode(
  tokenEndpoint: string,
  clientId: string,
  clientSecret: string | undefined,
  code: string,
  redirectUri: string,
  codeVerifier: string,
  logger?: ILogger,
): Promise<OidcTokenResponse> {
  const params = new URLSearchParams();
  params.append('grant_type', 'authorization_code');
  params.append('code', code);
  params.append('redirect_uri', redirectUri);
  params.append('code_verifier', codeVerifier);
  params.append('client_id', clientId);

  logger?.info('[OIDC] Exchanging authorization code for tokens', {
    tokenEndpoint,
  });

  const response = await axios.post(tokenEndpoint, params.toString(), {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      ...buildAuthHeaders(clientId, clientSecret),
    },
  });

  return mapTokenResponse(response.data);
}

export async function refreshOidcToken(
  tokenEndpoint: string,
  clientId: string,
  clientSecret: string | undefined,
  refreshToken: string,
  logger?: ILogger,
): Promise<OidcTokenResponse> {
  const params = new URLSearchParams();
  params.append('grant_type', 'refresh_token');
  params.append('refresh_token', refreshToken);
  params.append('client_id', clientId);

  logger?.info('[OIDC] Refreshing token', { tokenEndpoint });

  const response = await axios.post(tokenEndpoint, params.toString(), {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      ...buildAuthHeaders(clientId, clientSecret),
    },
  });

  return mapTokenResponse(response.data);
}

export interface OidcDeviceFlowInitResponse {
  deviceCode: string;
  userCode: string;
  verificationUri: string;
  verificationUriComplete?: string;
  interval?: number;
  expiresIn?: number;
}

export async function initiateDeviceAuthorization(
  deviceEndpoint: string,
  clientId: string,
  scope: string | undefined,
  logger?: ILogger,
): Promise<OidcDeviceFlowInitResponse> {
  const params = new URLSearchParams();
  params.append('client_id', clientId);
  if (scope) {
    params.append('scope', scope);
  }

  logger?.info('[OIDC] Initiating device authorization', { deviceEndpoint });

  const response = await axios.post(deviceEndpoint, params.toString(), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });

  const data = response.data;
  if (!data?.device_code || !data?.user_code || !data?.verification_uri) {
    throw new Error('Device authorization response missing required fields');
  }

  return {
    deviceCode: data.device_code,
    userCode: data.user_code,
    verificationUri: data.verification_uri,
    verificationUriComplete: data.verification_uri_complete,
    interval: data.interval,
    expiresIn: data.expires_in,
  };
}

export async function pollDeviceTokens(
  tokenEndpoint: string,
  clientId: string,
  clientSecret: string | undefined,
  deviceCode: string,
  interval: number = 5,
  logger?: ILogger,
): Promise<OidcTokenResponse> {
  const params = new URLSearchParams();
  params.append('grant_type', 'urn:ietf:params:oauth:grant-type:device_code');
  params.append('device_code', deviceCode);
  params.append('client_id', clientId);

  while (true) {
    try {
      const response = await axios.post(tokenEndpoint, params.toString(), {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          ...buildAuthHeaders(clientId, clientSecret),
        },
      });
      return mapTokenResponse(response.data);
    } catch (error: any) {
      const status = error?.response?.status;
      const errorCode = error?.response?.data?.error;
      if (status === 400 && (errorCode === 'authorization_pending' || errorCode === 'slow_down')) {
        const wait = errorCode === 'slow_down' ? interval + 5 : interval;
        logger?.debug('[OIDC] Device authorization pending', { wait });
        await new Promise((resolve) => setTimeout(resolve, wait * 1000));
        continue;
      }
      throw error;
    }
  }
}

export async function passwordGrant(
  tokenEndpoint: string,
  clientId: string,
  clientSecret: string | undefined,
  username: string,
  password: string,
  scope: string | undefined,
  logger?: ILogger,
): Promise<OidcTokenResponse> {
  const params = new URLSearchParams();
  params.append('grant_type', 'password');
  params.append('username', username);
  params.append('password', password);
  params.append('client_id', clientId);
  if (scope) {
    params.append('scope', scope);
  }

  logger?.info('[OIDC] Performing password grant', { tokenEndpoint });

  const response = await axios.post(tokenEndpoint, params.toString(), {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      ...buildAuthHeaders(clientId, clientSecret),
    },
  });

  return mapTokenResponse(response.data);
}

export async function tokenExchange(
  tokenEndpoint: string,
  clientId: string,
  clientSecret: string | undefined,
  subjectToken: string,
  subjectTokenType: string,
  scope: string | undefined,
  audience: string | undefined,
  actorToken?: string,
  actorTokenType?: string,
  logger?: ILogger,
): Promise<OidcTokenResponse> {
  const params = new URLSearchParams();
  params.append('grant_type', 'urn:ietf:params:oauth:grant-type:token-exchange');
  params.append('subject_token', subjectToken);
  params.append('subject_token_type', subjectTokenType);
  params.append('client_id', clientId);
  if (scope) {
    params.append('scope', scope);
  }
  if (audience) {
    params.append('audience', audience);
  }
  if (actorToken) {
    params.append('actor_token', actorToken);
  }
  if (actorTokenType) {
    params.append('actor_token_type', actorTokenType);
  }

  logger?.info('[OIDC] Performing token exchange', { tokenEndpoint });

  const response = await axios.post(tokenEndpoint, params.toString(), {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      ...buildAuthHeaders(clientId, clientSecret),
    },
  });

  return mapTokenResponse(response.data);
}
