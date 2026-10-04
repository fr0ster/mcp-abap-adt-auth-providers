/**
 * OIDC token endpoint helpers
 */

import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import axios, { type AxiosResponse } from 'axios';
import { tlsFailureCode } from './refusal';
import {
  grantSecrets,
  type PreparedTokenRequest,
  prepareTokenRequest,
  sendTokenRequest,
  type TokenRequestAuth,
  tokenEndpointError,
} from './tokenRequest';

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
  if (clientSecret !== undefined) {
    return { Authorization: `Basic ${toBasicAuth(clientId, clientSecret)}` };
  }
  return {};
}

/** Today's request: `params` as built (client_id included), Basic when a secret is given. */
function sendAsToday(
  endpoint: string,
  params: URLSearchParams,
  clientId: string,
  clientSecret: string | undefined,
): Promise<AxiosResponse> {
  return axios.post(endpoint, params.toString(), {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      ...buildAuthHeaders(clientId, clientSecret),
    },
    // A redirect would re-send the grant's secret (code, refresh token,
    // device code, password, subject token) and the client's: never followed.
    maxRedirects: 0,
  });
}

/**
 * With a strategy: today's parameters without `client_id` — the strategy
 * decides whether the body carries it.
 */
function prepareWith(
  auth: TokenRequestAuth,
  endpoint: string,
  clientId: string,
  grantType: string,
  params: URLSearchParams,
): Promise<PreparedTokenRequest> {
  const grant = new URLSearchParams(params);
  grant.delete('client_id');
  return prepareTokenRequest(
    { endpoint, clientId, grantType, parameters: grant },
    auth,
  );
}

/** One request: through the strategy when there is one, else as today. */
async function send(
  auth: TokenRequestAuth | undefined,
  endpoint: string,
  clientId: string,
  clientSecret: string | undefined,
  grantType: string,
  params: URLSearchParams,
): Promise<AxiosResponse> {
  const prepared = auth
    ? await prepareWith(auth, endpoint, clientId, grantType, params)
    : undefined;
  return sendTokenRequest(
    prepared,
    () => sendAsToday(endpoint, params, clientId, clientSecret),
    [clientSecret, ...grantSecrets(params)],
  );
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
  auth?: TokenRequestAuth,
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

  const response = await send(
    auth,
    tokenEndpoint,
    clientId,
    clientSecret,
    'authorization_code',
    params,
  );

  return mapTokenResponse(response.data);
}

export async function refreshOidcToken(
  tokenEndpoint: string,
  clientId: string,
  clientSecret: string | undefined,
  refreshToken: string,
  logger?: ILogger,
  auth?: TokenRequestAuth,
): Promise<OidcTokenResponse> {
  const params = new URLSearchParams();
  params.append('grant_type', 'refresh_token');
  params.append('refresh_token', refreshToken);
  params.append('client_id', clientId);

  logger?.info('[OIDC] Refreshing token', { tokenEndpoint });

  const response = await send(
    auth,
    tokenEndpoint,
    clientId,
    clientSecret,
    'refresh_token',
    params,
  );

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
  auth?: TokenRequestAuth,
): Promise<OidcDeviceFlowInitResponse> {
  const params = new URLSearchParams();
  params.append('client_id', clientId);
  if (scope) {
    params.append('scope', scope);
  }

  logger?.info('[OIDC] Initiating device authorization', { deviceEndpoint });

  // RFC 8628 §3.1: a confidential client authenticates here too. Without a
  // strategy, today's request: client_id in the body, never Basic.
  const prepared = auth
    ? await prepareWith(
        auth,
        deviceEndpoint,
        clientId,
        'device_authorization',
        params,
      )
    : undefined;
  let response: AxiosResponse;
  try {
    response = await sendTokenRequest(
      prepared,
      () =>
        axios.post(deviceEndpoint, params.toString(), {
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          // Never followed, like every token request.
          maxRedirects: 0,
        }),
      grantSecrets(params),
    );
  } catch (error: unknown) {
    // Unwrapped, so the refusal can name the TLS code and its fixed hint.
    if (tlsFailureCode(error) !== undefined) throw error;
    // Only `error` and `error_description`, with what the strategy sent
    // redacted: a server may echo it; the safe facts as properties.
    throw tokenEndpointError('OIDC device authorization failed', error, [
      ...grantSecrets(params),
      ...(prepared?.secrets ?? []),
    ]);
  }

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
  auth?: TokenRequestAuth,
): Promise<OidcTokenResponse> {
  const params = new URLSearchParams();
  params.append('grant_type', 'urn:ietf:params:oauth:grant-type:device_code');
  params.append('device_code', deviceCode);
  params.append('client_id', clientId);

  while (true) {
    // Authenticated anew per request: an assertion is never reused.
    const prepared = auth
      ? await prepareWith(
          auth,
          tokenEndpoint,
          clientId,
          'urn:ietf:params:oauth:grant-type:device_code',
          params,
        )
      : undefined;
    try {
      const response = await sendTokenRequest(
        prepared,
        () => sendAsToday(tokenEndpoint, params, clientId, clientSecret),
        [clientSecret, ...grantSecrets(params)],
      );
      return mapTokenResponse(response.data);
    } catch (error: any) {
      const status = error?.response?.status;
      const errorCode = error?.response?.data?.error;
      if (
        status === 400 &&
        (errorCode === 'authorization_pending' || errorCode === 'slow_down')
      ) {
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
  auth?: TokenRequestAuth,
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

  // Asked before the try: what the strategy throws is not a token-endpoint failure.
  const prepared = auth
    ? await prepareWith(auth, tokenEndpoint, clientId, 'password', params)
    : undefined;
  try {
    const response = await sendTokenRequest(
      prepared,
      () => sendAsToday(tokenEndpoint, params, clientId, clientSecret),
      [clientSecret, ...grantSecrets(params)],
    );
    return mapTokenResponse(response.data);
  } catch (error: any) {
    // Unwrapped, so the refusal can name the TLS code and its fixed hint.
    if (tlsFailureCode(error) !== undefined) throw error;
    // Only `error` and `error_description`, with the password, the secret
    // and what the strategy sent redacted: a server may echo them; the safe
    // facts as properties.
    throw tokenEndpointError('OIDC password grant failed', error, [
      password,
      clientSecret,
      ...(prepared?.secrets ?? []),
    ]);
  }
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
  auth?: TokenRequestAuth,
): Promise<OidcTokenResponse> {
  const params = new URLSearchParams();
  params.append(
    'grant_type',
    'urn:ietf:params:oauth:grant-type:token-exchange',
  );
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

  const response = await send(
    auth,
    tokenEndpoint,
    clientId,
    clientSecret,
    'urn:ietf:params:oauth:grant-type:token-exchange',
    params,
  );

  return mapTokenResponse(response.data);
}
