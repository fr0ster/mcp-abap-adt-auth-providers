/**
 * OIDC token endpoint helpers
 */

import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import axios, { type AxiosResponse } from 'axios';
import { readSafely } from './knownCodes';
import { tlsFailureCode } from './refusal';
import {
  type LegacyBasic,
  legacyBasic,
  logQuietly,
  type PreparedTokenRequest,
  prepareTokenRequest,
  sendTokenRequest,
  type TokenRequestAuth,
  type TokenRequestDiagnostics,
  tokenEndpointError,
} from './tokenRequest';

export interface OidcTokenResponse {
  accessToken: string;
  refreshToken?: string | undefined;
  idToken?: string | undefined;
  expiresIn?: number | undefined;
  tokenType?: string | undefined;
}

/**
 * Today's Basic header, when a secret is given and there is no strategy —
 * built only through legacyBasic, so its secrets join every redaction.
 */
function todaysBasic(
  prepared: PreparedTokenRequest | undefined,
  clientId: string,
  clientSecret: string | undefined,
): LegacyBasic | undefined {
  return !prepared && clientSecret !== undefined
    ? legacyBasic(clientId, clientSecret)
    : undefined;
}

/** Today's request: `params` as built (client_id included), Basic when a secret is given. */
function sendAsToday(
  endpoint: string,
  params: URLSearchParams,
  basic: LegacyBasic | undefined,
): Promise<AxiosResponse> {
  return axios.post(endpoint, params.toString(), {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      ...(basic ? { Authorization: basic.header } : {}),
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
  diagnostics: TokenRequestDiagnostics,
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
  const basic = todaysBasic(prepared, clientId, clientSecret);
  return sendTokenRequest(
    prepared,
    () => sendAsToday(endpoint, params, basic),
    diagnostics,
  );
}

/** A token endpoint's success body (RFC 6749 §5.1, OIDC Core §3.1.3.3). */
interface TokenResponseBody {
  access_token?: string;
  refresh_token?: string;
  id_token?: string;
  expires_in?: number;
  token_type?: string;
}

function mapTokenResponse(
  data: TokenResponseBody | null | undefined,
): OidcTokenResponse {
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
    { logger, label: 'OIDC authorization code exchange failed' },
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
    { logger, label: 'OIDC token refresh failed' },
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
      { logger, label: 'OIDC device authorization failed' },
    );
  } catch (error: unknown) {
    // Unwrapped, so the refusal can name the TLS code and its fixed hint.
    if (tlsFailureCode(error) !== undefined) throw error;
    // The safe facts only: the status and a registered code.
    throw tokenEndpointError('OIDC device authorization failed', error);
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
    const basic = todaysBasic(prepared, clientId, clientSecret);
    try {
      const response = await sendTokenRequest(
        prepared,
        () => sendAsToday(tokenEndpoint, params, basic),
        { logger, label: 'OIDC device poll failed' },
      );
      return mapTokenResponse(response.data);
    } catch (error) {
      const response = readSafely(error, 'response');
      const status = readSafely(response, 'status');
      const errorCode = readSafely(readSafely(response, 'data'), 'error');
      if (
        status === 400 &&
        (errorCode === 'authorization_pending' || errorCode === 'slow_down')
      ) {
        const wait = errorCode === 'slow_down' ? interval + 5 : interval;
        logQuietly(() =>
          logger?.debug('[OIDC] Device authorization pending', { wait }),
        );
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
  const basic = todaysBasic(prepared, clientId, clientSecret);
  try {
    const response = await sendTokenRequest(
      prepared,
      () => sendAsToday(tokenEndpoint, params, basic),
      { logger, label: 'OIDC password grant failed' },
    );
    return mapTokenResponse(response.data);
  } catch (error) {
    // Unwrapped, so the refusal can name the TLS code and its fixed hint.
    if (tlsFailureCode(error) !== undefined) throw error;
    // The safe facts only: the status and a registered code.
    throw tokenEndpointError('OIDC password grant failed', error);
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
    { logger, label: 'OIDC token exchange failed' },
    auth,
    tokenEndpoint,
    clientId,
    clientSecret,
    'urn:ietf:params:oauth:grant-type:token-exchange',
    params,
  );

  return mapTokenResponse(response.data);
}
