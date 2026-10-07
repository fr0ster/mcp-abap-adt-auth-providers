/**
 * OIDC token endpoint helpers
 */

import { readFailure } from '@mcp-abap-adt/auth-errors';
import type { Operation } from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import axios, { type AxiosResponse } from 'axios';
import { intervalWait, throwIfAborted, untilAborted } from './attempt';
import {
  attemptSite,
  type LegacyBasic,
  legacyBasic,
  logQuietly,
  type PreparedTokenRequest,
  prepareTokenRequest,
  rejectMissingToken,
  sendTokenRequest,
  siteSecrets,
  type TokenRequestAuth,
  type TokenRequestSite,
  type TokenResponseSnapshot,
  type TokenSiteOptions,
  tokenSite,
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
 * built only through legacyBasic, so its secrets are named in `sent`.
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
  signal: AbortSignal | undefined,
): Promise<AxiosResponse> {
  return axios.post(endpoint, params.toString(), {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      ...(basic ? { Authorization: basic.header } : {}),
    },
    // A redirect would re-send the grant's secret (code, refresh token,
    // device code, password, subject token) and the client's: never followed.
    maxRedirects: 0,
    // The attempt's abort cuts the request; a refresh site passes none.
    ...(signal === undefined ? {} : { signal }),
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

/** What one OIDC request is, beside its endpoint and parameters. */
interface OidcRequest {
  readonly operation: Operation;
  readonly logger: ILogger | undefined;
  readonly options: TokenSiteOptions | undefined;
  readonly auth: TokenRequestAuth | undefined;
  readonly clientId: string;
  readonly clientSecret: string | undefined;
  readonly grantType: string;
  /**
   * `attempt` for an attempt's own request, which carries its signal;
   * `refresh` for a refresh, which never does (spec §6b).
   */
  readonly kind: 'attempt' | 'refresh';
}

/**
 * One token request — through the strategy when there is one, else as today
 * — mapped to tokens; a `2xx` without `access_token` is `rejectMissingToken`'s.
 */
async function requestTokens(
  request: OidcRequest,
  endpoint: string,
  params: URLSearchParams,
): Promise<OidcTokenResponse> {
  const { auth, clientId, clientSecret } = request;
  const prepared = auth
    ? await prepareWith(auth, endpoint, clientId, request.grantType, params)
    : undefined;
  const basic = todaysBasic(prepared, clientId, clientSecret);
  const site = (request.kind === 'refresh' ? tokenSite : attemptSite)(
    request.operation,
    request.options,
    request.logger,
    siteSecrets(params, clientSecret),
    basic,
  );
  const response = await sendTokenRequest<TokenResponseBody>(
    prepared,
    (signal) => sendAsToday(endpoint, params, basic, signal),
    site,
  );
  return mapTokenResponse(site, prepared, response);
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
  site: TokenRequestSite,
  prepared: PreparedTokenRequest | undefined,
  response: TokenResponseSnapshot<TokenResponseBody>,
): OidcTokenResponse {
  const data = response.data;
  if (!data.access_token) {
    rejectMissingToken(site, prepared, response, 'no-access-token', 'debug');
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
  /** The PKCE verifier of the URL this code answers; none when no URL was built. */
  codeVerifier: string | undefined,
  logger?: ILogger,
  auth?: TokenRequestAuth,
  options?: TokenSiteOptions,
): Promise<OidcTokenResponse> {
  const params = new URLSearchParams();
  params.append('grant_type', 'authorization_code');
  params.append('code', code);
  params.append('redirect_uri', redirectUri);
  if (codeVerifier !== undefined) params.append('code_verifier', codeVerifier);
  params.append('client_id', clientId);

  logQuietly(() =>
    logger?.info('[OIDC] Exchanging authorization code for tokens'),
  );

  return requestTokens(
    {
      operation: 'oidc-token-request',
      logger,
      options,
      auth,
      clientId,
      clientSecret,
      grantType: 'authorization_code',
      kind: 'attempt',
    },
    tokenEndpoint,
    params,
  );
}

export async function refreshOidcToken(
  tokenEndpoint: string,
  clientId: string,
  clientSecret: string | undefined,
  refreshToken: string,
  logger?: ILogger,
  auth?: TokenRequestAuth,
  options?: TokenSiteOptions,
): Promise<OidcTokenResponse> {
  const params = new URLSearchParams();
  params.append('grant_type', 'refresh_token');
  params.append('refresh_token', refreshToken);
  params.append('client_id', clientId);

  logQuietly(() => logger?.info('[OIDC] Refreshing token'));

  return requestTokens(
    {
      operation: 'oidc-token-request',
      logger,
      options,
      auth,
      clientId,
      clientSecret,
      grantType: 'refresh_token',
      kind: 'refresh',
    },
    tokenEndpoint,
    params,
  );
}

export interface OidcDeviceFlowInitResponse {
  deviceCode: string;
  userCode: string;
  verificationUri: string;
  verificationUriComplete?: string | undefined;
  interval?: number | undefined;
  expiresIn?: number | undefined;
}

/** The device authorization response (RFC 8628 §3.2). */
interface DeviceAuthorizationBody {
  device_code?: string;
  user_code?: string;
  verification_uri?: string;
  verification_uri_complete?: string;
  interval?: number;
  expires_in?: number;
}

export async function initiateDeviceAuthorization(
  deviceEndpoint: string,
  clientId: string,
  scope: string | undefined,
  logger?: ILogger,
  auth?: TokenRequestAuth,
  options?: TokenSiteOptions,
): Promise<OidcDeviceFlowInitResponse> {
  const params = new URLSearchParams();
  params.append('client_id', clientId);
  if (scope) {
    params.append('scope', scope);
  }

  logQuietly(() => logger?.info('[OIDC] Initiating device authorization'));

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
  const site = attemptSite(
    'device-authorization',
    options,
    logger,
    siteSecrets(params, undefined),
  );
  const response = await sendTokenRequest<DeviceAuthorizationBody>(
    prepared,
    (signal) =>
      axios.post(deviceEndpoint, params.toString(), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        // Never followed, like every token request.
        maxRedirects: 0,
        // The attempt's abort cuts the initiation (spec §6b).
        ...(signal === undefined ? {} : { signal }),
      }),
    site,
  );

  const data = response.data;
  if (!data.device_code || !data.user_code || !data.verification_uri) {
    rejectMissingToken(
      site,
      prepared,
      response,
      'incomplete-response',
      'debug',
    );
  }

  return {
    deviceCode: data.device_code,
    userCode: data.user_code,
    verificationUri: data.verification_uri,
    verificationUriComplete: data.verification_uri_complete,
    interval: serverInterval(data.interval),
    expiresIn: data.expires_in,
  };
}

/** RFC 8628 §3.2: the poll interval when the server names none, in seconds. */
const DEFAULT_INTERVAL = 5;

/**
 * The server's `interval` when it is a finite, non-negative JSON number;
 * else undefined. A string — numeric or not — is no JSON number (RFC 8628
 * §3.2), and NaN, a negative or an infinite value would make the poll hot
 * or odd.
 */
function serverInterval(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0
    ? value
    : undefined;
}

/**
 * True for the device poll's waiting answers (§6, RFC 8628 §3.5): a `400`
 * whose registered `oauthError` is `authorization_pending` or `slow_down`,
 * read from the failure's classified facts alone.
 */
function waitingAnswer(
  error: unknown,
): 'authorization_pending' | 'slow_down' | undefined {
  const failure = readFailure(error, 'device-poll');
  if (failure.kind !== 'request-failed' || failure.facts.status !== 400) {
    return undefined;
  }
  const code = failure.facts.oauthError;
  return code === 'authorization_pending' || code === 'slow_down'
    ? code
    : undefined;
}

export async function pollDeviceTokens(
  tokenEndpoint: string,
  clientId: string,
  clientSecret: string | undefined,
  deviceCode: string,
  interval: number = DEFAULT_INTERVAL,
  logger?: ILogger,
  auth?: TokenRequestAuth,
  options?: TokenSiteOptions,
): Promise<OidcTokenResponse> {
  const params = new URLSearchParams();
  params.append('grant_type', 'urn:ietf:params:oauth:grant-type:device_code');
  params.append('device_code', deviceCode);
  params.append('client_id', clientId);

  const request: OidcRequest = {
    operation: 'device-poll',
    logger,
    options,
    auth,
    clientId,
    clientSecret,
    grantType: 'urn:ietf:params:oauth:grant-type:device_code',
    kind: 'attempt',
  };
  // The server's interval is the protocol, not a timeout of this package;
  // anything but a finite non-negative number is the RFC's default.
  let wait = serverInterval(interval) ?? DEFAULT_INTERVAL;
  // The attempt's signal (spec §6b): checked before every poll and after
  // every await — the request, the wait — so the loop never polls again
  // once the attempt is aborted. Each poll carries it (the abort cuts the
  // request), and the loop stops waiting for an outstanding poll at the
  // abort itself (`untilAborted`), not when its answer arrives.
  const signal = options?.signal;
  while (true) {
    throwIfAborted(signal);
    // Authenticated anew per request: an assertion is never reused.
    try {
      return await untilAborted(
        requestTokens(request, tokenEndpoint, params),
        signal,
      );
    } catch (error) {
      throwIfAborted(signal);
      const waiting = waitingAnswer(error);
      if (waiting === undefined) throw error;
      // RFC 8628 §3.5: slow_down adds 5 s for this and every later request.
      if (waiting === 'slow_down') wait += 5;
      logQuietly(() =>
        logger?.debug('[OIDC] Device authorization pending', { wait }),
      );
      // The server's interval, not a timeout of this package; the abort
      // ends it early.
      await intervalWait(wait * 1000, signal);
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
  options?: TokenSiteOptions,
): Promise<OidcTokenResponse> {
  const params = new URLSearchParams();
  params.append('grant_type', 'password');
  params.append('username', username);
  params.append('password', password);
  params.append('client_id', clientId);
  if (scope) {
    params.append('scope', scope);
  }

  logQuietly(() => logger?.info('[OIDC] Performing password grant'));

  return requestTokens(
    {
      operation: 'password-grant',
      logger,
      options,
      auth,
      clientId,
      clientSecret,
      grantType: 'password',
      kind: 'attempt',
    },
    tokenEndpoint,
    params,
  );
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
  options?: TokenSiteOptions,
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

  logQuietly(() => logger?.info('[OIDC] Performing token exchange'));

  return requestTokens(
    {
      operation: 'oidc-token-request',
      logger,
      options,
      auth,
      clientId,
      clientSecret,
      grantType: 'urn:ietf:params:oauth:grant-type:token-exchange',
      kind: 'attempt',
    },
    tokenEndpoint,
    params,
  );
}
