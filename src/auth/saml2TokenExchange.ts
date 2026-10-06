/**
 * SAML 2.0 bearer assertion exchange
 */

import { authError, logFields, readFailure } from '@mcp-abap-adt/auth-errors';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import axios, { type AxiosResponse } from 'axios';
import { misconfigured } from './configuration';
import type { Operation } from './contractTransition';
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
  type TokenResponseSnapshot,
  type TokenSiteOptions,
  tokenSite,
} from './tokenRequest';

export interface Saml2TokenExchangeResponse {
  accessToken: string;
  refreshToken?: string | undefined;
  expiresIn?: number | undefined;
  tokenType?: string | undefined;
}

/**
 * Today's Basic header, when a secret is known and there is no strategy —
 * built only through legacyBasic, so its secrets are named in `sent`.
 */
function todaysBasic(
  prepared: PreparedTokenRequest | undefined,
  clientId: string | undefined,
  clientSecret: string | undefined,
): LegacyBasic | undefined {
  return !prepared && clientId && clientSecret
    ? legacyBasic(clientId, clientSecret)
    : undefined;
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
    // E11: nothing is sent.
    throw misconfigured(
      authError.configuration({
        case: 'client-id-required-with-client-authentication',
        fields: ['clientId'],
      }),
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
  basic: LegacyBasic | undefined,
  signal: AbortSignal | undefined,
): Promise<AxiosResponse> {
  const params = new URLSearchParams(grant);
  if (clientId) {
    params.append('client_id', clientId);
  }
  const headers: Record<string, string> = {
    'Content-Type': 'application/x-www-form-urlencoded',
  };
  if (basic) {
    headers.Authorization = basic.header;
  }
  // A redirect would re-send the assertion or the refresh token, and the
  // secret: never followed.
  // The attempt's abort cuts the exchange; the refresh passes none (§6b).
  return axios.post(tokenUrl, params.toString(), {
    headers,
    maxRedirects: 0,
    ...(signal === undefined ? {} : { signal }),
  });
}

/** A token endpoint's success body (RFC 6749 §5.1). */
interface TokenResponseBody {
  access_token?: string;
  refresh_token?: string;
  expires_in?: number;
  token_type?: string;
}

/** What one SAML request is, beside its endpoint and grant. */
interface SamlRequest {
  readonly operation: Operation;
  /** H6: the error line the site writes for any failure of its request. */
  readonly failed: string;
  readonly clientId: string | undefined;
  readonly clientSecret: string | undefined;
  readonly logger: ILogger | undefined;
  readonly options: TokenSiteOptions | undefined;
  readonly prepared: PreparedTokenRequest | undefined;
  /**
   * `attempt` for the exchange, which carries the attempt's signal;
   * `refresh` for the refresh, which never does (spec §6b).
   */
  readonly kind: 'attempt' | 'refresh';
}

/**
 * Sends one SAML request and maps the answer. A failed request is logged at
 * `error` as `logFields` of its failure (H6) — inside `logQuietly`, so a
 * logger that throws never replaces the failure — and rethrown as it is; a
 * `2xx` without `access_token` is `rejectMissingToken`'s.
 */
async function requestTokens(
  request: SamlRequest,
  tokenUrl: string,
  grant: URLSearchParams,
): Promise<Saml2TokenExchangeResponse> {
  const { prepared, clientId, clientSecret, logger, operation } = request;
  const basic = todaysBasic(prepared, clientId, clientSecret);
  const site = (request.kind === 'refresh' ? tokenSite : attemptSite)(
    operation,
    request.options,
    logger,
    siteSecrets(grant, clientSecret),
    basic,
  );
  let response: TokenResponseSnapshot<TokenResponseBody>;
  try {
    response = await sendTokenRequest<TokenResponseBody>(
      prepared,
      (signal) => sendAsToday(tokenUrl, grant, clientId, basic, signal),
      site,
    );
  } catch (error) {
    // Cut by the attempt's own abort: nothing failed that a line could say.
    if (site.signal?.aborted === true) throw error;
    // The safe facts only: the failure's words, kind and status.
    logQuietly(() =>
      logger?.error(request.failed, logFields(readFailure(error, operation))),
    );
    throw error;
  }
  const data = response.data;
  if (!data.access_token) {
    rejectMissingToken(site, prepared, response, 'no-access-token', 'debug');
  }

  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    expiresIn: data.expires_in,
    tokenType: data.token_type,
  };
}

export async function exchangeSamlAssertion(
  samlResponse: string,
  tokenUrl: string,
  clientId: string | undefined,
  clientSecret: string | undefined,
  logger?: ILogger,
  auth?: TokenRequestAuth,
  options?: TokenSiteOptions,
): Promise<Saml2TokenExchangeResponse> {
  const grantType = 'urn:ietf:params:oauth:grant-type:saml2-bearer';
  const grant = new URLSearchParams();
  grant.append('grant_type', grantType);
  grant.append('assertion', samlResponse);
  const prepared = auth
    ? await prepareWith(auth, tokenUrl, clientId, grantType, grant)
    : undefined;

  logQuietly(() =>
    logger?.info('[SAML] Exchanging assertion for token', {
      tokenUrl: prepared?.config.url ?? tokenUrl,
    }),
  );

  return requestTokens(
    {
      operation: 'saml-token-exchange',
      failed: '[SAML] Token exchange failed',
      clientId,
      clientSecret,
      logger,
      options,
      prepared,
      kind: 'attempt',
    },
    tokenUrl,
    grant,
  );
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
  options?: TokenSiteOptions,
): Promise<Saml2TokenExchangeResponse> {
  const grant = new URLSearchParams();
  grant.append('grant_type', 'refresh_token');
  grant.append('refresh_token', refreshToken);
  const prepared = auth
    ? await prepareWith(auth, tokenUrl, clientId, 'refresh_token', grant)
    : undefined;

  logQuietly(() =>
    logger?.info('[SAML] Refreshing token', {
      tokenUrl: prepared?.config.url ?? tokenUrl,
    }),
  );

  return requestTokens(
    {
      operation: 'saml-token-refresh',
      failed: '[SAML] Token refresh failed',
      clientId,
      clientSecret,
      logger,
      options,
      prepared,
      kind: 'refresh',
    },
    tokenUrl,
    grant,
  );
}
