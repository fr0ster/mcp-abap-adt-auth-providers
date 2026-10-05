/**
 * The UAA one-time passcode exchange — what `cf login --sso` does.
 *
 * The user opens `<uaa>/passcode` in any browser, logs in however the
 * identity zone lets them (SSO, a corporate IdP, MFA), and copies the
 * "Temporary Authentication Code" shown there. That code is exchanged here
 * through the password grant, with `passcode` in place of a username and
 * password. It is a UAA extension, not an RFC; XSUAA inherits it.
 *
 * UAA hands the request to its passcode filter chain only when its Accept
 * header names JSON (`passcodeTokenMatcher` accepts `application/json` or
 * `application/x-www-form-urlencoded`). Otherwise it falls through to the
 * ordinary password grant, which answers `invalid_client: No password
 * supplied` — what a bare `fetch`, which sends `*\/*`, gets. axios's default
 * Accept happens to include `application/json`; the header is set explicitly
 * so the exchange does not depend on an HTTP client's defaults.
 */

import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import axios, { type AxiosResponse } from 'axios';
import {
  grantSecrets,
  legacyBasic,
  prepareTokenRequest,
  requestSecrets,
  sendTokenRequest,
  type TokenRequestAuth,
  tokenEndpointError,
} from './tokenRequest';

export interface PasscodeTokens {
  accessToken: string;
  refreshToken?: string | undefined;
  expiresIn?: number | undefined;
}

export async function exchangePasscode(
  uaaUrl: string,
  clientId: string,
  clientSecret: string | undefined,
  passcode: string,
  logger?: ILogger,
  auth?: TokenRequestAuth,
): Promise<PasscodeTokens> {
  const tokenUrl = `${uaaUrl.replace(/\/+$/, '')}/oauth/token`;
  const params = new URLSearchParams();
  params.append('grant_type', 'password');
  params.append('passcode', passcode);

  const prepared = auth
    ? await prepareTokenRequest(
        {
          endpoint: tokenUrl,
          clientId,
          grantType: 'password',
          parameters: params,
          headers: { Accept: 'application/json' },
        },
        auth,
      )
    : undefined;

  logger?.info('[UAA] Exchanging passcode for token', {
    tokenUrl: prepared?.config.url ?? tokenUrl,
  });

  // Today's request: Basic `id:secret` — a public client, `cf` among them,
  // authenticates with an empty secret — built only through legacyBasic, so
  // its secrets join every redaction of the answer.
  const basic = prepared
    ? undefined
    : legacyBasic(clientId, clientSecret ?? '');
  const sendAsToday = () =>
    axios.post(tokenUrl, params.toString(), {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
        ...(basic ? { Authorization: basic.header } : {}),
      },
      // A redirect would re-send the passcode and the secret: never followed.
      maxRedirects: 0,
    });

  let response: AxiosResponse<{
    access_token?: string;
    refresh_token?: string;
    expires_in?: number;
  }>;
  try {
    response = await sendTokenRequest(
      prepared,
      sendAsToday,
      [clientSecret, ...grantSecrets(params)],
      basic,
    );
  } catch (error) {
    // UAA says why in the body — "Invalid passcode" for a mistyped or
    // already spent code — which is what the user needs to read.
    if (axios.isAxiosError(error) && error.response) {
      // Only `error` and `error_description`, with the passcode, the
      // secret and what the strategy sent redacted: a server may echo them.
      throw tokenEndpointError(
        'Passcode exchange failed',
        error,
        requestSecrets([passcode, clientSecret], basic, prepared),
      );
    }
    throw error;
  }
  const data = response.data;
  if (!data?.access_token) {
    throw new Error('Passcode exchange returned no access_token');
  }
  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    expiresIn: data.expires_in,
  };
}
