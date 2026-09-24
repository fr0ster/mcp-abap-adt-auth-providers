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

export interface PasscodeTokens {
  accessToken: string;
  refreshToken?: string;
  expiresIn?: number;
}

export async function exchangePasscode(
  uaaUrl: string,
  clientId: string,
  clientSecret: string | undefined,
  passcode: string,
  logger?: ILogger,
): Promise<PasscodeTokens> {
  const tokenUrl = `${uaaUrl.replace(/\/+$/, '')}/oauth/token`;
  const params = new URLSearchParams();
  params.append('grant_type', 'password');
  params.append('passcode', passcode);

  logger?.info('[UAA] Exchanging passcode for token', { tokenUrl });

  // A public client — `cf` is one — authenticates with an empty secret.
  const basic = Buffer.from(`${clientId}:${clientSecret ?? ''}`).toString(
    'base64',
  );
  let response: AxiosResponse<{
    access_token?: string;
    refresh_token?: string;
    expires_in?: number;
  }>;
  try {
    response = await axios.post(tokenUrl, params.toString(), {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
        Authorization: `Basic ${basic}`,
      },
    });
  } catch (error) {
    // UAA says why in the body — "Invalid passcode" for a mistyped or
    // already spent code — which is what the user needs to read.
    if (axios.isAxiosError(error) && error.response) {
      const body = error.response.data as
        | { error?: string; error_description?: string }
        | undefined;
      const reason =
        body?.error_description ?? body?.error ?? 'no reason given';
      throw new Error(
        `Passcode exchange failed (${error.response.status}): ${reason}`,
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
