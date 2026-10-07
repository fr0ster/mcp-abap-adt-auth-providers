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
import axios from 'axios';
import {
  attemptSite,
  legacyBasic,
  logQuietly,
  prepareTokenRequest,
  rejectMissingToken,
  sendTokenRequest,
  siteSecrets,
  type TokenRequestAuth,
  type TokenSiteOptions,
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
  options?: TokenSiteOptions,
): Promise<PasscodeTokens> {
  let end = uaaUrl.length;
  while (end > 0 && uaaUrl[end - 1] === '/') end--;
  const tokenUrl = `${uaaUrl.slice(0, end)}/oauth/token`;
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

  logQuietly(() => logger?.info('[UAA] Exchanging passcode for token'));

  // Today's request: Basic `id:secret` — a public client, `cf` among them,
  // authenticates with an empty secret — built only through legacyBasic, so
  // its secrets are named in the `authDebug` line's `sent`.
  const basic = prepared
    ? undefined
    : legacyBasic(clientId, clientSecret ?? '');
  const sendAsToday = (signal: AbortSignal | undefined) =>
    axios.post(tokenUrl, params.toString(), {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
        ...(basic ? { Authorization: basic.header } : {}),
      },
      // A redirect would re-send the passcode and the secret: never followed.
      maxRedirects: 0,
      // The attempt's abort cuts the exchange (spec §6b).
      ...(signal === undefined ? {} : { signal }),
    });

  // UAA says why in the body — "Invalid passcode" for a mistyped or already
  // spent code — which is never read: the failure carries the status and a
  // registered code only (`passcode-exchange`).
  const site = attemptSite(
    'passcode-exchange',
    options,
    logger,
    siteSecrets(params, clientSecret),
    basic,
  );
  const response = await sendTokenRequest<{
    access_token?: string;
    refresh_token?: string;
    expires_in?: number;
  }>(prepared, sendAsToday, site);
  const data = response.data;
  if (!data.access_token) {
    rejectMissingToken(site, prepared, response, 'no-access-token', 'debug');
  }
  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    expiresIn: data.expires_in,
  };
}
