/**
 * Browser authentication - OAuth2 flow for obtaining tokens
 */

import type { IAuthorizationConfig } from '@mcp-abap-adt/interfaces-auth-sap';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import axios from 'axios';
import { requiredFieldsMissing } from './configuration';
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

/**
 * Extract an OAuth2 authorization code from arbitrary pasted input.
 *
 * Accepts:
 *  - a bare code: `abc123`
 *  - `code=abc123`
 *  - a full redirected URL: `http://localhost:7779/callback?code=abc123&state=...`
 *
 * Returns the decoded code, or null if nothing usable was found.
 * @internal - Exported for testing and for manual-paste flows.
 */
export function extractCode(input: string): string | null {
  if (!input) return null;
  const trimmed = input.trim();
  if (!trimmed) return null;

  // Anywhere a `code=` query parameter appears (full URL or query string).
  const fromQuery = codeFromQuery(trimmed);
  if (fromQuery !== undefined) return fromQuery;

  // Bare `code=XYZ`
  if (trimmed.startsWith('code=')) {
    const value = valueUntilBreak(trimmed, 5);
    if (value !== '' && 5 + value.length === trimmed.length) {
      return decodedOrNull(value);
    }
  }

  // Otherwise treat the whole token as the code, but reject anything with
  // whitespace (clearly not a single code).
  if ([...trimmed].some(isWhitespace)) return null;
  return trimmed;
}

/**
 * The code of the first `?code=` / `&code=` followed by at least one
 * character up to `&` or whitespace, decoded; `null` for a malformed escape;
 * `undefined` when there is none. Plain string scanning, no regex (pasted
 * input). Given a URL's `search`, it reads the query alone.
 */
export function codeFromQuery(text: string): string | null | undefined {
  for (let at = 0; at < text.length; at++) {
    const mark = text[at];
    if (mark !== '?' && mark !== '&') continue;
    if (!text.startsWith('code=', at + 1)) continue;
    const value = valueUntilBreak(text, at + 6);
    if (value !== '') return decodedOrNull(value);
  }
  return undefined;
}

/**
 * The value percent-decoded, or `null` when it holds a malformed escape
 * (`%ZZ`): pasted or posted text is anyone's, and an unreadable code is K16
 * (`unreadable-input`), never a thrown `URIError`.
 */
function decodedOrNull(value: string): string | null {
  try {
    const decoded = decodeURIComponent(value);
    return decoded === '' ? null : decoded;
  } catch {
    return null;
  }
}

/** Whitespace as `\s` reads it: what `trim()` removes. */
const isWhitespace = (character: string): boolean => character.trim() === '';

/** The characters from `start` up to `&`, whitespace or the end. */
function valueUntilBreak(text: string, start: number): string {
  let end = start;
  while (end < text.length) {
    const character = text[end] ?? '';
    if (character === '&' || isWhitespace(character)) break;
    end++;
  }
  return text.slice(start, end);
}

/**
 * What binds a UAA login to its attempt (spec §6a1): the `state` the
 * callback must carry and the PKCE challenge (S256) of the verifier its
 * exchange sends. Minted per URL by the provider; never logged.
 */
export interface AuthorizationBinding {
  readonly state: string;
  readonly codeChallenge: string;
}

/**
 * Build the OAuth2 authorization URL for a redirect URI that is already known.
 *
 * The URI is a parameter rather than a port because the port may have been
 * chosen by the OS moments earlier — see `ICallbackServerOptions.port`.
 * With a `binding`, the URL carries its `state`, `code_challenge` and
 * `code_challenge_method=S256`.
 */
export function getJwtAuthorizationUrl(
  authConfig: IAuthorizationConfig,
  redirectUri: string,
  binding?: AuthorizationBinding,
): string {
  const oauthUrl = authConfig.uaaUrl;
  const clientid = authConfig.uaaClientId;

  if (!oauthUrl || !clientid) {
    // E22: the names of what is missing.
    throw requiredFieldsMissing([
      ...(oauthUrl ? [] : ['uaaUrl']),
      ...(clientid ? [] : ['clientId']),
    ]);
  }

  const bound = binding
    ? `&state=${encodeURIComponent(binding.state)}&code_challenge=${encodeURIComponent(binding.codeChallenge)}&code_challenge_method=S256`
    : '';
  return `${oauthUrl}/oauth/authorize?client_id=${encodeURIComponent(clientid)}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code${bound}`;
}

/**
 * Exchange authorization code for tokens
 * @internal - Exported for testing
 */
export async function exchangeCodeForToken(
  authConfig: IAuthorizationConfig,
  code: string,
  redirectUri: string,
  log?: ILogger | null,
  auth?: TokenRequestAuth,
  options?: TokenSiteOptions,
  /** The PKCE verifier of the URL this code answers; none for a code the consumer brought. */
  codeVerifier?: string,
): Promise<{ accessToken: string; refreshToken?: string | undefined }> {
  const {
    uaaUrl: url,
    uaaClientId: clientid,
    uaaClientSecret: clientsecret,
  } = authConfig;
  const tokenUrl = `${url}/oauth/token`;

  const params = new URLSearchParams();
  params.append('grant_type', 'authorization_code');
  params.append('code', code);
  params.append('redirect_uri', redirectUri);
  if (codeVerifier !== undefined) params.append('code_verifier', codeVerifier);

  const prepared = auth
    ? await prepareTokenRequest(
        {
          endpoint: tokenUrl,
          clientId: clientid,
          grantType: 'authorization_code',
          parameters: params,
        },
        auth,
      )
    : undefined;

  // Today's request: Basic `id:secret` — an absent secret sent as it always
  // was, the word in a template — built only through legacyBasic, so its
  // secrets are named in the `authDebug` line's `sent`.
  const basic = prepared ? undefined : legacyBasic(clientid, `${clientsecret}`);
  const sendAsToday = (signal: AbortSignal | undefined) =>
    axios({
      method: 'post',
      url: tokenUrl,
      headers: {
        ...(basic ? { Authorization: basic.header } : {}),
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      data: params.toString(),
      // A redirect would re-send the code and the secret: never followed.
      maxRedirects: 0,
      // The attempt's abort cuts the exchange (spec §6b).
      ...(signal === undefined ? {} : { signal }),
    });

  // Every line on the token path is guarded: a logger that throws, or an
  // async one that rejects, changes nothing (logQuietly).
  logQuietly(() => log?.info('Exchanging code for token'));

  const site = attemptSite(
    'code-exchange',
    options,
    log,
    siteSecrets(params, clientsecret),
    basic,
  );
  const response = await sendTokenRequest<{
    access_token?: string;
    refresh_token?: string;
  }>(prepared, sendAsToday, site);

  const accessToken = response.data.access_token;
  if (!accessToken) {
    // 5.4.2's `error` line, the status and a registered code only: the
    // server's own words reach no log line.
    rejectMissingToken(site, prepared, response, 'no-access-token', 'error');
  }
  const refreshToken = response.data.refresh_token;
  logQuietly(() =>
    log?.info(
      `Tokens received: accessToken(${accessToken.length} chars), refreshToken(${refreshToken?.length || 0} chars)`,
    ),
  );
  return {
    accessToken,
    refreshToken,
  };
}

/**
 * Check if debug logging is enabled for auth providers
 */
function _isDebugEnabled(): boolean {
  return (
    process.env.DEBUG_AUTH_PROVIDERS === 'true' ||
    process.env.DEBUG_BROWSER_AUTH === 'true' ||
    process.env.DEBUG === 'true' ||
    process.env.DEBUG?.includes('auth-providers') === true ||
    process.env.DEBUG?.includes('browser-auth') === true
  );
}
