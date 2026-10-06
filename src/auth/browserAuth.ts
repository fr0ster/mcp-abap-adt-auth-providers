/**
 * Browser authentication - OAuth2 flow for obtaining tokens
 */

import * as child_process from 'node:child_process';
import type { IAuthorizationConfig } from '@mcp-abap-adt/interfaces-auth-sap';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import axios from 'axios';
import { loggedError } from './refusal';
import {
  legacyBasic,
  prepareTokenRequest,
  rejectMissingToken,
  sendTokenRequest,
  siteSecrets,
  type TokenRequestAuth,
  type TokenSiteOptions,
  tokenSite,
} from './tokenRequest';

const BROWSER_MAP: Record<string, string | undefined | null> = {
  chrome: 'chrome',
  edge: 'msedge',
  firefox: 'firefox',
  system: undefined, // system default
  auto: undefined, // try to open browser, fallback to showing URL
  headless: null, // no browser, log URL and wait for callback (SSH/remote)
  none: null, // no browser, log URL and wait for callback (same as headless)
};

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

  // Anywhere a `code=` query parameter appears (full URL or query string):
  // the first `?code=` / `&code=` followed by at least one character up to
  // `&` or whitespace. Plain string scanning, no regex (pasted input).
  for (let at = 0; at < trimmed.length; at++) {
    const mark = trimmed[at];
    if (mark !== '?' && mark !== '&') continue;
    if (!trimmed.startsWith('code=', at + 1)) continue;
    const value = valueUntilBreak(trimmed, at + 6);
    if (value !== '') return decodeURIComponent(value);
  }

  // Bare `code=XYZ`
  if (trimmed.startsWith('code=')) {
    const value = valueUntilBreak(trimmed, 5);
    if (value !== '' && 5 + value.length === trimmed.length) {
      return decodeURIComponent(value);
    }
  }

  // Otherwise treat the whole token as the code, but reject anything with
  // whitespace (clearly not a single code).
  if ([...trimmed].some(isWhitespace)) return null;
  return trimmed;
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
 * Build the OAuth2 authorization URL for a redirect URI that is already known.
 *
 * The URI is a parameter rather than a port because the port may have been
 * chosen by the OS moments earlier — see `ICallbackServerOptions.port`.
 */
export function getJwtAuthorizationUrl(
  authConfig: IAuthorizationConfig,
  redirectUri: string,
): string {
  const oauthUrl = authConfig.uaaUrl;
  const clientid = authConfig.uaaClientId;

  if (!oauthUrl || !clientid) {
    throw new Error('Authorization config missing UAA URL or client ID');
  }

  return `${oauthUrl}/oauth/authorize?client_id=${encodeURIComponent(clientid)}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code`;
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
  const sendAsToday = () =>
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
    });

  log?.info(`Exchanging code for token: ${prepared?.config.url ?? tokenUrl}`);

  const site = tokenSite(
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
  log?.info(
    `Tokens received: accessToken(${accessToken.length} chars), refreshToken(${refreshToken?.length || 0} chars)`,
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

/**
 * Open the authorization URL, or tell the user how to do it.
 *
 * Never awaited on the critical path by the caller: a launcher that hangs must
 * not delay the login timeout or the release of the port. A launcher that fails
 * is reported through the scope's `fail`, which is just another way for the
 * scope to end.
 */
export async function launchBrowser(
  authorizationUrl: string,
  browser: string,
  callbackUri: string,
  announce: (msg: string) => void,
  log: ILogger | null,
  /**
   * Extra guidance for 'none'/'headless', supplied only by a flow whose
   * transport really offers another way in. The UAA callback server has a paste
   * form on `/`; the OIDC and SAML ones do not, and promising one there sends
   * the user to a 404.
   */
  remoteHint?: string,
): Promise<void> {
  const browserApp = BROWSER_MAP[browser];

  // 'none' / 'headless': show the URL and wait. For SSH and remote sessions.
  if (browser === 'none' || browser === 'headless') {
    announce('🔗 Open this URL in your browser to authenticate:');
    announce(`   ${authorizationUrl}`);
    announce(`   Waiting for callback on ${callbackUri} ...`);
    if (remoteHint) announce(remoteHint);
    return;
  }

  if (browser === 'auto') {
    log?.info('🌐 Attempting to open browser for authentication...');
    try {
      const openModule = await import('open');
      await openModule.default(authorizationUrl);
      log?.info(
        '✅ Browser opened successfully. Waiting for authentication...',
      );
    } catch (error: unknown) {
      // Fixed words only: what `open` threw is not this package's text.
      log?.warn(
        `⚠️  Could not open browser automatically: ${loggedError(error, 'opening the browser').error}`,
      );
      announce('🔗 Please open this URL in your browser to authenticate:');
      announce(`   ${authorizationUrl}`);
      announce(`   Waiting for callback on ${callbackUri} ...`);
    }
    return;
  }

  if (browserApp === null) return;

  // On Linux, ensure DISPLAY is set for X11 applications.
  if (
    process.platform === 'linux' &&
    !process.env.DISPLAY &&
    !process.env.WAYLAND_DISPLAY
  ) {
    process.env.DISPLAY = ':0';
    log?.debug('DISPLAY not set, using fallback DISPLAY=:0');
  }

  type OpenFn = (
    url: string,
    opts?: { app: { name: string | readonly string[] } },
  ) => Promise<unknown>;
  let open: OpenFn | null = null;
  // `open`'s per-platform names for each common browser. An `app.name` is an
  // executable name, and Chrome is no `chrome` on Linux (`google-chrome`,
  // `google-chrome-stable`, …): handing `open` the bare name failed with ENOENT.
  let appNames: Partial<Record<string, string | readonly string[]>> = {};
  try {
    const openModule = await import('open');
    open = openModule.default;
    const apps = (openModule as { apps?: Record<string, string | string[]> })
      .apps;
    if (apps)
      appNames = {
        chrome: apps.chrome,
        msedge: apps.edge,
        firefox: apps.firefox,
      };
  } catch {
    open = null;
  }

  if (!open) {
    // Fallback: shell out. Non-blocking by design.
    const platform = process.platform;
    let command: string;
    if (browserApp === 'chrome') {
      command =
        platform === 'win32'
          ? 'cmd /c start "" "chrome"'
          : platform === 'darwin'
            ? 'open -a "Google Chrome"'
            : 'google-chrome || chromium || chromium-browser';
    } else if (browserApp === 'msedge') {
      command =
        platform === 'win32'
          ? 'cmd /c start "" "msedge"'
          : platform === 'darwin'
            ? 'open -a "Microsoft Edge"'
            : 'microsoft-edge || microsoft-edge-stable';
    } else if (browserApp === 'firefox') {
      command =
        platform === 'win32'
          ? 'cmd /c start "" "firefox"'
          : platform === 'darwin'
            ? 'open -a Firefox'
            : 'firefox || firefox-esr';
    } else {
      command =
        platform === 'win32'
          ? 'cmd /c start ""'
          : platform === 'darwin'
            ? 'open'
            : 'xdg-open';
    }
    child_process.exec(`${command} "${authorizationUrl}"`, (error) => {
      if (error) {
        const { error: words } = loggedError(error, 'opening the browser');
        log?.error(
          `❌ Failed to open browser: ${words}. Please open manually: ${authorizationUrl}`,
          { error: words, url: authorizationUrl },
        );
      }
    });
    return;
  }

  if (browserApp)
    await open(authorizationUrl, {
      app: { name: appNames[browserApp] ?? browserApp },
    });
  else await open(authorizationUrl);
}
