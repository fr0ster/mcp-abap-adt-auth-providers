/**
 * Browser authentication - OAuth2 flow for obtaining tokens
 */

import * as child_process from 'node:child_process';
import * as http from 'node:http';
import * as net from 'node:net';
import * as readline from 'node:readline';
import type { IAuthorizationConfig, ILogger } from '@mcp-abap-adt/interfaces';
import axios from 'axios';
import { withBrowserCallbackServer } from './callbackServer';

type BrowserAuthConfig = IAuthorizationConfig & {
  authorizationUrl?: string;
};

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

  // Anywhere a `code=` query parameter appears (full URL or query string)
  const fromQuery = trimmed.match(/[?&]code=([^&\s]+)/);
  if (fromQuery) return decodeURIComponent(fromQuery[1]);

  // Bare `code=XYZ`
  const bareKv = trimmed.match(/^code=([^&\s]+)$/);
  if (bareKv) return decodeURIComponent(bareKv[1]);

  // Otherwise treat the whole token as the code, but reject anything with
  // whitespace (clearly not a single code).
  if (/\s/.test(trimmed)) return null;
  return trimmed;
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
): Promise<{ accessToken: string; refreshToken?: string }> {
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

  const authString = Buffer.from(`${clientid}:${clientsecret}`).toString(
    'base64',
  );

  log?.info(`Exchanging code for token: ${tokenUrl}`);

  const response = await axios({
    method: 'post',
    url: tokenUrl,
    headers: {
      Authorization: `Basic ${authString}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    data: params.toString(),
  });

  if (response.data?.access_token) {
    const accessToken = response.data.access_token;
    const refreshToken = response.data.refresh_token;

    log?.info(
      `Tokens received: accessToken(${accessToken.length} chars), refreshToken(${refreshToken?.length || 0} chars)`,
    );

    return {
      accessToken,
      refreshToken,
    };
  } else {
    log?.error(
      `Token exchange failed: status ${response.status}, error: ${response.data?.error || 'unknown'}`,
    );
    throw new Error('Response does not contain access_token');
  }
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
 * Check if a port is available
 */
function isPortAvailable(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.listen(port, () => {
      server.once('close', () => resolve(true));
      server.close();
    });
    server.on('error', () => resolve(false));
  });
}

/**
 * Start browser authentication flow
 * @param authConfig Authorization configuration with UAA credentials
 * @param browser Browser name (chrome, edge, firefox, system, none)
 * @param logger Optional logger instance. If not provided, uses default logger.
 * @param port Port for OAuth callback server (default: 3001)
 * @returns Promise that resolves to tokens
 * @internal - Internal function, not exported from package
 *//**
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
      const message = error instanceof Error ? error.message : String(error);
      log?.warn(`⚠️  Could not open browser automatically: ${message}`);
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

  type OpenFn = (url: string, opts?: unknown) => Promise<unknown>;
  let open: OpenFn | null = null;
  try {
    const openModule = await import('open');
    open = openModule.default as unknown as OpenFn;
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
        log?.error(
          `❌ Failed to open browser: ${error.message}. Please open manually: ${authorizationUrl}`,
          { error: error.message, url: authorizationUrl },
        );
      }
    });
    return;
  }

  if (browserApp) await open(authorizationUrl, { app: { name: browserApp } });
  else await open(authorizationUrl);
}

/**
 * Interactive browser login for the UAA authorization-code flow.
 *
 * The callback socket is owned by `withBrowserCallbackServer`: it is released
 * when the scope ends, whatever ends it, and before the code is exchanged — so
 * a slow UAA cannot hold the port, and a settled promise always means the port
 * is free.
 */
export async function startBrowserAuth(
  authConfig: BrowserAuthConfig,
  browser: string = 'system',
  logger?: ILogger,
  port: number = 3001,
  timeoutMs: number = 30 * 1000,
): Promise<{ accessToken: string; refreshToken?: string }> {
  const log: ILogger | null = logger || null;

  // Essential, user-facing prompts (the auth URL, paste instructions) must be
  // visible even when no logger is supplied. Fall back to stderr — never stdout,
  // so stdio-based RPC transports (MCP/LSP) are not corrupted.
  const announce = (msg: string) => {
    if (log) log.info(msg);
    else process.stderr.write(`${msg}\n`);
  };

  // Pre-check kept for its message: AuthBroker matches /already in use/i to
  // distinguish a busy port from other failures.
  const portAvailable = await isPortAvailable(port);
  if (!portAvailable) {
    throw new Error(
      `Port ${port} is already in use. Please specify a different port or free the port.`,
    );
  }

  let stdinReader: readline.Interface | null = null;
  // Captured inside the scope below and reused after it ends, so the
  // authorization request and the token exchange always agree on the same
  // redirect URI — the one the callback server actually bound, not a string
  // rebuilt from a port that could in principle be 0 (OS-assigned).
  let redirectUri = '';

  const code = await withBrowserCallbackServer(
    { port, timeoutMs },
    async (server) => {
      redirectUri = server.redirectUri;
      const authorizationUrl =
        authConfig.authorizationUrl ??
        getJwtAuthorizationUrl(authConfig, redirectUri);

      log?.info(`[browserAuth] Authorization URL: ${authorizationUrl}`);
      log?.info(`[browserAuth] Server listening on port: ${server.port}`);

      const waiting = server.waitForResult();

      // Not awaited: a launcher that hangs must not delay the timeout or the
      // release, and one that fails ends the scope through `fail`.
      void launchBrowser(
        authorizationUrl,
        browser,
        redirectUri,
        announce,
        log,
        '   If your browser is on another machine, after login copy the ' +
          '`code` from the address bar and paste it at ' +
          `http://<this-host>:${server.port}/ — or paste it here and press Enter.`,
      ).catch((error: unknown) => {
        const message = error instanceof Error ? error.message : String(error);
        log?.error(
          `❌ Failed to open browser: ${message}. Please open manually: ${authorizationUrl}`,
          { error: message, url: authorizationUrl },
        );
        server.fail(
          new Error(
            `Browser opening failed for destination authentication. Please open manually: ${authorizationUrl}`,
          ),
        );
      });

      // Manual stdin paste — only when attached to an interactive terminal.
      // Under a stdio RPC transport stdin carries the protocol, so we must never
      // consume it; isTTY guards that. A pasted line is handed to the same
      // `/submit` route the paste form uses, so there is one way in, not two.
      if (
        (browser === 'none' || browser === 'headless') &&
        process.stdin.isTTY
      ) {
        stdinReader = readline.createInterface({ input: process.stdin });
        stdinReader.on('line', (line: string) => {
          const pasted = extractCode(line);
          if (!pasted) {
            process.stderr.write(
              'Could not read an authorization code from that input. Try again.\n',
            );
            return;
          }
          const req = http.get({
            host: '127.0.0.1',
            port: server.port,
            path: `/submit?input=${encodeURIComponent(pasted)}`,
            agent: false,
          });
          req.on('error', () => undefined);
        });
      }

      return await waiting;
    },
  ).finally(() => {
    stdinReader?.close();
    stdinReader = null;
  });

  log?.info('[browserAuth] Exchanging code for token...');
  return await exchangeCodeForToken(authConfig, code, redirectUri, log);
}
