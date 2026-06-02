/**
 * Browser authentication - OAuth2 flow for obtaining tokens
 */

import * as child_process from 'node:child_process';
import * as http from 'node:http';
import * as net from 'node:net';
import * as readline from 'node:readline';
import type { IAuthorizationConfig, ILogger } from '@mcp-abap-adt/interfaces';
import axios from 'axios';
import express from 'express';

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
 * Get OAuth2 authorization URL
 */
function getJwtAuthorizationUrl(
  authConfig: IAuthorizationConfig,
  port: number = 3001,
): string {
  const oauthUrl = authConfig.uaaUrl;
  const clientid = authConfig.uaaClientId;
  const redirectUri = `http://localhost:${port}/callback`;

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
  port: number = 3001,
  log?: ILogger | null,
): Promise<{ accessToken: string; refreshToken?: string }> {
  const {
    uaaUrl: url,
    uaaClientId: clientid,
    uaaClientSecret: clientsecret,
  } = authConfig;
  const tokenUrl = `${url}/oauth/token`;
  const redirectUri = `http://localhost:${port}/callback`;

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
 */
export async function startBrowserAuth(
  authConfig: BrowserAuthConfig,
  browser: string = 'system',
  logger?: ILogger,
  port: number = 3001,
): Promise<{ accessToken: string; refreshToken?: string }> {
  // Use logger if provided, otherwise null (no logging)
  const log: ILogger | null = logger || null;

  // Essential, user-facing prompts (the auth URL, paste instructions) must be
  // visible even when no logger is supplied. Fall back to stderr — never stdout,
  // so stdio-based RPC transports (MCP/LSP) are not corrupted.
  const announce = (msg: string) => {
    if (log) log.info(msg);
    else process.stderr.write(`${msg}\n`);
  };

  // Check if requested port is available, throw error if not
  const portAvailable = await isPortAvailable(port);
  if (!portAvailable) {
    throw new Error(
      `Port ${port} is already in use. Please specify a different port or free the port.`,
    );
  }

  return new Promise((originalResolve, originalReject) => {
    let timeoutId: NodeJS.Timeout | null = null;
    let finishTimeoutId: NodeJS.Timeout | null = null;
    let cleanupDone = false;
    let resolved = false;
    // Optional stdin reader for the manual paste channel (none/headless + TTY).
    let stdinReader: readline.Interface | null = null;
    const stopStdin = () => {
      if (stdinReader) {
        stdinReader.close();
        stdinReader = null;
      }
    };

    const app = express();
    const server = http.createServer(app);
    // Disable keep-alive to ensure connections close immediately
    server.keepAliveTimeout = 0;
    server.headersTimeout = 0;
    const PORT = port;
    let serverInstance: http.Server | null = null;

    // Cleanup function to ensure server is closed on process termination
    const cleanup = () => {
      if (cleanupDone) return;
      cleanupDone = true;
      log?.debug(`Cleaning up OAuth callback server on port ${PORT}`);
      if (timeoutId) {
        clearTimeout(timeoutId);
        timeoutId = null;
      }
      if (finishTimeoutId) {
        clearTimeout(finishTimeoutId);
        finishTimeoutId = null;
      }
      stopStdin();
      if (server) {
        try {
          if (typeof server.closeAllConnections === 'function') {
            server.closeAllConnections();
          }
          server.close(() => {
            log?.debug(
              `OAuth server closed during cleanup, port ${PORT} freed`,
            );
          });
        } catch (_e) {
          // Ignore errors during cleanup
        }
      }
    };

    // Remove cleanup listeners to prevent memory leaks
    const removeCleanupListeners = () => {
      process.removeListener('exit', cleanup);
      process.removeListener('SIGTERM', cleanup);
      process.removeListener('SIGINT', cleanup);
      process.removeListener('SIGHUP', cleanup);
      if (process.platform === 'win32') {
        process.removeListener('SIGBREAK', cleanup);
      }
    };

    const resolve = (value: { accessToken: string; refreshToken?: string }) => {
      if (resolved) return; // Prevent double resolution
      resolved = true;
      if (timeoutId) {
        clearTimeout(timeoutId);
        timeoutId = null;
      }
      if (finishTimeoutId) {
        clearTimeout(finishTimeoutId);
        finishTimeoutId = null;
      }
      stopStdin();
      removeCleanupListeners();
      originalResolve(value);
    };

    const reject = (reason: unknown) => {
      if (timeoutId) clearTimeout(timeoutId);
      removeCleanupListeners();
      originalReject(reason);
    };

    // Register cleanup handlers for process termination
    // This ensures port is freed when Cline or other clients kill the process
    process.once('exit', cleanup);
    process.once('SIGTERM', cleanup);
    process.once('SIGINT', cleanup);
    process.once('SIGHUP', cleanup);
    // SIGBREAK is Windows-specific (Ctrl+Break)
    if (process.platform === 'win32') {
      process.once('SIGBREAK', cleanup);
    }

    // Use provided authorization URL or build from authConfig
    const authorizationUrl =
      authConfig.authorizationUrl ?? getJwtAuthorizationUrl(authConfig, PORT);

    log?.info(`[browserAuth] Authorization URL: ${authorizationUrl}`);
    log?.info(`[browserAuth] Server listening on port: ${PORT}`);

    // Verify port in redirect_uri matches server port
    const redirectUriMatch = authorizationUrl.match(/redirect_uri=([^&]+)/);
    if (redirectUriMatch) {
      const redirectUri = decodeURIComponent(redirectUriMatch[1]);
      const urlPortMatch = redirectUri.match(/localhost:(\d+)/);
      if (urlPortMatch) {
        const urlPort = parseInt(urlPortMatch[1], 10);
        if (urlPort !== PORT) {
          log?.warn(
            `[browserAuth] WARNING: Port mismatch! URL has port ${urlPort}, but server listens on ${PORT}`,
          );
        } else {
          log?.info(
            `[browserAuth] Port match: URL and server both use port ${PORT}`,
          );
        }
      }
    }

    // Success page shown in the browser after a code is exchanged for tokens.
    const successHtml = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SAP BTP Authentication</title>
<style>body{font-family:'Segoe UI',Tahoma,sans-serif;text-align:center;padding:50px 20px;background:linear-gradient(135deg,#0070f3,#00d4ff);color:#fff;min-height:100vh;display:flex;flex-direction:column;justify-content:center;align-items:center}.container{background:rgba(255,255,255,.1);border-radius:20px;padding:40px;max-width:500px}.success-icon{font-size:4rem;margin-bottom:20px;color:#4ade80}h1{font-weight:300}</style>
</head><body><div class="container"><div class="success-icon">✓</div>
<h1>Authentication Successful!</h1>
<p>You have successfully authenticated with SAP BTP. You can close this window.</p>
</div></body></html>`;

    // Manual paste form (GET /). Used when the automatic localhost callback
    // cannot reach this server (browser on another machine). Accepts a bare
    // code or a full redirected URL; re-renders with a message on a bad paste.
    const pasteFormHtml = (message?: string) => `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SAP BTP Authentication — paste code</title>
<style>body{font-family:'Segoe UI',Tahoma,sans-serif;text-align:center;padding:50px 20px;background:linear-gradient(135deg,#0070f3,#00d4ff);color:#fff;min-height:100vh;display:flex;flex-direction:column;justify-content:center;align-items:center}.container{background:rgba(255,255,255,.1);border-radius:20px;padding:40px;max-width:560px;width:100%}h1{font-weight:300}input{width:100%;padding:12px;border-radius:8px;border:none;font-size:1rem;box-sizing:border-box;margin:14px 0}button{padding:12px 24px;border-radius:8px;border:none;background:#fff;color:#0070f3;font-size:1rem;cursor:pointer}.msg{color:#fde68a;margin-bottom:10px}</style>
</head><body><div class="container">
<h1>Paste authorization code</h1>
${message ? `<p class="msg">${message}</p>` : ''}
<p>After signing in, copy the <code>code</code> from your browser's address bar
(or paste the whole redirected URL) and submit it here.</p>
<form action="/submit" method="get">
<input name="input" autofocus placeholder="code=... or http://localhost/callback?code=..." />
<button type="submit">Submit</button>
</form></div></body></html>`;

    // Resolve the outer promise once a code has been turned into tokens.
    const finalizeSuccess = (
      tokens: { accessToken: string; refreshToken?: string },
      res?: express.Response,
    ) => {
      let serverClosing = false;
      const closeServerAndResolve = () => {
        if (serverClosing) return;
        serverClosing = true;
        if (finishTimeoutId) {
          clearTimeout(finishTimeoutId);
          finishTimeoutId = null;
        }
        if (typeof server.closeAllConnections === 'function') {
          server.closeAllConnections();
        }
        server.close(() => {
          log?.info(`[browserAuth] Server closed, port ${PORT} freed`);
          resolve({
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken,
          });
        });
      };
      if (res) {
        res.send(successHtml);
        res.once('finish', closeServerAndResolve);
        // Fallback if the finish event doesn't fire promptly.
        finishTimeoutId = setTimeout(closeServerAndResolve, 1000);
      } else {
        closeServerAndResolve();
      }
    };

    // Exchange a code for tokens and resolve. Throws on exchange failure so the
    // caller decides: reject (auto callback) or keep waiting (manual paste).
    const completeWithCode = async (
      code: string,
      res?: express.Response,
    ): Promise<void> => {
      if (resolved) return;
      log?.info(`[browserAuth] Exchanging code for token...`);
      const tokens = await exchangeCodeForToken(authConfig, code, PORT, log);
      log?.info(
        `[browserAuth] Tokens received: accessToken(${tokens.accessToken?.length || 0} chars), refreshToken(${tokens.refreshToken?.length || 0} chars)`,
      );
      finalizeSuccess(tokens, res);
    };

    // OAuth2 callback handler
    app.get(
      '/callback',
      async (req: express.Request, res: express.Response) => {
        try {
          log?.info(`[browserAuth] Callback received: ${req.url}`);
          log?.debug(`Callback query: ${JSON.stringify(req.query)}`);

          // Check for OAuth2 error parameters
          const { error, error_description, error_uri } = req.query;
          if (error) {
            log?.error(
              `Callback error: ${error}${error_description ? ` - ${error_description}` : ''}`,
            );
            const errorMsg = error_description
              ? `${error}: ${error_description}`
              : String(error);
            const errorHtml = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authentication Error</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            text-align: center;
            margin: 0;
            padding: 50px 20px;
            background: linear-gradient(135deg, #dc2626 0%, #ef4444 100%);
            color: white;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
        }
        .container {
            background: rgba(255, 255, 255, 0.1);
            border-radius: 20px;
            padding: 40px;
            backdrop-filter: blur(10px);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
            max-width: 500px;
            width: 100%;
        }
        .error-icon {
            font-size: 4rem;
            margin-bottom: 20px;
            color: #fbbf24;
            text-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
        }
        h1 {
            margin: 0 0 20px 0;
            font-size: 2rem;
            font-weight: 300;
        }
        p {
            margin: 0;
            font-size: 1.1rem;
            opacity: 0.9;
            line-height: 1.5;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="error-icon">✗</div>
        <h1>Authentication Failed</h1>
        <p>${errorMsg}</p>
        <p>Please check your service key configuration and try again.</p>
    </div>
</body>
</html>`;
            res.status(400).send(errorHtml);
            if (typeof server.closeAllConnections === 'function') {
              server.closeAllConnections();
            }
            server.close(() => {
              // Server closed on error
            });
            return reject(
              new Error(
                `OAuth2 authentication failed: ${errorMsg}${error_uri ? ` (${error_uri})` : ''}`,
              ),
            );
          }

          const { code } = req.query;
          log?.info(
            `[browserAuth] Callback code received: ${code ? 'yes' : 'no'}`,
          );
          log?.debug(`Callback code received: ${code ? 'yes' : 'no'}`);

          if (!code || typeof code !== 'string') {
            log?.error(`[browserAuth] Callback code missing`);
            res.status(400).send('Error: Authorization code missing');
            return reject(new Error('Authorization code missing'));
          }

          // Exchange code for tokens; on failure the auto-callback path rejects.
          try {
            await completeWithCode(code, res);
          } catch (error) {
            if (typeof server.closeAllConnections === 'function') {
              server.closeAllConnections();
            }
            // Use setTimeout to ensure connections are closed before server.close()
            setTimeout(() => {
              server.close(() => {
                log?.debug(
                  `Server closed on error, port ${PORT} should be freed`,
                );
              });
            }, 100);
            reject(error);
          }
        } catch (error) {
          res.status(500).send('Error processing authentication');
          if (typeof server.closeAllConnections === 'function') {
            server.closeAllConnections();
          }
          // Use setTimeout to ensure connections are closed before server.close()
          setTimeout(() => {
            server.close(() => {
              // Server closed on error - port should be freed
              log?.debug(
                `Server closed on error, port ${PORT} should be freed`,
              );
            });
          }, 100);
          reject(error);
        }
      },
    );

    // Manual paste form (served on the same already-listening server).
    app.get('/', (_req: express.Request, res: express.Response) => {
      res.send(pasteFormHtml());
    });

    // Manual paste submit: accept a bare code or a full redirected URL.
    app.get('/submit', async (req: express.Request, res: express.Response) => {
      const raw = req.query.input ?? req.query.code;
      const code = typeof raw === 'string' ? extractCode(raw) : null;
      if (!code) {
        res
          .status(400)
          .send(
            pasteFormHtml(
              'Could not read an authorization code from that input. Try again.',
            ),
          );
        return;
      }
      try {
        await completeWithCode(code, res);
      } catch (error) {
        // Recoverable: a wrong/expired code shouldn't end the whole flow.
        log?.warn(
          `[browserAuth] Manual code exchange failed: ${error instanceof Error ? error.message : String(error)}`,
        );
        res
          .status(400)
          .send(
            pasteFormHtml(
              'Code exchange failed. Check the code and try again.',
            ),
          );
      }
    });

    // Handle server errors (e.g., EADDRINUSE)
    server.on('error', (error: NodeJS.ErrnoException) => {
      if (error.code === 'EADDRINUSE') {
        log?.error(
          `Port ${PORT} is already in use. This should not happen after port check.`,
        );
        reject(
          new Error(
            `Port ${PORT} is already in use. Please try again or specify a different port.`,
          ),
        );
      } else {
        log?.error(`Server error: ${error.message}`);
        reject(error);
      }
    });

    serverInstance = server.listen(PORT, async () => {
      log?.info(`[browserAuth] Server started on port ${PORT}`);
      const browserApp = BROWSER_MAP[browser];

      // Handle 'none' and 'headless' modes - show URL and wait for the code
      // (for SSH/remote sessions or when no browser should be opened).
      // Use announce() so the URL is visible even without a logger.
      if (browser === 'none' || browser === 'headless') {
        announce(`🔗 Open this URL in your browser to authenticate:`);
        announce(`   ${authorizationUrl}`);
        announce(
          `   Waiting for callback on http://localhost:${PORT}/callback ...`,
        );
        announce(
          `   If your browser is on another machine, after login copy the ` +
            `\`code\` from the address bar and paste it at ` +
            `http://<this-host>:${PORT}/ — or paste it here and press Enter.`,
        );

        // Manual stdin paste — only when attached to an interactive terminal.
        // Under a stdio RPC transport stdin carries the protocol, so we must
        // never consume it; isTTY guards that.
        if (process.stdin.isTTY) {
          stdinReader = readline.createInterface({ input: process.stdin });
          stdinReader.on('line', async (line: string) => {
            const code = extractCode(line);
            if (!code) {
              process.stderr.write(
                'Could not read an authorization code from that input. Try again.\n',
              );
              return;
            }
            try {
              await completeWithCode(code);
            } catch (error) {
              process.stderr.write(
                `Code exchange failed: ${error instanceof Error ? error.message : String(error)}. Try again.\n`,
              );
            }
          });
        }
        // Don't open browser, don't reject - just wait for callback or paste.
        return;
      }

      // Handle 'auto' mode - try to open browser, fallback to showing URL
      if (browser === 'auto') {
        log?.info('🌐 Attempting to open browser for authentication...');
        try {
          const openModule = await import('open');
          const open = openModule.default;
          await open(authorizationUrl);
          log?.info(
            '✅ Browser opened successfully. Waiting for authentication...',
          );
          return;
        } catch (error: unknown) {
          // If browser cannot be opened, show URL and wait
          const errorMessage =
            error instanceof Error ? error.message : String(error);
          log?.warn(`⚠️  Could not open browser automatically: ${errorMessage}`);
          announce(`🔗 Please open this URL in your browser to authenticate:`);
          announce(`   ${authorizationUrl}`);
          announce(
            `   Waiting for callback on http://localhost:${PORT}/callback ...`,
          );
          // Don't reject - wait for callback
          return;
        }
      }

      // Handle browser opening (system, chrome, edge, firefox)
      if (browser && browserApp !== null) {
        log?.debug('🌐 Opening browser for authentication...');

        // On Linux, ensure DISPLAY is set for X11 applications
        // This helps when running from terminals that don't set DISPLAY automatically
        if (
          process.platform === 'linux' &&
          !process.env.DISPLAY &&
          !process.env.WAYLAND_DISPLAY
        ) {
          process.env.DISPLAY = ':0';
          log?.debug('DISPLAY not set, using fallback DISPLAY=:0');
        }

        try {
          // Try dynamic import first (for ES modules)
          let open: typeof import('open').default;
          try {
            const openModule = await import('open');
            open = openModule.default;
          } catch (_importError: unknown) {
            // Fallback: use child_process to open browser if import fails
            // This works in both CommonJS and ES module environments (like Jest)
            const platform = process.platform;
            let command: string;

            if (browserApp === 'chrome') {
              command =
                platform === 'win32'
                  ? 'cmd /c start "" "chrome"'
                  : platform === 'darwin'
                    ? 'open -a "Google Chrome"'
                    : 'google-chrome || google-chrome-stable || chromium || chromium-browser';
            } else if (browserApp === 'edge') {
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
              // System default
              command =
                platform === 'win32'
                  ? 'cmd /c start ""'
                  : platform === 'darwin'
                    ? 'open'
                    : 'xdg-open';
            }

            // Use child_process as fallback (non-blocking)
            child_process.exec(`${command} "${authorizationUrl}"`, (error) => {
              if (error) {
                log?.error(
                  `❌ Failed to open browser: ${error.message}. Please open manually: ${authorizationUrl}`,
                  { error: error.message, url: authorizationUrl },
                );
              }
            });
            return; // Exit early since we're using child_process (non-blocking)
          }

          // Use open module if import succeeded
          if (browserApp) {
            await open(authorizationUrl, { app: { name: browserApp } });
          } else {
            await open(authorizationUrl);
          }
        } catch (error: unknown) {
          // If browser cannot be opened, close server and show URL
          if (typeof server.closeAllConnections === 'function') {
            server.closeAllConnections();
          }
          // Use setTimeout to ensure connections are closed before server.close()
          setTimeout(() => {
            server.close(() => {
              // Server closed on browser open error - port should be freed
              log?.debug(
                `Server closed on browser open error, port ${PORT} should be freed`,
              );
            });
          }, 100);
          const errorMessage =
            error instanceof Error ? error.message : String(error);
          log?.error(
            `❌ Failed to open browser: ${errorMessage}. Please open manually: ${authorizationUrl}`,
            { error: errorMessage, url: authorizationUrl },
          );
          log?.info(`🔗 Open in browser: ${authorizationUrl}`, {
            url: authorizationUrl,
          });
          // Throw error so consumer can distinguish this from "service key missing" error
          reject(
            new Error(
              `Browser opening failed for destination authentication. Please open manually: ${authorizationUrl}`,
            ),
          );
        }
      }
    });

    // Timeout after 30 seconds to prevent blocking consumer
    timeoutId = setTimeout(
      () => {
        if (serverInstance) {
          if (typeof server.closeAllConnections === 'function') {
            server.closeAllConnections();
          }
          // Use setTimeout to ensure connections are closed before server.close()
          setTimeout(() => {
            server.close(() => {
              // Server closed on timeout - port should be freed
              log?.debug(
                `Server closed on timeout, port ${PORT} should be freed`,
              );
            });
          }, 100);
          reject(
            new Error(
              'Authentication timeout after 30 seconds. Please try again.',
            ),
          );
        }
      },
      30 * 1000, // 30 seconds
    );
  });
}
