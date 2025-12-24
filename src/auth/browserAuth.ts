/**
 * Browser authentication - OAuth2 flow for obtaining tokens
 */

import * as child_process from 'node:child_process';
import * as http from 'node:http';
import * as net from 'node:net';
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
  auto: undefined, // try to open browser, fallback to showing URL (like cf login)
  headless: null, // no browser, log URL and wait for callback (SSH/remote)
  none: null, // no browser, log URL and wait for callback (same as headless)
};

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

  // Check if requested port is available, throw error if not
  const portAvailable = await isPortAvailable(port);
  if (!portAvailable) {
    throw new Error(
      `Port ${port} is already in use. Please specify a different port or free the port.`,
    );
  }

  return new Promise((originalResolve, originalReject) => {
    let timeoutId: NodeJS.Timeout | null = null;
    let cleanupDone = false;

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
      if (timeoutId) clearTimeout(timeoutId);
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

          log?.info(`[browserAuth] Exchanging code for token...`);

          // Send success page
          const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SAP BTP Authentication</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            text-align: center;
            margin: 0;
            padding: 50px 20px;
            background: linear-gradient(135deg, #0070f3 0%, #00d4ff 100%);
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
        .success-icon {
            font-size: 4rem;
            margin-bottom: 20px;
            color: #4ade80;
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
        <div class="success-icon">✓</div>
        <h1>Authentication Successful!</h1>
        <p>You have successfully authenticated with SAP BTP.</p>
        <p>You can now close this browser window.</p>
    </div>
</body>
</html>`;

          // Exchange code for tokens first
          try {
            log?.info(`[browserAuth] Starting token exchange...`);
            const tokens = await exchangeCodeForToken(
              authConfig,
              code,
              PORT,
              log,
            );
            log?.info(
              `[browserAuth] Tokens received: accessToken(${tokens.accessToken?.length || 0} chars), refreshToken(${tokens.refreshToken?.length || 0} chars)`,
            );

            // Resolve promise FIRST - this allows test to continue immediately
            log?.info(`[browserAuth] Resolving promise with tokens...`);
            resolve(tokens);
            log?.info(`[browserAuth] Promise resolved, sending response...`);

            // Send success page (non-blocking, doesn't affect promise)
            res.send(html);
            log?.info(`[browserAuth] Response sent, waiting for finish...`);

            // Close all connections and server after response is sent
            res.once('finish', () => {
              log?.info(`[browserAuth] Response finished, closing server...`);
              if (typeof server.closeAllConnections === 'function') {
                server.closeAllConnections();
              }
              server.close(() => {
                // Server closed - port should be freed
                log?.info(
                  `[browserAuth] Server closed, port ${PORT} should be freed`,
                );
              });
            });
          } catch (error) {
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

      // Handle 'none' and 'headless' modes - log URL and wait for callback
      // (for SSH/remote sessions or when browser should not be opened)
      if (browser === 'none' || browser === 'headless') {
        log?.info(`🔗 Open this URL in your browser to authenticate:`);
        log?.info(`   ${authorizationUrl}`);
        log?.info(
          `   Waiting for callback on http://localhost:${PORT}/callback ...`,
        );
        // Don't open browser, don't reject - just wait for the callback
        return;
      }

      // Handle 'auto' mode - try to open browser, fallback to showing URL (like cf login)
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
          // If browser cannot be opened, show URL and wait (like cf login)
          const errorMessage =
            error instanceof Error ? error.message : String(error);
          log?.warn(`⚠️  Could not open browser automatically: ${errorMessage}`);
          log?.info(`🔗 Please open this URL in your browser to authenticate:`);
          log?.info(`   ${authorizationUrl}`);
          log?.info(
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

    // Timeout after 5 minutes
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
          reject(new Error('Authentication timeout. Process aborted.'));
        }
      },
      5 * 60 * 1000,
    );
  });
}
