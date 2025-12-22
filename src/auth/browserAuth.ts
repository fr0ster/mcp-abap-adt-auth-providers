/**
 * Browser authentication - OAuth2 flow for obtaining tokens
 */

import * as child_process from 'node:child_process';
import * as http from 'node:http';
import * as net from 'node:net';
import type { IAuthorizationConfig, ILogger } from '@mcp-abap-adt/interfaces';
import axios from 'axios';
import express from 'express';

const BROWSER_MAP: Record<string, string | undefined | null> = {
  chrome: 'chrome',
  edge: 'msedge',
  firefox: 'firefox',
  system: undefined, // system default
  headless: null, // no browser, log URL and wait for callback (SSH/remote)
  none: null, // no browser, reject immediately (automated tests)
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
 * Find an available port starting from the given port
 * Tries ports in range [startPort, startPort + maxAttempts)
 */
async function findAvailablePort(
  startPort: number,
  maxAttempts: number = 10,
): Promise<number> {
  for (let i = 0; i < maxAttempts; i++) {
    const port = startPort + i;
    if (await isPortAvailable(port)) {
      return port;
    }
  }
  throw new Error(
    `No available port found in range ${startPort}-${startPort + maxAttempts - 1}`,
  );
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
  authConfig: IAuthorizationConfig,
  browser: string = 'system',
  logger?: ILogger,
  port: number = 3001,
): Promise<{ accessToken: string; refreshToken?: string }> {
  // Use logger if provided, otherwise null (no logging)
  const log: ILogger | null = logger || null;

  // Find available port (try starting from requested port, then try next ports)
  let actualPort: number;
  try {
    actualPort = await findAvailablePort(port, 10);
    if (actualPort !== port) {
      log?.debug(`Port ${port} is in use, using port ${actualPort} instead`);
    }
  } catch (error) {
    throw new Error(
      `Failed to find available port starting from ${port}: ${error instanceof Error ? error.message : String(error)}`,
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
    const PORT = actualPort;
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

    const authorizationUrl = getJwtAuthorizationUrl(authConfig, PORT);

    // OAuth2 callback handler
    app.get(
      '/callback',
      async (req: express.Request, res: express.Response) => {
        try {
          log?.info(`Callback received: ${req.url}`);
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
          log?.debug(`Callback code received: ${code ? 'yes' : 'no'}`);

          if (!code || typeof code !== 'string') {
            log?.error(`Callback code missing`);
            res.status(400).send('Error: Authorization code missing');
            return reject(new Error('Authorization code missing'));
          }

          log?.debug(`Exchanging code for token`);

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

          // Send success page first and ensure response is finished
          res.send(html);

          // Wait for response to finish before closing server
          res.on('finish', () => {
            // Response finished, now we can safely close server
          });

          // Exchange code for tokens and close server
          try {
            const tokens = await exchangeCodeForToken(
              authConfig,
              code,
              PORT,
              log,
            );
            log?.info(
              `Tokens received: accessToken(${tokens.accessToken?.length || 0} chars), refreshToken(${tokens.refreshToken?.length || 0} chars)`,
            );

            // Close all connections first to ensure port is freed
            if (typeof server.closeAllConnections === 'function') {
              server.closeAllConnections();
            }

            // Close server after response is finished
            // This ensures the response connection is closed before server.close()
            const closeServer = () => {
              server.close(() => {
                // Server closed - port should be freed
                log?.debug(`Server closed, port ${PORT} should be freed`);
              });
            };

            if (res.finished) {
              // Response already finished, close immediately
              closeServer();
            } else {
              // Wait for response to finish
              res.once('finish', closeServer);
            }

            resolve(tokens);
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
      const browserApp = BROWSER_MAP[browser];

      // Handle 'none' mode - reject immediately (for automated tests)
      if (browser === 'none') {
        log?.info(`🔗 Browser authentication URL: ${authorizationUrl}`, {
          url: authorizationUrl,
        });
        if (serverInstance) {
          if (typeof server.closeAllConnections === 'function') {
            server.closeAllConnections();
          }
          setTimeout(() => {
            server.close(() => {
              log?.debug(
                `Server closed (browser=none), port ${PORT} should be freed`,
              );
            });
          }, 100);
        }
        reject(
          new Error(
            `Browser authentication required. Please open this URL manually: ${authorizationUrl}`,
          ),
        );
        return;
      }

      // Handle 'headless' mode - log URL and wait for callback (for SSH/remote sessions)
      if (browser === 'headless') {
        log?.info(
          `🔗 Headless mode: Open this URL in your browser to authenticate:`,
        );
        log?.info(`   ${authorizationUrl}`);
        log?.info(
          `   Waiting for callback on http://localhost:${PORT}/callback ...`,
        );
        // Don't open browser, don't reject - just wait for the callback
        return;
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
