/**
 * Browser authentication - OAuth2 flow for obtaining tokens
 */

import * as http from 'http';
import * as child_process from 'child_process';
import express from 'express';
import axios from 'axios';
import type { IAuthorizationConfig, ILogger } from '@mcp-abap-adt/interfaces';

const BROWSER_MAP: Record<string, string | undefined> = {
  chrome: 'chrome',
  edge: 'msedge',
  firefox: 'firefox',
  system: undefined, // system default
  none: null as any, // no browser, manual URL copy
};

/**
 * Get OAuth2 authorization URL
 */
function getJwtAuthorizationUrl(authConfig: IAuthorizationConfig, port: number = 3001): string {
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
  log?: ILogger | null
): Promise<{ accessToken: string; refreshToken?: string }> {
  const { uaaUrl: url, uaaClientId: clientid, uaaClientSecret: clientsecret } = authConfig;
  const tokenUrl = `${url}/oauth/token`;
  const redirectUri = `http://localhost:${port}/callback`;

  const params = new URLSearchParams();
  params.append('grant_type', 'authorization_code');
  params.append('code', code);
  params.append('redirect_uri', redirectUri);

  const authString = Buffer.from(`${clientid}:${clientsecret}`).toString('base64');
  
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

  if (response.data && response.data.access_token) {
    const accessToken = response.data.access_token;
    const refreshToken = response.data.refresh_token;
    
    log?.info(`Tokens received: accessToken(${accessToken.length} chars), refreshToken(${refreshToken?.length || 0} chars)`);
    
    return {
      accessToken,
      refreshToken,
    };
  } else {
    log?.error(`Token exchange failed: status ${response.status}, error: ${response.data?.error || 'unknown'}`);
    throw new Error('Response does not contain access_token');
  }
}

/**
 * Check if debug logging is enabled for auth providers
 */
function isDebugEnabled(): boolean {
  return process.env.DEBUG_AUTH_PROVIDERS === 'true' || 
         process.env.DEBUG_BROWSER_AUTH === 'true' ||
         process.env.DEBUG === 'true' ||
         process.env.DEBUG?.includes('auth-providers') === true ||
         process.env.DEBUG?.includes('browser-auth') === true;
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
  port: number = 3001
): Promise<{ accessToken: string; refreshToken?: string }> {
  // Use logger if provided, otherwise null (no logging)
  const log: ILogger | null = logger || null;
  
  return new Promise((originalResolve, originalReject) => {
    let timeoutId: NodeJS.Timeout | null = null;
    
    const resolve = (value: any) => {
      if (timeoutId) clearTimeout(timeoutId);
      originalResolve(value);
    };
    
    const reject = (reason: any) => {
      if (timeoutId) clearTimeout(timeoutId);
      originalReject(reason);
    };
    const app = express();
    const server = http.createServer(app);
    const PORT = port;
    let serverInstance: http.Server | null = null;

    const authorizationUrl = getJwtAuthorizationUrl(authConfig, PORT);

    // OAuth2 callback handler
    app.get('/callback', async (req: express.Request, res: express.Response) => {
      try {
        log?.info(`Callback received: ${req.url}`);
        log?.debug(`Callback query: ${JSON.stringify(req.query)}`);
        
        // Check for OAuth2 error parameters
        const { error, error_description, error_uri } = req.query;
        if (error) {
          log?.error(`Callback error: ${error}${error_description ? ` - ${error_description}` : ''}`);
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
          return reject(new Error(`OAuth2 authentication failed: ${errorMsg}${error_uri ? ` (${error_uri})` : ''}`));
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

        // Send success page first
        res.send(html);
        
        // Exchange code for tokens and close server
        try {
          const tokens = await exchangeCodeForToken(authConfig, code, PORT, log);
          log?.info(`Tokens received: accessToken(${tokens.accessToken?.length || 0} chars), refreshToken(${tokens.refreshToken?.length || 0} chars)`);
          // Close all connections and server immediately after getting tokens
          if (typeof server.closeAllConnections === 'function') {
            server.closeAllConnections();
          }
          server.close(() => {
            // Server closed
          });
          resolve(tokens);
        } catch (error) {
          if (typeof server.closeAllConnections === 'function') {
            server.closeAllConnections();
          }
          server.close(() => {
            // Server closed on error
          });
          reject(error);
        }
      } catch (error) {
        res.status(500).send('Error processing authentication');
        server.close(() => {
          // Server closed on error
        });
        reject(error);
      }
    });

    serverInstance = server.listen(PORT, async () => {
      const browserApp = BROWSER_MAP[browser];
      if (!browser || browser === 'none' || browserApp === null) {
        log?.info(`🔗 Open in browser: ${authorizationUrl}`, { url: authorizationUrl });
        // For 'none' browser, don't wait for callback - throw error immediately
        // User must open browser manually and we can't wait for callback in automated tests
        if (serverInstance) {
          server.close(() => {
            // Server closed
          });
        }
        reject(new Error(`Browser authentication required. Please open this URL manually: ${authorizationUrl}`));
        return;
      } else {
        log?.debug('🌐 Opening browser for authentication...');
        try {
          // Try dynamic import first (for ES modules)
          let open: typeof import('open').default;
          try {
            const openModule = await import('open');
            open = openModule.default;
          } catch (importError: any) {
            // Fallback: use child_process to open browser if import fails
            // This works in both CommonJS and ES module environments (like Jest)
            const platform = process.platform;
            let command: string;
            
            if (browserApp === 'chrome') {
              command = platform === 'win32' 
                ? 'start chrome' 
                : platform === 'darwin' 
                  ? 'open -a "Google Chrome"' 
                  : 'google-chrome';
            } else if (browserApp === 'edge') {
              command = platform === 'win32' 
                ? 'start msedge' 
                : platform === 'darwin' 
                  ? 'open -a "Microsoft Edge"' 
                  : 'microsoft-edge';
            } else if (browserApp === 'firefox') {
              command = platform === 'win32' 
                ? 'start firefox' 
                : platform === 'darwin' 
                  ? 'open -a Firefox' 
                  : 'firefox';
            } else {
              // System default
              command = platform === 'win32' 
                ? 'start' 
                : platform === 'darwin' 
                  ? 'open' 
                  : 'xdg-open';
            }
            
            // Use child_process as fallback (non-blocking)
            child_process.exec(`${command} "${authorizationUrl}"`, (error) => {
              if (error) {
                log?.error(`❌ Failed to open browser: ${error.message}. Please open manually: ${authorizationUrl}`, { error: error.message, url: authorizationUrl });
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
        } catch (error: any) {
          // If browser cannot be opened, show URL and throw error for consumer to catch
          log?.error(`❌ Failed to open browser: ${error?.message || String(error)}. Please open manually: ${authorizationUrl}`, { error: error?.message || String(error), url: authorizationUrl });
          log?.info(`🔗 Open in browser: ${authorizationUrl}`, { url: authorizationUrl });
          // Throw error so consumer can distinguish this from "service key missing" error
          reject(new Error(`Browser opening failed for destination authentication. Please open manually: ${authorizationUrl}`));
        }
      }
    });

    // Timeout after 5 minutes
    timeoutId = setTimeout(() => {
      if (serverInstance) {
        server.close(() => {
          // Server closed on timeout
        });
        reject(new Error('Authentication timeout. Process aborted.'));
      }
    }, 5 * 60 * 1000);
  });
}

