/**
 * OIDC browser authorization code flow (capture code)
 */

import * as http from 'node:http';
import * as net from 'node:net';
import type { ILogger } from '@mcp-abap-adt/interfaces';
import express from 'express';

const BROWSER_MAP: Record<string, string | undefined | null> = {
  chrome: 'chrome',
  edge: 'msedge',
  firefox: 'firefox',
  system: undefined,
  auto: undefined,
  headless: null,
  none: null,
};

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

async function openBrowserUrl(
  authorizationUrl: string,
  browser: string,
  logger?: ILogger,
): Promise<void> {
  const browserApp = BROWSER_MAP[browser];
  if (browserApp === null) {
    logger?.info('[OIDC] Browser suppressed, open URL manually', {
      authorizationUrl,
    });
    return;
  }

  if (browser === 'auto') {
    try {
      const openModule = await import('open');
      const open = openModule.default;
      await open(authorizationUrl);
      logger?.info('[OIDC] Browser opened');
      return;
    } catch (error) {
      logger?.warn('[OIDC] Failed to open browser automatically', {
        error: error instanceof Error ? error.message : String(error),
      });
      logger?.info('[OIDC] Open URL manually', { authorizationUrl });
      return;
    }
  }

  try {
    const openModule = await import('open');
    const open = openModule.default;
    if (browserApp) {
      await open(authorizationUrl, { app: { name: browserApp } });
    } else {
      await open(authorizationUrl);
    }
  } catch (error) {
    logger?.warn('[OIDC] Failed to open browser', {
      error: error instanceof Error ? error.message : String(error),
    });
    logger?.info('[OIDC] Open URL manually', { authorizationUrl });
  }
}

export async function startOidcBrowserAuth(
  authorizationUrl: string,
  browser: string,
  logger?: ILogger,
  port: number = 3001,
): Promise<{ code: string; state?: string }> {
  const portAvailable = await isPortAvailable(port);
  if (!portAvailable) {
    throw new Error(
      `Port ${port} is already in use. Please specify a different port or free the port.`,
    );
  }

  return new Promise((resolve, reject) => {
    const app = express();
    const server = http.createServer(app);
    server.keepAliveTimeout = 0;
    server.headersTimeout = 0;
    const PORT = port;

    let resolved = false;
    const cleanup = () => {
      if (resolved) return;
      resolved = true;
      server.close();
    };

    app.get('/callback', (req, res) => {
      const code = req.query.code;
      const state = req.query.state;
      if (!code || typeof code !== 'string') {
        res.status(400).send('Missing authorization code');
        cleanup();
        reject(new Error('Missing authorization code'));
        return;
      }
      res
        .status(200)
        .send('Authentication complete. You can close this window.');
      cleanup();
      resolve({ code, state: typeof state === 'string' ? state : undefined });
    });

    server.listen(PORT, async () => {
      logger?.info('[OIDC] Callback server listening', { port: PORT });
      await openBrowserUrl(authorizationUrl, browser, logger);
    });
  });
}
