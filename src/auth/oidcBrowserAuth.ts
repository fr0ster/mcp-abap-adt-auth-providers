/**
 * OIDC browser authorization code flow (capture code)
 */

import * as net from 'node:net';
import type {
  CallbackServerFactory,
  ICallbackServerHandle,
  ICallbackServerOptions,
  ILogger,
} from '@mcp-abap-adt/interfaces';
import { runCallbackScope } from './callbackServer';

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

export interface OidcCallbackResult {
  code: string;
  state?: string;
}

export const withOidcCallbackServer: CallbackServerFactory<
  OidcCallbackResult
> = <TReturn>(
  options: ICallbackServerOptions,
  use: (server: ICallbackServerHandle<OidcCallbackResult>) => Promise<TReturn>,
): Promise<TReturn> =>
  runCallbackScope<OidcCallbackResult, TReturn>(
    options,
    (app, settle) => {
      app.get('/callback', (req, res) => {
        // An IdP that declines says so explicitly. That is a finished login,
        // not a stray request, and it must not wait for the timeout.
        const { error, error_description, error_uri } = req.query;
        if (error) {
          const message = error_description
            ? `${String(error)}: ${String(error_description)}`
            : String(error);
          res.status(400).send(`Authentication failed: ${message}`);
          settle.err(
            new Error(
              `OIDC authentication failed: ${message}` +
                (error_uri ? ` (${String(error_uri)})` : ''),
            ),
            res,
          );
          return;
        }

        const code = req.query.code;
        const state = req.query.state;
        if (!code || typeof code !== 'string') {
          res.status(400).send('Error: not an authorization callback');
          settle.ignore('no code and no error in query', res);
          return;
        }

        res
          .status(200)
          .send('Authentication complete. You can close this window.');
        settle.ok(
          { code, state: typeof state === 'string' ? state : undefined },
          res,
        );
      });
    },
    use,
  );

/**
 * OIDC browser login.
 *
 * The callback socket belongs to the scope: it is released when the scope ends,
 * whatever ends it. Before this, the flow had no timeout at all — an abandoned
 * login never settled and the port was held for the life of the process.
 */
export async function startOidcBrowserAuth(
  authorizationUrl: string,
  browser: string,
  logger?: ILogger,
  port: number = 3001,
  timeoutMs: number = 30 * 1000,
): Promise<OidcCallbackResult> {
  // Pre-check kept for its message: AuthBroker matches /already in use/i to
  // distinguish a busy port from other failures.
  const portAvailable = await isPortAvailable(port);
  if (!portAvailable) {
    throw new Error(
      `Port ${port} is already in use. Please specify a different port or free the port.`,
    );
  }

  return await withOidcCallbackServer({ port, timeoutMs }, async (server) => {
    logger?.info('[OIDC] Callback server listening', { port: server.port });
    const waiting = server.waitForResult();
    // Not awaited: a launcher that hangs must not delay the timeout or the
    // release of the port.
    void openBrowserUrl(authorizationUrl, browser, logger).catch(
      (error: unknown) => {
        logger?.warn('[OIDC] Failed to open browser', {
          error: error instanceof Error ? error.message : String(error),
        });
        logger?.info('[OIDC] Open URL manually', { authorizationUrl });
      },
    );
    return await waiting;
  });
}
