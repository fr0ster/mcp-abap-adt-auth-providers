/**
 * SAML 2.0 auth helpers
 */

import { randomUUID } from 'node:crypto';
import * as net from 'node:net';
import { deflateRawSync } from 'node:zlib';
import type {
  CallbackServerFactory,
  ICallbackServerHandle,
  ICallbackServerOptions,
  ILogger,
} from '@mcp-abap-adt/interfaces';
import express from 'express';
import { runCallbackScope } from './callbackServer';

export interface Saml2AuthConfig {
  idpSsoUrl: string;
  spEntityId: string;
  acsUrl: string;
  relayState?: string;
  authorizationUrl?: string;
}

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

function base64Encode(input: string | Buffer): string {
  return Buffer.isBuffer(input)
    ? input.toString('base64')
    : Buffer.from(input, 'utf8').toString('base64');
}

function buildAuthnRequestXml(spEntityId: string, acsUrl: string): string {
  const issueInstant = new Date().toISOString();
  const id = `_${randomUUID()}`;
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"',
    ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"',
    ` ID="${id}"`,
    ' Version="2.0"',
    ` IssueInstant="${issueInstant}"`,
    ` ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"`,
    ` AssertionConsumerServiceURL="${acsUrl}">`,
    `<saml:Issuer>${spEntityId}</saml:Issuer>`,
    '</samlp:AuthnRequest>',
  ].join('');
}

export function buildSamlAuthorizationUrl(config: Saml2AuthConfig): string {
  if (config.authorizationUrl) {
    return config.authorizationUrl;
  }

  const xml = buildAuthnRequestXml(config.spEntityId, config.acsUrl);
  const deflated = deflateRawSync(Buffer.from(xml, 'utf8'));
  const samlRequest = encodeURIComponent(base64Encode(deflated));
  const relayState = config.relayState
    ? `&RelayState=${encodeURIComponent(config.relayState)}`
    : '';

  return `${config.idpSsoUrl}?SAMLRequest=${samlRequest}${relayState}`;
}

async function openBrowserUrl(
  authorizationUrl: string,
  browser: string,
  logger?: ILogger,
): Promise<void> {
  const browserApp = BROWSER_MAP[browser];
  if (browserApp === null) {
    logger?.info('[SAML] Browser suppressed, open URL manually', {
      authorizationUrl,
    });
    return;
  }

  if (browser === 'auto') {
    try {
      const openModule = await import('open');
      const open = openModule.default;
      await open(authorizationUrl);
      logger?.info('[SAML] Browser opened');
      return;
    } catch (error) {
      logger?.warn('[SAML] Failed to open browser automatically', {
        error: error instanceof Error ? error.message : String(error),
      });
      logger?.info('[SAML] Open URL manually', { authorizationUrl });
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
    logger?.warn('[SAML] Failed to open browser', {
      error: error instanceof Error ? error.message : String(error),
    });
    logger?.info('[SAML] Open URL manually', { authorizationUrl });
  }
}

export const withSamlCallbackServer: CallbackServerFactory<string> = <TReturn>(
  options: ICallbackServerOptions,
  use: (server: ICallbackServerHandle<string>) => Promise<TReturn>,
): Promise<TReturn> =>
  runCallbackScope<string, TReturn>(
    options,
    (app, settle) => {
      app.use(express.urlencoded({ extended: false, limit: '5mb' }));

      const handle = (samlResponse: unknown, res: express.Response): void => {
        // The response is decided after the payload is examined. Answering 200
        // first told a request that carried nothing that it had authenticated.
        if (typeof samlResponse === 'string' && samlResponse) {
          res
            .status(200)
            .send('SAML authentication complete. You can close this window.');
          settle.ok(samlResponse, res);
          return;
        }
        res.status(400).send('Error: not a SAML assertion callback');
        settle.ignore('no SAMLResponse in the request', res);
      };

      app.post('/callback', (req, res) => {
        handle(req.body?.SAMLResponse, res);
      });

      app.get('/callback', (req, res) => {
        handle(req.query.SAMLResponse, res);
      });
    },
    use,
  );

/**
 * SAML browser login.
 *
 * The callback socket belongs to the scope: it is released when the scope ends,
 * whatever ends it. Before this, the flow had no timeout at all — an abandoned
 * login never settled and the port was held for the life of the process.
 */
export async function startSamlBrowserAuth(
  config: Saml2AuthConfig,
  browser: string,
  logger?: ILogger,
  port: number = 3001,
  timeoutMs: number = 30 * 1000,
): Promise<string> {
  // Pre-check kept for its message: AuthBroker matches /already in use/i to
  // distinguish a busy port from other failures.
  const portAvailable = await isPortAvailable(port);
  if (!portAvailable) {
    throw new Error(
      `Port ${port} is already in use. Please specify a different port or free the port.`,
    );
  }

  const authorizationUrl = buildSamlAuthorizationUrl(config);

  return await withSamlCallbackServer({ port, timeoutMs }, async (server) => {
    logger?.info('[SAML] Callback server listening', { port: server.port });
    const waiting = server.waitForResult();
    // Not awaited: a launcher that hangs must not delay the timeout or the
    // release of the port.
    void openBrowserUrl(authorizationUrl, browser, logger).catch(
      (error: unknown) => {
        logger?.warn('[SAML] Failed to open browser', {
          error: error instanceof Error ? error.message : String(error),
        });
        logger?.info('[SAML] Open URL manually', { authorizationUrl });
      },
    );
    return await waiting;
  });
}

export function parseSamlNotOnOrAfter(
  samlResponse: string,
): number | undefined {
  try {
    const decoded = Buffer.from(samlResponse, 'base64').toString('utf8');
    const match = decoded.match(/NotOnOrAfter="([^"]+)"/);
    if (!match) {
      return undefined;
    }
    const date = Date.parse(match[1]);
    return Number.isNaN(date) ? undefined : date;
  } catch {
    return undefined;
  }
}
