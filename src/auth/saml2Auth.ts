/**
 * SAML 2.0 auth helpers
 */

import { randomUUID } from 'node:crypto';
import { deflateRawSync } from 'node:zlib';
import type {
  CallbackServerFactory,
  ICallbackServerHandle,
  ICallbackServerOptions,
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
