/**
 * SAML 2.0 auth helpers: the AuthnRequest and the URL that carries it
 */

import { randomUUID } from 'node:crypto';
import { deflateRawSync } from 'node:zlib';

export interface Saml2AuthConfig {
  idpSsoUrl: string;
  spEntityId: string;
  acsUrl: string;
  relayState?: string | undefined;
  authorizationUrl?: string | undefined;
}

function base64Encode(input: string | Buffer): string {
  return Buffer.isBuffer(input)
    ? input.toString('base64')
    : Buffer.from(input, 'utf8').toString('base64');
}

function buildAuthnRequestXml(
  id: string,
  spEntityId: string,
  acsUrl: string,
): string {
  const issueInstant = new Date().toISOString();
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

export interface BuiltAuthorizationUrl {
  readonly url: string;
  /** Present only when this function minted the request. */
  readonly requestId?: string;
}

export function buildSamlAuthorizationUrl(
  config: Saml2AuthConfig,
): BuiltAuthorizationUrl {
  if (config.authorizationUrl) {
    // Somebody else built the request; its ID is not ours to know.
    return { url: config.authorizationUrl };
  }

  const requestId = `_${randomUUID()}`;
  const xml = buildAuthnRequestXml(requestId, config.spEntityId, config.acsUrl);
  const deflated = deflateRawSync(Buffer.from(xml, 'utf8'));
  const samlRequest = encodeURIComponent(base64Encode(deflated));
  const relayState = config.relayState
    ? `&RelayState=${encodeURIComponent(config.relayState)}`
    : '';

  return {
    url: `${config.idpSsoUrl}?SAMLRequest=${samlRequest}${relayState}`,
    requestId,
  };
}
