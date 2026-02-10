/**
 * OIDC discovery helper
 */

import type { ILogger } from '@mcp-abap-adt/interfaces';
import axios from 'axios';

export interface OidcDiscoveryDocument {
  issuer: string;
  authorization_endpoint?: string;
  token_endpoint: string;
  device_authorization_endpoint?: string;
  jwks_uri?: string;
  end_session_endpoint?: string;
}

const discoveryCache = new Map<string, OidcDiscoveryDocument>();

function normalizeDiscoveryUrl(issuerOrDiscoveryUrl: string): string {
  if (issuerOrDiscoveryUrl.endsWith('/.well-known/openid-configuration')) {
    return issuerOrDiscoveryUrl;
  }
  return `${issuerOrDiscoveryUrl.replace(/\/+$/, '')}/.well-known/openid-configuration`;
}

export async function discoverOidc(
  issuerOrDiscoveryUrl: string,
  logger?: ILogger,
): Promise<OidcDiscoveryDocument> {
  const discoveryUrl = normalizeDiscoveryUrl(issuerOrDiscoveryUrl);
  const cached = discoveryCache.get(discoveryUrl);
  if (cached) {
    return cached;
  }

  logger?.info('[OIDC] Fetching discovery document', { discoveryUrl });
  const response = await axios.get<OidcDiscoveryDocument>(discoveryUrl, {
    headers: { Accept: 'application/json' },
  });

  if (!response.data?.token_endpoint) {
    throw new Error('OIDC discovery document missing token_endpoint');
  }

  discoveryCache.set(discoveryUrl, response.data);
  return response.data;
}
