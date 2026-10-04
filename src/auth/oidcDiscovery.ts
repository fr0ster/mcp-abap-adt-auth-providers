/**
 * OIDC discovery helper
 */

import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import axios from 'axios';

export interface OidcDiscoveryDocument {
  issuer: string;
  authorization_endpoint?: string;
  token_endpoint: string;
  device_authorization_endpoint?: string;
  jwks_uri?: string;
  end_session_endpoint?: string;
  /** RFC 8705 §5: the endpoints a client presenting a certificate uses instead. */
  mtls_endpoint_aliases?: {
    token_endpoint?: string;
    device_authorization_endpoint?: string;
  };
}

/**
 * The mTLS alias the server published for one of its endpoints (RFC 8705 §5),
 * as a draft's `mtlsEndpoint`; undefined when it published none, or no
 * discovery took place.
 */
export function mtlsAlias(
  document: OidcDiscoveryDocument | null | undefined,
  endpoint: 'token_endpoint' | 'device_authorization_endpoint',
): string | undefined {
  const aliases: unknown = document?.mtls_endpoint_aliases;
  if (!aliases || typeof aliases !== 'object') return undefined;
  const alias = (aliases as Record<string, unknown>)[endpoint];
  return typeof alias === 'string' && alias !== '' ? alias : undefined;
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
  // The one request that may follow a redirect: it sends no secret — no
  // credential, no grant, no client certificate — only a GET for public
  // metadata. Every token request sets `maxRedirects: 0`.
  const response = await axios.get<OidcDiscoveryDocument>(discoveryUrl, {
    headers: { Accept: 'application/json' },
  });

  if (!response.data?.token_endpoint) {
    throw new Error('OIDC discovery document missing token_endpoint');
  }

  discoveryCache.set(discoveryUrl, response.data);
  return response.data;
}
