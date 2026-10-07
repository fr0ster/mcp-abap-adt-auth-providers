/**
 * OIDC discovery helper
 */

import { AuthProviderFailure, authError } from '@mcp-abap-adt/auth-errors';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import axios from 'axios';
import { abortedFailure } from './attempt';
import { readSafely } from './knownCodes';
import { logQuietly, requestFailure } from './tokenRequest';

/**
 * The discovery snapshot (spec §6): the fields the providers and `mtlsAlias`
 * read, nothing else — never the document the server sent, nor the object a
 * consumer's response interceptor returned.
 */
export interface OidcDiscoveryDocument {
  readonly authorization_endpoint?: string | undefined;
  readonly token_endpoint: string;
  readonly device_authorization_endpoint?: string | undefined;
  /** RFC 8705 §5: the endpoints a client presenting a certificate uses instead. */
  readonly mtls_endpoint_aliases?: MtlsEndpointAliases | undefined;
}

/** The two mTLS aliases a provider reads (RFC 8705 §5). */
export interface MtlsEndpointAliases {
  readonly token_endpoint?: string | undefined;
  readonly device_authorization_endpoint?: string | undefined;
}

/** The endpoints a discovery snapshot keeps, beside `mtls_endpoint_aliases`. */
const DISCOVERY_FIELDS = [
  'authorization_endpoint',
  'token_endpoint',
  'device_authorization_endpoint',
] as const;

/** The aliases a snapshot keeps of `mtls_endpoint_aliases`. */
const ALIAS_FIELDS = [
  'token_endpoint',
  'device_authorization_endpoint',
] as const;

/** A field read through `readSafely`, kept only as a non-empty string. */
function nonEmptyString(value: unknown, key: string): string | undefined {
  const read = readSafely(value, key);
  return typeof read === 'string' && read !== '' ? read : undefined;
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
  return nonEmptyString(
    readSafely(document, 'mtls_endpoint_aliases'),
    endpoint,
  );
}

const discoveryCache = new Map<string, OidcDiscoveryDocument>();

function normalizeDiscoveryUrl(issuerOrDiscoveryUrl: string): string {
  if (issuerOrDiscoveryUrl.endsWith('/.well-known/openid-configuration')) {
    return issuerOrDiscoveryUrl;
  }
  let end = issuerOrDiscoveryUrl.length;
  while (end > 0 && issuerOrDiscoveryUrl[end - 1] === '/') end--;
  return `${issuerOrDiscoveryUrl.slice(0, end)}/.well-known/openid-configuration`;
}

/** `request-failed` `incomplete-response` of discovery, the operation only (D6). */
function incomplete(): AuthProviderFailure {
  return new AuthProviderFailure(
    authError['request-failed']({
      operation: 'oidc-discovery',
      problem: 'incomplete-response',
    }),
  );
}

/**
 * The snapshot of a discovery answer: each of `DISCOVERY_FIELDS` read through
 * `readSafely` and kept only as a non-empty string; `mtls_endpoint_aliases`
 * rebuilt as a plain object of its two aliases, each kept the same way. A
 * field that throws or is not a non-empty string is left out; without
 * `token_endpoint` there is no snapshot. Nothing else is read — no `toJSON`,
 * no other key.
 */
function discoverySnapshot(response: unknown): OidcDiscoveryDocument {
  const document = readSafely(response, 'data');
  const fields: Partial<Record<(typeof DISCOVERY_FIELDS)[number], string>> = {};
  for (const field of DISCOVERY_FIELDS) {
    const value = nonEmptyString(document, field);
    if (value !== undefined) fields[field] = value;
  }
  const tokenEndpoint = fields.token_endpoint;
  if (tokenEndpoint === undefined) throw incomplete();

  const rawAliases = readSafely(document, 'mtls_endpoint_aliases');
  const aliases: Partial<Record<(typeof ALIAS_FIELDS)[number], string>> = {};
  for (const field of ALIAS_FIELDS) {
    const value = nonEmptyString(rawAliases, field);
    if (value !== undefined) aliases[field] = value;
  }
  return {
    ...fields,
    token_endpoint: tokenEndpoint,
    ...(Object.keys(aliases).length === 0
      ? {}
      : { mtls_endpoint_aliases: aliases }),
  };
}

/**
 * Fetches the discovery document and answers its snapshot (spec §6, D6). A
 * transport rejection becomes `tls` or `request-failed` of `oidc-discovery`;
 * an answer without `token_endpoint`, or one that cannot be read, becomes
 * `request-failed` `incomplete-response` with the operation only. A failed
 * discovery is not cached; it writes no failure line. With the attempt's
 * `signal` (spec §6b), its abort cuts the request, and an aborted discovery
 * — cut, or answered after the abort — ends `aborted` and is not cached.
 */
export async function discoverOidc(
  issuerOrDiscoveryUrl: string,
  logger?: ILogger,
  signal?: AbortSignal,
): Promise<OidcDiscoveryDocument> {
  const discoveryUrl = normalizeDiscoveryUrl(issuerOrDiscoveryUrl);
  const cached = discoveryCache.get(discoveryUrl);
  if (cached) {
    return cached;
  }

  logQuietly(() => logger?.info('[OIDC] Fetching discovery document'));
  // The one request that may follow a redirect: it sends no secret — no
  // credential, no grant, no client certificate — only a GET for public
  // metadata. Every token request sets `maxRedirects: 0`.
  let response: unknown;
  try {
    response = await axios.get(discoveryUrl, {
      headers: { Accept: 'application/json' },
      // The attempt's abort cuts the discovery (spec §6b, C6).
      ...(signal === undefined ? {} : { signal }),
    });
  } catch (error) {
    if (signal?.aborted === true) throw abortedFailure();
    // Whatever was thrown — the server's text through a consumer's
    // interceptor included — becomes the safe facts alone.
    throw requestFailure(error, 'oidc-discovery');
  }

  // An answer that arrives after the abort is the aborted attempt's: not
  // cached, so the next call fetches again.
  if (signal?.aborted === true) throw abortedFailure();
  let document: OidcDiscoveryDocument;
  try {
    document = discoverySnapshot(response);
  } catch {
    throw incomplete();
  }
  discoveryCache.set(discoveryUrl, document);
  return document;
}
