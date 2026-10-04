/**
 * The codes a refusal, a log line or an error property may name: a fixed set
 * of system codes and Node's TLS failure codes, each TLS code with its fixed
 * words. A leaf module (no imports), so an error class can check a code in its
 * constructor without importing `refusal.ts`.
 */

/**
 * One property of a foreign value, or undefined when reading it throws: a
 * getter or a Proxy must not turn a refusal into an exception (rule 1).
 */
export function readSafely(value: unknown, key: string): unknown {
  if (
    value === null ||
    (typeof value !== 'object' && typeof value !== 'function')
  ) {
    return undefined;
  }
  try {
    return (value as Record<string, unknown>)[key];
  } catch {
    return undefined;
  }
}

export const KNOWN_SYSTEM_CODES: ReadonlySet<string> = new Set([
  'ENOENT',
  'EACCES',
  'EPERM',
  'ECONNREFUSED',
  'ECONNRESET',
  'ETIMEDOUT',
  'ENOTFOUND',
  'EAI_AGAIN',
  'EPIPE',
  'EADDRINUSE',
  'ECONNABORTED',
  'EPROTO',
  // axios's own, for a request that got no response
  'ERR_NETWORK',
]);

/** The fixed words for one TLS failure: what it says, and what to do. */
export interface TlsWords {
  readonly says: string;
  readonly hint: string;
}

const UNTRUSTED_SERVER: TlsWords = {
  says: "the server's certificate is not trusted",
  hint: 'if the server uses a private CA, name its certificate in NODE_EXTRA_CA_CERTS',
};

/**
 * The server asked for a client certificate and refused the one presented, or
 * its absence: the alert it sent, as Node names it. Current OpenSSL (3.5 with
 * Node 22 and 24, 3.6 — measured) spells the SSLv3-era alerts
 * `SSL/TLS_ALERT_…`; older releases spelled them `SSLV3_ALERT_…` — both are
 * listed.
 */
const REFUSED_CLIENT_CERTIFICATE: TlsWords = {
  says: 'the server refused the client certificate',
  hint: "check that the server trusts the certificate's issuer and that the certificate is valid and not revoked",
};

const CLIENT_CERTIFICATE_ALERTS = [
  'BAD_CERTIFICATE',
  'CERTIFICATE_UNKNOWN',
  'CERTIFICATE_EXPIRED',
  'CERTIFICATE_REVOKED',
  'UNSUPPORTED_CERTIFICATE',
].flatMap((alert) => [
  `ERR_SSL_SSL/TLS_ALERT_${alert}`,
  `ERR_SSL_SSLV3_ALERT_${alert}`,
]);

/**
 * Node's codes for a TLS failure, each with its fixed words. The code is the
 * only part of such an error a refusal names; its message never.
 */
export const TLS_CODES: ReadonlyMap<string, TlsWords> = new Map<
  string,
  TlsWords
>([
  ['UNABLE_TO_VERIFY_LEAF_SIGNATURE', UNTRUSTED_SERVER],
  ['SELF_SIGNED_CERT_IN_CHAIN', UNTRUSTED_SERVER],
  ['DEPTH_ZERO_SELF_SIGNED_CERT', UNTRUSTED_SERVER],
  ['UNABLE_TO_GET_ISSUER_CERT_LOCALLY', UNTRUSTED_SERVER],
  [
    'CERT_HAS_EXPIRED',
    {
      says: "the server's certificate has expired",
      hint: "the server must renew its certificate; check also this machine's clock",
    },
  ],
  [
    'ERR_TLS_CERT_ALTNAME_INVALID',
    {
      says: "the host name is not in the server's certificate",
      hint: "use the host name the server's certificate is issued for",
    },
  ],
  ['ERR_SSL_TLSV13_ALERT_CERTIFICATE_REQUIRED', REFUSED_CLIENT_CERTIFICATE],
  ['ERR_SSL_TLSV1_ALERT_UNKNOWN_CA', REFUSED_CLIENT_CERTIFICATE],
  ...CLIENT_CERTIFICATE_ALERTS.map(
    (code) => [code, REFUSED_CLIENT_CERTIFICATE] as const,
  ),
]);

/**
 * The allowlisted code of a TLS failure — the server's certificate, or the
 * server refusing the client's — else undefined. A site that wraps its errors
 * lets these through unwrapped, so the refusal can name the code.
 */
export function tlsFailureCode(error: unknown): string | undefined {
  const code = readSafely(error, 'code');
  return typeof code === 'string' && TLS_CODES.has(code) ? code : undefined;
}

/** The code when it is an allowlisted system or TLS code, else undefined. */
export function allowlistedCode(code: unknown): string | undefined {
  return typeof code === 'string' &&
    (KNOWN_SYSTEM_CODES.has(code) || TLS_CODES.has(code))
    ? code
    : undefined;
}

/** An integer HTTP status, else undefined. */
export function integerStatus(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isInteger(value)
    ? value
    : undefined;
}
