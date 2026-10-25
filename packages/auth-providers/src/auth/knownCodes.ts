/**
 * The codes a refusal, a log line or an error property may name: the system
 * codes and Node's TLS failure codes of interfaces-auth, read through
 * auth-errors' guards. It imports nothing of this package at run time, so an
 * error class can check a code in its constructor without importing
 * `refusal.ts`.
 */

import { isSystemCode, isTlsFailureCode } from '@mcp-abap-adt/auth-errors';
import type { TlsFailureCode } from '@mcp-abap-adt/interfaces-auth';

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

/**
 * The allowlisted code of a TLS failure — the server's certificate, or the
 * server refusing the client's — else undefined: interfaces-auth's
 * `TLS_FAILURE_CODES`, read through auth-errors' guard. A site that wraps its
 * errors lets these through unwrapped, so the refusal can name the code; the
 * words for each are auth-errors' (`tls`).
 */
export function tlsFailureCode(error: unknown): TlsFailureCode | undefined {
  const code = readSafely(error, 'code');
  return isTlsFailureCode(code) ? code : undefined;
}

/**
 * The code when it is an allowlisted system or TLS code (interfaces-auth's
 * `SYSTEM_CODES` and `TLS_FAILURE_CODES`, through auth-errors' guards), else
 * undefined.
 */
export function allowlistedCode(code: unknown): string | undefined {
  return isSystemCode(code) || isTlsFailureCode(code) ? code : undefined;
}

/** An integer HTTP status, else undefined. */
export function integerStatus(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isInteger(value)
    ? value
    : undefined;
}
