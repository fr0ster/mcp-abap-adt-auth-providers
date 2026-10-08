/**
 * What a listener's bind may end with: a port no socket
 * can bind, a port someone else holds, an address the machine
 * does not have, anything else.
 */

import { AuthProviderFailure, authError } from '@mcp-abap-adt/auth-errors';
import { misconfigured } from '../../auth/configuration';
import { failedLogin, portInUse } from '../../auth/interactiveLogin';

/**
 * A port no socket can bind — an integer in 0..65535 only; a string is
 * not a port (Node would bind a UNIX socket at that path). The value given
 * is not echoed. Checked before anything binds.
 */
export function validatePort(port: unknown): asserts port is number {
  if (
    typeof port !== 'number' ||
    !Number.isInteger(port) ||
    port < 0 ||
    port > 65535
  ) {
    throw misconfigured(
      authError.configuration({
        case: 'callback-port-invalid',
        fields: ['port'],
      }),
    );
  }
}

/** The system code of a thrown value, read without running anything. */
function codeOf(error: unknown): unknown {
  if (error === null || typeof error !== 'object') return undefined;
  try {
    const descriptor = Reflect.getOwnPropertyDescriptor(error, 'code');
    return descriptor !== undefined && 'value' in descriptor
      ? descriptor.value
      : undefined;
  } catch {
    return undefined;
  }
}

/** A machine without that address (IPv6 loopback disabled): skippable. */
export function unavailableAddress(error: unknown): boolean {
  const code = codeOf(error);
  return code === 'EADDRNOTAVAIL' || code === 'EAFNOSUPPORT';
}

/** The OS refused the address: it is in use. */
export function addressInUse(error: unknown): boolean {
  return codeOf(error) === 'EADDRINUSE';
}

/**
 * The bind failed: a port someone else holds is `port-in-use`, with its words; any
 * other failure names only its allowlisted code. A failure already
 * decided (the second family's port taken) passes as it is.
 */
export function bindFailure(error: unknown, port: number): Error {
  if (error instanceof AuthProviderFailure) return error;
  if (addressInUse(error) && port > 0) return portInUse(port);
  return failedLogin(error);
}
