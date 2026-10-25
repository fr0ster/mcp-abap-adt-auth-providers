// Rule 4 (C13): a branded integer and an error asserted instead of made by
// auth-errors' makers and builders. Must be found, both.
import type {
  HttpStatus,
  IAuthProviderError,
} from '@mcp-abap-adt/interfaces-auth';

export const status = 500 as HttpStatus;

export function forged(): IAuthProviderError {
  return { kind: 'unknown', reason: 'forged' } as unknown as IAuthProviderError;
}
