// Rule 3: an object literal that satisfies IAuthProvider. Must be found.
import { OK } from '@mcp-abap-adt/auth-errors';
import type { IAuthProvider } from '@mcp-abap-adt/interfaces-auth';

export function literal(): IAuthProvider {
  return {
    kind: 'literal',
    prepare: async () => OK,
    establish: async () => OK,
    authorize: async () => OK,
    rejected: async () => OK,
  };
}
