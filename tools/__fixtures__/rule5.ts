// Rule 5: a spread of a minted error, which keeps the brand. Must be found.
import { authError } from '@mcp-abap-adt/auth-errors';

export function reworded() {
  const minted = authError['credential-refused']({ credential: 'token' });
  return { ...minted, reason: 'reworded' };
}
