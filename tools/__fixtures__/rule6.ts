// Rule 6: a diagnostic passed outside the approved extraction sites of
// tools/diagnostic-sites.json — the field is listed, this site is not. Must
// be found.
import { authError } from '@mcp-abap-adt/auth-errors';

export function elsewhere(path: string) {
  return authError.snc({ problem: 'library-init-failed' }, { library: path });
}
