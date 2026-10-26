/**
 * What a transport rejects its wait with on an `end` verdict: a failure holding
 * the verdict's error when this copy minted it, else `failed` — the composer
 * re-mints what it latched; a transport never passes on a value it cannot vouch
 * for.
 */

import { AuthProviderFailure, isMinted } from '@mcp-abap-adt/auth-errors';
import { failedLogin } from '../../auth/interactiveLogin';

export function endFailure(error: unknown): AuthProviderFailure {
  return isMinted(error)
    ? new AuthProviderFailure(error)
    : failedLogin(undefined);
}
