/**
 * What a transport rejects its wait with on an `end` verdict: a failure holding the verdict's error when this copy minted
 * it, else `failed` — the composer re-mints what it latched; a
 * transport never passes on a value it cannot vouch for.
 */

import { AuthProviderFailure, isMinted } from '@mcp-abap-adt/auth-errors';
import type {
  AnswerJudge,
  AuthorizationAnswer,
} from '@mcp-abap-adt/interfaces-auth';
import { failedLogin } from '../../auth/interactiveLogin';

export function endFailure(error: unknown): AuthProviderFailure {
  return isMinted(error)
    ? new AuthProviderFailure(error)
    : failedLogin(undefined);
}

/**
 * The judge's answer to `answer`; a judge that throws is `failed`, nothing
 * of the throw kept (as the listener's fixed 500): the transport never
 * lets a judge's text escape (review m3).
 */
export function verdictOf(
  judge: AnswerJudge<unknown>,
  answer: AuthorizationAnswer,
): unknown {
  try {
    return judge(answer);
  } catch {
    throw failedLogin(undefined);
  }
}
