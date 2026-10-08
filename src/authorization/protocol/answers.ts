/**
 * The verdicts a shipped protocol answers, built in
 * one place: a refusal names a reason from `ANSWER_REFUSALS`, an end carries
 * an error minted through auth-errors — never a word of the answer.
 */

import { authError } from '@mcp-abap-adt/auth-errors';
import type {
  AnswerRefusal,
  AnswerVerdict,
  PasteWords,
} from '@mcp-abap-adt/interfaces-auth';
import { misconfigured } from '../../auth/configuration';

export const accept = <T>(payload: T): AnswerVerdict<T> => ({
  verdict: 'accept',
  payload,
});

export const refuse = <T>(reason: AnswerRefusal): AnswerVerdict<T> => ({
  verdict: 'refuse',
  reason,
});

/** An `end` with an `interactive-login` outcome that has no fact of its own. */
export const endWith = <T>(
  outcome: 'unreadable-input' | 'no-input',
): AnswerVerdict<T> => ({
  verdict: 'end',
  error: authError['interactive-login']({ outcome }),
});

/** A URL a protocol cannot bind an answer to: before anything is shown. */
export const unreadableUrl = () =>
  misconfigured(
    authError.configuration({
      case: 'invalid-value',
      fields: ['authorizationUrl'],
    }),
  );

/** Paste words, frozen: shared by every protocol of a kind. */
export const words = (prompt: string, instructions: string): PasteWords =>
  Object.freeze({ prompt, instructions });
