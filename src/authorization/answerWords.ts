/**
 * The fixed words per refused answer: what a listener
 * answers in its `400`, above the paste form, and what a terminal shows
 * before it asks again. Nothing of the answer is in them.
 */

import type { AnswerRefusal } from '@mcp-abap-adt/interfaces-auth';

export const ANSWER_WORDS: Readonly<Record<AnswerRefusal, string>> =
  Object.freeze({
    'not-armed': 'Error: the login is not ready yet.',
    host: 'Error: this server does not answer for that host.',
    'form-token': 'Error: not a submission of this login’s page.',
    state: 'Error: not a callback of this login.',
    'pasted-state':
      'That URL is not from this login. Paste the code or URL this login returned.',
    'no-payload': 'Error: nothing this login can use was received.',
    unreadable: 'Could not read an answer from that input. Try again.',
    'already-answered': 'Error: this login has already been answered.',
  });
