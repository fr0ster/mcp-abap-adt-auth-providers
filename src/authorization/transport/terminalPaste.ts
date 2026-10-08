/**
 * The terminal transport (spec §6d.2, §6d.3.2): the user pastes the answer
 * at a prompt. It binds nothing and advertises only the consumer's
 * redirect (C4). A refused answer gets the reason's words and the prompt
 * again; an `end` ends the wait (its `shown` dropped: nothing of the IdP is
 * printed). `open` settles only once the read in flight has settled — the
 * reader closed — so the next login never shares stdin with this one.
 */

import { createInterface } from 'node:readline';
import { authError } from '@mcp-abap-adt/auth-errors';
import type {
  AnswerJudge,
  AnswerRefusal,
  AnswerTransportOptions,
  IAnswerChannel,
  IAnswerTransport,
  IArmedChannel,
} from '@mcp-abap-adt/interfaces-auth';
import { untilAborted } from '../../auth/attempt';
import { misconfigured, ownOptions } from '../../auth/configuration';
import { abortedLogin, loginFailure } from '../../auth/interactiveLogin';
import { readSafely } from '../../auth/knownCodes';
import { ANSWER_WORDS } from '../answerWords';
import { consumerRedirect } from './consumerRedirect';
import { endFailure, verdictOf } from './endVerdict';

/** Reads one line for `prompt`; stops and releases what it holds at `signal`. */
export type TerminalRead = (
  prompt: string,
  signal: AbortSignal,
) => Promise<string>;

export interface TerminalPasteOptions {
  /** The redirect registered with the IdP; required with a redirect protocol. */
  readonly redirectUri?: string | undefined;
  /** Where the pasted line comes from. Default `readFromTerminal`. */
  readonly read?: TerminalRead | undefined;
}

/**
 * Reads one line from stdin.
 *
 * The prompt goes to stderr, never stdout, and stdin is touched only when it
 * is a terminal: under a stdio RPC transport those streams carry the
 * protocol. Closes its `readline` when the signal aborts, and settles only
 * once the interface has closed — its listeners gone from stdin.
 */
export async function readFromTerminal(
  prompt: string,
  signal: AbortSignal,
): Promise<string> {
  // Aborted before the read began: no readline, so stdin is never held for
  // a line nobody awaits (K12).
  if (signal.aborted) throw loginFailure({ outcome: 'input-abandoned' });
  if (!process.stdin.isTTY) throw loginFailure({ outcome: 'no-terminal' });
  process.stderr.write(prompt);
  const rl = createInterface({ input: process.stdin });
  const closed = new Promise<void>((resolve) => {
    rl.once('close', () => resolve());
  });
  const abort = () => rl.close();
  signal.addEventListener('abort', abort, { once: true });
  try {
    for await (const line of rl) return line.trim();
  } finally {
    signal.removeEventListener('abort', abort);
    rl.close();
    await closed;
  }
  throw loginFailure({ outcome: 'no-input' });
}

/** A value adopted as `await` would, a synchronous throw as a rejection. */
const adopt = <T>(run: () => T | Promise<T>): Promise<T> =>
  new Promise<T>((resolve) => resolve(run()));

/** The prompt of the protocol's paste words; without them, no terminal. */
function promptOf(value: unknown): string {
  const prompt = readSafely(value, 'prompt');
  if (typeof prompt === 'string') return prompt;
  throw misconfigured(
    authError.configuration({ case: 'invalid-value', fields: ['protocol'] }),
  );
}

export function terminalPaste(
  options: TerminalPasteOptions = {},
): IAnswerTransport {
  // Read once as own data: a hostile object throws nothing of its own.
  const own = ownOptions<Record<keyof TerminalPasteOptions, unknown>>(options);
  const redirectUri = consumerRedirect(own.redirectUri);
  if (own.read !== undefined && typeof own.read !== 'function') {
    throw misconfigured(
      authError.configuration({ case: 'invalid-value', fields: ['read'] }),
    );
  }
  const read = (own.read as TerminalRead | undefined) ?? readFromTerminal;
  return Object.freeze({
    label: 'manual' as const,
    async open<TReturn>(
      openOptions: AnswerTransportOptions,
      use: (channel: IAnswerChannel) => Promise<TReturn>,
    ): Promise<TReturn> {
      const given =
        ownOptions<Record<keyof AnswerTransportOptions, unknown>>(openOptions);
      const pastePrompt = promptOf(given.paste);
      const signal =
        given.signal instanceof AbortSignal ? given.signal : undefined;
      if (signal?.aborted) throw abortedLogin('manual');
      // The read stops at the signal and at the end of this open.
      const closing = new AbortController();
      const readSignal =
        signal === undefined
          ? closing.signal
          : AbortSignal.any([signal, closing.signal]);
      /** The read in flight, settled either way. */
      let reading: Promise<unknown> = Promise.resolve();
      let armed = false;

      const ask = async (prompt: string): Promise<string> => {
        // Never a read after this open ended: its reader is not awaited.
        if (readSignal.aborted) throw abortedLogin('manual');
        const line = adopt(() => read(prompt, readSignal));
        reading = line.then(
          () => undefined,
          () => undefined,
        );
        const text = await line;
        if (typeof text !== 'string') {
          throw loginFailure({ outcome: 'no-input' });
        }
        return text;
      };

      const wait = async (judge: AnswerJudge<unknown>): Promise<void> => {
        let prompt = pastePrompt;
        for (;;) {
          const text = await ask(prompt);
          const verdict = verdictOf(judge, { via: 'terminal', text });
          const kind = readSafely(verdict, 'verdict');
          if (kind === 'accept') return;
          if (kind === 'end') {
            // `shown` is for a listener's escaped page only: dropped here.
            throw endFailure(readSafely(verdict, 'error'));
          }
          const reason = readSafely(verdict, 'reason');
          if (
            kind !== 'refuse' ||
            typeof reason !== 'string' ||
            !Object.hasOwn(ANSWER_WORDS, reason)
          ) {
            throw loginFailure({ outcome: 'failed' });
          }
          // The reason's words, then the prompt again.
          prompt = `${ANSWER_WORDS[reason as AnswerRefusal]} ${pastePrompt}`;
        }
      };

      const channel: IAnswerChannel = Object.freeze({
        redirectUri,
        arm(judge: AnswerJudge<unknown>): IArmedChannel {
          if (typeof judge !== 'function' || armed) {
            throw loginFailure({ outcome: 'failed' });
          }
          armed = true;
          const answer = wait(judge);
          void answer.catch(() => undefined);
          return Object.freeze({ answer: () => answer });
        },
      });

      try {
        return await untilAborted(
          adopt(() => use(channel)),
          signal,
        );
      } catch (error) {
        if (signal?.aborted) throw abortedLogin('manual');
        throw error;
      } finally {
        // Released before settling: the reader closed, stdin let go.
        closing.abort();
        await reading;
      }
    },
  });
}
