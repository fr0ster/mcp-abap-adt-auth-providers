/**
 * The transports where the consumer's code returns the answer:
 * `consumerAnswer({ receive })`, and the pair `consumerHandoff({ provide })`
 * for a consumer whose one call shows the URL and returns the answer. Neither
 * binds anything nor advertises a redirect of its own; `open` settles at the
 * abort itself — it holds nothing to release. A refusal ends
 * `unreadable-input`: the consumer's code is not asked twice.
 */

import { authError } from '@mcp-abap-adt/auth-errors';
import type {
  AnswerJudge,
  AnswerTransportOptions,
  IAnswerChannel,
  IAnswerTransport,
  IArmedChannel,
  IAuthorizationPresentation,
  PresentationContext,
} from '@mcp-abap-adt/interfaces-auth';
import { untilAborted } from '../../auth/attempt';
import { misconfigured } from '../../auth/configuration';
import {
  abortedLogin,
  failedLogin,
  loginFailure,
} from '../../auth/interactiveLogin';
import { consumerRedirect } from './consumerRedirect';
import { endFailure } from './endVerdict';

/** The consumer's code: the answer, for the composition's signal. */
export type ReceiveAnswer = (signal: AbortSignal) => Promise<string>;

/** The consumer's code: shows `url`, returns the answer. */
export type ProvideAnswer = (
  authorizationUrl: string,
  signal: AbortSignal,
) => Promise<string>;

export interface ConsumerAnswerOptions {
  /** The redirect registered with the IdP; required with a redirect protocol. */
  readonly redirectUri?: string | undefined;
  readonly receive: ReceiveAnswer;
}

export interface ConsumerHandoffOptions {
  readonly redirectUri?: string | undefined;
  readonly provide: ProvideAnswer;
}

/** A value adopted as `await` would, a synchronous throw as a rejection. */
const adopt = <T>(run: () => T | Promise<T>): Promise<T> =>
  new Promise<T>((resolve) => resolve(run()));

const required = (field: 'receive' | 'provide') =>
  misconfigured(
    authError.configuration({
      case: 'required-fields-missing',
      fields: [field],
    }),
  );

/** A signal that never aborts, for an open given none. */
const never = new AbortController().signal;

/**
 * One text, judged once: accept resolves, refuse and end reject. The
 * judge's call and every read of its verdict share one boundary: a verdict
 * whose field throws is a judge that throws — `failed`, nothing of the
 * throw kept.
 */
function judgeOnce(judge: AnswerJudge<unknown>, text: string): void {
  let kind: string;
  let error: unknown;
  try {
    const verdict = judge({ via: 'consumer', text });
    kind = verdict.verdict;
    if (verdict.verdict === 'end') error = verdict.error;
  } catch {
    throw failedLogin(undefined);
  }
  if (kind === 'accept') return;
  if (kind === 'end') throw endFailure(error);
  // A refusal: it cannot ask again.
  throw loginFailure({
    outcome: kind === 'refuse' ? 'unreadable-input' : 'failed',
  });
}

/**
 * A socketless transport whose answer is `answerFor(signal)`, started when
 * the channel is armed.
 */
function socketless(
  redirectUri: string | undefined,
  answerFor: (signal: AbortSignal) => Promise<string>,
  onOpen?: () => () => void,
): IAnswerTransport {
  return Object.freeze({
    label: 'consumer' as const,
    async open<TReturn>(
      openOptions: AnswerTransportOptions,
      use: (channel: IAnswerChannel) => Promise<TReturn>,
    ): Promise<TReturn> {
      const signal: AbortSignal | undefined = openOptions.signal;
      if (signal?.aborted) throw abortedLogin('consumer');
      const close = onOpen?.();
      let armed = false;
      const channel: IAnswerChannel = Object.freeze({
        redirectUri,
        arm(judge: AnswerJudge<unknown>): IArmedChannel {
          if (armed) {
            throw loginFailure({ outcome: 'failed' });
          }
          armed = true;
          const answer = untilAborted(answerFor(signal ?? never), signal).then(
            (text) => judgeOnce(judge, text),
          );
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
        if (signal?.aborted) throw abortedLogin('consumer');
        throw error;
      } finally {
        close?.();
      }
    },
  });
}

/** The consumer's code returns the answer: `receive(signal)`. */
export function consumerAnswer(
  options: ConsumerAnswerOptions,
): IAnswerTransport {
  // A typed copy: the options are read once, here.
  const own = { ...options };
  const redirectUri = consumerRedirect(own.redirectUri);
  const { receive } = own;
  if (typeof receive !== 'function') throw required('receive');
  return socketless(redirectUri, (signal) => adopt(() => receive(signal)));
}

/**
 * One `provide(url, signal)` as a presentation and a transport: the
 * presentation calls it, the transport awaits what it returned. Its
 * failure ends the wait; the presentation itself never fails.
 */
export function consumerHandoff(options: ConsumerHandoffOptions): {
  readonly presentation: IAuthorizationPresentation;
  readonly transport: IAnswerTransport;
} {
  const own = { ...options };
  const redirectUri = consumerRedirect(own.redirectUri);
  const { provide } = own;
  if (typeof provide !== 'function') throw required('provide');

  /** The open in progress: where the presentation hands its answer. */
  let current: { readonly hand: (answer: Promise<string>) => void } | undefined;

  const transport = socketless(
    redirectUri,
    // The answer `provide` returned, once the presentation has called it.
    () => handed,
    () => {
      let hand!: (answer: Promise<string>) => void;
      handed = new Promise<string>((resolve) => {
        hand = (answer) => resolve(answer);
      });
      const opened = { hand };
      current = opened;
      return () => {
        if (current === opened) current = undefined;
      };
    },
  );
  let handed: Promise<string> = Promise.resolve('');

  const presentation: IAuthorizationPresentation = Object.freeze({
    present(authorizationUrl: string, context: PresentationContext): unknown {
      const opened = current;
      if (opened === undefined) return undefined;
      const answer = adopt(() => provide(authorizationUrl, context.signal));
      void answer.catch(() => undefined);
      opened.hand(answer);
      return undefined;
    },
  });

  return Object.freeze({ presentation, transport });
}
