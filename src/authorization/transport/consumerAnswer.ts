/**
 * The transports where the consumer's code returns the answer (spec §6d.2,
 * §6d.3.2): `consumerAnswer({ receive })`, and the pair
 * `consumerHandoff({ provide })` for a consumer whose one call shows the URL
 * and returns the answer. Neither binds anything nor advertises a redirect
 * of its own (C4); `open` settles at the abort itself — it holds nothing to
 * release. A refusal ends `unreadable-input`: the consumer's code is not
 * asked twice.
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
import { misconfigured, ownOptions } from '../../auth/configuration';
import { abortedLogin, loginFailure } from '../../auth/interactiveLogin';
import { readSafely } from '../../auth/knownCodes';
import { asAbortSignal } from '../../auth/signalledRequest';
import { consumerRedirect } from './consumerRedirect';
import { endFailure, verdictOf } from './endVerdict';

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

/** One text, judged once: accept resolves, refuse and end reject. */
function judgeOnce(judge: AnswerJudge<unknown>, text: unknown): void {
  // No string (absent, null, anything else): nothing was given.
  if (typeof text !== 'string') throw loginFailure({ outcome: 'no-input' });
  const verdict = verdictOf(judge, { via: 'consumer', text });
  const kind = readSafely(verdict, 'verdict');
  if (kind === 'accept') return;
  if (kind === 'end') {
    throw endFailure(readSafely(verdict, 'error'));
  }
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
  answerFor: (signal: AbortSignal) => Promise<unknown>,
  onOpen?: () => () => void,
): IAnswerTransport {
  return Object.freeze({
    label: 'consumer' as const,
    async open<TReturn>(
      openOptions: AnswerTransportOptions,
      use: (channel: IAnswerChannel) => Promise<TReturn>,
    ): Promise<TReturn> {
      const given =
        ownOptions<Record<keyof AnswerTransportOptions, unknown>>(openOptions);
      const signal = asAbortSignal(given.signal);
      if (signal?.aborted) throw abortedLogin('consumer');
      const close = onOpen?.();
      let armed = false;
      const channel: IAnswerChannel = Object.freeze({
        redirectUri,
        arm(judge: AnswerJudge<unknown>): IArmedChannel {
          if (typeof judge !== 'function' || armed) {
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
  // Read once as own data: a hostile object throws nothing of its own.
  const own = ownOptions<Record<keyof ConsumerAnswerOptions, unknown>>(options);
  const redirectUri = consumerRedirect(own.redirectUri);
  const { receive } = own;
  if (typeof receive !== 'function') throw required('receive');
  return socketless(redirectUri, (signal) =>
    adopt(() => (receive as ReceiveAnswer)(signal)),
  );
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
  const own =
    ownOptions<Record<keyof ConsumerHandoffOptions, unknown>>(options);
  const redirectUri = consumerRedirect(own.redirectUri);
  const { provide } = own;
  if (typeof provide !== 'function') throw required('provide');

  /** The open in progress: where the presentation hands its answer. */
  let current:
    | { readonly hand: (answer: Promise<unknown>) => void }
    | undefined;

  const transport = socketless(
    redirectUri,
    // The answer `provide` returned, once the presentation has called it.
    () => handed,
    () => {
      let hand!: (answer: Promise<unknown>) => void;
      handed = new Promise<unknown>((resolve) => {
        hand = (answer) => resolve(answer);
      });
      const opened = { hand };
      current = opened;
      return () => {
        if (current === opened) current = undefined;
      };
    },
  );
  let handed: Promise<unknown> = Promise.resolve(undefined);

  const presentation: IAuthorizationPresentation = Object.freeze({
    present(authorizationUrl: string, context: PresentationContext): unknown {
      const opened = current;
      if (opened === undefined) return undefined;
      const signal = readSafely(context, 'signal');
      const answer = adopt(() =>
        (provide as ProvideAnswer)(
          authorizationUrl,
          asAbortSignal(signal) ?? never,
        ),
      );
      void answer.catch(() => undefined);
      opened.hand(answer);
      return undefined;
    },
  });

  return Object.freeze({ presentation, transport });
}
