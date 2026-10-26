/**
 * The composer: one authorization strategy from a
 * presentation, a transport and a protocol. It has no default part and no
 * default endpoint — the named compositions are the only place today's
 * values live.
 *
 * One authorization, in this order: open the transport; build the URL
 * from the redirect the channel advertises; `begin` the protocol on that
 * URL; arm the channel with the composer's judge; present the URL (not
 * awaited); wait. The judge the channel gets latches the first terminal
 * verdict — `accept` with its payload, or `end` with its error —
 * synchronously, before any response is flushed: every later answer
 * is refused `already-answered`, and the authorization settles with what
 * was latched. The payload returned is the one the protocol accepted, never
 * anything a transport hands back.
 *
 * `authorize` settles only once the transport's `open` has settled — the
 * port free, the reader closed — and only then is it free for the next
 * call: the drain (`attempt.exclusive`) waits for exactly this.
 * An overlapping `authorize` is `busy`; `dispose()` ends the call in flight
 * and resolves once it has settled.
 */

import {
  authError,
  isAuthProviderFailure,
  logFields,
  readFailure,
} from '@mcp-abap-adt/auth-errors';
import type {
  AnswerJudge,
  AnswerTransportOptions,
  AnswerVerdict,
  AuthorizationOutcome,
  AuthorizationRequest,
  IAnswerChannel,
  IAnswerTransport,
  IAuthorizationPresentation,
  IAuthorizationProtocol,
  IAuthorizationStrategy,
  InteractiveLoginStrategy,
  PasteWords,
  PresentationContext,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { whenRejected } from '../auth/attempt';
import { misconfigured } from '../auth/configuration';
import {
  abortedLogin,
  failedLogin,
  loginFailure,
} from '../auth/interactiveLogin';
import { logQuietly } from '../auth/tokenRequest';
import { checkedEndpoint } from './transport/endpoint';
import { endFailure } from './transport/endVerdict';

export interface ComposedAuthorization<TPayload> {
  readonly presentation: IAuthorizationPresentation;
  readonly transport: IAnswerTransport;
  readonly protocol: IAuthorizationProtocol<TPayload>;
  /** Ends every login of this strategy, beside the request's signal. */
  readonly signal?: AbortSignal | undefined;
  /**
   * The endpoint path the redirect arrives at — required, no default; the
   * named compositions pass `'/callback'`. It must survive URL parsing
   * unchanged and is not one of the listener's own routes (`/`,
   * `/submit`): else `configuration` `invalid-value` `endpoint`.
   */
  readonly endpoint: string;
}

/** A composed strategy: an `IAuthorizationStrategy` that can be disposed. */
export type ComposedStrategy<TPayload> = IAuthorizationStrategy<TPayload> & {
  dispose(): Promise<void>;
};

/** The protocol's descriptor, read once, as typed. */
interface ProtocolRead {
  readonly redirect: 'required' | 'unused';
  readonly callbackMethods: readonly ('GET' | 'POST')[];
  readonly paste: PasteWords | undefined;
}

function readProtocol<TPayload>(
  protocol: IAuthorizationProtocol<TPayload>,
): ProtocolRead {
  const { redirect, callbackMethods, paste } = protocol;
  // Each method once, in the protocol's order.
  const methods = [...new Set(callbackMethods)];
  return {
    redirect,
    callbackMethods: Object.freeze(methods),
    paste:
      paste === undefined
        ? undefined
        : Object.freeze({
            prompt: paste.prompt,
            instructions: paste.instructions,
          }),
  };
}

/** A value adopted as `await` would, a synchronous throw as a rejection. */
const adopt = <T>(run: () => T | Promise<T>): Promise<T> =>
  new Promise<T>((resolve) => resolve(run()));

const ALREADY_ANSWERED: AnswerVerdict<never> = Object.freeze({
  verdict: 'refuse',
  reason: 'already-answered',
});

/** The first terminal verdict of one authorization. */
type Latched =
  | { readonly kind: 'accept'; readonly payload: unknown }
  | { readonly kind: 'end'; readonly error: unknown };

/**
 * A protocol's verdict, every field read once: what to latch, and the fresh
 * frozen verdict the transport gets. May throw (a getter): the caller's
 * boundary takes it as the judge's own throw.
 */
function readVerdict(verdict: AnswerVerdict<unknown>): {
  readonly latch?: Latched;
  readonly verdict: AnswerVerdict<unknown>;
} {
  const kind = verdict.verdict;
  if (kind === 'accept') {
    const payload = verdict.payload;
    return {
      latch: { kind: 'accept', payload },
      verdict: Object.freeze({ verdict: 'accept', payload }),
    };
  }
  if (kind === 'end') {
    const failure = endFailure(verdict.error);
    const shown = verdict.shown;
    return {
      latch: { kind: 'end', error: failure },
      verdict: Object.freeze({ verdict: 'end', error: failure.error, shown }),
    };
  }
  return {
    verdict: Object.freeze({ verdict: 'refuse', reason: verdict.reason }),
  };
}

/** One `authorize` in flight. */
interface Call {
  readonly controller: AbortController;
  /** Settles once the call has (after its transport's `open`). */
  readonly done: Promise<void>;
}

/** Whether a thrown value is an `interactive-login` `aborted` failure. */
function isAbortedFailure(error: unknown): boolean {
  const read = readFailure(error, 'browser-login');
  return read.kind === 'interactive-login' && read.facts.outcome === 'aborted';
}

export function composeAuthorization<TPayload>(
  parts: ComposedAuthorization<TPayload>,
): ComposedStrategy<TPayload> {
  // A typed copy: the options are read once, here.
  const own = { ...parts };
  const endpoint = checkedEndpoint(own.endpoint);
  const { presentation, transport, protocol } = own;
  const strategy: InteractiveLoginStrategy = transport.label;
  const described = readProtocol(protocol);
  const optionSignal = own.signal;

  let disposed = false;
  let current: Call | undefined;

  async function authorize(
    request: AuthorizationRequest,
  ): Promise<AuthorizationOutcome<TPayload>> {
    if (disposed) throw loginFailure({ outcome: 'disposed', strategy });
    // A transport holds a port or a reader: one authorization at a time.
    if (current !== undefined) throw loginFailure({ outcome: 'busy' });

    const controller = new AbortController();
    // Aborted once this call has ended: a presentation that answers later
    // prompts and logs nothing.
    const ended = new AbortController();
    const requestSignal = request.signal;
    const relay = () => controller.abort();
    optionSignal?.addEventListener('abort', relay, { once: true });
    requestSignal?.addEventListener('abort', relay, { once: true });
    if (optionSignal?.aborted || requestSignal?.aborted) controller.abort();
    const logger: ILogger | undefined = request.logger;
    let latched: Latched | undefined;
    /**
     * What `use` returned, once it has: the only outcome this call answers.
     * Whatever `open` itself resolves with — a transport that never called
     * `use`, or settled while it was still running — is never taken.
     */
    let kept: AuthorizationOutcome<TPayload> | undefined;

    /** The judge the channel gets: the first terminal verdict latched. */
    const latching =
      (judge: AnswerJudge<TPayload>): AnswerJudge<unknown> =>
      (answer) => {
        if (latched !== undefined || ended.signal.aborted) {
          return ALREADY_ANSWERED;
        }
        // The judge's call and every read of its verdict share one
        // boundary: a verdict whose field throws ends the login as a judge
        // that throws does.
        let read: {
          readonly latch?: Latched;
          readonly verdict: AnswerVerdict<unknown>;
        };
        try {
          read = readVerdict(judge(answer));
        } catch (error) {
          // A judge that throws ends the login: the transport answers its
          // fixed 500 page; nothing of the throw goes anywhere.
          latched = {
            kind: 'end',
            error: isAuthProviderFailure(error) ? error : failedLogin(error),
          };
          throw failedLogin(undefined);
        }
        if (read.latch !== undefined) latched = read.latch;
        return read.verdict;
      };

    const use = async (
      channel: IAnswerChannel,
    ): Promise<AuthorizationOutcome<TPayload>> => {
      const redirectUri = channel.redirectUri;
      // A protocol whose URL carries a redirect needs one from the channel.
      if (described.redirect === 'required' && redirectUri === undefined) {
        throw misconfigured(
          authError.configuration({
            case: 'required-fields-missing',
            fields: ['redirectUri'],
          }),
        );
      }
      // A builder's throw passes as it is (a configuration failure, OIDC
      // discovery).
      const url = await request.buildAuthorizationUrl(redirectUri ?? '');
      // Aborted while the URL was built: nothing is armed or shown.
      if (controller.signal.aborted) throw abortedLogin(strategy);
      const judge = protocol.begin(url);
      // Armed after `begin`, before the URL is shown: until now the
      // channel refused every answer.
      const armed = channel.arm(latching(judge));

      // Presented, not awaited: a failure is logged in fixed
      // words and the login keeps waiting; the fallback is the
      // presentation's own. Once the call has ended, nothing.
      const failedPresentation = (error: unknown) => {
        if (ended.signal.aborted) return;
        const fields = logFields(
          readFailure(error, 'presenting-authorization-url'),
        );
        logQuietly(() =>
          logger?.error(
            `Failed to present the authorization URL: ${fields.error}`,
            fields,
          ),
        );
      };
      const { waitingOn, routeHint } = channel;
      const context: PresentationContext = Object.freeze({
        redirectUri,
        waitingOn,
        routeHint,
        signal: AbortSignal.any([controller.signal, ended.signal]),
        logger,
      });
      let presented: unknown;
      try {
        presented = presentation.present(url, context);
      } catch (error) {
        failedPresentation(error);
      }
      whenRejected(presented, failedPresentation);

      try {
        await armed.answer();
      } catch (error) {
        if (latched?.kind === 'end') throw latched.error;
        throw error;
      }
      // Settled with what was latched, never with what `answer()` gave.
      if (latched?.kind === 'end') throw latched.error;
      if (latched?.kind !== 'accept') throw failedLogin(undefined);
      const outcome: AuthorizationOutcome<TPayload> = {
        payload: latched.payload as TPayload,
        redirectUri: redirectUri ?? '',
      };
      kept = outcome;
      return outcome;
    };

    const options: AnswerTransportOptions = Object.freeze({
      signal: controller.signal,
      logger,
      paste: described.paste,
      callbackMethods: described.callbackMethods,
      endpoint,
    });
    // Started in this turn, and `current` set in this turn: a `dispose`
    // landing at once finds the call and aborts it.
    const run = (async (): Promise<AuthorizationOutcome<TPayload>> => {
      // An already-aborted signal is honoured before anything opens.
      if (controller.signal.aborted) throw abortedLogin(strategy);
      // Awaited for its settlement only: `open` settles once released.
      await adopt(() => transport.open(options, use));
      if (kept === undefined) throw failedLogin(undefined);
      return kept;
    })();
    const call: Call = {
      controller,
      done: run.then(
        () => undefined,
        () => undefined,
      ),
    };
    current = call;

    try {
      return await run;
    } catch (error) {
      if (controller.signal.aborted) {
        // Disposal ended it; else the consumer's or the attempt's abort —
        // the transport's own failure keeps its tally.
        const signalled =
          optionSignal?.aborted === true || requestSignal?.aborted === true;
        if (disposed && !signalled) {
          throw loginFailure({ outcome: 'disposed', strategy });
        }
        throw isAbortedFailure(error) ? error : abortedLogin(strategy);
      }
      if (latched?.kind === 'end') throw latched.error;
      // A failure already built — the composer's, the transport's, the
      // protocol's, the URL builder's — is relayed as it is.
      if (isAuthProviderFailure(error)) throw error;
      throw failedLogin(error);
    } finally {
      optionSignal?.removeEventListener('abort', relay);
      requestSignal?.removeEventListener('abort', relay);
      ended.abort();
      // Cleared only now: `open` has settled, the transport is released.
      if (current === call) current = undefined;
    }
  }

  return Object.freeze({
    authorize,
    /**
     * Idempotent; ends the authorization in flight and resolves once it has
     * settled — its port free, its reader closed.
     */
    async dispose(): Promise<void> {
      disposed = true;
      const pending = current;
      if (pending === undefined) return;
      pending.controller.abort();
      await pending.done;
    },
  });
}
