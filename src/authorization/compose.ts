/**
 * The composer (spec §6d.4): one authorization strategy from a
 * presentation, a transport and a protocol. It has no default part and no
 * default endpoint — the named compositions are the only place today's
 * values live.
 *
 * One authorization, in this order: open the transport; build the URL
 * from the redirect the channel advertises; `begin` the protocol on that
 * URL; arm the channel with the composer's judge; present the URL (not
 * awaited); wait. The judge the channel gets latches the first terminal
 * verdict — `accept` with its payload, or `end` with its error —
 * synchronously, before any response is flushed (C9): every later answer
 * is refused `already-answered`, and the authorization settles with what
 * was latched. The payload returned is the one the protocol accepted, never
 * anything a transport hands back.
 *
 * `authorize` settles only once the transport's `open` has settled — the
 * port free, the reader closed — and only then is it free for the next
 * call: the drain (spec §6b, `attempt.exclusive`) waits for exactly this.
 * An overlapping `authorize` is `busy`; `dispose()` ends the call in flight
 * and resolves once it has settled.
 */

import {
  authError,
  isAuthProviderFailure,
  isInteractiveLoginStrategy,
  logFields,
  readFailure,
} from '@mcp-abap-adt/auth-errors';
import type {
  AnswerJudge,
  AnswerRefusal,
  AnswerTransportOptions,
  AnswerVerdict,
  AuthorizationAnswer,
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
import { misconfigured, ownOptions } from '../auth/configuration';
import { onAnswerRejection } from '../auth/handled';
import {
  abortedLogin,
  failedLogin,
  loginFailure,
} from '../auth/interactiveLogin';
import { readSafely } from '../auth/knownCodes';
import { asAbortSignal, signalOf } from '../auth/signalledRequest';
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

type Part = 'presentation' | 'transport' | 'protocol';

const requiredMissing = (field: Part | 'endpoint') =>
  misconfigured(
    authError.configuration({
      case: 'required-fields-missing',
      fields: [field],
    }),
  );

const invalidPart = (field: Part) =>
  misconfigured(
    authError.configuration({ case: 'invalid-value', fields: [field] }),
  );

/** A function read off a part, guarded; else the part is unusable. */
function methodOf(
  part: unknown,
  name: string,
  field: Part,
): (...args: unknown[]) => unknown {
  const method = readSafely(part, name);
  if (typeof method !== 'function') throw invalidPart(field);
  return method as (...args: unknown[]) => unknown;
}

/** The protocol's descriptor, read once, guarded. */
interface ProtocolRead {
  readonly redirect: 'required' | 'unused';
  readonly callbackMethods: readonly ('GET' | 'POST')[];
  readonly paste: PasteWords | undefined;
  readonly begin: (...args: unknown[]) => unknown;
}

function readProtocol(protocol: unknown): ProtocolRead {
  const redirect = readSafely(protocol, 'redirect');
  if (redirect !== 'required' && redirect !== 'unused') {
    throw invalidPart('protocol');
  }
  const methods: ('GET' | 'POST')[] = [];
  const listed = readSafely(protocol, 'callbackMethods');
  if (Array.isArray(listed)) {
    try {
      for (const method of listed as unknown[]) {
        if (
          (method === 'GET' || method === 'POST') &&
          !methods.includes(method)
        ) {
          methods.push(method);
        }
      }
    } catch {
      // An unreadable list: no method.
    }
  }
  const paste = readSafely(protocol, 'paste');
  const prompt = readSafely(paste, 'prompt');
  const instructions = readSafely(paste, 'instructions');
  return {
    redirect,
    callbackMethods: Object.freeze(methods),
    paste:
      typeof prompt === 'string' && typeof instructions === 'string'
        ? Object.freeze({ prompt, instructions })
        : undefined,
    begin: methodOf(protocol, 'begin', 'protocol'),
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

/** One `authorize` in flight. */
interface Call {
  readonly controller: AbortController;
  /** Settles once the call has (after its transport's `open`). */
  readonly done: Promise<void>;
}

/** The logger a request carries, guarded. */
function loggerOf(request: unknown): ILogger | undefined {
  const logger = readSafely(request, 'logger');
  return logger !== null && typeof logger === 'object'
    ? (logger as ILogger)
    : undefined;
}

/** A string field of a channel, guarded. */
function channelText(channel: unknown, name: string): string | undefined {
  const value = readSafely(channel, name);
  return typeof value === 'string' ? value : undefined;
}

/** Whether a thrown value is an `interactive-login` `aborted` failure. */
function isAbortedFailure(error: unknown): boolean {
  const read = readFailure(error, 'browser-login');
  return read.kind === 'interactive-login' && read.facts.outcome === 'aborted';
}

export function composeAuthorization<TPayload>(
  parts: ComposedAuthorization<TPayload>,
): ComposedStrategy<TPayload> {
  // Read once as own data: a hostile object throws nothing of its own.
  const own =
    ownOptions<Partial<Record<keyof ComposedAuthorization<TPayload>, unknown>>>(
      parts,
    );
  for (const part of ['presentation', 'transport', 'protocol'] as const) {
    if (own[part] === undefined || own[part] === null) {
      throw requiredMissing(part);
    }
  }
  if (own.endpoint === undefined) throw requiredMissing('endpoint');
  const endpoint = checkedEndpoint(own.endpoint);
  const { presentation, transport, protocol } = own;
  const present = methodOf(presentation, 'present', 'presentation');
  const open = methodOf(transport, 'open', 'transport');
  const label = readSafely(transport, 'label');
  if (!isInteractiveLoginStrategy(label)) throw invalidPart('transport');
  const strategy: InteractiveLoginStrategy = label;
  const described = readProtocol(protocol);
  const optionSignal = asAbortSignal(own.signal);

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
    const requestSignal = signalOf(request);
    const relay = () => controller.abort();
    optionSignal?.addEventListener('abort', relay, { once: true });
    requestSignal?.addEventListener('abort', relay, { once: true });
    if (optionSignal?.aborted || requestSignal?.aborted) controller.abort();
    const logger = loggerOf(request);
    let latched: Latched | undefined;

    /** The judge the channel gets: the first terminal verdict latched (C9). */
    const latching =
      (judge: (answer: AuthorizationAnswer) => unknown): AnswerJudge<unknown> =>
      (answer) => {
        if (latched !== undefined || ended.signal.aborted) {
          return ALREADY_ANSWERED;
        }
        let verdict: unknown;
        try {
          verdict = judge(answer);
        } catch (error) {
          // A judge that throws ends the login: the transport answers its
          // fixed 500 page; nothing of the throw goes anywhere.
          latched = {
            kind: 'end',
            error: isAuthProviderFailure(error) ? error : failedLogin(error),
          };
          throw failedLogin(undefined);
        }
        const kind = readSafely(verdict, 'verdict');
        if (kind === 'accept') {
          const payload = readSafely(verdict, 'payload');
          latched = { kind: 'accept', payload };
          return Object.freeze({ verdict: 'accept', payload });
        }
        if (kind === 'end') {
          const failure = endFailure(readSafely(verdict, 'error'));
          const shown = readSafely(verdict, 'shown');
          latched = { kind: 'end', error: failure };
          return Object.freeze({
            verdict: 'end',
            error: failure.error,
            shown: typeof shown === 'string' ? shown : undefined,
          });
        }
        if (kind === 'refuse') {
          const reason = readSafely(verdict, 'reason');
          return Object.freeze({
            verdict: 'refuse',
            reason: reason as AnswerRefusal,
          });
        }
        // No readable verdict: the login fails, as for a throw.
        latched = { kind: 'end', error: failedLogin(undefined) };
        throw failedLogin(undefined);
      };

    const use = async (
      channel: IAnswerChannel,
    ): Promise<AuthorizationOutcome<TPayload>> => {
      const redirectUri = channelText(channel, 'redirectUri');
      // A protocol whose URL carries a redirect needs one from the channel.
      if (described.redirect === 'required' && redirectUri === undefined) {
        throw misconfigured(
          authError.configuration({
            case: 'required-fields-missing',
            fields: ['redirectUri'],
          }),
        );
      }
      // A builder's throw passes as it is (E7, E8, E12, OIDC discovery).
      const url: unknown = await request.buildAuthorizationUrl(
        redirectUri ?? '',
      );
      // Aborted while the URL was built: nothing is armed or shown.
      if (controller.signal.aborted) throw abortedLogin(strategy);
      if (typeof url !== 'string') throw failedLogin(undefined);
      const judge = described.begin.call(protocol, url);
      if (typeof judge !== 'function') throw failedLogin(undefined);
      const arm = readSafely(channel, 'arm');
      if (typeof arm !== 'function') throw failedLogin(undefined);
      // Armed after `begin`, before the URL is shown: until now the
      // channel refused every answer.
      const armed: unknown = arm.call(
        channel,
        latching(judge as (answer: AuthorizationAnswer) => unknown),
      );
      const answer = readSafely(armed, 'answer');
      if (typeof answer !== 'function') throw failedLogin(undefined);

      // Presented, not awaited (spec §6d.5): a failure is logged in fixed
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
      const waitingOn = channelText(channel, 'waitingOn');
      const routeHint = channelText(channel, 'routeHint');
      const context: PresentationContext = Object.freeze({
        redirectUri,
        waitingOn,
        routeHint,
        signal: AbortSignal.any([controller.signal, ended.signal]),
        logger,
      });
      let presented: unknown;
      try {
        presented = present.call(presentation, url, context);
      } catch (error) {
        failedPresentation(error);
      }
      onAnswerRejection(presented, failedPresentation);

      try {
        await answer.call(armed);
      } catch (error) {
        if (latched?.kind === 'end') throw latched.error;
        throw error;
      }
      // Settled with what was latched, never with what `answer()` gave.
      if (latched?.kind === 'end') throw latched.error;
      if (latched?.kind !== 'accept') throw failedLogin(undefined);
      return {
        payload: latched.payload as TPayload,
        redirectUri: redirectUri ?? '',
      };
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
      return (await adopt(() =>
        open.call(transport, options, use),
      )) as AuthorizationOutcome<TPayload>;
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
