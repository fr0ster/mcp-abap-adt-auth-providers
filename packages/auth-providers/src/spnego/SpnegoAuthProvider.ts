/**
 * SPNego (Kerberos) over HTTP: every request carries `Authorization:
 * Negotiate <token>`, a token the consumer's source makes afresh for the
 * service principal — a Kerberos authenticator is single-use against a
 * service that checks for replay, so nothing is kept between requests.
 *
 * The source answers facts, never errors (`INegotiateTokenSource`): a token,
 * or a problem from a closed list, which this provider mints into a `spnego`
 * refusal. Anything else a source does — a throw, a foreign thenable, an
 * answer of another shape — is `unknown` with the moment's operation, its
 * value read nowhere. A token is checked before it is written: NTLM (raw, or
 * inside a SPNEGO token, as Windows' Negotiate falls back) is `ntlm-token`,
 * anything neither Kerberos nor NTLM `token-unreadable`.
 *
 * No collaborator is defaulted (rule 7): the consumer composes the source.
 * No token and no service principal reaches a refusal or a log line.
 */

import {
  authError,
  createParties,
  isNegotiateSourceProblem,
  logFields,
  OK,
} from '@mcp-abap-adt/auth-errors';
import type {
  AuthOutcome,
  IAuthRefusal,
  IAuthRejection,
  INegotiateTokenSource,
  IRequestTarget,
  NegotiateSourceProblem,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { AuthProviderBase } from '../auth/AuthProviderBase';
import { throwIfAborted, untilAborted } from '../auth/attempt';
import {
  misconfigured,
  ownOptions,
  requiredFieldsMissing,
} from '../auth/configuration';
import { isPlainPromise, markHandled } from '../auth/handled';
import { readSafely } from '../auth/knownCodes';
import { refuseFor } from '../auth/rejection';
import { logQuietly } from '../auth/tokenRequest';
import { readNegotiateToken } from './negotiateToken';

export interface SpnegoAuthProviderConfig {
  /**
   * The GSS host-based name of the service, `service@host`
   * (`HTTP@sap.example.com`). Required; not the Kerberos form
   * `HTTP/host@REALM`.
   */
  servicePrincipal: string;
  /** Where each token comes from. Required, never defaulted. */
  tokenSource: INegotiateTokenSource;
  logger?: ILogger | undefined;
  /**
   * The first attached party, as `attach(signal)` right after construction.
   * The source is handed a signal that aborts when every attached party has
   * aborted; with none live, a moment waits for the source. No timeout of
   * this package's choosing.
   */
  signal?: AbortSignal | undefined;
}

type TokenOperation =
  | 'obtaining-negotiate-token'
  | 'presenting-negotiate-token';

type Obtained =
  | { readonly ok: true; readonly token: string }
  | { readonly ok: false; readonly refusal: IAuthRefusal };

const isLetter = (c: string) =>
  (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
const isDigit = (c: string) => c >= '0' && c <= '9';
const isNameChar = (c: string) => isLetter(c) || isDigit(c) || c === '-';

/**
 * `service@host` and nothing else (spec §4.1): exactly one `@`; the service
 * an ASCII letter, then ASCII letters, digits or `-`; the host labels of
 * ASCII letters, digits or `-`, none starting or ending with `-`, joined by
 * single dots. Plain code, no regular expression.
 */
function isHostBasedName(value: string): boolean {
  const at = value.indexOf('@');
  if (at <= 0 || at !== value.lastIndexOf('@')) return false;
  const service = value.slice(0, at);
  const host = value.slice(at + 1);
  if (!isLetter(service[0] ?? '')) return false;
  for (const c of service) if (!isNameChar(c)) return false;
  if (host === '') return false;
  for (const label of host.split('.')) {
    if (label === '' || label[0] === '-' || label.at(-1) === '-') return false;
    for (const c of label) if (!isNameChar(c)) return false;
  }
  return true;
}

/** A source's problem, minted with the operation: one literal per builder call. */
function sourceRefusal(
  problem: NegotiateSourceProblem,
  operation: TokenOperation,
): IAuthRefusal {
  switch (problem) {
    case 'no-credential':
      return authError.spnego<'no-credential'>({
        problem: 'no-credential',
        operation,
      });
    case 'service-unknown':
      return authError.spnego<'service-unknown'>({
        problem: 'service-unknown',
        operation,
      });
    case 'kdc-unreachable':
      return authError.spnego<'kdc-unreachable'>({
        problem: 'kdc-unreachable',
        operation,
      });
    case 'clock-skew':
      return authError.spnego<'clock-skew'>({
        problem: 'clock-skew',
        operation,
      });
    case 'binding-unavailable':
      return authError.spnego<'binding-unavailable'>({
        problem: 'binding-unavailable',
        operation,
      });
    case 'source-failed':
      return authError.spnego<'source-failed'>({
        problem: 'source-failed',
        operation,
      });
    case 'mechanism-unsupported':
      return authError.spnego<'mechanism-unsupported'>({
        problem: 'mechanism-unsupported',
        operation,
      });
  }
}

export class SpnegoAuthProvider extends AuthProviderBase {
  readonly kind = 'spnego';
  private readonly servicePrincipal: string;
  private readonly tokenSource: INegotiateTokenSource;
  private readonly logger?: ILogger | undefined;
  private readonly parties = createParties();

  constructor(config: SpnegoAuthProviderConfig) {
    super({
      prepare: 'obtaining-negotiate-token',
      establish: 'establishing',
      authorize: 'presenting-negotiate-token',
      rejected: 'reading-rejection',
    });
    const own =
      ownOptions<Partial<Record<keyof SpnegoAuthProviderConfig, unknown>>>(
        config,
      );
    const servicePrincipal = own.servicePrincipal;
    const tokenSource = own.tokenSource;
    const missing: string[] = [];
    if (servicePrincipal === undefined) missing.push('servicePrincipal');
    if (
      tokenSource === null ||
      typeof tokenSource !== 'object' ||
      typeof readSafely(tokenSource, 'token') !== 'function'
    ) {
      missing.push('tokenSource');
    }
    if (missing.length > 0) throw requiredFieldsMissing(missing);
    if (
      typeof servicePrincipal !== 'string' ||
      !isHostBasedName(servicePrincipal)
    ) {
      // The value is never echoed: the field alone is named.
      throw misconfigured(
        authError.configuration({
          case: 'invalid-value',
          fields: ['servicePrincipal'],
        }),
      );
    }
    this.servicePrincipal = servicePrincipal;
    this.tokenSource = tokenSource as INegotiateTokenSource;
    this.logger = own.logger as ILogger | undefined;
    // The config's signal is the first party; an aborted one adds nothing.
    if (own.signal !== undefined) {
      this.parties.attach(own.signal as AbortSignal);
    }
  }

  /**
   * Attaches a party sharing this provider: a moment waits on the parties
   * live at its start and any attached while it runs, and ends `aborted`
   * when all of them have aborted. Released when its signal aborts or by the
   * returned `detach()`.
   */
  attach(signal: AbortSignal): () => void {
    return this.parties.attach(signal);
  }

  /** One token, checked and dropped: a connect fails before any request. */
  protected async onPrepare(): Promise<AuthOutcome> {
    const obtained = await this.obtain('obtaining-negotiate-token');
    return obtained.ok ? OK : { ok: false, refusal: obtained.refusal };
  }

  /** SPNego has nothing for a logon (rule 3). */
  protected onEstablish(): AuthOutcome {
    return OK;
  }

  /** A new token for every request, never one obtained before. */
  protected async onAuthorize(request: IRequestTarget): Promise<AuthOutcome> {
    const obtained = await this.obtain('presenting-negotiate-token');
    if (!obtained.ok) return { ok: false, refusal: obtained.refusal };
    // A target answering a rejecting promise raises nothing (rule 1).
    markHandled(request.header('Authorization', `Negotiate ${obtained.token}`));
    return OK;
  }

  /** A 401 blames the ticket; renewing is the next request's fresh token. */
  protected onRejected(rejection: IAuthRejection): AuthOutcome {
    return refuseFor(rejection, 'kerberos-ticket');
  }

  /** The source asked once, with the moment's parties' signal; its answer read. */
  private async obtain(operation: TokenOperation): Promise<Obtained> {
    const waiter = this.parties.waiterSignal();
    try {
      const signal = waiter?.signal;
      throwIfAborted(signal);
      const answer = await this.ask(signal);
      // A source that ignored the abort: its answer is dropped.
      throwIfAborted(signal);
      const obtained = this.read(answer, operation);
      if (!obtained.ok) {
        const fields = logFields(obtained.refusal);
        logQuietly(() =>
          this.logger?.debug('no SPNego token to present', fields),
        );
      }
      return obtained;
    } finally {
      waiter?.release();
    }
  }

  /**
   * The source's answer, or `undefined` when it threw, rejected or answered
   * anything but a plain native promise (a foreign `then` is never called).
   * Settles at the abort, whether or not the source honours the signal.
   */
  private async ask(signal: AbortSignal | undefined): Promise<unknown> {
    const source = this.tokenSource;
    const token = readSafely(source, 'token');
    if (typeof token !== 'function') return undefined;
    let pending: unknown;
    try {
      pending = Reflect.apply(token, source, [
        this.servicePrincipal,
        { signal },
      ]);
    } catch {
      return undefined;
    }
    if (!isPlainPromise(pending)) return undefined;
    try {
      return await untilAborted(pending, signal);
    } catch {
      throwIfAborted(signal);
      return undefined;
    }
  }

  /** The answer field by field; the token checked before it is presented. */
  private read(answer: unknown, operation: TokenOperation): Obtained {
    const ok = readSafely(answer, 'ok');
    if (ok === false) {
      const problem = readSafely(answer, 'problem');
      return isNegotiateSourceProblem(problem)
        ? { ok: false, refusal: sourceRefusal(problem, operation) }
        : { ok: false, refusal: authError.unknown({ operation }) };
    }
    const token = ok === true ? readSafely(answer, 'token') : undefined;
    if (typeof token !== 'string') {
      return { ok: false, refusal: authError.unknown({ operation }) };
    }
    switch (readNegotiateToken(token)) {
      case 'kerberos':
        return { ok: true, token };
      case 'ntlm':
        return {
          ok: false,
          refusal: authError.spnego<'ntlm-token'>({
            problem: 'ntlm-token',
            operation,
          }),
        };
      case 'unreadable':
        return {
          ok: false,
          refusal: authError.spnego<'token-unreadable'>({
            problem: 'token-unreadable',
            operation,
          }),
        };
    }
  }
}
