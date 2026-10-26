/**
 * The one owner of a provider's four moments (rule 1): each runs
 * inside `guard`, so whatever a provider's body, a collaborator or a target
 * throws becomes a minted refusal, and no moment ever rejects.
 *
 * Nothing a subclass controls is evaluated outside the boundary: the
 * operations (typed `MomentOperations`) live in an ECMAScript private field,
 * copied once at construction; `grant()` and the `on…` dispatch are called
 * inside `guard`'s `try`, which reads the grant once and normalises the
 * body's answer (`classifyOutcome`): an unminted refusal does not pass.
 */

import { guard } from '@mcp-abap-adt/auth-errors';
import type {
  AuthOutcome,
  IAuthProvider,
  IAuthRejection,
  ILogonTarget,
  IRequestTarget,
  OAuth2GrantType,
  Operation,
} from '@mcp-abap-adt/interfaces-auth';

/** The four moments of the contract. */
export type Moment = 'prepare' | 'establish' | 'authorize' | 'rejected';

/** The operation each moment's refusals name. */
export type MomentOperations = Readonly<Record<Moment, Operation>>;

/**
 * The base every provider of this package extends, exported for a consumer
 * writing a provider of its own: it implements the four moments, a subclass
 * implements `on…`.
 */
export abstract class AuthProviderBase implements IAuthProvider {
  abstract readonly kind: string;

  /** Base-owned, captured once: no subclass can override it. */
  readonly #moments: MomentOperations;

  protected constructor(moments: MomentOperations) {
    this.#moments = Object.freeze({
      prepare: moments.prepare,
      establish: moments.establish,
      authorize: moments.authorize,
      rejected: moments.rejected,
    });
  }

  /** The grant a refusal names; read only inside `guard`'s boundary. */
  protected grant(): OAuth2GrantType | undefined {
    return undefined;
  }

  prepare(): Promise<AuthOutcome> {
    return guard(
      this.#moments.prepare,
      () => this.onPrepare(),
      () => this.grant(),
    );
  }

  establish(logon: ILogonTarget): Promise<AuthOutcome> {
    return guard(
      this.#moments.establish,
      () => this.onEstablish(logon),
      () => this.grant(),
    );
  }

  authorize(request: IRequestTarget): Promise<AuthOutcome> {
    return guard(
      this.#moments.authorize,
      () => this.onAuthorize(request),
      () => this.grant(),
    );
  }

  rejected(rejection: IAuthRejection): Promise<AuthOutcome> {
    return guard(
      this.#moments.rejected,
      () => this.onRejected(rejection),
      () => this.grant(),
    );
  }

  protected abstract onPrepare(): AuthOutcome | Promise<AuthOutcome>;
  protected abstract onEstablish(
    logon: ILogonTarget,
  ): AuthOutcome | Promise<AuthOutcome>;
  protected abstract onAuthorize(
    request: IRequestTarget,
  ): AuthOutcome | Promise<AuthOutcome>;
  protected abstract onRejected(
    rejection: IAuthRejection,
  ): AuthOutcome | Promise<AuthOutcome>;
}
