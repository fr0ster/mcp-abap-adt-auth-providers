/**
 * The one owner of a provider's four moments (rule 1): each runs
 * inside `guard`, so whatever a provider's body, a collaborator or a target
 * throws becomes a minted refusal, and no moment ever rejects.
 *
 * Nothing a subclass controls is evaluated outside the boundary: the
 * operations live in an ECMAScript private field, captured and validated
 * once at construction (a throwing getter or a value off the list is the
 * moment's fixed fallback); `grant()` and the `on…` dispatch are called
 * inside `guard`'s `try`, which reads the grant once and normalises the
 * body's answer (`classifyOutcome`): an unminted refusal does not pass.
 */

import { guard, isOperation } from '@mcp-abap-adt/auth-errors';
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

/** Fixed, used when a configured operation cannot be read or is off the list. */
const FALLBACK: MomentOperations = Object.freeze({
  prepare: 'preparing',
  establish: 'establishing',
  authorize: 'authorizing',
  rejected: 'reading-rejection',
});

const MOMENTS: readonly Moment[] = [
  'prepare',
  'establish',
  'authorize',
  'rejected',
];

/** Each entry read once, guarded, checked against the operations. */
function validatedMoments(moments: unknown): MomentOperations {
  const read = (moment: Moment): Operation => {
    try {
      const value =
        moments !== null && typeof moments === 'object'
          ? (moments as Record<Moment, unknown>)[moment]
          : undefined;
      return isOperation(value) ? value : FALLBACK[moment];
    } catch {
      return FALLBACK[moment];
    }
  };
  const validated: Partial<Record<Moment, Operation>> = {};
  for (const moment of MOMENTS) validated[moment] = read(moment);
  return Object.freeze({ ...FALLBACK, ...validated });
}

/**
 * The base every provider of this package extends, exported for a consumer
 * writing a provider of its own: it implements the four moments, a subclass
 * implements `on…`.
 */
export abstract class AuthProviderBase implements IAuthProvider {
  abstract readonly kind: string;

  /** Base-owned, captured and validated once: no subclass can override it. */
  readonly #moments: MomentOperations;

  protected constructor(moments: MomentOperations) {
    this.#moments = validatedMoments(moments);
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
