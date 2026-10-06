/**
 * The one owner of a provider's four moments (spec §8.1, rule 1): each runs
 * inside `guard`, so whatever a provider's body, a collaborator or a target
 * throws becomes a minted refusal, and no moment ever rejects.
 *
 * Nothing a subclass controls is evaluated outside the boundary: the
 * operations live in an ECMAScript private field, captured and validated
 * once at construction (a throwing getter or a value off the list is the
 * moment's fixed fallback); `grant()` and the `on…` dispatch are called
 * inside `guard`'s `try`.
 *
 * TRANSITION (Decision D6, removed in Task 27): `guard` is
 * `contractTransition`'s, typed for the 4.x `IAuthProvider`; `legacyBridge`
 * answers the class ladder's refusal for a body throwing one of this
 * package's error classes, which auth-errors' `classify` does not know.
 */

import { isOperation } from '@mcp-abap-adt/auth-errors';
import type {
  AuthOutcome,
  IAuthProvider,
  IAuthRejection,
  ILogonTarget,
  IRequestTarget,
} from '@mcp-abap-adt/interfaces-auth';
import {
  type AnyOutcome,
  guard,
  type OAuth2GrantType,
  type Operation,
} from './contractTransition';
import { isGrant } from './grants';
import { isLadderClass, refusalFor } from './refusal';

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
 * TRANSITION (removed in Task 27): a body throwing one of this package's
 * error classes answers the ladder's refusal, inside the boundary; anything
 * else is rethrown to `guard`'s `classify`. `grant` is the guard's memoised
 * read: its value, never a second call of the provider's `grant()`.
 */
async function legacyBridge(
  body: () => AnyOutcome | Promise<AnyOutcome>,
  operation: Operation,
  grant: () => unknown,
): Promise<AnyOutcome> {
  try {
    return await body();
  } catch (error) {
    if (!isLadderClass(error)) throw error;
    const read = grant();
    return refusalFor(error, {
      operation,
      ...(isGrant(read) ? { grant: read } : {}),
    });
  }
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
      (grant) =>
        legacyBridge(() => this.onPrepare(), this.#moments.prepare, grant),
      () => this.grant(),
    );
  }

  establish(logon: ILogonTarget): Promise<AuthOutcome> {
    return guard(
      this.#moments.establish,
      (grant) =>
        legacyBridge(
          () => this.onEstablish(logon),
          this.#moments.establish,
          grant,
        ),
      () => this.grant(),
    );
  }

  authorize(request: IRequestTarget): Promise<AuthOutcome> {
    return guard(
      this.#moments.authorize,
      (grant) =>
        legacyBridge(
          () => this.onAuthorize(request),
          this.#moments.authorize,
          grant,
        ),
      () => this.grant(),
    );
  }

  rejected(rejection: IAuthRejection): Promise<AuthOutcome> {
    return guard(
      this.#moments.rejected,
      (grant) =>
        legacyBridge(
          () => this.onRejected(rejection),
          this.#moments.rejected,
          grant,
        ),
      () => this.grant(),
    );
  }

  protected abstract onPrepare(): AnyOutcome | Promise<AnyOutcome>;
  protected abstract onEstablish(
    logon: ILogonTarget,
  ): AnyOutcome | Promise<AnyOutcome>;
  protected abstract onAuthorize(
    request: IRequestTarget,
  ): AnyOutcome | Promise<AnyOutcome>;
  protected abstract onRejected(
    rejection: IAuthRejection,
  ): AnyOutcome | Promise<AnyOutcome>;
}
