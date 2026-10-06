/**
 * TEMPORARY — removed in Task 27 of the error-contract plan, when the direct
 * dependency moves to interfaces-auth 6.0.0 and every name here comes from
 * interfaces-auth / auth-errors themselves (Decision D6).
 *
 * Until then this package stays on interfaces-auth 4.x as a direct
 * dependency, while auth-errors brings 6.0.0 nested. The 6.0.0 names are
 * derived here from auth-errors' own signatures — never from a second,
 * aliased copy of interfaces-auth, whose `minted` symbol would be another.
 *
 * C1: a minted error's `hint?: string | undefined` does not assign to the
 * 4.x refusal's `hint?: string` under `exactOptionalPropertyTypes`, so a
 * 5.x outcome reaches a 4.x-typed return only through `toLegacyOutcome`.
 */
import type {
  AuthErrorBuilders,
  classify,
  guard,
} from '@mcp-abap-adt/auth-errors';
import type {
  AuthOutcome as LegacyAuthOutcome,
  IAuthRefusal as LegacyAuthRefusal,
} from '@mcp-abap-adt/interfaces-auth';

/** interfaces-auth 6.0.0's `IAuthProviderError`, as auth-errors returns it. */
export type IAuthProviderError = ReturnType<typeof classify>;

/** interfaces-auth 6.0.0's `Operation`, as auth-errors takes it. */
export type Operation = Parameters<typeof classify>[1];

/** interfaces-auth 6.0.0's `AuthOutcome`, as auth-errors answers it. */
export type AuthOutcome = Awaited<ReturnType<typeof guard>>;

/** interfaces-auth 6.0.0's `OAuth2GrantType`, as auth-errors takes it. */
export type OAuth2GrantType = NonNullable<Parameters<typeof classify>[2]>;

/** interfaces-auth 6.0.0's `TlsFailureCode`, as the `tls` builder takes it. */
export type TlsFailureCode = Parameters<AuthErrorBuilders['tls']>[0]['code'];

/** The hint key absent or a string: the error is a 4.x refusal as it is. */
function isLegacyShaped(
  error: IAuthProviderError,
): error is IAuthProviderError & LegacyAuthRefusal {
  return !('hint' in error) || typeof error.hint === 'string';
}

/**
 * The minted error itself when it is already a 4.x refusal — always, since a
 * builder omits an absent key — so `kind`, `facts` and identity survive;
 * otherwise `{ reason }`, never a `hint: undefined` key.
 */
export function toLegacyRefusal(error: IAuthProviderError): LegacyAuthRefusal {
  if (isLegacyShaped(error)) return error;
  return { reason: error.reason };
}

/** A 5.x outcome as a 4.x one, its refusal through `toLegacyRefusal`. */
export function toLegacyOutcome(outcome: AuthOutcome): LegacyAuthOutcome {
  if (outcome.ok) return outcome;
  return { ok: false, refusal: toLegacyRefusal(outcome.refusal) };
}
