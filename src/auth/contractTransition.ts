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
import {
  type AuthErrorBuilders,
  authError,
  type classify,
  classifyOutcome,
  guard as guardOf6,
} from '@mcp-abap-adt/auth-errors';
import type {
  AuthOutcome as LegacyAuthOutcome,
  IAuthRefusal as LegacyAuthRefusal,
} from '@mcp-abap-adt/interfaces-auth';
import { isGrant } from './grants';

/** interfaces-auth 6.0.0's `IAuthProviderError`, as auth-errors returns it. */
export type IAuthProviderError = ReturnType<typeof classify>;

/** interfaces-auth 6.0.0's `Operation`, as auth-errors takes it. */
export type Operation = Parameters<typeof classify>[1];

/** interfaces-auth 6.0.0's `AuthOutcome`, as auth-errors answers it. */
export type AuthOutcome = Awaited<ReturnType<typeof guardOf6>>;

/** interfaces-auth 6.0.0's `OAuth2GrantType`, as auth-errors takes it. */
export type OAuth2GrantType = NonNullable<Parameters<typeof classify>[2]>;

/** interfaces-auth 6.0.0's `TlsFailureCode`, as the `tls` builder takes it. */
export type TlsFailureCode = Parameters<AuthErrorBuilders['tls']>[0]['code'];

/** interfaces-auth 6.0.0's `CredentialKind`, as `credential-refused` takes it. */
export type CredentialKind = Parameters<
  AuthErrorBuilders['credential-refused']
>[0]['credential'];

/** What a body may answer while modules move: a 5.x outcome, or a 4.x one. */
export type AnyOutcome = AuthOutcome | LegacyAuthOutcome;

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

/**
 * auth-errors' `guard`, typed for this package's 4.x `IAuthProvider` (C1):
 * the body may still answer a 4.x outcome — normalised by `classifyOutcome`
 * exactly as `guard` normalises any answer, an unminted refusal becoming the
 * fallback `guard` itself builds (`unknown` with the operation and the grant
 * read inside the boundary) — and the answer reaches the caller through
 * `toLegacyOutcome`, the minted error itself. Never rejects (`guard` does
 * not). Task 27: `AuthProviderBase` imports `guard` from auth-errors.
 */
export function guard(
  operation: Operation,
  body: () => AnyOutcome | Promise<AnyOutcome>,
  grant?: () => unknown,
): Promise<LegacyAuthOutcome> {
  return guardOf6(
    operation,
    async () => {
      const answer = await body();
      // Read again, inside the boundary: a throw is guard's to classify.
      const read = grant?.();
      return classifyOutcome(
        answer,
        authError.unknown({
          operation,
          ...(isGrant(read) ? { grant: read } : {}),
        }),
      );
    },
    grant,
  ).then(toLegacyOutcome);
}
