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

/** interfaces-auth 6.0.0's `SamlAssertionError`: every `saml-assertion` variant. */
export type SamlAssertionError = Extract<
  IAuthProviderError,
  { kind: 'saml-assertion' }
>;

/** interfaces-auth 6.0.0's `AssertionRule` (Appendix B's 56 rule ids). */
export type AssertionRule = SamlAssertionError['variant'];

/** interfaces-auth 6.0.0's `AssertionCheck`, fixed by each rule. */
export type AssertionCheck = SamlAssertionError['facts']['check'];

/** interfaces-auth 6.0.0's `CredentialKind`, as `credential-refused` takes it. */
export type CredentialKind = Parameters<
  AuthErrorBuilders['credential-refused']
>[0]['credential'];

/** interfaces-auth 6.0.0's `ConfigurationError`: every `configuration` case. */
export type ConfigurationError = Extract<
  IAuthProviderError,
  { kind: 'configuration' }
>;

/** interfaces-auth 6.0.0's `ConfigField`: a field a configuration error names. */
export type ConfigField = ConfigurationError['facts']['fields'][number];

/** interfaces-auth 6.0.0's `ClientCertificateProblem`. */
export type ClientCertificateProblem = Parameters<
  AuthErrorBuilders['client-certificate']
>[0]['problem'];

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
 * auth-errors' `guard`, typed for this package's 4.x `IAuthProvider` (C1).
 * The grant is read **once**: `grant` is wrapped in a memoising thunk that
 * auth-errors' `guard` calls inside its boundary (a throw, or a rejecting
 * promise it answers, is guard's to handle); the body receives that same
 * thunk, so the bridge and the fallback reuse the value and never call
 * `grant` again. The body may still answer a 4.x outcome: `classifyOutcome`
 * is the one assertion-free way to the 5.x type, normalising it exactly as
 * `guard` does (an unminted refusal becomes `unknown` with the operation and
 * the grant read). The answer reaches the caller through `toLegacyOutcome`,
 * the minted error itself. Never rejects. Task 27: `AuthProviderBase`
 * imports `guard` from auth-errors.
 */
export function guard(
  operation: Operation,
  body: (grant: () => unknown) => AnyOutcome | Promise<AnyOutcome>,
  grant?: () => unknown,
): Promise<LegacyAuthOutcome> {
  let read = false;
  let value: unknown;
  const once = (): unknown => {
    if (!read) {
      read = true;
      value = grant?.();
    }
    return value;
  };
  return guardOf6(
    operation,
    async () => {
      const answer = await body(once);
      const kept = once();
      return classifyOutcome(
        answer,
        authError.unknown({
          operation,
          ...(isGrant(kept) ? { grant: kept } : {}),
        }),
      );
    },
    once,
  ).then(toLegacyOutcome);
}
