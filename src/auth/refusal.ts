/**
 * How a provider in this package answers Oops — the one place thrown values
 * become refusals (spec rule 2).
 *
 * A refusal never carries an error's message. `refusalFrom` first walks the
 * class ladder — each of this package's error classes to its auth-errors
 * builder (spec Appendix A.1) — then hands anything else to auth-errors'
 * `classify`, which keeps only allowlisted facts. The `what` a caller names
 * is mapped to the closed operation whose words are the same (A.8).
 *
 * TRANSITION (Decision D6): the ladder, `refusalFrom`, `loggedError` and
 * `refusalWords` are removed in Task 27; the outcome reaches its 4.x-typed
 * callers through `toLegacyOutcome`, the minted error itself.
 */

import {
  authError,
  classify,
  httpStatus,
  isAssertionCheck,
  isConfigField,
  isOAuthErrorCode,
  isSystemCode,
} from '@mcp-abap-adt/auth-errors';
import type { AuthOutcome, IAuthRefusal } from '@mcp-abap-adt/interfaces-auth';
import { DeviceCodePresentationError } from '../deviceCode/DeviceCodePresenter';
import { AssertionValidationError } from '../errors/AssertionValidationError';
import { CertificateMaterialError } from '../errors/CertificateMaterialError';
import {
  BasicClientIdError,
  ClientAuthenticationError,
  ClientAuthenticationResultError,
} from '../errors/ClientAuthenticationError';
import { TokenEndpointError } from '../errors/TokenEndpointError';
import {
  BrowserAuthError,
  RefreshError,
  ServiceKeyError,
  SessionDataError,
  TokenProviderError,
  ValidationError,
} from '../errors/TokenProviderErrors';
import { AuthorizationRefusedError } from './callbackScopeError';
import {
  type IAuthProviderError,
  type OAuth2GrantType,
  type Operation,
  toLegacyOutcome,
} from './contractTransition';
import { isGrant } from './grants';
import { integerStatus, readSafely } from './knownCodes';

export { OK } from '@mcp-abap-adt/auth-errors';
export { allowlistedCode, tlsFailureCode } from './knownCodes';

export function oops(reason: string, hint?: string): AuthOutcome {
  return hint === undefined
    ? { ok: false, refusal: { reason } }
    : { ok: false, refusal: { reason, hint } };
}

/** The operation a `what` names, with the grant of a token request. */
export interface OperationOf {
  readonly operation: Operation;
  readonly grant?: OAuth2GrantType;
}

/**
 * Each `what` this package passes, and the operation whose words are the
 * same (spec A.8): `<operation words> failed (…)` reads as 5.4.2's
 * `<what> failed (…)`.
 */
const OPERATION_OF_WHAT: Readonly<Record<string, Operation>> = Object.freeze({
  'the token request': 'token-request',
  'the refresh': 'refresh',
  onTokens: 'on-tokens-hook',
  'presenting the token': 'presenting-token',
  'presenting the certificate': 'presenting-certificate',
  'loading the certificate': 'loading-certificate',
  'writing the Authorization header': 'writing-authorization-header',
  'offering the logon parameters': 'offering-logon-parameters',
  'writing the session cookies': 'writing-session-cookies',
  'reading the rejection': 'reading-rejection',
  'the token source': 'token-source',
  'the probe': 'probing-snc-product',
  'the presenter': 'presenting-device-code',
  'the SAML token exchange': 'saml-token-exchange',
  'the SAML token refresh': 'saml-token-refresh',
  'the browser login': 'browser-login',
  'opening the browser': 'opening-browser',
});

const TOKEN_REQUEST = ' token request';

/**
 * The closed operation a `what` names — `<grant> token request` with its
 * grant, else the table above. A `what` this package does not use (a
 * consumer's own, through `refusalWords`) has no operation: it is the
 * unfamiliar one, its free text lost (spec L10).
 */
export function operationFor(what: string): OperationOf {
  if (what.endsWith(TOKEN_REQUEST)) {
    const grant = what.slice(0, -TOKEN_REQUEST.length);
    if (isGrant(grant)) return { operation: 'token-request', grant };
  }
  // Own keys only: `what` may be `constructor` or `__proto__`.
  const operation = Object.hasOwn(OPERATION_OF_WHAT, what)
    ? OPERATION_OF_WHAT[what]
    : undefined;
  return { operation: operation ?? 'unfamiliar-error' };
}

/** How many elements of `missingFields` are read at most. */
const MAX_FIELDS_READ = 64;

/**
 * The known config field names among `missing`, read element by element:
 * none of the array's own methods is called (an array may carry its own
 * `filter` or `join`), only values passing auth-errors' `isConfigField` are
 * kept, and at most MAX_FIELDS_READ elements are read — a Proxy array may
 * claim any length.
 */
function knownFields(missing: unknown): string {
  if (!Array.isArray(missing)) return '';
  const length = readSafely(missing, 'length');
  if (typeof length !== 'number' || !Number.isInteger(length)) return '';
  const names: string[] = [];
  for (let i = 0; i < Math.min(length, MAX_FIELDS_READ); i++) {
    const name = readSafely(missing, String(i));
    if (isConfigField(name) && !names.includes(name)) names.push(name);
  }
  return names.length ? `: ${names.join(', ')}` : '';
}

/** A refusal outcome of a minted error, typed for a 4.x caller. */
function refused(error: IAuthProviderError): AuthOutcome {
  return toLegacyOutcome({ ok: false, refusal: error });
}

/** Which certificate problem a CertificateMaterialError's flags say. */
function certificateProblem(
  error: unknown,
): 'incomplete' | 'expired' | 'unusable' {
  if (readSafely(error, 'incomplete') === true) return 'incomplete';
  return readSafely(error, 'expired') === true ? 'expired' : 'unusable';
}

/**
 * A TokenEndpointError's facts, each re-checked whoever built the error:
 * `refused` with an HTTP status, else `no-response` (A14).
 */
function requestFailed(error: unknown, of: OperationOf): IAuthProviderError {
  const status = httpStatus(readSafely(error, 'status'));
  const oauthError = readSafely(error, 'oauthError');
  const code = readSafely(error, 'code');
  return authError['request-failed']({
    ...of,
    problem: status === undefined ? 'no-response' : 'refused',
    ...(status === undefined ? {} : { status }),
    ...(isOAuthErrorCode(oauthError) ? { oauthError } : {}),
    ...(isSystemCode(code) ? { code } : {}),
  });
}

/**
 * Total (rule 1): reading a foreign error — a getter, a Proxy, an `instanceof`
 * whose prototype trap throws — never makes this throw; whatever does is
 * `unknown` with the operation (A1).
 */
export function refusalFrom(error: unknown, what: string): AuthOutcome {
  return refusalFor(error, operationFor(what));
}

/** `refusalFrom` for a closed operation: the ladder, then `classify`. Total. */
export function refusalFor(error: unknown, of: OperationOf): AuthOutcome {
  try {
    return ladder(error, of);
  } catch {
    return refused(authError.unknown(of));
  }
}

/** This package's error classes, the ladder's rungs (A.1's 13). */
const LADDER: ReadonlyArray<abstract new (...args: never[]) => unknown> = [
  DeviceCodePresentationError,
  AssertionValidationError,
  CertificateMaterialError,
  ClientAuthenticationResultError,
  ClientAuthenticationError,
  BasicClientIdError,
  BrowserAuthError,
  RefreshError,
  ValidationError,
  ServiceKeyError,
  SessionDataError,
  TokenProviderError,
  TokenEndpointError,
];

/**
 * Whether `error` is one of this package's classes — what auth-errors'
 * `classify` does not know. May throw (a Proxy's prototype trap): a caller
 * runs it inside a boundary.
 */
export function isLadderClass(error: unknown): boolean {
  return LADDER.some((rung) => error instanceof rung);
}

/**
 * Each class of this package, most specific first, to its builder (A.1); the
 * rest to `classify`. A3, A11 and A12 keep their 5.4.2 words unminted: their
 * class carries no `rule` / `case`, and A12 has no kind (removed in Task 27).
 */
function ladder(error: unknown, of: OperationOf): AuthOutcome {
  if (error instanceof DeviceCodePresentationError) {
    return refused(
      authError['interactive-login']({ outcome: 'device-code-not-shown' }),
    );
  }
  if (error instanceof AssertionValidationError) {
    // Read once: a getter could answer an allowed value to the test and
    // another to the interpolation.
    const value = readSafely(error, 'check');
    const check = isAssertionCheck(value) ? ` (${value})` : '';
    return oops(`the SAML assertion was refused${check}`);
  }
  if (error instanceof CertificateMaterialError) {
    // Chosen from the two flags, never read from `words`: an instance (or an
    // object whose prototype is this class) may carry its own `words`.
    return refused(
      authError['client-certificate']({ problem: certificateProblem(error) }),
    );
  }
  if (error instanceof ClientAuthenticationResultError) {
    return refused(
      authError['client-authentication']({ problem: 'result-unsendable' }),
    );
  }
  if (error instanceof ClientAuthenticationError) {
    return refused(
      authError['client-authentication']({ problem: 'signing-key-unusable' }),
    );
  }
  if (error instanceof BasicClientIdError) {
    return refused(
      authError['client-authentication']({ problem: 'basic-client-id-colon' }),
    );
  }
  if (error instanceof BrowserAuthError) {
    const cause = readSafely(error, 'cause');
    if (cause instanceof AuthorizationRefusedError) {
      // Re-checked: `readonly` is TypeScript's, the instance can be mutated.
      const oauthError = readSafely(cause, 'oauthError');
      return refused(
        authError['interactive-login']({
          outcome: 'identity-provider-refused',
          ...(isOAuthErrorCode(oauthError) ? { oauthError } : {}),
        }),
      );
    }
    return refused(authError['interactive-login']({ outcome: 'failed' }));
  }
  if (error instanceof RefreshError) {
    return refused(
      authError['credential-refused']({ credential: 'refresh-token' }),
    );
  }
  if (error instanceof ValidationError) {
    return oops(
      `the provider configuration is incomplete or invalid${knownFields(readSafely(error, 'missingFields'))}`,
      'check the provider configuration',
    );
  }
  if (error instanceof ServiceKeyError || error instanceof SessionDataError) {
    return oops(
      `the service key or session data is incomplete${knownFields(readSafely(error, 'missingFields'))}`,
      'check the service key or session data',
    );
  }
  if (error instanceof TokenProviderError) {
    // A13: the class label is lost (spec L11).
    return refused(authError.unknown(of));
  }
  if (error instanceof TokenEndpointError) {
    return refused(requestFailed(error, of));
  }
  return refused(classify(error, of.operation, of.grant));
}

/**
 * The refusal words this package would give for a thrown value — exactly the
 * `reason` and `hint` of `refusalFrom(error, what)`, as a plain object, for a
 * consumer that relays them. Total. A `what` that is not one of this
 * package's own is the unfamiliar operation (spec L10); a consumer moves to
 * auth-errors' `classify(error, operation)` (Decision D7: removed in Task 27).
 */
export function refusalWords(error: unknown, what: string): IAuthRefusal {
  const outcome = refusalFrom(error, what);
  // refusalFrom only ever answers Oops; the branch exists for the type.
  if (outcome.ok) return { reason: `${what} failed (unknown error)` };
  const { reason, hint } = outcome.refusal;
  return hint === undefined ? { reason } : { reason, hint };
}

/**
 * What a log line may say about a thrown value: the reason its refusal would
 * carry (`refusalFrom`) and an HTTP status when the value carries a numeric
 * one. Never its `message`, `cause`, `stack` or a stringified form: a
 * consumer's strategy, loader, presenter or validator may throw text holding
 * a key, a passphrase or a token, and so may a network failure.
 */
export function loggedError(
  error: unknown,
  what: string,
): { error: string; status?: number } {
  const outcome = refusalFrom(error, what);
  const words = outcome.ok ? `${what} failed` : outcome.refusal.reason;
  // Guarded reads: `status` (a TokenEndpointError's) or `response.status`.
  const status =
    integerStatus(readSafely(error, 'status')) ??
    integerStatus(readSafely(readSafely(error, 'response'), 'status'));
  return status === undefined ? { error: words } : { error: words, status };
}
