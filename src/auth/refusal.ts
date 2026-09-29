/**
 * How a provider in this package answers Oops — the one place thrown values
 * become refusals (spec rule 2).
 *
 * A refusal never carries an error's message: the class of an error says
 * nothing about what its message holds (BrowserAuthError is built from an IdP
 * callback's text; a consumer can construct any exported class). It is fixed
 * wording chosen per class, plus metadata only when the value is on an
 * allowlist this package owns. A `name` property is never read.
 */

import type { AuthOutcome } from '@mcp-abap-adt/interfaces-auth';
import {
  type AssertionCheck,
  AssertionValidationError,
} from '../errors/AssertionValidationError';
import {
  BrowserAuthError,
  RefreshError,
  ServiceKeyError,
  SessionDataError,
  TokenProviderError,
  ValidationError,
} from '../errors/TokenProviderErrors';

export const OK: AuthOutcome = { ok: true };

export function oops(reason: string, hint?: string): AuthOutcome {
  return hint === undefined
    ? { ok: false, refusal: { reason } }
    : { ok: false, refusal: { reason, hint } };
}

/** Every config property name this package's providers declare. */
export const KNOWN_CONFIG_FIELDS: ReadonlySet<string> = new Set([
  'accessToken',
  'acsUrl',
  'actorToken',
  'actorTokenType',
  'assertionValidator',
  'audience',
  'authnRequestId',
  'authorization',
  'authorizationEndpoint',
  'authorizationUrl',
  'certKeyPath',
  'certPassphrase',
  'certPath',
  'certPfxPath',
  'clientId',
  'clientSecret',
  'clockSkewMs',
  'cookieProvider',
  'deviceAuthorizationEndpoint',
  'idpCertificates',
  'idpEntityId',
  'idpInitiated',
  'idpSsoUrl',
  'issuerUrl',
  'locator',
  'logger',
  'myName',
  'onTokens',
  'partnerName',
  'password',
  'presenter',
  'probes',
  'qop',
  'refreshToken',
  'relayState',
  'replayStore',
  'scope',
  'scopes',
  'sncLib',
  'spEntityId',
  'subjectToken',
  'subjectTokenType',
  'tokenEndpoint',
  'tokenUrl',
  'uaaUrl',
  'username',
]);

const ASSERTION_CHECKS: ReadonlySet<AssertionCheck> = new Set<AssertionCheck>([
  'document',
  'duplicateId',
  'signature',
  'signedNode',
  'status',
  'assertionId',
  'issuer',
  'conditions',
  'notBefore',
  'notOnOrAfter',
  'audience',
  'bearerConfirmation',
  'destination',
  'replay',
]);

const KNOWN_SYSTEM_CODES: ReadonlySet<string> = new Set([
  'ENOENT',
  'EACCES',
  'EPERM',
  'ECONNREFUSED',
  'ECONNRESET',
  'ETIMEDOUT',
  'ENOTFOUND',
  'EAI_AGAIN',
  'EPIPE',
]);

export const KNOWN_RFC_KEYS: ReadonlySet<string> = new Set([
  'RFC_COMMUNICATION_FAILURE',
  'RFC_LOGON_FAILURE',
  'RFC_ABAP_RUNTIME_FAILURE',
  'RFC_ABAP_MESSAGE',
  'RFC_EXTERNAL_FAILURE',
  'RFC_INVALID_PARAMETER',
  'RFC_CLOSED',
  'RFC_TIMEOUT',
]);

/** Most specific first. */
const OWN_CLASSES: ReadonlyArray<
  readonly [abstract new (...a: never[]) => unknown, string]
> = [
  [AssertionValidationError, 'AssertionValidationError'],
  [BrowserAuthError, 'BrowserAuthError'],
  [RefreshError, 'RefreshError'],
  [ValidationError, 'ValidationError'],
  [ServiceKeyError, 'ServiceKeyError'],
  [SessionDataError, 'SessionDataError'],
  [TokenProviderError, 'TokenProviderError'],
];

/** The label of one of this package's classes, by instanceof; else "unknown error". */
export function ownLabel(error: unknown): string {
  for (const [ctor, label] of OWN_CLASSES) {
    if (error instanceof ctor) return label;
  }
  return 'unknown error';
}

function knownFields(missing: unknown): string {
  if (!Array.isArray(missing)) return '';
  const names = missing.filter(
    (m): m is string => typeof m === 'string' && KNOWN_CONFIG_FIELDS.has(m),
  );
  return names.length ? `: ${names.join(', ')}` : '';
}

function systemCode(error: unknown): string {
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === 'string' && KNOWN_SYSTEM_CODES.has(code)
    ? `, ${code}`
    : '';
}

export function refusalFrom(error: unknown, what: string): AuthOutcome {
  if (error instanceof AssertionValidationError) {
    const check = ASSERTION_CHECKS.has(error.check) ? ` (${error.check})` : '';
    return oops(`the SAML assertion was refused${check}`);
  }
  if (error instanceof BrowserAuthError) {
    return oops(
      'the interactive login did not complete',
      "complete the login within the strategy's time",
    );
  }
  if (error instanceof RefreshError) {
    return oops('the refresh token was refused', 'log in again');
  }
  if (error instanceof ValidationError) {
    return oops(
      `the provider configuration is incomplete or invalid${knownFields(error.missingFields)}`,
      'check the provider configuration',
    );
  }
  if (error instanceof ServiceKeyError || error instanceof SessionDataError) {
    return oops(
      `the service key or session data is incomplete${knownFields(error.missingFields)}`,
      'check the service key or session data',
    );
  }
  if (error instanceof TokenProviderError) {
    return oops(`${what} failed (${ownLabel(error)})`);
  }
  return oops(`${what} failed (unknown error${systemCode(error)})`);
}

/** The boundary every contract method runs inside (spec rule 1). */
export async function safely(
  what: string,
  work: () => AuthOutcome | Promise<AuthOutcome>,
): Promise<AuthOutcome> {
  try {
    return await work();
  } catch (error) {
    return refusalFrom(error, what);
  }
}
