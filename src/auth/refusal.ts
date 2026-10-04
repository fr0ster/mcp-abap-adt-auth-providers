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
import { DeviceCodePresentationError } from '../deviceCode/DeviceCodePresenter';
import {
  type AssertionCheck,
  AssertionValidationError,
} from '../errors/AssertionValidationError';
import { CertificateMaterialError } from '../errors/CertificateMaterialError';
import {
  BASIC_CLIENT_ID_UNUSABLE,
  BasicClientIdError,
  CLIENT_AUTHENTICATION_UNUSABLE,
  CLIENT_KEY_UNUSABLE,
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
  allowlistedCode,
  integerStatus,
  readSafely,
  TLS_CODES,
  tlsFailureCode,
} from './knownCodes';
import { registeredOAuthError } from './oauthErrorBody';

export const OK: AuthOutcome = { ok: true };

export function oops(reason: string, hint?: string): AuthOutcome {
  return hint === undefined
    ? { ok: false, refusal: { reason } }
    : { ok: false, refusal: { reason, hint } };
}

/**
 * The fixed words for a token held bound to a client certificate while no
 * certificate is pinned (spec §4) — none configured, or a binding it cannot
 * read. No thumbprint appears in them.
 */
export const TOKEN_BOUND_ELSEWHERE = {
  reason:
    'the token is bound to a client certificate this provider does not present',
  hint: 'give the provider a clientAuthentication that presents the certificate the token was issued for',
} as const;

/**
 * The fixed words for a token renewed because the one held was bound to
 * another certificate than the pinned one, when the new token is bound
 * elsewhere too. No thumbprint appears in them.
 */
export const TOKEN_RENEWED_BOUND_ELSEWHERE = {
  reason:
    'the new token is bound to a client certificate this provider does not present',
  hint: 'the authorization server bound the new token to another certificate: check the certificate registered for this client',
} as const;

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
  'encoding',
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

export { allowlistedCode, tlsFailureCode } from './knownCodes';

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
  [CertificateMaterialError, 'CertificateMaterialError'],
  [ClientAuthenticationResultError, 'ClientAuthenticationResultError'],
  [ClientAuthenticationError, 'ClientAuthenticationError'],
  [BasicClientIdError, 'BasicClientIdError'],
  [BrowserAuthError, 'BrowserAuthError'],
  [RefreshError, 'RefreshError'],
  [ValidationError, 'ValidationError'],
  [ServiceKeyError, 'ServiceKeyError'],
  [SessionDataError, 'SessionDataError'],
  [DeviceCodePresentationError, 'DeviceCodePresentationError'],
  [TokenEndpointError, 'TokenEndpointError'],
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

/**
 * What may be named of a thrown value besides its class: an integer HTTP
 * status (`status`, else `response.status`), a registered OAuth error code
 * (`oauthError`, else `response.data.error`) and an allowlisted code. Each is
 * re-checked here, whoever built the error; nothing else is read.
 */
function safeFacts(error: unknown): string[] {
  const facts: string[] = [];
  const response = readSafely(error, 'response');
  const status =
    integerStatus(readSafely(error, 'status')) ??
    integerStatus(readSafely(response, 'status'));
  if (status !== undefined) facts.push(`HTTP ${status}`);
  const oauth =
    registeredOAuthError(readSafely(error, 'oauthError')) ??
    registeredOAuthError(readSafely(readSafely(response, 'data'), 'error'));
  if (oauth) facts.push(oauth);
  const code = allowlistedCode(readSafely(error, 'code'));
  if (code) facts.push(code);
  return facts;
}

/**
 * Total (rule 1): reading a foreign error — a getter, a Proxy, an `instanceof`
 * whose prototype trap throws — never makes this throw; whatever does is
 * "unknown error".
 */
export function refusalFrom(error: unknown, what: string): AuthOutcome {
  try {
    return refusalFromUnguarded(error, what);
  } catch {
    return oops(`${what} failed (unknown error)`);
  }
}

function refusalFromUnguarded(error: unknown, what: string): AuthOutcome {
  if (error instanceof DeviceCodePresentationError) {
    return oops('showing the device code failed');
  }
  if (error instanceof AssertionValidationError) {
    const check = ASSERTION_CHECKS.has(error.check) ? ` (${error.check})` : '';
    return oops(`the SAML assertion was refused${check}`);
  }
  if (error instanceof CertificateMaterialError) {
    const { reason, hint } = error.words;
    return oops(reason, hint);
  }
  if (error instanceof ClientAuthenticationResultError) {
    return oops(
      CLIENT_AUTHENTICATION_UNUSABLE.reason,
      CLIENT_AUTHENTICATION_UNUSABLE.hint,
    );
  }
  if (error instanceof ClientAuthenticationError) {
    return oops(CLIENT_KEY_UNUSABLE.reason, CLIENT_KEY_UNUSABLE.hint);
  }
  if (error instanceof BasicClientIdError) {
    return oops(BASIC_CLIENT_ID_UNUSABLE.reason, BASIC_CLIENT_ID_UNUSABLE.hint);
  }
  if (error instanceof BrowserAuthError) {
    const refused = error.cause;
    if (refused instanceof AuthorizationRefusedError) {
      // Re-checked: `readonly` is TypeScript's, the instance can be mutated.
      const code = registeredOAuthError(readSafely(refused, 'oauthError'));
      return oops(
        `the identity provider refused the login${code ? ` (${code})` : ''}`,
        'check the identity provider: the user, the client and the scopes it allows',
      );
    }
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
  if (error instanceof TokenEndpointError) {
    const facts = safeFacts(error);
    return oops(
      `${what} failed (${facts.length ? facts.join(', ') : 'the token endpoint gave no reason'})`,
    );
  }
  const tls = tlsFailureCode(error);
  const words = tls === undefined ? undefined : TLS_CODES.get(tls);
  if (words !== undefined) {
    return oops(`${what} failed: ${words.says} (${tls})`, words.hint);
  }
  const facts = safeFacts(error);
  // A server answered: its status (and code) say what happened, the same
  // words as a TokenEndpointError's. Without one, "unknown error" leads.
  if (facts.some((fact) => fact.startsWith('HTTP '))) {
    return oops(`${what} failed (${facts.join(', ')})`);
  }
  return oops(
    `${what} failed (unknown error${facts.length ? `, ${facts.join(', ')}` : ''})`,
  );
}

/**
 * What a log line may say about a thrown value: the reason its refusal would
 * carry (`refusalFrom`) — fixed words per class decided by `instanceof`, plus
 * allowlisted metadata (a known config field, a TLS or system code, an
 * assertion check), else "unknown error" — and an HTTP status when the value
 * carries a numeric one. Never its `message`, `cause`, `stack` or a
 * stringified form: a consumer's strategy, loader, presenter or validator may
 * throw text holding a key, a passphrase or a token, and so may a network
 * failure. No class of this package keeps its message here either — even
 * ones built from fixed words: the class's words are the same.
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
