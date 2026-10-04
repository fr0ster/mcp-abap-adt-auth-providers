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
  CLIENT_AUTHENTICATION_UNUSABLE,
  CLIENT_KEY_UNUSABLE,
  ClientAuthenticationError,
  ClientAuthenticationResultError,
} from '../errors/ClientAuthenticationError';
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

/**
 * The fixed words for a token bound to a certificate this provider does not
 * present (spec §4) — none pinned, another one, or a binding it cannot read.
 * No thumbprint appears in them.
 */
export const TOKEN_BOUND_ELSEWHERE = {
  reason:
    'the token is bound to a client certificate this provider does not present',
  hint: 'configure the certificate the token was issued for, or obtain a new token',
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

/** The fixed words for one TLS failure: what it says, and what to do. */
interface TlsWords {
  readonly says: string;
  readonly hint: string;
}

const UNTRUSTED_SERVER: TlsWords = {
  says: "the server's certificate is not trusted",
  hint: 'if the server uses a private CA, name its certificate in NODE_EXTRA_CA_CERTS',
};

/**
 * The server asked for a client certificate and refused the one presented, or
 * its absence: the alert it sent, as Node names it. Current OpenSSL (3.5 with
 * Node 22 and 24, 3.6 — measured) spells the SSLv3-era alerts
 * `SSL/TLS_ALERT_…`; older releases spelled them `SSLV3_ALERT_…` — both are
 * listed.
 */
const REFUSED_CLIENT_CERTIFICATE: TlsWords = {
  says: 'the server refused the client certificate',
  hint: 'check that the server trusts the certificate’s issuer and that the certificate is valid and not revoked',
};

const CLIENT_CERTIFICATE_ALERTS = [
  'BAD_CERTIFICATE',
  'CERTIFICATE_UNKNOWN',
  'CERTIFICATE_EXPIRED',
  'CERTIFICATE_REVOKED',
  'UNSUPPORTED_CERTIFICATE',
].flatMap((alert) => [
  `ERR_SSL_SSL/TLS_ALERT_${alert}`,
  `ERR_SSL_SSLV3_ALERT_${alert}`,
]);

/**
 * Node's codes for a TLS failure, each with its fixed words. The code is the
 * only part of such an error a refusal names; its message never.
 */
const TLS_CODES: ReadonlyMap<string, TlsWords> = new Map<string, TlsWords>([
  ['UNABLE_TO_VERIFY_LEAF_SIGNATURE', UNTRUSTED_SERVER],
  ['SELF_SIGNED_CERT_IN_CHAIN', UNTRUSTED_SERVER],
  ['DEPTH_ZERO_SELF_SIGNED_CERT', UNTRUSTED_SERVER],
  ['UNABLE_TO_GET_ISSUER_CERT_LOCALLY', UNTRUSTED_SERVER],
  [
    'CERT_HAS_EXPIRED',
    {
      says: "the server's certificate has expired",
      hint: 'the server must renew its certificate; check also this machine’s clock',
    },
  ],
  [
    'ERR_TLS_CERT_ALTNAME_INVALID',
    {
      says: "the host name is not in the server's certificate",
      hint: 'use the host name the server’s certificate is issued for',
    },
  ],
  ['ERR_SSL_TLSV13_ALERT_CERTIFICATE_REQUIRED', REFUSED_CLIENT_CERTIFICATE],
  ['ERR_SSL_TLSV1_ALERT_UNKNOWN_CA', REFUSED_CLIENT_CERTIFICATE],
  ...CLIENT_CERTIFICATE_ALERTS.map(
    (code) => [code, REFUSED_CLIENT_CERTIFICATE] as const,
  ),
]);

/**
 * The allowlisted code of a TLS failure — the server's certificate, or the
 * server refusing the client's — else undefined. A site that wraps its errors
 * lets these through unwrapped, so the refusal can name the code.
 */
export function tlsFailureCode(error: unknown): string | undefined {
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === 'string' && TLS_CODES.has(code) ? code : undefined;
}

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
  [BrowserAuthError, 'BrowserAuthError'],
  [RefreshError, 'RefreshError'],
  [ValidationError, 'ValidationError'],
  [ServiceKeyError, 'ServiceKeyError'],
  [SessionDataError, 'SessionDataError'],
  [DeviceCodePresentationError, 'DeviceCodePresentationError'],
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
  const tls = tlsFailureCode(error);
  const words = tls === undefined ? undefined : TLS_CODES.get(tls);
  if (words !== undefined) {
    return oops(`${what} failed: ${words.says} (${tls})`, words.hint);
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
