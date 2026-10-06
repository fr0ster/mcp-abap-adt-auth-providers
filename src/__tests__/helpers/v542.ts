/**
 * 5.4.2's own log lines, copied verbatim from the published 5.4.2
 * (`b628c69`) as an oracle: 6.0.0 removed the code that wrote them, and the
 * tests that keep its lines (H10, spec §6 "The safe-facts line stays") compare
 * against these, not against a restatement.
 *
 * - `logRefusedRequest`: `src/auth/tokenRequest.ts:441-461` at 5.4.2.
 * - `codeExchangeMissingTokenLine`: `src/auth/browserAuth.ts:174-183` at 5.4.2.
 */
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { integerStatus, readSafely } from '../../auth/knownCodes';
import { registeredOAuthError } from '../../auth/oauthErrorBody';

/** 5.4.2's `TokenRequestDiagnostics`. */
export interface TokenRequestDiagnostics542 {
  readonly logger?: ILogger | null | undefined;
  readonly label: string;
}

/** 5.4.2's per-site labels (`sendTokenRequest`'s third argument). */
export const LABELS_542 = {
  'code-exchange': 'Token exchange failed',
  'token-refresh': 'Token refresh failed',
  'client-credentials': 'Client credentials authentication failed',
  'passcode-exchange': 'Passcode exchange failed',
  'saml-token-exchange': '[SAML] Token exchange failed',
  'saml-token-refresh': '[SAML] Token refresh failed',
  'device-authorization': 'OIDC device authorization failed',
  'device-poll': 'OIDC device poll failed',
  'password-grant': 'OIDC password grant failed',
} as const;

const WAITING = new Set(['authorization_pending', 'slow_down']);

/** 5.4.2's `logRefusedRequest`, verbatim. */
export function logRefusedRequest542(
  diagnostics: TokenRequestDiagnostics542 | undefined,
  status: unknown,
  data: unknown,
): void {
  const logger = diagnostics?.logger;
  if (!logger) return;
  try {
    const error = registeredOAuthError(readSafely(data, 'error'));
    if (error !== undefined && WAITING.has(error)) return;
    logger.debug(
      `${diagnostics.label}: the token endpoint refused the request`,
      {
        status: integerStatus(status),
        ...(error === undefined ? {} : { error }),
      },
    );
  } catch {
    // The site's failure is what the caller needs.
  }
}

/**
 * 5.4.2's UAA code exchange line for a `2xx` without `access_token`,
 * verbatim (it logged at `error`).
 */
export function codeExchangeMissingTokenLine542(response: {
  status: unknown;
  data: unknown;
}): string {
  const code = registeredOAuthError(readSafely(response.data, 'error'));
  return `Token exchange failed: status ${response.status}, error: ${code === undefined ? 'no error given' : JSON.stringify(code)}`;
}
