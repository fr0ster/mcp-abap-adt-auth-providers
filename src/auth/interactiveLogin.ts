/**
 * The failures an interactive login ends with (spec Appendix A.3, K1–K17):
 * one `interactive-login` error per outcome, thrown as an
 * `AuthProviderFailure`. Every fact is checked by the builder; nothing a
 * server, an identity provider, a launcher or a consumer's transport said
 * reaches the words — only an integer status, a registered OAuth `error`
 * and an allowlisted system code, each read through `readSafely`.
 */

import {
  type AuthErrorBuilders,
  AuthProviderFailure,
  authError,
  count,
  httpStatus,
  isOAuthErrorCode,
  isSystemCode,
  port as portNumber,
} from '@mcp-abap-adt/auth-errors';
import type { InteractiveLoginStrategy } from '@mcp-abap-adt/interfaces-auth';
import { readSafely } from './knownCodes';

/** The facts the `interactive-login` builder takes. */
type InteractiveFacts = Parameters<AuthErrorBuilders['interactive-login']>[0];

/** Which strategy or transport a login belongs to. */
export type LoginStrategy = InteractiveLoginStrategy;

/** An `interactive-login` failure of these facts. */
export function loginFailure(facts: InteractiveFacts): AuthProviderFailure {
  return new AuthProviderFailure(authError['interactive-login'](facts));
}

/**
 * K4: the login was aborted — by the consumer's signal or the attempt's —
 * naming the strategy, and for a browser login the number of incomplete
 * `/callback` requests that were ignored while it waited (none: no clause).
 */
export function abortedLogin(
  strategy: LoginStrategy,
  ignored = 0,
): AuthProviderFailure {
  const tally = ignored > 0 ? count(ignored) : undefined;
  return loginFailure({
    outcome: 'aborted',
    strategy,
    ...(tally === undefined ? {} : { ignoredCallbacks: tally }),
  });
}

/**
 * K1: the callback port is held by someone else — its words keep "already in
 * use" for any consumer that matches it. A value that is no port is K11.
 */
export function portInUse(port: number): AuthProviderFailure {
  const checked = portNumber(port);
  return checked === undefined
    ? loginFailure({ outcome: 'failed' })
    : loginFailure({ outcome: 'port-in-use', port: checked });
}

/** An allowlisted system code of a thrown value, else `undefined`. */
function systemCodeOf(error: unknown) {
  const code = readSafely(error, 'code');
  return isSystemCode(code) ? code : undefined;
}

/**
 * K11: anything else that ends a browser login — a consumer's transport, a
 * foreign rejection: its integer HTTP status (own or its response's), a
 * registered OAuth `error` (own `oauthError`, or its response body's) and an
 * allowlisted system code; never its message.
 */
export function failedLogin(error: unknown): AuthProviderFailure {
  const response = readSafely(error, 'response');
  const status =
    httpStatus(readSafely(error, 'status')) ??
    httpStatus(readSafely(response, 'status'));
  const own = readSafely(error, 'oauthError');
  const oauthError = isOAuthErrorCode(own)
    ? own
    : readSafely(readSafely(response, 'data'), 'error');
  const code = systemCodeOf(error);
  return loginFailure({
    outcome: 'failed',
    ...(status === undefined ? {} : { status }),
    ...(isOAuthErrorCode(oauthError) ? { oauthError } : {}),
    ...(code === undefined ? {} : { code }),
  });
}

/**
 * K10 / A8: the identity provider refused the login on the callback
 * (`?error=…`). Its `error` is kept only when it is a registered OAuth / OIDC
 * code; `error_description`, `error_uri` and an unregistered code are
 * dropped — anyone can put them in a link to the local callback.
 */
export function identityProviderRefused(error: unknown): AuthProviderFailure {
  return loginFailure({
    outcome: 'identity-provider-refused',
    ...(isOAuthErrorCode(error) ? { oauthError: error } : {}),
  });
}
