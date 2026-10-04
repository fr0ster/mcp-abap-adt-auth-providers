import { registeredOAuthError } from './oauthErrorBody';

/**
 * A browser login's own failure — the timeout, a port in use, an abort, a
 * scope that ended — whose message this package builds from fixed words and
 * configured numbers only (a port, a timeout, a count, the authorization URL
 * already shown to the user), never from what a server, an identity provider
 * or a collaborator said. That guarantee is why `BrowserCallbackStrategy`
 * keeps its message (the text, "already in use" among it, stays for any
 * consumer that may match it) while any other error ends in fixed words. Not
 * exported: a consumer cannot construct one with text of its own.
 */
export class CallbackScopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CallbackScopeError';
    Object.setPrototypeOf(this, CallbackScopeError.prototype);
  }
}

/**
 * The identity provider refused the login on the callback (`?error=…`). Its
 * `error` is kept only when it is a registered OAuth / OIDC code
 * (`oauthError`) — "consent_required" is what a user who declined needs to
 * read; `error_description`, `error_uri` and an unregistered code are dropped:
 * anyone can put them in a link to the local callback.
 */
export class AuthorizationRefusedError extends CallbackScopeError {
  readonly oauthError?: string;

  constructor(error: unknown) {
    const code = registeredOAuthError(error);
    super(
      `the identity provider refused the login (${code ?? 'an unregistered error code'})`,
    );
    this.name = 'AuthorizationRefusedError';
    Object.setPrototypeOf(this, AuthorizationRefusedError.prototype);
    if (code) this.oauthError = code;
  }
}
