/**
 * A browser login's own failure — the timeout, a port in use, an abort, a
 * scope that ended — whose message this package builds from fixed words and
 * configured numbers only (a port, a timeout, a count, the authorization URL
 * already shown to the user), never from what a server, an identity provider
 * or a collaborator said. That guarantee is why `BrowserCallbackStrategy`
 * keeps its message (a consumer such as AuthBroker matches "already in use")
 * while any other error ends in fixed words. Not exported: a consumer cannot
 * construct one with text of its own.
 */
export class CallbackScopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CallbackScopeError';
    Object.setPrototypeOf(this, CallbackScopeError.prototype);
  }
}
