/**
 * What a static factory that composes an interactive strategy takes
 * (`inBrowser`, `fromTerminal`). There is no bound of the package's choosing: a login ends on its result, the identity provider's refusal or
 * this signal — compose `AbortSignal.timeout(ms)` for a deadline.
 */
export interface LoginFactoryOptions {
  /** Ends every login of the composed strategy `aborted`. */
  signal?: AbortSignal | undefined;
}
