/**
 * Type test, compiled by `test:check` and run by nothing: no option
 * this package owns takes a login bound any more — `timeoutMs` on a
 * strategy's options or a static factory's options is a compile error, and
 * `DEFAULT_LOGIN_TIMEOUT_MS` is not exported. A consumer that wants a bound
 * composes `signal: AbortSignal.timeout(ms)`, which compiles everywhere.
 * Nor does interfaces-auth 6.0.0's `ICallbackServerOptions`: its
 * `timeoutMs` is gone, `signal` is the only way a scope ends without a result.
 */

import type { ICallbackServerOptions } from '@mcp-abap-adt/interfaces-auth';
import {
  AuthorizationCodeProvider,
  browserCallbackStrategy,
  type ComposedAuthorization,
  // @ts-expect-error DEFAULT_LOGIN_TIMEOUT_MS is gone with the built-in bound
  DEFAULT_LOGIN_TIMEOUT_MS,
  type ManualStrategyOptions,
  manualPasscodeStrategy,
  manualPasteStrategy,
  manualSamlResponseStrategy,
  OidcBrowserProvider,
  oidcCallbackStrategy,
  Saml2BearerProvider,
  Saml2PureProvider,
  samlCallbackStrategy,
  UaaPasscodeProvider,
} from '../../index';

void DEFAULT_LOGIN_TIMEOUT_MS;

declare const parts: ComposedAuthorization<string>;
declare const uaa: Parameters<typeof AuthorizationCodeProvider.inBrowser>[0];
declare const oidc: Parameters<typeof OidcBrowserProvider.inBrowser>[0];
declare const bearer: Parameters<typeof Saml2BearerProvider.inBrowser>[0];
declare const pure: Parameters<typeof Saml2PureProvider.inBrowser>[0];
declare const trust: Parameters<typeof Saml2BearerProvider.inBrowser>[1];
declare const passcode: Parameters<typeof UaaPasscodeProvider.fromTerminal>[0];
const signal = AbortSignal.timeout(1000);

// The composer's parts and the named compositions' options.
export const composed: ComposedAuthorization<string> = {
  ...parts,
  signal,
  // @ts-expect-error no login bound on ComposedAuthorization
  timeoutMs: 1000,
};
export const browser = [
  browserCallbackStrategy({ signal }),
  // @ts-expect-error no login bound on browserCallbackStrategy
  browserCallbackStrategy({ timeoutMs: 1000 }),
  oidcCallbackStrategy({ signal }),
  // @ts-expect-error no login bound on oidcCallbackStrategy
  oidcCallbackStrategy({ timeoutMs: 1000 }),
  samlCallbackStrategy({ signal }),
  // @ts-expect-error no login bound on samlCallbackStrategy
  samlCallbackStrategy({ timeoutMs: 1000 }),
];
export const manual = [
  manualPasteStrategy({ redirectUri: 'http://localhost:1/cb', signal }),
  // @ts-expect-error no login bound on ManualStrategyOptions
  manualPasteStrategy({ redirectUri: 'http://localhost:1/cb', timeoutMs: 1 }),
  // @ts-expect-error no login bound on ManualStrategyOptions
  manualSamlResponseStrategy({ redirectUri: 'http://x/acs', timeoutMs: 1 }),
  // @ts-expect-error no login bound on ManualPasscodeStrategyOptions
  manualPasscodeStrategy({ timeoutMs: 1000 }),
];
export const manualOptions: ManualStrategyOptions = {
  redirectUri: 'http://localhost:1/cb',
  signal,
};

// The static factories' options.
export const factories = [
  AuthorizationCodeProvider.inBrowser(uaa, { signal }),
  // @ts-expect-error no login bound on AuthorizationCodeProvider.inBrowser
  AuthorizationCodeProvider.inBrowser(uaa, { timeoutMs: 1000 }),
  OidcBrowserProvider.inBrowser(oidc, { signal }),
  // @ts-expect-error no login bound on OidcBrowserProvider.inBrowser
  OidcBrowserProvider.inBrowser(oidc, { timeoutMs: 1000 }),
  Saml2BearerProvider.inBrowser(bearer, trust, { signal }),
  // @ts-expect-error no login bound on Saml2BearerProvider.inBrowser
  Saml2BearerProvider.inBrowser(bearer, trust, { timeoutMs: 1000 }),
  Saml2PureProvider.inBrowser(pure, trust, { signal }),
  // @ts-expect-error no login bound on Saml2PureProvider.inBrowser
  Saml2PureProvider.inBrowser(pure, trust, { timeoutMs: 1000 }),
  UaaPasscodeProvider.fromTerminal(passcode, { signal }),
  // @ts-expect-error no login bound on UaaPasscodeProvider.fromTerminal
  UaaPasscodeProvider.fromTerminal(passcode, { timeoutMs: 1000 }),
];

// The callback server's options (interfaces-auth 6.0.0).
export const serverOptions: ICallbackServerOptions = { port: 0, signal };
export const serverOptionsWithBound: ICallbackServerOptions = {
  port: 0,
  signal,
  // @ts-expect-error no login bound on ICallbackServerOptions
  timeoutMs: 1000,
};
