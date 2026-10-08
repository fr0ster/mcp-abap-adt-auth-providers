/**
 * Type test, compiled by `test:check` and run by nothing (spec §6d.7,
 * §6d.10, §6d.11 "Named compositions"): the calls the server and the
 * auth-broker CLI make today compile unchanged; the options 6.0.0 removes
 * (`callbackServer`, `host`, `allowedHosts`, `stateGate`, the manual and
 * external strategies' optional `redirectUri`, `manualPasscodeStrategy`'s
 * `redirectUri`) are compile errors; `BrowserCallbackStrategy` and the
 * callback server factories are gone from the package root; the parts and
 * the composer are there.
 */

import type {
  IAnswerTransport,
  IAuthorizationStrategy,
} from '@mcp-abap-adt/interfaces-auth';
import {
  AuthorizationCodeProvider,
  asOidcResult,
  browserCallbackStrategy,
  type ComposedAuthorization,
  type ComposedStrategy,
  composeAuthorization,
  consumerAnswer,
  consumerHandoff,
  consumerPresentation,
  DEFAULT_CALLBACK_PORT,
  externalCodeStrategy,
  loopback,
  loopback4,
  loopback6,
  manualPasscodeStrategy,
  manualPasteStrategy,
  manualSamlResponseStrategy,
  type OidcCallbackResult,
  oauthCode,
  oidcCallbackStrategy,
  oidcCode,
  openInBrowser,
  passcode,
  samlCallbackStrategy,
  samlResponse,
  showUrl,
  staticCodeStrategy,
  terminalPaste,
  UaaPasscodeProvider,
} from '../../index';

type Surface = typeof import('../../index');

declare const browser: string;
declare const redirectPort: number | undefined;
declare const acsUrl: string;
declare const readManualInput: (
  prompt: string,
  signal: AbortSignal,
) => Promise<string>;
const signal = AbortSignal.timeout(1000);

// The server: `browserCallbackStrategy({ browser, port })`.
export const server: IAuthorizationStrategy<string> = browserCallbackStrategy({
  browser,
  port: redirectPort,
});
// The CLI's calls (auth-broker-cli 3.0.0, `timeoutMs` already gone).
export const cli = [
  browserCallbackStrategy({ browser: 'system' }),
  browserCallbackStrategy({ browser, port: redirectPort }),
  oidcCallbackStrategy({ port: redirectPort, browser }),
  samlCallbackStrategy({ port: redirectPort, browser }),
  manualPasscodeStrategy({ read: (p, s) => readManualInput(p, s) }),
  manualSamlResponseStrategy({
    redirectUri: acsUrl,
    read: (p, s) => readManualInput(p, s),
  }),
  staticCodeStrategy({ payload: 'code' }),
  asOidcResult(staticCodeStrategy({ payload: 'code' })),
];
export const oidcStrategy: IAuthorizationStrategy<OidcCallbackResult> =
  oidcCallbackStrategy({ signal });
export const withOpenUrl = browserCallbackStrategy({
  openUrl: async (_url, _browser, _redirectUri) => undefined,
  remoteHint: (redirectUri) => `tunnel to ${redirectUri}`,
  signal,
});
export const external = externalCodeStrategy({
  redirectUri: acsUrl,
  provide: async () => 'code',
  signal,
});
export const paste = manualPasteStrategy({ redirectUri: acsUrl, signal });

// The static factories still pass `{ signal }`.
declare const uaa: Parameters<typeof AuthorizationCodeProvider.inBrowser>[0];
declare const passcodeConfig: Parameters<
  typeof UaaPasscodeProvider.fromTerminal
>[0];
export const factories = [
  AuthorizationCodeProvider.inBrowser(uaa, { signal }),
  UaaPasscodeProvider.fromTerminal(passcodeConfig, { signal }),
];

// Removed options.
export const removed = [
  // @ts-expect-error callbackServer is gone: compose an IAnswerTransport
  browserCallbackStrategy({ callbackServer: async () => undefined }),
  // @ts-expect-error host is gone: a non-loopback listener is the consumer's transport
  browserCallbackStrategy({ host: '0.0.0.0' }),
  // @ts-expect-error allowedHosts is gone: the listener answers only what it advertises
  oidcCallbackStrategy({ allowedHosts: ['build.example'] }),
  // @ts-expect-error stateGate is gone: whether a protocol binds by state is the protocol
  samlCallbackStrategy({ stateGate: false }),
  // @ts-expect-error manualPasteStrategy requires redirectUri (C4)
  manualPasteStrategy({}),
  // @ts-expect-error manualPasteStrategy requires its options
  manualPasteStrategy(),
  // @ts-expect-error manualSamlResponseStrategy requires redirectUri (the ACS)
  manualSamlResponseStrategy({ read: readManualInput }),
  // @ts-expect-error externalCodeStrategy requires redirectUri (C4)
  externalCodeStrategy({ provide: async () => 'code' }),
  // @ts-expect-error manualPasscodeStrategy takes no redirectUri (unused)
  manualPasscodeStrategy({ redirectUri: acsUrl }),
];

// @ts-expect-error the class is gone: composeAuthorization
export type R1 = Surface['BrowserCallbackStrategy'];
// @ts-expect-error the factory is gone: loopback and the protocols
export type R2 = Surface['withBrowserCallbackServer'];
// @ts-expect-error the factory is gone
export type R3 = Surface['withOidcCallbackServer'];
// @ts-expect-error the factory is gone
export type R4 = Surface['withSamlCallbackServer'];
// @ts-expect-error the scope is gone
export type R5 = Surface['runCallbackScope'];
// @ts-expect-error the options type is gone with the class
export type R6 = import('../../index').BrowserCallbackStrategyOptions<string>;

// The parts and the composer.
declare const transport: IAnswerTransport;
const parts: ComposedAuthorization<string> = {
  presentation: showUrl(),
  transport,
  protocol: oauthCode(),
  endpoint: '/callback',
};
export const composed: ComposedStrategy<string> = composeAuthorization(parts);
export const composedOidc: ComposedStrategy<OidcCallbackResult> =
  composeAuthorization({
    presentation: openInBrowser({ browser: 'system' }),
    transport: loopback({ port: DEFAULT_CALLBACK_PORT }),
    protocol: oidcCode(),
    endpoint: '/callback',
  });
export const more = [
  composeAuthorization({
    presentation: consumerPresentation({ show: async () => undefined }),
    transport: loopback4({ port: 0 }),
    protocol: samlResponse(),
    endpoint: '/acs',
  }),
  composeAuthorization({
    presentation: showUrl(),
    transport: terminalPaste({ redirectUri: acsUrl }),
    protocol: oidcCode(),
    endpoint: '/callback',
  }),
  composeAuthorization({
    presentation: showUrl(),
    transport: consumerAnswer({ receive: async () => 'code' }),
    protocol: passcode(),
    endpoint: '/callback',
  }),
  composeAuthorization({
    ...consumerHandoff({ redirectUri: acsUrl, provide: async () => 'c' }),
    protocol: oauthCode(),
    endpoint: '/callback',
  }),
  loopback6({ port: 0 }),
];
// @ts-expect-error the composer has no default endpoint
export const noEndpoint = composeAuthorization({
  presentation: showUrl(),
  transport,
  protocol: oauthCode(),
});
// @ts-expect-error a listener has no default port
export const noPort = loopback({});
// @ts-expect-error openInBrowser does not take 'none': that is showUrl
export const none = openInBrowser({ browser: 'none' });
