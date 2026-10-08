/**
 * The browser compositions (spec §6d.7): a loopback listener on today's
 * port, the URL shown or opened, and the flow's protocol. Each returns
 * `composeAuthorization(…)`; the parts have no default — these names are
 * where today's values live.
 *
 * | Name | Protocol |
 * |---|---|
 * | `browserCallbackStrategy` | `oauthCode()` |
 * | `oidcCallbackStrategy` | `oidcCode()` |
 * | `samlCallbackStrategy` | `samlResponse()` |
 *
 * Presentation: `openUrl` → `consumerPresentation`; `browser` absent,
 * `'none'` or `'headless'` → `showUrl()`; else `openInBrowser({ browser })`
 * (`'edge'` is `'msedge'`). Transport: `loopback({ port: port ??
 * DEFAULT_CALLBACK_PORT })`, its route hint replaced by `remoteHint` when
 * given.
 */

import { authError } from '@mcp-abap-adt/auth-errors';
import type {
  AnswerJudge,
  AnswerTransportOptions,
  IAnswerChannel,
  IAnswerTransport,
  IAuthorizationPresentation,
  IAuthorizationProtocol,
} from '@mcp-abap-adt/interfaces-auth';
import { misconfigured, ownOptions } from '../auth/configuration';
import { readSafely } from '../auth/knownCodes';
import { asAbortSignal } from '../auth/signalledRequest';
import {
  type ComposedStrategy,
  composeAuthorization,
} from '../authorization/compose';
import {
  consumerPresentation,
  type OpenableBrowser,
  openInBrowser,
  showUrl,
} from '../authorization/presentation';
import {
  type OidcCallbackResult,
  oauthCode,
  oidcCode,
  samlResponse,
} from '../authorization/protocol';
import { loopback } from '../authorization/transport';
import { CALLBACK_ENDPOINT, DEFAULT_CALLBACK_PORT } from './defaults';

export interface CallbackStrategyOptions {
  /**
   * The loopback port; `0` binds an ephemeral one — unusable where the IdP
   * has a registered redirect. Default `DEFAULT_CALLBACK_PORT` (61001).
   */
  port?: number | undefined;
  /**
   * `'none'` / `'headless'` (or absent) show the URL on stderr; `'auto'`,
   * `'system'`, `'chrome'`, `'edge'` / `'msedge'`, `'firefox'` open it.
   * Anything else is refused at construction.
   */
  browser?: string | undefined;
  /**
   * The consumer's own way to show the URL — replaces `browser`. Receives
   * the bound redirect too, since with `port: 0` nobody knew it earlier.
   */
  openUrl?:
    | ((url: string, browser: string, redirectUri: string) => Promise<void>)
    | undefined;
  /**
   * Replaces the listener's route hint ("if your browser is elsewhere, do
   * this instead"), built from the redirect actually bound.
   */
  remoteHint?: ((redirectUri: string) => string) | undefined;
  /**
   * Ends every login of this strategy, beside the request's own signal (the
   * attempt's, spec §6b): either one aborting ends it `aborted`. There is no
   * other bound — compose `AbortSignal.timeout(ms)` for a deadline.
   */
  signal?: AbortSignal | undefined;
}

/** Today's browser names, as `openInBrowser` takes them. */
const OPENABLE: Readonly<Record<string, OpenableBrowser>> = Object.freeze({
  auto: 'auto',
  system: 'system',
  chrome: 'chrome',
  edge: 'msedge',
  msedge: 'msedge',
  firefox: 'firefox',
});

function presentationOf(
  own: Partial<Record<keyof CallbackStrategyOptions, unknown>>,
): IAuthorizationPresentation {
  const { browser, openUrl } = own;
  if (browser !== undefined && typeof browser !== 'string') {
    throw misconfigured(
      authError.configuration({
        case: 'invalid-value',
        fields: ['presentation'],
      }),
    );
  }
  if (openUrl !== undefined) {
    if (typeof openUrl !== 'function') {
      throw misconfigured(
        authError.configuration({ case: 'invalid-value', fields: ['show'] }),
      );
    }
    const open = openUrl as NonNullable<CallbackStrategyOptions['openUrl']>;
    return consumerPresentation({
      show: (url, context) =>
        open(url, browser ?? 'none', context.redirectUri ?? ''),
    });
  }
  if (browser === undefined || browser === 'none' || browser === 'headless') {
    return showUrl();
  }
  const openable = Object.hasOwn(OPENABLE, browser)
    ? OPENABLE[browser]
    : undefined;
  if (openable === undefined) {
    throw misconfigured(
      authError.configuration({
        case: 'invalid-value',
        fields: ['presentation'],
      }),
    );
  }
  return openInBrowser({ browser: openable });
}

/**
 * `transport` with its channel's route hint replaced by `remoteHint(redirect)`;
 * a hint that throws or is no string is none.
 */
function withRouteHint(
  transport: IAnswerTransport,
  remoteHint: (redirectUri: string) => string,
): IAnswerTransport {
  return Object.freeze({
    label: transport.label,
    open<TReturn>(
      options: AnswerTransportOptions,
      use: (channel: IAnswerChannel) => Promise<TReturn>,
    ): Promise<TReturn> {
      return transport.open(options, (channel) => {
        const redirectUri = readSafely(channel, 'redirectUri');
        const waitingOn = readSafely(channel, 'waitingOn');
        let routeHint: unknown;
        if (typeof redirectUri === 'string') {
          try {
            routeHint = remoteHint(redirectUri);
          } catch {
            routeHint = undefined;
          }
        }
        return use(
          Object.freeze({
            redirectUri:
              typeof redirectUri === 'string' ? redirectUri : undefined,
            waitingOn: typeof waitingOn === 'string' ? waitingOn : undefined,
            routeHint: typeof routeHint === 'string' ? routeHint : undefined,
            arm: (judge: AnswerJudge<unknown>) => channel.arm(judge),
          }),
        );
      });
    },
  });
}

function transportOf(
  own: Partial<Record<keyof CallbackStrategyOptions, unknown>>,
): IAnswerTransport {
  const listener = loopback({
    port: (own.port ?? DEFAULT_CALLBACK_PORT) as number,
  });
  const { remoteHint } = own;
  if (remoteHint === undefined) return listener;
  if (typeof remoteHint !== 'function') {
    throw misconfigured(
      authError.configuration({ case: 'invalid-value', fields: ['transport'] }),
    );
  }
  return withRouteHint(listener, remoteHint as (redirectUri: string) => string);
}

function callbackComposition<T>(
  options: CallbackStrategyOptions,
  protocol: IAuthorizationProtocol<T>,
): ComposedStrategy<T> {
  // Read once as own data: a hostile object throws nothing of its own.
  const own =
    ownOptions<Partial<Record<keyof CallbackStrategyOptions, unknown>>>(
      options,
    );
  return composeAuthorization({
    presentation: presentationOf(own),
    transport: transportOf(own),
    protocol,
    endpoint: CALLBACK_ENDPOINT,
    signal: asAbortSignal(own.signal),
  });
}

/** A UAA / XSUAA browser login: the code on a loopback callback. */
export function browserCallbackStrategy(
  options: CallbackStrategyOptions = {},
): ComposedStrategy<string> {
  return callbackComposition(options, oauthCode());
}

/** An OIDC browser login: `{ code, state }` on a loopback callback. */
export function oidcCallbackStrategy(
  options: CallbackStrategyOptions = {},
): ComposedStrategy<OidcCallbackResult> {
  return callbackComposition(options, oidcCode());
}

/** A SAML browser login: the `SAMLResponse` posted to a loopback ACS. */
export function samlCallbackStrategy(
  options: CallbackStrategyOptions = {},
): ComposedStrategy<string> {
  return callbackComposition(options, samlResponse());
}
