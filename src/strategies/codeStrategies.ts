/**
 * Strategies where the consumer supplies the payload.
 *
 * The two are separate because one needs the authorization URL and the other
 * does not — and asking for a URL that is not needed would drag in OIDC
 * discovery that a static payload never required.
 */

import type {
  AuthorizationOutcome,
  AuthorizationRequest,
  IAuthorizationStrategy,
} from '@mcp-abap-adt/interfaces-auth';
import { throwIfAborted, untilAborted } from '../auth/attempt';
import { loginFailure } from '../auth/interactiveLogin';
import { signalOf } from '../auth/signalledRequest';
import { DEFAULT_CALLBACK_PORT } from './BrowserCallbackStrategy';

const defaultRedirectUri = () =>
  `http://localhost:${DEFAULT_CALLBACK_PORT}/callback`;

export interface ExternalCodeStrategyOptions {
  redirectUri?: string | undefined;
  /**
   * Receives the assembled URL — so the code returned matches its PKCE
   * challenge — and a signal that aborts when the login is aborted (this
   * option's `signal` or the request's): the strategy settles at the abort
   * itself, it holds nothing to release.
   */
  provide: (authorizationUrl: string, signal: AbortSignal) => Promise<string>;
  /** Ends every login of this strategy `aborted`, beside the request's own signal. */
  signal?: AbortSignal | undefined;
}

export interface StaticCodeStrategyOptions {
  redirectUri?: string | undefined;
  payload: string;
}

/** One signal that aborts when either given one does. */
function combined(...signals: Array<AbortSignal | undefined>): AbortSignal {
  return AbortSignal.any(
    signals.filter((signal): signal is AbortSignal => signal !== undefined),
  );
}

/** The consumer drives its own interactive flow and needs the URL to do it. */
export function externalCodeStrategy(
  options: ExternalCodeStrategyOptions,
): IAuthorizationStrategy<string> {
  const redirectUri = options.redirectUri ?? defaultRedirectUri();
  return {
    async authorize(
      request: AuthorizationRequest,
    ): Promise<AuthorizationOutcome<string>> {
      const signal = combined(options.signal, signalOf(request));
      throwIfAborted(signal);
      const url = await untilAborted(
        Promise.resolve(request.buildAuthorizationUrl(redirectUri)),
        signal,
      );
      throwIfAborted(signal);
      const payload = await untilAborted(
        Promise.resolve(options.provide(url, signal)),
        signal,
      );
      if (!payload) {
        throw loginFailure({ outcome: 'no-input' });
      }
      return { payload, redirectUri };
    },
  };
}

/** The consumer already holds the payload; the builder is never called. */
export function staticCodeStrategy(
  options: StaticCodeStrategyOptions,
): IAuthorizationStrategy<string> {
  const redirectUri = options.redirectUri ?? defaultRedirectUri();
  if (!options.payload) {
    throw new Error('staticCodeStrategy requires a payload');
  }
  return {
    async authorize(): Promise<AuthorizationOutcome<string>> {
      return { payload: options.payload, redirectUri };
    },
  };
}
