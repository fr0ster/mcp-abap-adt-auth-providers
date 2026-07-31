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
} from '@mcp-abap-adt/interfaces';
import { DEFAULT_CALLBACK_PORT } from './BrowserCallbackStrategy';

const defaultRedirectUri = () =>
  `http://localhost:${DEFAULT_CALLBACK_PORT}/callback`;

export interface ExternalCodeStrategyOptions {
  redirectUri?: string;
  /** Receives the assembled URL — so the code returned matches its PKCE challenge. */
  provide: (authorizationUrl: string) => Promise<string>;
}

export interface StaticCodeStrategyOptions {
  redirectUri?: string;
  payload: string;
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
      const url = await request.buildAuthorizationUrl(redirectUri);
      const payload = await options.provide(url);
      if (!payload) {
        throw new Error('Authorization code provider returned an empty value');
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
