/**
 * Strategies where the consumer supplies the payload.
 *
 * The two are separate because one needs the authorization URL and the other
 * does not — and asking for a URL that is not needed would drag in OIDC
 * discovery that a static payload never required. `externalCodeStrategy` is
 * a composition (spec §6d.7): `consumerHandoff({ redirectUri, provide })` as
 * its presentation and transport, `oauthCode()` as its protocol.
 * `staticCodeStrategy` presents no URL and waits for no answer: not one.
 */

import { authError } from '@mcp-abap-adt/auth-errors';
import type {
  AuthorizationOutcome,
  IAuthorizationStrategy,
} from '@mcp-abap-adt/interfaces-auth';
import {
  misconfigured,
  ownOptions,
  requiredFieldsMissing,
} from '../auth/configuration';
import { asAbortSignal } from '../auth/signalledRequest';
import {
  type ComposedStrategy,
  composeAuthorization,
} from '../authorization/compose';
import { oauthCode } from '../authorization/protocol';
import {
  consumerHandoff,
  type ProvideAnswer,
} from '../authorization/transport';
import { CALLBACK_ENDPOINT, DEFAULT_CALLBACK_PORT } from './defaults';

const defaultRedirectUri = () =>
  `http://localhost:${DEFAULT_CALLBACK_PORT}${CALLBACK_ENDPOINT}`;

export interface ExternalCodeStrategyOptions {
  /** Required: the redirect registered with the identity provider (C4). */
  redirectUri: string;
  /**
   * Receives the assembled URL — so the code returned matches its PKCE
   * challenge — and a signal that aborts when the login ends (this option's
   * `signal`, the request's, or `dispose()`): the strategy settles at the
   * abort itself, it holds nothing to release.
   */
  provide: ProvideAnswer;
  /** Ends every login of this strategy `aborted`, beside the request's own signal. */
  signal?: AbortSignal | undefined;
}

export interface StaticCodeStrategyOptions {
  redirectUri?: string | undefined;
  payload: string;
}

/** The consumer drives its own interactive flow and needs the URL to do it. */
export function externalCodeStrategy(
  options: ExternalCodeStrategyOptions,
): ComposedStrategy<string> {
  // Read once as own data: a hostile object throws nothing of its own.
  const own =
    ownOptions<Partial<Record<keyof ExternalCodeStrategyOptions, unknown>>>(
      options,
    );
  if (own.redirectUri === undefined) {
    throw requiredFieldsMissing(['redirectUri']);
  }
  const { presentation, transport } = consumerHandoff({
    redirectUri: own.redirectUri as string,
    provide: own.provide as ProvideAnswer,
  });
  return composeAuthorization({
    presentation,
    transport,
    protocol: oauthCode(),
    endpoint: CALLBACK_ENDPOINT,
    signal: asAbortSignal(own.signal),
  });
}

/** The consumer already holds the payload; the builder is never called. */
export function staticCodeStrategy(
  options: StaticCodeStrategyOptions,
): IAuthorizationStrategy<string> {
  // Read once as own data: a hostile object throws nothing of its own.
  const own = ownOptions<StaticCodeStrategyOptions>(options);
  const redirectUri = own.redirectUri ?? defaultRedirectUri();
  if (!own.payload) {
    // E27.
    throw misconfigured(
      authError.configuration({
        case: 'static-code-without-payload',
        fields: ['payload'],
      }),
    );
  }
  return {
    async authorize(): Promise<AuthorizationOutcome<string>> {
      return { payload: own.payload, redirectUri };
    },
  };
}
