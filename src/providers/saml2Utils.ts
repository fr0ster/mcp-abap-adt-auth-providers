/**
 * SAML2 provider shared helpers
 */

import type { ILogger } from '@mcp-abap-adt/interfaces';
import {
  buildSamlAuthorizationUrl,
  startSamlBrowserAuth,
} from '../auth/saml2Auth';

export type Saml2AssertionFlow = 'browser' | 'manual' | 'assertion';

export interface Saml2CommonConfig {
  idpSsoUrl: string;
  spEntityId: string;
  acsUrl?: string;
  relayState?: string;
  authorizationUrl?: string;
  browser?: string;
  redirectPort?: number;
  logger?: ILogger;
}

export interface Saml2AssertionConfig extends Saml2CommonConfig {
  assertionFlow: Saml2AssertionFlow;
  assertionProvider?: () => Promise<string>;
  manualInput?: () => Promise<string>;
}

export interface Saml2BearerExchangeConfig {
  tokenUrl?: string;
  uaaUrl?: string;
  clientId?: string;
  clientSecret?: string;
}

export function resolveAcsUrl(config: Saml2CommonConfig): string {
  const port = config.redirectPort || 3001;
  return config.acsUrl || `http://localhost:${port}/callback`;
}

export function resolveTokenUrl(config: Saml2BearerExchangeConfig): string {
  if (config.tokenUrl) {
    return config.tokenUrl;
  }
  if (config.uaaUrl) {
    return `${config.uaaUrl.replace(/\/+$/, '')}/oauth/token`;
  }
  throw new Error('Missing tokenUrl or uaaUrl for SAML bearer exchange');
}

export async function getSamlAssertion(
  config: Saml2AssertionConfig,
): Promise<string> {
  const acsUrl = resolveAcsUrl(config);
  const authConfig = {
    idpSsoUrl: config.idpSsoUrl,
    spEntityId: config.spEntityId,
    acsUrl,
    relayState: config.relayState,
    authorizationUrl: config.authorizationUrl,
  };

  if (config.assertionFlow === 'assertion') {
    if (!config.assertionProvider) {
      throw new Error('assertionProvider is required for assertion flow');
    }
    return await config.assertionProvider();
  }

  if (config.assertionFlow === 'manual') {
    const authorizationUrl = buildSamlAuthorizationUrl(authConfig);
    config.logger?.info('[SAML] Open URL to authenticate', {
      authorizationUrl,
    });
    // The stdin/stdout default this used to fall back to (`readManualInput`)
    // wrote its prompt to stdout, which corrupts an MCP stdio transport — it
    // was removed rather than kept as a trap. Task 13 replaces this whole
    // module with the `manualSamlResponseStrategy` from
    // `../strategies/manualStrategies`; until then, callers of the 'manual'
    // flow must supply `manualInput` themselves.
    if (!config.manualInput) {
      throw new Error(
        "assertionFlow: 'manual' requires a `manualInput` callback; there is no default reader",
      );
    }
    return await config.manualInput();
  }

  const browser = config.browser || 'auto';
  return await startSamlBrowserAuth(
    authConfig,
    browser,
    config.logger,
    config.redirectPort || 3001,
  );
}
