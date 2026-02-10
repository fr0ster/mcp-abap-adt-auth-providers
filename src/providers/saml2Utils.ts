/**
 * SAML2 provider shared helpers
 */

import type { ILogger } from '@mcp-abap-adt/interfaces';
import { readManualInput } from '../auth/manualInput';
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
    const input = config.manualInput || readManualInput;
    return await input('Paste SAMLResponse: ');
  }

  const browser = config.browser || 'auto';
  return await startSamlBrowserAuth(
    authConfig,
    browser,
    config.logger,
    config.redirectPort || 3001,
  );
}
