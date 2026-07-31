/**
 * SAML2 provider shared helpers.
 */

import type { IAuthorizationStrategy, ILogger } from '@mcp-abap-adt/interfaces';
import { buildSamlAuthorizationUrl } from '../auth/saml2Auth';
import { samlCallbackStrategy } from '../strategies';

export interface Saml2CommonConfig {
  idpSsoUrl: string;
  spEntityId: string;
  /**
   * Where the assertion is delivered. Required when `authorizationUrl` is set:
   * the ACS is then buried in a deflated `SAMLRequest` this package did not
   * build and cannot read, so it must be declared rather than inferred.
   */
  acsUrl?: string;
  relayState?: string;
  authorizationUrl?: string;
  /** How the login is conducted. Omitted means a browser callback. */
  authorization?: IAuthorizationStrategy<string>;
  logger?: ILogger;
}

export interface Saml2BearerExchangeConfig {
  tokenUrl?: string;
  uaaUrl?: string;
  clientId?: string;
  clientSecret?: string;
}

/** Throw at construction rather than half-verify at runtime. */
export function validateSamlConfig(config: Saml2CommonConfig): void {
  if (config.authorizationUrl && !config.acsUrl) {
    throw new Error(
      'acsUrl is required when authorizationUrl is set: the ACS inside a ' +
        'pre-built SAML request cannot be read, so it must be declared.',
    );
  }
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
  config: Saml2CommonConfig,
): Promise<string> {
  const declaredAcs = config.acsUrl;

  const request = {
    logger: config.logger,
    buildAuthorizationUrl: async (redirectUri: string): Promise<string> => {
      // A declared ACS is registered with the IdP; the strategy must be
      // listening exactly there, and an ephemeral port cannot be.
      const acsUrl = declaredAcs ?? redirectUri;
      if (declaredAcs && declaredAcs !== redirectUri) {
        throw new Error(
          `SAML acsUrl is ${declaredAcs}, but the authorization strategy is ` +
            `listening on ${redirectUri}. They must match.`,
        );
      }
      return buildSamlAuthorizationUrl({
        idpSsoUrl: config.idpSsoUrl,
        spEntityId: config.spEntityId,
        acsUrl,
        relayState: config.relayState,
        authorizationUrl: config.authorizationUrl,
      });
    },
  };

  const supplied = config.authorization;
  const strategy = supplied ?? samlCallbackStrategy();
  try {
    const outcome = await strategy.authorize(request);
    // The second net, for a strategy that never called the builder and so
    // never met the check inside it.
    if (declaredAcs && declaredAcs !== outcome.redirectUri) {
      throw new Error(
        `SAML acsUrl is ${declaredAcs}, but the authorization strategy used ` +
          `${outcome.redirectUri}. They must match.`,
      );
    }
    return outcome.payload;
  } finally {
    if (!supplied) {
      await strategy.dispose?.().catch((error: unknown) => {
        config.logger?.warn('[SAML] dispose failed', {
          error: error instanceof Error ? error.message : String(error),
        });
      });
    }
  }
}
