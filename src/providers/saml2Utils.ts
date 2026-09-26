/**
 * SAML2 provider shared helpers.
 */

import type {
  IAssertionReplayStore,
  IAssertionValidator,
  IAuthorizationStrategy,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { buildSamlAuthorizationUrl } from '../auth/saml2Auth';
import { ValidationError } from '../errors/TokenProviderErrors';
import { samlCallbackStrategy } from '../strategies';
import {
  createSignedAssertionValidator,
  createSignedResponseValidator,
  isShippedValidator,
} from '../validation/assertionValidator';

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
  /** PEM or bare base64 DER. Required when no `assertionValidator` is supplied. */
  idpCertificates?: string[];
  /**
   * The `Issuer` the assertion must name. Required unless the supplied
   * `assertionValidator` is a custom one: a shipped validator supplied there
   * still needs it, since it fails closed without an expected issuer.
   */
  idpEntityId?: string;
  /** Finite, non-negative, integer. Defaults to 0. */
  clockSkewMs?: number;
  /**
   * The AuthnRequest ID this login answers, when this package did not mint one
   * itself — a pre-built `authorizationUrl`, or a strategy that obtained the
   * response some other way after a request the consumer sent.
   */
  authnRequestId?: string;
  /**
   * Declares that no AuthnRequest is sent: the assertion must carry no
   * `InResponseTo`. Default `false`. Combining this with a request ID is a
   * configuration error, since the two describe different logins: with
   * `authnRequestId` a provider refuses at construction.
   */
  idpInitiated?: boolean;
  /** Which validator to use. Omitted means the provider's own default. */
  assertionValidator?: IAssertionValidator;
  /** A consumer's own replay store, for a deployment running more than one process. */
  assertionReplayStore?: IAssertionReplayStore;
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
  // The runtime check in resolveExpectedRequestId stays for a direct caller
  // of getSamlAssertion; through a provider this refuses first, before any
  // browser opens.
  if (config.idpInitiated && config.authnRequestId) {
    throw new ValidationError(
      'SAML idpInitiated is true and authnRequestId is set: an IdP-initiated ' +
        'login sends no request, so the two describe different logins. ' +
        'Remove one of them.',
      ['idpInitiated'],
    );
  }
}

/**
 * The consumer's validator when supplied, otherwise the provider's default —
 * `createSignedAssertionValidator` for `"bearer"`, since the token endpoint
 * receives the Assertion alone (#40) and its own signature is what that
 * endpoint verifies; `createSignedResponseValidator` for `"pure"`, since the
 * whole response is handed on and `Status`/`Destination` must be inside a
 * signature. See the spec's "A bare Assertion, and which validator each
 * provider defaults to".
 */
export function resolveAssertionValidator(
  config: Saml2CommonConfig,
  provider: 'bearer' | 'pure',
): IAssertionValidator {
  if (config.assertionValidator) {
    // A shipped validator fails closed without expectedIssuer, so supplying
    // one without idpEntityId would construct fine and then refuse every
    // login at `issuer` — after the browser step. A custom validator needs
    // no idpEntityId: it may establish trust some other way.
    if (isShippedValidator(config.assertionValidator) && !config.idpEntityId) {
      throw new ValidationError(
        'The supplied assertionValidator is a shipped one ' +
          '(createSignedResponseValidator or createSignedAssertionValidator), ' +
          'which refuses every assertion without an expected issuer: missing ' +
          'idpEntityId.',
        ['idpEntityId'],
      );
    }
    return config.assertionValidator;
  }

  const missing: string[] = [];
  if (!config.idpCertificates?.length) missing.push('idpCertificates');
  if (!config.idpEntityId) missing.push('idpEntityId');
  if (missing.length > 0) {
    throw new ValidationError(
      `The default assertion validator needs the identity provider it should ` +
        `trust: missing ${missing.join(', ')}. Supply these, or supply an ` +
        `assertionValidator of your own.`,
      missing,
    );
  }

  const options = {
    idpCertificates: config.idpCertificates as string[],
    clockSkewMs: config.clockSkewMs,
    replayStore: config.assertionReplayStore,
  };
  return provider === 'bearer'
    ? createSignedAssertionValidator(options)
    : createSignedResponseValidator(options);
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

/** What `getSamlAssertion` hands back: the wire payload, plus what it knows about the login. */
export interface SamlAssertionResult {
  readonly payload: string;
  /**
   * `undefined` exactly when the login is declared `idpInitiated` and no ID
   * was minted or declared for it.
   */
  readonly requestId?: string;
  /** Where the strategy actually listened — `outcome.redirectUri`, never `config.acsUrl`. */
  readonly acsUrl: string;
}

export async function getSamlAssertion(
  config: Saml2CommonConfig,
): Promise<SamlAssertionResult> {
  const declaredAcs = config.acsUrl;
  let mintedRequestId: string | undefined;

  const request = {
    logger: config.logger,
    buildAuthorizationUrl: async (redirectUri: string): Promise<string> => {
      // An IdP-initiated login sends no AuthnRequest, and without a pre-built
      // authorizationUrl the only URL this could produce is one carrying a
      // freshly minted request. Refused here, before any URL exists, so the
      // mistake surfaces before a browser opens rather than after a login.
      if (config.idpInitiated && !config.authorizationUrl) {
        throw new ValidationError(
          'SAML idpInitiated is true and no authorizationUrl is configured, ' +
            'but the authorization strategy asked for an authorization URL: ' +
            'the only one this package can build carries an AuthnRequest. ' +
            'Configure the IdP-initiated SSO URL as authorizationUrl, or use a ' +
            'strategy that does not call buildAuthorizationUrl.',
          ['authorizationUrl'],
        );
      }
      // A declared ACS is registered with the IdP; the strategy must be
      // listening exactly there, and an ephemeral port cannot be.
      const acsUrl = declaredAcs ?? redirectUri;
      if (declaredAcs && declaredAcs !== redirectUri) {
        throw new Error(
          `SAML acsUrl is ${declaredAcs}, but the authorization strategy is ` +
            `listening on ${redirectUri}. They must match.`,
        );
      }
      const built = buildSamlAuthorizationUrl({
        idpSsoUrl: config.idpSsoUrl,
        spEntityId: config.spEntityId,
        acsUrl,
        relayState: config.relayState,
        authorizationUrl: config.authorizationUrl,
      });
      mintedRequestId = built.requestId;
      return built.url;
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

    const requestId = resolveExpectedRequestId(config, mintedRequestId);

    return {
      payload: outcome.payload,
      requestId,
      acsUrl: outcome.redirectUri,
    };
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

/**
 * The ID `InResponseTo` must answer, from the three sources the spec allows:
 * minted, declared, or none by explicit `idpInitiated: true`. Anything else —
 * no ID and no declaration, or `idpInitiated` combined with an ID from either
 * of the other two sources — is a configuration error, not a validation
 * failure blamed on the assertion.
 */
function resolveExpectedRequestId(
  config: Saml2CommonConfig,
  mintedRequestId: string | undefined,
): string | undefined {
  const declaredRequestId = config.authnRequestId;

  if (config.idpInitiated) {
    if (mintedRequestId || declaredRequestId) {
      throw new ValidationError(
        'SAML idpInitiated is true, but a request ID was also minted or ' +
          'configured (an authorization strategy called buildAuthorizationUrl, ' +
          'or authnRequestId is set). An IdP-initiated login sends no request, ' +
          'so an ID means the configuration describes two different logins.',
        ['idpInitiated'],
      );
    }
    return undefined;
  }

  const requestId = mintedRequestId ?? declaredRequestId;
  if (!requestId) {
    throw new ValidationError(
      'Cannot validate InResponseTo: this login did not build its own AuthnRequest, ' +
        'so authnRequestId must be configured — or, if the identity provider ' +
        'starts this login itself, idpInitiated: true. This happens with a ' +
        'pre-built authorizationUrl, or an authorization strategy that supplies an ' +
        'assertion without asking for a URL.',
      ['authnRequestId'],
    );
  }
  return requestId;
}
