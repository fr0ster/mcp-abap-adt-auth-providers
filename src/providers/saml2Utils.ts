/**
 * SAML2 provider shared helpers.
 */

import { type AttemptContext, authError } from '@mcp-abap-adt/auth-errors';
import type {
  AuthorizationRequest,
  IAssertionReplayStore,
  IAssertionValidator,
  IAuthorizationStrategy,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { misconfigured, requiredFieldsMissing } from '../auth/configuration';
import { buildSamlAuthorizationUrl } from '../auth/saml2Auth';
import { isShippedValidator } from '../validation/assertionValidator';

export interface Saml2CommonConfig {
  idpSsoUrl: string;
  spEntityId: string;
  /**
   * Where the assertion is delivered. Required when `authorizationUrl` is set:
   * the ACS is then buried in a deflated `SAMLRequest` this package did not
   * build and cannot read, so it must be declared rather than inferred.
   */
  acsUrl?: string | undefined;
  relayState?: string | undefined;
  authorizationUrl?: string | undefined;
  /**
   * How the login is conducted. Required — see the static factories for the
   * usual choice.
   */
  authorization: IAuthorizationStrategy<string>;
  logger?: ILogger | undefined;
  /**
   * The `Issuer` the assertion must name. Required unless the supplied
   * `assertionValidator` is a custom one: a shipped validator supplied there
   * still needs it, since it fails closed without an expected issuer.
   */
  idpEntityId?: string | undefined;
  /**
   * The AuthnRequest ID this login answers, when this package did not mint one
   * itself — a pre-built `authorizationUrl`, or a strategy that obtained the
   * response some other way after a request the consumer sent.
   */
  authnRequestId?: string | undefined;
  /**
   * Declares that no AuthnRequest is sent: the assertion must carry no
   * `InResponseTo`. Default `false`. Combining this with a request ID is a
   * configuration error, since the two describe different logins: with
   * `authnRequestId` a provider refuses at construction.
   */
  idpInitiated?: boolean | undefined;
  /**
   * Which validator to use. Required — see the static factories for the
   * usual choice, which builds a shipped one from a `SamlTrust`.
   */
  assertionValidator: IAssertionValidator;
}

export interface Saml2BearerExchangeConfig {
  tokenUrl?: string | undefined;
  uaaUrl?: string | undefined;
  clientId?: string | undefined;
  clientSecret?: string | undefined;
}

/** Throw at construction rather than half-verify at runtime. */
export function validateSamlConfig(config: Saml2CommonConfig): void {
  // E28: no validator is built for the consumer (rule 7); a JavaScript
  // caller past the type is told which collaborator is missing.
  if (!config.assertionValidator) {
    throw requiredFieldsMissing(['assertionValidator']);
  }
  if (config.authorizationUrl && !config.acsUrl) {
    // E3.
    throw misconfigured(
      authError.configuration({
        case: 'saml-acs-required-with-authorization-url',
        fields: ['acsUrl'],
      }),
    );
  }
  // The runtime check in resolveExpectedRequestId stays for a direct caller
  // of getSamlAssertion; through a provider this refuses first, before any
  // browser opens.
  if (config.idpInitiated && config.authnRequestId) {
    // E4: an IdP-initiated login sends no request, so the two describe
    // different logins.
    throw misconfigured(
      authError.configuration({
        case: 'saml-idp-initiated-with-request-id',
        fields: ['idpInitiated', 'authnRequestId'],
      }),
    );
  }
}

/** What a recipe needs to build a shipped validator. */
export interface SamlTrust {
  idpCertificates: string[];
  clockSkewMs?: number | undefined;
  /** Default in the recipe: the process-wide `defaultReplayStore`. */
  replayStore?: IAssertionReplayStore | undefined;
}

/**
 * Confirms the supplied validator is usable, and hands it back.
 *
 * A shipped validator fails closed without `expectedIssuer`, so supplying one
 * without `idpEntityId` would construct fine and then refuse every login at
 * `issuer` — after the browser step. A custom validator needs no
 * `idpEntityId`: it may establish trust some other way.
 */
export function checkAssertionValidator(
  config: Saml2CommonConfig,
): IAssertionValidator {
  if (isShippedValidator(config.assertionValidator) && !config.idpEntityId) {
    // E5.
    throw misconfigured(
      authError.configuration({
        case: 'saml-shipped-validator-without-issuer',
        fields: ['idpEntityId'],
      }),
    );
  }
  return config.assertionValidator;
}

export function resolveTokenUrl(config: Saml2BearerExchangeConfig): string {
  if (config.tokenUrl) {
    return config.tokenUrl;
  }
  if (config.uaaUrl) {
    // Trailing slashes dropped in plain code (no regex on configuration:
    // `/\/+$/` was quadratic on a long run of slashes).
    let end = config.uaaUrl.length;
    while (end > 0 && config.uaaUrl[end - 1] === '/') end--;
    return `${config.uaaUrl.slice(0, end)}/oauth/token`;
  }
  // E6.
  throw misconfigured(
    authError.configuration({
      case: 'saml-token-endpoint-missing',
      fields: ['tokenUrl', 'uaaUrl'],
    }),
  );
}

/**
 * E8: the strategy listens, or listened, elsewhere than the declared ACS —
 * the two addresses are diagnostics (origin and path only), never in the
 * words (L9).
 */
function acsMismatch(configured: string, used: string) {
  return misconfigured(
    authError.configuration(
      { case: 'saml-acs-mismatch', fields: ['acsUrl'] },
      { configuredUri: configured, strategyUri: used },
    ),
  );
}

/** What `getSamlAssertion` hands back: the wire payload, plus what it knows about the login. */
export interface SamlAssertionResult {
  readonly payload: string;
  /**
   * `undefined` exactly when the login is declared `idpInitiated` and no ID
   * was minted or declared for it.
   */
  readonly requestId?: string | undefined;
  /** Where the strategy actually listened — `outcome.redirectUri`, never `config.acsUrl`. */
  readonly acsUrl: string;
}

export async function getSamlAssertion(
  config: Saml2CommonConfig,
  attempt?: Pick<AttemptContext, 'signal' | 'exclusive'>,
): Promise<SamlAssertionResult> {
  const declaredAcs = config.acsUrl;
  let mintedRequestId: string | undefined;

  const request: AuthorizationRequest = {
    logger: config.logger,
    // The attempt's signal: every waiter gone ends the login (spec §6b).
    ...(attempt === undefined ? {} : { signal: attempt.signal }),
    buildAuthorizationUrl: async (redirectUri: string): Promise<string> => {
      // An IdP-initiated login sends no AuthnRequest, and without a pre-built
      // authorizationUrl the only URL this could produce is one carrying a
      // freshly minted request. Refused here, before any URL exists, so the
      // mistake surfaces before a browser opens rather than after a login.
      if (config.idpInitiated && !config.authorizationUrl) {
        // E7: the only URL this package can build carries an AuthnRequest.
        throw misconfigured(
          authError.configuration({
            case: 'saml-idp-initiated-without-authorization-url',
            fields: ['idpInitiated', 'authorizationUrl'],
          }),
        );
      }
      // A declared ACS is registered with the IdP; the strategy must be
      // listening exactly there, and an ephemeral port cannot be.
      const acsUrl = declaredAcs ?? redirectUri;
      if (declaredAcs && declaredAcs !== redirectUri) {
        throw acsMismatch(declaredAcs, redirectUri);
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

  const strategy = config.authorization;
  const authorize = () => strategy.authorize(request);
  // The strategy holds an exclusive resource (a socket, a reader): it starts
  // only once the previous attempt has released its own (the drain).
  const outcome = await (attempt ? attempt.exclusive(authorize) : authorize());
  // The second net, for a strategy that never called the builder and so
  // never met the check inside it.
  if (declaredAcs && declaredAcs !== outcome.redirectUri) {
    throw acsMismatch(declaredAcs, outcome.redirectUri);
  }

  const requestId = resolveExpectedRequestId(config, mintedRequestId);

  return {
    payload: outcome.payload,
    requestId,
    acsUrl: outcome.redirectUri,
  };
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
      // E9: an ID minted (a strategy called buildAuthorizationUrl) or
      // declared means the configuration describes two different logins.
      throw misconfigured(
        authError.configuration({
          case: 'saml-idp-initiated-with-request-id',
          fields: ['idpInitiated'],
        }),
      );
    }
    return undefined;
  }

  const requestId = mintedRequestId ?? declaredRequestId;
  if (!requestId) {
    // E10: a pre-built authorizationUrl, or a strategy that supplies an
    // assertion without asking for a URL.
    throw misconfigured(
      authError.configuration({
        case: 'saml-in-response-to-undeclared',
        fields: ['authnRequestId', 'idpInitiated'],
      }),
    );
  }
  return requestId;
}
