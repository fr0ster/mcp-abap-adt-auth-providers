/**
 * Configuration throws (spec Appendix A.5, E1–E28; A.3, K6): each is an
 * `AuthProviderFailure` of kind `configuration` with its `case` and the
 * `fields` it names — field names only, from the `CONFIG_FIELDS` allowlist,
 * never a configured value (L5). A constructor may throw one (a constructor
 * is not a moment of the contract, spec §8.1); a site inside a moment throws
 * one and the moment's boundary answers it.
 *
 * The sites build their error with `authError.configuration(…)` and a literal
 * `case`, so the compiler fixes which diagnostics that case may carry; these
 * helpers cover the cases several sites share.
 */

import {
  AuthProviderFailure,
  authError,
  classify,
  isConfigField,
  isMinted,
} from '@mcp-abap-adt/auth-errors';
import type { ConfigField } from './contractTransition';

/**
 * What a site hands `misconfigured`: the builder's result, typed by its kind
 * alone. Deliberately not `ConfigurationError`, the union of every case: a
 * union as the contextual type of the builder call widens the inferred case
 * to all of them (the builder's `One<C>` then refuses it) — the same reason
 * as `SamlRefusal`. With a contextual type that names no case, the case is
 * inferred from the literal at the site, and so are the diagnostics it may
 * carry.
 */
export interface ConfigurationRefusal {
  readonly kind: 'configuration';
}

/**
 * A configuration error a site built, as an `AuthProviderFailure`. Every
 * caller passes a builder's result, which this copy minted; anything else
 * (never, by construction) is classified rather than trusted.
 */
export function misconfigured(
  error: ConfigurationRefusal,
): AuthProviderFailure {
  return new AuthProviderFailure(
    isMinted(error) ? error : classify(error, 'unfamiliar-error'),
  );
}

/**
 * E1, E22, E28: the required fields that are missing, by name. A name not on
 * the `CONFIG_FIELDS` allowlist is never echoed (the builder would drop it;
 * it is dropped here first so the type holds).
 */
export function requiredFieldsMissing(
  names: readonly string[],
): AuthProviderFailure {
  const fields: ConfigField[] = [];
  for (const name of names) {
    if (isConfigField(name)) fields.push(name);
  }
  return misconfigured(
    authError.configuration({ case: 'required-fields-missing', fields }),
  );
}

/** E13: an OIDC endpoint must be discovered, and there is no issuer. */
export function oidcIssuerRequired(): AuthProviderFailure {
  return misconfigured(
    authError.configuration({
      case: 'oidc-discovery-needs-issuer',
      fields: ['issuerUrl'],
    }),
  );
}

/** E14–E16: an OIDC endpoint neither configured nor discovered. */
export function oidcEndpointMissing(
  field:
    | 'authorizationEndpoint'
    | 'tokenEndpoint'
    | 'deviceAuthorizationEndpoint',
): AuthProviderFailure {
  return misconfigured(
    authError.configuration({ case: 'oidc-endpoint-missing', fields: [field] }),
  );
}
