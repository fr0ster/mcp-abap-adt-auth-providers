/**
 * The grant types of interfaces-auth, one entry each: a missing or an
 * unknown one does not compile (`GrantTable`). interfaces-auth exports no
 * array of them.
 */
import type { OAuth2GrantType } from '@mcp-abap-adt/interfaces-auth';

/** One entry per grant type: a missing or an unknown one does not compile. */
export type GrantTable = { readonly [G in OAuth2GrantType]: true };

/** The grant types a `<grant> token request` names (`getAuthType()`). */
export const GRANTS = Object.freeze({
  authorization_code: true,
  authorization_code_pkce: true,
  password: true,
  client_credentials: true,
  user_token: true,
  client_x509: true,
  saml2_bearer: true,
} as const satisfies GrantTable);

/** A grant type of interfaces-auth; own keys only (`__proto__` is none). */
export function isGrant(value: unknown): value is OAuth2GrantType {
  return typeof value === 'string' && Object.hasOwn(GRANTS, value);
}
