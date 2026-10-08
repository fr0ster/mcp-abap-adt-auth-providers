/**
 * Type test, compiled by `test:check` and run by nothing: `GrantTable`, the
 * type `grants.ts`'s grant list satisfies, takes every grant type and no
 * other — a list missing one, or naming one that does not exist, does not
 * compile.
 */
import type { GrantTable } from '../../auth/grants';

export const complete = {
  authorization_code: true,
  authorization_code_pkce: true,
  password: true,
  client_credentials: true,
  user_token: true,
  client_x509: true,
  saml2_bearer: true,
} as const satisfies GrantTable;

export const missing = {
  authorization_code: true,
  authorization_code_pkce: true,
  password: true,
  client_credentials: true,
  user_token: true,
  client_x509: true,
  // @ts-expect-error a grant type missing (saml2_bearer)
} as const satisfies GrantTable;

export const unknown = {
  authorization_code: true,
  authorization_code_pkce: true,
  password: true,
  client_credentials: true,
  user_token: true,
  client_x509: true,
  saml2_bearer: true,
  // @ts-expect-error a grant type that does not exist
  device_code: true,
} as const satisfies GrantTable;
