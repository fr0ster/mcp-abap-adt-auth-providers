/**
 * The grant types of interfaces-auth as a table type: one entry each, so a
 * missing or an unknown one does not compile (`GrantTable`). interfaces-auth
 * exports no array of them.
 */
import type { OAuth2GrantType } from '@mcp-abap-adt/interfaces-auth';

/** One entry per grant type: a missing or an unknown one does not compile. */
export type GrantTable = { readonly [G in OAuth2GrantType]: true };
