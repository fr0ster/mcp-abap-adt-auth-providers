import { AuthProviderFailure, authError } from '@mcp-abap-adt/auth-errors';
import type { IClientAuthentication } from '@mcp-abap-adt/interfaces-auth';
import { misconfigured } from '../auth/configuration';

/**
 * How `clientSecretBasic` writes the client id and secret before joining them.
 * It depends on the server, so the consumer chooses — there is no default.
 *
 * - `'raw'`: as given, `base64(id + ':' + secret)`. Measured, for the
 *   measured id and secret: XSUAA accepts only this; UAA and Keycloak, which
 *   form-decode each component (RFC 6749 §2.3.1), refuse it for a secret
 *   holding `+` and `%`. An id holding `+` or `%`, or a space anywhere:
 *   Inference from the same rule, not measured.
 * - `'form'`: each component `application/x-www-form-urlencoded` first
 *   (RFC 6749 §2.3.1; a space becomes `+`). Measured: UAA and Keycloak accept
 *   it; XSUAA refused it for the measured id and secret, which encoding
 *   changes. A server percent-decoding per RFC 3986 would read a space's `+`
 *   as `+` (Inference, not measured).
 */
export interface ClientSecretBasicOptions {
  readonly encoding: 'raw' | 'form';
}

const ENCODINGS: ReadonlySet<unknown> = new Set(['raw', 'form']);

/** One component as `application/x-www-form-urlencoded` writes it. */
const formEncoded = (value: string): string =>
  new URLSearchParams([['', value]]).toString().slice(1);

/**
 * `client_secret_basic`: `Authorization: Basic base64(id:secret)`, the id and
 * the secret written as `options.encoding` says. `encoding` is required: a
 * call without it, or with another value, is a `configuration` failure
 * (`basic-encoding-missing`) naming `encoding`. With `'raw'`, a client id
 * containing `:` cannot be carried (RFC 7617): each request is refused with
 * `client-authentication` `basic-client-id-colon`, before anything is sent.
 */
export function clientSecretBasic(
  secret: string,
  options: ClientSecretBasicOptions,
): IClientAuthentication {
  const encoding = (options as { encoding?: unknown } | undefined)?.encoding;
  if (!ENCODINGS.has(encoding)) {
    // E19: the allowed values are named by their set, never the value given.
    throw misconfigured(
      authError.configuration({
        case: 'basic-encoding-missing',
        fields: ['encoding'],
        allowed: 'basic-encoding',
      }),
    );
  }
  const form = encoding === 'form';
  return {
    authenticate: async (draft) => {
      if (!form && draft.clientId.includes(':')) {
        // A7: refused before anything is sent.
        throw new AuthProviderFailure(
          authError['client-authentication']({
            problem: 'basic-client-id-colon',
          }),
        );
      }
      const credential = form
        ? `${formEncoded(draft.clientId)}:${formEncoded(secret)}`
        : `${draft.clientId}:${secret}`;
      return {
        headers: {
          Authorization: `Basic ${Buffer.from(credential).toString('base64')}`,
        },
      };
    },
  };
}

/** `client_secret_post`: `client_id` and `client_secret` in the body. */
export function clientSecretPost(secret: string): IClientAuthentication {
  return {
    authenticate: async (draft) => ({
      parameters: { client_id: draft.clientId, client_secret: secret },
    }),
  };
}
