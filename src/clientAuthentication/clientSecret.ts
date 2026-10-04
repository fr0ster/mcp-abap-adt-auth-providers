import type { IClientAuthentication } from '@mcp-abap-adt/interfaces-auth';

/** `client_secret_basic`: `Authorization: Basic base64(id:secret)`. */
export function clientSecretBasic(secret: string): IClientAuthentication {
  return {
    authenticate: async (draft) => ({
      headers: {
        Authorization: `Basic ${Buffer.from(`${draft.clientId}:${secret}`).toString('base64')}`,
      },
    }),
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
