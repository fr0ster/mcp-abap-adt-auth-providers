import type { IClientAuthentication } from '@mcp-abap-adt/interfaces-auth';

/** A public client: `client_id` in the body, nothing else. */
export function noClientAuthentication(): IClientAuthentication {
  return {
    authenticate: async (draft) => ({
      parameters: { client_id: draft.clientId },
    }),
  };
}
