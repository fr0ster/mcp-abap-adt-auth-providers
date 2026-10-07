import type {
  ICertificateMaterial,
  IClientAuthentication,
} from '@mcp-abap-adt/interfaces-auth';
import { assertCertificateMaterial } from '../auth/certificateMaterial';

export interface TlsClientCertificateConfig {
  /** The material, or a loader the consumer owns; read and checked once. */
  material: ICertificateMaterial | (() => Promise<ICertificateMaterial>);
  /** Where the request goes; else the draft's mTLS alias, else its endpoint. */
  endpoint?: string | undefined;
}

/** `tls_client_auth`: the client is the certificate it presents in the handshake. */
export function tlsClientCertificate(
  config: TlsClientCertificateConfig,
): IClientAuthentication {
  let checked: Promise<ICertificateMaterial> | undefined;
  const load = (): Promise<ICertificateMaterial> => {
    if (checked) return checked;
    const attempt = (async () => {
      const material =
        typeof config.material === 'function'
          ? await config.material()
          : config.material;
      assertCertificateMaterial(material);
      return material;
    })();
    checked = attempt;
    // A success stays; a failure is forgotten so the next call loads again.
    attempt.catch(() => {
      if (checked === attempt) checked = undefined;
    });
    return attempt;
  };
  return {
    authenticate: async (draft) => {
      await load();
      return {
        endpoint: config.endpoint ?? draft.mtlsEndpoint ?? draft.endpoint,
        parameters: { client_id: draft.clientId },
      };
    },
    tlsMaterial: load,
  };
}
