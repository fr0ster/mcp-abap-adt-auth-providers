import type {
  ICertificateMaterial,
  IClientAuthentication,
} from '@mcp-abap-adt/interfaces-auth';
import { checkCertificateMaterial } from '../auth/certificateMaterial';
import {
  CERTIFICATE_INCOMPLETE,
  CertificateMaterialError,
} from '../errors/CertificateMaterialError';

export interface TlsClientCertificateConfig {
  /** The material, or a loader the consumer owns; read and checked once. */
  material: ICertificateMaterial | (() => Promise<ICertificateMaterial>);
  /** Where the request goes; else the draft's mTLS alias, else its endpoint. */
  endpoint?: string;
}

/** `tls_client_auth`: the client is the certificate it presents in the handshake. */
export function tlsClientCertificate(
  config: TlsClientCertificateConfig,
): IClientAuthentication {
  let checked: Promise<ICertificateMaterial> | undefined;
  const load = (): Promise<ICertificateMaterial> => {
    checked ??= (async () => {
      const material =
        typeof config.material === 'function'
          ? await config.material()
          : config.material;
      const outcome = checkCertificateMaterial(material);
      if (!outcome.ok) {
        throw new CertificateMaterialError(
          outcome.refusal.reason === CERTIFICATE_INCOMPLETE.reason,
        );
      }
      return material;
    })();
    return checked;
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
