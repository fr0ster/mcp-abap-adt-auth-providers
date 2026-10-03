import { createSecureContext } from 'node:tls';
import type {
  AuthOutcome,
  IAuthProvider,
  IAuthRejection,
  ICertificateMaterial,
  ILogonTarget,
  IRequestTarget,
} from '@mcp-abap-adt/interfaces-auth';
import type {
  ICertificateMaterialLoader,
  ISapConfig,
} from '@mcp-abap-adt/interfaces-auth-sap';
import { OK, oops, safely } from '../auth/refusal';
import { refuseFor } from '../auth/rejection';
import { FileCertificateMaterialLoader } from './FileCertificateMaterialLoader';

/** A client certificate, presented in the TLS handshake of each logon. */
export class CertificateAuthProvider implements IAuthProvider {
  readonly kind = 'certificate';
  private material: ICertificateMaterial | null = null;

  constructor(
    private readonly loader: ICertificateMaterialLoader,
    private readonly config: ISapConfig,
  ) {}

  /**
   * Loads the material and proves it usable here, not at the wire: a TLS
   * context is built from it, so a wrong passphrase, a key that is not the
   * certificate's, or a damaged file is refused now, in fixed words — the
   * error's own text, which can name what it read, never reaches a refusal.
   */
  async prepare(): Promise<AuthOutcome> {
    return safely('loading the certificate', async () => {
      this.material = null;
      const material = await this.loader.load(this.config);
      try {
        createSecureContext(material);
      } catch {
        return oops(
          'the client certificate could not be used',
          'check the certificate and key files and the passphrase',
        );
      }
      this.material = material;
      return OK;
    });
  }

  /** No other way in: the wire's Oops is this provider's own. */
  async establish(logon: ILogonTarget): Promise<AuthOutcome> {
    const material = this.material;
    if (!material)
      return oops(
        'the certificate is not loaded',
        'connect() prepares it first',
      );
    return safely('presenting the certificate', () => {
      const { cert, key, pfx, passphrase } = material;
      const presented: ICertificateMaterial = {};
      if (cert !== undefined) presented.cert = cert;
      if (key !== undefined) presented.key = key;
      if (pfx !== undefined) presented.pfx = pfx;
      if (passphrase !== undefined) presented.passphrase = passphrase;
      return logon.tlsMaterial(presented);
    });
  }

  /** The usual choice: PEM or PFX files named in the config. */
  static fromFiles(config: ISapConfig): CertificateAuthProvider {
    return new CertificateAuthProvider(
      new FileCertificateMaterialLoader(),
      config,
    );
  }

  async authorize(_request: IRequestTarget): Promise<AuthOutcome> {
    return OK;
  }

  /** Blames the certificate only when the system refused the credential. */
  async rejected(rejection: IAuthRejection): Promise<AuthOutcome> {
    return safely('reading the rejection', () =>
      refuseFor(rejection, {
        reason: 'the client certificate was refused',
        hint: 'check that it is mapped to a user (CERTRULE / USREXTID)',
      }),
    );
  }
}
