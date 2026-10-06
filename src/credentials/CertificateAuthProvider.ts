import { authError, relayOutcome } from '@mcp-abap-adt/auth-errors';
import type {
  IAuthRejection,
  ICertificateMaterial,
  ILogonTarget,
} from '@mcp-abap-adt/interfaces-auth';
import type {
  ICertificateMaterialLoader,
  ISapConfig,
} from '@mcp-abap-adt/interfaces-auth-sap';
import { AuthProviderBase } from '../auth/AuthProviderBase';
import {
  assertNotExpired,
  certificateNotAfter,
  checkCertificateMaterial,
} from '../auth/certificateMaterial';
import type { AnyOutcome } from '../auth/contractTransition';
import { OK } from '../auth/refusal';
import { refuseFor } from '../auth/rejection';
import { FileCertificateMaterialLoader } from './FileCertificateMaterialLoader';

/** A client certificate, presented in the TLS handshake of each logon. */
export class CertificateAuthProvider extends AuthProviderBase {
  readonly kind = 'certificate';
  private material: ICertificateMaterial | null = null;
  /** The loaded certificate's `notAfter`, checked again before each logon. */
  private notAfter = 0;

  constructor(
    private readonly loader: ICertificateMaterialLoader,
    private readonly config: ISapConfig,
  ) {
    super({
      prepare: 'loading-certificate',
      establish: 'presenting-certificate',
      authorize: 'authorizing',
      rejected: 'reading-rejection',
    });
  }

  /**
   * Loads the material and proves it usable here, not at the wire: a TLS
   * context is built from it, so a wrong passphrase, a key that is not the
   * certificate's, or a damaged file is refused now, in fixed words — the
   * error's own text, which can name what it read, never reaches a refusal.
   */
  protected async onPrepare(): Promise<AnyOutcome> {
    this.material = null;
    const material = await this.loader.load(this.config);
    const checked = checkCertificateMaterial(material);
    if (!checked.ok) return checked;
    this.notAfter = certificateNotAfter(material);
    this.material = material;
    return OK;
  }

  /** No other way in: the wire's Oops is this provider's own. */
  protected onEstablish(logon: ILogonTarget): AnyOutcome {
    const material = this.material;
    if (!material) {
      return {
        ok: false,
        refusal: authError['not-prepared']({ provider: 'certificate' }),
      };
    }
    // Valid at prepare() is not valid for life: a long-lived connection
    // reaches the certificate's notAfter between logons.
    assertNotExpired(this.notAfter);
    const { cert, key, pfx, passphrase } = material;
    const presented: ICertificateMaterial = {};
    if (cert !== undefined) presented.cert = cert;
    if (key !== undefined) presented.key = key;
    if (pfx !== undefined) presented.pfx = pfx;
    if (passphrase !== undefined) presented.passphrase = passphrase;
    // No other way in (rule 4): the target's answer, returned or thrown, is
    // this provider's — never the target's own object.
    return relayOutcome(
      () => logon.tlsMaterial(presented),
      'tls-material',
      'presenting-certificate',
    ).outcome;
  }

  /** The usual choice: PEM or PFX files named in the config. */
  static fromFiles(config: ISapConfig): CertificateAuthProvider {
    return new CertificateAuthProvider(
      new FileCertificateMaterialLoader(),
      config,
    );
  }

  protected onAuthorize(): AnyOutcome {
    return OK;
  }

  /** Blames the certificate only when the system refused the credential. */
  protected onRejected(rejection: IAuthRejection): AnyOutcome {
    return refuseFor(rejection, 'client-certificate');
  }
}
