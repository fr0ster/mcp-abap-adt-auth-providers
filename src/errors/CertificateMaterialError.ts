import { TOKEN_PROVIDER_ERROR_CODES } from '@mcp-abap-adt/interfaces-auth';
import { TokenProviderError } from './TokenProviderErrors';

/** The fixed words for certificate material that is not whole: the one source. */
export const CERTIFICATE_INCOMPLETE = {
  reason: 'the client certificate is incomplete',
  hint: 'give a PFX, or a certificate together with its key',
} as const;

/** The fixed words for certificate material that is whole but cannot be used. */
export const CERTIFICATE_UNUSABLE = {
  reason: 'the client certificate could not be used',
  hint: 'check the certificate, the key and the passphrase, and that a PFX uses current encryption (not legacy RC2)',
} as const;

/**
 * The fixed words for a client certificate past its `notAfter` — at pin time,
 * or before a request that would present it.
 */
export const CERTIFICATE_EXPIRED = {
  reason: 'the client certificate has expired',
  hint: 'renew the certificate; a token provider pins its certificate for life, so give the renewed one to a new provider',
} as const;

/** Which fixed words a CertificateMaterialError carries. */
function wordsFor(incomplete: boolean, expired: boolean) {
  if (incomplete) return CERTIFICATE_INCOMPLETE;
  return expired ? CERTIFICATE_EXPIRED : CERTIFICATE_UNUSABLE;
}

/**
 * Thrown when certificate material cannot be used. Its message is fixed and
 * carries nothing of the material; a refusal is built from `incomplete` and
 * `expired` alone.
 */
export class CertificateMaterialError extends TokenProviderError {
  constructor(
    public readonly incomplete: boolean,
    /** Whole and usable, but past its `notAfter`. */
    public readonly expired: boolean = false,
  ) {
    super(
      wordsFor(incomplete, expired).reason,
      TOKEN_PROVIDER_ERROR_CODES.CERTIFICATE_MATERIAL_ERROR,
    );
    this.name = 'CertificateMaterialError';
    Object.setPrototypeOf(this, CertificateMaterialError.prototype);
  }

  /** The fixed reason and hint this error stands for. */
  get words(): { readonly reason: string; readonly hint: string } {
    return wordsFor(this.incomplete, this.expired);
  }
}
