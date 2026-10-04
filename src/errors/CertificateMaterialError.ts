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
 * Thrown when certificate material cannot be used. Its message is fixed and
 * carries nothing of the material; a refusal is built from `incomplete` alone.
 */
export class CertificateMaterialError extends TokenProviderError {
  constructor(public readonly incomplete: boolean) {
    super(
      incomplete ? CERTIFICATE_INCOMPLETE.reason : CERTIFICATE_UNUSABLE.reason,
      TOKEN_PROVIDER_ERROR_CODES.CERTIFICATE_MATERIAL_ERROR,
    );
    this.name = 'CertificateMaterialError';
    Object.setPrototypeOf(this, CertificateMaterialError.prototype);
  }
}
